"""Disposable Ed25519 receipt signer/verifier; no production keys or custody."""
import hashlib
import json
import re
import subprocess
import tempfile
import uuid
from pathlib import Path

DOMAIN = b"CEPHAS-CRM-RECOVERY-AUDIT-RECEIPT-V1\x00"
ZERO = "0" * 64
SPKI = bytes.fromhex("302a300506032b6570032100")
FIELDS = {"version", "deployment", "revision", "previous", "sequence", "epoch",
          "phase", "audit_sequence", "digest"}


def require(ok):
    if not ok:
        raise ValueError("invalid authority receipt")


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def validate(p, deployment):
    require(type(p) is dict and set(p) == FIELDS)
    require(type(p["version"]) is int and p["version"] == 1)
    require(p["deployment"] == deployment and str(uuid.UUID(deployment)) == deployment)
    for field, minimum in (("revision",1),("sequence",1),("audit_sequence",0)):
        require(type(p[field]) is int and minimum <= p[field] <= 2**53-1)
    require(str(uuid.UUID(p["epoch"])) == p["epoch"])
    require(p["phase"] in ("active","quarantine"))
    for field in ("previous","digest"):
        require(type(p[field]) is str and re.fullmatch(r"[0-9a-f]{64}",p[field]))
    require((p["audit_sequence"] == 0) == (p["digest"] == ZERO))


def run(*args):
    return subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=5).stdout


class TestSigner:
    """Ephemeral signer. Key is outside both DBs but on the trusted CI host."""
    def __init__(self, directory):
        self._key = Path(directory) / "receipt-private.pem"
        require(not self._key.exists())
        run("genpkey","-algorithm","Ed25519","-out",str(self._key))
        self._key.chmod(0o600)
        self.public = run("pkey","-in",str(self._key),"-pubout","-outform","DER")
        require(len(self.public) == 44 and self.public.startswith(SPKI))

    def sign(self, payload, domain=DOMAIN):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "message"
            path.write_bytes(domain+payload)
            signature = run("pkeyutl","-sign","-inkey",str(self._key),"-rawin","-in",str(path))
            require(len(signature) == 64)
            return signature


def verify_signature(public,raw,signature,domain):
    require(type(public) is bytes and len(public)==44 and public.startswith(SPKI))
    require(type(raw) is bytes and 0<len(raw)<=2048 and type(signature) is bytes and len(signature)==64)
    with tempfile.TemporaryDirectory() as d:
        d=Path(d)
        (d/"public").write_bytes(public)
        (d/"message").write_bytes(domain+raw)
        (d/"sig").write_bytes(signature)
        run("pkeyutl","-verify","-pubin","-keyform","DER","-inkey",str(d/"public"),
            "-rawin","-in",str(d/"message"),"-sigfile",str(d/"sig"))


def verify(public, raw, signature, deployment):
    require(type(public) is bytes and len(public)==44 and public.startswith(SPKI))
    require(type(raw) is bytes and 0 < len(raw) <= 2048 and len(signature)==64)
    p = json.loads(raw)
    require(canonical(p) == raw)
    validate(p, deployment)
    verify_signature(public,raw,signature,DOMAIN)
    return p, hashlib.sha256(DOMAIN+raw+signature).hexdigest()


def transition(old, new, previous):
    require(new["previous"] == previous)
    if old is None:
        require(new["revision"]==new["sequence"]==1 and new["phase"]=="active"
                and new["audit_sequence"]==0)
        return
    require(new["revision"]==old["revision"]+1)
    audit_same=(new["audit_sequence"],new["digest"])==(old["audit_sequence"],old["digest"])
    epoch_same=(new["sequence"],new["epoch"])==(old["sequence"],old["epoch"])
    if old["phase"]==new["phase"]=="active":
        require(epoch_same and new["audit_sequence"]==old["audit_sequence"]+1
                and new["digest"]!=old["digest"])
    elif old["phase"]=="active" and new["phase"]=="quarantine":
        require(audit_same and new["sequence"]==old["sequence"]+1 and new["epoch"]!=old["epoch"])
    elif old["phase"]=="quarantine" and new["phase"]=="active":
        require(audit_same and epoch_same)
    else:
        raise ValueError("invalid authority transition")

# Separate candidate transition contract; not used by current receipt runtime.
ROTATION_DOMAIN = b"CEPHAS-CRM-AUTHORITY-ROTATION-V1\x00"


def verify_rotation(raw, old_signature, new_signature, old_public, expected_new_public,
                    deployment, generation, floor):
    """Both keys prove possession; trusted operator pins the new public key.
    Binding to generation and exact current floor prevents stale certificates.
    A compromised old key alone cannot authorize an unapproved replacement.
    """
    p=json.loads(raw)
    require(type(raw) is bytes and canonical(p)==raw)
    require(type(p) is dict and set(p)=={"version","deployment","generation","revision",
                                       "receipt_digest","old_fingerprint","new_fingerprint"})
    require(type(p["version"]) is int and p["version"]==1)
    require(str(uuid.UUID(deployment))==deployment and p["deployment"]==deployment)
    require(type(generation) is int and 1<=generation<2**53-1)
    require(type(p["generation"]) is int and p["generation"]==generation+1)
    require(type(p["revision"]) is int and 1<=p["revision"]<=2**53-1)
    require(type(floor) is tuple and len(floor)==2 and (p["revision"],p["receipt_digest"])==floor)
    require(type(p["receipt_digest"]) is str and re.fullmatch(r"[0-9a-f]{64}",p["receipt_digest"]))
    require(old_public!=expected_new_public)
    require(p["old_fingerprint"]==hashlib.sha256(old_public).hexdigest())
    require(p["new_fingerprint"]==hashlib.sha256(expected_new_public).hexdigest())
    verify_signature(old_public,raw,old_signature,ROTATION_DOMAIN)
    verify_signature(expected_new_public,raw,new_signature,ROTATION_DOMAIN)
    return p["generation"]
