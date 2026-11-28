"""Experimental offline verifier; public keys only. Not production code."""
import base64
import hashlib
import json
import re
import subprocess
import tempfile
import uuid
from pathlib import Path

PRODUCT = "CEPHAS_CRM"
LICENCE_DOMAIN = b"CEPHAS-CRM-LICENCE-V1\x00"
BUNDLE_DOMAIN = b"CEPHAS-CRM-TRUST-V1\x00"
AUDIT_DOMAIN = b"CEPHAS-CRM-AUDIT-V1\x00"
CHECKPOINT_DOMAIN = b"CEPHAS-CRM-CHECKPOINT-V1\x00"
SPKI = bytes.fromhex("302a300506032b6570032100")
MAX = 2**53 - 1
MODULES = frozenset({"customer", "sales", "service"})
EDITIONS = frozenset({"enterprise", "standard"})


class Invalid(ValueError):
    pass


def require(condition):
    if not condition:
        raise Invalid("invalid security evidence")


def closed(obj, fields):
    require(type(obj) is dict and set(obj) == set(fields.split()))


def number(value, low=0):
    require(type(value) is int and low <= value <= MAX)
    return value


def ident(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value))
    return value


def uid(value):
    require(type(value) is str and re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value))
    require(str(uuid.UUID(value)) == value)
    return value


def canonical(value):
    # Restricted JCS subset: all validated keys/strings ASCII, safe integers,
    # no floats, duplicate fields or user-supplied arbitrary objects.
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 65536)
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                         parse_float=lambda _: (_ for _ in ()).throw(Invalid("float")),
                         parse_constant=lambda _: (_ for _ in ()).throw(Invalid("constant")))
        require(canonical(obj) == raw)
        return obj
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise Invalid("invalid encoding") from exc


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64(value, size):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]+", value))
    require(len(value) == (size * 8 + 5) // 6)
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4),
                               altchars=b"-_", validate=True)
    except ValueError as exc:
        raise Invalid("invalid base64") from exc
    require(len(raw) == size and b64(raw) == value)
    return raw


def verify_ed25519(public, message, signature):
    require(type(public) is bytes and len(public) == 32)
    require(type(signature) is bytes and len(signature) == 64)
    # Delegate Ed25519 to OpenSSL; never implement primitives ourselves.
    # CI records OpenSSL version; exact provider packaging qualification pending.
    with tempfile.TemporaryDirectory() as directory:
        d = Path(directory)
        (d / "key").write_bytes(SPKI + public)
        (d / "message").write_bytes(message)
        (d / "signature").write_bytes(signature)
        try:
            result = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                 "-inkey", str(d / "key"), "-rawin", "-in", str(d / "message"),
                 "-sigfile", str(d / "signature")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Invalid("verification unavailable") from exc
        require(result.returncode == 0)


def envelope(raw):
    obj = decode(raw)
    closed(obj, "payload signature")
    require(type(obj["payload"]) is dict)
    return obj["payload"], unb64(obj["signature"], 64)


def verify_bundle(raw, root, now, floor):
    number(now)
    number(floor, 1)
    p, sig = envelope(raw)
    closed(p, "schema_version product sequence not_before expires_at keys revoked")
    require(number(p["schema_version"]) == 1 and p["product"] == PRODUCT)
    require(number(p["sequence"], 1) >= floor)
    require(number(p["not_before"]) <= now < number(p["expires_at"]))
    require(type(p["keys"]) is list and 1 <= len(p["keys"]) <= 64)
    keys = {}
    for key in p["keys"]:
        closed(key, "kid public_key not_before expires_at")
        kid = ident(key["kid"])
        require(kid not in keys)
        require(number(key["not_before"]) < number(key["expires_at"]))
        keys[kid] = (unb64(key["public_key"], 32), key["not_before"], key["expires_at"])
    require(list(keys) == sorted(keys))
    revoked = p["revoked"]
    require(type(revoked) is list and len(revoked) <= 256)
    for kid in revoked:
        ident(kid)
    require(revoked == sorted(set(revoked)))
    verify_ed25519(root, BUNDLE_DOMAIN + canonical(p), sig)
    return p["sequence"], keys, frozenset(revoked), hashlib.sha256(raw).hexdigest()


def verify_licence(raw, bundle, root, now, floor, binding, module,
                   previous_time, pinned_bundle_digest=None):
    # floor, previous_time and binding are trusted operator inputs, not request data.
    number(previous_time)
    number(now)
    require(now >= previous_time)
    sequence, keys, revoked, digest = verify_bundle(bundle, root, now, floor)
    if sequence == floor and pinned_bundle_digest is not None:
        require(digest == pinned_bundle_digest)
    p, sig = envelope(raw)
    closed(p, "schema_version licence_id product customer_id tenant_id deployment_id environment edition modules limits issued_at not_before expires_at kid alg")
    require(number(p["schema_version"]) == 1 and p["product"] == PRODUCT)
    require(p["alg"] == "Ed25519")
    for field in ("licence_id", "customer_id", "tenant_id", "deployment_id"):
        uid(p[field])
    closed(binding, "customer_id tenant_id deployment_id environment")
    require(all(p[field] == binding[field] for field in binding))
    require(type(p["environment"]) is str and p["environment"] in ("production", "test", "development"))
    require(type(p["edition"]) is str and p["edition"] in EDITIONS)
    require(type(p["modules"]) is list and 1 <= len(p["modules"]) <= len(MODULES))
    for item in p["modules"]:
        ident(item)
        require(item in MODULES)
    require(p["modules"] == sorted(set(p["modules"])))
    require(type(module) is str and module in p["modules"])
    closed(p["limits"], "max_users max_records max_transactions_per_day")
    for value in p["limits"].values():
        number(value)
    issued, start, end = (number(p[k]) for k in ("issued_at", "not_before", "expires_at"))
    require(issued <= start <= now < end)
    kid = ident(p["kid"])
    require(kid in keys and kid not in revoked)
    public, key_start, key_end = keys[kid]
    require(key_start <= issued <= now < key_end)
    verify_ed25519(public, LICENCE_DOMAIN + canonical(p), sig)
    # Return candidate floor and digest only; caller must persist atomically
    # before granting production entitlements. No quota counters in this proof.
    return sequence, digest, dict(p["limits"])


def audit_digest(event, previous, sequence, scope):
    closed(event, "event_id scope action outcome timestamp")
    closed(scope, "tenant_id bu_id")
    uid(event["event_id"])
    require(event["scope"] == scope)
    for value in scope.values():
        uid(value)
    ident(event["action"])
    require(event["outcome"] in ("allowed", "denied"))
    number(event["timestamp"])
    number(sequence, 1)
    require(type(previous) is str and re.fullmatch(r"[0-9a-f]{64}", previous))
    return hashlib.sha256(AUDIT_DOMAIN + canonical(
        {"event": event, "previous": previous, "sequence": sequence})).hexdigest()


def verify_audit(events, checkpoint, public, scope, expected_sequence, expected_digest):
    # Checkpoint must be retrieved from trusted external custody, never from the
    # database being checked. The floor is a trusted independently held value.
    p, sig = envelope(checkpoint)
    closed(p, "schema_version product scope sequence digest")
    require(number(p["schema_version"]) == 1 and p["product"] == PRODUCT)
    require(p["scope"] == scope)
    require(number(p["sequence"], 1) == number(expected_sequence, 1))
    require(p["digest"] == expected_digest)
    require(type(expected_digest) is str and re.fullmatch(r"[0-9a-f]{64}", expected_digest))
    verify_ed25519(public, CHECKPOINT_DOMAIN + canonical(p), sig)
    require(type(events) is list and len(events) == expected_sequence)
    previous = "0" * 64
    seen = set()
    for sequence, event in enumerate(events, 1):
        previous = audit_digest(event, previous, sequence, scope)
        require(event["event_id"] not in seen)
        seen.add(event["event_id"])
    require(previous == expected_digest)
    return previous
