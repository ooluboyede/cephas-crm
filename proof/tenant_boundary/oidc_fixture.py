"""Synthetic RSA IdP signing fixture. Never deployed or trusted in production."""
import json
import subprocess
from pathlib import Path
from oidc_boundary import b64


class TestIdP:
    def __init__(self,directory,kid):
        self.kid=kid
        self.path=Path(directory)/("idp-"+kid+".pem")
        subprocess.run(["openssl","genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:2048",
                        "-out",str(self.path)],check=True,capture_output=True,timeout=15)
        self.path.chmod(0o600)
        modulus=subprocess.run(["openssl","rsa","-in",str(self.path),"-noout","-modulus"],
                               check=True,capture_output=True,text=True,timeout=5).stdout.strip()
        self.jwk={"kty":"RSA","use":"sig","alg":"RS256","kid":kid,
                  "n":b64(bytes.fromhex(modulus.split("=")[1])),"e":"AQAB"}

    def token(self,claims,header=None):
        if header is None:
            header={"alg":"RS256","kid":self.kid,"typ":"JWT"}
        def encode(obj):
            return b64(json.dumps(obj,separators=(",",":")).encode("utf-8"))
        first=encode(header)+"."+encode(claims)
        sig=subprocess.run(["openssl","dgst","-sha256","-sign",str(self.path)],
                           input=first.encode("ascii"),check=True,capture_output=True,timeout=5).stdout
        return first+"."+b64(sig)
