"""Disposable OIDC ID-token and server-session boundary; not a full OIDC client.

Trusted callback transport supplies ID token after code exchange. Discovery,
TLS/JWKS retrieval, actual PKCE code exchange, cookies and production IdP are
not implemented. OpenSSL supplies RS256 verification, not custom RSA math.
"""
import base64
import hashlib
import hmac
import json
import re
import secrets
import subprocess
import tempfile
import threading
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit

from broker import Denied


def need(ok):
    if not ok:
        raise Denied("identity denied")


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode(s):
    need(type(s) is str and 0<len(s)<=16384 and re.fullmatch(r"[A-Za-z0-9_-]+",s))
    raw=base64.b64decode(s+"="*(-len(s)%4),altchars=b"-_",validate=True)
    need(b64(raw)==s)
    return raw


def pairs(values):
    obj={}
    for key,value in values:
        need(key not in obj)
        obj[key]=value
    return obj


def object_json(raw):
    obj=json.loads(raw.decode("utf-8"),object_pairs_hook=pairs,
                   parse_constant=lambda _: (_ for _ in ()).throw(Denied("identity denied")))
    need(type(obj) is dict)
    return obj


def integer(v):
    need(type(v) is int and 0<=v<=2**53-1)
    return v


def identifier(v):
    need(type(v) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,128}",v))
    return v


def tlv(tag,body):
    n=len(body)
    length=bytes([n]) if n<128 else bytes([128+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,"big")
    return bytes([tag])+length+body


def der_integer(raw):
    need(raw and raw[0]!=0)
    return tlv(2,(b"\x00" if raw[0]&128 else b"")+raw)


def rsa_spki(jwk):
    # RFC 7518 unsigned integer encoding, fixed exponent; DER is only encoding.
    need(type(jwk) is dict and set(jwk)=={"kty","use","alg","kid","n","e"})
    need(jwk["kty"]=="RSA" and jwk["use"]=="sig" and jwk["alg"]=="RS256")
    n,e=decode(jwk["n"]),decode(jwk["e"])
    need(len(n) in (256,384,512) and n[0]&128 and n[-1]&1 and e==b"\x01\x00\x01")
    key=tlv(48,der_integer(n)+der_integer(e))
    return tlv(48,bytes.fromhex("300d06092a864886f70d0101010500")+tlv(3,b"\x00"+key)),len(n)


class OIDCVerifier:
    def __init__(self,issuer,audience,clock):
        parsed=urlsplit(issuer)
        need(parsed.scheme=="https" and parsed.hostname and not parsed.username and not parsed.password
             and not parsed.query and not parsed.fragment)
        self.issuer=issuer
        self.audience=identifier(audience)
        self._clock=clock
        self._lock=threading.RLock()
        self._last_time=0
        self._generation=0
        self._keys={}
        self._expires=0

    def _now(self):
        now=integer(self._clock())
        need(now>=self._last_time)
        self._last_time=now
        return now

    def now(self):
        with self._lock:
            return self._now()

    def install_keys(self,generation,jwks,ttl):
        # Trusted configuration/transport only; never called with token-supplied URL.
        with self._lock:
            now=self._now()
            need(integer(generation)==self._generation+1 and type(ttl) is int and 1<=ttl<=300)
            need(type(jwks) is dict and set(jwks)=={"keys"} and type(jwks["keys"]) is list
                 and 1<=len(jwks["keys"])<=16)
            keys={}
            for jwk in jwks["keys"]:
                kid=identifier(jwk["kid"])
                need(kid not in keys)
                keys[kid]=rsa_spki(jwk)
            # Replace rather than retain retired keys. Malformed update never extends TTL.
            self._keys=MappingProxyType(keys)
            self._generation=generation
            self._expires=now+ttl

    def verify(self,token,nonce):
        try:
            with self._lock:
                now=self._now()
                need(now<self._expires)
                need(type(token) is str and len(token)<=32768)
                parts=token.split(".")
                need(len(parts)==3)
                header=object_json(decode(parts[0]))
                need(set(header) in ({"alg","kid"},{"alg","kid","typ"}))
                need(header["alg"]=="RS256" and header.get("typ","JWT")=="JWT")
                key=self._keys.get(identifier(header["kid"]))
                need(key is not None)
                der,size=key
                sig=decode(parts[2])
                need(len(sig)==size)
                with tempfile.TemporaryDirectory() as d:
                    d=Path(d)
                    (d/"pub").write_bytes(der)
                    (d/"data").write_bytes(".".join(parts[:2]).encode("ascii"))
                    (d/"sig").write_bytes(sig)
                    result=subprocess.run(["openssl","dgst","-sha256","-verify",str(d/"pub"),
                        "-keyform","DER","-signature",str(d/"sig"),str(d/"data")],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
                    need(result.returncode==0)
                claims=object_json(decode(parts[1]))
                need(claims["iss"]==self.issuer)
                aud=claims["aud"]
                need(aud==self.audience or aud==[self.audience])
                need(claims.get("azp",self.audience)==self.audience)
                sub=identifier(claims["sub"])
                need(type(nonce) is str and nonce==claims["nonce"])
                iat,exp,auth=(integer(claims[k]) for k in ("iat","exp","auth_time"))
                need(auth<=iat<=now<exp and exp-iat<=300 and now-auth<=300)
                need(integer(claims.get("nbf",iat))<=now)
                need(type(claims.get("acr")) is str)
                return (self.issuer,sub),claims["acr"],auth,exp
        except Exception:
            raise Denied("identity denied") from None


class SessionGate:
    """Trusted in-process session adapter with fixed principal/operation mapping."""
    def __init__(self,verifier,principals,credentials,authority,factory,exchange=None,entitlement=None):
        self._verifier=verifier
        self._principals=MappingProxyType(dict(principals))
        self._credentials=MappingProxyType(dict(credentials))
        self._authority=authority
        self._factory=factory
        self._pending={}
        self._code_pending={}
        self._sessions={}
        self._exchange=exchange
        self._entitlement=entitlement
        self._redirect='https://crm.example.invalid/oidc/callback'
        self._lock=threading.RLock()

    def _prune(self,now):
        for store in (self._pending,self._code_pending):
            for key,value in list(store.items()):
                if now>=value[-1]:
                    del store[key]
        for key,value in list(self._sessions.items()):
            if now>=value[3] or now>=value[4]+30:
                del self._sessions[key]

    def begin(self):
        # Legacy trusted post-exchange test path only, not a public callback.
        with self._lock:
            now=self._verifier.now()
            self._prune(now)
            need(len(self._pending)+len(self._code_pending)<128)
            state,nonce=secrets.token_hex(32),secrets.token_hex(32)
            self._pending[state]=(nonce,now+60)
            return state,nonce

    def _issue_session(self,token,nonce,now):
        need(len(self._sessions)<128)
        principal,_,_,exp=self._verifier.verify(token,nonce)
        need(principal in self._principals)
        session=secrets.token_hex(32)
        self._sessions[session]=(token,nonce,principal,min(now+60,exp),now)
        return session

    def complete(self,state,token):
        # Trusted post-exchange regression only; not exposed to browser.
        with self._lock:
            now=self._verifier.now()
            self._prune(now)
            entry=self._pending.pop(state,None)
            need(entry is not None)
            return self._issue_session(token,entry[0],now)

    def begin_code(self,browser_binding):
        # browser_binding supplied by trusted server transport, not request body.
        with self._lock:
            need(callable(self._exchange))
            need(type(browser_binding) is str and re.fullmatch(r"[0-9a-f]{64}",browser_binding))
            now=self._verifier.now()
            self._prune(now)
            need(len(self._pending)+len(self._code_pending)<128)
            state,nonce=secrets.token_hex(32),secrets.token_hex(32)
            verifier=secrets.token_urlsafe(48)
            challenge=b64(hashlib.sha256(verifier.encode("ascii")).digest())
            self._code_pending[state]=(nonce,verifier,browser_binding,now+60)
            return {"response_type":"code","state":state,"nonce":nonce,
                    "code_challenge":challenge,"code_challenge_method":"S256",
                    "client_id":self._verifier.audience,"redirect_uri":self._redirect,
                    "scope":"openid"}

    def complete_code(self,state,code,browser_binding,callback_issuer):
        # Exchange is injected at trusted startup; no caller-specified endpoint,
        # redirect URI, code verifier, or token. Consume state before exchange.
        try:
            with self._lock:
                now=self._verifier.now()
                self._prune(now)
                entry=self._code_pending.pop(state,None)
                need(entry is not None)
                nonce,verifier,binding,_=entry
                need(type(browser_binding) is str and re.fullmatch(r"[0-9a-f]{64}",browser_binding)
                     and hmac.compare_digest(binding,browser_binding))
                need(callback_issuer==self._verifier.issuer)
                need(type(code) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,256}",code))
                token=self._exchange(code,verifier,self._redirect,self._verifier.audience)
                return self._issue_session(token,nonce,self._verifier.now())
        except Exception:
            raise Denied("identity denied") from None

    def logout(self,session):
        with self._lock:
            self._sessions.pop(session,None)

    def execute(self,session,tenant,bu,operation):
        try:
            with self._lock:
                now=self._verifier.now()
                self._prune(now)
                entry=self._sessions.get(session)
                need(entry is not None)
                token,nonce,principal,deadline,_=entry
                actual,acr,_,_=self._verifier.verify(token,nonce)
                need(actual==principal)
                actor=self._principals.get(principal)
                need(actor in self._credentials)
                need(operation in ("list_items","list_notes"))
                # Synthetic privileged action uses configured exact ACR, not email or
                # client claims of role/membership. Database checks live membership.
                if operation=="list_notes":
                    need(acr=="urn:cephas:proof:mfa")
                reservation=None
                if self._entitlement is not None:
                    reservation=self._entitlement.reserve(actor,tenant,bu,operation,now)
                rows=self._authority.fenced_read(self._credentials,self._factory,
                    self._credentials[actor],tenant,bu,operation)
                finished=self._verifier.now()
                need(finished<deadline and finished<now+30)
                if reservation is not None:
                    self._entitlement.confirm(reservation,finished)
                self._sessions[session]=(token,nonce,principal,deadline,finished)
                return rows
        except Exception:
            raise Denied("identity denied") from None
