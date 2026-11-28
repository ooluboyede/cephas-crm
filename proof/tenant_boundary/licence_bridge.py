"""Disposable cross-language entitlement adapter; trusted local paths/time only."""
import hashlib
import json
import re
import secrets
import subprocess
from pathlib import Path
from broker import Denied

_SCRIPT=Path(__file__).resolve().parent.parent/"universal_licence"/"read_bridge.mjs"
_ACTIONS={"list_items":"read_items","list_notes":"read_notes"}


class ReadEntitlement:
    def __init__(self,directory):
        self._directory=Path(directory).resolve(strict=True)

    def _check(self,action,request,target,now,expected):
        try:
            result=subprocess.run(["node",str(_SCRIPT),str(self._directory)],
                input=json.dumps({"action":action,"requestId":request,"target":target,
                                  "now":now*1000}),text=True,capture_output=True,timeout=8)
            if result.returncode!=0 or result.stdout!=expected:
                raise Denied("entitlement denied")
        except Exception:
            raise Denied("entitlement denied") from None

    def reserve(self,actor,tenant,bu,operation,now):
        # Trusted deployment mapping: synthetic customer TEST-A, A/1 only.
        # Never infer customer binding from caller-supplied tenant or token claims.
        if (tenant,bu)!=("A","1") or actor not in ("alice","charlie") or operation not in _ACTIONS:
            raise Denied("entitlement denied")
        request=secrets.token_hex(32)
        target=hashlib.sha256(f"{actor}:{tenant}:{bu}:{operation}:{request}".encode("ascii")).hexdigest()
        action=_ACTIONS[operation]
        self._check(action,request,target,now,"applied")
        return action,request,target

    def confirm(self,reservation,now):
        self._check(*reservation,now,"duplicate")
