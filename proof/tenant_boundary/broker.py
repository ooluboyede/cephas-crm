"""Synthetic trusted broker experiment; not a production authentication service."""
import hmac
import re
from types import MappingProxyType

from recovery_state import RecoveryState

_SCOPE_ROLE = MappingProxyType({
    ("A", "1"): "proof_a1", ("A", "2"): "proof_a2",
    ("B", "1"): "proof_b1", ("B", "2"): "proof_b2",
})
_ACTORS = MappingProxyType({"alice": "proof_issuer_a", "bob": "proof_issuer_b"})
_OPERATIONS = MappingProxyType({
    "list_items": "SELECT value FROM crm.item ORDER BY id",
    "list_notes": "SELECT value FROM crm.note ORDER BY id",
})


class Denied(Exception):
    """Generic denial; never return raw database errors or credentials."""


class Broker:
    def __init__(self, credentials, session_factory, recovery_reader):
        # Only trusted bootstrap injects credentials and connection factory.
        if set(credentials) != set(_ACTORS):
            raise ValueError("invalid actor registry")
        if any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v)
               for v in credentials.values()) or len(set(credentials.values())) != len(_ACTORS):
            raise ValueError("invalid credential material")
        self._credentials = MappingProxyType(dict(credentials))
        if not callable(recovery_reader):
            raise ValueError("missing trusted recovery reader")
        self._recovery_reader = recovery_reader
        try:
            self._expected_state = self._read_recovery()
        except Exception:
            raise Denied("denied") from None
        self._expected_epoch = self._expected_state.epoch
        self._session_factory = session_factory

    def _read_recovery(self):
        state = self._recovery_reader()
        if (not isinstance(state, RecoveryState) or type(state.sequence) is not int
                or state.sequence < 1 or not isinstance(state.epoch, str)
                or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", state.epoch)):
            raise Denied("denied")
        return state

    def _require_recovery(self):
        if self._read_recovery() != self._expected_state:
            raise Denied("denied")

    def _authenticate(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            raise Denied("denied")
        matches = [actor for actor, secret in self._credentials.items()
                   if hmac.compare_digest(token, secret)]
        if len(matches) != 1:
            raise Denied("denied")
        return matches[0]

    def execute(self, token, tenant, bu, operation):
        # No caller-provided actor, SQL, connection, target PID/XID, role or callback.
        actor = self._authenticate(token)
        if any(type(v) is not str for v in (tenant, bu, operation)):
            raise Denied("denied")
        role = _SCOPE_ROLE.get((tenant, bu))
        query = _OPERATIONS.get(operation)
        if role is None or query is None:
            raise Denied("denied")
        runtime = issuer = None
        try:
            self._require_recovery()
            runtime = self._session_factory(role)
            runtime.query("BEGIN ISOLATION LEVEL READ COMMITTED")
            result = runtime.query("SELECT pg_backend_pid(),pg_current_xact_id()")
            if len(result) != 1 or not re.fullmatch(r"[0-9]+\|[0-9]+", result[0]):
                raise Denied("denied")
            pid, xid = result[0].split("|")
            issuer = self._session_factory(_ACTORS[actor])
            if issuer.query("SELECT auth.current_epoch()") != [self._expected_epoch]:
                raise Denied("denied")
            # Scope literals originate exclusively from the fixed allowlist above.
            issuer.query(f"SELECT auth.issue({pid},'{xid}'::xid8,'{tenant}','{bu}')")
            if runtime.query(f"SELECT auth.allowed('{tenant}','{bu}')") != ["t"]:
                raise Denied("denied")
            rows = runtime.query(query)
            if issuer.query("SELECT auth.current_epoch()") != [self._expected_epoch]:
                raise Denied("denied")
            if runtime.query(f"SELECT auth.allowed('{tenant}','{bu}')") != ["t"]:
                raise Denied("denied")
            self._require_recovery()
            runtime.query("COMMIT")
            self._require_recovery()
            return rows
        except Exception:
            raise Denied("denied") from None
        finally:
            # No pooling and no connection exposed to the caller. Closing even on
            # failure is essential; cleanup failure prevents returning data.
            cleanup_failed = False
            for session in (issuer, runtime):
                if session is not None:
                    try:
                        session.close()
                    except Exception:
                        cleanup_failed = True
            if cleanup_failed:
                raise Denied("denied") from None
