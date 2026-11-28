"""Read-only candidate actor-specific broker, no target selector.

Trusted process, synthetic credentials and connection factory only.
No OIDC, remote service, pooling, or production role lifecycle.
"""
import hmac
import re
from types import MappingProxyType
from broker import Denied
from recovery_state import RecoveryState

_ROLES = MappingProxyType({
    ("alice","A","1"):"proof_alice_a1",
    ("charlie","A","1"):"proof_charlie_a1",
    ("bob","B","1"):"proof_bob_b1",
})
_OPERATIONS = MappingProxyType({
    "list_items":"SELECT value FROM crm.item ORDER BY id",
    "list_notes":"SELECT value FROM crm.note ORDER BY id",
})


class ActorBroker:
    def __init__(self, credentials, factory, recovery):
        if set(credentials)!={"alice","charlie","bob"} or any(
                type(v) is not str or not re.fullmatch(r"[0-9a-f]{64}",v)
                for v in credentials.values()) or len(set(credentials.values()))!=3:
            raise ValueError("invalid credentials")
        self._credentials=MappingProxyType(dict(credentials))
        self._factory=factory
        self._recovery=recovery
        self._state=self._read_state()

    def _read_state(self):
        state=self._recovery()
        if (not isinstance(state,RecoveryState) or type(state.sequence) is not int
                or state.sequence<1 or type(state.epoch) is not str
                or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",state.epoch)):
            raise Denied("denied")
        return state

    def _check_state(self):
        if self._read_state()!=self._state:
            raise Denied("denied")

    @staticmethod
    def _identity(session, role):
        rows = session.query("SELECT session_user,pg_backend_pid(),pg_current_xact_id()")
        if (len(rows) != 1 or not re.fullmatch(r"[a-z0-9_]+\|[1-9][0-9]*\|[1-9][0-9]*", rows[0])
                or rows[0].split("|")[0] != role):
            raise Denied("denied")
        return rows[0]

    def execute(self, token, tenant, bu, operation):
        session=None
        try:
            if type(token) is not str or not re.fullmatch(r"[0-9a-f]{64}",token):
                raise Denied("denied")
            actors=[a for a,s in self._credentials.items() if hmac.compare_digest(s,token)]
            if len(actors)!=1 or any(type(x) is not str for x in (tenant,bu,operation)):
                raise Denied("denied")
            role=_ROLES.get((actors[0],tenant,bu))
            query=_OPERATIONS.get(operation)
            if role is None or query is None:
                raise Denied("denied")
            self._check_state()
            session=self._factory(role)
            session.query("BEGIN ISOLATION LEVEL READ COMMITTED")
            identity = self._identity(session, role)
            # All interpolated values are fixed registry literals or validated UUID.
            session.query(f"SELECT auth.bind_self('{tenant}','{bu}','{self._state.epoch}'::uuid)")
            if session.query(f"SELECT auth.allowed('{tenant}','{bu}')")!=["t"]:
                raise Denied("denied")
            if self._identity(session, role) != identity:
                raise Denied("denied")
            rows=session.query(query)
            if self._identity(session, role) != identity:
                raise Denied("denied")
            if session.query(f"SELECT auth.allowed('{tenant}','{bu}')")!=["t"]:
                raise Denied("denied")
            self._check_state()
            session.query("COMMIT")
            self._check_state()
            return rows
        except Exception:
            raise Denied("denied") from None
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    raise Denied("denied") from None
