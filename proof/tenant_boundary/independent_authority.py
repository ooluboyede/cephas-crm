"""Two-cluster disposable recovery and audit proof.

Both clusters are controlled by a single CI operator. No production custody,
WORM, external signed receipts or service network authentication is claimed.
"""
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from recovery_state import initialize, advance, read_state, RecoveryState

ZERO = "0" * 64


class AuthorityDenied(Exception):
    pass


def demand(condition):
    if not condition:
        raise AuthorityDenied("authority denied")


def identifier(value):
    demand(type(value) is str and re.fullmatch(r"[a-z0-9_]{1,64}", value))
    return value


@dataclass(frozen=True)
class Head:
    sequence: int
    epoch: str
    phase: str
    audit_sequence: int
    digest: str


class R2Proof:
    """Trusted coordinator harness, not exposed to untrusted callers."""
    def __init__(self, primary, authority, local):
        self.primary = primary
        self.authority = authority
        self.local = local
        epoch = str(uuid.uuid4())
        # Per-test schemas; explicit operator-only setup, never startup repair.
        primary.query("DROP SCHEMA IF EXISTS r2 CASCADE")
        authority.query("DROP SCHEMA IF EXISTS anchor CASCADE")
        primary.query("CREATE SCHEMA r2")
        primary.query("REVOKE ALL ON SCHEMA r2 FROM PUBLIC")
        primary.query("CREATE TABLE r2.epoch(value uuid PRIMARY KEY)")
        primary.query(f"INSERT INTO r2.epoch VALUES('{epoch}')")
        primary.query("CREATE TABLE r2.effect(id text PRIMARY KEY)")
        primary.query("CREATE TABLE r2.outbox(seq bigint PRIMARY KEY, payload text NOT NULL, digest text NOT NULL)")
        primary.query("""CREATE FUNCTION r2.apply(event_id text) RETURNS text
            LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
            DECLARE n bigint; prev text; body text; next_digest text;
            BEGIN
              IF event_id !~ '^[a-z0-9_]{1,64}$' THEN RAISE EXCEPTION 'invalid id'; END IF;
              LOCK TABLE r2.outbox IN EXCLUSIVE MODE;
              SELECT seq,digest INTO n,prev FROM r2.outbox ORDER BY seq DESC LIMIT 1;
              n := coalesce(n,0)+1; prev := coalesce(prev,repeat('0',64));
              body := jsonb_build_object('seq',n,'previous',prev,'event_id',event_id,
                 'tenant','A','bu','1','actor','synthetic','action','create',
                 'target',event_id,'outcome','allowed','correlation',event_id,
                 'timestamp',to_char(clock_timestamp() AT TIME ZONE 'UTC',
                 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text;
              next_digest := encode(sha256(convert_to('CEPHAS-R2-AUDIT-V1:'||body,'UTF8')),'hex');
              INSERT INTO r2.effect VALUES(event_id);
              INSERT INTO r2.outbox VALUES(n,body,next_digest);
              RETURN next_digest;
            END $body$""")
        primary.query("REVOKE ALL ON FUNCTION r2.apply(text) FROM PUBLIC")
        authority.query("CREATE SCHEMA anchor")
        authority.query("REVOKE ALL ON SCHEMA anchor FROM PUBLIC")
        authority.query("""CREATE TABLE anchor.head(singleton boolean PRIMARY KEY CHECK(singleton),
            seq bigint NOT NULL CHECK(seq>0), epoch uuid NOT NULL,
            phase text NOT NULL CHECK(phase IN ('active','quarantine')),
            audit_seq bigint NOT NULL CHECK(audit_seq>=0), digest text NOT NULL)""")
        authority.query("CREATE TABLE anchor.history(epoch uuid PRIMARY KEY, seq bigint NOT NULL UNIQUE)")
        authority.query(f"INSERT INTO anchor.head VALUES(true,1,'{epoch}','active',0,'{ZERO}')")
        authority.query(f"INSERT INTO anchor.history VALUES('{epoch}',1)")
        initialize(local, epoch)

    def external(self, lock=False):
        try:
            rows = self.authority.query("SELECT seq,epoch,phase,audit_seq,digest FROM anchor.head WHERE singleton"
                                        + (" FOR UPDATE" if lock else ""))
            demand(len(rows) == 1)
            seq, epoch, phase, audit, digest = rows[0].split("|")
            demand(str(uuid.UUID(epoch)) == epoch and phase in ("active", "quarantine"))
            demand(re.fullmatch(r"[0-9a-f]{64}", digest) and int(seq) > 0 and int(audit) >= 0)
            return Head(int(seq), epoch, phase, int(audit), digest)
        except Exception:
            raise AuthorityDenied("authority unavailable") from None

    def local_head(self):
        try:
            rows = self.primary.query("SELECT seq,encode(convert_to(payload,'UTF8'),'hex'),digest FROM r2.outbox ORDER BY seq")
            previous = ZERO
            ids = []
            for expected, row in enumerate(rows, 1):
                seq, raw, digest = row.split("|")
                body = bytes.fromhex(raw)
                event = json.loads(body)
                demand(set(event) == {"seq","previous","event_id","tenant","bu","actor","action",
                                      "target","outcome","correlation","timestamp"})
                demand(int(seq) == expected and event["seq"] == expected and event["previous"] == previous)
                eid = identifier(event["event_id"])
                demand(event["tenant"] == "A" and event["bu"] == "1" and event["actor"] == "synthetic")
                demand(event["action"] == "create" and event["outcome"] == "allowed")
                demand(event["target"] == eid and event["correlation"] == eid and eid not in ids)
                demand(isinstance(event["timestamp"], str))
                demand(hashlib.sha256(b"CEPHAS-R2-AUDIT-V1:" + body).hexdigest() == digest)
                ids.append(eid)
                previous = digest
            demand(self.primary.query("SELECT id FROM r2.effect ORDER BY id") == sorted(ids))
            return len(rows), previous
        except Exception:
            raise AuthorityDenied("audit unavailable") from None

    def _match(self, head, active=True):
        demand(not active or head.phase == "active")
        demand(self.primary.query("SELECT value FROM r2.epoch") == [head.epoch])
        demand(read_state(self.local) == RecoveryState(head.sequence, head.epoch))
        demand(self.local_head() == (head.audit_sequence, head.digest))
        return head

    def guard(self):
        try:
            return self._match(self.external())
        except Exception:
            raise AuthorityDenied("protected operation denied") from None

    def _locked(self, action):
        try:
            self.authority.query("BEGIN")
            head = self.external(lock=True)
            result = action(head)
            self.authority.query("COMMIT")
            return result
        except Exception:
            try:
                self.authority.query("ROLLBACK")
            except Exception:
                pass
            raise AuthorityDenied("protected operation denied") from None

    def mutate(self, event_id):
        identifier(event_id)
        def apply(head):
            self._match(head)
            # Primary commit and authority commit are distinct. If interrupted
            # between them, mismatch blocks later operations, no auto-adoption.
            digest = self.primary.query(f"SELECT r2.apply('{event_id}')")[0]
            demand(self.local_head() == (head.audit_sequence + 1, digest))
            rows = self.authority.query(f"UPDATE anchor.head SET audit_seq=audit_seq+1,digest='{digest}' "
                                        "WHERE singleton RETURNING audit_seq")
            demand(rows == [str(head.audit_sequence+1)])
            return Head(head.sequence,head.epoch,head.phase,head.audit_sequence+1,digest)
        return self._locked(apply)

    def quarantine(self):
        def begin(head):
            demand(head.phase == "active")
            epoch = str(uuid.uuid4())
            self.authority.query(f"INSERT INTO anchor.history VALUES('{epoch}',{head.sequence+1})")
            self.authority.query(f"UPDATE anchor.head SET seq=seq+1,epoch='{epoch}',phase='quarantine' WHERE singleton")
            return epoch
        return self._locked(begin)

    def reconcile_epoch(self):
        def reconcile(head):
            demand(head.phase == "quarantine")
            # Never silently adopt a changed audit history. Explicit operator
            # repair needed if restored primary lacks authoritative checkpoint.
            demand(self.local_head() == (head.audit_sequence, head.digest))
            old = read_state(self.local)
            if old == RecoveryState(head.sequence,head.epoch):
                demand(self.primary.query("SELECT value FROM r2.epoch") == [head.epoch])
                return head
            demand(old.sequence == head.sequence-1)
            prior = self.authority.query(f"SELECT epoch FROM anchor.history WHERE seq={old.sequence}")
            demand(prior == [old.epoch])
            demand(self.primary.query("SELECT value FROM r2.epoch") in ([old.epoch],[head.epoch]))
            self.primary.query(f"UPDATE r2.epoch SET value='{head.epoch}'")
            advance(self.local,old,head.epoch)
            return head
        return self._locked(reconcile)

    def activate(self):
        def activate(head):
            demand(head.phase == "quarantine")
            self._match(head,active=False)
            self.authority.query("UPDATE anchor.head SET phase='active' WHERE singleton")
            return Head(head.sequence,head.epoch,"active",head.audit_sequence,head.digest)
        return self._locked(activate)
