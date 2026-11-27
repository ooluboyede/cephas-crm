"""Two-cluster disposable recovery and audit proof.

Both clusters are controlled by a single CI operator. No production custody,
WORM or service network authentication is claimed. Receipts are synthetic.
"""
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from recovery_state import initialize, advance, read_state, RecoveryState
from authority_receipt import TestSigner, canonical, verify, transition
from receipt_floor import ReceiptFloor
from actor_broker import ActorBroker

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
        self.deployment = str(uuid.uuid4())
        self.signer = TestSigner(local.parent)
        self.public = self.signer.public
        self.witness = ReceiptFloor(local.parent / 'receipt-floor.sqlite',self.deployment,self.public)
        # Per-test schemas; explicit operator-only setup, never startup repair.
        primary.query("DROP SCHEMA IF EXISTS r2 CASCADE")
        authority.query("DROP SCHEMA IF EXISTS anchor CASCADE")
        primary.query("CREATE SCHEMA r2")
        primary.query("REVOKE ALL ON SCHEMA r2 FROM PUBLIC")
        primary.query("CREATE TABLE r2.epoch(value uuid PRIMARY KEY)")
        primary.query(f"INSERT INTO r2.epoch VALUES('{epoch}')")
        primary.query(f"UPDATE auth.epoch SET value='{epoch}'")
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
        authority.query("CREATE TABLE anchor.receipt(revision bigint PRIMARY KEY, payload text NOT NULL, signature text NOT NULL)")
        genesis=self._append_receipt(Head(1,epoch,"active",0,ZERO), None, ZERO)
        self.witness.initialize(genesis)
        initialize(local, epoch)
        self.guard()

    @classmethod
    def resume(cls,primary,authority,local,deployment,public,signer):
        """Trusted bootstrap supplies pinned identity; never recreate missing state."""
        obj=cls.__new__(cls)
        obj.primary=primary
        obj.authority=authority
        obj.local=local
        obj.deployment=deployment
        obj.public=public
        obj.signer=signer
        demand(signer.public==public)
        obj.witness=ReceiptFloor(local.parent / 'receipt-floor.sqlite',deployment,public)
        try:
            obj.witness.read()
            # Startup can inspect quarantined state, but cannot activate it.
            obj._locked(lambda head:head)
            return obj
        except Exception:
            raise AuthorityDenied("resume denied") from None

    def _receipt_head(self):
        rows = self.authority.query("SELECT revision,payload,signature FROM anchor.receipt ORDER BY revision LIMIT 4097")
        demand(0 < len(rows) <= 4096)
        prior, previous = None, ZERO
        seen_epochs = set()
        floor = self.witness.read()
        floor_seen = False
        entries = []
        for row in rows:
            revision, body, sig = row.split("|")
            payload, digest = verify(self.public, bytes.fromhex(body), bytes.fromhex(sig), self.deployment)
            demand(int(revision) == payload["revision"])
            transition(prior, payload, previous)
            if prior is None or payload["epoch"] != prior["epoch"]:
                demand(payload["epoch"] not in seen_epochs)
                seen_epochs.add(payload["epoch"])
            if payload["revision"] == floor[0]:
                demand(digest == floor[1])
                floor_seen = True
            if payload["revision"] > floor[0]:
                entries.append((payload["revision"],digest,bytes.fromhex(body),bytes.fromhex(sig)))
            prior, previous = payload, digest
        demand(floor_seen)
        return prior, previous, floor, entries

    def _append_receipt(self, head, prior, previous):
        payload={"version":1,"deployment":self.deployment,
                 "revision":1 if prior is None else prior["revision"]+1,
                 "previous":previous,"sequence":head.sequence,"epoch":head.epoch,
                 "phase":head.phase,"audit_sequence":head.audit_sequence,"digest":head.digest}
        transition(prior,payload,previous)
        raw=canonical(payload)
        signature=self.signer.sign(raw)
        _, digest=verify(self.public,raw,signature,self.deployment)
        self.authority.query(f"INSERT INTO anchor.receipt VALUES({payload['revision']},'{raw.hex()}','{signature.hex()}')")
        return payload["revision"],digest,raw,signature

    def external(self, lock=False):
        try:
            rows = self.authority.query("SELECT seq,epoch,phase,audit_seq,digest FROM anchor.head WHERE singleton"
                                        + (" FOR UPDATE" if lock else ""))
            demand(len(rows) == 1)
            seq, epoch, phase, audit, digest = rows[0].split("|")
            demand(str(uuid.UUID(epoch)) == epoch and phase in ("active", "quarantine"))
            demand(re.fullmatch(r"[0-9a-f]{64}", digest) and int(seq) > 0 and int(audit) >= 0)
            head = Head(int(seq), epoch, phase, int(audit), digest)
            receipt, _, _, _ = self._receipt_head()
            demand(head == Head(receipt['sequence'],receipt['epoch'],receipt['phase'],
                                receipt['audit_sequence'],receipt['digest']))
            return head
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
        demand(self.primary.query("SELECT value FROM auth.epoch") == [head.epoch])
        demand(read_state(self.local) == RecoveryState(head.sequence, head.epoch))
        demand(self.local_head() == (head.audit_sequence, head.digest))
        return head

    def guard(self):
        try:
            return self._locked(self._match)
        except Exception:
            raise AuthorityDenied("protected operation denied") from None

    def _locked(self, action):
        try:
            self.authority.query("BEGIN")
            self.authority.query("SET LOCAL lock_timeout='5s'")
            head = self.external(lock=True)
            prior, previous, floor, entries = self._receipt_head()
            # Persist verified existing history even if the requested operation
            # is subsequently denied. Lock order authority then witness.
            floor = self.witness.append(floor,entries)
            result = action(head)
            if isinstance(result,Head) and result != head:
                next_floor = self._append_receipt(result,prior,previous)
                # Witness first; if authority commit is lost, a witness ahead
                # denies all protected operations, including after restart.
                self.witness.append(floor,[next_floor])
            self.authority.query("COMMIT")
            return result
        except Exception:
            try:
                self.authority.query("ROLLBACK")
            except Exception:
                pass
            raise AuthorityDenied("protected operation denied") from None

    def recover_quarantine_receipt(self, expected_digest):
        """Explicit trusted operator repair of one lost quarantine commit only.

        No signing, new floor, primary mutation, activation or tail adoption.
        """
        try:
            demand(type(expected_digest) is str and re.fullmatch(r"[0-9a-f]{64}",expected_digest))
            self.authority.query("BEGIN")
            self.authority.query("SET LOCAL lock_timeout='5s'")
            rows=self.authority.query("SELECT seq,epoch,phase,audit_seq,digest FROM anchor.head WHERE singleton FOR UPDATE")
            retained=self.witness.retained()
            demand(len(rows)==1 and len(retained)>=2 and retained[-1][1]==expected_digest)
            prior=None
            previous=ZERO
            seen=set()
            for revision,digest,raw,sig in retained:
                payload,verified=verify(self.public,raw,sig,self.deployment)
                demand(verified==digest and payload["revision"]==revision)
                transition(prior,payload,previous)
                if prior is None or payload["epoch"]!=prior["epoch"]:
                    demand(payload["epoch"] not in seen)
                    seen.add(payload["epoch"])
                prior,previous=payload,digest
            n,digest,raw,sig=retained[-1]
            target=prior
            old,_=verify(self.public,retained[-2][2],retained[-2][3],self.deployment)
            demand(old["phase"]=="active" and target["phase"]=="quarantine")
            demand(rows==["|".join(str(old[k]) for k in ("sequence","epoch","phase","audit_sequence","digest"))])
            expected_prefix=[f"{rev}|{body.hex()}|{signature.hex()}" for rev,_,body,signature in retained[:-1]]
            demand(self.authority.query("SELECT revision,payload,signature FROM anchor.receipt ORDER BY revision LIMIT 4097")==expected_prefix)
            expected_history=[]
            last_epoch=None
            for _,_,body,_ in retained[:-1]:
                item=json.loads(body)
                if item["epoch"]!=last_epoch:
                    expected_history.append(f"{item['sequence']}|{item['epoch']}")
                    last_epoch=item["epoch"]
            demand(self.authority.query("SELECT seq,epoch FROM anchor.history ORDER BY seq")==expected_history)
            demand(self.local_head()==(old["audit_sequence"],old["digest"]))
            demand(read_state(self.local)==RecoveryState(old["sequence"],old["epoch"]))
            for table in ("r2.epoch","auth.epoch"):
                demand(self.primary.query(f"SELECT value FROM {table}")==[old["epoch"]])
            demand(self.witness.read()==(n,digest))
            epoch=target["epoch"]
            seq=target["sequence"]
            self.authority.query(f"INSERT INTO anchor.history VALUES('{epoch}',{seq})")
            self.authority.query(f"INSERT INTO anchor.receipt VALUES({n},'{raw.hex()}','{sig.hex()}')")
            self.authority.query(f"UPDATE anchor.head SET seq={seq},epoch='{epoch}',phase='quarantine' WHERE singleton")
            head=self.external(lock=True)
            demand(head.phase=="quarantine" and head.epoch==epoch)
            self.authority.query("COMMIT")
            return head
        except Exception:
            try:
                self.authority.query("ROLLBACK")
            except Exception:
                pass
            raise AuthorityDenied("recovery denied") from None

    def fenced_read(self, credentials, factory, token, tenant, bu, operation):
        # Trusted broker composition. No caller SQL or callback at public edge.
        # Cooperative quarantine waits on the authority lock until read completes.
        def read(head):
            self._match(head)
            broker=ActorBroker(credentials,factory,lambda:RecoveryState(head.sequence,head.epoch))
            rows=broker.execute(token,tenant,bu,operation)
            self._match(head)
            return rows
        return self._locked(read)

    def mutate(self, event_id):
        identifier(event_id)
        def apply(head):
            self._match(head)
            # Primary commit and authority commit are distinct. If interrupted
            # between them, mismatch blocks later operations, no auto-adoption.
            digest = self.primary.query(f"SELECT r2.apply('{event_id}')")[0]
            demand(self.local_head() == (head.audit_sequence + 1, digest))
            if head.audit_sequence:
                demand(self.primary.query(f"SELECT digest FROM r2.outbox WHERE seq={head.audit_sequence}") == [head.digest])
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
            return Head(head.sequence+1,epoch,'quarantine',head.audit_sequence,head.digest)
        return self._locked(begin).epoch

    def reconcile_epoch(self):
        def reconcile(head):
            demand(head.phase == "quarantine")
            # Never silently adopt a changed audit history. Explicit operator
            # repair needed if restored primary lacks authoritative checkpoint.
            demand(self.local_head() == (head.audit_sequence, head.digest))
            old = read_state(self.local)
            if old == RecoveryState(head.sequence,head.epoch):
                demand(self.primary.query("SELECT value FROM r2.epoch") == [head.epoch])
                demand(self.primary.query("SELECT value FROM auth.epoch") == [head.epoch])
                return head
            demand(old.sequence == head.sequence-1)
            prior = self.authority.query(f"SELECT epoch FROM anchor.history WHERE seq={old.sequence}")
            demand(prior == [old.epoch])
            demand(self.primary.query("SELECT value FROM r2.epoch") in ([old.epoch],[head.epoch]))
            demand(self.primary.query("SELECT value FROM auth.epoch") in ([old.epoch],[head.epoch]))
            self.primary.query("BEGIN")
            try:
                self.primary.query(f"UPDATE r2.epoch SET value='{head.epoch}'")
                self.primary.query(f"UPDATE auth.epoch SET value='{head.epoch}'")
                self.primary.query("COMMIT")
            except Exception:
                self.primary.query("ROLLBACK")
                raise
            advance(self.local,old,head.epoch)
            return head
        return self._locked(reconcile)

    def activate(self, expected_epoch):
        def activate(head):
            demand(head.phase == "quarantine" and head.epoch == expected_epoch)
            self._match(head,active=False)
            self.authority.query("UPDATE anchor.head SET phase='active' WHERE singleton")
            return Head(head.sequence,head.epoch,"active",head.audit_sequence,head.digest)
        return self._locked(activate)
