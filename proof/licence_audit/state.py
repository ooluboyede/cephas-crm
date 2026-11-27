"""Disposable operator-controlled state store; not a privileged rollback anchor.

The proof assumes exclusive trusted service access to this file and its parent
directory. No automatic creation on service startup, no production keys.
"""
import hashlib
import os
import re
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from protocol import Invalid, canonical, number, require, verify_licence, verify_audit


def digest(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value))
    return value


class State:
    def __init__(self, path):
        self.path = Path(path)

    @classmethod
    def initialize(cls, path, floor, bundle_digest, observed_time):
        number(floor, 1)
        digest(bundle_digest)
        number(observed_time)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        obj = cls(path)
        with obj.transaction() as db:
            db.execute("CREATE TABLE licence(singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                       "floor INTEGER NOT NULL,digest TEXT NOT NULL,time INTEGER NOT NULL) STRICT")
            db.execute("INSERT INTO licence VALUES(1,?,?,?)", (floor,bundle_digest,observed_time))
            db.execute("CREATE TABLE usage(scope TEXT NOT NULL,day INTEGER NOT NULL,"
                       "request TEXT NOT NULL, module TEXT NOT NULL, PRIMARY KEY(scope,request)) STRICT")
            db.execute("CREATE TABLE checkpoint(scope TEXT PRIMARY KEY,sequence INTEGER NOT NULL,"
                       "digest TEXT NOT NULL) STRICT")
        return obj

    @contextmanager
    def transaction(self):
        try:
            require(self.path.is_file() and not self.path.is_symlink())
            with closing(sqlite3.connect(self.path.resolve(strict=True).as_uri()+"?mode=rw",
                                         uri=True, timeout=3, isolation_level=None)) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
                yield db
                db.commit()
        except (sqlite3.Error, OSError) as exc:
            raise Invalid("state unavailable") from exc

    @staticmethod
    def scope_key(binding):
        return hashlib.sha256(canonical(binding)).hexdigest()

    def reserve(self, raw, bundle, root, now, binding, module, request):
        # Trusted service inputs only. Reservation counts one synthetic transaction
        # per request, not a CRM mutation or distributed atomic commit.
        require(type(request) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", request))
        with self.transaction() as db:
            row = db.execute("SELECT floor,digest,time FROM licence WHERE singleton=1").fetchone()
            require(row is not None)
            floor, pinned, previous = row
            digest(pinned)
            seq, candidate, limits = verify_licence(
                raw, bundle, root, now, floor, binding, module, previous, pinned)
            scope = self.scope_key(binding)
            day = now // 86400
            prior = db.execute("SELECT day,module FROM usage WHERE scope=? AND request=?",
                               (scope, request)).fetchone()
            if prior is not None:
                require(prior == (day,module))
                db.execute("UPDATE licence SET floor=?,digest=?,time=? WHERE singleton=1",
                           (seq,candidate,now))
                return "duplicate"
            used = db.execute("SELECT count(*) FROM usage WHERE scope=? AND day=?",
                              (scope,day)).fetchone()[0]
            require(used < limits["max_transactions_per_day"])
            db.execute("INSERT INTO usage VALUES(?,?,?,?)", (scope,day,request,module))
            db.execute("UPDATE licence SET floor=?,digest=?,time=? WHERE singleton=1",
                       (seq,candidate,now))
        return "reserved"

    def accept_checkpoint(self, events, checkpoint, public, scope, sequence, head_digest):
        # Caller retrieves a trusted signed checkpoint; full-prefix proof.
        # Existing anchored prefix cannot be replaced by a different chain.
        from protocol import audit_digest
        with self.transaction() as db:
            key = self.scope_key(scope)
            old = db.execute("SELECT sequence,digest FROM checkpoint WHERE scope=?",
                             (key,)).fetchone()
            verify_audit(events, checkpoint, public, scope, sequence, head_digest)
            if old is not None:
                old_seq, old_digest = old
                require(sequence >= old_seq)
                previous = "0"*64
                for i, event in enumerate(events[:old_seq], 1):
                    previous = audit_digest(event, previous, i, scope)
                require(previous == old_digest)
            db.execute("INSERT INTO checkpoint VALUES(?,?,?) ON CONFLICT(scope) DO UPDATE "
                       "SET sequence=excluded.sequence,digest=excluded.digest",
                       (key,sequence,head_digest))
        return head_digest
