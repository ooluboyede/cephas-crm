"""Disposable persistent receipt witness.

Separate backup/restore set only. Trusted CI filesystem, operator and
coordinator assumed. Not independent privileged rollback protection.
"""
import hashlib
import os
import re
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path


def require(ok):
    if not ok:
        raise ValueError("receipt floor unavailable")


class ReceiptFloor:
    def __init__(self,path,deployment,public):
        self.path=Path(path)
        require(str(uuid.UUID(deployment))==deployment)
        require(type(public) is bytes and len(public)==44)
        self.deployment=deployment
        self.fingerprint=hashlib.sha256(public).hexdigest()

    @staticmethod
    def validate(floor):
        require(type(floor) is tuple and len(floor)==2)
        n,d=floor
        require(type(n) is int and 1<=n<=2**53-1)
        require(type(d) is str and re.fullmatch(r"[0-9a-f]{64}",d))
        return floor

    def connect(self,mode):
        require(self.path.is_file() and not self.path.is_symlink())
        return sqlite3.connect(self.path.resolve(strict=True).as_uri()+"?mode="+mode,
                               uri=True,timeout=3,isolation_level=None)

    def initialize(self,genesis):
        self.validate(genesis)
        require(genesis[0]==1)
        fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        os.close(fd)
        with closing(self.connect("rw")) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),deployment TEXT NOT NULL,fingerprint TEXT NOT NULL) STRICT")
            db.execute("INSERT INTO identity VALUES(1,?,?)",(self.deployment,self.fingerprint))
            db.execute("CREATE TABLE floor(revision INTEGER PRIMARY KEY CHECK(revision>0),digest TEXT NOT NULL) STRICT")
            db.execute("INSERT INTO floor VALUES(?,?)",genesis)
            db.commit()
        fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _head(self,db):
        require(db.execute("SELECT deployment,fingerprint FROM identity WHERE singleton=1").fetchone()
                ==(self.deployment,self.fingerprint))
        n,low,high=db.execute("SELECT count(*),min(revision),max(revision) FROM floor").fetchone()
        require(n and low==1 and high==n)
        return self.validate(db.execute("SELECT revision,digest FROM floor ORDER BY revision DESC LIMIT 1").fetchone())

    def read(self):
        with closing(self.connect("ro")) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            return self._head(db)

    def append(self,expected,entries):
        # Only verified contiguous receipts from trusted coordinator.
        # CAS across independent connections; no reset or blind adoption.
        self.validate(expected)
        with closing(self.connect("rw")) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            require(self._head(db)==expected)
            prior=expected
            for entry in entries:
                self.validate(entry)
                require(entry[0]==prior[0]+1)
                db.execute("INSERT INTO floor VALUES(?,?)",entry)
                prior=entry
            db.commit()
        return prior
