"""Disposable external recovery journal. Trusted host filesystem is assumed.

Not a WORM service, HSM, or protection from privileged journal rollback.
Only the trusted operator may create/advance it. Broker uses read-only access.
"""
import os
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

_EPOCH = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@dataclass(frozen=True)
class RecoveryState:
    sequence: int
    epoch: str


def _validate(value):
    if (not isinstance(value, RecoveryState) or type(value.sequence) is not int
            or not 1 <= value.sequence <= 2**63 - 1
            or not isinstance(value.epoch, str) or not _EPOCH.fullmatch(value.epoch)):
        raise ValueError("invalid recovery state")
    return value


def _connect(path, mode):
    # Caller configures an independently administered private directory.
    # No automatic file creation except explicit operator bootstrap.
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("recovery journal unavailable")
    return sqlite3.connect(path.resolve(strict=True).as_uri() + "?mode=" + mode,
                           uri=True, timeout=2, isolation_level=None)


def _head(connection):
    count, low, high = connection.execute(
        "SELECT count(*), min(sequence), max(sequence) FROM recovery"
    ).fetchone()
    if not count or low != 1 or count != high:
        raise ValueError("invalid recovery history")
    row = connection.execute(
        "SELECT sequence, epoch FROM recovery ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    return _validate(RecoveryState(*row))


def read_state(path):
    with closing(_connect(path, "ro")) as connection:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        return _head(connection)


def initialize(path, epoch):
    """Explicit, one-time trusted bootstrap. Never run on service startup."""
    initial = _validate(RecoveryState(1, epoch))
    path = Path(path)
    # Exclusive creation; a partially initialized file stays fail-closed.
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with closing(_connect(path, "rw")) as connection:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "CREATE TABLE recovery(sequence INTEGER PRIMARY KEY CHECK(sequence>0),"
            "epoch TEXT NOT NULL UNIQUE) STRICT"
        )
        connection.execute("INSERT INTO recovery VALUES(?,?)",
                           (initial.sequence, initial.epoch))
        connection.commit()
    # Persist directory entry on the supported Linux proof host.
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return initial


def advance(path, expected, new_epoch):
    """Operator-only compare-and-append; no blind adoption of DB state."""
    _validate(expected)
    next_state = _validate(RecoveryState(expected.sequence + 1, new_epoch))
    with closing(_connect(path, "rw")) as connection:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        if _head(connection) != expected:
            raise ValueError("recovery sequence conflict")
        # Unique epoch rejects reuse of any prior epoch.
        connection.execute("INSERT INTO recovery VALUES(?,?)",
                           (next_state.sequence, next_state.epoch))
        connection.commit()
    return next_state
