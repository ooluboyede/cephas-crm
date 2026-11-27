"""Disposable real PostgreSQL proof; no customer data or production secrets."""
import os
import re
import secrets
import subprocess
import time
import unittest
import tempfile
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from broker import Broker, Denied
from recovery_state import RecoveryState, initialize, advance, read_state

ROOT = Path(__file__).resolve().parent
NAME = "cephas-proof-" + secrets.token_hex(6)
PASSWORDS = {role: secrets.token_hex(24) for role in
             ("postgres", "proof_runtime", "proof_issuer_a", "proof_issuer_b",
              "proof_a1", "proof_a2", "proof_b1", "proof_b2")}
PINNED_IMAGE = "postgres@sha256:64c8b0d31e4ab6ea665e8426ea406a94bf52de3c05b3a4a8bf713704eefa9328"
IMAGE = os.environ.get("PROOF_POSTGRES_IMAGE", PINNED_IMAGE)
if IMAGE != PINNED_IMAGE:
    raise RuntimeError("unreviewed PostgreSQL image override")


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, text=True, **kwargs)


def command(role):
    return ["docker", "exec", "-i", "-e", "PGPASSWORD=" + PASSWORDS[role],
            NAME, "psql", "-X", "-qAt", "-h", "127.0.0.1", "-U", role,
            "-d", "postgres", "-P", "pager=off"]


class Session:
    def __init__(self, role):
        self.p = subprocess.Popen(command(role), stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, bufsize=1)

    def query(self, sql, state="00000"):
        marker = "END_" + secrets.token_hex(8)
        self.p.stdin.write(sql.rstrip(";") + ";\n\\echo " + marker + " :SQLSTATE\n")
        self.p.stdin.flush()
        lines = []
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise AssertionError("psql terminated before result")
            line = line.rstrip("\n")
            if line.startswith(marker + " "):
                actual = line.split()[-1]
                break
            lines.append(line)
        if actual != state:
            raise AssertionError(f"expected SQLSTATE {state}, received {actual}")
        return lines if state == "00000" else []

    def reset(self):
        # Trusted checkout boundary, never hand a raw psql session to a new actor
        # until rollback and DISCARD ALL both complete. Failure => discard session.
        self.query("ROLLBACK")
        self.query("DISCARD ALL")

    def close(self):
        try:
            self.p.stdin.write("\\q\n")
            self.p.stdin.flush()
        except (BrokenPipeError, ValueError, OSError):
            pass
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        try:
            self.p.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        self.p.stdout.close()


class Boundary(unittest.TestCase):
    def setUp(self):
        self.sessions = []
        self.admin = self.open("postgres")
        self.a = self.open("proof_runtime")
        self.ia = self.open("proof_issuer_a")
        self.ib = self.open("proof_issuer_b")

    def tearDown(self):
        for session in reversed(self.sessions):
            session.close()

    def open(self, role):
        session = Session(role)
        self.sessions.append(session)
        return session

    def begin(self, session=None, isolation="READ COMMITTED"):
        s = session or self.a
        s.query("BEGIN ISOLATION LEVEL " + isolation)
        pid, xid = s.query("SELECT pg_backend_pid(),pg_current_xact_id()")[0].split("|")
        self.assertRegex(pid, r"^\d+$")
        self.assertRegex(xid, r"^\d+$")
        return pid, xid

    def issue(self, binding, tenant="A", bu="1", issuer=None, state="00000"):
        pid, xid = binding
        return (issuer or self.ia).query(
            f"SELECT auth.issue({pid},'{xid}'::xid8,'{tenant}','{bu}')", state)

    def values(self, s=None):
        return (s or self.a).query("SELECT value FROM crm.item ORDER BY tenant,bu,id")

    def broker(self, factory=Session):
        tokens = {actor: secrets.token_hex(32) for actor in ("alice", "bob")}
        # Explicit trusted test-operator setup; never adopt restored DB state in production.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        journal = Path(directory.name) / "recovery.sqlite"
        epoch = self.admin.query("SELECT value FROM auth.epoch")[0]
        initialize(journal, epoch)
        return Broker(tokens, factory, lambda: read_state(journal)), tokens

    def recovery_fixture(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        journal = Path(directory.name) / "recovery.sqlite"
        epoch = self.admin.query("SELECT value FROM auth.epoch")[0]
        state = initialize(journal, epoch)
        tokens = {actor: secrets.token_hex(32) for actor in ("alice", "bob")}
        return journal, state, tokens

    def test_p06_journal_survives_broker_reconstruction(self):
        journal, state, tokens = self.recovery_fixture()
        for _ in range(2):
            broker = Broker(tokens, Session, lambda: read_state(journal))
            self.assertEqual(read_state(journal), state)
            self.assertEqual(broker.execute(tokens["alice"], "A", "1", "list_items"), ["A1"])

    def test_p06_journal_missing_or_corrupt_denied(self):
        journal, state, tokens = self.recovery_fixture()
        broker = Broker(tokens, Session, lambda: read_state(journal))
        journal.unlink()
        with self.assertRaises(Denied):
            broker.execute(tokens["alice"], "A", "1", "list_items")
        with self.assertRaises(Denied):
            Broker(tokens, Session, lambda: read_state(journal))
        journal.write_bytes(b"invalid sqlite")
        with self.assertRaises(Denied):
            Broker(tokens, Session, lambda: read_state(journal))
        self.assertEqual(state.sequence, 1)

    def test_p06_journal_compare_append_and_epoch_reuse(self):
        journal, initial, _ = self.recovery_fixture()
        with self.assertRaises(FileExistsError):
            initialize(journal, str(uuid.uuid4()))
        second = advance(journal, initial, str(uuid.uuid4()))
        self.assertEqual(second.sequence, 2)
        with self.assertRaises(ValueError):
            advance(journal, initial, str(uuid.uuid4()))
        with self.assertRaises(sqlite3.IntegrityError):
            advance(journal, second, initial.epoch)
        self.assertEqual(read_state(journal), second)

    def test_p06_journal_concurrent_advance_single_winner(self):
        journal, initial, _ = self.recovery_fixture()
        def attempt():
            try:
                return advance(journal, initial, str(uuid.uuid4()))
            except ValueError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(attempt) for _ in range(2)]
            results = [f.result(timeout=5) for f in futures]
        winners = [r for r in results if r is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(read_state(journal), winners[0])

    def test_p06_journal_advance_quarantines_old_broker_and_database(self):
        journal, initial, tokens = self.recovery_fixture()
        old = Broker(tokens, Session, lambda: read_state(journal))
        new = advance(journal, initial, str(uuid.uuid4()))
        with self.assertRaises(Denied):
            old.execute(tokens["alice"], "A", "1", "list_items")
        replacement = Broker(tokens, Session, lambda: read_state(journal))
        with self.assertRaises(Denied):
            replacement.execute(tokens["alice"], "A", "1", "list_items")
        self.admin.query(f"UPDATE auth.epoch SET value='{new.epoch}'::uuid")
        self.assertEqual(replacement.execute(tokens["alice"], "A", "1", "list_items"), ["A1"])
        with self.assertRaises(Denied):
            old.execute(tokens["alice"], "A", "1", "list_items")

    def test_p06_journal_change_during_read_suppresses_result(self):
        journal, initial, tokens = self.recovery_fixture()
        class RotateDuringRead(Session):
            def query(self, sql, state="00000"):
                rows = super().query(sql, state)
                if sql.startswith("SELECT value FROM crm.item"):
                    advance(journal, initial, str(uuid.uuid4()))
                return rows
        def factory(role):
            return RotateDuringRead(role) if role == "proof_a1" else Session(role)
        broker = Broker(tokens, factory, lambda: read_state(journal))
        with self.assertRaises(Denied):
            broker.execute(tokens["alice"], "A", "1", "list_items")
        self.assertEqual(read_state(journal).sequence, 2)

    def test_p05_cancel_active_statement_and_discard_session(self):
        scoped = self.open("proof_a1")
        pid, xid = self.begin(scoped)
        self.issue((pid, xid))
        self.assertEqual(self.values(scoped), ["A1"])
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(scoped.query, "SELECT pg_sleep(20)", "57014")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if self.admin.query(
                    f"SELECT count(*) FROM pg_stat_activity WHERE pid={pid} AND wait_event='PgSleep'"
                ) == ["1"]:
                    break
                time.sleep(0.05)
            else:
                self.fail("query never entered sleep")
            self.assertEqual(self.admin.query(f"SELECT pg_cancel_backend({pid})"), ["t"])
            future.result(timeout=5)
        scoped.query("ROLLBACK")
        scoped.close()
        self.sessions.remove(scoped)
        replacement = self.open("proof_a1")
        self.begin(replacement)
        self.assertEqual(self.values(replacement), [])
        replacement.query("ROLLBACK")
        self.issue(self.begin(replacement))
        self.assertEqual(self.values(replacement), ["A1"])
        replacement.query("ROLLBACK")

    def test_p05_broker_connection_loss_denies_and_closes(self):
        opened = []
        admin = self.admin
        class LostRuntime(Session):
            def query(self, sql, state="00000"):
                if sql.startswith("SELECT value FROM crm.item"):
                    pid = super().query("SELECT pg_backend_pid()")[0]
                    admin.query(f"SELECT pg_terminate_backend({pid})")
                return super().query(sql, state)
        def factory(role):
            s = LostRuntime(role) if role == "proof_a1" else Session(role)
            opened.append(s)
            return s
        broker, tokens = self.broker(factory)
        with self.assertRaisesRegex(Denied, "^denied$"):
            broker.execute(tokens["alice"], "A", "1", "list_items")
        self.assertEqual(len(opened), 2)
        self.assertTrue(all(s.p.poll() is not None for s in opened))
        healthy, tokens = self.broker()
        self.assertEqual(healthy.execute(tokens["alice"], "A", "1", "list_items"), ["A1"])

    def test_p05_broker_cleanup_failure_no_result(self):
        opened = []
        class BadCleanup(Session):
            def close(self):
                super().close()
                raise RuntimeError("synthetic cleanup failure")
        def factory(role):
            s = BadCleanup(role) if role == "proof_issuer_a" else Session(role)
            opened.append(s)
            return s
        broker, tokens = self.broker(factory)
        with self.assertRaisesRegex(Denied, "^denied$"):
            broker.execute(tokens["alice"], "A", "1", "list_items")
        self.assertEqual(len(opened), 2)
        self.assertTrue(all(s.p.poll() is not None for s in opened))

    def test_p06_external_epoch_mismatch_denies_broker(self):
        broker, tokens = self.broker()
        self.assertEqual(broker.execute(tokens["alice"], "A", "1", "list_items"), ["A1"])
        self.admin.query("UPDATE auth.epoch SET value=gen_random_uuid()")
        with self.assertRaisesRegex(Denied, "^denied$"):
            broker.execute(tokens["alice"], "A", "1", "list_items")
        # Explicit test operator adoption; not automatic on untrusted restore.
        replacement, new_tokens = self.broker()
        self.assertEqual(replacement.execute(new_tokens["alice"], "A", "1", "list_items"), ["A1"])

    def test_p06_logical_restore_rejects_rolled_back_epoch(self):
        # Real pg_dump/pg_restore of authority data into the disposable DB.
        # No production database or credentials are involved.
        old_epoch = self.admin.query("SELECT value FROM auth.epoch")[0]
        self.issue(self.begin())
        self.assertEqual(self.values(), ["A1"])
        self.a.query("COMMIT")
        dump = subprocess.run(
            ["docker", "exec", "-e", "PGPASSWORD="+PASSWORDS["postgres"], NAME,
             "pg_dump", "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres",
             "--data-only", "--table=auth.epoch", "--table=auth.binding",
             "--table=auth.membership", "--format=custom"],
            check=True, capture_output=True).stdout
        self.admin.query("UPDATE auth.membership SET active=false,revision=revision+1 WHERE principal='alice' AND tenant='A' AND bu='1'")
        self.admin.query("UPDATE auth.epoch SET value=gen_random_uuid()")
        expected_epoch = self.admin.query("SELECT value FROM auth.epoch")[0]
        broker, tokens = self.broker()
        self.assertNotEqual(old_epoch, expected_epoch)
        try:
            self.admin.query("TRUNCATE auth.binding,auth.membership,auth.epoch")
            subprocess.run(
                ["docker", "exec", "-i", "-e", "PGPASSWORD="+PASSWORDS["postgres"], NAME,
                 "pg_restore", "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres",
                 "--data-only", "--exit-on-error"], input=dump, check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            self.assertEqual(self.admin.query("SELECT value FROM auth.epoch"), [old_epoch])
            self.assertEqual(self.admin.query(
                "SELECT active FROM auth.membership WHERE principal='alice' AND tenant='A' AND bu='1'"), ["t"])
            with self.assertRaisesRegex(Denied, "^denied$"):
                broker.execute(tokens["alice"], "A", "1", "list_items")
            self.begin()
            self.assertEqual(self.values(), [])
            self.a.query("ROLLBACK")
        finally:
            # Restore stays quarantined until authority is reconciled and epoch
            # rotated. Synthetic operator explicitly restores known-good state.
            self.admin.query("UPDATE auth.membership SET active=true,revision=revision+1 WHERE principal='alice' AND tenant='A' AND bu='1'")
            self.admin.query("UPDATE auth.epoch SET value=gen_random_uuid()")
        replacement, new_tokens = self.broker()
        self.assertEqual(replacement.execute(new_tokens["alice"], "A", "1", "list_items"), ["A1"])

    def test_p04_scope_login_cannot_signal_foreign_backend(self):
        a = self.open("proof_a1")
        b = self.open("proof_b1")
        pid, _ = self.begin(b)
        a.query(f"SELECT pg_cancel_backend({pid})", "42501")
        a.query(f"SELECT pg_terminate_backend({pid})", "42501")
        self.issue((pid, b.query("SELECT pg_current_xact_id()")[0]), tenant="B", issuer=self.ib)
        self.assertEqual(self.values(b), ["B1"])
        b.query("ROLLBACK")

    def test_p04_runtime_cannot_read_recovery_epoch_function(self):
        for role in ("proof_runtime", "proof_a1", "proof_b1"):
            scoped = self.open(role)
            scoped.query("SELECT auth.current_epoch()", "42501")

    def test_p08_broker_authenticates_and_binds_fresh_sessions(self):
        broker, tokens = self.broker()
        self.assertEqual(broker.execute(tokens["alice"], "A", "1", "list_items"), ["A1"])
        self.assertEqual(broker.execute(tokens["alice"], "A", "2", "list_notes"), ["note-A2"])
        self.assertEqual(broker.execute(tokens["bob"], "B", "1", "list_items"), ["B1"])
        self.assertEqual(broker.execute(tokens["bob"], "B", "2", "list_items"), ["B2"])

    def test_p08_broker_denies_bad_credentials_scope_and_operation(self):
        broker, tokens = self.broker()
        for token, tenant, bu, op in (
            ("invalid", "A", "1", "list_items"),
            (secrets.token_hex(32), "A", "1", "list_items"),
            (tokens["alice"], "B", "1", "list_items"),
            (tokens["bob"], "A", "2", "list_items"),
            (tokens["alice"], "A", "*", "list_items"),
            (tokens["alice"], "A", "1", "SELECT * FROM auth.binding"),
            (tokens["alice"], "A", "1", ["list_items"]),
        ):
            with self.assertRaisesRegex(Denied, "^denied$"):
                broker.execute(token, tenant, bu, op)
        self.assertEqual(broker.execute(tokens["alice"], "A", "1", "list_items"), ["A1"])

    def test_p08_broker_rejects_caller_target_injection(self):
        broker, tokens = self.broker()
        for extra in ({"actor": "bob"}, {"target_pid": 1}, {"target_xid": "42"},
                      {"role": "postgres"}, {"sql": "SELECT 1"}, {"connection": self.a}):
            with self.assertRaises(TypeError):
                broker.execute(tokens["alice"], "A", "1", "list_items", **extra)

    def test_p08_broker_revoked_membership_denied(self):
        broker, tokens = self.broker()
        try:
            self.admin.query("UPDATE auth.membership SET active=false,revision=revision+1 WHERE principal='alice' AND tenant='A' AND bu='1'")
            with self.assertRaises(Denied):
                broker.execute(tokens["alice"], "A", "1", "list_items")
            self.assertEqual(broker.execute(tokens["alice"], "A", "2", "list_items"), ["A2"])
        finally:
            self.admin.query("UPDATE auth.membership SET active=true,revision=revision+1 WHERE principal='alice' AND tenant='A' AND bu='1'")

    def test_p08_broker_disposes_connections_on_success_and_failure(self):
        opened = []
        def factory(role):
            session = Session(role)
            opened.append(session)
            return session
        broker, tokens = self.broker(factory)
        self.assertEqual(broker.execute(tokens["alice"], "A", "1", "list_items"), ["A1"])
        with self.assertRaises(Denied):
            broker.execute(tokens["alice"], "B", "1", "list_items")
        self.assertEqual(len(opened), 4)
        self.assertTrue(all(s.p.poll() is not None for s in opened))

    def test_p04_scope_login_rejects_foreign_issuance_and_role_switch(self):
        scoped = self.open("proof_a1")
        binding = self.begin(scoped)
        self.issue(binding, tenant="B", issuer=self.ib, state="42501")
        self.issue(binding, bu="2", state="42501")
        self.assertEqual(self.values(scoped), [])
        self.issue(binding)
        self.assertEqual(self.values(scoped), ["A1"])
        scoped.query("SAVEPOINT denied")
        scoped.query("SET ROLE proof_b1", "42501")
        scoped.query("ROLLBACK TO denied")
        scoped.query("SET SESSION AUTHORIZATION proof_b1", "42501")
        scoped.query("ROLLBACK TO denied")
        scoped.query("INSERT INTO crm.item VALUES ('B','1',9,'bad')", "42501")
        scoped.query("ROLLBACK TO denied")
        self.assertEqual(self.values(scoped), ["A1"])
        scoped.query("ROLLBACK")

    def test_p04_scope_login_cannot_mint_context_or_read_authority(self):
        scoped = self.open("proof_b2")
        binding = self.begin(scoped)
        self.issue(binding, tenant="B", bu="2", issuer=self.ib)
        self.assertEqual(self.values(scoped), ["B2"])
        scoped.query("SAVEPOINT denied")
        self.issue(binding, tenant="B", bu="2", issuer=scoped, state="42501")
        scoped.query("ROLLBACK TO denied")
        scoped.query("SELECT * FROM auth.scope_login", "42501")
        scoped.query("ROLLBACK TO denied")
        scoped.query("SELECT query FROM pg_catalog.pg_stat_activity", "42501")
        scoped.query("ROLLBACK")
        self.assertEqual(self.values(scoped), [])

    def test_p02_live_target_validation(self):
        pid, xid = self.begin()
        self.issue(("2147483647", xid), state="42501")
        self.issue((pid, str(int(xid) + 1)), state="42501")
        self.assertEqual(self.values(), [])
        self.issue((pid, xid))
        self.assertEqual(self.values(), ["A1"])
        self.a.query("ROLLBACK")
        self.issue((pid, xid), state="42501")

    def test_p03_session_reset_prepared_cursor_and_scope_switch(self):
        self.issue(self.begin())
        self.a.query("PREPARE scoped AS SELECT value FROM crm.item ORDER BY id")
        self.assertEqual(self.a.query("EXECUTE scoped"), ["A1"])
        self.a.query("DECLARE saved CURSOR WITH HOLD FOR SELECT value FROM crm.item")
        self.a.query("COMMIT")
        # A retained cursor is sensitive state, not a new RLS authorisation.
        self.a.reset()
        self.a.query("FETCH ALL FROM saved", "34000")
        self.a.query("EXECUTE scoped", "26000")
        self.issue(self.begin(), tenant="B", issuer=self.ib)
        self.assertEqual(self.values(), ["B1"])
        self.a.query("ROLLBACK")
        self.a.reset()
        self.assertEqual(self.values(), [])

    def test_p03_prepared_plan_rechecks_scope_without_reset(self):
        self.issue(self.begin())
        self.a.query("PREPARE scoped AS SELECT value FROM crm.item ORDER BY id")
        self.assertEqual(self.a.query("EXECUTE scoped"), ["A1"])
        self.a.query("COMMIT")
        self.assertEqual(self.a.query("EXECUTE scoped"), [])
        self.issue(self.begin(), tenant="B", issuer=self.ib)
        self.assertEqual(self.a.query("EXECUTE scoped"), ["B1"])
        self.a.query("ROLLBACK")
        self.a.reset()

    def test_p04_statistics_and_authority_role_access(self):
        self.assertEqual(self.admin.query(
            "SELECT pg_has_role('proof_runtime','pg_read_all_stats','MEMBER')"), ["f"])
        self.assertEqual(self.admin.query(
            "SELECT has_table_privilege('proof_runtime','auth.binding','SELECT')"), ["f"])
        self.assertEqual(self.admin.query(
            "SELECT has_function_privilege('proof_runtime','auth.issue(integer,xid8,text,text)','EXECUTE')"), ["f"])
        self.a.query("SET ROLE pg_read_all_stats", "42501")
        self.a.query("SELECT * FROM pg_catalog.pg_stat_activity", "42501")
        self.a.query("SELECT * FROM auth.issuer", "42501")

    def test_p05_failed_transaction_reset(self):
        self.issue(self.begin())
        self.a.query("SELECT 1/0", "22012")
        self.a.reset()
        self.assertEqual(self.values(), [])
        self.issue(self.begin(), tenant="B", issuer=self.ib)
        self.assertEqual(self.values(), ["B1"])
        self.a.query("ROLLBACK")

    def test_p06_epoch_cannot_rebind_active_transaction(self):
        binding = self.begin()
        self.issue(binding)
        self.assertEqual(self.values(), ["A1"])
        self.admin.query("UPDATE auth.epoch SET value=gen_random_uuid()")
        self.assertEqual(self.values(), [])
        self.issue(binding, tenant="B", issuer=self.ib, state="23505")
        self.assertEqual(self.values(), [])
        self.a.query("ROLLBACK")

    def test_p06_restart_invalidates_old_binding(self):
        binding = self.begin()
        self.issue(binding)
        self.assertEqual(self.values(), ["A1"])
        self.a.query("COMMIT")
        old_boot = self.admin.query("SELECT pg_postmaster_start_time()")[0]
        for session in reversed(self.sessions):
            session.close()
        self.sessions.clear()
        docker("restart", NAME, stdout=subprocess.DEVNULL)
        wait_ready()
        self.admin = self.open("postgres")
        self.a = self.open("proof_runtime")
        self.ia = self.open("proof_issuer_a")
        self.ib = self.open("proof_issuer_b")
        self.assertNotEqual(self.admin.query("SELECT pg_postmaster_start_time()")[0], old_boot)
        self.assertEqual(self.admin.query("SELECT count(*)>0 FROM auth.binding"), ["t"])
        self.begin()
        self.assertEqual(self.values(), [])
        self.a.query("ROLLBACK")
        self.issue(self.begin())
        self.assertEqual(self.values(), ["A1"])
        self.a.query("ROLLBACK")

    def test_p01_absent_context_and_spoofed_settings(self):
        self.begin()
        self.assertEqual(self.values(), [])
        self.a.query("SET LOCAL crm.tenant='A'")
        self.a.query("SET LOCAL crm.bu='1'")
        self.assertEqual(self.values(), [])

    def test_p01_cross_scope_crud_and_join(self):
        self.issue(self.begin())
        self.assertEqual(self.values(), ["A1"])
        self.assertEqual(self.a.query("SELECT n.value FROM crm.note n JOIN crm.item i USING(tenant,bu)"), ["note-A1"])
        self.assertEqual(self.a.query("UPDATE crm.item SET value='forbidden' WHERE tenant='B' RETURNING value"), [])
        self.assertEqual(self.a.query("DELETE FROM crm.item WHERE tenant='A' AND bu='2' RETURNING value"), [])
        self.a.query("SAVEPOINT denied")
        self.a.query("INSERT INTO crm.item VALUES ('B','1',9,'bad')", "42501")
        self.a.query("ROLLBACK TO denied")
        self.a.query("INSERT INTO crm.item VALUES ('A','2',9,'bad')", "42501")
        self.a.query("ROLLBACK TO denied")
        self.a.query("INSERT INTO crm.item VALUES ('A','1',9,'allowed')")
        self.assertEqual(self.a.query("UPDATE crm.item SET value='changed' WHERE id=9 RETURNING value"), ["changed"])
        self.assertEqual(self.a.query("DELETE FROM crm.item WHERE id=9 RETURNING value"), ["changed"])
        self.a.query("ROLLBACK")
        self.assertEqual(self.admin.query("SELECT value FROM crm.item ORDER BY tenant,bu,id"), ["A1","A2","B1","B2"])

    def test_p01_composite_fk_and_upsert(self):
        self.issue(self.begin())
        self.a.query("SAVEPOINT denied")
        self.a.query("INSERT INTO crm.note VALUES ('A','1',8,999,'bad')", "23503")
        self.a.query("ROLLBACK TO denied")
        self.a.query("INSERT INTO crm.item VALUES ('B','1',1,'bad') ON CONFLICT(tenant,bu,id) DO UPDATE SET value=excluded.value", "42501")
        self.a.query("ROLLBACK TO denied")
        self.a.query("UPDATE crm.item SET tenant='B' WHERE id=1", "42501")
        self.a.query("ROLLBACK")

    def test_p02_p04_runtime_cannot_issue_or_mutate_authority(self):
        binding = self.begin()
        self.a.query("SAVEPOINT denied")
        self.issue(binding, issuer=self.a, state="42501")
        self.a.query("ROLLBACK TO denied")
        self.a.query("SELECT * FROM auth.binding", "42501")
        self.a.query("ROLLBACK TO denied")
        self.a.query("UPDATE auth.membership SET active=true", "42501")
        self.a.query("ROLLBACK TO denied")
        self.a.query("SET ROLE proof_auth_owner", "42501")
        self.a.query("ROLLBACK TO denied")
        self.a.query("TRUNCATE crm.item CASCADE", "42501")
        self.a.query("ROLLBACK TO denied")
        self.a.query("CREATE TEMP TABLE binding(x int)", "42501")
        self.a.query("ROLLBACK TO denied")
        self.a.query("ALTER TABLE crm.item DISABLE ROW LEVEL SECURITY", "42501")
        self.a.query("ROLLBACK TO denied")
        self.a.query("SET LOCAL row_security=off")
        self.a.query("SELECT * FROM crm.item", "42501")
        self.a.query("ROLLBACK")

    def test_p03_p08_unique_binding_and_concurrent_sessions(self):
        binding = self.begin()
        self.issue(binding)
        self.issue(binding, bu="2", state="23505")
        self.issue(binding, tenant="B", issuer=self.ib, state="23505")
        b = self.open("proof_runtime")
        self.issue(self.begin(b), tenant="B", issuer=self.ib)
        self.assertEqual(self.values(), ["A1"])
        self.assertEqual(self.values(b), ["B1"])
        self.a.query("SAVEPOINT keep_scope")
        self.a.query("SET LOCAL crm.tenant='B'")
        self.a.query("ROLLBACK TO keep_scope")
        self.assertEqual(self.values(), ["A1"])
        self.a.query("COMMIT")
        self.begin()
        self.assertEqual(self.values(), [])
        self.a.query("ROLLBACK")
        self.assertEqual(self.values(b), ["B1"])
        b.query("ROLLBACK")

    def test_p04_catalog_query_text_denied(self):
        self.a.query("SELECT query FROM pg_catalog.pg_stat_activity", "42501")
        self.a.query("SELECT * FROM pg_catalog.pg_stat_get_activity(NULL)", "42501")
        self.assertEqual(self.admin.query(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='crm' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity"), ["2"])
        self.assertEqual(self.admin.query(
            "SELECT count(*) FROM pg_roles WHERE rolname='proof_runtime' AND NOT rolsuper "
            "AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication"), ["1"])
        self.assertEqual(self.admin.query(
            "SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='proof_runtime')"), ["0"])

    def test_p05_revocation_and_revision(self):
        self.issue(self.begin())
        self.assertEqual(self.values(), ["A1"])
        try:
            self.admin.query("UPDATE auth.membership SET active=false,revision=revision+1 WHERE principal='alice' AND tenant='A' AND bu='1'")
            self.assertEqual(self.values(), [])
            self.admin.query("UPDATE auth.membership SET active=true,revision=revision+1 WHERE principal='alice' AND tenant='A' AND bu='1'")
            self.assertEqual(self.values(), [])
        finally:
            self.admin.query("UPDATE auth.membership SET active=true WHERE principal='alice' AND tenant='A' AND bu='1'")
        self.a.query("ROLLBACK")

    def test_p05_unsupported_isolation_denied(self):
        for isolation in ("REPEATABLE READ", "SERIALIZABLE"):
            self.issue(self.begin(isolation=isolation))
            self.assertEqual(self.values(), [])
            self.a.query("ROLLBACK")

    def test_p05_expired_binding(self):
        pid, xid = self.begin()
        self.issue((pid,xid))
        self.assertEqual(self.values(), ["A1"])
        self.admin.query(f"UPDATE auth.binding SET expires=clock_timestamp()-interval '1 second' WHERE pid={pid} AND xid='{xid}'::xid8")
        self.assertEqual(self.values(), [])
        self.a.query("ROLLBACK")

    def test_p05_real_expiry_and_cursor_limitation(self):
        self.issue(self.begin())
        self.assertEqual(self.values(), ["A1"])
        self.a.query("DECLARE held CURSOR WITH HOLD FOR SELECT value FROM crm.item ORDER BY id")
        self.a.query("COMMIT")
        # A held cursor may retain previously authorised results. This is not a
        # new authorization. Never claim revocation erases already returned data.
        self.assertEqual(self.a.query("FETCH ALL FROM held"), ["A1"])
        self.a.query("CLOSE held")
        self.assertEqual(self.values(), [])
        self.issue(self.begin())
        self.assertEqual(self.values(), ["A1"])
        time.sleep(31)
        self.assertEqual(self.values(), [])
        self.a.query("ROLLBACK")

    def test_p06_epoch_rotation_invalidates_binding(self):
        self.issue(self.begin())
        self.assertEqual(self.values(), ["A1"])
        self.admin.query("UPDATE auth.epoch SET value=gen_random_uuid()")
        self.assertEqual(self.values(), [])
        self.a.query("ROLLBACK")

    def test_p08_issuer_denies_foreign_membership_and_runtime_login(self):
        binding = self.begin()
        self.issue(binding, tenant="B", issuer=self.ia, state="42501")
        self.issue(binding, tenant="A", issuer=self.ib, state="42501")
        self.assertEqual(self.values(), [])
        self.issue(binding)
        self.assertEqual(self.values(), ["A1"])
        self.a.query("ROLLBACK")


def wait_ready():
    for _ in range(60):
        ready = subprocess.run(["docker", "exec", NAME, "pg_isready", "-h", "127.0.0.1"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ready.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("PostgreSQL did not become ready")


def main():
    # The only accepted image is the digest verified in Run #10.
    docker("pull", IMAGE, stdout=subprocess.DEVNULL)
    digest = docker("image", "inspect", "--format", "{{index .RepoDigests 0}}",
                    IMAGE, capture_output=True).stdout.strip()
    if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", digest):
        raise RuntimeError("missing immutable image digest")
    if digest.split("@", 1)[1] != PINNED_IMAGE.split("@", 1)[1]:
        raise RuntimeError("PostgreSQL digest mismatch")
    print("PostgreSQL image:", digest, flush=True)
    try:
        docker("run", "-d", "--network", "none", "--name", NAME,
               "-e", "POSTGRES_PASSWORD=" + PASSWORDS["postgres"],
               "-e", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
               digest, stdout=subprocess.DEVNULL)
        wait_ready()
        args = command("postgres") + ["-v","ON_ERROR_STOP=1",
                 "-v","runtime_pw="+PASSWORDS["proof_runtime"],
                 "-v","issuer_a_pw="+PASSWORDS["proof_issuer_a"],
                 "-v","issuer_b_pw="+PASSWORDS["proof_issuer_b"]]
        for role in ("proof_a1", "proof_a2", "proof_b1", "proof_b2"):
            args.extend(["-v", role+"_pw="+PASSWORDS[role]])
        setup = subprocess.run(args, input=(ROOT / "bootstrap.sql").read_text(),
                               text=True, capture_output=True)
        if setup.returncode:
            # Do not emit raw bootstrap diagnostics containing password literals.
            raise RuntimeError("bootstrap SQL failed; reproduce with disposable local credentials")
        with_version = subprocess.run(command("postgres")+["-c","SHOW server_version"],
                                      text=True, check=True, capture_output=True)
        print("Server:", with_version.stdout.strip(), "merge SHA:", os.environ.get("GITHUB_SHA", "local"),
              "PR head:", os.environ.get("PROOF_PR_HEAD", "local"), flush=True)
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Boundary))
        if not result.wasSuccessful() or result.skipped or result.testsRun != 39:
            raise SystemExit(1)
    finally:
        subprocess.run(["docker","rm","-f",NAME],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
