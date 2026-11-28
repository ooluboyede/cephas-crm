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
from actor_broker import ActorBroker
from oidc_boundary import OIDCVerifier, SessionGate
from oidc_fixture import TestIdP
from licence_bridge import ReadEntitlement
from independent_authority import R2Proof, AuthorityDenied
from recovery_state import RecoveryState, initialize, advance, read_state

ROOT = Path(__file__).resolve().parent
NAME = "cephas-proof-" + secrets.token_hex(6)
AUTHORITY_NAME = NAME + "-authority"
AUTHORITY_PASSWORD = secrets.token_hex(24)
PASSWORDS = {role: secrets.token_hex(24) for role in
             ("postgres", "proof_runtime", "proof_issuer_a", "proof_issuer_b",
              "proof_a1", "proof_a2", "proof_b1", "proof_b2",
              "proof_alice_a1", "proof_charlie_a1", "proof_bob_b1")}
PINNED_IMAGE = "postgres@sha256:64c8b0d31e4ab6ea665e8426ea406a94bf52de3c05b3a4a8bf713704eefa9328"
IMAGE = os.environ.get("PROOF_POSTGRES_IMAGE", PINNED_IMAGE)
if IMAGE != PINNED_IMAGE:
    raise RuntimeError("unreviewed PostgreSQL image override")


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, text=True, **kwargs)


def command(role, container=NAME, password=None):
    return ["docker", "exec", "-i", "-e", "PGPASSWORD=" + (PASSWORDS[role] if password is None else password),
            "-e", "PGOPTIONS=-c client_min_messages=error",
            container, "psql", "-X", "-qAt", "-h", "127.0.0.1", "-U", role,
            "-d", "postgres", "-P", "pager=off"]


class Session:
    def __init__(self, role, container=NAME, password=None):
        self.p = subprocess.Popen(command(role, container, password), stdin=subprocess.PIPE,
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

    def actor_epoch(self):
        return self.admin.query("SELECT value FROM auth.epoch")[0]

    def test_f01_legacy_issuer_cannot_target_actor_connections(self):
        alice = self.open("proof_alice_a1")
        charlie = self.open("proof_charlie_a1")
        for target in (alice, charlie):
            binding = self.begin(target)
            self.issue(binding, state="42501")
            self.assertEqual(self.values(target), [])
            target.query("ROLLBACK")

    def test_f01_same_scope_actor_binding_and_revocation(self):
        alice = self.open("proof_alice_a1")
        charlie = self.open("proof_charlie_a1")
        epoch = self.actor_epoch()
        for target in (alice, charlie):
            self.begin(target)
            target.query(f"SELECT auth.bind_self('A','1','{epoch}')")
            self.assertEqual(self.values(target), ["A1"])
        self.admin.query("UPDATE auth.membership SET active=false,revision=revision+1 WHERE principal='alice' AND tenant='A' AND bu='1'")
        try:
            self.assertEqual(self.values(alice), [])
            self.assertEqual(self.values(charlie), ["A1"])
        finally:
            alice.query("ROLLBACK")
            charlie.query("ROLLBACK")
            self.admin.query("UPDATE auth.membership SET active=true,revision=revision+1 WHERE principal='alice' AND tenant='A' AND bu='1'")

    def test_f01_actor_cannot_switch_or_issue_foreign_context(self):
        actor = self.open("proof_alice_a1")
        victim = self.open("proof_charlie_a1")
        binding = self.begin(victim)
        self.issue(binding, issuer=actor, state="42501")
        actor.query("SET ROLE proof_charlie_a1", "42501")
        actor.query("SET SESSION AUTHORIZATION proof_charlie_a1", "42501")
        self.begin(actor)
        actor.query(f"SELECT auth.bind_self('B','1','{self.actor_epoch()}')", "42501")
        actor.query("ROLLBACK")
        self.assertEqual(self.values(victim), [])
        victim.query("ROLLBACK")

    def test_f01_self_binding_one_transaction_and_read_only(self):
        actor = self.open("proof_alice_a1")
        epoch = self.actor_epoch()
        self.begin(actor)
        actor.query(f"SELECT auth.bind_self('A','1','{epoch}')")
        self.assertEqual(self.values(actor), ["A1"])
        actor.query(f"SELECT auth.bind_self('A','1','{epoch}')", "23505")
        actor.query("ROLLBACK")
        self.assertEqual(self.values(actor), [])
        self.begin(actor)
        actor.query(f"SELECT auth.bind_self('A','1','{epoch}')")
        actor.query("UPDATE crm.item SET value='no'", "42501")
        actor.query("ROLLBACK")

    def test_f01_actor_broker_selects_connection_from_authenticated_identity(self):
        tokens = {a: secrets.token_hex(32) for a in ("alice","charlie","bob")}
        epoch = self.actor_epoch()
        state = RecoveryState(1, epoch)
        broker = ActorBroker(tokens, Session, lambda: state)
        self.assertEqual(broker.execute(tokens["alice"],"A","1","list_items"),["A1"])
        self.assertEqual(broker.execute(tokens["charlie"],"A","1","list_notes"),["note-A1"])
        self.assertEqual(broker.execute(tokens["bob"],"B","1","list_items"),["B1"])
        with self.assertRaises(Denied):
            broker.execute(tokens["alice"],"B","1","list_items")
        with self.assertRaises(Denied):
            broker.execute("0"*64,"A","1","list_items")

    def test_f01_broker_rejects_substituted_same_scope_connection(self):
        tokens = {a: secrets.token_hex(32) for a in ("alice","charlie","bob")}
        state = RecoveryState(1,self.actor_epoch())
        def substitute(role):
            return Session("proof_charlie_a1" if role=="proof_alice_a1" else role)
        broker = ActorBroker(tokens, substitute, lambda: state)
        with self.assertRaises(Denied):
            broker.execute(tokens["alice"],"A","1","list_items")

    def test_f01_same_actor_sessions_do_not_share_binding(self):
        first = self.open("proof_alice_a1")
        second = self.open("proof_alice_a1")
        epoch = self.actor_epoch()
        self.begin(first)
        self.begin(second)
        first.query(f"SELECT auth.bind_self('A','1','{epoch}')")
        self.assertEqual(self.values(first), ["A1"])
        self.assertEqual(self.values(second), [])
        second.query(f"SELECT auth.bind_self('A','1','{epoch}')")
        first.query("ROLLBACK")
        self.assertEqual(self.values(second), ["A1"])
        second.query("ROLLBACK")

    def test_f01_concurrent_actor_broker_requests(self):
        from threading import Barrier
        tokens = {a: secrets.token_hex(32) for a in ("alice","charlie","bob")}
        state = RecoveryState(1,self.actor_epoch())
        barrier = Barrier(3, timeout=10)
        broker = ActorBroker(tokens,Session,lambda: state)
        def call(actor,tenant,operation):
            barrier.wait()
            return broker.execute(tokens[actor],tenant,"1",operation)
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(call,*args) for args in (
                ("alice","A","list_items"),("charlie","A","list_notes"),("bob","B","list_items"))]
            self.assertEqual([future.result(timeout=20) for future in futures],
                             [["A1"],["note-A1"],["B1"]])

    def test_f01_broker_detects_same_role_transaction_replacement(self):
        tokens = {a: secrets.token_hex(32) for a in ("alice","charlie","bob")}
        state = RecoveryState(1,self.actor_epoch())
        class ReplaceAfterRead(Session):
            def query(self, sql, state_code="00000"):
                rows = super().query(sql,state_code)
                if sql.startswith("SELECT value FROM crm.item"):
                    super().query("ROLLBACK")
                    super().query("BEGIN ISOLATION LEVEL READ COMMITTED")
                    super().query(f"SELECT auth.bind_self('A','1','{state.epoch}')")
                return rows
        broker = ActorBroker(tokens,ReplaceAfterRead,lambda: state)
        with self.assertRaises(Denied):
            broker.execute(tokens["alice"],"A","1","list_items")

    def test_f01_actor_authority_tables_and_legacy_binding_denied(self):
        actor = self.open("proof_alice_a1")
        actor.query("SELECT * FROM auth.actor_login", "42501")
        actor.query("SELECT * FROM auth.binding", "42501")
        actor.query("UPDATE auth.membership SET active=true", "42501")
        actor.query("SELECT auth.current_epoch()", "42501")
        self.ia.query(f"SELECT auth.bind_self('A','1','{self.actor_epoch()}')", "42501")
        self.a.query(f"SELECT auth.bind_self('A','1','{self.actor_epoch()}')", "42501")

    def r2_fixture(self):
        authority = Session("postgres", AUTHORITY_NAME, AUTHORITY_PASSWORD)
        self.sessions.append(authority)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return R2Proof(self.admin, authority, Path(directory.name) / "local.sqlite")

    def test_f02_f03_external_head_rejects_coordinated_restore(self):
        r = self.r2_fixture()
        original = r.local.read_bytes()
        dump = subprocess.run(["docker","exec","-e","PGPASSWORD="+PASSWORDS["postgres"],NAME,
            "pg_dump","-h","127.0.0.1","-U","postgres","-d","postgres","--data-only",
            "--table=r2.epoch","--table=r2.effect","--table=r2.outbox","--format=custom"],
            check=True,capture_output=True).stdout
        r.mutate("event1")
        r.quarantine()
        r.reconcile_epoch()
        r.activate(r.external().epoch)
        self.assertEqual(r.guard().sequence,2)
        self.admin.query("TRUNCATE r2.effect,r2.outbox,r2.epoch")
        subprocess.run(["docker","exec","-i","-e","PGPASSWORD="+PASSWORDS["postgres"],NAME,
            "pg_restore","-h","127.0.0.1","-U","postgres","-d","postgres","--data-only","--exit-on-error"],
            input=dump,check=True,capture_output=True)
        r.local.write_bytes(original)
        with self.assertRaises(AuthorityDenied):
            r.guard()
        with self.assertRaises(AuthorityDenied):
            r.mutate("event2")
        self.assertEqual(r.external().sequence,2)

    def test_f02_quarantine_interrupted_cutover_requires_reconciliation(self):
        r = self.r2_fixture()
        r.mutate("event1")
        r.quarantine()
        with self.assertRaises(AuthorityDenied):
            r.guard()
        with self.assertRaises(AuthorityDenied):
            r.activate(r.external().epoch)
        r.reconcile_epoch()
        with self.assertRaises(AuthorityDenied):
            r.guard()
        r.activate(r.external().epoch)
        self.assertEqual(r.guard().sequence,2)

    def test_f03_tamper_truncate_and_fork_detected(self):
        r = self.r2_fixture()
        r.mutate("event1")
        r.mutate("event2")
        self.admin.query("UPDATE r2.outbox SET payload='{}' WHERE seq=1")
        with self.assertRaises(AuthorityDenied):
            r.guard()
        self.admin.query("DELETE FROM r2.outbox")
        with self.assertRaises(AuthorityDenied):
            r.guard()
        with self.assertRaises(AuthorityDenied):
            r.mutate("event3")

    def test_f03_atomic_effect_and_outbox_rollback(self):
        r = self.r2_fixture()
        self.admin.query("BEGIN")
        self.admin.query("SELECT r2.apply('rollback1')")
        self.admin.query("ROLLBACK")
        self.assertEqual(r.guard().audit_sequence,0)
        self.assertEqual(self.admin.query("SELECT count(*) FROM r2.effect"),["0"])
        self.assertEqual(r.mutate("event1").audit_sequence,1)
        self.assertEqual(self.admin.query("SELECT count(*) FROM r2.effect"),["1"])

    def test_f02_f03_unanchored_commit_denies_until_operator_recovery(self):
        r = self.r2_fixture()
        self.admin.query("SELECT r2.apply('unanchored')")
        with self.assertRaises(AuthorityDenied):
            r.guard()
        with self.assertRaises(AuthorityDenied):
            r.mutate("event2")
        r.quarantine()
        with self.assertRaises(AuthorityDenied):
            r.reconcile_epoch()
        self.assertEqual(r.external().audit_sequence,0)

    def test_f02_authority_unavailable_and_runtime_access_denied(self):
        r = self.r2_fixture()
        self.a.query("SELECT * FROM r2.outbox","42501")
        self.a.query("SELECT r2.apply('forbidden')","42501")
        r.authority.query("DROP SCHEMA anchor CASCADE")
        with self.assertRaises(AuthorityDenied):
            r.guard()
        with self.assertRaises(AuthorityDenied):
            r.mutate("event1")

    def test_f03_receipt_tamper_and_unsigned_head_denied(self):
        r = self.r2_fixture()
        r.mutate("event1")
        head=r.external()
        r.authority.query("UPDATE anchor.head SET digest=repeat('a',64)")
        with self.assertRaises(AuthorityDenied):
            r.guard()
        r.authority.query(f"UPDATE anchor.head SET digest='{head.digest}'")
        self.assertEqual(r.guard(),head)
        r.authority.query("UPDATE anchor.receipt SET signature=repeat('0',128) WHERE revision=2")
        with self.assertRaises(AuthorityDenied):
            r.external()

    def test_f03_valid_old_receipt_replay_denied_by_live_floor(self):
        r = self.r2_fixture()
        r.mutate("event1")
        r.authority.query("DELETE FROM anchor.receipt WHERE revision=2")
        r.authority.query("UPDATE anchor.head SET audit_seq=0,digest=repeat('0',64)")
        self.admin.query("TRUNCATE r2.effect,r2.outbox")
        with self.assertRaises(AuthorityDenied):
            r.guard()

    def test_f03_rehashed_audit_fork_denied(self):
        r = self.r2_fixture()
        r.mutate("event1")
        r.mutate("event2")
        # Rewrite a valid-looking complete history with the same event count.
        self.admin.query("TRUNCATE r2.effect,r2.outbox")
        self.admin.query("SELECT r2.apply('fork1')")
        self.admin.query("SELECT r2.apply('fork2')")
        with self.assertRaises(AuthorityDenied):
            r.guard()

    def test_f02_stale_activation_epoch_denied(self):
        r = self.r2_fixture()
        previous=r.external().epoch
        expected=r.quarantine()
        r.reconcile_epoch()
        with self.assertRaises(AuthorityDenied):
            r.activate(previous)
        self.assertEqual(r.external().phase,"quarantine")
        r.activate(expected)
        self.assertEqual(r.guard().epoch,expected)

    def test_f02_concurrent_mutation_and_quarantine_are_serialized(self):
        from copy import copy
        from threading import Barrier
        r = self.r2_fixture()
        other = copy(r)
        other.primary = self.open("postgres")
        other.authority = Session("postgres",AUTHORITY_NAME,AUTHORITY_PASSWORD)
        self.sessions.append(other.authority)
        barrier=Barrier(2,timeout=10)
        def mutate():
            barrier.wait()
            try:
                r.mutate("race1")
                return "committed"
            except AuthorityDenied:
                return "denied"
        def quarantine():
            barrier.wait()
            return other.quarantine()
        with ThreadPoolExecutor(max_workers=2) as pool:
            m=pool.submit(mutate)
            q=pool.submit(quarantine)
            outcome=m.result(timeout=25)
            epoch=q.result(timeout=25)
        self.assertEqual(r.external().phase,"quarantine")
        self.assertEqual(r.external().epoch,epoch)
        self.assertEqual(r.external().audit_sequence,1 if outcome=="committed" else 0)
        with self.assertRaises(AuthorityDenied):
            r.mutate("after_fence")
        other.reconcile_epoch()
        other.activate(epoch)
        self.assertEqual(other.guard().phase,"active")

    def r2_resume(self,r):
        authority=Session("postgres",AUTHORITY_NAME,AUTHORITY_PASSWORD)
        self.sessions.append(authority)
        return R2Proof.resume(self.admin,authority,r.local,r.deployment,r.public,r.signer)

    def test_f02_receipt_floor_survives_reconstruction_and_old_head_replay(self):
        r=self.r2_fixture()
        r.mutate("event1")
        restarted=self.r2_resume(r)
        self.assertEqual(restarted.guard().audit_sequence,1)
        self.assertEqual(restarted.witness.read()[0],2)
        r.authority.query("DELETE FROM anchor.receipt WHERE revision=2")
        r.authority.query("UPDATE anchor.head SET audit_seq=0,digest=repeat('0',64)")
        self.admin.query("TRUNCATE r2.effect,r2.outbox")
        with self.assertRaises(AuthorityDenied):
            self.r2_resume(r)
        with self.assertRaises(AuthorityDenied):
            restarted.guard()

    def test_f02_missing_or_corrupted_witness_denies_restart(self):
        r=self.r2_fixture()
        r.witness.path.unlink()
        with self.assertRaises(AuthorityDenied):
            self.r2_resume(r)
        r.witness.path.write_bytes(b"not sqlite")
        with self.assertRaises(AuthorityDenied):
            self.r2_resume(r)

    def test_f02_witness_first_interrupted_authority_commit_blocks_restart(self):
        r=self.r2_fixture()
        class Interrupted:
            def query(self,sql):
                if sql=="COMMIT":
                    r_original.query("ROLLBACK")
                    raise RuntimeError("simulated interrupted commit")
                return r_original.query(sql)
        r_original=r.authority
        r.authority=Interrupted()
        with self.assertRaises(AuthorityDenied):
            r.quarantine()
        r.authority=r_original
        self.assertEqual(r.witness.read()[0],2)
        self.assertEqual(r.authority.query("SELECT max(revision) FROM anchor.receipt"),["1"])
        with self.assertRaises(AuthorityDenied):
            self.r2_resume(r)
        with self.assertRaises(AuthorityDenied):
            r.guard()

    def test_f02_interrupted_epoch_reconciliation_can_resume_under_quarantine(self):
        r=self.r2_fixture()
        epoch=r.quarantine()
        # Simulate committed primary epoch update before local journal advance.
        self.admin.query("BEGIN")
        self.admin.query(f"UPDATE r2.epoch SET value='{epoch}'")
        self.admin.query(f"UPDATE auth.epoch SET value='{epoch}'")
        self.admin.query("COMMIT")
        restarted=self.r2_resume(r)
        with self.assertRaises(AuthorityDenied):
            restarted.guard()
        restarted.reconcile_epoch()
        restarted.activate(epoch)
        self.assertEqual(restarted.guard().epoch,epoch)

    def test_f02_actor_read_requires_live_fence_and_matching_epoch(self):
        r=self.r2_fixture()
        tokens={a:secrets.token_hex(32) for a in ("alice","charlie","bob")}
        def read():
            return r.fenced_read(tokens,Session,tokens["alice"],"A","1","list_items")
        self.assertEqual(read(),["A1"])
        epoch=r.quarantine()
        with self.assertRaises(AuthorityDenied):
            read()
        r.reconcile_epoch()
        r.activate(epoch)
        self.assertEqual(read(),["A1"])
        self.admin.query("UPDATE auth.epoch SET value=gen_random_uuid()")
        with self.assertRaises(AuthorityDenied):
            read()

    def test_f02_witness_identity_and_compare_append_are_pinned(self):
        from receipt_floor import ReceiptFloor
        r=self.r2_fixture()
        floor=r.witness.read()
        wrong=ReceiptFloor(r.witness.path,str(uuid.uuid4()),r.public)
        with self.assertRaises(ValueError):
            wrong.read()
        r.mutate("event1")
        with self.assertRaises(ValueError):
            r.witness.append(floor,[(2,"a"*64)])
        self.assertEqual(r.witness.read()[0],2)

    def test_f02_retained_quarantine_commit_repaired_without_floor_reset(self):
        r=self.r2_fixture()
        original=r.authority
        class Interrupted:
            def query(self,sql):
                if sql=="COMMIT":
                    original.query("ROLLBACK")
                    raise RuntimeError("simulated interrupted commit")
                return original.query(sql)
        r.authority=Interrupted()
        with self.assertRaises(AuthorityDenied):
            r.quarantine()
        r.authority=original
        retained=r.witness.read()
        with self.assertRaises(AuthorityDenied):
            r.recover_quarantine_receipt("a"*64)
        head=r.recover_quarantine_receipt(retained[1])
        self.assertEqual(head.phase,"quarantine")
        self.assertEqual(r.witness.read(),retained)
        with self.assertRaises(AuthorityDenied):
            r.guard()
        restarted=self.r2_resume(r)
        restarted.reconcile_epoch()
        restarted.activate(head.epoch)
        self.assertEqual(restarted.guard().sequence,2)

    def test_f02_retained_receipt_tamper_blocks_repair(self):
        r=self.r2_fixture()
        original=r.authority
        class Interrupted:
            def query(self,sql):
                if sql=="COMMIT":
                    original.query("ROLLBACK")
                    raise RuntimeError("interrupted")
                return original.query(sql)
        r.authority=Interrupted()
        with self.assertRaises(AuthorityDenied):
            r.quarantine()
        r.authority=original
        expected=r.witness.read()
        db=sqlite3.connect(r.witness.path)
        try:
            db.execute("UPDATE floor SET signature=zeroblob(64) WHERE revision=2")
            db.commit()
        finally:
            db.close()
        with self.assertRaises(AuthorityDenied):
            r.recover_quarantine_receipt(expected[1])

    def test_f02_unanchored_mutation_cannot_be_repaired_as_quarantine(self):
        r=self.r2_fixture()
        original=r.authority
        class Interrupted:
            def query(self,sql):
                if sql=="COMMIT":
                    original.query("ROLLBACK")
                    raise RuntimeError("interrupted")
                return original.query(sql)
        r.authority=Interrupted()
        with self.assertRaises(AuthorityDenied):
            r.mutate("event1")
        r.authority=original
        with self.assertRaises(AuthorityDenied):
            r.recover_quarantine_receipt(r.witness.read()[1])
        with self.assertRaises(AuthorityDenied):
            r.guard()

    def test_f03_rotation_certificate_requires_both_keys_and_current_floor(self):
        import hashlib
        from authority_receipt import TestSigner, canonical, verify_rotation, ROTATION_DOMAIN
        r=self.r2_fixture()
        with tempfile.TemporaryDirectory() as d:
            replacement=TestSigner(Path(d))
            floor=r.witness.read()
            raw=canonical({"version":1,"deployment":r.deployment,"generation":2,
                "revision":floor[0],"receipt_digest":floor[1],
                "old_fingerprint":hashlib.sha256(r.public).hexdigest(),
                "new_fingerprint":hashlib.sha256(replacement.public).hexdigest()})
            old=r.signer.sign(raw,ROTATION_DOMAIN)
            new=replacement.sign(raw,ROTATION_DOMAIN)
            self.assertEqual(verify_rotation(raw,old,new,r.public,replacement.public,r.deployment,1,floor),2)
            for args in ((old,b"0"*64,r.public,replacement.public,r.deployment,1,floor),
                         (old,new,r.public,replacement.public,r.deployment,2,floor),
                         (old,new,r.public,replacement.public,r.deployment,1,(2,"a"*64)),
                         (old,new,r.public,replacement.public,str(uuid.uuid4()),1,floor)):
                with self.assertRaises(Exception):
                    verify_rotation(raw,*args)
            # Ordinary receipt signatures cannot authorize rotation.
            with self.assertRaises(Exception):
                verify_rotation(raw,r.signer.sign(raw),new,r.public,replacement.public,r.deployment,1,floor)

    def oidc_fixture(self,entitlement=None):
        r=self.r2_fixture()
        now=[1800000000]
        idp=TestIdP(r.local.parent,"key1")
        issuer="https://idp.example.invalid/realms/proof"
        verifier=OIDCVerifier(issuer,"cephas-crm-proof",lambda:now[0])
        verifier.install_keys(1,{"keys":[idp.jwk]},60)
        principals={(issuer,"subject-alice"):"alice",(issuer,"subject-charlie"):"charlie",
                    (issuer,"subject-bob"):"bob"}
        tokens={a:secrets.token_hex(32) for a in ("alice","charlie","bob")}
        gate=SessionGate(verifier,principals,tokens,r,Session,exchange=idp.exchange,entitlement=entitlement)
        def claims(expected_nonce,**changes):
            value={"iss":issuer,"aud":"cephas-crm-proof","sub":"subject-alice",
                   "nonce":expected_nonce,"iat":now[0],"exp":now[0]+120,"auth_time":now[0],
                   "acr":"urn:cephas:proof:mfa"}
            value.update(changes)
            return value
        return r,now,idp,verifier,gate,claims

    def test_f05_signed_identity_maps_immutable_subject_and_fenced_scope(self):
        r,now,idp,verifier,gate,claims=self.oidc_fixture()
        state,nonce=gate.begin()
        session=gate.complete(state,idp.token(claims(nonce,email="bob@example.invalid",
                                                    tenant="B",role="admin")))
        self.assertEqual(gate.execute(session,"A","1","list_items"),["A1"])
        with self.assertRaises(Denied):
            gate.execute(session,"B","1","list_items")
        gate.logout(session)
        with self.assertRaises(Denied):
            gate.execute(session,"A","1","list_items")

    def test_f05_invalid_issuer_audience_nonce_time_and_subject_rejected(self):
        r,now,idp,verifier,gate,claims=self.oidc_fixture()
        for change in ({"iss":"https://foreign.invalid"},{"aud":"wrong"},{"azp":"wrong"},
                       {"nonce":"wrong"},{"exp":now[0]},{"iat":now[0]+1},
                       {"nbf":now[0]+1},{"sub":"unregistered"}):
            state,nonce=gate.begin()
            with self.assertRaises(Denied):
                gate.complete(state,idp.token(claims(nonce,**change)))
            with self.assertRaises(Denied):
                gate.complete(state,idp.token(claims(nonce)))

    def test_f05_invalid_signature_algorithm_and_token_key_rejected(self):
        r,now,idp,verifier,gate,claims=self.oidc_fixture()
        for header in ({"alg":"none","kid":"key1"},{"alg":"HS256","kid":"key1"},
                       {"alg":"RS256","kid":"unknown"},{"alg":"RS256","kid":"key1","jku":"https://foreign.invalid"}):
            state,nonce=gate.begin()
            with self.assertRaises(Denied):
                gate.complete(state,idp.token(claims(nonce),header))
        state,nonce=gate.begin()
        token=idp.token(claims(nonce))
        parts=token.split(".")
        parts[2]=("A" if parts[2][0]!="A" else "B")+parts[2][1:]
        with self.assertRaises(Denied):
            gate.complete(state,".".join(parts))

    def test_f05_key_rotation_stale_cache_and_clock_rollback_denied(self):
        r,now,idp,verifier,gate,claims=self.oidc_fixture()
        state,nonce=gate.begin()
        old=gate.complete(state,idp.token(claims(nonce)))
        new=TestIdP(r.local.parent,"key2")
        verifier.install_keys(2,{"keys":[new.jwk]},60)
        with self.assertRaises(Denied):
            gate.execute(old,"A","1","list_items")
        with self.assertRaises(Denied):
            verifier.install_keys(2,{"keys":[idp.jwk]},60)
        state,nonce=gate.begin()
        current=gate.complete(state,new.token(claims(nonce)))
        self.assertEqual(gate.execute(current,"A","1","list_items"),["A1"])
        now[0]+=60
        with self.assertRaises(Denied):
            gate.execute(current,"A","1","list_items")
        now[0]-=1
        with self.assertRaises(Denied):
            verifier.install_keys(3,{"keys":[new.jwk]},60)

    def test_f05_mfa_and_one_time_callback_state(self):
        r,now,idp,verifier,gate,claims=self.oidc_fixture()
        state,nonce=gate.begin()
        token=idp.token(claims(nonce,acr="urn:cephas:proof:password"))
        session=gate.complete(state,token)
        with self.assertRaises(Denied):
            gate.complete(state,token)
        self.assertEqual(gate.execute(session,"A","1","list_items"),["A1"])
        with self.assertRaises(Denied):
            gate.execute(session,"A","1","list_notes")

    def test_f05_membership_revocation_blocks_existing_session_and_quarantine(self):
        r,now,idp,verifier,gate,claims=self.oidc_fixture()
        state,nonce=gate.begin()
        session=gate.complete(state,idp.token(claims(nonce)))
        self.assertEqual(gate.execute(session,"A","1","list_notes"),["note-A1"])
        self.admin.query("UPDATE auth.membership SET active=false,revision=revision+1 WHERE principal='alice' AND tenant='A' AND bu='1'")
        try:
            with self.assertRaises(Denied):
                gate.execute(session,"A","1","list_items")
        finally:
            self.admin.query("UPDATE auth.membership SET active=true,revision=revision+1 WHERE principal='alice' AND tenant='A' AND bu='1'")
        r.quarantine()
        with self.assertRaises(Denied):
            gate.execute(session,"A","1","list_items")

    def test_f05_pkce_code_callback_binds_browser_and_consumes_code(self):
        r,now,idp,verifier,gate,claims=self.oidc_fixture()
        browser=secrets.token_hex(32)
        request=gate.begin_code(browser)
        self.assertEqual(request["code_challenge_method"],"S256")
        self.assertNotIn("code_verifier",request)
        code=idp.authorize(request,claims(request["nonce"]))
        session=gate.complete_code(request["state"],code,browser,verifier.issuer)
        self.assertEqual(gate.execute(session,"A","1","list_items"),["A1"])
        with self.assertRaises(Denied):
            gate.complete_code(request["state"],code,browser,verifier.issuer)
        request2=gate.begin_code(browser)
        with self.assertRaises(Denied):
            gate.complete_code(request2["state"],code,browser,verifier.issuer)

    def test_f05_pkce_wrong_browser_issuer_and_verifier_denied(self):
        r,now,idp,verifier,gate,claims=self.oidc_fixture()
        browser=secrets.token_hex(32)
        for actual_browser,issuer in ((secrets.token_hex(32),verifier.issuer),
                                      (browser,"https://foreign.invalid")):
            request=gate.begin_code(browser)
            code=idp.authorize(request,claims(request["nonce"]))
            with self.assertRaises(Denied):
                gate.complete_code(request["state"],code,actual_browser,issuer)
            with self.assertRaises(Denied):
                gate.complete_code(request["state"],code,browser,verifier.issuer)
        request=gate.begin_code(browser)
        code=idp.authorize(request,claims(request["nonce"]))
        with self.assertRaises(Denied):
            idp.exchange(code,"wrong-verifier",request["redirect_uri"],request["client_id"])
        with self.assertRaises(Denied):
            gate.complete_code(request["state"],code,browser,verifier.issuer)

    def test_f05_expired_callback_and_idle_session_denied(self):
        r,now,idp,verifier,gate,claims=self.oidc_fixture()
        browser=secrets.token_hex(32)
        pending=gate.begin_code(browser)
        code=idp.authorize(pending,claims(pending["nonce"]))
        now[0]+=60
        verifier.install_keys(2,{"keys":[idp.jwk]},300)
        with self.assertRaises(Denied):
            gate.complete_code(pending["state"],code,browser,verifier.issuer)
        pending=gate.begin_code(browser)
        code=idp.authorize(pending,claims(pending["nonce"]))
        session=gate.complete_code(pending["state"],code,browser,verifier.issuer)
        now[0]+=29
        self.assertEqual(gate.execute(session,"A","1","list_items"),["A1"])
        now[0]+=30
        with self.assertRaises(Denied):
            gate.execute(session,"A","1","list_items")

    def test_f05_session_absolute_deadline_not_extended_by_activity(self):
        r,now,idp,verifier,gate,claims=self.oidc_fixture()
        verifier.install_keys(2,{"keys":[idp.jwk]},300)
        browser=secrets.token_hex(32)
        pending=gate.begin_code(browser)
        code=idp.authorize(pending,claims(pending["nonce"]))
        session=gate.complete_code(pending["state"],code,browser,verifier.issuer)
        for _ in range(3):
            now[0]+=19
            self.assertEqual(gate.execute(session,"A","1","list_items"),["A1"])
        now[0]+=3
        with self.assertRaises(Denied):
            gate.execute(session,"A","1","list_items")

    def licensed_fixture(self,profile="full"):
        directory=tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path=Path(directory.name)
        helper=ROOT.parent/"universal_licence"/"read_fixture.mjs"
        subprocess.run(["node",str(helper),"init",str(path),"1800000000000",profile],
                       check=True,capture_output=True,timeout=15)
        r,now,idp,verifier,gate,claims=self.oidc_fixture(ReadEntitlement(path))
        def login(subject="subject-alice"):
            state,nonce=gate.begin()
            return gate.complete(state,idp.token(claims(nonce,sub=subject)))
        def revoke():
            subprocess.run(["node",str(helper),"revoke",str(path),str(now[0]*1000)],
                           check=True,capture_output=True,timeout=15)
        return r,now,gate,login,revoke,path

    def test_f04_signed_entitlements_gate_authenticated_reads_and_quota(self):
        r,now,gate,login,revoke,path=self.licensed_fixture()
        session=login()
        self.assertEqual(gate.execute(session,"A","1","list_items"),["A1"])
        self.assertEqual(gate.execute(session,"A","1","list_notes"),["note-A1"])
        with self.assertRaises(Denied):
            gate.execute(session,"A","1","list_items")
        db=sqlite3.connect(path/"state.sqlite")
        try:
            self.assertEqual(db.execute("SELECT count(*) FROM effects WHERE quota='apiCalls'").fetchone(),(2,))
        finally:
            db.close()

    def test_f04_missing_module_feature_and_zero_quota_deny_reads(self):
        for profile,operation in (("no_notes","list_notes"),("no_api","list_items"),("zero","list_items")):
            r,now,gate,login,revoke,path=self.licensed_fixture(profile)
            with self.assertRaises(Denied):
                gate.execute(login(),"A","1",operation)
            db=sqlite3.connect(path/"state.sqlite")
            try:
                self.assertEqual(db.execute("SELECT count(*) FROM effects").fetchone(),(0,))
            finally:
                db.close()

    def test_f04_licensed_deployment_scope_not_inferred_from_identity(self):
        r,now,gate,login,revoke,path=self.licensed_fixture()
        # Bob is authorized by the underlying broker, but belongs to a
        # different synthetic customer not entitled by this installation.
        with self.assertRaises(Denied):
            gate.execute(login("subject-bob"),"B","1","list_items")
        self.assertEqual(gate.execute(login(),"A","1","list_items"),["A1"])

    def test_f04_revocation_and_missing_state_deny_existing_sessions(self):
        r,now,gate,login,revoke,path=self.licensed_fixture()
        session=login()
        self.assertEqual(gate.execute(session,"A","1","list_items"),["A1"])
        revoke()
        with self.assertRaises(Denied):
            gate.execute(session,"A","1","list_items")
        (path/"state.sqlite").unlink()
        with self.assertRaises(Denied):
            gate.execute(session,"A","1","list_items")

    def test_f04_revocation_during_read_suppresses_buffered_result(self):
        r,now,gate,login,revoke,path=self.licensed_fixture()
        original=r.fenced_read
        def revoked(*args):
            rows=original(*args)
            revoke()
            return rows
        r.fenced_read=revoked
        with self.assertRaises(Denied):
            gate.execute(login(),"A","1","list_items")
        db=sqlite3.connect(path/"state.sqlite")
        try:
            self.assertEqual(db.execute("SELECT count(*) FROM effects").fetchone(),(1,))
        finally:
            db.close()

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
        actor = self.open("proof_alice_a1")
        late = self.open("proof_charlie_a1")
        epoch = self.actor_epoch()
        self.begin(actor)
        actor.query("SAVEPOINT before_bind")
        actor.query(f"SELECT auth.bind_self('A','1','{epoch}')")
        self.assertEqual(self.values(actor), ["A1"])
        self.begin(late)
        # Share the existing real expiry wait across all three transactions.
        time.sleep(31)
        self.assertEqual(self.values(), [])
        self.assertEqual(self.values(actor), [])
        actor.query("ROLLBACK TO SAVEPOINT before_bind")
        actor.query(f"SELECT auth.bind_self('A','1','{epoch}')", "42501")
        late.query(f"SELECT auth.bind_self('A','1','{epoch}')", "42501")
        actor.query("ROLLBACK")
        late.query("ROLLBACK")
        self.a.query("ROLLBACK")
        self.begin(actor)
        actor.query(f"SELECT auth.bind_self('A','1','{epoch}')")
        self.assertEqual(self.values(actor), ["A1"])
        actor.query("ROLLBACK")

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


def wait_ready(container=NAME):
    for _ in range(60):
        ready = subprocess.run(["docker", "exec", container, "pg_isready", "-h", "127.0.0.1"],
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
        docker("run", "-d", "--network", "none", "--name", AUTHORITY_NAME,
               "-e", "POSTGRES_PASSWORD=" + AUTHORITY_PASSWORD,
               "-e", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
               digest, stdout=subprocess.DEVNULL)
        wait_ready(AUTHORITY_NAME)
        args = command("postgres") + ["-v","ON_ERROR_STOP=1",
                 "-v","runtime_pw="+PASSWORDS["proof_runtime"],
                 "-v","issuer_a_pw="+PASSWORDS["proof_issuer_a"],
                 "-v","issuer_b_pw="+PASSWORDS["proof_issuer_b"]]
        for role in ("proof_a1", "proof_a2", "proof_b1", "proof_b2",
                     "proof_alice_a1", "proof_charlie_a1", "proof_bob_b1"):
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
        if not result.wasSuccessful() or result.skipped or result.testsRun != 85:
            raise SystemExit(1)
    finally:
        for container in (NAME, AUTHORITY_NAME):
            subprocess.run(["docker","rm","-f","-v",container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
