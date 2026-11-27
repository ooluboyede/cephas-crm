"""Disposable real PostgreSQL proof; no customer data or production secrets."""
import os
import re
import secrets
import subprocess
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NAME = "cephas-proof-" + secrets.token_hex(6)
PASSWORDS = {role: secrets.token_hex(24) for role in
             ("postgres", "proof_runtime", "proof_issuer_a", "proof_issuer_b")}
IMAGE = os.environ.get("PROOF_POSTGRES_IMAGE", "postgres:18")


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

    def close(self):
        try:
            self.p.stdin.write("\\q\n")
            self.p.stdin.flush()
        except (BrokenPipeError, ValueError):
            pass
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        self.p.stdin.close()
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


def main():
    # Pull candidate tag once, then execute the immutable resolved image.
    docker("pull", IMAGE, stdout=subprocess.DEVNULL)
    digest = docker("image", "inspect", "--format", "{{index .RepoDigests 0}}",
                    IMAGE, capture_output=True).stdout.strip()
    if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", digest):
        raise RuntimeError("missing immutable image digest")
    print("PostgreSQL image:", digest, flush=True)
    try:
        docker("run", "-d", "--rm", "--network", "none", "--name", NAME,
               "-e", "POSTGRES_PASSWORD=" + PASSWORDS["postgres"],
               "-e", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
               digest, stdout=subprocess.DEVNULL)
        for _ in range(60):
            ready = subprocess.run(["docker","exec",NAME,"pg_isready","-h","127.0.0.1"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("PostgreSQL did not become ready")
        args = command("postgres") + ["-v","ON_ERROR_STOP=1",
                 "-v","runtime_pw="+PASSWORDS["proof_runtime"],
                 "-v","issuer_a_pw="+PASSWORDS["proof_issuer_a"],
                 "-v","issuer_b_pw="+PASSWORDS["proof_issuer_b"]]
        setup = subprocess.run(args, input=(ROOT / "bootstrap.sql").read_text(),
                               text=True, capture_output=True)
        if setup.returncode:
            # Do not emit raw bootstrap diagnostics containing password literals.
            raise RuntimeError("bootstrap SQL failed; reproduce with disposable local credentials")
        with_version = subprocess.run(command("postgres")+["-c","SHOW server_version"],
                                      text=True, check=True, capture_output=True)
        print("Server:",with_version.stdout.strip(),"SHA:",os.environ.get("GITHUB_SHA","local"),flush=True)
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Boundary))
        if not result.wasSuccessful() or result.skipped or result.testsRun != 12:
            raise SystemExit(1)
    finally:
        subprocess.run(["docker","rm","-f",NAME],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
