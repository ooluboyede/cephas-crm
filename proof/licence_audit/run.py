"""Disposable protocol tests; ephemeral keys never committed."""
import copy
import hashlib
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from state import State
from pathlib import Path

from protocol import (PRODUCT, LICENCE_DOMAIN, BUNDLE_DOMAIN, CHECKPOINT_DOMAIN,
                      SPKI, Invalid, canonical, b64, verify_licence, verify_audit,
                      audit_digest)

NOW = 1800000000
A = "00000000-0000-4000-8000-000000000001"
B = "00000000-0000-4000-8000-000000000002"
C = "00000000-0000-4000-8000-000000000003"
D = "00000000-0000-4000-8000-000000000004"


class Proof(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.path = Path(cls.directory.name)
        for name in ("root", "licence", "rotated", "audit"):
            subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                            "-out", str(cls.path / name)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def public(self, name):
        raw = subprocess.run(["openssl", "pkey", "-in", str(self.path / name),
                              "-pubout", "-outform", "DER"], check=True,
                             capture_output=True).stdout
        self.assertEqual(raw[:len(SPKI)], SPKI)
        return raw[len(SPKI):]

    def signed(self, payload, name, domain):
        with tempfile.TemporaryDirectory() as directory:
            message = Path(directory) / "message"
            message.write_bytes(domain + canonical(payload))
            sig = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey",
                                  str(self.path / name), "-rawin", "-in", str(message)],
                                 check=True, capture_output=True).stdout
        return canonical({"payload": payload, "signature": b64(sig)})

    def setUp(self):
        self.binding = {"customer_id": A, "tenant_id": B, "deployment_id": C,
                        "environment": "test"}
        self.licence = {"schema_version": 1, "licence_id": D, "product": PRODUCT,
                        **self.binding, "edition": "enterprise",
                        "modules": ["customer", "sales"],
                        "limits": {"max_users": 25, "max_records": 1000,
                                   "max_transactions_per_day": 50},
                        "issued_at": NOW - 10, "not_before": NOW - 5,
                        "expires_at": NOW + 100, "kid": "k1", "alg": "Ed25519"}
        self.bundle = {"schema_version": 1, "product": PRODUCT, "sequence": 2,
                       "not_before": NOW - 100, "expires_at": NOW + 200,
                       "keys": [{"kid": "k1", "public_key": b64(self.public("licence")),
                                 "not_before": NOW - 100, "expires_at": NOW + 200}],
                       "revoked": []}
        self.scope = {"tenant_id": B, "bu_id": C}
        self.events = [{"event_id": A, "scope": self.scope, "action": "read",
                        "outcome": "allowed", "timestamp": NOW},
                       {"event_id": D, "scope": self.scope, "action": "write",
                        "outcome": "denied", "timestamp": NOW + 1}]

    def validate(self, licence=None, bundle=None, **kwargs):
        args = {"now": NOW, "floor": 2, "binding": self.binding,
                "module": "sales", "previous_time": NOW}
        args.update(kwargs)
        return verify_licence(
            licence if licence is not None else self.signed(self.licence, "licence", LICENCE_DOMAIN),
            bundle if bundle is not None else self.signed(self.bundle, "root", BUNDLE_DOMAIN),
            self.public("root"), **args)

    def test_licence_valid(self):
        sequence, digest, limits = self.validate()
        self.assertEqual(sequence, 2)
        self.assertEqual(len(digest), 64)
        self.assertEqual(limits["max_users"], 25)

    def test_licence_wrong_domain_and_key(self):
        for name, domain in (("root", LICENCE_DOMAIN), ("licence", BUNDLE_DOMAIN)):
            with self.assertRaises(Invalid):
                self.validate(licence=self.signed(self.licence, name, domain))

    def test_licence_tamper(self):
        raw = self.signed(self.licence, "licence", LICENCE_DOMAIN)
        with self.assertRaises(Invalid):
            self.validate(licence=raw.replace(b'"max_users":25', b'"max_users":26'))

    def test_licence_duplicate_and_noncanonical(self):
        raw = self.signed(self.licence, "licence", LICENCE_DOMAIN)
        for bad in (b" " + raw, raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'),
                    raw.replace(b'"max_users":25', b'"max_users":25.0')):
            with self.assertRaises(Invalid):
                self.validate(licence=bad)

    def test_licence_wrong_binding_module_and_product(self):
        for field, value in (("tenant_id", A), ("customer_id", D),
                             ("deployment_id", D), ("environment", "production"),
                             ("product", "OTHER"), ("alg", "none")):
            payload = dict(self.licence, **{field: value})
            with self.assertRaises(Invalid):
                self.validate(licence=self.signed(payload, "licence", LICENCE_DOMAIN))
        with self.assertRaises(Invalid):
            self.validate(module="service")

    def test_licence_expiry_and_clock_rollback(self):
        for now, previous in ((NOW + 100, NOW), (NOW - 6, NOW - 10), (NOW, NOW + 1)):
            with self.assertRaises(Invalid):
                self.validate(now=now, previous_time=previous)

    def test_licence_limits_and_schema(self):
        for value in (-1, True, 2**53, "25"):
            payload = copy.deepcopy(self.licence)
            payload["limits"]["max_users"] = value
            with self.assertRaises(Invalid):
                self.validate(licence=self.signed(payload, "licence", LICENCE_DOMAIN))
        with self.assertRaises(Invalid):
            self.validate(licence=self.signed(dict(self.licence, extra=1), "licence", LICENCE_DOMAIN))

    def test_bundle_rollback_and_equal_sequence_conflict(self):
        with self.assertRaises(Invalid):
            self.validate(floor=3)
        _, digest, _ = self.validate()
        self.bundle["expires_at"] += 1
        with self.assertRaises(Invalid):
            self.validate(pinned_bundle_digest=digest)

    def test_bundle_rotation_and_revocation(self):
        self.bundle["keys"].append({"kid": "k2", "public_key": b64(self.public("rotated")),
                                    "not_before": NOW - 100, "expires_at": NOW + 200})
        self.bundle["revoked"] = ["k1"]
        with self.assertRaises(Invalid):
            self.validate()
        self.licence["kid"] = "k2"
        self.assertEqual(self.validate(licence=self.signed(self.licence, "rotated", LICENCE_DOMAIN))[0], 2)

    def test_bundle_untrusted_root_and_retired_key(self):
        with self.assertRaises(Invalid):
            self.validate(bundle=self.signed(self.bundle, "rotated", BUNDLE_DOMAIN))
        self.bundle["keys"][0]["expires_at"] = NOW
        with self.assertRaises(Invalid):
            self.validate()

    def state_fixture(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "authority.sqlite"
        bundle = self.signed(self.bundle, "root", BUNDLE_DOMAIN)
        store = State.initialize(path, 2, hashlib.sha256(bundle).hexdigest(), NOW)
        return store, bundle

    def reserve(self, store, bundle, request, now=NOW):
        licence = self.signed(self.licence, "licence", LICENCE_DOMAIN)
        return store.reserve(licence, bundle, self.public("root"), now,
                             self.binding, "sales", request)

    def test_state_quota_and_duplicate(self):
        self.licence["limits"]["max_transactions_per_day"] = 1
        store, bundle = self.state_fixture()
        self.assertEqual(self.reserve(store,bundle,"one"), "reserved")
        self.assertEqual(self.reserve(State(store.path),bundle,"one"), "duplicate")
        with self.assertRaises(Invalid):
            self.reserve(store,bundle,"two")

    def test_state_quota_concurrency(self):
        self.licence["limits"]["max_transactions_per_day"] = 1
        store, bundle = self.state_fixture()
        licence = self.signed(self.licence, "licence", LICENCE_DOMAIN)
        public = self.public("root")
        def attempt(request):
            try:
                return store.reserve(licence,bundle,public,NOW,self.binding,"sales",request)
            except Invalid:
                return "denied"
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(list(pool.map(attempt, ["one","two"])), ["reserved","denied"])

    def test_state_trust_floor_and_time_persist(self):
        store, bundle = self.state_fixture()
        self.bundle["sequence"] = 3
        newer = self.signed(self.bundle,"root",BUNDLE_DOMAIN)
        self.assertEqual(self.reserve(store,newer,"one",NOW+1),"reserved")
        reopened = State(store.path)
        with self.assertRaises(Invalid):
            self.reserve(reopened,bundle,"two",NOW+1)
        with self.assertRaises(Invalid):
            self.reserve(reopened,newer,"two",NOW)

    def test_state_missing_and_equal_sequence_conflict(self):
        store,bundle = self.state_fixture()
        self.bundle["expires_at"] += 1
        changed = self.signed(self.bundle,"root",BUNDLE_DOMAIN)
        with self.assertRaises(Invalid):
            self.reserve(store,changed,"one")
        store.path.unlink()
        with self.assertRaises(Invalid):
            self.reserve(store,bundle,"two")

    def test_state_zero_quota(self):
        self.licence["limits"]["max_transactions_per_day"] = 0
        store,bundle = self.state_fixture()
        with self.assertRaises(Invalid):
            self.reserve(store,bundle,"one")

    def test_state_checkpoint_rejects_fork_and_rollback(self):
        store,_ = self.state_fixture()
        checkpoint, head = self.checkpoint()
        self.assertEqual(store.accept_checkpoint(self.events,checkpoint,self.public("audit"),
                                                 self.scope,2,head),head)
        original = copy.deepcopy(self.events)
        self.events[0]["action"] = "delete"
        fork, fork_head = self.checkpoint()
        with self.assertRaises(Invalid):
            store.accept_checkpoint(self.events,fork,self.public("audit"),self.scope,2,fork_head)
        self.events = original[:1]
        old, old_head = self.checkpoint()
        with self.assertRaises(Invalid):
            store.accept_checkpoint(self.events,old,self.public("audit"),self.scope,1,old_head)
        self.events = original + [{"event_id": C,"scope":self.scope,"action":"read",
                                   "outcome":"allowed","timestamp":NOW+2}]
        newer,new_head = self.checkpoint()
        self.assertEqual(store.accept_checkpoint(self.events,newer,self.public("audit"),
                                                 self.scope,3,new_head),new_head)

    def checkpoint(self):
        previous = "0" * 64
        for sequence, event in enumerate(self.events, 1):
            previous = audit_digest(event, previous, sequence, self.scope)
        payload = {"schema_version": 1, "product": PRODUCT, "scope": self.scope,
                   "sequence": len(self.events), "digest": previous}
        return self.signed(payload, "audit", CHECKPOINT_DOMAIN), previous

    def check(self, events, checkpoint, digest, public=None, scope=None):
        return verify_audit(events, checkpoint, public or self.public("audit"),
                            scope or self.scope, 2, digest)

    def test_audit_valid(self):
        checkpoint, digest = self.checkpoint()
        self.assertEqual(self.check(self.events, checkpoint, digest), digest)

    def test_audit_rewrite_reorder_truncate(self):
        checkpoint, digest = self.checkpoint()
        changed = copy.deepcopy(self.events)
        changed[0]["action"] = "delete"
        for events in (changed, list(reversed(self.events)), self.events[:1]):
            with self.assertRaises(Invalid):
                self.check(events, checkpoint, digest)

    def test_audit_duplicate_and_cross_scope(self):
        checkpoint, digest = self.checkpoint()
        changed = copy.deepcopy(self.events)
        changed[1]["event_id"] = changed[0]["event_id"]
        with self.assertRaises(Invalid):
            self.check(changed, checkpoint, digest)
        with self.assertRaises(Invalid):
            self.check(self.events, checkpoint, digest, scope={"tenant_id": A, "bu_id": C})

    def test_audit_wrong_key_and_checkpoint_floor(self):
        checkpoint, digest = self.checkpoint()
        with self.assertRaises(Invalid):
            self.check(self.events, checkpoint, digest, public=self.public("root"))
        with self.assertRaises(Invalid):
            self.check(self.events, checkpoint, "0" * 64)


if __name__ == "__main__":
    subprocess.run(["openssl", "version"], check=True)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Proof)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun != 20 or result.skipped or not result.wasSuccessful():
        raise SystemExit(1)
