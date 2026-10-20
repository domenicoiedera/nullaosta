"""Pinned-format, policy and gate unit tests."""

import hashlib
import json
import os
import shutil
import tempfile
import unittest

from . import support

from nullaosta import gate, policy, receipt
from nullaosta.gate import action_hash, new_action

GENESIS = "0" * 64


class CanonicalActionBytes(support.KeyedCase):
    """§2: the exact serialisation every signature in the product binds."""

    def test_digest_of_params_is_order_canonical(self):
        params = {"order": "X-77", "cents": 4200}
        self.assertEqual(policy.digest_bytes(params), policy.digest_bytes(
            {"cents": 4200, "order": "X-77"}))
        self.assertEqual(policy.digest_bytes(params), hashlib.sha256(
            b'{"cents":4200,"order":"X-77"}').hexdigest())

    def test_action_hash_is_over_nonce_and_issued_at(self):
        action = {"action_class": "pay", "target": "https://shop.example.com",
                  "params_digest": "aa" * 32,
                  "nonce": "00" * 16,
                  "issued_at": "2026-10-20T08:00:00+00:00"}
        pinned = hashlib.sha256(json.dumps(
            action, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        self.assertEqual(action_hash(action), pinned)

    def test_fresh_action_gets_a_fresh_nonce_every_attempt(self):
        action = new_action("pay", "https://shop.example.com", {"a": 1})
        other = new_action("pay", "https://shop.example.com", {"a": 1})
        self.assertNotEqual(action["nonce"], other["nonce"])
        self.assertNotEqual(action["nonce"], "")


class GenesisAndHead(support.KeyedCase):
    def test_empty_head_is_the_hash_of_nothing(self):
        self.assertEqual(receipt.head_at([], 0),
                         hashlib.sha256(b"").hexdigest())

    def test_seal_preimage_is_pinned(self):
        head_value = "h" * 64
        self.assertEqual(
            receipt.seal_preimage(3, head_value),
            f"nullaosta-receipt:v1:3:{head_value}")

    def test_genesis_is_64_zeros(self):
        self.assertEqual(receipt.GENESIS, GENESIS)


class PolicyRules(unittest.TestCase):
    def test_default_preset_gates_the_irreversible_classes(self):
        pol = policy.default_policy()
        for klass in ("pay", "submit", "delete", "send", "publish"):
            self.assertEqual(policy.rule_for(pol, klass, "https://x.example.com"),
                             "require-approval")
        self.assertEqual(policy.rule_for(pol, "browse", "https://x.example.com"),
                         "allow")

    def test_unknown_class_defaults_to_deny(self):
        self.assertEqual(
            policy.rule_for(policy.default_policy(), "teleport", "https://x.com"),
            "deny")

    def test_domain_rules_override_defaults_and_specificity_wins(self):
        pol = policy.default_policy()
        pol["domains"] = {
            "example.com": {"pay": "allow"},
            "shop.example.com": {"pay": "deny"},
        }
        self.assertEqual(policy.rule_for(pol, "pay", "https://shop.example.com/b"),
                         "deny")
        self.assertEqual(policy.rule_for(pol, "pay", "https://other.example.com"),
                         "allow")

    def test_wilder_suffix_rule_applies_to_subdomains(self):
        pol = policy.default_policy()
        pol["domains"] = {"com": {"pay": "allow"}}
        self.assertEqual(policy.rule_for(pol, "pay", "https://shop.example.com/x"),
                         "allow")


class PolicyLoadFailsClosed(unittest.TestCase):
    def test_unreadable_policy_is_never_read_as_no_rules(self):
        root = tempfile.mkdtemp(prefix="nullaosta-p-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        broken = os.path.join(root, "policy.json")
        with open(broken, "w", encoding="utf-8") as handle:
            handle.write('{"nullaosta_policy": asksdlk')
        with self.assertRaises(policy.PolicyError):
            policy.load(broken)

    def test_bad_verdict_rejected(self):
        root = tempfile.mkdtemp(prefix="nullaosta-q-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        path = os.path.join(root, "policy.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"nullaosta_policy": {"v": 1},
                       "defaults": {"browse": "yes-please"}}, handle)
        with self.assertRaises(policy.PolicyError):
            policy.load(path)


class ReceiptLoadFailsClosed(support.KeyedCase):
    def test_empty_receipt_file_is_a_fresh_document(self):
        root = tempfile.mkdtemp(prefix="nullaosta-r-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        path = os.path.join(root, "r.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("")
        self.assertEqual(receipt.load(path)["entries"], [])

    def test_absent_receipt_file_is_a_fresh_document(self):
        root = tempfile.mkdtemp(prefix="nullaosta-a-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        doc = receipt.load(os.path.join(root, "missing.json"))
        self.assertEqual(doc["entries"], [])


class GateBranchesWithoutCrypto(support.KeyedCase):
    """Branches of decide() that need no valid signature."""

    def test_policy_deny_cannot_be_approved_open(self):
        pol = policy.default_policy()
        pol["defaults"]["teleport"] = "deny"
        action = new_action("teleport", "https://shop.example.com", {})
        verdict, branch, _detail, _who = gate.decide(
            pol, {"entries": []}, action, {}, "sig-text",
            self.paths["allowed_signers"], "agent-receipt")
        self.assertEqual((verdict, branch), ("BLOCKED", "POLICY-DENY"))

    def test_gated_class_without_approval_is_blocked(self):
        action = new_action("pay", "https://shop.example.com", {"x": 1})
        verdict, branch, _detail, _who = gate.decide(
            policy.default_policy(), {"entries": []}, action, {}, None, None,
            self.paths["allowed_signers"], "agent-receipt")
        self.assertEqual((verdict, branch), ("BLOCKED", "NO-APPROVAL"))

    def test_ungated_allow_class_opens_without_approval(self):
        action = new_action("browse", "https://shop.example.com", {})
        verdict, branch, _detail, _who = gate.decide(
            policy.default_policy(), {"entries": []}, action, {}, None, None,
            self.paths["allowed_signers"], "agent-receipt")
        self.assertEqual((verdict, branch), ("OPEN", None))
