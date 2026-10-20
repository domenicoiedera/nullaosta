"""The discriminating tamper tests: EVERY class below must make
``verify`` fail with a nonzero exit, and each pins the breach label that
names the failure.

Setup builds ONE genuine receipt (blocked entry, then an approved OPEN that
spends the nonce). Each test tampers the file in exactly one way and
re-verifies; the writer-role tests are honest rewrites (a real writer CAN
re-stamp and re-seal with its receipt key — the point is what the third
party can still detect).
"""

import hashlib
import json
import os
import shutil
import tempfile
import unittest

from . import support

from nullaosta import gate, policy, receipt
from nullaosta.gate import action_hash, approval_preimage, new_action
from nullaosta.verify import verify

APR = gate.APPROVAL_NAMESPACE
RECEIPT_NS = receipt.SEAL_NAMESPACE


def signed_approval(paths, action, key="approver_key", principal="founder"):
    """The approver's real SSHSIG over this exact action hash."""
    preimage = approval_preimage(action_hash(action))
    sig, detail = receipt.sign_preimage(preimage, paths[key], APR)
    assert sig, detail
    return sig


def build_genuine_receipt(paths):
    """A valid receipt: [0] blocked NO-APPROVAL, [1] OPEN (approval spent)."""
    root = tempfile.mkdtemp(prefix="nullaosta-tamper-")
    path = os.path.join(root, "r.json")
    pol = policy.default_policy()
    blocked_action = new_action("pay", "https://shop.example.com/one", {"x": 1})
    open_action = new_action("pay", "https://shop.example.com/one", {"x": 1})
    sig = signed_approval(paths, open_action)
    blocked = gate.record_decision(blocked_action, None, "BLOCKED",
                                   "NO-APPROVAL", "no approval", None, True, 900)
    verdict, branch, detail, matched = gate.decide(
        pol, {"entries": [blocked]}, open_action, {"x": 1}, sig,
        paths["allowed_signers"], "agent-receipt")
    assert (verdict, matched) == ("OPEN", "founder"), (verdict, matched)
    opened = gate.record_decision(open_action, sig, "OPEN", None, detail,
                                  matched, True, 900)
    doc, error = receipt.append_and_seal(path, [blocked, opened],
                                         paths["receipt_key"], "agent-receipt")
    assert doc is not None, error
    return path, doc


class TamperBase(support.KeyedCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.genuine_path, cls.genuine = build_genuine_receipt(cls.paths)
        cls.genuine_bytes = open(cls.genuine_path, "rb").read()

    def _reset(self):
        """Restore the genuine bytes so every test tampers from identical
        state."""
        with open(self.genuine_path, "wb") as handle:
            handle.write(self.genuine_bytes)
        return json.loads(self.genuine_bytes.decode("utf-8"))

    def _save(self, doc):
        with open(self.genuine_path, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, indent=1, sort_keys=True)

    def _append_as_writer(self, payload):
        """Append one entry (and seal it) with the genuine receipt key —
        the honest writer's own power."""
        clean = {k: v for k, v in payload.items()
                 if k not in ("seq", "prev_hash", "seal")}
        doc, error = receipt.append_and_seal(self.genuine_path, [clean],
                                             self.paths["receipt_key"],
                                             "agent-receipt")
        self.assertIsNotNone(doc, error)

    def verify_fails(self, expected_breach=None):
        result = verify(self.genuine_path, self.paths["allowed_signers"])
        self.assertEqual(result["exit"], 1)
        return result


class TestFileLevelTamper(TamperBase):
    def test_truncation_fails_verification(self):
        """A crash-truncated file: the tail bytes are gone. NOT OK."""
        self._reset()
        with open(self.genuine_path, "wb") as handle:
            handle.write(self.genuine_bytes[:-140])
        result = self.verify_fails()
        self.assertEqual(result["breach"], "UNSEALED-OR-TRUNCATED")

    def test_unsealed_tail_fails_verification(self):
        """The last entry loses its seal (seal cadence violated) → NOT OK."""
        doc = self._reset()
        doc["entries"][-1].pop("seal")
        self._save(doc)
        result = self.verify_fails()
        self.assertIn("no seal", result["detail"])

    def test_reorder_fails_verification(self):
        """Swapping two entries breaks seq/prev linkage. NOT OK."""
        doc = self._reset()
        doc["entries"][0], doc["entries"][1] = doc["entries"][1], doc["entries"][0]
        self._save(doc)
        result = self.verify_fails()
        self.assertIn("seq", result["detail"])


class TestEntryLevelTamper(TamperBase):
    def test_single_field_edit_fails_verification(self):
        """Edit one decision detail; the chain no longer links."""
        doc = self._reset()
        doc["entries"][0]["decision"]["detail"] = "benign rewrite"
        self._save(doc)
        result = self.verify_fails()
        self.assertEqual(result["breach"], "CHAIN-BROKEN")

    def test_mismatched_action_hash_fails_verification(self):
        """A recorded action_hash that is NOT the action's canonical bytes —
        rebuilt as a full, honestly re-sealed single-entry receipt."""
        self._reset()
        doc = json.loads(self.genuine_bytes.decode("utf-8"))
        entry = doc["entries"][0]
        entry.pop("seal", None)
        entry.pop("approval", None)
        entry.pop("spent", None)
        entry["decision"] = {"verdict": "BLOCKED", "branch": "NO-APPROVAL",
                             "detail": "legit blocked", "expire_seconds": 900}
        entry["action_hash"] = "9" * 64          # the lie under test
        doc["entries"] = [entry]
        self._save(doc)
        head_value = hashlib.sha256(
            receipt.entry_hash(entry).encode("utf-8")).hexdigest()
        sig, detail = receipt.sign_preimage(
            receipt.seal_preimage(1, head_value, self.genuine_path),
            self.paths["receipt_key"], RECEIPT_NS)
        self.assertTrue(sig, detail)
        doc["entries"][0]["seal"] = {"covered": 1, "head": head_value,
                                     "sig": sig}
        self._save(doc)
        result = self.verify_fails()
        self.assertEqual(result["breach"], "MISMATCHED-ACTION-HASH")


class TestSealTamper(TamperBase):
    def test_swapped_key_on_the_seal_fails_verification(self):
        """Re-sign the tail's seal preimage with a DIFFERENT (attacker) key:
        still a valid SSHSIG, but not the executor's — NOT OK."""
        doc = self._reset()
        seal = doc["entries"][-1]["seal"]
        sig, detail = receipt.sign_preimage(
            receipt.seal_preimage(seal["covered"], seal["head"],
                                  self.genuine_path),
            self.paths["attacker_key"], RECEIPT_NS)
        self.assertTrue(sig, detail)
        doc["entries"][-1]["seal"]["sig"] = sig
        self._save(doc)
        result = self.verify_fails()
        self.assertEqual(result["breach"], "SEAL-INVALID")

    def test_forged_receipt_resealed_by_a_forged_executor_fails(self):
        """A whole rewritten chain where every seal is re-signed by the
        ATTACKER key (claimed as the executor): the trust anchor rejects it."""
        doc = self._reset()
        for entry in doc["entries"]:
            entry.pop("seal", None)
        entries_out = []
        prev = receipt.GENESIS
        for index, entry in enumerate(doc["entries"]):
            entry["seq"] = index
            entry["prev_hash"] = prev
            prev = receipt.entry_hash(entry)
        entries_out = doc["entries"]
        # seal EVERY entry with the attacker key over the correct heads —
        # a perfect structural rewrite by an untrusted writer
        for index, entry in enumerate(entries_out):
            covered = index + 1
            head_value = hashlib.sha256(
                "\n".join(receipt.entry_hash(e)
                          for e in entries_out[:covered]).
                encode("utf-8")).hexdigest()
            sig, detail = receipt.sign_preimage(
                receipt.seal_preimage(covered, head_value,
                                      self.genuine_path),
                self.paths["attacker_key"], RECEIPT_NS)
            self.assertTrue(sig, detail)
            entry["seal"] = {"covered": covered, "head": head_value, "sig": sig}
        doc["entries"] = entries_out
        self._save(doc)
        result = self.verify_fails()
        self.assertEqual(result["breach"], "SEAL-INVALID")


class TestApprovalTamper(TamperBase):
    def test_spent_nonce_reopened_twice_fails_verification(self):
        """The SAME action (same nonce, same approval) OPENed twice in one
        receipt: the ledger catches the double spend."""
        doc = self._reset()
        double = dict(doc["entries"][-1])
        double["at"] = "2026-10-20T10:00:00+00:00"
        double.pop("seq", None)
        double.pop("prev_hash", None)
        double.pop("seal", None)
        self._append_as_writer(double)
        result = self.verify_fails()
        self.assertEqual(result["breach"], "SPENT-NONCE-REUSE")

    def test_open_gated_entry_without_approval_fails_verification(self):
        """A writer-rewritten OPEN on a gated class with no approval at
        all: NO-APPROVAL-ON-OPEN."""
        self._reset()
        action = new_action("pay", "https://shop.example.com/fresh",
                            {"fresh": True})
        stripped = gate.record_decision(
            action, None, "OPEN", None, "opened without any approval",
            None, True, 900)
        self._append_as_writer(stripped)
        result = self.verify_fails()
        self.assertEqual(result["breach"], "NO-APPROVAL-ON-OPEN")

    def test_approval_by_the_executor_key_on_a_fresh_action_fails(self):
        """The executor approves ITS OWN fresh gated action with the
        receipt key, claimed as the executor principal: the signature IS
        valid, the trust split is NOT."""
        self._reset()
        action = new_action("pay", "https://shop.example.com/self",
                            {"fresh": True})
        self_sig, detail = receipt.sign_preimage(
            approval_preimage(action_hash(action)),
            self.paths["receipt_key"], APR)
        self.assertTrue(self_sig, detail)
        payload = gate.record_decision(
            action, self_sig, "OPEN", None, "self-approved fresh action",
            "agent-receipt", True, 900)
        payload["approval"] = {"principal": "agent-receipt", "sig": self_sig}
        self._append_as_writer(payload)
        result = self.verify_fails()
        self.assertEqual(result["breach"], "TRUST-SPLIT-VIOLATION")

    def test_forged_approval_claiming_another_principal_fails(self):
        """An approval signed with the WRONG key but claimed as the legit
        approver principal: the claim does not verify."""
        self._reset()
        action = new_action("pay", "https://shop.example.com/forge",
                            {"fresh": True})
        forged, detail = receipt.sign_preimage(
            approval_preimage(action_hash(action)),
            self.paths["attacker_key"], APR)
        self.assertTrue(forged, detail)
        payload = gate.record_decision(
            action, forged, "OPEN", None, "forged claimant", "founder",
            True, 900)
        payload["approval"] = {"principal": "founder", "sig": forged}
        self._append_as_writer(payload)
        result = self.verify_fails()
        self.assertEqual(result["breach"], "APPROVAL-INVALID")


class MissingAnchor(TamperBase):
    def test_verify_without_anchor_cannot_run(self):
        root = tempfile.mkdtemp(prefix="nullaosta-anchor-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        result = verify(self.genuine_path, os.path.join(root, "no-signers"))
        self.assertEqual(result["exit"], 2)

    def test_verify_missing_receipt_cannot_run(self):
        root = tempfile.mkdtemp(prefix="nullaosta-anchor-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        from nullaosta.verify import VerifyInputError
        with self.assertRaises(VerifyInputError):
            verify(os.path.join(root, "no-receipt.json"),
                   self.paths["allowed_signers"])
