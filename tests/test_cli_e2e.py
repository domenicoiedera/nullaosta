"""End-to-end CLI tests: the five verbs, the exit taxonomy, and the
fail-closed an operator actually hits — no approval, replays, spent
nonces, expiry, unreachable approver, tampered receipts."""

import json
import os
import subprocess
import sys
import time
import unittest

from . import support


class CliBase(support.KeyedCase):
    """One sandbox + one receipt key + one approver key + one attacker key.
    Keys are generated per test session; nothing is committed."""

    @classmethod
    def setUpClass(cls):
        if not support.ssh_keygen_available():
            raise unittest.SkipTest("ssh-keygen is not on PATH")
        cls.paths = support.make_environment()
        cls.dir = os.path.join(cls.paths["root"], "work")
        os.makedirs(cls.dir, exist_ok=True)
        cls.env = dict(os.environ)
        cls.env["PYTHONPATH"] = support.ROOT + os.pathsep + cls.env.get(
            "PYTHONPATH", "")
        cls.config = os.path.join(cls.dir, "nullaosta.json")
        cls.receipt = os.path.join(cls.dir, "receipt.json")
        cls.policy = os.path.join(cls.dir, "policy.json")
        cls.pending = os.path.join(cls.dir, "pending.json")
        cls.params = os.path.join(cls.dir, "params.json")
        with open(cls.params, "w", encoding="utf-8") as handle:
            json.dump({"order": "X-9", "cents": 999}, handle)
        with open(cls.policy, "w", encoding="utf-8") as handle:
            json.dump({"nullaosta_policy": {"v": 1},
                       "defaults": {"browse": "allow"},
                       "domains": {"shady.example.com": {"pay": "deny"}}},
                      handle)
        with open(cls.config, "w", encoding="utf-8") as handle:
            json.dump({"nullaosta_config": {"v": 1},
                       "executor": "agent-receipt",
                       "receipt": cls.receipt,
                       "policy": cls.policy,
                       "pending": cls.pending,
                       "expire_seconds": 900}, handle, indent=2)

    def run_cli(self, *args, timeout=180):
        """One bounded CLI invocation: (exit_code, stdout, stderr)."""
        result = subprocess.run(
            [sys.executable, "-m", "nullaosta", *args],
            capture_output=True, text=True, timeout=timeout, env=self.env)
        return result.returncode, result.stdout, result.stderr

    # ── one full round-trip, reused by the single-use tests ──────────────

    def _check(self, target, extra=()):
        return self.run_cli(
            "check", "--class", "pay", "--target", target,
            "--params-file", self.params, "--allowed-signers",
            self.paths["allowed_signers"], "--key", self.paths["receipt_key"],
            "--config", self.config, *extra)

    def _check_action_file(self, sig_name, extra=()):
        return self.run_cli(
            "check", "--action-file", self.pending, "--approval",
            os.path.join(self.dir, sig_name), "--allowed-signers",
            self.paths["allowed_signers"], "--key", self.paths["receipt_key"],
            "--config", self.config, *extra)

    def _approve(self, sig_name):
        return self.run_cli(
            "approve", "--action-file", self.pending, "--key",
            self.paths["approver_key"], "--principal", "founder",
            "--out", os.path.join(self.dir, sig_name), "--config", self.config)


class TestCheckApproveLoop(CliBase):
    def test_full_flow_no_approval_then_open_then_verify_clean(self):
        code, _out, err = self._check("https://shop.example.com")
        self.assertEqual(code, 1)
        self.assertIn("NO-APPROVAL", err)
        self.assertTrue(os.path.exists(self.pending))
        code, _out, err = self._approve("a.sig")
        self.assertEqual(code, 0, err)
        code, out, err = self._check_action_file("a.sig")
        self.assertEqual(code, 0, err)
        self.assertIn("OPEN", out)
        code, out, _err = self.run_cli(
            "verify", "--receipt", self.receipt, "--allowed-signers",
            self.paths["allowed_signers"])
        self.assertEqual(code, 0, out)
        self.assertIn("verify OK", out)

    def test_replay_same_approval_same_action_is_spent(self):
        code, _out, err = self._check("https://shop.example.com")
        self._approve("b.sig")
        code, _out, _err = self._check_action_file("b.sig")
        self.assertEqual(code, 0)
        code, _out, err = self._check_action_file("b.sig")
        self.assertEqual(code, 1)
        self.assertIn("SPENT", err)

    def test_replay_of_the_same_approval_on_a_later_identical_action_is_blocked(self):
        """A LATER attempt with identical class/target/params gets a FRESH
        nonce, so the old approval no longer matches any canonical hash."""
        # Attempt 1: block, approve, open.
        self._check("https://shop.example.com")
        self._approve("c.sig")
        code0, _out, _err = self._check_action_file("c.sig")
        self.assertEqual(code0, 0)
        # then a SECOND independent attempt with the same params:
        code1, _out, err1 = self._check("https://shop.example.com")
        self.assertEqual(code1, 1)
        self.assertIn("NO-APPROVAL", err1)
        code2, _out, err2 = self._check_action_file("c.sig")
        self.assertEqual(code2, 1)
        self.assertIn("INVALID-APPROVAL", err2)
        # Verification of the tamper trail remains CLEAN: nothing was spent
        # twice, the receipts are intact.
        code3, out, _err = self.run_cli(
            "verify", "--receipt", self.receipt, "--allowed-signers",
            self.paths["allowed_signers"])
        self.assertEqual(code3, 0, out)


class TestApproveRefusals(CliBase):
    def test_self_reference_refused(self):
        self._check("https://shop.example.com/selfx")
        code, _out, err = self.run_cli(
            "approve", "--action-file", self.pending, "--key",
            self.paths["receipt_key"], "--principal", "agent-receipt",
            "--out", os.path.join(self.dir, "self.sig"),
            "--config", self.config)
        self.assertEqual(code, 1)
        self.assertIn("SELF-REFERENCE", err)

    def test_unknown_action_file_is_a_usage_error(self):
        code, _out, err = self.run_cli(
            "approve", "--action-file", os.path.join(self.dir, "nah.json"),
            "--key", self.paths["approver_key"], "--principal", "founder",
            "--config", self.config)
        self.assertEqual(code, 2)


class TestOtherBranches(CliBase):
    def test_expired_attempt_is_blocked(self):
        self._check("https://shop.example.com/flash")
        time.sleep(1.1)
        self._approve("d.sig")
        code, _out, err = self._check_action_file(
            "d.sig", extra=("--expire-seconds", "1"))
        self.assertEqual(code, 1)
        self.assertIn("EXPIRED", err)

    def test_missing_approval_file_is_unreachable(self):
        self._check("https://shop.example.com/ur1")
        code, _out, err = self.run_cli(
            "check", "--action-file", self.pending, "--approval",
            os.path.join(self.dir, "never-signed.sig"), "--allowed-signers",
            self.paths["allowed_signers"], "--key", self.paths["receipt_key"],
            "--config", self.config)
        self.assertEqual(code, 1)
        self.assertIn("APPROVER-UNREACHABLE", err)

    def test_dead_approver_command_is_unreachable(self):
        code, _out, err = self.run_cli(
            "check", "--class", "pay", "--target", "https://shop.example.com/x2",
            "--params-file", self.params, "--approver-cmd",
            os.path.join(self.dir, "definitely-not-here"), "--await-seconds",
            "5", "--allowed-signers", self.paths["allowed_signers"], "--key",
            self.paths["receipt_key"], "--config", self.config)
        self.assertEqual(code, 1)
        self.assertIn("APPROVER-UNREACHABLE", err)

    def test_policy_deny_blocks_even_with_a_valid_approval(self):
        # A REAL approval on a permitted target exists, then the same class
        # on a policy-denied domain is refused — the deny outranks it.
        self._check("https://shop.example.com/plain")
        self._approve("e.sig")
        code, _out, err = self.run_cli(
            "check", "--class", "pay", "--target", "https://shady.example.com/cart",
            "--params-file", self.params, "--approval",
            os.path.join(self.dir, "e.sig"), "--allowed-signers",
            self.paths["allowed_signers"], "--key", self.paths["receipt_key"],
            "--config", self.config)
        self.assertEqual(code, 1)
        self.assertIn("POLICY-DENY", err)

    def test_ungated_allow_class_opens_without_approval(self):
        code, out, err = self.run_cli(
            "check", "--class", "browse", "--target", "https://shop.example.com",
            "--params-file", self.params, "--allowed-signers",
            self.paths["allowed_signers"], "--key", self.paths["receipt_key"],
            "--config", self.config)
        self.assertEqual(code, 0, err)
        self.assertIn("OPEN", out)


class TestTamperedReceiptViaCli(CliBase):
    def test_verify_flags_a_single_field_edit_nonzero(self):
        self._check("https://shop.example.com")
        self._approve("f.sig")
        self._check_action_file("f.sig")
        code, _out, _err = self.run_cli(
            "verify", "--receipt", self.receipt, "--allowed-signers",
            self.paths["allowed_signers"])
        self.assertEqual(code, 0)
        with open(self.receipt, encoding="utf-8") as handle:
            doc = json.load(handle)
        doc["entries"][0]["decision"]["detail"] = "rewritten by the author"
        with open(self.receipt, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, indent=1, sort_keys=True)
        code, out, _err = self.run_cli(
            "verify", "--receipt", self.receipt, "--allowed-signers",
            self.paths["allowed_signers"])
        self.assertEqual(code, 1)
        self.assertIn("NOT OK", out)

    def test_verify_flags_a_truncated_receipt_nonzero(self):
        self._check("https://shop.example.com")
        self._approve("g.sig")
        self._check_action_file("g.sig")
        with open(self.receipt, "rb") as handle:
            data = handle.read()
        with open(self.receipt, "wb") as handle:
            handle.write(data[:-160])
        code, out, _err = self.run_cli(
            "verify", "--receipt", self.receipt, "--allowed-signers",
            self.paths["allowed_signers"])
        self.assertEqual(code, 1)
        self.assertIn("NOT OK", out)


class TestInitAndLog(CliBase):
    def test_init_refuses_existing_config(self):
        code, _out, err = self.run_cli("init", "--config", self.config)
        self.assertEqual(code, 2)

    def test_log_readable_then_unreadable(self):
        code, out, _err = self.run_cli("log", "--receipt", self.receipt)
        self.assertEqual(code, 0)
        self.assertIn("entries", out)
        broken = os.path.join(self.dir, "broken.json")
        with open(broken, "w", encoding="utf-8") as handle:
            handle.write('{"nullaosta_receipt": {"v": 1}, "entries": [ BROKEN')
        code, _out, err = self.run_cli("log", "--receipt", broken)
        self.assertEqual(code, 2)


class TestLibraryApi(CliBase):
    def test_decide_seal_verify_names_are_bound(self):
        probe = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, %r); "
             "import nullaosta; "
             "assert nullaosta.decide and nullaosta.seal and nullaosta.verify; "
             "print('api-ok')" % support.ROOT],
            capture_output=True, text=True, env=self.env, timeout=60)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertIn("api-ok", probe.stdout)
