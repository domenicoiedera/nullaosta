"""Shared test support: throwaway SSH keys, a working sandbox, the pin of
the canonical serialisation.

Keys are generated per test session in a temp dir (never committed); every
test that signs or seals needs a real ``ssh-keygen`` on PATH and is skipped,
loudly, without one — a validation that silently fakes its crypto would be
worth nothing.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from nullaosta import policy as policy_mod  # noqa: E402


def ssh_keygen_available():
    return bool(shutil.which("ssh-keygen"))


def make_environment():
    """One sandbox with three keys (receipt / approver / attacker), a config,
    the default policy, and an allowed_signers naming all three principals.

    Returns a dict of paths; caller owns cleanup of the ``root`` dir.
    """
    root = tempfile.mkdtemp(prefix="nullaosta-env-")

    def key(name):
        path = os.path.join(root, name)
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", path,
                        "-C", name], check=True, capture_output=True)
        return path

    paths = {"root": root}
    paths["receipt_key"] = key("receipt_key")
    paths["receipt_pub"] = paths["receipt_key"] + ".pub"
    paths["approver_key"] = key("approver_key")
    paths["approver_pub"] = paths["approver_key"] + ".pub"
    paths["attacker_key"] = key("attacker_key")
    paths["attacker_pub"] = paths["attacker_key"] + ".pub"

    def pubkey(path):
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()

    anchor = os.path.join(root, "allowed_signers")
    with open(anchor, "w", encoding="utf-8") as handle:
        # Note: the names, not the files, decide trust — the executor's key
        # is named 'agent-receipt', the approver's 'founder'. An attacker key
        # ALSO sits in the anchor (principal 'attacker') so that a swapped
        # key validates and must still be rejected by the trust split.
        handle.write(f"agent-receipt {pubkey(paths['receipt_pub'])}\n")
        handle.write(f"founder {pubkey(paths['approver_pub'])}\n")
        handle.write(f"attacker {pubkey(paths['attacker_pub'])}\n")
    paths["allowed_signers"] = anchor

    config = {
        "nullaosta_config": {"v": 1},
        "executor": "agent-receipt",
        "receipt": os.path.join(root, "receipts", "r.json"),
        "policy": os.path.join(root, "policy.json"),
        "pending": os.path.join(root, "pending.json"),
        "expire_seconds": 900,
    }
    paths["config"] = os.path.join(root, "nullaosta.json")
    with open(paths["config"], "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
    paths["policy"] = config["policy"]
    with open(paths["policy"], "w", encoding="utf-8") as handle:
        json.dump(policy_mod.default_policy(), handle, indent=2)
    paths["receipt"] = config["receipt"]
    paths["pending"] = config["pending"]
    paths["params"] = os.path.join(root, "params.json")
    with open(paths["params"], "w", encoding="utf-8") as handle:
        json.dump({"order": "X-77", "cents": 4200}, handle)
    return paths


class KeyedCase(unittest.TestCase):
    """Base for tests that need a real OpenSSH environment."""

    @classmethod
    def setUpClass(cls):
        if not ssh_keygen_available():
            raise unittest.SkipTest(
                "ssh-keygen is not on PATH — refusing to fake the cryptography")
        cls.paths = make_environment()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.paths["root"], ignore_errors=True)
