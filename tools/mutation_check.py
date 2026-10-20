#!/usr/bin/env python3
"""mutation_check — prove the fail-closed guards are LOAD-BEARING.

For each guard below: disable it in the source (a single, exact,
one-site replacement), run the matching discriminating tests, and require
them to go RED; restore the source and require GREEN again. If any guard's
tests still pass with the guard deleted, that guard is decoration and the
harness exits 1.

Usage: python3 tools/mutation_check.py [--guard NAME] [--fast-tail]
Exit 0 — every guard flips its tests RED (mutated) and GREEN (restored).
Exit 1 — at least one guard did not.

The replacements must match EXACTLY ONE occurrence in their file; the
harness verifies occurrence count before mutating and refuses to guess.
"""

import argparse
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON = sys.executable

GUARDS = (
    # 1. broken chain linkage (order/prev_hash) is caught, not ignored
    {
        "id": "chain_link",
        "why": "a rewritten entry (order or content) must break verification "
               "and the gate's receipt load, never read as a clean chain",
        "mutations": [("nullaosta/receipt.py",
                       '        raise ChainBrokenError(f"chain broken at entry {index}")',
                       '        pass  # MUTATION')],
        "tests": ["tests.test_tamper.TestEntryLevelTamper."
                  "test_single_field_edit_fails_verification"],
    },
    # 2. a tail without a sealed, covering seal is UNSEALED = NOT OK
    {
        "id": "seal_coverage",
        "why": "the per-append seal cadence: an entry without its seal is "
               "never 'just one lost entry' — it makes the file fail verify",
        "mutations": [
            ("nullaosta/receipt.py",
             '        seal = last.get("seal")\n'
             '        if not isinstance(seal, dict) or not seal.get("sig"):\n',
             '        seal = last.get("seal")\n'
             '        if False and (not isinstance(seal, dict) or not seal.get("sig")):\n'),
            ("nullaosta/verify.py",
             '        if not isinstance(seal, dict) or not seal.get("sig") or \\\n'
             '                seal.get("covered") != index + 1:\n',
             '        if False:\n'),
        ],
        "tests": ["tests.test_tamper.TestFileLevelTamper."
                  "test_unsealed_tail_fails_verification"],
    },
    # 3. the executor principal is not a valid approver (trust split)
    {
        "id": "trust_split",
        "why": "an approval by the writer's own principal must NEVER open a "
               "gated action and must fail third-party verification",
        "mutations": [
            ("nullaosta/verify.py",
             '            if principal == executor:\n',
             '            if False and principal == executor:\n'),
            ("nullaosta/gate.py",
             '    if matched == executor:\n',
             '    if False and matched == executor:\n'),
        ],
        "tests": ["tests.test_tamper.TestApprovalTamper."
                  "test_approval_by_the_executor_key_on_a_fresh_action_fails"],
    },
    # 4. approve refuses the executor as its principal
    {
        "id": "approve_split",
        "why": "the human verb itself must refuse to sign as the executor",
        "mutations": [("nullaosta/cli.py",
                       '    if args.principal == executor:\n',
                       '    if False and args.principal == executor:\n')],
        "tests": ["tests.test_cli_e2e.TestApproveRefusals."
                  "test_self_reference_refused"],
    },
    # 5. the single-use ledger
    {
        "id": "spent_ledger",
        "why": "a consumed nonce must be unspendable — at the gate AND on "
               "third-party re-verification",
        "mutations": [
            ("nullaosta/gate.py",
             '    if is_spent(receipt_doc.get("entries", []), action.get("nonce", "")):\n',
             '    if False and is_spent(receipt_doc.get("entries", []), action.get("nonce", "")):\n'),
            ("nullaosta/verify.py",
             '            if action.get("nonce") in seen:\n',
             '            if False and action.get("nonce") in seen:\n'),
        ],
        "tests": ["tests.test_cli_e2e.TestCheckApproveLoop."
                  "test_replay_same_approval_same_action_is_spent",
                  "tests.test_tamper.TestApprovalTamper."
                  "test_spent_nonce_reopened_twice_fails_verification"],
    },
    # 6. an approval must be bound to THIS attempt's canonical action hash
    {
        "id": "approval_binding",
        "why": "a captured approval reused on a later identical attempt "
               "(fresh nonce) must be refused as INVALID",
        "mutations": [("nullaosta/gate.py",
                       '    if matched is None:\n',
                       '    if False and matched is None:\n')],
        "tests": ["tests.test_cli_e2e.TestCheckApproveLoop."
                  "test_replay_of_the_same_approval_on_a_later_identical_action_"
                  "is_blocked"],
    },
    # 7. a policy DENY cannot be approved open
    {
        "id": "policy_deny",
        "why": "deny outranks any signature: no approval opens a denied action",
        "mutations": [("nullaosta/gate.py",
                       '    if verdict_policy == "deny":\n',
                       '    if False and verdict_policy == "deny":\n')],
        "tests": ["tests.test_cli_e2e.TestOtherBranches."
                  "test_policy_deny_blocks_even_with_a_valid_approval"],
    },
    # 8. seals by any key other than the executor's are rejected
    {
        "id": "seal_signature",
        "why": "a swapped attacker key re-signing the seal must fail "
               "verification, though the SSHSIG itself is valid",
        "mutations": [("nullaosta/verify.py",
                       '        if not ok:\n'
                       '            return _raise1(\n'
                       '                "SEAL-INVALID",\n',
                       '        if False and not ok:\n'
                       '            return _raise1(\n'
                       '                "SEAL-INVALID",\n')],
        "tests": ["tests.test_tamper.TestSealTamper."
                  "test_swapped_key_on_the_seal_fails_verification",
                  "tests.test_tamper.TestSealTamper."
                  "test_forged_receipt_resealed_by_a_forged_executor_fails"],
    },
    # 9. freshness: approvals die with their own issued_at
    {
        "id": "expire_guard",
        "why": "an attempt older than expire_seconds must be refused "
               "regardless of signature validity",
        "mutations": [("nullaosta/gate.py",
                       '    if _age_seconds(action) > expire_seconds:\n',
                       '    if False and _age_seconds(action) > expire_seconds:\n')],
        "tests": ["tests.test_cli_e2e.TestOtherBranches."
                  "test_expired_attempt_is_blocked"],
    },
    # 10. the recorded action_hash must equal the canonical re-derivation
    {
        "id": "action_hash_binding",
        "why": "the receipt cannot claim an action_hash the action's bytes "
               "do not produce (the binding approvals signed)",
        "mutations": [("nullaosta/verify.py",
                       '        if entry.get("action_hash") != action_hash(action):\n',
                       '        if False and entry.get("action_hash") != action_hash(action):\n')],
        "tests": ["tests.test_tamper.TestEntryLevelTamper."
                  "test_mismatched_action_hash_fails_verification"],
    },
)


def run_tests(test_ids):
    """Run one unittest invocation with the given ids; True = all pass."""
    args = [PYTHON, "-m", "unittest", *test_ids]
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                            timeout=600)
    return result.returncode == 0, (result.stdout + result.stderr)[-400:]


def apply_guard(muts, reverse=False):
    """Apply (or, reverse, pre-check) the mutations; returns list of
    (path, original_bytes, mutated_bytes) and any error detail."""
    applied = []
    for path, old, new in muts:
        target = os.path.join(ROOT, path)
        with open(target, "r", encoding="utf-8") as handle:
            text = handle.read()
        want = new if reverse else old
        if want not in text:
            return None, f"target string not found in {path}"
        if text.count(want) != 1:
            return None, f"target string occurs {text.count(want)}x in {path}, not 1"
        with open(target, "wb") as handle:
            handle.write(text.replace(want, new if not reverse else old)
                         .encode("utf-8"))
        applied.append((target, text.encode("utf-8")))
    return applied, None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guard", default=None,
                        help="run one guard only (by id)")
    args = parser.parse_args(argv)

    selection = GUARDS
    if args.guard:
        selection = [g for g in GUARDS if g["id"] == args.guard]
        if not selection:
            print(f"unknown guard {args.guard!r}; known: "
                  + ", ".join(g["id"] for g in GUARDS))
            return 2

    bad = []
    print(f"mutation_check: {len(selection)} guard(s) x "
          f"RED(mutated)/GREEN(restore)")
    for guard in selection:
        print(f"\n== guard {guard['id']}: {guard['why']}")
        # GREEN first: the tests must pass on the clean tree.
        ok, tail = run_tests(guard["tests"])
        if not ok:
            print(f"   CLEAN TREE: FLANKED — tests did not pass unmutated "
                  f"(infra problem, not a proof):", tail[-200:])
            bad.append(guard["id"])
            continue
        print("   clean tree: GREEN (tests pass)")
        applied, error = apply_guard(guard["mutations"])
        if error:
            print(f"   MUTATION ERROR: {error}")
            bad.append(guard["id"])
            continue
        try:
            red_ok, tail = run_tests(guard["tests"])
        finally:
            with open(applied[0][0], "wb") as handle:   # guaranteed restore
                handle.write(applied[0][1])
            for target, blob in applied[1:]:
                with open(target, "wb") as handle:
                    handle.write(blob)
        if red_ok:
            print("   MUTATED: still GREEN — the guard is NOT load-bearing")
            bad.append(guard["id"])
        else:
            print("   mutated: RED (gate catches the deletion)")
        ok, _tail = run_tests(guard["tests"])
        print("   restored:", "GREEN (tests pass again)" if ok else "STILL RED")
        if not ok:
            bad.append(guard["id"] + "#restore")

    print()
    if bad:
        print(f"mutation_check FAILURE: {', '.join(bad)}")
        return 1
    print(f"mutation_check OK: {len(selection)}/{len(selection)} guards are "
          f"load-bearing (RED(mutated) / GREEN(restored))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
