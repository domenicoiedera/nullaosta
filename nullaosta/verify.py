"""Independent third-party verification: receipt file + allowed_signers ONLY.

The verifier holds no private key and no state file beyond the two inputs.
For every entry it re-derives (a) the canonical action bytes and the
``action_hash``; (b) the chain linkage; (c) the per-append seal — the entry's
own seal must cover the head THROUGH that entry and validate under the
receipt's ``executor`` principal; (d) for every OPEN entry of a gated class,
the approval: SSHSIG valid over the entry's OWN action hash, principal inside
``allowed_signers`` and distinct from the executor (the trust split);
(e) the single-use ledger: no nonce consumed twice.

Exit taxonomy (§7): **0** verified; **1** any tamper/spend/split breach —
including UNSEALED = NOT OK (crash-truncated tail, missing seal, stale seal);
**2** could not run at all (no ssh-keygen, unreadable anchor). Never a
traceback; the reason string names the breach class.

This answers the EVIDENCE question: receipts intact and independently
signed. It does not claim the gate intercepted actions that never went
through it.
"""

import hashlib
import os

from . import receipt
from .gate import APPROVAL_NAMESPACE, action_hash, approval_preimage, spent_nonces

# Breach classes verify can report (each one ALSO has a discriminating test):
BREACHES = (
    "MISMATCHED-ACTION-HASH",
    "NO-APPROVAL-ON-OPEN",
    "APPROVAL-INVALID",
    "TRUST-SPLIT-VIOLATION",
    "SPENT-NONCE-REUSE",
    "UNSEALED-OR-TRUNCATED",
    "SEAL-INVALID",
    "SEAL-STALE",
    "CHAIN-BROKEN",
    "STRUCTURE-BROKEN",
)


class VerifyInputError(Exception):
    """An input verify cannot read at all — exit 2 territory."""


def _raise1(breach, detail):
    return {"ok": False, "exit": 1, "breach": breach, "detail": detail}


def verify(receipt_path, allowed_signers):
    """Verify ``receipt_path`` against ``allowed_signers``.

    Returns a dict ``{"ok", "exit", "breach", "detail", "entries"}`` —
    ``ok=True`` only when every check below passes.
    """
    tool = receipt.ssh_keygen()
    if not tool:
        return {"ok": False, "exit": 2, "breach": None,
                "detail": "ssh-keygen not found on PATH — verification could not run"}
    if not allowed_signers or not os.path.isfile(allowed_signers):
        return {"ok": False, "exit": 2, "breach": None,
                "detail": f"allowed_signers not found: {allowed_signers!r}"}
    if not receipt_path or not os.path.exists(receipt_path):
        raise VerifyInputError(f"receipt not found: {receipt_path!r}")
    try:
        doc = receipt.load(receipt_path)
    except receipt.ReceiptError as exc:
        # Unparsable/truncated/structure-broken/unsealed all fail verification
        # with exit 1 — never treated as an empty clean receipt.
        breach = "UNSEALED-OR-TRUNCATED" if isinstance(exc, receipt.UnsealedError) else (
            "CHAIN-BROKEN" if isinstance(exc, receipt.ChainBrokenError) else
            "STRUCTURE-BROKEN" if isinstance(exc, receipt.StructureError) else
            # remaining ReceiptError = the file itself could not be parsed —
            # a torn write or byte truncation: NOT OK either way
            "UNSEALED-OR-TRUNCATED")
        return _raise1(breach, str(exc))
    executor = doc["executor"]
    entries = doc.get("entries", [])
    path = receipt.normalize_path(receipt_path)

    seen = set()
    for index, entry in enumerate(entries):
        # (a) action bytes — the receipt's OWN recorded hash must match the
        # canonical re-derivation, or the binding the approval signed is not
        # the action this entry claims.
        action = entry.get("action")
        if not isinstance(action, dict):
            return _raise1("STRUCTURE-BROKEN", f"entry {index}: missing action")
        if entry.get("action_hash") != action_hash(action):
            return _raise1(
                "MISMATCHED-ACTION-HASH",
                f"entry {index}: action_hash does not match the action's "
                f"canonical bytes")
        decision = entry.get("decision", {})
        verdict = decision.get("verdict") if isinstance(decision, dict) else None

        # (e) single-use: a nonce may be SPENT (consumed by an OPEN of a
        # gated class) exactly once. Blocked attempts only record the
        # attempt — the approved approval may legitimately follow them.
        if verdict == "OPEN" and entry.get("gated"):
            if action.get("nonce") in seen:
                return _raise1(
                    "SPENT-NONCE-REUSE",
                    f"entry {index} OPENs nonce {action['nonce'][:12]}… that "
                    f"another OPEN already consumed — every approval is "
                    f"single-use")
            seen.add(action.get("nonce"))

        # (b+c) chain seals — every seal, not just the tail's.
        seal = entry.get("seal")
        if not isinstance(seal, dict) or not seal.get("sig") or \
                seal.get("covered") != index + 1:
            return _raise1("UNSEALED-OR-TRUNCATED",
                           f"entry {index}: seal missing or coverage wrong")
        expected_head = hashlib.sha256(
            "\n".join(receipt.entry_hash(e) for e in entries[:index + 1]).
            encode("utf-8")).hexdigest()
        if seal.get("head") != expected_head:
            return _raise1("SEAL-STALE",
                           f"entry {index}: seal head does not cover this "
                           f"chain position — entries changed after sealing")
        ok, detail = receipt.verify_sshsig(
            str(seal["sig"]),
            receipt.seal_preimage(index + 1, expected_head, path),
            receipt.SEAL_NAMESPACE, allowed_signers, executor)
        if ok is None:
            return {"ok": False, "exit": 2, "breach": None, "detail": detail}
        if not ok:
            return _raise1(
                "SEAL-INVALID",
                f"entry {index}: seal does not validate as '{executor}': {detail}")

        # (d) the trust split and the approval binding.
        approval = entry.get("approval")
        if verdict == "OPEN" and entry.get("gated"):
            if not isinstance(approval, dict) or not approval.get("sig"):
                return _raise1("NO-APPROVAL-ON-OPEN",
                               f"entry {index}: OPEN on a gated class with no approval")
            principal = approval.get("principal")
            if not isinstance(principal, str) or not principal:
                return _raise1("APPROVAL-INVALID",
                               f"entry {index}: approval names no principal")
            ok, detail = receipt.verify_sshsig(
                str(approval["sig"]),
                approval_preimage(entry["action_hash"]),
                APPROVAL_NAMESPACE, allowed_signers, principal)
            if ok is None:
                return {"ok": False, "exit": 2, "breach": None, "detail": detail}
            if not ok:
                return _raise1("APPROVAL-INVALID", f"entry {index}: {detail}")
            if principal == executor:
                return _raise1(
                    "TRUST-SPLIT-VIOLATION",
                    f"entry {index}: approval principal '{principal}' IS the "
                    f"executor '{executor}' — the approver must be independent")
            spent = entry.get("spent")
            if not isinstance(spent, dict) or spent.get("nonce") != action.get("nonce"):
                return _raise1(
                    "STRUCTURE-BROKEN",
                    f"entry {index}: an OPEN gated entry must spend its own nonce")

    # (e) the ledger, computed for the report: every OPEN item spends a
    # nonce, and per-entry duplication was already rejected above.
    claimed = spent_nonces(entries)
    return {"ok": True, "exit": 0, "breach": None,
            "detail": (f"{len(entries)} entr(ies) verified: chain sound, seals "
                       f"valid as '{executor}', approvals trusted and "
                       f"non-executor, nonces single-use"),
            "spent": sorted(claimed), "entries": len(entries)}


def render(result):
    """One human line plus the structured detail the tests pin."""
    if result["exit"] == 0:
        return f"verify OK: {result['detail']}"
    breach = f" [{result['breach']}]" if result.get("breach") else ""
    return f"verify NOT OK{breach}: {result['detail']}"
