"""The fail-closed gate: policy decision + approval binding + single-use.

The irreversible classes (pay / submit / delete / send / publish) never open
on policy alone. Every OPEN needs, for THIS attempt:

1. a VERDICT that is not ``deny`` (a naked ``deny`` cannot be approved open);
2. an approval whose SSHSIG validates over the canonical bytes of **this
   exact attempt** — the ``action_hash`` of
   ``{action_class, target, params_digest, nonce, issued_at}``, nonce
   freshly minted by the gate per attempt — in namespace
   ``nullaosta-approval``, by a principal inside ``allowed_signers`` that is
   **not** the executor (the trust split, §3.3);
3. a nonce not spent in the sealed receipt ledger (single-use);
4. freshness: not older than ``expire_seconds`` from its own ``issued_at``.

Any miss is BLOCKED (exit 1 at the CLI) — a hung/absent approver, an expired
approval, a replay, a spent nonce, or a wrong key all land on the same
latch: closed. Exit 2 is reserved for "could not decide" (unreadable
config/policy, ssh-keygen unavailable); 2 is also not an OPEN.

Every decision — OPEN or BLOCKED — is appended to the receipt and sealed
immediately, so the third-party artifact records what was gated and why.
"""

import datetime
import hashlib
import json
import secrets

from . import receipt
from .policy import (canonical_bytes, digest_bytes, rule_for)

APPROVAL_NAMESPACE = "nullaosta-approval"
APPROVAL_VERSION = "v1"

# The fail-closed branch taxonomy every caller prints verbatim.
BRANCHES = (
    "POLICY-DENY",
    "NO-APPROVAL",
    "APPROVER-UNREACHABLE",
    "INVALID-APPROVAL",
    "REPLAYED",
    "SPENT",
    "EXPIRED",
    "NOT-AUTHORIZED",
    "OPEN",
)


class GateError(Exception):
    """Input the gate cannot use — maps to exit 2, never to an OPEN."""


def new_action(action_class, target, params):
    """One fresh attempt: digest the params, mint the nonce, hash the action.

    The nonce is generated HERE, per attempt — this is the property that
    makes a captured approval useless on any later run, even of the very
    same command with the same params.
    """
    action = {
        "action_class": action_class,
        "target": target,
        "params_digest": digest_bytes(params),
        "nonce": secrets.token_hex(16),
        "issued_at": receipt.now(),
    }
    return action


def action_hash(action):
    """sha256 hex over the canonical action bytes — the value approvals sign."""
    return hashlib.sha256(canonical_bytes(action)).hexdigest()


def load_action_file(path):
    """Re-derive the action from a pending file; any inconsistency raises
    :class:`GateError` (exit 2 — a locally inconsistent instrument is never
    turned into a decision)."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise GateError(f"{path}: unreadable pending action — {exc}") from exc
    marker = data.get("nullaosta_action")
    if not isinstance(marker, dict) or marker.get("v") != 1:
        raise GateError(f"{path}: unsupported pending-action marker {marker!r}")
    action = data.get("action")
    params = data.get("params")
    recorded = data.get("action_hash")
    if not (isinstance(action, dict) and isinstance(params, dict)
            and isinstance(recorded, str)):
        raise GateError(f"{path}: pending action is not the recorded shape")
    if action.get("params_digest") != digest_bytes(params):
        raise GateError(f"{path}: params do not digest to the recorded params_digest")
    if action_hash(action) != recorded:
        raise GateError(f"{path}: recorded action_hash does not match the action")
    return action, params


def approval_preimage(action_hash_hex):
    """The exact string the approver signs — pinned; do not reorder fields."""
    return f"nullaosta-approval:{APPROVAL_VERSION}:{action_hash_hex}"


def _age_seconds(action):
    """Seconds since the attempt's own ``issued_at`` (its expiry anchor)."""
    issued = action.get("issued_at", "")
    try:
        issued_at = datetime.datetime.fromisoformat(issued)
    except ValueError:
        raise GateError(f"action issued_at is not ISO-8601: {issued!r}")
    at = datetime.datetime.now(datetime.timezone.utc)
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=datetime.timezone.utc)
    return (at - issued_at).total_seconds()


def is_spent(entries, nonce):
    """Single-use ledger over the sealed chain: the nonce must appear in
    exactly zero entries for a fresh attempt (any OPEN of a gated class
    spends its action's nonce)."""
    for entry in entries:
        spent = entry.get("spent") if isinstance(entry, dict) else None
        if isinstance(spent, dict) and spent.get("nonce") == nonce:
            return True
    return False


def spent_nonces(entries):
    """Every nonce any OPEN entry consumed — used by verify's replay audit."""
    spent = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("decision", {}).get("verdict") == "OPEN":
            action = entry.get("action")
            if isinstance(action, dict) and isinstance(action.get("nonce"), str):
                spent.add(action["nonce"])
    return spent


def decide(policy, receipt_doc, action, params, approval, allowed_signers,
           executor, expire_seconds=900):
    """The ONE gate decision. Returns ``(verdict, branch, detail, matched)``.

    ``verdict`` is ``"OPEN"`` or ``"BLOCKED"``; ``branch`` is one of
    :data:`BRANCHES` (None on OPEN); ``matched`` is the verifying principal
    on OPEN, else ``None``. Ordering is deliberate: hard deny first, then
    approval supply, then cryptographic validity, then identity, then
    single-use, then freshness — each is an independent latch on CLOSED.
    """
    verdict_policy = rule_for(policy, action["action_class"], action["target"])
    if verdict_policy == "deny":
        return ("BLOCKED", "POLICY-DENY",
                f"policy denies '{action['action_class']}' on "
                f"'{action['target']}' — approval cannot open a deny", None)
    if verdict_policy == "allow":
        return "OPEN", None, "policy allows this class for this domain", None
    if approval is None or not str(approval).strip():
        return ("BLOCKED", "NO-APPROVAL",
                "gated class needs an independently signed approval — none "
                "was presented; the action is on hold", None)
    recorded_hash = action_hash(action)
    preimage = approval_preimage(recorded_hash)
    candidates = _candidate_principals(allowed_signers)
    if candidates is None:
        raise GateError(f"allowed_signers unreadable: {allowed_signers!r}")
    if not candidates:
        raise GateError(f"allowed_signers names no principal: {allowed_signers!r}")
    matched = None
    invalid_detail = "no allowed principal validates the approval"
    for principal in candidates:
        ok, detail = receipt.verify_sshsig(
            str(approval), preimage, APPROVAL_NAMESPACE, allowed_signers,
            principal)
        if ok is None:          # could not run at all — exit 2 territory
            raise GateError(detail)
        if ok:
            matched = principal
            break
        if detail:
            invalid_detail = detail
    if matched is None:
        return ("BLOCKED", "INVALID-APPROVAL",
                f"approval does not sign this action's canonical hash "
                f"({recorded_hash[:12]}…): {invalid_detail}", None)
    if matched == executor:
        return ("BLOCKED", "NOT-AUTHORIZED",
                f"approval signed by the executor identity '{executor}' — the "
                f"trust split requires an approver distinct from the writer",
                None)
    if is_spent(receipt_doc.get("entries", []), action.get("nonce", "")):
        return ("BLOCKED", "SPENT",
                f"nonce {action['nonce'][:12]}… was already spent in the "
                f"sealed ledger — every approval is single-use", None)
    if _age_seconds(action) > expire_seconds:
        return ("BLOCKED", "EXPIRED",
                f"the attempt is older than {expire_seconds}s "
                f"(issued_at {action.get('issued_at')}) — approvals do not "
                f"survive their own timeout", None)
    detail = (f"approval by '{matched}' over action hash "
              f"{recorded_hash[:12]}… verified, unspent, in time")
    return "OPEN", None, detail, matched


def _candidate_principals(allowed_signers):
    """Principals named in an ``allowed_signers`` file (first field), or
    ``None`` when the file cannot be read (the caller raises GateError → 2)."""
    try:
        with open(allowed_signers, encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None
    names = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for name in line.split()[0].split(","):
            name = name.strip()
            if name and name not in names:
                names.append(name)
    return names


def record_decision(action, approval_sig, verdict, branch, detail, matched,
                    gated, expire_seconds):
    """Build the receipt payload for one decision.

    The receipt stores digests, never raw payloads, and a detached
    signature text — enough for an independent verifier to redo every
    check without either key.
    """
    payload = {
        "at": receipt.now(),
        "action": action,
        "action_hash": action_hash(action),
        "gated": bool(gated),
        "decision": {"verdict": verdict,
                     "branch": branch,
                     "detail": detail,
                     "expire_seconds": expire_seconds},
    }
    if approval_sig:
        payload["approval"] = {"principal": matched, "sig": str(approval_sig)}
    if verdict == "OPEN" and gated:
        payload["spent"] = {"nonce": action["nonce"]}
    return payload
