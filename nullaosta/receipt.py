"""Append-only, hash-chained, **per-append sealed** receipts.

One file, one writer, no unsealed tail — this is the part that fixes what a
chain alone cannot cover. Each entry is sealed the moment it is written, and
the seal signs the ENTIRE chain as of that append (the head through the new
entry), so the last entry is always covered. A file whose last entry has no
valid seal — a crash leftover, or anything that truncated a signature — is
UNSEALED = NOT OK, and :func:`load` says so loudly; it is never read as
"just one lost entry".

Pinned definitions (§3.0 in RECEIPT-SPEC; the tests pin them byte-exactly):

* **Canonical entry bytes** — the entry JSON object with the ``seal`` key
  removed, serialised sorted-keys, compact, ``ensure_ascii=False``, UTF-8.
  Unlike the signed action dict, ``seq``/``prev_hash`` STAY in the hashed
  bytes (see :func:`canonical_entry_bytes`): any rewrite of history forces a
  full downstream re-stamp, and the per-entry seal then makes even that
  detectable.
* **entry_hash** — ``sha256`` hex of the canonical entry bytes.
* **Genesis** — ``prev_hash`` of entry 0 is 64 hex zeros; ``seq`` is 0-based.
* **head(n)** — ``sha256`` over the newline-joined entry hashes of entries
  ``0..n-1``. This is the value the seal at append ``n`` signs.
* **Seal** — entry ``n``'s ``seal`` is ``{"covered": n, "head": head(n),
  "sig": SSHSIG}``; the SSHSIG signs the preimage
  ``nullaosta-receipt:v1:<n>:<head(n)>:<path>`` in namespace
  ``nullaosta-receipt``, made with the executor's receipt key.

Nothing here decides policy or reads approvals; :mod:`nullaosta.gate` and
:mod:`nullaosta.verify` do that on top of these primitives.
"""

import datetime
import hashlib
import json
import os
import subprocess
import tempfile

from . import proc
from .policy import canonical_bytes

MARKER = "nullaosta_receipt"
RECEIPT_VERSION = 1
GENESIS = "0" * 64
SEAL_NAMESPACE = "nullaosta-receipt"
SUB_TIMEOUT = 30  # every ssh-keygen call is bounded


class ReceiptError(Exception):
    """A receipt file that exists but cannot be used."""


class StructureError(ReceiptError):
    """The file is valid JSON but the receipt shape is unusable."""


class ChainBrokenError(ReceiptError):
    """The recorded hashes do not link up."""


class UnsealedError(ReceiptError):
    """The tail is not sealed — a crash leftover or truncation. NOT OK."""


def new_receipt(executor):
    """The empty receipt document for ``executor`` (the writer principal)."""
    return {MARKER: {"v": RECEIPT_VERSION},
            "executor": executor,
            "entries": []}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def canonical_entry_bytes(entry):
    """The exact bytes hashed for an entry — the ``seal`` key removed.
    ``seq`` and ``prev_hash`` participate (they are stamped-before-hash)."""
    body = {k: v for k, v in entry.items() if k != "seal"}
    return canonical_bytes(body)


def entry_hash(entry):
    return hashlib.sha256(canonical_entry_bytes(entry)).hexdigest()


def entries_hashes(entries):
    return [entry_hash(entry) for entry in entries]


def head_at(entries, count):
    """``head(count)`` — sha256 over the newline-joined entry hashes of the
    first ``count`` entries. The seed of every per-append seal."""
    joined = "\n".join(entries_hashes(entries)[:count])
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def head(entries):
    return head_at(entries, len(entries))


def stamp(entries, payloads):
    """Turn ``payloads`` (plain dicts, in order) into chain-valid entries.

    Callers build payloads; this assigns ``seq``/``prev_hash`` and returns
    the sealed-ready entry list tail-appended to ``entries``.
    """
    prev = entry_hash(entries[-1]) if entries else GENESIS
    out = []
    seq = len(entries)
    for payload in payloads:
        entry = dict(payload)
        entry["seq"] = seq
        entry["prev_hash"] = prev
        prev = entry_hash(entry)
        out.append(entry)
        seq += 1
    return out


def normalize_path(path):
    """``./r.json`` and ``r.json`` must seal and verify identically."""
    if not path:
        return path
    return os.path.normpath(path).replace("\\", "/")


def seal_preimage(count, head_value, path):
    """The exact string the receipt seal signs — pinned, field order matters."""
    return f"nullaosta-receipt:v1:{count}:{head_value}:{normalize_path(path)}"


# ── ssh-keygen plumbing (the executor's receipt key) ─────────────────────────


def ssh_keygen():
    import shutil
    return shutil.which("ssh-keygen")


def _leading_dash(path):
    return isinstance(path, str) and path.startswith("-")


def verify_sshsig(sig_text, preimage_text, namespace, allowed_signers, principal):
    """Validate ONE detached SSHSIG over a preimage string.

    Returns ``(True, principal)`` when ``principal``'s key validates it,
    ``(False, detail)`` otherwise, and ``(None, detail)`` when the check
    could not run at all (no tool, unreadable anchor) — the caller maps
    ``None`` to exit 2 ("could not decide"), never to a gate OPEN.
    """
    tool = ssh_keygen()
    if not tool:
        return (None, "ssh-keygen not found on PATH")
    if not allowed_signers or not os.path.isfile(allowed_signers):
        return (None, f"allowed_signers file not found: {allowed_signers!r}")
    if principal and _leading_dash(principal):
        return (None, "principal may not begin with '-'")
    workdir = tempfile.mkdtemp(prefix="nullaosta-verify-")
    try:
        data_file = os.path.join(workdir, "preimage")
        sig_file = os.path.join(workdir, "signature.sig")
        with open(data_file, "w", encoding="utf-8", newline="") as handle:
            handle.write(preimage_text)
        with open(sig_file, "w", encoding="utf-8", newline="") as handle:
            handle.write(sig_text)
        with open(data_file, "rb") as preimage_stream:
            result = proc.run(
                [tool, "-Y", "verify", "-f", allowed_signers, "-I", principal,
                 "-n", namespace, "-s", sig_file],
                stdin=preimage_stream, timeout=SUB_TIMEOUT)
    except subprocess.TimeoutExpired:
        return (None, f"ssh-keygen timed out after {SUB_TIMEOUT}s")
    except OSError as exc:
        return (None, f"cannot run the verification — {exc}")
    finally:
        for name in (data_file, sig_file):
            try:
                os.unlink(name)
            except OSError:
                pass
        try:
            os.rmdir(workdir)
        except OSError:
            pass
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        return (False, detail)
    return (True, principal)


def sign_preimage(preimage_text, key_path, namespace):
    """Produce a detached SSHSIG over ``preimage_text`` with ``key_path``.

    The key bytes are read by ``ssh-keygen`` only — this module never touches
    them. Returns ``(sig_text, None)`` on success, ``(None, detail)`` when
    signing is impossible (fail-closed for every caller).
    """
    tool = ssh_keygen()
    if not tool:
        return (None, "ssh-keygen not found on PATH — cannot sign")
    if _leading_dash(key_path):
        return (None, f"key path may not begin with '-': {key_path!r}")
    if not key_path or not os.path.isfile(key_path):
        return (None, f"signing key not found: {key_path!r}")
    workdir = tempfile.mkdtemp(prefix="nullaosta-sign-")
    try:
        data_file = os.path.join(workdir, "preimage")
        with open(data_file, "w", encoding="utf-8", newline="") as handle:
            handle.write(preimage_text)
        result = proc.run(
            [tool, "-Y", "sign", "-f", key_path, "-n", namespace, data_file],
            timeout=SUB_TIMEOUT)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            return (None, f"ssh-keygen -Y sign failed (exit {result.returncode}): {detail}")
        with open(data_file + ".sig", encoding="utf-8") as handle:
            return (handle.read(), None)
    except subprocess.TimeoutExpired:
        return (None, f"ssh-keygen timed out after {SUB_TIMEOUT}s while signing")
    except OSError as exc:
        return (None, f"cannot sign — {exc}")
    finally:
        for name in os.listdir(workdir):
            try:
                os.unlink(os.path.join(workdir, name))
            except OSError:
                pass
        try:
            os.rmdir(workdir)
        except OSError:
            pass


# ── load / append / save ─────────────────────────────────────────────────────


def load(path):
    """Load the receipt file, verifying structure AND every seal.

    Absent/empty => a fresh empty document (nothing has happened yet). A
    file that exists and cannot be parsed — including a write-truncated or
    hand-edited one — raises, because the dangerous failure of this artifact
    is reading it as clean. A file whose last entry carries no seal, or a
    seal that does not cover the current head, raises :class:`UnsealedError`.
    """
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        return new_receipt(None)
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ReceiptError(f"{path}: unreadable receipt (possibly truncated) — {exc}") from exc
    if not isinstance(data, dict):
        raise StructureError(f"{path}: receipt root must be a JSON object")
    marker = data.get(MARKER)
    if not isinstance(marker, dict) or marker.get("v") != RECEIPT_VERSION:
        raise StructureError(
            f"{path}: unsupported receipt marker {marker!r}; "
            f"expected {{'v': {RECEIPT_VERSION}}}")
    executor = data.get("executor")
    if not isinstance(executor, str) or not executor:
        raise StructureError(f"{path}: receipt 'executor' must be a non-empty string")
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise StructureError(f"{path}: receipt 'entries' must be a list")
    verify_chain(entries)
    return data


def verify_chain(entries):
    """Walk order + linkage, then every per-entry seal's *head* coverage.

    Signature validation against a trust anchor is :mod:`nullaosta.verify`'s
    job; this checks the arithmetic the tamper detection stands on. Raises
    :class:`ChainBrokenError` on a broken link, :class:`UnsealedError` on a
    tail whose last seal does not cover the entries it claims.
    """
    prev = GENESIS
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise StructureError(f"entry {index} is not an object")
        if "seq" not in entry or "prev_hash" not in entry:
            raise StructureError(f"entry {index}: missing seq/prev_hash")
        if entry["seq"] != index:
            raise StructureError(f"entry {index}: seq {entry['seq']!r} != {index}")
        if entry["prev_hash"] != prev:
            raise ChainBrokenError(f"chain broken at entry {index}")
        prev = entry_hash(entry)
    if entries:
        # The no-unsealed-tail rule (§5): the last entry's seal must exist and
        # must cover EVERY entry so far.
        last = entries[-1]
        seal = last.get("seal")
        if not isinstance(seal, dict) or not seal.get("sig"):
            raise UnsealedError(
                f"entry {len(entries) - 1} has no seal — the receipt is UNSEALED "
                f"(crash or truncation); the receipt is NOT OK")
        if seal.get("covered") != len(entries):
            raise UnsealedError(
                f"entry {len(entries) - 1} seal claims to cover {seal.get('covered')!r} "
                f"entries but the file holds {len(entries)} — UNSEALED/UNCOVERED tail")
        if seal.get("head") != head_at(entries, len(entries)):
            raise UnsealedError(
                f"entry {len(entries) - 1} seal head does not match the current "
                f"chain head — the tail changed after it was sealed")


def append_and_seal(path, payloads, key, executor=None):
    """Append ``payloads`` and seal the tail in the same write (§5 cadence).

    Writes atomically (temp + ``os.replace``), so the file at rest is either
    the old complete state or the new complete state. Returns
    ``(doc, None)`` on success or ``(None, detail)`` failure — a failure
    leaves the file exactly as it was.
    """
    doc = load(path)
    configured_executor = executor or doc["executor"]
    if not doc.get("executor"):
        if not configured_executor:
            raise ReceiptError("no executor configured for a fresh receipt")
        doc["executor"] = configured_executor
    if doc["executor"] != configured_executor:
        raise ReceiptError(
            f"receipt executor {doc['executor']!r} != "
            f"configured {configured_executor!r}")
    new_entries = stamp(doc.get("entries", []), payloads)
    entries = list(doc["entries"]) + new_entries
    try:
        base = len(entries) - len(new_entries)
        # Per-append cadence, but per-ENTRY coverage: every entry written in
        # this call is sealed against the head THROUGH itself, so any reader
        # sees a fully sealed tail at every point in the chain.
        for index in range(base, len(entries)):
            covered = index + 1
            head_value = head_at(entries, covered)
            preimage = seal_preimage(covered, head_value, path)
            sig, error = sign_preimage(preimage, key, SEAL_NAMESPACE)
            if sig is None:
                return (None, error)
            entries[index]["seal"] = {"covered": covered, "head": head_value,
                                      "sig": sig}
        save(path, {MARKER: doc[MARKER], "executor": doc["executor"],
                    "entries": entries})
    except (ReceiptError, OSError) as exc:
        return (None, str(exc))
    return (load(path), None)


def save(path, doc):
    """Atomically write the receipt document (single writer assumed)."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    directory, base = os.path.split(os.path.abspath(path))
    handle, tmp = tempfile.mkstemp(dir=directory, prefix=base + ".tmp-")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            json.dump(doc, stream, ensure_ascii=False, indent=1, sort_keys=True)
            stream.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
