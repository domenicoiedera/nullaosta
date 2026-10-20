"""nullaosta — fail-closed approval gate + third-party-verifiable receipts.

The library API is exactly three names, bound here and in pyproject.toml:

* :func:`decide` — the gate's fail-closed decision for one action attempt
  (binds the approval to the attempt's canonical hash, enforces single-use,
  the trust split, and the expiry latch);
* :func:`seal`   — append payloads to the receipt AND seal the tail in the
  same write (per-append cadence: no unsealed tail);
* :func:`verify` — independent verification from the receipt file and an
  allowed_signers anchor alone; nonzero exit on ANY tamper, including an
  unsealed tail.

Everything else lives in submodules (policy, receipt, verify, gate, cli,
proc).
"""

from .gate import decide, new_action, action_hash, approval_preimage
from .receipt import append_and_seal as seal
from .verify import verify

__version__ = "0.1.0"

__all__ = ["decide", "seal", "verify", "new_action", "action_hash",
           "approval_preimage", "__version__"]
