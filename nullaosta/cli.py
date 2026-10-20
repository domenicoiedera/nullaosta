"""Command-line entry point.

``nullaosta <verb> [flags]`` — init, check, approve, verify, log.

Every decision verb is fail-closed: 0 = OPEN/verified, 1 = BLOCKED/tamper,
2 = could not decide (usage, unreadable instruments, a subprocess that would
not answer). A traceback is never an exit path.
"""

import argparse
import json
import os
import subprocess
import sys

from . import __version__, gate, policy, proc, receipt
from .verify import VerifyInputError, render, verify as _verify_one

DEFAULT_CONFIG = "./nullaosta.json"
DEFAULT_PENDING = "./nullaosta-pending.json"


class ConfigError(Exception):
    """A config that exists but cannot be used (exit 2)."""


# ── forced UTF-8 on any host code page ───────────────────────────────────────

def _force_utf8_output():
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


# ── config ───────────────────────────────────────────────────────────────────

def load_config(path):
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        raise ConfigError(
            f"no config at {path or DEFAULT_CONFIG!r} — run 'nullaosta init' first")
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("nullaosta_config", {}).get("v") != 1:
        raise ConfigError(f"{path}: unsupported config (expected nullaosta_config v1)")
    executor = data.get("executor")
    if not isinstance(executor, str) or not executor:
        raise ConfigError(f"{path}: 'executor' must be a non-empty string")
    return data


def cfg_path(config, key, default):
    value = config.get(key, default)
    return value if value else default


# ── init ─────────────────────────────────────────────────────────────────────

def cmd_init(args):
    config_path = args.config
    if config_path and os.path.exists(config_path):
        print(f"refusing to overwrite existing config {config_path}", file=sys.stderr)
        return 2
    config = {
        "nullaosta_config": {"v": 1},
        "executor": args.executor,
        "config_path": config_path,
        "receipt": args.receipt,
        "policy": args.policy,
        "pending": DEFAULT_PENDING,
        "expire_seconds": 900,
    }
    policy_path = args.policy
    if policy_path and os.path.exists(policy_path):
        print(f"keeping existing policy at {policy_path}", file=sys.stderr)
    else:
        with open(policy_path, "w", encoding="utf-8") as handle:
            json.dump(policy.default_policy(), handle, indent=2, sort_keys=True)
            handle.write("\n")
    parent = os.path.dirname(os.path.abspath(config_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"initialized {config_path}")
    print(f"  executor (receipt writer): {args.executor}")
    print(f"  receipt:                   {args.receipt}")
    print(f"  policy:                    {policy_path}")
    print("next: generate two SEPARATE OpenSSH keys (receipt key for the "
          "writer, approver key for a human) and write allowed_signers "
          "OUTSIDE this repo, then name it with --allowed-signers on "
          "check/verify/approve runs.")
    return 0


# ── shared plumbing for check ────────────────────────────────────────────────

def _read_params_file(path):
    try:
        with open(path, encoding="utf-8") as handle:
            params = json.load(handle)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise gate.GateError(f"{path}: unreadable params — {exc}") from exc
    if not isinstance(params, dict):
        raise gate.GateError(f"{path}: params must be a JSON object")
    return params


def _write_pending(path, action, params):
    doc = {"nullaosta_action": {"v": 1},
           "action": action,
           "params": params,
           "action_hash": gate.action_hash(action)}
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)
    return doc


def _run_approver(argv, pending_path, seconds):
    """Invoke a configured approver command. Returns (sig_text, None) or
    (None, detail). Bounded; output is UTF-8; no secrets are printed."""
    argv = [argv, pending_path]
    try:
        result = proc.run(argv, timeout=seconds)
    except subprocess.TimeoutExpired:
        return (None, f"approver did not answer within {seconds}s")
    except FileNotFoundError:
        return (None, f"approver command not found: {argv[0]!r} (unreachable)")
    except OSError as exc:
        return (None, f"approver unreachable: {exc}")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        return (None, f"approver exited {result.returncode}: {detail[:200]}")
    return (result.stdout or "", None)


def _append(config, payload, key_path):
    """Append+seal; a receipt the writer cannot seal is a hard stop (exit 2),
    never a decision recorded unsigned."""
    doc, detail = receipt.append_and_seal(
        cfg_path(config, "receipt", "./nullaosta-receipt.json"),
        [payload], key_path, executor=config["executor"])
    if doc is None:
        raise ConfigError(f"cannot seal the receipt: {detail}")
    return doc


def cmd_check(args):
    config = load_config(args.config)
    absolute = os.path.abspath(cfg_path(config, "policy", "./policy.json"))
    pol = policy.load(absolute)
    expire = args.expire_seconds if args.expire_seconds is not None else \
        int(config.get("expire_seconds", 900))
    pending_path = args.pending or cfg_path(config, "pending", DEFAULT_PENDING)
    receipt_path = cfg_path(config, "receipt", "./nullaosta-receipt.json")
    normal = receipt.normalize_path(receipt_path)

    if not args.action_file and (not args.action_class or not args.target):
        raise gate.GateError("--class and --target are required without --action-file")

    if args.action_file:
        action, params = gate.load_action_file(args.action_file)
    else:
        if not args.params_file:
            raise gate.GateError("--params-file is required when no --action-file")
        params = _read_params_file(args.params_file)
        action = gate.new_action(args.action_class, args.target, params)

    allowed = args.allowed_signers
    approval_text = None
    branch = None

    if args.approval:
        try:
            with open(args.approval, encoding="utf-8", errors="replace") as handle:
                approval_text = handle.read()
        except OSError as exc:
            approval_text = None
            branch = ("APPROVER-UNREACHABLE",
                      f"approval could not be read ({args.approval!r}): {exc}")
    elif args.approver_cmd:
        pending = _write_pending(pending_path, action, params)
        sig, detail = _run_approver(args.approver_cmd, args.action_file or pending_path,
                                    args.await_seconds)
        if sig is None:
            approval_text = None
            branch = ("APPROVER-UNREACHABLE", detail)
        else:
            approval_text = sig

    try:
        doc = receipt.load(normal)
    except receipt.ReceiptError as exc:
        raise ConfigError(f"receipt unreadable, refusing to decide: {exc}")

    if branch is None:
        verdict, branch, detail, matched = gate.decide(
            pol, doc, action, params, approval_text, allowed,
            executor=config["executor"], expire_seconds=expire)
    else:
        verdict, detail, matched = "BLOCKED", branch[1], None
        branch = branch[0]

    gated = policy.rule_for(pol, action["action_class"],
                            action["target"]) == "require-approval"
    payload = gate.record_decision(action, approval_text, verdict, branch,
                                   detail, matched, gated, expire)
    _append(config, payload, args.key)

    if verdict == "OPEN":
        print(f"OPEN — {detail}")
        print(f"  action_hash: {payload['action_hash']}")
        return 0
    print(f"DO-NOT-EXECUTE — {branch}: {detail}", file=sys.stderr)
    if branch == "NO-APPROVAL":
        _write_pending(pending_path, action, params)
        print(f"  pending action written: {pending_path}", file=sys.stderr)
        print(f"  approve with: nullaosta approve --action-file {pending_path} "
              f"--key <approver key> --principal <approver>", file=sys.stderr)
    return 1 if verdict == "BLOCKED" else 0


# ── approve ──────────────────────────────────────────────────────────────────

def cmd_approve(args):
    config = load_config(args.config)
    executor = config["executor"]
    if args.principal == executor:
        print(f"SELF-REFERENCE: principal '{args.principal}' is the executor "
              f"'{executor}' — the approver must be an independent principal.",
              file=sys.stderr)
        return 1
    action, _params = gate.load_action_file(args.action_file)
    action_hash_hex = gate.action_hash(action)
    preimage = gate.approval_preimage(action_hash_hex)
    sig, detail = receipt.sign_preimage(preimage, args.key, gate.APPROVAL_NAMESPACE)
    if sig is None:
        print(f"approve failed: {detail}", file=sys.stderr)
        return 2
    if args.out:
        parent = os.path.dirname(os.path.abspath(args.out))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="") as handle:
            handle.write(sig)
        print(f"approval written: {args.out}")
    else:
        sys.stdout.write(sig)
    print(f"  action_hash: {action_hash_hex}", file=sys.stderr)
    print(f"  principal:   {args.principal}", file=sys.stderr)
    return 0


# ── verify ───────────────────────────────────────────────────────────────────

def cmd_verify(args):
    result = _verify_one(args.receipt, args.allowed_signers)
    print(render(result))
    return result["exit"]


# ── log ──────────────────────────────────────────────────────────────────────

def cmd_log(args):
    try:
        doc = receipt.load(args.receipt)
    except receipt.ReceiptError as exc:
        print(f"log: receipt unreadable — {exc}", file=sys.stderr)
        return 2
    print(f"executor: {doc['executor']}   entries: {len(doc['entries'])}")
    for entry in doc["entries"]:
        decision = entry["decision"]
        gated = "GATED" if entry.get("gated") else "ungated"
        line = (f"[{entry['seq']}] {entry['at']}  {gated}  "
                f"{decision['verdict']}"
                + (f" ({decision['branch']})" if decision.get("branch") else "")
                + f"  {entry['action']['action_class']} "
                  f"{entry['action']['target']}")
        print(line)
        if decision.get("detail"):
            print(f"      {decision['detail']}")
    return 0


# ── parser ───────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="nullaosta",
        description="Fail-closed approval gate + third-party-verifiable "
                    "receipts for agent actions.")
    parser.add_argument("--version", action="version",
                        version=f"nullaosta {__version__}")
    sub = parser.add_subparsers(dest="verb", required=True)

    p = sub.add_parser("init", help="write config + the default policy")
    p.add_argument("--executor", default="agent-receipt",
                   help="principal of the receipt writer (the executor role)")
    p.add_argument("--config", default=DEFAULT_CONFIG)
    p.add_argument("--receipt", default="./nullaosta-receipt.json")
    p.add_argument("--policy", default="./policy.json")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("check", help="gate one action (the agent's verb)")
    p.add_argument("--class", dest="action_class", default=None,
                   help="action class, e.g. pay/submit/delete/send/publish "
                        "(required unless --action-file)")
    p.add_argument("--target", default=None)
    p.add_argument("--params-file", help="JSON object of the action parameters")
    p.add_argument("--action-file", help="reuse a recorded pending action "
                                         "(its nonce and issued_at)")
    p.add_argument("--approval", help="file holding the approver's SSHSIG")
    p.add_argument("--approver-cmd", help="optional: APPROVER command run as "
                                          "'CMD <pending path>' printing the SSHSIG")
    p.add_argument("--await-seconds", type=int, default=30)
    p.add_argument("--allowed-signers", required=True,
                   help="trust anchor, supplied from OUTSIDE the repo")
    p.add_argument("--key", required=True, help="the receipt key (writer role)")
    p.add_argument("--expire-seconds", type=int, default=None)
    p.add_argument("--pending", default=None)
    p.add_argument("--config", default=DEFAULT_CONFIG)
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("approve", help="the human's verb: sign one action hash")
    p.add_argument("--action-file", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--principal", required=True)
    p.add_argument("--out", default=None)
    p.add_argument("--config", default=DEFAULT_CONFIG)
    p.set_defaults(fn=cmd_approve)

    p = sub.add_parser("verify", help="independent third-party verification")
    p.add_argument("--receipt", required=True)
    p.add_argument("--allowed-signers", required=True)
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("log", help="informational listing of the receipts")
    p.add_argument("--receipt", required=True)
    p.set_defaults(fn=cmd_log)
    return parser


def main(argv=None):
    _force_utf8_output()
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except gate.GateError as exc:
        print(f"nullaosta: could not decide — {exc}", file=sys.stderr)
        return 2
    except ConfigError as exc:
        print(f"nullaosta: {exc}", file=sys.stderr)
        return 2
    except policy.PolicyError as exc:
        print(f"nullaosta: unreadable policy — {exc}", file=sys.stderr)
        return 2
    except receipt.ReceiptError as exc:
        print(f"nullaosta: cannot seal the receipt — {exc}", file=sys.stderr)
        return 2
    except VerifyInputError as exc:
        print(f"nullaosta: cannot verify — {exc}", file=sys.stderr)
        return 2
    except subprocess.TimeoutExpired as exc:
        print(f"nullaosta: subprocess did not answer in time — {exc}",
              file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"nullaosta: I/O error — {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
