"""The nullaosta policy engine: action classes, per-domain rules, default-deny.

Verdicts, exactly three, per (action class, domain): allow / deny /
require-approval.

* ``allow``            — run; the gate only records it;
* ``deny``             — hard block; no approval can open it;
* ``require-approval`` — fail-closed approval gate (the irreversible classes
  pay / submit / delete / send / publish). "Default-deny" for those classes
  means exactly this: they never run absent an explicit, independently signed
  grant — there is no static allow, and the absence of any matching rule
  falls back to ``deny``, never ``allow``.

Policy file (a JSON object; unreadable => :class:`PolicyError`, so the caller
exits 2 — a broken instrument is never read as "no rules", which would be a
silent fail-open)::

    {"nullaosta_policy": {"v": 1},
     "defaults": {"browse": "allow"},
     "domains": {"shop.example.com": {"pay": "require-approval"}}}
"""

import hashlib
import json
import os

from urllib.parse import urlsplit

MARKER = "nullaosta_policy"
POLICY_VERSION = 1

IRREVERSIBLE = ("pay", "submit", "delete", "send", "publish")
VERDICTS = ("allow", "deny", "require-approval")

# Restrictiveness order used whenever two matching rules disagree.
ORDER = {"deny": 0, "require-approval": 1, "allow": 2}


class PolicyError(Exception):
    """A policy file exists but cannot be read, or is the wrong shape."""


def empty():
    """The pristine policy: deny unless listed."""
    return {MARKER: {"v": POLICY_VERSION}, "defaults": {}, "domains": {}}


def default_policy():
    """The preset ``init`` ships.

    Only ``browse`` opens out of the box; the irreversible classes are the
    fail-closed approval gate; every class not named here defaults to deny.
    """
    policy = empty()
    rules = {"browse": "allow"}
    for klass in IRREVERSIBLE:
        rules[klass] = "require-approval"
    policy["defaults"] = rules
    return policy


def load(path):
    """Read ``path``; absent/empty => the default preset; unreadable => raise.

    The same asymmetry as the proven sibling's registry: a missing file means
    "nothing configured yet"; a file that IS there but cannot be parsed must
    never degrade into a permissive default.
    """
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        return default_policy()
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise PolicyError(f"{path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: policy root must be a JSON object")
    marker = data.get(MARKER)
    if not isinstance(marker, dict) or marker.get("v") != POLICY_VERSION:
        raise PolicyError(
            f"{path}: unsupported policy marker {marker!r}; "
            f"expected {{'v': {POLICY_VERSION}}}")
    for key in ("defaults", "domains"):
        if key in data and not isinstance(data[key], dict):
            raise PolicyError(f"{path}: {key!r} must be a JSON object")
    for group in (data.get("defaults", {}),):
        for verdict in group.values():
            if verdict not in VERDICTS:
                raise PolicyError(f"{path}: unknown verdict {verdict!r}")
    for host, rules in data.get("domains", {}).items():
        if not isinstance(rules, dict):
            raise PolicyError(f"{path}: domains[{host!r}] must be a JSON object")
        for verdict in rules.values():
            if verdict not in VERDICTS:
                raise PolicyError(f"{path}: unknown verdict {verdict!r}")
    return data


def host_of(target):
    """The lowercase host of a URL-shaped target, else ``None``."""
    try:
        parts = urlsplit(str(target))
    except ValueError:
        return None
    host = parts.hostname
    return host.lower() if host else None


def rule_for(policy, action_class, target):
    """The verdict for ``action_class`` against ``target`` (a URL or domain).

    Domain matching walks the target's host through its suffixes —
    ``a.b.example.com`` matches ``example.com``. The most specific domain
    rule wins; when two rules match equally, the MORE restrictive verdict
    wins (deny > require-approval > allow). No rule at all => deny.
    """
    verdict = _verdict(policy.get("defaults", {}), action_class)
    domains = policy.get("domains", {})
    host = host_of(target)
    if host and domains:
        labels = host.split(".")
        best = -1
        for start in range(len(labels)):
            candidate = ".".join(labels[start:])
            if candidate in domains:
                rules = domain_rules(candidate, domains)
                candidate_verdict = _verdict(rules, action_class)
                if len(candidate) > best:
                    best = len(candidate)
                    verdict = candidate_verdict
                elif len(candidate) == best:
                    verdict = min(verdict, candidate_verdict, key=lambda v: ORDER[v])
    return verdict


def domain_rules(host, domains):
    """The rule object for ``host``; tolerate a malformed one by ignoring it
    (the shape check in :func:`load` already rejects non-objects)."""
    rules = domains.get(host, {})
    return rules if isinstance(rules, dict) else {}


def _verdict(rules, action_class):
    if action_class in rules:
        return rules[action_class]
    if action_class in IRREVERSIBLE:
        return "require-approval"
    return "deny"


def canonical_bytes(payload):
    """The one serialisation every hash in this package agrees on: sorted
    keys, compact separators, UTF-8. Deterministic across runs and hosts."""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def digest_bytes(payload):
    """``sha256`` hex of the canonical bytes of ``payload``."""
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()
