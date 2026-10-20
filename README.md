# nullaosta

[![CI](https://github.com/domenicoiedera/nullaosta/actions/workflows/ci.yml/badge.svg)](https://github.com/domenicoiedera/nullaosta/actions/workflows/ci.yml) ![Python 3.10 | 3.11 | 3.12](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue) ![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)

A fail-closed approval gate and tamper-evident, third-party-verifiable receipts for AI agents. Zero dependencies, MIT, runs entirely on your machine.

**Honest scope note:** in v0.1 the gate is advisory at the call boundary. An agent that never calls `check` is not stopped by it. v0.1 governs the actions that go through the gate and proves what happened.

## Who it is for

Developers and teams who run AI agents that can spend money, submit forms, delete data, send messages, or publish content, and who need a human checkpoint and provable evidence for what the agent did.

## Install

No PyPI account needed. Install the wheel attached to the release:

```bash
pip install https://github.com/domenicoiedera/nullaosta/releases/download/v0.1.0/nullaosta-0.1.0-py3-none-any.whl
```

Or straight from source (needs `git`):

```bash
pip install "git+https://github.com/domenicoiedera/nullaosta.git"
```

Or clone the repository and run `pip install .` inside it.

Or into an isolated environment, which is the better default on macOS and puts the CLI on your PATH:

```bash
pipx install https://github.com/domenicoiedera/nullaosta/releases/download/v0.1.0/nullaosta-0.1.0-py3-none-any.whl
uv tool install https://github.com/domenicoiedera/nullaosta/releases/download/v0.1.0/nullaosta-0.1.0-py3-none-any.whl
```

Requires Python 3.10 or newer. No other dependencies. The package is not on PyPI yet; publishing it there would only shorten that first command to `pip install nullaosta`.

## Usage

The CLI has five verbs: `init`, `check`, `approve`, `verify`, `log`. This is a real run, kept
short; run the commands in an empty directory.

```bash
# 1. Initialise a workspace: writes nullaosta.json (config) and policy.json
#    (default: the irreversible classes pay, submit, delete, send and publish
#    require approval).
nullaosta init

# 2. Make TWO SEPARATE OpenSSH keys: one for the tool (the receipt writer), one
#    for the human approver. The trust anchor must live OUTSIDE the repo being
#    governed. v0.1 is tested with passphrase-free keys; put a passphrase on the
#    approver key in real use (that interactive path is not covered by the tests).
ssh-keygen -t ed25519 -N '' -C 'receipt writer' -f receipt_key
ssh-keygen -t ed25519 -N '' -C 'human approver' -f approver_key
mkdir -p "$HOME/.config/nullaosta"
printf 'agent-receipt %s\nfounder %s\n' \
  "$(cat receipt_key.pub)" "$(cat approver_key.pub)" > "$HOME/.config/nullaosta/allowed_signers"

# 3. The agent asks to act. A gated class with no approval is refused, and the
#    attempt is written out as a pending action for a human to look at:
#      DO-NOT-EXECUTE — NO-APPROVAL: ... the action is on hold        (exit 1)
echo '{"amount":"120.00","currency":"EUR"}' > params.json
nullaosta check --class pay --target https://shop.example.com/checkout \
  --params-file params.json \
  --allowed-signers "$HOME/.config/nullaosta/allowed_signers" --key receipt_key

# 4. The human reads the pending action and signs THAT action's hash.
nullaosta approve --action-file nullaosta-pending.json \
  --key approver_key --principal founder --out a.sig

# 5. Present it. The gate opens and seals the action and the decision:
#      OPEN — approval by 'founder' over action hash ... verified, unspent, in time   (exit 0)
nullaosta check --action-file nullaosta-pending.json --approval a.sig \
  --allowed-signers "$HOME/.config/nullaosta/allowed_signers" --key receipt_key

#    Presenting that same approval again is refused, because it is single-use:
#      DO-NOT-EXECUTE — SPENT: ... every approval is single-use        (exit 1)

# 6. Anyone with the receipt and the public keys can verify, with no access to
#    this machine and no key of their own; the file may be copied or renamed
#    first, that changes nothing. Any tamper exits nonzero.
nullaosta verify --receipt nullaosta-receipt.json \
  --allowed-signers "$HOME/.config/nullaosta/allowed_signers"

# 7. Read the chain.
nullaosta log --receipt nullaosta-receipt.json
```

## What the receipt proves

Proves: which actions ran, in what order, with what parameters, which were human-approved, by whom, and that an uninvolved third party cannot alter the record undetectably.

Two honest boundaries on that. First, the writer holds the receipt key and can therefore rewrite the file itself: delete entries, re-stamp and re-seal, and the rewritten file still verifies against the public keys. That is why the chain head should be anchored out of band, in a place the writer cannot touch. The spent-approval ledger lives inside the receipt file, so a spent approval can open again against a fresh receipt file; that is a second reason to anchor the head out of band. Second, timestamps in the entries are asserted by the writer and are not independently checked.

An uninvolved third party can verify all of the above from the file and the public keys alone, with no access to this machine, no private key, and no problem with the file having been copied or renamed in between.

Does not prove: what the agent *thought* or intended, that every action the agent performed went through the gate (see the honesty note above), or the correctness of the underlying work.

## Security model

| Role | Holds | Can do |
|---|---|---|
| Agent | nothing | nothing; it cannot sign anything |
| Tool | receipt key | writes and seals the receipt chain |
| Human | approver key | approves a specific action hash |

- The approval is bound to the hash of that exact action. It cannot be spent on a different action.
- Every approval is single-use within its receipt file. A spent or replayed approval is rejected; a spent approval can open again against a fresh receipt file, which is why the chain head should be anchored out of band.
- Entries are sealed per append, so there is no unsealed tail; an unsealed file verifies as FAILED, not clean. The seal binds the file contents, not the file name, so a renamed copy of an otherwise untouched receipt verifies.
- `verify` additionally checks that the approver is in `allowed_signers` and is not the executor identity, and it does not trust the receipt's own `gated` flag: an OPEN on an irreversible class (pay, submit, delete, send, publish) must carry a valid approval no matter what the entry claims.
- The gate is fail-closed: anything other than a valid, unspent, approving signature blocks.

## What it is not

- Not a browser driver, not a scraper, not an agent harness.
- Not an MCP server (that is a later increment).
- Not a cloud service: no accounts, no hosted component, no telemetry.
- No anti-bot, CAPTCHA, stealth or bypass code, ever. That is a permanent product boundary, not a backlog item.

## Prompt injection

This tool does not claim to prevent prompt injection. The claim is containment plus evidence: what could not be prevented can be proven after the fact.

## Local-first / EU note

Everything runs on your machine. Policy, keys, approvals and receipts stay local; nothing leaves the machine. There is no vendor to send data to, which keeps the tool compatible with EU data-residency expectations without any special configuration.

## Status

v0.1.0 is under active development. See CHANGELOG.md.

## License

MIT.
