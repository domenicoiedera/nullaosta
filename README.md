# nullaosta

A fail-closed approval gate and tamper-evident, third-party-verifiable receipts for AI agents. Zero dependencies, MIT, runs entirely on your machine.

**Honest scope note:** in v0.1 the gate is advisory at the call boundary. An agent that never calls `check` is not stopped by it. v0.1 governs the actions that go through the gate and proves what happened.

## Who it is for

Developers and teams who run AI agents that can spend money, submit forms, delete data, send messages, or publish content, and who need a human checkpoint and provable evidence for what the agent did.

## Install

Until the package is published on PyPI, install from source: clone this repository, then

```bash
pip install .
```

Requires Python 3.10 or newer. No other dependencies.

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
#    this machine and no key of their own. Any tamper exits nonzero.
nullaosta verify --receipt nullaosta-receipt.json \
  --allowed-signers "$HOME/.config/nullaosta/allowed_signers"

# 7. Read the chain.
nullaosta log --receipt nullaosta-receipt.json
```

## What the receipt proves

Proves: which actions ran, in what order, with what parameters, which were human-approved, by whom, and that the record has not been altered since it was written. An uninvolved third party can verify this from the file and the public keys alone.

Does not prove: what the agent *thought* or intended, that every action the agent performed went through the gate (see the honesty note above), or the correctness of the underlying work.

## Security model

| Role | Holds | Can do |
|---|---|---|
| Agent | nothing | nothing; it cannot sign anything |
| Tool | receipt key | writes and seals the receipt chain |
| Human | approver key | approves a specific action hash |

- The approval is bound to the hash of that exact action. It cannot be spent on a different action.
- Every approval is single-use. A spent or replayed approval is rejected.
- Entries are sealed per append, so there is no unsealed tail; an unsealed file verifies as FAILED, not clean.
- `verify` additionally checks that the approver is in `allowed_signers` and is not the executor identity.
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
