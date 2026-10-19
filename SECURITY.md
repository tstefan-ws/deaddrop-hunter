# Security Policy

There are two different kinds of "security report" for this project. Please pick the
right channel.

## 1. A vulnerability in deaddrop-hunter itself

Examples: the dashboard renders an IOC as a clickable link or executes injected HTML
from on-chain data, a decoder can be made to crash or hang the pipeline, a workflow
leaks a secret, a dependency is compromised.

- **Do not open a public issue.** Use GitHub's
  [private vulnerability reporting](../../security/advisories/new).
- Include: affected file/version (commit SHA), reproduction steps, impact.
- We aim to acknowledge within 7 days and to fix or mitigate within 30 days.
- Only the latest commit on the default branch is supported.

On-chain data is attacker-controlled. Anything that reads `data/*.json` (dashboard,
exporters, connectors) must treat every decoded string as untrusted input. Bugs in that
boundary are in scope and taken seriously.

## 2. A malicious contract, wallet or infrastructure (threat intel)

This is not a vulnerability in our code; it is a contribution. Use the
**"Report a suspicious contract/wallet"** issue form, or open a PR adding a hunt.
Rules for such reports:

- TLP:CLEAR only. Do not submit anything you are not allowed to share publicly.
- Defang URLs/domains/IPs in prose (`hxxps://example[.]com`, `1.2.3[.]4`).
- Never attach live malware. Link to a public sandbox report or a hash instead.
- Do not include victim personal data.

If you believe a finding must not be public yet (for example, an active campaign where
a takedown is in progress), report it privately through the advisory link above and say
so. We will coordinate with the relevant explorer, RPC provider, or CERT before publishing.

## Secrets

The project only needs optional read-only API keys (`ETHERSCAN_API_KEY`, `DUNE_API_KEY`,
`VT_API_KEY`). They are passed to CI as GitHub Actions secrets and must never be
committed, logged, or written to `data/`. If you find a committed secret, report it
through the private channel so it can be revoked.
