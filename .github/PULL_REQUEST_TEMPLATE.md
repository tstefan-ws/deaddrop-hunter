## What does this change?

<!-- One or two sentences. Link the issue it closes: "Closes #123". -->

## Type

- [ ] New hunt / fingerprint / watch wallet (`config/hunts.toml`)
- [ ] Decoder / classifier / collector (`src/`)
- [ ] Exporter / public API / connector
- [ ] Dashboard (`web/`)
- [ ] Detection rule (Sigma / YARA / Suricata)
- [ ] Docs / CI / scripts / other

## Checklist

- [ ] Tests added or updated; `pytest` and `ruff check src tests` pass locally
- [ ] No secrets, API keys or private RPC URLs in code, config, logs or screenshots
- [ ] IOCs in this description, docs and comments are **defanged** (`hxxps://evil[.]example`, `1.2.3[.]4`)
- [ ] Everything shared here is **TLP:CLEAR**; no victim data, no live malware
- [ ] The hunter stays read-only (no signing / sending transactions, no contact with IOCs)
- [ ] `data/*.json` not hand-edited (or the reason is explained below)
- [ ] Detection rules: `sigma check rules/sigma` passes, YARA compiles, Suricata SIDs in 9100000-9100999
- [ ] Docs updated if behaviour, flags, env vars or config keys changed

## Evidence / notes

<!-- For new hunts: example contracts and transactions, measured noise, decoded sample (defanged). -->
