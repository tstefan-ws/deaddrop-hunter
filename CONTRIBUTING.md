# Contributing to deaddrop-hunter

Thanks for helping hunt blockchain dead drops. Contributions of every size are welcome:
a new fingerprint, a false-positive report, a decoder, a detection rule, or a doc fix.

## Ground rules

- **Read-only, always.** The hunter only uses read RPC methods (`eth_blockNumber`,
  `eth_getLogs`, `eth_getTransactionByHash`, `eth_getBlockByNumber`, `eth_getCode`,
  `eth_call`). Code that signs, sends transactions, or interacts with contracts in a
  state-changing way will not be merged.
- **Never visit IOCs.** No code path may fetch, resolve, or connect to a decoded C2,
  pool, or URL. Enrichment goes through third-party intel APIs only.
- **TLP:CLEAR only.** Do not contribute data you are not allowed to share publicly.
- **Defang in prose.** Issues, PR descriptions, docs: `hxxps://evil[.]example`,
  `185.10.68[.]110`. `data/*.json` stores raw values by design (see
  [docs/data-schema.md](docs/data-schema.md)); renderers defang them.
- **No secrets.** API keys come from environment variables only.
- **No live malware** in the repo, issues, or PRs. Hashes and public sandbox links are fine.

## Development setup

```bash
git clone https://github.com/tstefan-ws/deaddrop-hunter.git
cd deaddrop-hunter
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

ruff check src tests
pytest
```

Run a small hunt locally (one chain, short window):

```bash
deaddrop-hunter hunt --chains polygon --days 3
deaddrop-hunter export --data data --out site/feeds
python scripts/build_site.py --out site
python -m http.server -d site 8000
```

## What to contribute, and where

| You want to...                         | Touch                                         | Guide |
|----------------------------------------|-----------------------------------------------|-------|
| Add an event/selector/wallet fingerprint | `config/hunts.toml`                          | [docs/adding-a-hunt.md](docs/adding-a-hunt.md) |
| Add a chain                            | `config/hunts.toml` `[chains.*]`              | [docs/adding-a-hunt.md](docs/adding-a-hunt.md), [docs/providers.md](docs/providers.md) |
| Add a decoder / family classifier      | `src/deaddrop_hunter/` + tests                | [docs/architecture.md](docs/architecture.md) |
| Add an export format / SIEM connector  | `src/deaddrop_hunter/exporters/`, `connectors/` | [docs/integrations.md](docs/integrations.md) |
| Improve detection rules                | `rules/sigma`, `rules/yara`, `rules/suricata` | [rules/sigma/README.md](rules/sigma/README.md) |
| Report a contract/wallet               | Issue form "Report a suspicious contract/wallet" | - |
| Report a false positive                | Issue form "False positive"                   | - |

Please do **not** hand-edit `data/*.json` except to fix a confirmed false positive; the
scheduled hunt regenerates it. If you must, explain why in the PR.

## Pull requests

1. Fork, create a branch (`hunt/<short-name>`, `fix/<short-name>`, `rules/<short-name>`).
2. Keep changes focused. Add or update tests for code changes (`tests/`). Decoders need
   a test vector (raw hex in, decoded value out) taken from a real on-chain value.
3. Make sure CI passes: ruff, pytest, `node --check` on dashboard JS, JSON validation,
   Sigma check, YARA compile.
4. Fill in the PR template checklist.

### Detection rules

- Sigma: follow the [Sigma specification](https://github.com/SigmaHQ/sigma-specification);
  give each rule a new UUIDv4 `id`, `author: deaddrop-hunter contributors` (or add your
  name), `date`, `references`, ATT&CK `tags`, `falsepositives`, `level`. Validate with
  `sigma check rules/sigma`.
- YARA: include `meta` (author, date, description, reference). Must compile with
  `yara-python` (CI) and should compile with YARA-X.
- Suricata: use SIDs in the project's local range `9100000-9100999`; bump `rev` on change.

## Commit messages

Short imperative subject (`hunts: add selector 0x1234abcd on BSC`). Automated data
commits from CI use the `data:` prefix; please don't use it for manual commits.

## License

By contributing you agree that your contributions are licensed under the MIT License
(see [LICENSE](LICENSE)).
