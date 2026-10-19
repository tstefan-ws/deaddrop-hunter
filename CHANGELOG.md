# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-19

Initial public release.

### Added
- **Hunter** (`deaddrop-hunter hunt`): incremental sweeps with per-chain/per-hunt cursors in
  `data/meta.json`.
  - Event hunts: topic-only `eth_getLogs` sweeps (Tenderly gateways for Polygon, Ethereum,
    Arbitrum, Optimism, Base, Avalanche), Dune (`bnb.logs`) or a free-key RPC (`DDH_RPC_BSC`)
    for BSC.
  - Selector hunts (4-byte function selectors, via an indexed provider).
  - Operator wallet watches on EVM chains, and account watches on Tron, Solana (memo) and
    Aptos for transaction-data dead drops.
- **Decoders**: ABI strings, plain text, hex-UTF-8, single-byte XOR with key recovery from the
  expected leading character, base64.
- **Classification & IOC extraction**: IPv4/IPv6, domains, URLs, Monero/Bitcoin wallets, EVM
  addresses; family rules (`xmrig-stealth`, `xmrig`, `c2-url`); clustering by operator wallet.
- **Data model** in `data/*.json` (see `docs/data-schema.md`), committed by CI as an audit trail.
- **Exports** (`deaddrop-hunter export`): STIX 2.1 bundle, MISP feed, CSV, TXT, a static
  versioned public JSON API (`feeds/api/v1/...`) and an Atom feed.
- **Dashboard**: static site on GitHub Pages (`web/`), built by `scripts/build_site.py`.
- **Detection rules**: 7 Sigma rules (Windows/macOS), 7 YARA rules (loaders, DataUpdated
  topic, stealth XMRig configs incl. XOR 0x5a), 45 Suricata rules (DNS/TLS SNI to public RPCs,
  JSON-RPC `eth_call` in HTTP).
- **Automation**: `hunt.yml` (every 6 h, commit data, deploy Pages), `deploy-pages.yml`,
  `ci.yml` (ruff, pytest on 3.11-3.13, JS syntax, JSON, Sigma/YARA/Suricata validation,
  shellcheck), Dependabot.
- **Self-hosting**: `scripts/run_hunt.sh`, `scripts/bootstrap_wsl.sh`, `Makefile`, `Dockerfile`
  and `docker-compose.yml`; deployment guide in `docs/deploy.md`.

### First findings (Polygon, 2026-10-19)
- 6 contracts, 71 config updates, 3 operator wallets.
- Stealth XMRig cluster storing XOR(0x5a)-encoded miner configs.
- A contract rotating C2 URLs.

[Unreleased]: https://github.com/tstefan-ws/deaddrop-hunter/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tstefan-ws/deaddrop-hunter/releases/tag/v0.1.0
