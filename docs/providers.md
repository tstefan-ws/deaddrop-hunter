# Platforms and providers for blockchain dead-drop hunting

A field guide to the services that help with this hunt: what each is good for, whether a free
tier exists and whether it has an API.

**How to read the status marks**

- **measured 2026-10-19** - tested by the project on that date (limits change; re-measure).
- unmarked - based on the provider's public documentation as known to the authors; free-tier
  limits and pricing change often, so **not re-verified**. Corrections welcome via PR.

Columns: **Free** = usable free tier (may need an account/key); **API** = programmatic access.

## Block explorers

| Platform | Good for in this hunt | Free | API |
|---|---|---|---|
| [Polygonscan](https://polygonscan.com) | Contract/wallet pages, verified source, labels, "Report/Flag address" | yes | yes (via Etherscan V2) |
| [Etherscan](https://etherscan.io) + **Etherscan V2 multichain API** | One key for 50+ EVM chains: `txlist` (operator wallet history), `getLogs` by topic, contract source/ABI, creator | yes (limited) | yes |
| [BscScan](https://bscscan.com) | BSC contracts used by ClearFake / UNC5142 and DPRK UNC5342 | web: yes | via Etherscan V2: **free plan does not cover BSC** (measured 2026-10-19) |
| [Arbiscan](https://arbiscan.io), [Basescan](https://basescan.org), [Optimistic Etherscan](https://optimistic.etherscan.io) | Same as Etherscan for L2s | yes | yes (Etherscan V2; per-chain free coverage varies) |
| [Snowtrace](https://snowtrace.io) (Avalanche C-Chain) | Avalanche contracts / wallets | yes | yes (Routescan / Etherscan V2) |
| [Tronscan](https://tronscan.org) | Tron accounts, tx notes/data, TRC-20 | yes | yes |
| [Solscan](https://solscan.io) | Solana accounts, memos (GlassWorm-style C2) | yes | yes (Pro API; free tier limited) |
| [Aptos Explorer](https://explorer.aptoslabs.com) | Aptos accounts, entry-function args, resources | yes | via fullnode REST |
| [Blockscout](https://www.blockscout.com) instances | Open-source explorer for many chains/testnets; Etherscan-compatible API | yes | yes |

## Indexed / SQL data (search what RPC can't: selectors, tx input, history)

| Platform | Good for in this hunt | Free | API |
|---|---|---|---|
| [Dune](https://dune.com) | SQL over decoded and raw tables (`<chain>.logs`, `<chain>.transactions`); **BSC topic sweeps (`bnb.logs`) and selector hunts** used by this project (`DUNE_API_KEY`) | yes (credits) | yes |
| [Google BigQuery public crypto datasets](https://cloud.google.com/blog/products/data-analytics/introducing-six-new-cryptocurrencies-in-bigquery-public-datasets-for-blockchain-analytics) | `bigquery-public-data.crypto_ethereum` / `crypto_polygon` etc.: full tx/log tables, selector and bytecode queries | yes (1 TB/month query) | yes |
| [Allium](https://www.allium.so) | Multichain warehouse incl. non-EVM | limited / trial | yes |
| [Flipside](https://flipsidecrypto.xyz) | SQL over many chains incl. Solana | yes (limits changed over time) | yes |
| [Covalent / GoldRush](https://goldrush.dev) | Unified API: logs by topic, tx history across 100+ chains | yes (limited) | yes |
| [The Graph](https://thegraph.com) | Subgraphs for a known contract/event (continuous indexing) | yes (limited queries) | yes (GraphQL) |
| [Bitquery](https://bitquery.io) | GraphQL across EVM, Tron, Solana; event/argument filters | yes (limited) | yes |
| [Transpose](https://www.transpose.io) | SQL API for EVM chains (availability of the service: not verified) | not verified | yes |

## RPC providers (topic-only `eth_getLogs` limits)

The critical capability is an **address-less, topic-only `eth_getLogs`** over a large block range.

| Endpoint | Chains | Topic-only getLogs | Free | Status |
|---|---|---|---|---|
| Tenderly public gateways `https://<chain>.gateway.tenderly.co` | Polygon, Ethereum, Arbitrum, Optimism, Avalanche, Sepolia, Polygon Amoy | **~400,000 blocks / request** | yes, no key | measured 2026-10-19 |
| Tenderly Base gateway `https://base.gateway.tenderly.co` | Base | **1,000 blocks / request** | yes | measured 2026-10-19 |
| QuikNode public `https://rpc-mainnet.matic.quiknode.pro` | Polygon | 10,000 blocks | yes | measured 2026-10-19 |
| PublicNode `https://*-rpc.publicnode.com` | many | refused / capped (fine for `eth_call`, tx lookups) | yes | measured 2026-10-19 |
| dRPC public `https://*.drpc.org` | many | refused / capped on free public | yes | measured 2026-10-19 |
| 1RPC `https://1rpc.io` | many | refused / capped | yes | measured 2026-10-19 |
| `https://polygon-rpc.com` | Polygon | disabled for this use | - | measured 2026-10-19 |
| Public BSC (`bsc-dataseed*.binance.org`, `bsc-rpc.publicnode.com`) | BSC | refused / rate limited | yes | measured 2026-10-19 |
| `https://api.avax.network/ext/bc/C/rpc` | Avalanche | treated as no sweeps (span 0) in config | yes | not measured |
| NodeReal, Chainstack, Ankr (free key) | BSC and others | allowed with a key, span depends on plan | yes (key) | use via `DDH_RPC_BSC="url\|span"`; limits not verified |
| Alchemy, Infura, QuickNode (free key) | many EVM | allowed with ranges/result caps per plan | yes (key) | not verified |
| TronGrid `https://api.trongrid.io` | Tron | n/a (account tx API) | yes (`TRONGRID_API_KEY` raises limit) | used by `nonevm/tron.py` |
| Solana public `https://api.mainnet-beta.solana.com` | Solana | n/a (`getSignaturesForAddress`) | yes, heavily rate limited | override `DDH_RPC_SOLANA` (Helius etc.) |
| Aptos fullnode `https://fullnode.mainnet.aptoslabs.com/v1` | Aptos | n/a (REST) | yes | used by `nonevm/aptos.py` |

Re-measure a provider before adding it: run a topic-only query over 1k, 10k, 100k, 400k blocks and
record the largest span that returns, as `max_log_span` in `config/hunts.toml`.

## Signature databases

| Platform | Good for | Free | API |
|---|---|---|---|
| [4byte.directory](https://www.4byte.directory) | Function selectors and event signatures (topic0) -> text | yes | yes |
| [openchain.xyz signature database](https://openchain.xyz/signatures) | Fast lookup of selectors and event topics; large DB | yes | yes |
| [Etherface](https://www.etherface.io) | Signatures with source references (where a signature was seen on GitHub/Etherscan) | yes | yes |

## Contract analysis

| Tool | Good for | Free | API |
|---|---|---|---|
| [Dedaub decompiler](https://app.dedaub.com/decompile) | Decompile unverified contracts: find setter/getter, storage slots, events | yes (web) | no public API |
| [ethervm.io](https://ethervm.io/decompile) | Quick online decompile/disassembly | yes | no |
| [Heimdall-rs](https://github.com/Jon-Becker/heimdall-rs) | Local decompiler, ABI recovery, CFG; scriptable | yes (OSS) | CLI |
| [Panoramix](https://github.com/palkeo/panoramix) | Decompiler (used historically by Etherscan) | yes (OSS) | CLI |

## Web-side hunting (find compromised sites and loaders that read contracts)

| Platform | Good for | Free | API |
|---|---|---|---|
| [urlscan.io](https://urlscan.io) | Search page DOM/requests for RPC hosts, contract addresses, `eth_call` bodies | yes | yes |
| [PublicWWW](https://publicwww.com) | Source-code search across websites for loader snippets / contract addresses | limited | yes (paid) |
| [Censys](https://search.censys.io) | Hosts/certs for decoded C2 IPs and domains | yes (limited) | yes |
| [Shodan](https://www.shodan.io) | Services on C2 IPs (e.g. stratum ports, panels) | limited | yes |
| [FOFA](https://en.fofa.info) | Host / body search, good coverage of some regions | limited | yes |
| [Validin](https://www.validin.com) | Passive DNS, host responses, pivoting on C2 infra | yes (community) | yes |
| [DomainTools](https://www.domaintools.com) | Whois history, passive DNS | no (commercial) | yes |
| [crt.sh](https://crt.sh) | Certificate transparency: new domains of the same operator | yes | yes (simple JSON) |

## Malware and sandboxes (validate and find samples)

| Platform | Good for | Free | API |
|---|---|---|---|
| [VirusTotal](https://www.virustotal.com) | IOC relations, communicating files, sandbox traffic containing RPC hosts / contract addresses (`VT_API_KEY`) | yes (limited) | yes |
| [ANY.RUN](https://any.run) | Interactive sandbox; public reports searchable by IOC | yes (community) | paid |
| [Triage (Recorded Future)](https://tria.ge) | Sandbox, public reports, good config extraction | yes (researcher) | yes |
| [Joe Sandbox](https://www.joesandbox.com) | Deep analysis reports incl. macOS | limited (public cloud basic) | paid |
| [Hybrid Analysis](https://www.hybrid-analysis.com) | Free sandbox reports, IOC search | yes | yes |
| [MalwareBazaar](https://bazaar.abuse.ch) | Samples by hash/tag/family | yes | yes |

## IOC sharing

| Platform | Good for | Free | API |
|---|---|---|---|
| [ThreatFox](https://threatfox.abuse.ch) | Submit / look up C2 IOCs (preferred place to report decoded C2s) | yes | yes |
| [URLhaus](https://urlhaus.abuse.ch) | Payload / distribution URLs | yes | yes |
| [AlienVault OTX](https://otx.alienvault.com) | Pulses; community distribution | yes | yes |
| [MISP communities](https://www.misp-project.org/communities/) | Consume our MISP feed; share with sector communities | yes | yes |
| [OpenCTI](https://filigran.io/solutions/open-cti/) | TIP; this repo ships an OpenCTI connector (`connectors/opencti/`) | yes (OSS) | yes |

## Blockchain attribution and labels

| Platform | Good for | Free | API |
|---|---|---|---|
| Etherscan-family labels / "Report address" | Check existing labels; request a phishing/malware label for dead-drop contracts | yes | labels via paid API |
| [Chainabuse](https://www.chainabuse.com) | Report and search abuse reports per address (multi-chain) | yes | yes (key) |
| [Arkham Intelligence](https://intel.arkm.com) | Entity labels, fund flows of operator wallets | yes (account) | limited |
| [MistTrack (SlowMist)](https://misttrack.io) | AML labels, funding source tracing (exchanges, mixers) | limited | paid |

## What this project uses by default

| Need | Default (no keys) | With keys |
|---|---|---|
| Topic sweeps Polygon / Ethereum / Arbitrum / Optimism / Avalanche | Tenderly gateways | - |
| Topic sweeps Base | Tenderly (1k-block windows) | `DDH_RPC_BASE` |
| Topic sweeps BSC / BSC testnet | skipped | `DUNE_API_KEY` or `DDH_RPC_BSC` / `DDH_RPC_BSC_TESTNET` |
| Selector hunts | skipped | `DUNE_API_KEY` (fallback: `ETHERSCAN_API_KEY` for known contracts) |
| EVM operator wallet watches | skipped | `ETHERSCAN_API_KEY` |
| Tron / Solana / Aptos account watches | public endpoints | `TRONGRID_API_KEY`, `DDH_RPC_SOLANA` |
| `eth_call`, tx/receipt lookups | config RPCs | - |
