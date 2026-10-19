# Methodology

How deaddrop-hunter finds blockchain dead drops, step by step, with what was measured on
2026-10-19 and what the method cannot see. IOCs in this document are defanged.

## 0. The idea

An EtherHiding contract is a tiny key-value store: a setter the operator calls to rotate the
value, a getter the malware reads with a free `eth_call`. Anything that is the same across
contracts of one toolkit is a fingerprint:

| Fingerprint | Where it lives | How to search it |
|---|---|---|
| Event emitted by the setter | `topic0` of every log | `eth_getLogs` with only `topics[0]` set |
| Setter function selector | first 4 bytes of tx input | indexed data (Dune / BigQuery / explorer API) |
| Operator wallet | `tx.from` of every update | explorer API `txlist` |
| Contract bytecode | `eth_getCode` | hash / similarity compare |
| Encoding of the value | the stored string | decoder heuristics (XOR, base64, ...) |

The hunter starts from one known sample and expands along these pivots.

## 1. From signature to topic0

Event logs index the event by `topic0 = keccak256("<Name>(<types>)")`. The signature is taken
from a verified contract, a decompiled one (see [providers.md](providers.md#contract-analysis)),
or a public report. For the cluster this project started from:

```
keccak256("DataUpdated(string,string)")
  = 0xee986145c636aca5c6c0b4ce0e9d371e77ab30b3e28fe5c3a8d977f05fc8cf24
```

The keccak implementation is in `src/deaddrop_hunter/keccak.py` (stdlib only, tested against
known vectors). Note Ethereum uses **Keccak-256, not SHA3-256** (different padding).

Unknown topic? Look it up in a signature DB (4byte.directory event signatures,
openchain.xyz, Etherface). The reverse also works: hash candidate names
(`ConfigUpdated(string)`, `UrlChanged(string,string)`, ...) and sweep for them.

## 2. Topic-only `eth_getLogs` sweep

```json
{"method":"eth_getLogs","params":[{"fromBlock":"0x57d6b93","toBlock":"0x5b5bf93",
  "topics":["0xee986145c636aca5c6c0b4ce0e9d371e77ab30b3e28fe5c3a8d977f05fc8cf24"]}]}
```

No `address` filter: we want **every** contract emitting the event, on every chain. This is
the expensive query most public nodes refuse. Measured limits (2026-10-19, block span accepted
for an address-less, topic-only query):

| Endpoint | Result |
|---|---|
| Tenderly public gateways (`<chain>.gateway.tenderly.co`): Polygon, Ethereum, Arbitrum, Optimism, Avalanche, Sepolia, Amoy | **~400,000 blocks** per request |
| Tenderly Base gateway | 1,000 blocks per request |
| QuikNode public Polygon (`rpc-mainnet.matic.quiknode.pro`) | 10,000 blocks |
| PublicNode (`*-rpc.publicnode.com`), dRPC public, 1RPC | refuse address-less queries or cap them to a few blocks |
| `polygon-rpc.com` | disabled for this use (no longer a usable public endpoint) |
| Public BSC nodes (`bsc-dataseed*`, PublicNode BSC) | refuse or rate-limit topic-only queries |
| Etherscan V2 API, free plan | does **not** cover BSC ("Free API access is not supported for this chain") |

Consequences, encoded in `config/hunts.toml` as `max_log_span` per RPC (0 = refuses):
- Polygon/Ethereum/Arbitrum/Optimism/Avalanche are swept for free via Tenderly.
- Base works but needs many small requests (1k blocks at ~2 s/block = ~33 min of chain per request).
- BSC sweeps go through **Dune** (`DUNE_API_KEY`, table `bnb.logs`) or a free-key RPC that allows
  it (`DDH_RPC_BSC="url|max_span"`: NodeReal, Chainstack, Ankr). BSC testnet: `DDH_RPC_BSC_TESTNET`.

The sweeper splits the range into `max_log_span` windows, halves the window on "too many
results"/timeout errors, falls back to the next RPC on failure, waits 5 confirmations, and
stores a cursor per (chain, hunt) in `data/meta.json` so the next run is incremental.

## 3. ABI decoding

For `DataUpdated(string,string)` both strings live in the log `data` (non-indexed), ABI-encoded:
two offsets, then length-prefixed byte arrays. `decoders.abi_decode` handles `string`/`bytes`
and static types. For selector hunts the same decoder runs on `tx.input[4:]`.

The decoded "string" is often not text: it is the obfuscated payload.

## 4. Value decoding and XOR key recovery

Decoders run in order, first success wins (`decoders.VALUE_DECODERS`):

1. `plain` - printable UTF-8.
2. `hex-utf8` - the string is hex of printable UTF-8.
3. `xor-1byte:0xNN` - single-byte XOR with **known-plaintext key recovery**: configs are JSON
   (start with `{`) and C2s are URLs (start with `h`), so `key = byte[0] ^ ord('{')` (or `'h'`).
   The candidate is accepted only if the whole result is printable and structurally sane (ends
   with `}` / starts with `http`).
4. `base64`.
5. otherwise `undecoded` (raw hex is kept; a later `rebuild` can decode it once a decoder exists).

Example from the stealth-XMRig cluster: the stored bytes start `21 78 3b 36 ...`;
`0x21 ^ 0x7b('{') = 0x5a`, and XOR 0x5a over the whole value yields
`{"algo":"rx/0","pool":"78.40.198[.]61:...",...}`.

## 5. IOC extraction and classification

`classify.extract_iocs` walks the decoded JSON (or text) and extracts IPv4/IPv6 (public only),
domains (validated TLD, benign-domain allow-list), URLs (including `stratum+tcp://`),
host:port pairs, Monero and Bitcoin wallets (checksum-validated) and EVM addresses.
`classify.classify` assigns a family by ordered rules (`xmrig-stealth`, `xmrig`, `c2-url`,
else `unknown`). Each IOC records first/last seen, how often it was seen and whether it is in
the **current** value of a contract (`current: true` = live infrastructure).

## 6. Pivots

Each finding is expanded:

| Pivot | How | What it found on 2026-10-19 |
|---|---|---|
| **Operator wallet** | `tx.from` of each update (`eth_getTransactionByHash`) | 3 operator wallets; one runs 4 contracts |
| **Setter selector** | first 4 bytes of the update tx input | `0x68446ead` (XMRig config contracts). Not every input prefix is a setter: the C2-URL operator routes updates through MetaMask's public DelegationManager, whose `redeemDelegations` selector `0xcef6d209` then appears in the input |
| **Wallet history** | explorer `txlist` of the operator (`watch_wallets`) | contract creations and updates that emit no event |
| **Funding source** | first incoming tx of the operator wallet | often an exchange hot wallet or a bridge; sometimes a shared funder linking clusters |
| **Bytecode similarity** | `keccak(eth_getCode(addr))`, or compare after stripping the metadata hash | identical setter/getter templates across contracts and chains |
| **Selector sweep** | Dune / BigQuery: transactions whose input starts with the selector | contracts using the same setter without our event |

Contracts are clustered by shared operator wallet (union-find); `cluster_id` is
`c-` + first 8 hex chars of the lowest operator address.

Shared public infrastructure breaks that assumption: when several unrelated operators call the
same verified public contract, wallet watching records it as a candidate dead drop and union-find
merges their clusters. Such contracts are listed under `[[ignore_contracts]]` in
`config/hunts.toml` and dropped by the wallet-watch collector. The first entry is MetaMask's
DelegationManager `0xdb9b1e94b5b69df7e401ddbede43491141047db3` on Polygon, which three of the
watched operators use.

## 6a. Discovery without a fingerprint

Every other hunt needs something known in advance: an event name, a selector, an operator
wallet, somebody's report. `birth-watch` needs none of them, and exists because a crew that
renames its event walks straight past a topic sweep (measured on 2026-10-19: a live resolver
emitted 85 `URLUpdated` events inside a Polygon range we had already swept).

It rests on one asymmetry. A dead drop must answer anonymous readers, because the infected
machines calling it carry no credentials, and the operator cannot add authentication without
breaking their own malware. So every dead drop, whoever wrote it, must:

1. exist, which means a creation transaction nobody can hide;
2. expose a public reader that returns text;
3. restrict writing to one address;
4. hold a value that decodes to somewhere a victim connects.

The collector reads the blocks in its range, derives each new contract's address from the
deployer and nonce (`keccak(rlp([sender, nonce]))[12:]`, no receipt lookup), fetches the code
once and judges it on shape alone: a selector from a confirmed family, or a small contract with
an owner accessor (`bytecode.Shape`). Survivors are asked what they hold with `eth_call`, and
the answer goes through the usual decoders.

Shape alone never convicts. A contract that answers with a decodable value becomes a finding
like any other; one that matches the shape and stays silent is recorded with
`evidence: candidate` and scored accordingly. The known misses are honest ones: an encrypted
payload, a value kept in a storage slot rather than behind a reader, or a drop that is deployed
and never updated.

## 6b. What the data claims, and what it does not

Three honesty markers keep a lead from reading like a finding:

- **`evidence: candidate`** on a contract means a watched operator deployed or called it and
  nothing has been decoded from it. It may be the operator's next dead drop or an unrelated
  contract they touched. Treat it as a lead and verify before acting.
- **`dual_use: true`** on an indicator means the value is genuinely in the config but is shared
  public infrastructure, such as a mining pool. Blocking it causes collateral damage, so it is
  published as context and withheld from the blocklists.
- **`confidence`** follows the evidence, not the type: 90 for a decoded dead drop, 85 for its
  operator wallet, 55 for a candidate account.

## 7. Validation

On-chain data proves *that* something is stored, not *what* it is. Before publishing a cluster
as malicious, check (without connecting to the IOC yourself):

- **VirusTotal** - relations of the IP/domain, communicating files, sandbox network traffic
  that contains the contract address or the RPC host.
- **abuse.ch ThreatFox / URLhaus / MalwareBazaar** - known C2s, payload URLs, samples.
- **Public sandboxes** (ANY.RUN, Triage, Joe Sandbox, Hybrid Analysis) - search for the contract
  address, the selector or the RPC host in public reports to find the sample that reads it.
- **Explorer labels / Chainabuse** - is the address already reported?
- **Structure** - legitimate contracts rarely store XOR-encoded mining configs or rotate bare
  IP URLs; a decoded value that is plainly benign (a website URL of a real dApp) is a false
  positive and goes into the allow-list.

Confidence in `iocs.json` reflects this: decoded-and-structured values score higher than
loose strings.

## 8. Non-EVM chains: data hidden in transactions

Not every dead drop is a contract. On Tron, Solana and Aptos actors also hide data directly in
**transaction data** of an account they control:

- **Solana** - the SPL Memo program: the C2 (often base64 or a URL) is the memo of a tiny
  transfer. GlassWorm used this: the malware reads the latest memo of a known account.
- **Tron** - the `data`/note field of a transaction, or a TRC-20/contract call parameter.
- **Aptos** - entry-function arguments or resource data of an account (fullnode REST API).

There is no event topic to sweep, so the approach is **account watching**
(`src/deaddrop_hunter/nonevm/`): for every `[[watch_wallets]]` entry on `tron`, `solana` or
`aptos`, the collector pages the account's transactions since the last cursor (TronGrid,
Solana `getSignaturesForAddress` + `getTransaction`, Aptos `/accounts/<a>/transactions`),
extracts the data-carrying field, and runs the same decoders and IOC extraction. Events use
`hunt_id = "watch:<address>"` (or `memo-sweep`), `old_*` fields are null, and the decoder may
be `memo`. Seeds for these watches come from reports and sandbox traffic (the account address
is hard-coded in the malware).

## Known gaps

- **Storage-only contracts.** A setter that writes storage without emitting an event is
  invisible to log sweeps. Covered only by selector hunts (indexed data), wallet watches, or
  bytecode similarity.
- **Other event names.** We only find events we know. Each new family needs its own signature;
  generic patterns (any event with one or two `string` args from a contract with tiny bytecode)
  require indexed data and produce noise.
- **BSC needs an indexed provider** (Dune or a free-key RPC). Without keys BSC is skipped, and
  BSC is where ClearFake / UNC5142 and DPRK UNC5342 operate.
- **Transaction-data hiding** on Tron / Aptos / Solana memos is only found for accounts already
  known (no global sweep yet).
- **Value-only obfuscation beyond 1-byte XOR / base64** (AES, multi-byte XOR, custom alphabets)
  stays `undecoded` until someone writes a decoder from a sample.
- **Web-side discovery.** Many EtherHiding loaders are injected into compromised websites.
  Searching page content for RPC hosts + contract addresses (urlscan.io, PublicWWW) finds new
  contracts that are not in any of our fingerprints; this is manual today.
- **Attribution.** Shared operator wallets show common control, not identity.
