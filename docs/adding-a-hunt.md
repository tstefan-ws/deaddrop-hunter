# Adding a hunt

Most contributions are a few lines of TOML in `config/hunts.toml`. Code changes are only needed
for new decoders, family rules, providers or chain types.

Before you start: read [methodology.md](methodology.md) (what each hunt kind can and cannot
see) and keep everything **TLP:CLEAR** and **defanged** in prose.

## 1. Event fingerprint (`kind = "event"`)

You know the event the setter emits, e.g. from a verified contract, a decompiler or a report.

```toml
[[hunts]]
id = "configchanged-string"              # unique, kebab-case; used in data/ and cursors
kind = "event"
signature = "ConfigChanged(string)"      # topic0 is computed from it (Keccak-256)
# topic0 = "0x..."                       # optional: give it explicitly if you only know the hash
abi = ["string"]                         # types of the NON-indexed args, in order (log data)
chains = ["polygon", "ethereum", "bsc"]
reference = "https://example.org/report" # public source (optional)
note = "Seen in <family> loader, sample sha256 ..."
```

- `abi` describes the log `data`. For `DataUpdated(string,string)` it is `["string", "string"]`
  (old, new); the **last** string is treated as the new value.
- If both `signature` and `topic0` are given they must match; compute with
  `python -c "from deaddrop_hunter.keccak import topic0; print(topic0('ConfigChanged(string)'))"`
  (and `selector(...)` for 4-byte selectors).
- Check noise first: a common signature (`Transfer`, `OwnershipTransferred`, generic
  `Updated(string)`) will flood the data. Run a short sweep and look at the result:

```bash
deaddrop-hunter hunt --hunts configchanged-string --chains polygon --days 3 --data /tmp/ddh-test
jq length /tmp/ddh-test/events.json
```

## 2. Selector fingerprint (`kind = "selector"`)

The setter's 4-byte selector, when the contract emits no (known) event. Needs indexed data:
`DUNE_API_KEY` (preferred) or `ETHERSCAN_API_KEY` (only for contracts already known).

```toml
[[hunts]]
id = "selector-1234abcd"
kind = "selector"
selector = "0x1234abcd"          # or: signature = "setUrl(string)" and it is computed
abi = ["string"]                 # argument types of the call
chains = ["polygon"]
note = "Setter of contract 0x..., found via operator wallet 0x..."
```

## 3. Watch a wallet or account (`[[watch_wallets]]`)

Operator wallets (EVM) and data-carrying accounts (Tron / Solana / Aptos):

```toml
[[watch_wallets]]
chain = "polygon"
address = "0x19532c0fbaf0fb8c1d0f3fac0b704bf2f4645539"
label = "Operator: stealth-XMRig cluster (4 contracts)"

[[watch_wallets]]
chain = "solana"
address = "<base58 account>"
label = "Memo C2 account (GlassWorm-style)"
```

- EVM watches use the Etherscan V2 `txlist` (`ETHERSCAN_API_KEY`); they surface contract
  creations and updates that emit no event. Run them alone with `--hunts watch-wallet`.
- Non-EVM watches use the public endpoints in `[chains.tron|solana|aptos]` (see
  `src/deaddrop_hunter/nonevm/`). Addresses use the chain's native format
  ([data-schema.md](data-schema.md#per-chain-identifiers)).
- Label honestly: describe the role, not a person.

## 4. Add a chain

EVM chain:

```toml
[chains.linea]
chain_id = 59144
block_time_s = 2
explorer = "https://lineascan.build"
rpcs = [
  { url = "https://linea.gateway.tenderly.co", max_log_span = 0 },   # measure before setting!
]
# indexed_provider = "dune"   # when public RPCs refuse topic-only sweeps
# dune_chain = "linea"        # Dune table prefix (<dune_chain>.logs)
```

**Measure `max_log_span`**: send an address-less `eth_getLogs` with just your topic0 over 1k,
10k, 100k and 400k blocks; set the largest span that answers reliably, `0` if it refuses. Record
the date in the PR (and in [providers.md](providers.md)). Then add the chain key to the
`chains` list of each hunt that should run there, and to the Sigma/Suricata host lists in
`rules/` if it introduces new public RPC hostnames.

Any chain's RPC list can be prepended at runtime with `DDH_RPC_<CHAIN>="url|max_span"`
(comma-separate several), which is how keyed RPCs are added without committing them.

Non-EVM chain types (`type = "tron" | "solana" | "aptos"`) need a collector in
`src/deaddrop_hunter/nonevm/`; a new type means a new module registered in `COLLECTORS`.

## 5. Decoder or family rule (code)

- **Decoders** - `src/deaddrop_hunter/decoders.py`, list `VALUE_DECODERS` (ordered, first match
  wins). A decoder takes the raw bytes and returns text or `None`; return `None` unless the result
  is clearly right (printable, structurally valid) to avoid garbage. Name it the way it should
  appear in `decoder` (e.g. `xor-multibyte:<hex>`, `aes-cbc:<keyid>`).
- **Family rules** - `src/deaddrop_hunter/classify.py`, list `FAMILY_RULES` (ordered, more
  specific first). Each rule gets the decoded text / parsed JSON and returns bool; give it a slug
  (`family`), a cluster name and tags.
- **IOC types** - also in `classify.py`; any new type must be added to
  [data-schema.md](data-schema.md) and the exporters.
- **Tests** - add a test vector from a real on-chain value (raw hex in, decoded text and family
  out) under `tests/core/`. Then run `deaddrop-hunter rebuild` locally: it re-decodes every stored
  event without network access, so you can see the effect on the whole dataset.

## 6. Submit

**Pull request** (preferred): branch `hunt/<short-name>`, change `config/hunts.toml` (and code +
tests if needed), run `ruff check src tests && pytest`, and fill the PR template: example
contracts/transactions, measured noise, why it is malicious. Don't commit `data/` from your test
run; CI's next scheduled hunt picks up the new hunt and backfills `default_lookback_days`.

**Issue**: no time for a PR? Use the
[New hunt / fingerprint proposal](https://github.com/tstefan-ws/deaddrop-hunter/issues/new?template=hunt-proposal.yml)
form, or [Report a suspicious contract/wallet](https://github.com/tstefan-ws/deaddrop-hunter/issues/new?template=report-contract.yml)
for a single address.

Backfilling older history after merge: a maintainer runs the `hunt` workflow manually with
`hunts=<id>` and `days=<N>`.
