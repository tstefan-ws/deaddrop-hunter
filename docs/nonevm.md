# Non-EVM collectors (Tron, Solana, Aptos)

On EVM chains, dead drops usually live in contract storage and announce themselves through events.
On Tron, Solana and Aptos, the actors seen so far hide data in **transactions** sent from an account
they control: a memo, a call argument, or the "recipient" of a zero-value transfer. Malware reads it
back through a free public API. `deaddrop_hunter.nonevm` watches those accounts and decodes what they
publish.

Runtime is stdlib only. All calls are read-only: HTTP GET, or the JSON-RPC methods
`getSignaturesForAddress` and `getTransaction`. Nothing is ever signed or sent. **Decoded values are
attacker-controlled.** The collectors never fetch, resolve or connect to them, and neither should
anything downstream.

## API

```python
from deaddrop_hunter.nonevm import collect
events, cursor = collect(chain_key, chain_cfg, watch_wallets, since)
```

- `chain_cfg` is the raw `[chains.<key>]` TOML table. `type` (`tron` / `solana` / `aptos`) selects
  the collector.
- `watch_wallets` are `{chain, address, label}` entries. Entries for other chains are ignored.
- `since` is the cursor returned by the previous run, or `None`. On the first run the collector
  fetches the newest `max_txs_per_address` transactions per account (default 200).
- `events` follow the events.json shape in [data-schema.md](data-schema.md), newest first.
  `old_raw` and `old_decoded` are always `null`. Only transactions that actually carry data are
  emitted.
- `cursor` is `{"accounts": {<address>: {...}}, "updated_at": ...}`:
  - Tron stores `last_timestamp` and `last_txs`.
  - Solana stores `last_signature` and `last_slot`.
  - Aptos stores `next_seq`, `last_version` and `resource_digests`.

  If an account fails (network error, for example), its cursor is not advanced and its events are
  dropped for that run. The next run retries it.
- Optional keyword-only arguments: `transport=` and `sleep=` (used by tests) and `log=` (defaults to
  stderr).

Optional `chain_cfg` keys:
- All chains: `max_txs_per_address` and `requests_per_second`.
- Tron: `only_from` (default `true`).
- Solana: `fetch_transactions` (default `true`).
- Aptos: `archive_api` and `resources` (default `true`).

Environment variables:
- `DDH_RPC_SOLANA` replaces the Solana RPC.
- `TRONGRID_API_KEY` is sent as the `TRON-PRO-API-KEY` header and raises the request rate.
- `DDH_RPC_APTOS` replaces the Aptos fullnode.

## Per chain

| chain | what is read | event fields |
|---|---|---|
| tron | `GET /v1/accounts/{a}/transactions?limit=200&only_from=true[&min_timestamp=][&fingerprint=]`, newest first, paged by `meta.fingerprint`. Data comes from `raw_data.data` (the hex memo) and from `TriggerSmartContract` `parameter.value.data`. For contract calls, ABI `string`/`bytes` arguments are extracted, and plain calls such as token transfers are skipped. | `block` = block number. `contract` = the watched account, or the called contract (base58) for contract calls. `selector` = `0x`+method id for contract calls. `from` = owner address in base58. |
| solana | `getSignaturesForAddress` (`limit`, `before` for paging, `until` = last seen signature). Its `memo` field already holds the memo text (`"[len] text"`). For signatures that carry a memo, `getTransaction` (`jsonParsed`, `maxSupportedTransactionVersion: 0`) is called to get the fee payer and the exact Memo-program instructions, outer and inner. The Memo programs are `MemoSq4gq…` (v2) and `Memo1UhkJ…` (v1). | `block` = slot. `from` = fee payer. `contract` = the watched account. |
| aptos | `GET /accounts/{a}` gives `sequence_number`. `GET /accounts/{a}/transactions?start=&limit=100` lists the transactions the account sent. Entry-function string arguments and `0x` byte vectors are decoded. For **zero-value transfers**, the recipient argument is emitted, because it is the pointer. `GET /accounts/{a}/resources` collects string fields of non-framework Move resources. | `block` = ledger version. Resource events use `hunt_id` `watch:<a>:resource`, `block` = current ledger version and `tx_hash` = `null`, and are emitted only when the content changes. |

**Aptos pruning.** Public fullnodes keep only about the last 150 M versions
(`x-aptos-ledger-oldest-version`). For older history they return `[]` or a `version_pruned` error,
and the error names the `archival_endpoint`. The collector detects both cases and retries on
`archive_api`, which defaults to `https://archive.mainnet.aptoslabs.com/v1`. All four seed Aptos
accounts needed the archive on 2026-10-19.

### Decoders

The `decoder` values are:

- `memo`: the Solana memo text, as-is.
- `plain`: a text argument as-is, or an Aptos pointer address.
- `hex-utf8`: hex bytes that decode to printable UTF-8.
- `base64`: base64 that decodes to printable text. This also covers JSON memos whose string values are
  base64, such as GlassWorm's `{"link":"aHR0cDov…"}`. Those are expanded in `new_decoded`.
- `xor-1byte:0xNN`: single-byte XOR, with the key recovered from a leading `{` or `h`. It is preferred
  over plain text when the result is JSON or a URL.
- `undecoded`: the transaction carries data, but none of the above produced readable text.

There are two extra values, in addition to the list in data-schema.md:

- **`hex-utf8+reverse`**: the hex decodes to text that, reversed, is a `0x`+64-hex hash. This is the
  Cross-Chain TxDataHiding pointer to a BSC transaction.
- **`plain+reverse`**: the same pointer, found in text that was never hex-encoded.

Consumers that only know the base list can treat `*+reverse` as `hex-utf8` / `plain`.

## Seed accounts (`[[watch_wallets]]` in `config/hunts.toml`)

Every address was copied from the cited report and then confirmed live (2026-10-19) to publish the
described data.

| chain | accounts | campaign | source |
|---|---|---|---|
| solana | `28PKnu7RzizxBzFPoLp69HLXp9bJL3JFtT2s5QzHsEA2` | GlassWorm (original Oct-2025 wave) | [Truesec](https://www.truesec.com/hub/blog/glassworm-self-propagating-vscode-extension) |
| solana | `BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC`, `6YGcuyFRJKZtcaYCCFba9fScNUvPkGXodXE1mJiSzqDJ`, `DSRUBTziADDHSik7WQvSMjvwCHFsbsThrbbjWMoJPUiW` | GlassWorm loaders and the Chrome-extension RAT | [Aikido](https://www.aikido.dev/blog/glassworm-chrome-extension-rat) |
| tron | `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP`, `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG` | DPRK Cross-Chain TxDataHiding (XCTDH) | [Ransom-ISAC part 1](https://ransom-isac.org/blog/cross-chain-txdatahiding-crypto-heist/) |
| tron | `TCqf6ZkaQD84vYsC2cuu1jRwB6JveTaRrF`, `TFMryB9m6d4kBMRjEVyFRbqKSV1cV2NcpH` | XCTDH | [Ransom-ISAC, HashHiding](https://ransom-isac.org/blog/xctdh-adopts-hash-hiding/) |
| tron | `TLmj13VL4p6NQ7jpxz8d9uYY6FUKCYatSe` | XCTDH fee payer / pointer | [Ransom-ISAC part 4](https://ransom-isac.org/blog/cross-chain-txdatahiding-crypto-heist-part-4/) |
| aptos | `0xbe0374…811e`, `0x3f0e57…dce3` | XCTDH Aptos fallback index | [Ransom-ISAC part 1](https://ransom-isac.org/blog/cross-chain-txdatahiding-crypto-heist/) |
| aptos | `0x9d202c…6519`, `0x3d2075…9471` | XCTDH Aptos fallback index | [Ransom-ISAC, HashHiding](https://ransom-isac.org/blog/xctdh-adopts-hash-hiding/) |

What the live run on 2026-10-19 showed:

- **Solana.** GlassWorm memos are `{"link":"<base64 URL>"}` (stage-1 loaders) or
  `{"c2server":…,"checkIp":…,"dht_data":…}` (Chrome RAT). The watched wallets also receive memos from
  *other* senders, for example `5m49aU7p…`, which posts identical links to all four wallets, and
  `6M5EoVyp…`, which posts "I know you". Use `from` to tell operator posts from third-party noise.
- **Tron and Aptos.** These form one rotating pointer system. The same BSC transaction hashes show up
  reversed in the Tron memos and as zero-APT transfer "recipients" on the paired Aptos account. The
  Tron pointers match the BSC hashes Ransom-ISAC published, for example `0x84e8cecd…8f62` (chain 1)
  and `0x610c9ec9…9e22` (chain 2).
- **Older Tron memos.** The memos from June 2025 on `TMfKQ…` are large and encrypted, with a repeating
  key that is not single-byte. They are emitted as `undecoded`.

## Rate limits observed (2026-10-19, keyless)

- **TronGrid.** No rate-limit headers are returned. Without a key it is throttled, with 403/429
  "exceed the frequency limit" errors. The collector defaults to 1 req/s without a key and 4 req/s
  with one. 403 responses that mention "frequency" are retried.
- **Solana public RPC.** Headers report `x-ratelimit-method-limit: 10` (per method per 10 s) and
  `x-ratelimit-rps-limit: 250`, alongside the documented 100 req/10 s per IP. `getTransaction` loops
  hit 429 fairly quickly. The default is 2 req/s, with exponential backoff (2, 4, 8, 16, 32 s). In the
  live run of 4 wallets × 15 signatures, 75 requests took about 74 s, including the 429 back-offs. Use
  `DDH_RPC_SOLANA` with a keyed provider for large watch lists.
- **Aptos Labs fullnode and archive.** No 429 responses were seen. The default is 4 req/s.

## Limitations

- These are watch lists only. Nothing here sweeps a whole chain for unknown memo or dead-drop
  accounts (`memo-sweep` is reserved in the schema). New accounts must come from reporting or from
  pivots on `from` and the funders.
- TronGrid `only_from=true` misses data that someone else sends *to* the watched account. Set
  `only_from = false` to include it, at the cost of more noise.
- Aptos history before `max_txs_per_address` sends is not fetched. Resource events have no
  `tx_hash`.
- Following cross-chain pointers (Tron/Aptos → BSC transaction) is left to the EVM side. The
  decoded `0x…` hash is emitted as-is.
- Multi-byte XOR/AES-encrypted payloads are reported as `undecoded`. No keys are guessed.
