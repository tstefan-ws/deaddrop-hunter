# Data schema (`data/*.json`)

`data/` is the single source of truth. The hunter writes it, the web UI and every
exporter read it, and git history is the audit trail. All files are UTF-8 JSON,
pretty-printed with 2-space indent and keys in the order below, arrays sorted
deterministically (so diffs stay small).

IOC values are stored **raw** (not defanged). Anything that renders them for humans
(web UI, Markdown reports) must defang them and must never make them clickable.

Common conventions:
- `chain`: key from `config/hunts.toml` (`polygon`, `ethereum`, `bsc`, ...).
- Addresses and hashes: EVM chains use lowercase `0x` hex. Non-EVM chains use their
  native format: Tron base58 (`T...`, 34 chars) and 64-hex tx ids; Solana base58
  addresses (32–44 chars) and base58 signatures (87–88 chars); Aptos `0x` + 64 hex
  addresses and `0x` + 64 hex tx hashes. Consumers must validate per chain
  (see "Per-chain identifiers" below) and never assume 0x-40-hex.
- Timestamps: ISO-8601 UTC strings, e.g. `2026-10-18T09:12:44Z`.
- `cluster_id`: `"c-" + first 8 hex chars of the lowest operator wallet address` for
  contracts/wallets grouped by shared operator; `null` when unclustered. For non-EVM
  chains: `"c-"` + first 8 characters of the lowest operator address with any `0x`
  prefix removed, lowercased. Consumers accept `^c-[A-Za-z0-9]{1,64}$`.

## Per-chain identifiers

| chain | `contract` / wallet address | `tx_hash` | `block` | explorer address URL | explorer tx URL |
|---|---|---|---|---|---|
| EVM (polygon, ethereum, bsc, base, ...) | `^0x[0-9a-f]{40}$` | `^0x[0-9a-f]{64}$` | block number | `<explorer>/address/<a>` | `<explorer>/tx/<h>` |
| tron | `^T[1-9A-HJ-NP-Za-km-z]{33}$` | `^[0-9a-f]{64}$` | block number | `https://tronscan.org/#/address/<a>` | `https://tronscan.org/#/transaction/<h>` |
| solana | `^[1-9A-HJ-NP-Za-km-z]{32,44}$` | `^[1-9A-HJ-NP-Za-km-z]{86,88}$` | slot | `https://solscan.io/account/<a>` | `https://solscan.io/tx/<h>` |
| aptos | `^0x[0-9a-f]{64}$` | `^0x[0-9a-f]{64}$` | ledger version | `https://explorer.aptoslabs.com/account/<a>?network=mainnet` | `https://explorer.aptoslabs.com/txn/<h>?network=mainnet` |

For non-EVM chains the `contract` field holds the account (or program/contract
address on Tron) whose transactions carry the hidden data, `selector` is `null`
(or the Tron contract method id when applicable), `hunt_id` is
`watch:<address>` or `memo-sweep`, `old_raw`/`old_decoded` are `null` (transaction
data has no "old value"), and `decoder` may also be `memo`.

## meta.json
```json
{
  "schema_version": 1,
  "generated_at": "2026-10-19T12:00:00Z",
  "tool_version": "0.1.0",
  "cursors": [
    { "chain": "polygon", "hunt_id": "dataupdated-string-string",
      "from_block": 92107923, "to_block": 95797923, "updated_at": "2026-10-19T12:00:00Z" }
  ],
  "counts": { "contracts": 6, "wallets": 3, "events": 71, "iocs": 20, "clusters": 3 }
}
```
`cursors` lets the next run continue incrementally from `to_block + 1`.

## contracts.json — array of
```json
{
  "chain": "polygon",
  "address": "0x17fff8d3f56574a85840d12af91b9d8f4178f85b",
  "cluster_id": "c-19532c0f",
  "family": "xmrig-stealth",
  "hunt_ids": ["dataupdated-string-string"],
  "operator_wallets": ["0x19532c0fbaf0fb8c1d0f3fac0b704bf2f4645539"],
  "selectors": ["0x68446ead"],
  "decoder": "xor-1byte:0x5a",
  "update_count": 21,
  "first_seen": "2026-08-01T10:00:00Z",
  "last_seen": "2026-10-18T09:12:44Z",
  "status": "active",
  "code_hash": "62d0c35063de139e",
  "discovered_at": "2026-10-19T20:00:00Z",
  "new": false,
  "evidence": "decoded",
  "latest_value_raw": "21783b36...",
  "latest_value_decoded": "{\"algo\":\"rx/0\",\"pool\":\"78.40.198.61\",...}",
  "tags": ["xmrig", "config-on-chain"]
}
```
`status`: `active` if updated in the last 30 days, else `dormant`.
`code_hash`: short hash of the runtime bytecode with the compiler's trailing metadata
stripped, so two deployments of one source match. Contracts sharing it were built from the
same template, which links a redeploy across a fresh wallet, another chain or a renamed
event. It is a relation, not a merge: an off-the-shelf kit can be used by unrelated people,
so clusters are still formed only by shared operator wallets.
`discovered_at`: when the entry first appeared in *our* data, which is not when it appeared
on-chain: a contract deployed in March but found today is new to the reader, not to the chain.
`new`: `discovered_at` falls inside `settings.new_window_hours` (default 24), so a reader can
tell at a glance what arrived since yesterday. Contracts, indicators and clusters all carry
both fields.
`evidence`: `decoded` when at least one value has been decoded from this contract,
`candidate` when a watched operator only deployed or called it and nothing has been
decoded yet. Candidates are reported at a lower IOC confidence (55) and marked in the
dashboard; they are leads, not confirmed dead drops.
`family`: free text slug from classification rules; `unknown` if none matched.
`decoder`: `plain`, `xor-1byte:0xNN`, `base64`, `hex-utf8`, `memo`, `undecoded`, or a
`+reverse` variant (`plain+reverse`, `hex-utf8+reverse`) when the decoded value is stored
reversed — e.g. the DPRK XCTDH Tron/Aptos pointers, which are backwards BSC tx hashes.

## wallets.json — array of
```json
{
  "chain": "polygon",
  "address": "0x19532c0fbaf0fb8c1d0f3fac0b704bf2f4645539",
  "role": "operator",
  "label": "Operator: stealth-XMRig cluster (4 contracts)",
  "cluster_id": "c-19532c0f",
  "contracts": ["0x17ff...", "0x2fbd..."],
  "tx_count": 67,
  "first_seen": "2026-08-01T10:00:00Z",
  "last_seen": "2026-10-18T09:12:44Z",
  "watched": true,
  "funded_by": []
}
```
`role`: `operator` (sent updates), `deployer`, `funder`, or `payout` (mining/payout
wallet found inside a decoded config — `chain` is then e.g. `monero`).

## events.json — array of (newest first)
```json
{
  "chain": "polygon",
  "block": 95621219,
  "timestamp": "2026-10-18T09:12:44Z",
  "tx_hash": "0x774e...",
  "contract": "0x2fbd66fe245052d265ca0eda7d01d35b2d8b9feb",
  "from": "0x19532c0fbaf0fb8c1d0f3fac0b704bf2f4645539",
  "selector": "0x68446ead",
  "hunt_id": "dataupdated-string-string",
  "old_raw": "21783b...",
  "new_raw": "21783b...",
  "old_decoded": "{...}",
  "new_decoded": "{...}",
  "decoder": "xor-1byte:0x5a"
}
```
`from` and `selector` may be `null` if the transaction lookup failed.

## iocs.json — array of
```json
{
  "type": "ipv4",
  "value": "78.40.198.61",
  "port": 31270,
  "family": "xmrig-stealth",
  "cluster_id": "c-19532c0f",
  "chain": "polygon",
  "contracts": ["0x17ff..."],
  "first_seen": "2026-08-01T10:00:00Z",
  "last_seen": "2026-10-18T09:12:44Z",
  "times_seen": 40,
  "current": true,
  "discovered_at": "2026-10-19T20:00:00Z",
  "new": false,
  "confidence": 70,
  "dual_use": false,
  "enrichment": {}
}
```
`type`: `ipv4`, `ipv6`, `domain`, `url`, `xmr-wallet`, `btc-wallet`, `evm-contract`,
`evm-wallet`. One entry per (type, value, port). `current` = appears in the latest
value of at least one contract. `dual_use` = a real indicator that is also a shared
public service (a mining pool, say): kept in the JSON, CSV, STIX and MISP feeds, where
MISP marks it `to_ids: false`, and withheld from the plain-text blocklists because
blocking it would hit legitimate users. `confidence` reflects the evidence: 90 for a
contract we decoded a value from, 85 for its operator wallet, 55 for a candidate
account seen only through a watched operator's transaction. `enrichment` is keyed by source
(`virustotal`, `threatfox`, `urlscan`, ...) and is optional.

`meta.scan_interval_minutes`: how often a scan is expected. Each cursor records the chain's
`head_block` at the moment it ran, so a reader can tell whether a scan is level with the
chain or hours behind it, and whether scanning is still happening at all. The dashboard shows
both on the overview and in the top bar.

## clusters.json — array of
```json
{
  "id": "c-19532c0f",
  "name": "Stealth XMRig config cluster",
  "family": "xmrig-stealth",
  "chains": ["polygon"],
  "contracts": ["0x17ff...", "..."],
  "wallets": ["0x1953..."],
  "ioc_count": 8,
  "first_seen": "2026-08-01T10:00:00Z",
  "last_seen": "2026-10-18T09:12:44Z"
}
```
