# Integrations: consuming deaddrop-hunter data

Every hunt run regenerates the feeds and GitHub Pages publishes them. All data is
**TLP:CLEAR, CC0-1.0**.

```
BASE=https://tstefan-ws.github.io/deaddrop-hunter/feeds
```

| What | URL (relative to `$BASE`) | Use it for |
|---|---|---|
| STIX 2.1 bundle (everything) | `/stix/deaddrop-hunter.bundle.json` | OpenCTI, Sekoia.io, any STIX 2.1 TIP |
| STIX 2.1 bundle per cluster | `/stix/clusters/<cluster_id>.json` | Importing one campaign only |
| MISP feed | `/misp/` (`manifest.json`, `hashes.csv`, `<uuid>.json`) | MISP |
| CSV | `/csv/iocs.csv`, `/csv/contracts.csv`, `/csv/wallets.csv` | SIEM lookups, spreadsheets |
| Blocklists (current IOCs only) | `/txt/ipv4.txt`, `/txt/ipv6.txt`, `/txt/domains.txt`, `/txt/urls.txt` | Firewalls, DNS RPZ, proxies |
| JSON API | `/api/v1/...` (see below) | Scripts, dashboards, enrichment |
| Atom feed | `/atom.xml` | RSS readers, Slack/Teams RSS apps |
| File index | `/index.json` | Path, format, size and sha256 of every file above |

The raw source of truth is also in git:
`https://raw.githubusercontent.com/tstefan-ws/deaddrop-hunter/main/data/iocs.json`.
`contracts.json`, `wallets.json`, `events.json`, `clusters.json` and `meta.json` are next
to it. The format is described in [data-schema.md](data-schema.md).

All IDs (STIX ids, MISP UUIDs) are derived deterministically. A re-import updates objects
and never duplicates them. Each IOC has `first_seen`, `last_seen` and `current`. `current`
means the value is still served by at least one contract right now. **Block on `current`,
hunt on everything.**

> Mining pools such as `pool.hashvault.pro` or `xmr-eu1.nanopool.org` appear as IOCs because
> the malware connects to them. Blocking them is usually fine on corporate networks, but they
> are not "malicious infrastructure" in the takedown sense. Check before you report them.

---

## OpenCTI

**Recommended: the connector.** [`connectors/opencti/`](../connectors/opencti/README.md) is
an external-import connector. It polls the STIX bundle (ETag-aware, PT6H by default), sends
it through a work item, and keeps its state between runs. Run it with Docker next to your
platform. Pin `pycti` to your OpenCTI version.

**One-off import without the connector:**
- UI: **Data → Import → Upload files**, then upload `deaddrop-hunter.bundle.json` and
  validate it with the *ImportFileStix* connector.
- Or the built-in **Data → Ingestion → TAXII/RSS/CSV feeds**. OpenCTI 6.x has *CSV Feeds*,
  where you can map `csv/iocs.csv`. For full fidelity (relationships, reports, wallets),
  use the connector or the STIX upload.

What you get: Indicators with `x_opencti_detection` (= `current`) and `x_opencti_score`
(= confidence). You also get observables, OpenCTI **Cryptocurrency-Wallet** observables
(a custom SCO, `cryptocurrency-wallet--…`, specific to OpenCTI) for contracts and wallets,
one Infrastructure per contract with an explorer link, the XMRig and other Malware
objects, and one Report per cluster. Everything is authored by the `deaddrop-hunter`
organization and marked TLP:CLEAR.

## MISP

Add the MISP feed at `$BASE/misp/`. Use **Sync Actions → Feeds → Add Feed** with source
format *MISP Feed*. There is one event per cluster: `ip-dst|port`, `hostname|port`,
`domain` and `url` attributes with `to_ids`, plus `coin-address` objects. The CSV and TXT
freetext alternatives are covered too. Full steps:
[`connectors/misp/README.md`](../connectors/misp/README.md).

## Sekoia.io

Sekoia's Intelligence Center is STIX 2.1 native.

- **STIX import:** *Intelligence → Import* (or the `POST /v2/inthreat/bundles` API).
  Upload `deaddrop-hunter.bundle.json`, or one per-cluster bundle. Indicators, malware,
  infrastructure and relationships are kept. Sekoia does not know the OpenCTI-specific
  `cryptocurrency-wallet` objects and may drop them. The wallets are still in
  `csv/wallets.csv`.
- **IOC collection for detection:** create an IOC Collection under *Intelligence → IOC
  Collections*. Then add indicators on a schedule with a small job that pulls
  `$BASE/api/v1/iocs/current.json` (or `txt/*.txt`) and pushes it through the IOC
  Collection API (`/v2/inthreat/ioc-collections/{uuid}/indicators/text`). Use
  `valid_from`/`last_seen` to let old entries expire.

## Microsoft Sentinel / Splunk / Elastic (no TAXII server: pull CSV/TXT/JSON)

There is no TAXII server, because GitHub Pages only serves static files. Pull the static
files on a schedule instead.

**Microsoft Sentinel**
- *Threat Intelligence – Upload indicators API* or *TI upload*. A Logic App or Function
  (every 6h) fetches `api/v1/iocs/current.json` and posts STIX indicators. Alternatively,
  feed `stix/deaddrop-hunter.bundle.json` through the *STIX objects upload API*, which
  accepts indicator objects.
- Quick KQL lookup without ingestion:
  ```kql
  let ddh = externaldata(type:string, value:string, port:string, family:string, cluster_id:string,
      chain:string, first_seen:datetime, last_seen:datetime, current:bool, confidence:int, contracts:string)
      [@"https://tstefan-ws.github.io/deaddrop-hunter/feeds/csv/iocs.csv"] with (format="csv", ignoreFirstRecord=true);
  CommonSecurityLog
  | where TimeGenerated > ago(1d)
  | join kind=inner (ddh | where type == "ipv4" and current) on $left.DestinationIP == $right.value
  ```

**Splunk**
- Lookup: download `csv/iocs.csv` into `$SPLUNK_HOME/etc/apps/<app>/lookups/` with a
  scripted input or cron and `curl`. Then:
  ```spl
  index=proxy OR index=firewall
  | lookup deaddrop_iocs.csv value AS dest_ip OUTPUT family current cluster_id
  | where current="true"
  ```
- Or use Splunk ES *Threat Intelligence Management → Threat Intelligence Sources* with
  URLs `txt/ipv4.txt`, `txt/domains.txt` and `txt/urls.txt` (line-oriented, `#` comments
  ignored), and an interval of 21600s.

**Elastic Security**
- *Threat Intel* via the Filebeat/Elastic Agent **Threat Intel → "Custom HTTP JSON"
  (httpjson / CEL input)** pointed at `$BASE/api/v1/iocs/current.json`. Split on `data`
  and map `value` to `threat.indicator.ip` / `.url.full` / `.domain` by `type`.
- Indicator match rules then fire on `threat.indicator.*`. A simpler alternative is a
  `terms` lookup index built from `csv/iocs.csv`.

## Firewalls, proxies, DNS sinkholes (TXT lists)

The `txt/*.txt` lists have one value per line, `#` comment headers (generation time,
license), only **current** IOCs, and are sorted.

- **pfSense/OPNsense:** Firewall → Aliases → URL Table (IPs) →
  `$BASE/txt/ipv4.txt`, refresh 1 day.
- **FortiGate:** Security Fabric → External Connectors → Threat Feeds → IP Address /
  Domain Name, using `ipv4.txt` / `domains.txt`.
- **Palo Alto:** External Dynamic Lists of type IP List / Domain List / URL List.
- **Pi-hole / AdGuard / Unbound / BIND RPZ:** subscribe to `domains.txt`. For RPZ, convert it:
  `curl -s $BASE/txt/domains.txt | grep -v '^#' | sed 's/$/ CNAME ./'`.
- **Squid/proxies:** `urls.txt` and `domains.txt` as ACL files.

## abuse.ch ThreatFox

We **do not auto-submit**. Submissions are reviewed by a human so that mining pools,
shared hosting and stale values are not reported. To submit manually:

1. Take **current** IOCs only (`api/v1/iocs/current.json`), and only real attacker
   infrastructure. Exclude public mining pools.
2. Use the ThreatFox web form or API (`https://threatfox-api.abuse.ch/api/v1/`,
   `query: submit_ioc`, with your Auth-Key):
   - `ioc_type`: `ip:port` (`144.31.108.193:443`), `domain` or `url`
   - `threat_type`: `botnet_cc` for C2, `payload_delivery` for download URLs
   - `malware`: the malpedia name if one exists (for example `win.xmrig`), otherwise `unknown`
   - `confidence_level`: map from our `confidence`
   - `reference`: the contract's explorer URL (from `api/v1/contracts/<chain>/<address>.json`)
   - `comment`: "C2/config retrieved from on-chain dead drop <chain>:<address> (deaddrop-hunter)"
   - `tags`: `EtherHiding`, `deaddrop-hunter`, `<chain>`
3. Check for duplicates first (`query: search_ioc`).

---

## Static JSON API (`$BASE/api/v1/`)

GitHub Pages serves these files with `Access-Control-Allow-Origin: *`, so they can be
fetched from browsers and scripts. URLs are stable within `v1`. Every file has the same
envelope:

```json
{"schema_version": 1, "generated_at": "2026-10-19T12:00:00Z",
 "license": "TLP:CLEAR, CC0-1.0 data", "count": 12, "data": [ ... ]}
```

Values in `data` are **raw, not defanged** (for machine use). Defang them before you show
them to people.

| Endpoint | `data` |
|---|---|
| `index.json` | Endpoint list: `path`, `url`, `description`, `count`, `sha256` |
| `iocs.json` | Every IOC record (format as in `data/iocs.json`) |
| `iocs/current.json` | IOCs with `current: true` |
| `iocs/<type>.json` | Per type: `ipv4`, `ipv6`, `domain`, `url`, `xmr-wallet`, `btc-wallet`, `evm-contract`, `evm-wallet`. These always exist, even when empty. |
| `families/<family>.json` | IOCs of one family (e.g. `xmrig-stealth`, `c2-url`, `unknown`) |
| `chains/<chain>.json` | IOCs found on one chain (`polygon`, `bsc`, `solana`, ...) |
| `contracts.json`, `wallets.json`, `clusters.json` | As in `data/` |
| `contracts/<chain>/<address>.json` | **Object** (`count` = 1): the contract plus `explorer_url`, its `events` and `iocs` |
| `changes.json` | The newest 200 on-chain rotations (events), newest first |

Every record has a `first_seen` field (events get `first_seen` = `timestamp`), so you can
filter for anything new since a date on the client side.

**curl + jq**

```bash
BASE=https://tstefan-ws.github.io/deaddrop-hunter/feeds
# all current IPv4 C2/pool endpoints as ip:port
curl -s $BASE/api/v1/iocs/ipv4.json | jq -r '.data[] | select(.current) | "\(.value):\(.port // "")"'
# what is new since 2026-10-01
curl -s $BASE/api/v1/iocs.json | jq '.data[] | select(.first_seen >= "2026-10-01")'
# history of one contract
curl -s $BASE/api/v1/contracts/polygon/0x17fff8d3f56574a85840d12af91b9d8f4178f85b.json \
  | jq '.data.events[] | {timestamp, new_decoded}'
# verify a download against the index
curl -s $BASE/api/v1/index.json | jq -r '.data[] | select(.path=="iocs.json") | .sha256'
```

**Python (stdlib only)**

```python
import json, urllib.request

BASE = "https://tstefan-ws.github.io/deaddrop-hunter/feeds/api/v1"

def get(path):
    with urllib.request.urlopen(f"{BASE}/{path}", timeout=30) as r:
        return json.load(r)

current = get("iocs/current.json")
print(current["generated_at"], current["count"], "current IOCs")
for ioc in current["data"]:
    if ioc["type"] in ("ipv4", "domain", "url"):
        print(ioc["type"], ioc["value"], ioc.get("port"), ioc["family"], ioc["cluster_id"])

new = [i for i in get("iocs.json")["data"] if i["first_seen"] >= "2026-10-01"]
```

## Atom feed

`$BASE/atom.xml` lists the newest 100 events: contract rotations (new on-chain values) and
newly discovered contracts. Each entry links to the transaction or address on the block
explorer. IOC values in titles and summaries are **defanged** (`hxxps[://]1[.]2[.]3[.]4`).
Subscribe with any RSS reader, the Slack `/feed subscribe` RSS app, or the Teams RSS
connector.
