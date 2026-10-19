# MISP: consuming the deaddrop-hunter feed

deaddrop-hunter publishes a standard **MISP feed**, the same layout PyMISP's feed
generator produces, at:

```
https://tstefan-ws.github.io/deaddrop-hunter/feeds/misp/
```

It contains:

- `manifest.json`: one entry per event, keyed by event UUID, with `info`, `date`,
  `analysis`, `threat_level_id`, `timestamp`, `Orgc` and `Tag`.
- `hashes.csv`: lines of `md5(value),event_uuid`, used for MISP's feed-correlation cache.
- `<event-uuid>.json`: one event per cluster, plus one for unclustered data.

Each event has:

- `info`: `deaddrop-hunter: <cluster name>`
- tags: `tlp:clear`, `deaddrop-hunter:family="..."` and `deaddrop-hunter:chain="..."`
- attributes `ip-dst|port` / `ip-dst`, `hostname|port` / `domain` and `url`, all with
  `to_ids=true`. Each attribute also carries the tag `deaddrop-hunter:current="true|false"`
  and its first/last seen times.
- `coin-address` objects for the dead-drop contracts/accounts, operator wallets and payout
  wallets. They use `address-crypto` (EVM, Tron, Solana, Aptos), `address-xmr` or
  `address` (BTC), and `symbol` (POL, ETH, BNB, AVAX, TRX, SOL, APT, XMR, ...).

UUIDs never change, and `timestamp` comes from the cluster's `last_seen`. MISP therefore
only re-pulls an event when the cluster has actually changed.

## Add the feed (MISP 2.4 / 2.5)

1. **Sync Actions → Feeds → Add Feed**
2. Fill in:
   - *Enabled*: yes. *Caching enabled*: yes, so correlations show up without a full import.
   - *Name*: `deaddrop-hunter`
   - *Provider*: `deaddrop-hunter`
   - *Input Source*: `Network`
   - *URL*: `https://tstefan-ws.github.io/deaddrop-hunter/feeds/misp/`
   - *Source Format*: **MISP Feed**
   - *Distribution*: your choice. The data is TLP:CLEAR.
   - Optionally set a *Default Tag*, for example `osint:source-type="block-or-filter-list"`.
3. Save. In the feed list, click **Fetch and store all feed data**, or let the scheduled
   `fetchFeed` task run it.

From the CLI or cron:

```bash
# fetch one feed by id (from the Feeds list)
sudo -u www-data /var/www/MISP/app/Console/cake Server fetchFeed <user_id> <feed_id>
# or every enabled feed
sudo -u www-data /var/www/MISP/app/Console/cake Server fetchFeed <user_id> all
```

Use **Preview** on the feed row to browse the events before importing them.

## Alternative: CSV or plain-text as a freetext feed

If you only want network IOCs as attributes in one rolling event:

1. **Sync Actions → Feeds → Add Feed**
2. *Source Format*: **Freetext Parsed Feed**
3. *URL*: one of
   - `https://tstefan-ws.github.io/deaddrop-hunter/feeds/txt/ipv4.txt`
   - `https://tstefan-ws.github.io/deaddrop-hunter/feeds/txt/domains.txt`
   - `https://tstefan-ws.github.io/deaddrop-hunter/feeds/txt/urls.txt`

   (`#` comment lines are ignored.)
4. Enable *Fixed event* and *Delta merge*, so indicators that are no longer current are
   soft-deleted. Set *Target Event* to a new event.

For richer columns, use a **Simple CSV Parsed Feed** with
`https://tstefan-ws.github.io/deaddrop-hunter/feeds/csv/iocs.csv`. Set *Value field(s) in
the CSV* to `2` (the `value` column) and exclude the header row. That file mixes types,
including wallets. Prefer the TXT lists when you want a single type per feed.

## Feeding back

If you have sightings or new dead-drop contracts, open an issue at
https://github.com/tstefan-ws/deaddrop-hunter/issues.
