"""Tron collector (TronGrid REST v1, read-only GETs).

Endpoint: ``GET {api}/v1/accounts/{address}/transactions?limit=&only_from=&min_timestamp=&fingerprint=``
(newest first, paginated with ``meta.fingerprint``). Hidden data is taken from:
  * ``raw_data.data`` - the transaction memo/note (hex). Cross-Chain TxDataHiding (DPRK, Ransom-ISAC
    2025) stores a reversed BSC tx hash here on zero-value TRX transfers.
  * ``TriggerSmartContract`` ``parameter.value.data`` - method id + ABI args; ABI ``string``/``bytes``
    arguments are extracted, ordinary calls (token transfers etc.) are skipped.
"""

from __future__ import annotations

import os
import urllib.parse

from .common import iso_utc, make_event, max_txs, tron_hex_to_base58
from .decode import decode_bytes, decode_hex, is_printable_text
from .net import Client

PAGE_LIMIT = 200  # TronGrid maximum


def _client(chain_cfg: dict, transport=None, sleep=None) -> Client:
    headers = {}
    key = os.environ.get("TRONGRID_API_KEY")
    if key:
        headers["TRON-PRO-API-KEY"] = key
    # keyless TronGrid is heavily throttled; keyed allows ~15 qps
    rate = float(chain_cfg.get("requests_per_second", 4.0 if key else 1.0))
    kw = {"per_second": rate, "headers": headers, "transport": transport}
    if sleep is not None:
        kw["sleep"] = sleep
    return Client(**kw)


def abi_strings(args: bytes) -> list[str]:
    """Best-effort extraction of ABI-encoded dynamic ``string``/``bytes`` values from call args."""
    out: list[str] = []
    n = len(args)
    if n < 64:
        return out
    seen = set()
    for i in range(0, min(n, 32 * 16), 32):
        off = int.from_bytes(args[i:i + 32], "big")
        if off % 32 or off < 32 or off + 32 > n or off in seen:
            continue
        ln = int.from_bytes(args[off:off + 32], "big")
        if ln == 0 or off + 32 + ln > n:
            continue
        seen.add(off)
        val = args[off + 32:off + 32 + ln]
        text, _ = decode_bytes(val)
        if text is not None:
            out.append(val.hex())
    return out


def _trigger_event(chain_key, tx, val, watched, block, ts, sender):
    data = (val.get("data") or "").lower()
    if len(data) < 8:
        return None
    selector = "0x" + data[:8]
    try:
        args = bytes.fromhex(data[8:])
    except ValueError:
        return None
    contract = tron_hex_to_base58(val.get("contract_address")) or watched
    strings = abi_strings(args)
    if strings:
        raw = strings[0] if len(strings) == 1 else "|".join(strings)
        decoded_parts = []
        decoder = None
        for s in strings:
            text, dec = decode_hex(s)
            decoded_parts.append(text or "")
            decoder = decoder or dec
        return make_event(chain=chain_key, block=block, timestamp=ts, tx_hash=tx.get("txID"),
                          contract=contract, sender=sender, selector=selector,
                          hunt_id=f"watch:{watched}", new_raw=raw,
                          new_decoded="\n".join(decoded_parts), decoder=decoder or "undecoded")
    # no ABI string: data in non-standard calldata (e.g. raw bytes after the method id)
    stripped = args.strip(b"\0")
    text, dec = decode_bytes(stripped) if len(stripped) >= 8 else (None, "undecoded")
    if text is not None and is_printable_text(text, 8):
        return make_event(chain=chain_key, block=block, timestamp=ts, tx_hash=tx.get("txID"),
                          contract=contract, sender=sender, selector=selector,
                          hunt_id=f"watch:{watched}", new_raw=data[8:], new_decoded=text, decoder=dec)
    return None


def tx_events(chain_key: str, tx: dict, watched: str) -> list[dict]:
    raw = tx.get("raw_data") or {}
    if not tx.get("txID") or not raw:
        return []
    block = tx.get("blockNumber")
    ts_ms = tx.get("block_timestamp") or raw.get("timestamp")
    ts = iso_utc(ts_ms / 1000) if ts_ms else None
    contracts = raw.get("contract") or [{}]
    first = contracts[0] if contracts else {}
    val = ((first.get("parameter") or {}).get("value")) or {}
    sender = tron_hex_to_base58(val.get("owner_address"))
    events = []
    memo_hex = raw.get("data")
    if memo_hex:
        text, dec = decode_hex(memo_hex)
        events.append(make_event(chain=chain_key, block=block, timestamp=ts, tx_hash=tx["txID"],
                                 contract=watched, sender=sender, selector=None,
                                 hunt_id=f"watch:{watched}", new_raw=memo_hex.lower(),
                                 new_decoded=text, decoder=dec))
    for c in contracts:
        if c.get("type") == "TriggerSmartContract":
            v = ((c.get("parameter") or {}).get("value")) or {}
            ev = _trigger_event(chain_key, tx, v, watched, block, ts,
                                tron_hex_to_base58(v.get("owner_address")) or sender)
            if ev:
                events.append(ev)
    return events


def collect(chain_key: str, chain_cfg: dict, watch_wallets: list[dict], since: dict | None,
            transport=None, sleep=None, log=None) -> tuple[list[dict], dict]:
    api = chain_cfg.get("api", "https://api.trongrid.io").rstrip("/")
    only_from = bool(chain_cfg.get("only_from", True))
    limit_total = max_txs(chain_cfg)
    client = _client(chain_cfg, transport, sleep)
    prev = (since or {}).get("accounts", {}) if since else {}
    cursor: dict = {"accounts": dict(prev)}
    events: list[dict] = []
    for w in watch_wallets:
        addr = w["address"]
        st = prev.get(addr) or {}
        last_ts = st.get("last_timestamp")
        seen_at_last = set(st.get("last_txs") or [])
        params = {"limit": min(PAGE_LIMIT, limit_total), "only_from": str(only_from).lower()}
        if last_ts:
            params["min_timestamp"] = last_ts
            params["order_by"] = "block_timestamp,desc"
        fetched = 0
        newest_ts, newest_ids = last_ts, set(seen_at_last)
        fingerprint = None
        wallet_events: list[dict] = []
        try:
            while fetched < limit_total:
                q = dict(params)
                if fingerprint:
                    q["fingerprint"] = fingerprint
                url = f"{api}/v1/accounts/{urllib.parse.quote(addr)}/transactions?{urllib.parse.urlencode(q)}"
                resp = client.get(url)
                data = (resp or {}).get("data") or []
                for tx in data:
                    if fetched >= limit_total:
                        break
                    ts_ms = tx.get("block_timestamp")
                    txid = tx.get("txID")
                    if not txid:
                        continue  # internal-transaction records have no raw_data
                    if last_ts and ts_ms == last_ts and txid in seen_at_last:
                        continue
                    fetched += 1
                    if ts_ms is not None:
                        if newest_ts is None or ts_ms > newest_ts:
                            newest_ts, newest_ids = ts_ms, {txid}
                        elif ts_ms == newest_ts:
                            newest_ids.add(txid)
                    wallet_events.extend(tx_events(chain_key, tx, addr))
                fingerprint = ((resp or {}).get("meta") or {}).get("fingerprint")
                if not fingerprint or not data:
                    break
        except Exception as e:  # keep other wallets going; cursor for this one is not advanced
            if log:
                log(f"tron {addr}: {e}")
            continue
        events.extend(wallet_events)
        if newest_ts is not None:
            cursor["accounts"][addr] = {"last_timestamp": newest_ts, "last_txs": sorted(newest_ids)}
    return events, cursor
