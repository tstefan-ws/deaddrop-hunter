"""Aptos collector (fullnode REST v1, read-only GETs).

* ``GET {api}/accounts/{a}`` -> ``sequence_number`` (how many txs the account has sent).
* ``GET {api}/accounts/{a}/transactions?start=<seq>&limit=100`` -> txs sent by the account. Entry
  function arguments are inspected: strings / byte vectors (``0x..`` -> UTF-8) and, for zero-value
  transfers, the 32-byte "recipient" (Cross-Chain TxDataHiding stores a BSC tx hash there).
* ``GET {api}/accounts/{a}/resources`` -> string fields in non-framework Move resources (actor config
  stored on-chain). Emitted with ``block`` = current ledger version, ``hunt_id`` =
  ``watch:<a>:resource`` and only when the content changed since the last run.

Pruned history: public fullnodes keep only recent versions (``oldest_ledger_version``); for older
transactions the API returns ``[]`` or ``version_pruned`` and names an ``archival_endpoint``. The
collector then retries on chain_cfg ``archive_api`` (default ``https://archive.mainnet.aptoslabs.com/v1``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re

from .common import iso_utc, make_event, max_txs, normalize_aptos_address
from .decode import decode_hex, decode_text, hex_to_bytes
from .net import ApiError, Client

PAGE_LIMIT = 100  # fullnode maximum
DEFAULT_ARCHIVE = "https://archive.mainnet.aptoslabs.com/v1"
_ADDR_ARG_RE = re.compile(r"^0x[0-9a-fA-F]{1,64}$")
_NUM_RE = re.compile(r"^-?\d+$")
_TRANSFER_FUNCS = re.compile(r"::(aptos_account|coin|primary_fungible_store)::transfer(_coins|_fungible_assets)?$")


def _client(chain_cfg: dict, transport=None, sleep=None) -> Client:
    # Aptos Labs public fullnode: anonymous limit is generous (~compute-unit based); stay polite
    rate = float(chain_cfg.get("requests_per_second", 4.0))
    kw = {"per_second": rate, "transport": transport}
    if sleep is not None:
        kw["sleep"] = sleep
    return Client(**kw)


def _flatten(args):
    for a in args:
        if isinstance(a, list):
            yield from _flatten(a)
        elif isinstance(a, dict):
            yield from _flatten(list(a.values()))
        else:
            yield a


def argument_data(payload: dict) -> list[tuple[str, str | None, str]]:
    """Return [(raw, decoded, decoder)] for data-carrying arguments of an entry-function payload."""
    if not payload or payload.get("type") != "entry_function_payload":
        return []
    func = payload.get("function") or ""
    args = payload.get("arguments") or []
    out: list[tuple[str, str | None, str]] = []
    is_transfer = bool(_TRANSFER_FUNCS.search(func))
    if is_transfer:
        amounts = [a for a in args if isinstance(a, str) and _NUM_RE.match(a)]
        if amounts and all(int(a) == 0 for a in amounts):
            # zero-value transfer: the "recipient" is the payload (pointer), not a real counterparty
            for a in args:
                if isinstance(a, str) and _ADDR_ARG_RE.match(a):
                    text, dec = decode_hex(a)
                    if text is None:
                        # Aptos prints addresses without leading zeros -> restore the 32-byte value
                        text, dec = normalize_aptos_address(a), "plain"
                    out.append((a.lower(), text, dec))
        return out
    for a in _flatten(args):
        if not isinstance(a, str) or not a or _NUM_RE.match(a) or a in ("true", "false"):
            continue
        if _ADDR_ARG_RE.match(a):
            b = hex_to_bytes(a if len(a) % 2 == 0 else "0x0" + a[2:])
            text, dec = decode_hex(a) if b is not None else (None, "undecoded")
            if text is not None:
                out.append((a.lower(), text, dec))
            # a bare address-sized value that does not decode is just an address argument
            continue
        if a.startswith("0x") and hex_to_bytes(a) is not None:
            # byte vector longer than an address
            text, dec = decode_hex(a)
            out.append((a.lower(), text, dec))
            continue
        text, dec = decode_text(a, default="plain")
        out.append((a, text, dec))
    return out


def tx_event(chain_key: str, tx: dict, watched: str) -> dict | None:
    if tx.get("type") != "user_transaction":
        return None
    parts = argument_data(tx.get("payload") or {})
    if not parts:
        return None
    raw = parts[0][0] if len(parts) == 1 else json.dumps([p[0] for p in parts])
    decoded = "\n".join(p[1] or "" for p in parts)
    decoder = next((p[2] for p in parts if p[2] != "undecoded"), "undecoded")
    ts_us = int(tx.get("timestamp") or 0)
    return make_event(chain=chain_key, block=int(tx["version"]), timestamp=iso_utc(ts_us / 1e6) if ts_us else None,
                      tx_hash=tx.get("hash"), contract=watched, sender=tx.get("sender"), selector=None,
                      hunt_id=f"watch:{watched}", new_raw=raw, new_decoded=decoded or None, decoder=decoder)


def _strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def resource_fields(resource: dict) -> dict[str, tuple[str, str | None, str]]:
    """String fields of a non-framework resource that look like data (not numbers / plain addresses)."""
    rtype = resource.get("type") or ""
    if rtype.startswith(("0x1::", "0x3::", "0x4::")):
        return {}
    out = {}
    for path, s in _strings(resource.get("data") or {}):
        if not s or _NUM_RE.match(s):
            continue
        if _ADDR_ARG_RE.match(s) and len(s) <= 66:
            text, dec = decode_hex(s)
            if text is None:
                continue
            out[path] = (s, text, dec)
            continue
        if s.startswith("0x") and hex_to_bytes(s) is not None:
            text, dec = decode_hex(s)
        else:
            text, dec = decode_text(s, default="plain")
        out[path] = (s, text, dec)
    return out


def _get_txs(client: Client, base: str, addr: str, start: int, end: int) -> list[dict]:
    txs: list[dict] = []
    while start < end:
        lim = min(PAGE_LIMIT, end - start)
        page = client.get(f"{base}/accounts/{addr}/transactions?start={start}&limit={lim}") or []
        if not page:
            break
        txs.extend(page)
        start = int(page[-1].get("sequence_number", start + len(page) - 1)) + 1
    return txs


def collect(chain_key: str, chain_cfg: dict, watch_wallets: list[dict], since: dict | None,
            transport=None, sleep=None, log=None) -> tuple[list[dict], dict]:
    api = (os.environ.get("DDH_RPC_APTOS") or chain_cfg.get("api")
           or "https://fullnode.mainnet.aptoslabs.com/v1").rstrip("/")
    archive = (chain_cfg.get("archive_api") or DEFAULT_ARCHIVE).rstrip("/")
    want_resources = bool(chain_cfg.get("resources", True))
    limit_total = max_txs(chain_cfg)
    client = _client(chain_cfg, transport, sleep)
    prev = (since or {}).get("accounts", {}) if since else {}
    cursor: dict = {"accounts": dict(prev)}
    events: list[dict] = []
    ledger = None
    for w in watch_wallets:
        addr = normalize_aptos_address(w["address"])
        st = dict(prev.get(addr) or {})
        wallet_events: list[dict] = []
        try:
            try:
                acct = client.get(f"{api}/accounts/{addr}")
            except ApiError as e:
                if e.status == 404:
                    if log:
                        log(f"aptos {addr}: account not found")
                    continue
                raise
            seq = int(acct.get("sequence_number", 0))
            start = int(st.get("next_seq", max(0, seq - limit_total)))
            if seq - start > limit_total:
                start = seq - limit_total
            txs: list[dict] = []
            if start < seq:
                try:
                    txs = _get_txs(client, api, addr, start, seq)
                except ApiError as e:
                    body = e.json() or {}
                    if body.get("error_code") != "version_pruned":
                        raise
                    archive = (body.get("archival_endpoint") or archive).rstrip("/")
                    txs = []
                got = {int(t.get("sequence_number", -1)) for t in txs}
                if len(got) < seq - start and archive and archive != api:
                    # history pruned on this fullnode (oldest_ledger_version) -> ask the archive node
                    if log:
                        log(f"aptos {addr}: {seq - start - len(got)} txs pruned on {api}, using archive")
                    txs = _get_txs(client, archive, addr, start, seq)
            for tx in txs:
                ev = tx_event(chain_key, tx, addr)
                if ev:
                    wallet_events.append(ev)
            if txs:
                st["next_seq"] = max(int(t["sequence_number"]) for t in txs) + 1
                st["last_version"] = max(int(t["version"]) for t in txs)
            elif start >= seq:
                st["next_seq"] = seq
            if want_resources:
                if ledger is None:
                    ledger = client.get(f"{api}/") or {}
                digests = dict(st.get("resource_digests") or {})
                for res in client.get(f"{api}/accounts/{addr}/resources") or []:
                    fields = resource_fields(res)
                    if not fields:
                        continue
                    rtype = res.get("type")
                    raw = json.dumps({"resource": rtype, "fields": {k: v[0] for k, v in sorted(fields.items())}},
                                     separators=(",", ":"), ensure_ascii=False)
                    digest = hashlib.sha256(raw.encode()).hexdigest()
                    if digests.get(rtype) == digest:
                        continue
                    digests[rtype] = digest
                    decoded = "\n".join(f"{k}={v[1] if v[1] is not None else v[0]}"
                                        for k, v in sorted(fields.items()))
                    decoder = next((v[2] for _, v in sorted(fields.items()) if v[2] != "undecoded"),
                                   "undecoded")
                    ts_us = int(ledger.get("ledger_timestamp") or 0)
                    wallet_events.append(make_event(
                        chain=chain_key, block=int(ledger.get("ledger_version") or 0),
                        timestamp=iso_utc(ts_us / 1e6) if ts_us else None, tx_hash=None, contract=addr,
                        sender=None, selector=None, hunt_id=f"watch:{addr}:resource", new_raw=raw,
                        new_decoded=decoded, decoder=decoder))
                st["resource_digests"] = digests
        except Exception as e:
            if log:
                log(f"aptos {addr}: {e}")
            continue
        events.extend(wallet_events)
        cursor["accounts"][addr] = st
    return events, cursor
