"""Solana collector (JSON-RPC, read-only methods only).

1. ``getSignaturesForAddress(address, {limit, before, until})`` - newest first; ``until`` = last seen
   signature makes runs incremental. Its ``memo`` field already carries the memo text
   (``"[len] text"``, several joined with ``"; "``) - this is exactly what GlassWorm reads.
2. For signatures with a memo, ``getTransaction(sig, {encoding: jsonParsed,
   maxSupportedTransactionVersion: 0})`` gives the fee payer (``from``) and the exact Memo-program
   instructions (top-level and inner). Disable with chain_cfg ``fetch_transactions = false``.
"""

from __future__ import annotations

import os

from .common import iso_utc, make_event, max_txs
from .decode import decode_text, split_rpc_memo
from .net import Client

MEMO_PROGRAMS = {
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",  # SPL Memo v2
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVaJwQjqMRbo",  # SPL Memo v1
}
PAGE_LIMIT = 1000  # RPC maximum


def _client(chain_cfg: dict, transport=None, sleep=None) -> Client:
    # public mainnet-beta: ~100 req/10 s per IP and 10 req/10 s per method (x-ratelimit-method-limit)
    rate = float(chain_cfg.get("requests_per_second", 2.0))
    kw = {"per_second": rate, "transport": transport}
    if sleep is not None:
        kw["sleep"] = sleep
    return Client(**kw)


def memos_from_transaction(tx: dict) -> list[str]:
    """Memo-program instruction texts (outer + inner) from a jsonParsed getTransaction result."""
    out: list[str] = []
    if not tx:
        return out
    msg = (tx.get("transaction") or {}).get("message") or {}
    instrs = list(msg.get("instructions") or [])
    for inner in ((tx.get("meta") or {}).get("innerInstructions") or []):
        instrs.extend(inner.get("instructions") or [])
    for ins in instrs:
        if ins.get("programId") not in MEMO_PROGRAMS:
            continue
        parsed = ins.get("parsed")
        if isinstance(parsed, str):
            out.append(parsed)
        elif isinstance(parsed, dict) and isinstance(parsed.get("memo"), str):
            out.append(parsed["memo"])
        elif isinstance(ins.get("data"), str):  # unparsed: base58 data, keep as-is
            out.append(ins["data"])
    return out


def fee_payer(tx: dict) -> str | None:
    keys = (((tx or {}).get("transaction") or {}).get("message") or {}).get("accountKeys") or []
    if not keys:
        return None
    k = keys[0]
    return k.get("pubkey") if isinstance(k, dict) else k


def _event(chain_key, watched, sig_info, memo_texts, sender):
    raw = "\n".join(memo_texts)
    decoded_parts, decoder = [], None
    for m in memo_texts:
        text, dec = decode_text(m, default="memo")
        decoded_parts.append(text if text is not None else m)
        if decoder is None or (decoder == "memo" and dec != "memo"):
            decoder = dec
    ts = sig_info.get("blockTime")
    return make_event(chain=chain_key, block=sig_info.get("slot"), timestamp=iso_utc(ts) if ts else None,
                      tx_hash=sig_info.get("signature"), contract=watched, sender=sender, selector=None,
                      hunt_id=f"watch:{watched}", new_raw=raw, new_decoded="\n".join(decoded_parts),
                      decoder=decoder or "undecoded")


def collect(chain_key: str, chain_cfg: dict, watch_wallets: list[dict], since: dict | None,
            transport=None, sleep=None, log=None) -> tuple[list[dict], dict]:
    api = os.environ.get("DDH_RPC_SOLANA") or chain_cfg.get("api", "https://api.mainnet-beta.solana.com")
    fetch_tx = bool(chain_cfg.get("fetch_transactions", True))
    limit_total = max_txs(chain_cfg)
    client = _client(chain_cfg, transport, sleep)
    prev = (since or {}).get("accounts", {}) if since else {}
    cursor: dict = {"accounts": dict(prev)}
    events: list[dict] = []
    for w in watch_wallets:
        addr = w["address"]
        until = (prev.get(addr) or {}).get("last_signature")
        sigs: list[dict] = []
        before = None
        wallet_events: list[dict] = []
        try:
            while len(sigs) < limit_total:
                opts = {"limit": min(PAGE_LIMIT, limit_total - len(sigs)), "commitment": "finalized"}
                if until:
                    opts["until"] = until
                if before:
                    opts["before"] = before
                page = client.rpc(api, "getSignaturesForAddress", [addr, opts]) or []
                sigs.extend(page)
                if len(page) < opts["limit"]:
                    break
                before = page[-1]["signature"]
            for s in sigs:
                if not s.get("memo"):
                    continue
                memo_texts = split_rpc_memo(s["memo"])
                sender = None
                if fetch_tx:
                    try:
                        tx = client.rpc(api, "getTransaction", [s["signature"], {
                            "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0,
                            "commitment": "finalized"}])
                        sender = fee_payer(tx)
                        exact = memos_from_transaction(tx)
                        if exact:
                            memo_texts = exact
                    except Exception as e:  # fall back to the memo from getSignaturesForAddress
                        if log:
                            log(f"solana getTransaction {s['signature']}: {e}")
                wallet_events.append(_event(chain_key, addr, s, memo_texts, sender))
        except Exception as e:
            if log:
                log(f"solana {addr}: {e}")
            continue
        events.extend(wallet_events)
        if sigs:
            cursor["accounts"][addr] = {"last_signature": sigs[0]["signature"], "last_slot": sigs[0].get("slot")}
    return events, cursor
