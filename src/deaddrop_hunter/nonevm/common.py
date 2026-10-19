"""Shared helpers: event construction, timestamps, base58 / Tron address conversion."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime

DEFAULT_MAX_TXS = 200

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TRON_ADDR_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
SOLANA_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
APTOS_ADDR_RE = re.compile(r"^0x[0-9a-f]{64}$")


def iso_utc(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(b) - len(b.lstrip(b"\0"))
    return "1" * pad + out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\0" * pad + full


def tron_hex_to_base58(h: str | None) -> str | None:
    """``41``-prefixed 21-byte hex (TronGrid's owner_address format) -> ``T...`` base58check."""
    if not h:
        return None
    if TRON_ADDR_RE.match(h):
        return h
    h = h.lower()
    if h.startswith("0x"):
        h = "41" + h[2:]
    try:
        raw = bytes.fromhex(h)
    except ValueError:
        return None
    if len(raw) != 21:
        return None
    chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return b58encode(raw + chk)


def tron_address_valid(a: str) -> bool:
    if not TRON_ADDR_RE.match(a or ""):
        return False
    raw = b58decode(a)
    if len(raw) != 25 or raw[0] != 0x41:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def normalize_aptos_address(a: str) -> str:
    a = a.strip().lower()
    if a.startswith("0x"):
        a = a[2:]
    return "0x" + a.rjust(64, "0")


def make_event(*, chain: str, block, timestamp: str | None, tx_hash: str | None, contract: str,
               sender: str | None, selector: str | None, hunt_id: str, new_raw: str | None,
               new_decoded: str | None, decoder: str) -> dict:
    """Build an events.json record with the exact key order from docs/data-schema.md."""
    return {
        "chain": chain,
        "block": block,
        "timestamp": timestamp,
        "tx_hash": tx_hash,
        "contract": contract,
        "from": sender,
        "selector": selector,
        "hunt_id": hunt_id,
        "old_raw": None,
        "new_raw": new_raw,
        "old_decoded": None,
        "new_decoded": new_decoded,
        "decoder": decoder,
    }


def max_txs(chain_cfg: dict) -> int:
    try:
        return max(1, int(chain_cfg.get("max_txs_per_address", DEFAULT_MAX_TXS)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_TXS


def sort_events(events: list[dict]) -> list[dict]:
    """Newest first; deterministic tie-break on tx hash / contract."""
    return sorted(events, key=lambda e: (e.get("timestamp") or "", e.get("block") or 0,
                                         e.get("tx_hash") or "", e.get("contract") or ""), reverse=True)
