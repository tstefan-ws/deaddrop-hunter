"""Shared helpers for the exporters: data loading, deterministic IDs, file writing.

Everything here is stdlib only. Determinism rules:
- IDs are uuid5 values derived from PROJECT_NAMESPACE and stable keys.
- Timestamps come from the data (first_seen / last_seen); the only "run" time is
  ``meta.generated_at``.
- JSON is written with a fixed layout and ``\\n`` line endings on every platform.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_NAME = "deaddrop-hunter"
# Project home; exporters only use it in descriptive text.
PROJECT_URL = "https://github.com/tstefan-ws/deaddrop-hunter"
FEEDS_BASE_URL = "https://tstefan-ws.github.io/deaddrop-hunter/feeds"
DATA_LICENSE = "TLP:CLEAR, CC0-1.0 data"
LICENSE_NOTE = (
    f"{DATA_LICENSE}; provided AS IS, without warranty. See the LICENSE file at {PROJECT_URL}"
)

# Fixed namespace for every deaddrop-hunter derived UUID. Never change it: doing so
# changes every STIX/MISP id and breaks updates in consumers.
PROJECT_NAMESPACE = uuid.UUID("5d1f8a3c-6b2e-5c47-9a0e-de4dd409b07e")

# STIX 2.1 namespace for deterministic SCO ids (spec section 2.9).
STIX_SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# Fallback when config/hunts.toml is not found next to the data dir.
DEFAULT_EXPLORERS = {
    "polygon": "https://polygonscan.com",
    "ethereum": "https://etherscan.io",
    "arbitrum": "https://arbiscan.io",
    "optimism": "https://optimistic.etherscan.io",
    "base": "https://basescan.org",
    "avalanche": "https://snowtrace.io",
    "bsc": "https://bscscan.com",
    "bsc_testnet": "https://testnet.bscscan.com",
    "tron": "https://tronscan.org/#",
    "solana": "https://solscan.io",
    "aptos": "https://explorer.aptoslabs.com",
}

# Address / tx URL path per chain type (``type`` in hunts.toml; EVM when absent),
# appended to the explorer base (see the
# "Per-chain identifiers" table in docs/data-schema.md). Default is EVM style.
ADDRESS_PATHS = {
    "solana": "/account/{a}",
    "aptos": "/account/{a}?network=mainnet",
}
TX_PATHS = {
    "tron": "/transaction/{h}",
    "aptos": "/txn/{h}?network=mainnet",
}
DEFAULT_ADDRESS_PATH = "/address/{a}"
DEFAULT_TX_PATH = "/tx/{h}"

CHAIN_SYMBOLS = {
    "polygon": "POL",
    "ethereum": "ETH",
    "arbitrum": "ETH",
    "optimism": "ETH",
    "base": "ETH",
    "avalanche": "AVAX",
    "bsc": "BNB",
    "bsc_testnet": "BNB",
    "tron": "TRX",
    "solana": "SOL",
    "aptos": "APT",
    "monero": "XMR",
    "bitcoin": "BTC",
}

NETWORK_IOC_TYPES = ("ipv4", "ipv6", "domain", "url")
WALLET_IOC_TYPES = ("xmr-wallet", "btc-wallet", "evm-contract", "evm-wallet")


def uid(*parts: object) -> str:
    """Deterministic UUID string from the project namespace and key parts."""
    key = "|".join("" if p is None else str(p) for p in parts)
    return str(uuid.uuid5(PROJECT_NAMESPACE, key))


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def stix_ts(value: str | None, fallback: str) -> str:
    """ISO timestamp -> STIX timestamp with millisecond precision (``...000Z``)."""
    dt = parse_ts(value) or parse_ts(fallback)
    assert dt is not None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def epoch(value: str | None, fallback: str) -> int:
    dt = parse_ts(value) or parse_ts(fallback)
    assert dt is not None
    return int(dt.timestamp())


def chain_symbol(chain: str | None) -> str:
    if not chain:
        return ""
    return CHAIN_SYMBOLS.get(chain, chain.upper())


def dumps_json(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def write_bytes(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def write_json(path: Path, obj: Any) -> Path:
    return write_bytes(path, dumps_json(obj))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_list(data_dir: Path, name: str) -> list[dict]:
    path = data_dir / name
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON array")
    return data


def _load_explorers(data_dir: Path) -> tuple[dict[str, str], dict[str, str]]:
    """(explorer base per chain, chain type per chain) from config/hunts.toml + defaults."""
    explorers = dict(DEFAULT_EXPLORERS)
    types = {c: c for c in ("tron", "solana", "aptos")}
    for candidate in (data_dir.parent / "config" / "hunts.toml", data_dir / "hunts.toml"):
        if candidate.exists():
            try:
                cfg = tomllib.loads(candidate.read_text(encoding="utf-8"))
            except (tomllib.TOMLDecodeError, OSError):
                break
            for chain, settings in (cfg.get("chains") or {}).items():
                if not isinstance(settings, dict):
                    continue
                if settings.get("explorer"):
                    explorers[chain] = str(settings["explorer"]).rstrip("/")
                if settings.get("type"):
                    types[chain] = str(settings["type"])
            break
    return explorers, types


@dataclass
class Dataset:
    meta: dict
    contracts: list[dict]
    wallets: list[dict]
    events: list[dict]
    iocs: list[dict]
    clusters: list[dict]
    explorers: dict[str, str] = field(default_factory=dict)
    chain_types: dict[str, str] = field(default_factory=dict)  # chain -> evm/tron/solana/aptos

    @property
    def generated_at(self) -> str:
        if self.meta.get("generated_at"):
            return self.meta["generated_at"]
        # Deterministic fallback: newest timestamp present in the data.
        stamps = [
            x.get("last_seen")
            for x in (*self.contracts, *self.wallets, *self.iocs, *self.clusters)
            if x.get("last_seen")
        ]
        return max(stamps) if stamps else "1970-01-01T00:00:00Z"

    @property
    def clusters_by_id(self) -> dict[str, dict]:
        return {c["id"]: c for c in self.clusters}

    def explorer_url(self, chain: str, address: str) -> str | None:
        """Explorer page for an address/account; None for chains without one (e.g. monero)."""
        base = self.explorers.get(chain)
        if not base:
            return None
        kind = self.chain_types.get(chain, chain)
        return base + ADDRESS_PATHS.get(kind, DEFAULT_ADDRESS_PATH).format(a=address)

    def explorer_tx_url(self, chain: str, tx_hash: str) -> str | None:
        base = self.explorers.get(chain)
        # A value read straight out of storage has no transaction behind it and carries a
        # "probe:" id instead; linking that to an explorer would invent a page that is not there.
        if not base or not tx_hash or tx_hash.startswith("probe:"):
            return None
        kind = self.chain_types.get(chain, chain)
        return base + TX_PATHS.get(kind, DEFAULT_TX_PATH).format(h=tx_hash)


def load_dataset(data_dir: Path) -> Dataset:
    data_dir = Path(data_dir)
    meta_path = data_dir / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    explorers, chain_types = _load_explorers(data_dir)
    return Dataset(
        meta=meta,
        contracts=_load_list(data_dir, "contracts.json"),
        wallets=_load_list(data_dir, "wallets.json"),
        events=_load_list(data_dir, "events.json"),
        iocs=_load_list(data_dir, "iocs.json"),
        clusters=_load_list(data_dir, "clusters.json"),
        explorers=explorers,
        chain_types=chain_types,
    )


def ioc_sort_key(ioc: dict) -> tuple:
    return (ioc.get("type") or "", ioc.get("value") or "", ioc.get("port") or 0)


def host_with_port(ioc: dict) -> str:
    value = ioc["value"]
    port = ioc.get("port")
    if not port or ioc.get("type") == "url":
        return value
    if ioc.get("type") == "ipv6":
        return f"[{value}]:{port}"
    return f"{value}:{port}"


def safe_name(value: str) -> str:
    """File-name-safe version of an id (cluster ids are ``c-<hex>`` already)."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value).lstrip(".") or "_"
