"""Reading/writing ``data/*.json`` deterministically, plus the event record shape."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from .decoders import decode_value, raw_text

DATA_FILES = ("meta.json", "contracts.json", "wallets.json", "events.json", "iocs.json", "clusters.json")


def iso(ts: int | float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm(v: str) -> str:
    """Lower-case 0x-hex identifiers; keep chain-native (base58 etc.) ones as-is."""
    return v.lower() if v[:2].lower() == "0x" else v


def make_event(
    *,
    chain: str,
    block: int,
    timestamp: str | None,
    tx_hash: str,
    contract: str,
    sender: str | None,
    selector: str | None,
    hunt_id: str,
    old: bytes | None,
    new: bytes | None,
) -> dict:
    """Build an event record in the exact key order of docs/data-schema.md."""
    old_dec, _ = decode_value(old) if old is not None else (None, "undecoded")
    new_dec, new_decoder = decode_value(new) if new is not None else (None, "undecoded")
    return {
        "chain": chain,
        "block": int(block),
        "timestamp": timestamp,
        "tx_hash": _norm(tx_hash),
        "contract": _norm(contract),
        "from": _norm(sender) if sender else None,
        "selector": selector.lower() if selector else None,
        "hunt_id": hunt_id,
        "old_raw": raw_text(old) if old is not None else None,
        "new_raw": raw_text(new) if new is not None else None,
        "old_decoded": old_dec,
        "new_decoded": new_dec,
        "decoder": new_decoder,
    }


def event_key(e: dict) -> tuple:
    return (e["chain"], e["tx_hash"], e["contract"], e.get("new_raw") or "")


def merge_events(existing: list[dict], new: list[dict]) -> tuple[list[dict], int]:
    """Union of events; the first record for a key wins. Returns (merged, added_count)."""
    seen: dict[tuple, dict] = {}
    for e in existing:
        seen.setdefault(event_key(e), e)
    added = 0
    for e in new:
        k = event_key(e)
        if k not in seen:
            seen[k] = e
            added += 1
    return list(seen.values()), added


def dumps(obj: object) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(dumps(obj))
    os.replace(tmp, path)


def read_json(path: Path, default: object) -> object:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def load_data(data_dir: Path) -> dict:
    return {
        "meta": read_json(data_dir / "meta.json", {}),
        "events": read_json(data_dir / "events.json", []),
        "iocs": read_json(data_dir / "iocs.json", []),
        "contracts": read_json(data_dir / "contracts.json", []),
    }


def write_data(data_dir: Path, built: dict) -> list[Path]:
    paths = []
    for name in DATA_FILES:
        key = name[:-5]
        p = data_dir / name
        write_json(p, built[key])
        paths.append(p)
    return paths
