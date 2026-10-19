"""Dune API (read-only SQL) for selector hunts: transactions whose input starts with a selector.

Requires env ``DUNE_API_KEY``; without it :class:`ProviderUnavailable` is raised.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime

from ..http import Transport, urllib_transport
from . import ProviderUnavailable

log = logging.getLogger(__name__)

API = "https://api.dune.com/api/v1"

# config chain key -> Dune schema
DUNE_CHAINS = {
    "ethereum": "ethereum",
    "polygon": "polygon",
    "arbitrum": "arbitrum",
    "optimism": "optimism",
    "bsc": "bnb",
    "base": "base",
    "avalanche": "avalanche_c",
}


class DuneError(Exception):
    pass


def parse_dune_time(v: object) -> str | None:
    """Dune timestamps ('2026-10-18 09:12:44.000 UTC') -> ISO-8601 UTC."""
    if not v:
        return None
    s = str(v).replace(" UTC", "").replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return None


_IDENT = re.compile(r"[a-z][a-z0-9_]*")


def _schema(chain: str, dune_chain: str | None = None) -> str:
    schema = dune_chain or DUNE_CHAINS.get(chain)
    if not schema:
        raise ProviderUnavailable(f"chain {chain!r} not mapped to a Dune schema (set dune_chain)")
    if not _IDENT.fullmatch(schema):
        raise ValueError(f"bad Dune schema name {schema!r}")
    return schema


def logs_sql(chain: str, topic0: str, from_block: int, to_block: int, dune_chain: str | None = None) -> str:
    schema = _schema(chain, dune_chain)
    if not re.fullmatch(r"0x[0-9a-f]{64}", topic0):
        raise ValueError(f"bad topic0 {topic0!r}")
    return (
        "SELECT block_number, block_time, contract_address, tx_hash, tx_from, topic0, data "
        f"FROM {schema}.logs "
        f"WHERE topic0 = {topic0} AND block_number BETWEEN {int(from_block)} AND {int(to_block)} "
        "ORDER BY block_number"
    )


def selector_sql(chain: str, selector: str, days: int, dune_chain: str | None = None) -> str:
    schema = dune_chain or DUNE_CHAINS.get(chain)
    if not schema:
        raise ProviderUnavailable(f"chain {chain!r} not mapped to a Dune schema")
    if not re.fullmatch(r"0x[0-9a-f]{8}", selector):
        raise ValueError(f"bad selector {selector!r}")
    return (
        f'SELECT block_number, block_time, hash, "from", "to", input '
        f"FROM {schema}.transactions "
        f"WHERE bytearray_substring(input, 1, 4) = {selector} "
        f"AND block_time > now() - interval '{int(days)}' day "
        f"AND success ORDER BY block_number"
    )


class Dune:
    def __init__(self, api_key: str | None = None, transport: Transport = urllib_transport,
                 sleep: Callable[[float], None] = time.sleep, poll_timeout: float = 600.0):
        key = api_key if api_key is not None else os.environ.get("DUNE_API_KEY", "")
        if not key:
            raise ProviderUnavailable("DUNE_API_KEY not set")
        self.key = key
        self.transport = transport
        self.sleep = sleep
        self.poll_timeout = poll_timeout

    def _req(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        status, raw = self.transport(method, API + path, data,
                                     {"X-Dune-Api-Key": self.key, "Content-Type": "application/json"}, 60.0)
        try:
            payload = json.loads(raw)
        except ValueError as e:
            raise DuneError(f"HTTP {status}: invalid JSON") from e
        if status >= 400:
            raise DuneError(f"HTTP {status}: {payload.get('error', payload)}")
        return payload

    def run_sql(self, sql: str) -> list[dict]:
        ex = self._req("POST", "/sql/execute", {"sql": sql, "performance": "medium"})
        exec_id = ex.get("execution_id")
        if not exec_id:
            raise DuneError(f"no execution_id in {ex}")
        waited = 0.0
        while True:
            st = self._req("GET", f"/execution/{exec_id}/status")
            state = st.get("state", "")
            if state == "QUERY_STATE_COMPLETED":
                break
            if state in ("QUERY_STATE_FAILED", "QUERY_STATE_CANCELLED", "QUERY_STATE_EXPIRED"):
                raise DuneError(f"execution {exec_id} {state}: {st.get('error')}")
            if waited > self.poll_timeout:
                raise DuneError(f"execution {exec_id} timed out")
            self.sleep(3.0)
            waited += 3.0
        rows: list[dict] = []
        offset = 0
        while True:
            res = self._req("GET", f"/execution/{exec_id}/results?limit=1000&offset={offset}")
            batch = res.get("result", {}).get("rows", [])
            rows.extend(batch)
            if not res.get("next_offset") or not batch:
                break
            offset = int(res["next_offset"])
        return rows

    def topic_logs(self, chain: str, topic0: str, from_block: int, to_block: int,
                   dune_chain: str | None = None) -> list[dict]:
        """Logs with ``topic0`` in a block range, in RPC log shape plus ``txFrom`` and
        ``blockTime`` (Dune's timestamp string)."""
        rows = self.run_sql(logs_sql(chain, topic0, from_block, to_block, dune_chain))
        out = []
        for r in rows:
            out.append({
                "address": str(r.get("contract_address", "")).lower(),
                "topics": [str(r.get("topic0", "")).lower()],
                "data": str(r.get("data") or "0x"),
                "blockNumber": hex(int(r.get("block_number") or 0)),
                "blockTime": r.get("block_time"),
                "transactionHash": str(r.get("tx_hash", "")).lower(),
                "txFrom": str(r.get("tx_from", "")).lower() or None,
            })
        return out

    def selector_txs(self, chain: str, selector: str, days: int, dune_chain: str | None = None) -> list[dict]:
        """Return txs as dicts: block, timestamp (ISO string or None), hash, from, to, input."""
        rows = self.run_sql(selector_sql(chain, selector, days, dune_chain))
        out = []
        for r in rows:
            out.append({
                "block": int(r.get("block_number") or 0),
                "time": r.get("block_time"),
                "hash": str(r.get("hash", "")).lower(),
                "from": str(r.get("from", "")).lower() or None,
                "to": str(r.get("to", "")).lower() or None,
                "input": str(r.get("input", "0x")),
            })
        return out
