"""Etherscan V2 unified API client (read-only): logs by topic0, txlist, contract creation.

Requires env ``ETHERSCAN_API_KEY``; without it :class:`ProviderUnavailable` is raised so callers
can log a warning and skip.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
from collections.abc import Callable

from ..http import RateLimiter, Transport, urllib_transport
from . import ProviderUnavailable

log = logging.getLogger(__name__)

API = "https://api.etherscan.io/v2/api"
PAGE_SIZE = 1000
MAX_WINDOW = 10_000  # Etherscan caps page * offset at 10k


class EtherscanError(Exception):
    pass


class EtherscanV2:
    def __init__(
        self,
        chain_id: int,
        api_key: str | None = None,
        transport: Transport = urllib_transport,
        limiter: RateLimiter | None = None,
        retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ):
        key = api_key if api_key is not None else os.environ.get("ETHERSCAN_API_KEY", "")
        if not key:
            raise ProviderUnavailable("ETHERSCAN_API_KEY not set")
        self.chain_id = chain_id
        self.key = key
        self.transport = transport
        self.limiter = limiter or RateLimiter(5.0)
        self.retries = retries
        self.sleep = sleep

    def _get(self, params: dict) -> object:
        q = {"chainid": str(self.chain_id), **{k: str(v) for k, v in params.items()}, "apikey": self.key}
        url = API + "?" + urllib.parse.urlencode(q)
        last = ""
        for attempt in range(self.retries):
            if attempt:
                self.sleep(1.0 * 2 ** (attempt - 1))
            self.limiter.wait()
            try:
                status, raw = self.transport("GET", url, None, {}, 60.0)
            except OSError as e:
                last = str(e)
                continue
            if status >= 400:
                last = f"HTTP {status}"
                continue
            try:
                payload = json.loads(raw)
            except ValueError:
                last = "invalid JSON"
                continue
            result = payload.get("result")
            if str(payload.get("status")) == "1":
                return result
            msg = f"{payload.get('message')}: {result}"
            if isinstance(result, list) or "No records found" in str(payload.get("message")) \
                    or "No transactions found" in str(payload.get("message")):
                return []
            if "rate limit" in msg.lower():
                last = msg
                continue
            raise EtherscanError(msg)
        raise EtherscanError(last or "request failed")

    def block_number(self) -> int:
        q = {"module": "proxy", "action": "eth_blockNumber"}
        res = self._get(q)
        return int(res, 16) if isinstance(res, str) else 0

    def get_logs(self, topic0: str, from_block: int, to_block: int, address: str | None = None) -> list[dict]:
        """All logs with ``topic0`` in [from_block, to_block], splitting the range when the
        10k result window is exhausted. Returned in RPC log shape (hex strings)."""
        out: list[dict] = []
        stack = [(from_block, to_block)]
        while stack:
            lo, hi = stack.pop()
            page_logs: list[dict] = []
            full = False
            for page in range(1, MAX_WINDOW // PAGE_SIZE + 1):
                params = {"module": "logs", "action": "getLogs", "fromBlock": lo, "toBlock": hi,
                          "topic0": topic0, "page": page, "offset": PAGE_SIZE}
                if address:
                    params["address"] = address
                res = self._get(params)
                batch = res if isinstance(res, list) else []
                page_logs.extend(batch)
                if len(batch) < PAGE_SIZE:
                    break
            else:
                full = True
            if full and hi > lo:
                mid = (lo + hi) // 2
                stack.extend([(mid + 1, hi), (lo, mid)])
                continue
            out.extend(page_logs)
        return [_normalize_log(lg) for lg in out]

    def txlist(self, address: str, start_block: int = 0, end_block: int = 99_999_999) -> list[dict]:
        out: list[dict] = []
        page = 1
        while True:
            res = self._get({"module": "account", "action": "txlist", "address": address,
                             "startblock": start_block, "endblock": end_block, "page": page,
                             "offset": PAGE_SIZE, "sort": "asc"})
            batch = res if isinstance(res, list) else []
            out.extend(batch)
            if len(batch) < PAGE_SIZE or page * PAGE_SIZE >= MAX_WINDOW:
                break
            page += 1
        return out

    def contract_creation(self, addresses: list[str]) -> list[dict]:
        out: list[dict] = []
        for i in range(0, len(addresses), 5):
            res = self._get({"module": "contract", "action": "getcontractcreation",
                             "contractaddresses": ",".join(addresses[i:i + 5])})
            if isinstance(res, list):
                out.extend(res)
        return out


def _to_hex(v: object) -> str:
    if isinstance(v, str) and v.startswith("0x"):
        return v if v != "0x" else "0x0"
    try:
        return hex(int(str(v)))
    except ValueError:
        return "0x0"


def _normalize_log(lg: dict) -> dict:
    return {
        "address": lg.get("address", "").lower(),
        "topics": lg.get("topics", []),
        "data": lg.get("data", "0x"),
        "blockNumber": _to_hex(lg.get("blockNumber")),
        "blockTimestamp": _to_hex(lg.get("timeStamp")) if lg.get("timeStamp") else None,
        "transactionHash": lg.get("transactionHash", "").lower(),
        "logIndex": _to_hex(lg.get("logIndex", "0x0")),
    }
