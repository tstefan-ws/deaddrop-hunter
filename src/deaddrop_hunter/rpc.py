"""Read-only JSON-RPC client with retries, endpoint fallback and span-halving log sweeps."""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
from collections.abc import Callable, Sequence

from .config import Chain, RpcEndpoint
from .http import Transport, urllib_transport

log = logging.getLogger(__name__)

# Hard allow-list: this tool never signs or sends anything.
READ_ONLY_METHODS = frozenset({
    "eth_blockNumber",
    "eth_getLogs",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getBlockByNumber",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_call",
    "eth_chainId",
})

_RANGE_ERR = re.compile(
    r"range|too large|too many|limit|exceed|more than \d+|10000 results|response size|query timeout"
    r"|block range|max results|returned more|timeout",
    re.I,
)
MIN_SPAN = 500


class RpcError(Exception):
    def __init__(self, message: str, code: int | None = None, endpoint: str = ""):
        super().__init__(message)
        self.code = code
        self.endpoint = endpoint


class RangeTooLarge(RpcError):
    pass


class NoSweepEndpoint(RpcError):
    pass


def is_range_error(message: str, code: int | None = None) -> bool:
    if code in (-32005, -32602) and _RANGE_ERR.search(message or ""):
        return True
    return bool(_RANGE_ERR.search(message or ""))


class RpcClient:
    def __init__(
        self,
        chain: Chain,
        transport: Transport = urllib_transport,
        timeout: float = 60.0,
        retries: int = 3,
        backoff: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.chain = chain
        self.transport = transport
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.sleep = sleep
        self._id = 0
        self._block_ts: dict[int, int] = {}

    # -- low level ---------------------------------------------------------------------------
    def call_endpoint(self, ep: RpcEndpoint, method: str, params: list):
        if method not in READ_ONLY_METHODS:
            raise ValueError(f"refusing non read-only RPC method {method!r}")
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        last_exc: Exception | None = None
        for attempt in range(self.retries):
            if attempt:
                self.sleep(self.backoff * (2 ** (attempt - 1)))
            try:
                status, raw = self.transport("POST", ep.url, body, {"Content-Type": "application/json"},
                                             self.timeout)
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                last_exc = RpcError(f"transport error: {e}", endpoint=ep.url)
                if method == "eth_getLogs" and "timed out" in str(e):
                    # A timeout on a big log query is usually the range; let the caller halve.
                    raise RangeTooLarge(f"timeout: {e}", endpoint=ep.url) from e
                continue
            if status == 429 or status >= 500:
                text = raw[:300].decode("utf-8", "replace")
                if status != 429 and method == "eth_getLogs" and is_range_error(text):
                    raise RangeTooLarge(text, endpoint=ep.url)
                last_exc = RpcError(f"HTTP {status}: {text}", endpoint=ep.url)
                continue
            try:
                payload = json.loads(raw)
            except ValueError:
                last_exc = RpcError(f"HTTP {status}: invalid JSON", endpoint=ep.url)
                continue
            if status >= 400 and not isinstance(payload, dict):
                last_exc = RpcError(f"HTTP {status}", endpoint=ep.url)
                continue
            err = payload.get("error") if isinstance(payload, dict) else None
            if err:
                msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                code = err.get("code") if isinstance(err, dict) else None
                if isinstance(err, dict) and err.get("data"):
                    msg = f"{msg} {err.get('data')}"
                if code in (-32029, 429) or re.search(r"rate.?limit|too many requests", msg, re.I):
                    last_exc = RpcError(msg, code, ep.url)
                    continue
                if method == "eth_getLogs" and is_range_error(msg, code):
                    raise RangeTooLarge(msg, code, ep.url)
                raise RpcError(msg, code, ep.url)
            if status >= 400:
                last_exc = RpcError(f"HTTP {status}", endpoint=ep.url)
                continue
            return payload.get("result")
        assert last_exc is not None
        raise last_exc

    def call(self, method: str, params: list, endpoints: Sequence[RpcEndpoint] | None = None):
        """Call with fallback across the chain's endpoints (in config order)."""
        eps = list(endpoints if endpoints is not None else self.chain.rpcs)
        if not eps:
            raise RpcError(f"{self.chain.key}: no RPC endpoints configured")
        last: Exception | None = None
        for ep in eps:
            try:
                return self.call_endpoint(ep, method, params)
            except RpcError as e:
                log.warning("%s %s via %s failed: %s", self.chain.key, method, ep.url, e)
                last = e
        assert last is not None
        raise last

    # -- helpers -----------------------------------------------------------------------------
    def block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def get_block(self, number: int) -> dict | None:
        return self.call("eth_getBlockByNumber", [hex(number), False])

    def block_timestamp(self, number: int) -> int | None:
        if number in self._block_ts:
            return self._block_ts[number]
        blk = self.get_block(number)
        if not blk:
            return None
        ts = int(blk["timestamp"], 16)
        self._block_ts[number] = ts
        return ts

    def remember_timestamp(self, number: int, ts: int) -> None:
        self._block_ts[number] = ts

    def get_transaction(self, tx_hash: str) -> dict | None:
        return self.call("eth_getTransactionByHash", [tx_hash])

    def eth_call(self, to: str, data: str, block: str = "latest") -> str:
        return self.call("eth_call", [{"to": to, "data": data}, block])

    def get_code(self, address: str) -> str:
        return self.call("eth_getCode", [address, "latest"])

    def get_storage_at(self, address: str, slot: int | str, block: str = "latest",
                       endpoints: Sequence[RpcEndpoint] | None = None) -> str:
        """Read one storage slot. Contract storage is public even when no function exposes
        it, which is how a dead drop with no reader still gives up its value."""
        key = slot if isinstance(slot, str) else hex(slot)
        return self.call("eth_getStorageAt", [address, key, block], endpoints=endpoints)

    def get_logs_sweep(
        self,
        topic0: str,
        from_block: int,
        to_block: int,
        address: str | None = None,
        on_chunk: Callable[[int, int, int], None] | None = None,
    ) -> list[dict]:
        """Topic-only (or address-filtered) eth_getLogs over a block range.

        The range is split by each endpoint's ``max_log_span``; when an endpoint answers with a
        "range too large"/"limit" style error the span is halved and the chunk retried. When the
        span drops below ``MIN_SPAN`` or the endpoint fails otherwise, the next endpoint (with
        max_log_span > 0) takes over for the remainder of the range.
        """
        eps = list(self.chain.sweep_rpcs)
        if not eps:
            raise NoSweepEndpoint(f"{self.chain.key}: no RPC endpoint supports topic-only sweeps")
        out: list[dict] = []
        idx = 0
        span = eps[0].max_log_span
        cur = from_block
        while cur <= to_block:
            ep = eps[idx]
            span = max(1, min(span, ep.max_log_span))
            end = min(to_block, cur + span - 1)
            flt: dict = {"fromBlock": hex(cur), "toBlock": hex(end), "topics": [topic0]}
            if address:
                flt["address"] = address
            try:
                logs = self.call_endpoint(ep, "eth_getLogs", [flt]) or []
            except RangeTooLarge as e:
                if span > MIN_SPAN:
                    span = span // 2
                    log.info("%s: %s range too large (%s); halving span to %d", self.chain.key, ep.url,
                             str(e)[:80], span)
                    continue
                idx += 1
                if idx >= len(eps):
                    raise
                span = eps[idx].max_log_span
                continue
            except RpcError as e:
                log.warning("%s: getLogs via %s failed (%s); trying next endpoint", self.chain.key, ep.url, e)
                idx += 1
                if idx >= len(eps):
                    raise
                span = eps[idx].max_log_span
                continue
            for lg in logs:
                ts = lg.get("blockTimestamp")
                if ts and lg.get("blockNumber"):
                    try:
                        self.remember_timestamp(int(lg["blockNumber"], 16), int(ts, 16))
                    except (TypeError, ValueError):
                        pass
            out.extend(logs)
            if on_chunk:
                on_chunk(cur, end, len(logs))
            cur = end + 1
        return out
