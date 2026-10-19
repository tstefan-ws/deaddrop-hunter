"""Read-only HTTP client for the non-EVM collectors (stdlib only).

A *transport* is any callable ``(method, url, body: bytes | None, headers: dict, timeout) -> (status, bytes)``
so tests can inject recorded responses. Only GET and read-only JSON-RPC POSTs are ever issued.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable

USER_AGENT = "deaddrop-hunter/0.1 (+threat-hunting; read-only)"

Transport = Callable[[str, str, "bytes | None", dict, float], "tuple[int, bytes]"]

RETRY_STATUSES = {429, 500, 502, 503, 504}


class ApiError(Exception):
    def __init__(self, status: int, body: bytes = b"", url: str = ""):
        snippet = body[:300].decode("utf-8", "replace") if body else ""
        super().__init__(f"HTTP {status} from {url}: {snippet}")
        self.status = status
        self.body = body
        self.url = url

    def json(self):
        try:
            return json.loads(self.body)
        except ValueError:
            return None


def urllib_transport(method: str, url: str, body: bytes | None, headers: dict, timeout: float) -> tuple[int, bytes]:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - configured API hosts only
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, (e.read() if e.fp else b"")


class Client:
    """Throttled JSON client with exponential backoff on 429/5xx (and TronGrid 403 'frequency' limits)."""

    def __init__(self, per_second: float = 2.0, transport: Transport | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                 headers: dict | None = None, max_retries: int = 5, backoff_base: float = 2.0,
                 timeout: float = 30.0):
        self.interval = 1.0 / per_second if per_second > 0 else 0.0
        self.transport = transport or urllib_transport
        self.sleep = sleep
        self.clock = clock
        self.headers = dict(headers or {})
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.timeout = timeout
        self._last = None
        self.requests = 0
        self.retries = 0

    def _throttle(self) -> None:
        if self._last is not None and self.interval:
            delta = self._last + self.interval - self.clock()
            if delta > 0:
                self.sleep(delta)
        self._last = self.clock()

    @staticmethod
    def _retryable(status: int, body: bytes) -> bool:
        if status in RETRY_STATUSES:
            return True
        # TronGrid answers 403 with "exceed the frequency limit" when throttling keyless callers
        return status == 403 and b"frequency" in body.lower()

    def request(self, method: str, url: str, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        headers = dict(self.headers)
        if body is not None:
            headers["Content-Type"] = "application/json"
        attempt = 0
        while True:
            self._throttle()
            self.requests += 1
            status, data = self.transport(method, url, body, headers, self.timeout)
            if 200 <= status < 300:
                try:
                    return json.loads(data or b"null")
                except ValueError as e:
                    raise ApiError(status, data, url) from e
            if self._retryable(status, data) and attempt < self.max_retries:
                self.retries += 1
                self.sleep(self.backoff_base * (2 ** attempt))
                attempt += 1
                continue
            raise ApiError(status, data, url)

    def get(self, url: str):
        return self.request("GET", url)

    def rpc(self, url: str, method: str, params: list):
        """JSON-RPC call (read-only methods only). Retries JSON-RPC level rate-limit errors too."""
        attempt = 0
        while True:
            resp = self.request("POST", url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            err = resp.get("error") if isinstance(resp, dict) else None
            if not err:
                return resp.get("result") if isinstance(resp, dict) else None
            code = err.get("code") if isinstance(err, dict) else None
            msg = str(err.get("message", "")) if isinstance(err, dict) else str(err)
            if (code == 429 or "rate" in msg.lower() or "too many" in msg.lower()) and attempt < self.max_retries:
                self.retries += 1
                self.sleep(self.backoff_base * (2 ** attempt))
                attempt += 1
                continue
            raise ApiError(200, json.dumps(err).encode(), f"{url} {method}")
