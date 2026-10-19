"""Minimal HTTP transport over urllib (stdlib only).

A *transport* is any callable ``(method, url, body: bytes | None, headers: dict, timeout) -> (status, bytes)``.
Tests inject fake transports so no network is touched.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from collections.abc import Callable

from . import USER_AGENT

Transport = Callable[[str, str, "bytes | None", dict, float], "tuple[int, bytes]"]


class HttpError(Exception):
    def __init__(self, status: int, body: bytes = b"", msg: str = ""):
        super().__init__(msg or f"HTTP {status}")
        self.status = status
        self.body = body


def urllib_transport(method: str, url: str, body: bytes | None, headers: dict, timeout: float) -> tuple[int, bytes]:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed API hosts only
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b""


class RateLimiter:
    """Simple minimum-interval limiter (e.g. 5 req/s -> 0.2 s)."""

    def __init__(self, per_second: float, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.interval = 1.0 / per_second if per_second > 0 else 0.0
        self._last = 0.0
        self._clock = clock
        self._sleep = sleep

    def wait(self) -> None:
        now = self._clock()
        delta = self._last + self.interval - now
        if delta > 0:
            self._sleep(delta)
            now = self._clock()
        self._last = now
