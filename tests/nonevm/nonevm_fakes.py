"""Fakes and recorded fixtures for the non-EVM collector tests. No network: a fake transport serves recorded responses.

Recorded 2026-10-19 (read-only) from api.trongrid.io, api.mainnet-beta.solana.com and
fullnode/archive.mainnet.aptoslabs.com for publicly reported dead-drop accounts
(see the non-EVM [[watch_wallets]] in config/hunts.toml).
Aptos tx fixtures had their bulky ``changes``/``events`` emptied.
"""

from __future__ import annotations

import json
from pathlib import Path

FIX = Path(__file__).parent / "fixtures"


def load(name: str):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


class FakeTransport:
    """Routes requests to handlers. ``routes`` = list of (predicate(method, url, body_json), response)
    where response is (status, obj|bytes) or a callable returning that. First match wins."""

    def __init__(self, routes):
        self.routes = routes
        self.calls: list[dict] = []

    def __call__(self, method, url, body, headers, timeout):
        payload = json.loads(body) if body else None
        self.calls.append({"method": method, "url": url, "payload": payload, "headers": dict(headers)})
        for pred, resp in self.routes:
            if pred(method, url, payload):
                if callable(resp):
                    resp = resp(method, url, payload)
                status, obj = resp
                data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
                return status, data
        raise AssertionError(f"unexpected request {method} {url} {payload}")


class FakeSleep:
    def __init__(self):
        self.calls: list[float] = []

    def __call__(self, s):
        self.calls.append(s)
