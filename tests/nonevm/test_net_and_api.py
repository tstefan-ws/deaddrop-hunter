import re

import pytest
from nonevm_fakes import FakeTransport, load

from deaddrop_hunter.nonevm import collect
from deaddrop_hunter.nonevm.net import ApiError, Client

SCHEMA_KEYS = ["chain", "block", "timestamp", "tx_hash", "contract", "from", "selector", "hunt_id",
               "old_raw", "new_raw", "old_decoded", "new_decoded", "decoder"]


class Seq:
    def __init__(self, responses):
        self.responses = list(responses)

    def __call__(self, m, u, b):
        return self.responses.pop(0)


def test_backoff_on_429_then_success(fake_sleep):
    t = FakeTransport([(lambda m, u, b: True, Seq([(429, b"slow down"), (429, b""), (200, {"ok": 1})]))])
    c = Client(per_second=0, transport=t, sleep=fake_sleep, backoff_base=1.0)
    assert c.get("https://api.example.invalid/x") == {"ok": 1}
    assert fake_sleep.calls == [1.0, 2.0]
    assert c.retries == 2 and len(t.calls) == 3


def test_tron_frequency_403_is_retried(fake_sleep):
    t = FakeTransport([(lambda m, u, b: True, Seq([(403, b'{"Error":"exceed the frequency limit"}'),
                                                     (200, {"ok": 1})]))])
    c = Client(per_second=0, transport=t, sleep=fake_sleep, backoff_base=1.0)
    assert c.get("https://api.trongrid.io/x") == {"ok": 1}


def test_gives_up_after_max_retries(fake_sleep):
    t = FakeTransport([(lambda m, u, b: True, (429, b"no"))])
    c = Client(per_second=0, transport=t, sleep=fake_sleep, max_retries=2, backoff_base=1.0)
    with pytest.raises(ApiError) as ei:
        c.get("https://api.example.invalid/x")
    assert ei.value.status == 429 and len(t.calls) == 3


def test_jsonrpc_rate_limit_error_is_retried(fake_sleep):
    t = FakeTransport([(lambda m, u, b: True, Seq([
        (200, {"jsonrpc": "2.0", "id": 1, "error": {"code": 429, "message": "Too many requests"}}),
        (200, {"jsonrpc": "2.0", "id": 1, "result": [1]})]))])
    c = Client(per_second=0, transport=t, sleep=fake_sleep, backoff_base=0.5)
    assert c.rpc("https://rpc.example.invalid", "getSlot", []) == [1]
    assert fake_sleep.calls == [0.5]


def test_throttle_interval(fake_sleep):
    clock = iter([0.0, 0.1, 0.5]).__next__
    t = FakeTransport([(lambda m, u, b: True, (200, {}))])
    c = Client(per_second=2, transport=t, sleep=fake_sleep, clock=clock)
    c.get("https://x.invalid/1")
    c.get("https://x.invalid/2")
    assert fake_sleep.calls == [pytest.approx(0.4)]


def test_collect_end_to_end_schema_and_identifiers(fake_sleep):
    p1 = load("tron_page1.json")
    p1 = {**p1, "meta": {}}
    t = FakeTransport([(lambda m, u, b: True, (200, p1))])
    events, cursor = collect("tron", {"type": "tron", "api": "https://api.trongrid.io"},
                             [{"chain": "tron", "address": "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP", "label": "x"},
                              {"chain": "solana", "address": "ignored", "label": "other chain"}],
                             None, transport=t, sleep=fake_sleep)
    assert len(t.calls) == 1
    assert events and "updated_at" in cursor
    for e in events:
        assert list(e) == SCHEMA_KEYS
        assert re.match(r"^T[1-9A-HJ-NP-Za-km-z]{33}$", e["contract"])
        assert re.match(r"^[0-9a-f]{64}$", e["tx_hash"])
        assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", e["timestamp"])
        assert e["old_raw"] is None and e["old_decoded"] is None


def test_unsupported_type():
    with pytest.raises(ValueError):
        collect("near", {"type": "near"}, [], None)
