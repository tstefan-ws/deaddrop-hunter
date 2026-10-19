import json

import pytest

from deaddrop_hunter.config import Chain, RpcEndpoint
from deaddrop_hunter.rpc import NoSweepEndpoint, RpcClient, RpcError


class FakeNode:
    """Fake JSON-RPC transport. Refuses getLogs ranges wider than ``limit`` blocks per URL."""

    def __init__(self, limits: dict[str, int], logs_at: dict[int, list] | None = None, down: set | None = None):
        self.limits = limits
        self.logs_at = logs_at or {}
        self.down = down or set()
        self.calls: list[tuple[str, str, list]] = []

    def __call__(self, method, url, body, headers, timeout):
        req = json.loads(body)
        self.calls.append((url, req["method"], req["params"]))
        if url in self.down:
            return 503, b"service unavailable"
        if req["method"] == "eth_getLogs":
            f = req["params"][0]
            lo, hi = int(f["fromBlock"], 16), int(f["toBlock"], 16)
            if hi - lo + 1 > self.limits[url]:
                return 200, json.dumps({"jsonrpc": "2.0", "id": req["id"], "error": {
                    "code": -32005, "message": "query exceeds max block range"}}).encode()
            res = [lg for b, lgs in self.logs_at.items() if lo <= b <= hi for lg in lgs]
            return 200, json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": res}).encode()
        if req["method"] == "eth_getBlockByNumber":
            n = int(req["params"][0], 16)
            return 200, json.dumps({"jsonrpc": "2.0", "id": req["id"],
                                    "result": {"timestamp": hex(1_700_000_000 + n)}}).encode()
        if req["method"] == "eth_blockNumber":
            return 200, json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": "0x64"}).encode()
        return 200, json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": None}).encode()


def _chain(*eps):
    return Chain(key="test", chain_id=1, block_time_s=1, rpcs=tuple(RpcEndpoint(u, s) for u, s in eps))


def test_span_halving_on_range_error():
    node = FakeNode({"a": 3000}, logs_at={5: [{"blockNumber": "0x5"}], 9999: [{"blockNumber": "0x270f"}]})
    rpc = RpcClient(_chain(("a", 10000)), transport=node, sleep=lambda s: None)
    logs = rpc.get_logs_sweep("0x" + "11" * 32, 0, 9999)
    assert len(logs) == 2
    spans = [int(p[0]["toBlock"], 16) - int(p[0]["fromBlock"], 16) + 1
             for _u, m, p in node.calls if m == "eth_getLogs"]
    assert spans[:3] == [10000, 5000, 2500]  # halved twice, then accepted
    ok_ranges = [(int(p[0]["fromBlock"], 16), int(p[0]["toBlock"], 16))
                 for _u, m, p in node.calls if m == "eth_getLogs"
                 and int(p[0]["toBlock"], 16) - int(p[0]["fromBlock"], 16) + 1 <= 3000]
    assert ok_ranges[0][0] == 0 and ok_ranges[-1][1] == 9999
    covered = sum(b - a + 1 for a, b in ok_ranges)
    assert covered == 10000  # contiguous, no gaps or overlaps


def test_fallback_to_next_endpoint_and_skip_span_zero():
    node = FakeNode({"bad": 10**9, "good": 10**9, "nosweep": 10**9}, down={"bad"})
    rpc = RpcClient(_chain(("nosweep", 0), ("bad", 1000), ("good", 500)), transport=node, sleep=lambda s: None)
    rpc.get_logs_sweep("0x" + "11" * 32, 0, 999)
    urls = [u for u, m, _p in node.calls if m == "eth_getLogs"]
    assert "nosweep" not in urls
    assert urls.count("bad") == 3  # retried, then fell back
    assert urls.count("good") == 2  # 1000 blocks at span 500


def test_no_sweep_endpoint():
    rpc = RpcClient(_chain(("x", 0)), transport=FakeNode({"x": 1}))
    with pytest.raises(NoSweepEndpoint):
        rpc.get_logs_sweep("0x" + "11" * 32, 0, 10)


def test_block_timestamp_cache():
    node = FakeNode({"a": 1})
    rpc = RpcClient(_chain(("a", 1)), transport=node)
    assert rpc.block_timestamp(7) == rpc.block_timestamp(7) == 1_700_000_007
    assert sum(1 for _u, m, _p in node.calls if m == "eth_getBlockByNumber") == 1


def test_refuses_write_methods():
    rpc = RpcClient(_chain(("a", 1)), transport=FakeNode({"a": 1}))
    with pytest.raises(ValueError):
        rpc.call("eth_sendRawTransaction", ["0x00"])


def test_error_surfaces_after_all_endpoints_fail():
    node = FakeNode({"a": 1}, down={"a"})
    rpc = RpcClient(_chain(("a", 1)), transport=node, sleep=lambda s: None)
    with pytest.raises(RpcError):
        rpc.block_number()
