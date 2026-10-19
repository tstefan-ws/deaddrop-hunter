import json
import sys
import types

from deaddrop_hunter.cli import main
from deaddrop_hunter.collectors.wallet_watch import tx_events
from deaddrop_hunter.config import load_config, parse_config
from deaddrop_hunter.hunt import make_context, plan_ranges, run_hunt
from deaddrop_hunter.keccak import selector as keccak_selector
from deaddrop_hunter.providers import ProviderUnavailable
from deaddrop_hunter.rpc import RpcClient

from .fixtures_util import load_fixture

TOPIC = "0xee986145c636aca5c6c0b4ce0e9d371e77ab30b3e28fe5c3a8d977f05fc8cf24"
# MetaMask's verified public DelegationManager on Polygon: shared infrastructure, not a dead drop.
DELEGATION_MANAGER = "0xdb9b1e94b5b69df7e401ddbede43491141047db3"
OPS = {
    "0x774e03243db1b1c7c972b7f5a9f21b7be23e00a719582b5afdf8b1dea062c53d": "0x19532c0fbaf0fb8c1d0f3fac0b704bf2f4645539",
    "0x08233ee528890aec38ef97810e7074d5ebe1b87c72995fd8758c652231bcd53f": "0xde275ad38c3352a7cb6b0d3efcbf45900c9716f2",
}


class Chainsim:
    def __init__(self, head: int):
        self.head = head
        self.logs = load_fixture("polygon_dataupdated_logs.json")
        self.ranges: list[tuple[int, int]] = []

    def __call__(self, method, url, body, headers, timeout):
        req = json.loads(body)
        m, p = req["method"], req["params"]
        if m == "eth_blockNumber":
            res = hex(self.head)
        elif m == "eth_getLogs":
            lo, hi = int(p[0]["fromBlock"], 16), int(p[0]["toBlock"], 16)
            self.ranges.append((lo, hi))
            res = [lg for lg in self.logs if lo <= int(lg["blockNumber"], 16) <= hi]
        elif m == "eth_getBlockByNumber":
            res = {"timestamp": hex(1_760_000_000 + int(p[0], 16) - 95_000_000)}
        elif m == "eth_getTransactionByHash":
            res = {"from": OPS[p[0]], "input": "0x68446ead" + "00" * 32}
        else:
            res = None
        return 200, json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": res}).encode()


def _cfg():
    return parse_config({
        "settings": {"default_lookback_days": 90},
        "chains": {
            "polygon": {"chain_id": 137, "block_time_s": 2.0,
                        "rpcs": [{"url": "https://fake.invalid", "max_log_span": 400000}]},
            "bsc": {"chain_id": 56, "rpcs": [{"url": "https://bsc.invalid", "max_log_span": 0}],
                    "indexed_provider": "dune", "dune_chain": "bnb"},
            "tron": {"type": "tron", "api": "https://tron.invalid"},
        },
        "hunts": [{"id": "dataupdated-string-string", "kind": "event", "signature": "DataUpdated(string,string)",
                   "abi": ["string", "string"], "chains": ["polygon", "bsc"]}],
        "watch_wallets": [{"chain": "polygon", "address": "0x19532c0fbaf0fb8c1d0f3fac0b704bf2f4645539",
                           "label": "Op"}],
    }, env={})


def _ctx(cfg, sim):
    def no_key(*_a):
        raise ProviderUnavailable("no key (test)")

    return make_context(cfg, rpc_factory=lambda c: RpcClient(c, transport=sim, sleep=lambda s: None),
                        etherscan_factory=no_key, dune_factory=no_key)


def test_plan_ranges():
    assert plan_ranges(None, 100, 10, False) == [(10, 100)]
    cur = {"from_block": 50, "to_block": 80}
    assert plan_ranges(cur, 100, 10, False) == [(81, 100)]
    assert plan_ranges(cur, 100, 10, True) == [(10, 49), (81, 100)]
    assert plan_ranges(cur, 80, 60, True) == []


def test_hunt_incremental_no_duplicates(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "deaddrop_hunter.nonevm", None)  # import fails -> skip
    cfg = _cfg()
    head = 95_900_000
    sim = Chainsim(head)
    rep = run_hunt(cfg, tmp_path, ctx=_ctx(cfg, sim), now="2026-10-19T12:00:00Z")
    assert rep.added == 2
    assert any(s.startswith("bsc/dataupdated") for s in rep.skipped)
    assert any(s.startswith("polygon/watch-wallet") for s in rep.skipped)
    assert any(s.startswith("tron/nonevm") for s in rep.skipped)
    meta = json.loads((tmp_path / "meta.json").read_text())
    (cur,) = meta["cursors"]
    assert cur["chain"] == "polygon" and cur["to_block"] == head - 5
    events = json.loads((tmp_path / "events.json").read_text())
    assert len(events) == 2
    assert {e["from"] for e in events} == set(OPS.values())
    assert all(e["selector"] == "0x68446ead" for e in events)

    sim2 = Chainsim(head + 1000)
    rep2 = run_hunt(cfg, tmp_path, ctx=_ctx(cfg, sim2), now="2026-10-19T13:00:00Z")
    assert rep2.added == 0
    assert sim2.ranges == [(head - 5 + 1, head + 1000 - 5)]
    assert len(json.loads((tmp_path / "events.json").read_text())) == 2


def test_nonevm_delegation(tmp_path, monkeypatch):
    seen = {}

    def collect(chain_key, chain_cfg, watch_wallets, since):
        seen.update(chain_key=chain_key, api=chain_cfg.get("api"), since=since)
        ev = {"chain": "tron", "block": 7, "timestamp": "2026-10-10T00:00:00Z", "tx_hash": "ab" * 32,
              "contract": "TXYZopqrsTUVWxyz1234567890abcdefgh", "from": "TOperatorAAAAAAAAAAAAAAAAAAAAAAAAA",
              "selector": None, "hunt_id": "memo-sweep", "old_raw": None, "new_raw": "http://8.8.8.8",
              "old_decoded": None, "new_decoded": "http://8.8.8.8", "decoder": "plain"}
        return [ev], {"from_block": 1, "to_block": 7}

    monkeypatch.setitem(sys.modules, "deaddrop_hunter.nonevm", types.SimpleNamespace(collect=collect))
    cfg = _cfg()
    rep = run_hunt(cfg, tmp_path, chains=["tron"], ctx=_ctx(cfg, Chainsim(1)), now="2026-10-19T12:00:00Z")
    assert rep.added == 1
    assert seen == {"chain_key": "tron", "api": "https://tron.invalid", "since": None}
    meta = json.loads((tmp_path / "meta.json").read_text())
    assert meta["cursors"] == [{"chain": "tron", "hunt_id": "nonevm", "from_block": 1, "to_block": 7,
                                "updated_at": "2026-10-19T12:00:00Z"}]
    contracts = json.loads((tmp_path / "contracts.json").read_text())
    assert contracts[0]["address"] == "TXYZopqrsTUVWxyz1234567890abcdefgh"


def test_env_rpc_override():
    cfg = parse_config({"chains": {"bsc": {"chain_id": 56, "rpcs": [{"url": "https://pub", "max_log_span": 0}],
                                           "indexed_provider": "dune"}}},
                       env={"DDH_RPC_BSC": "https://a/key|50000, https://b"})
    rpcs = cfg.chains["bsc"].rpcs
    assert [(r.url, r.max_log_span) for r in rpcs] == [("https://a/key", 50000), ("https://b", 0), ("https://pub", 0)]
    assert [r.url for r in cfg.chains["bsc"].sweep_rpcs] == ["https://a/key"]


def test_rebuild_and_export_cli(tmp_path, monkeypatch, capsys):
    (tmp_path / "events.json").write_text(json.dumps(load_fixture("events_sample.json")))
    cfgp = tmp_path / "hunts.toml"
    cfgp.write_text('[chains.polygon]\nchain_id = 137\nrpcs = []\n')
    assert main(["rebuild", "--config", str(cfgp), "--data", str(tmp_path)]) == 0
    first = (tmp_path / "contracts.json").read_bytes()
    assert main(["rebuild", "--config", str(cfgp), "--data", str(tmp_path)]) == 0
    assert (tmp_path / "contracts.json").read_bytes() == first
    assert main(["read", "polygon", "0x1823a9a0ec8e0c25dd957d0841e3d41a4474badc", "--data", str(tmp_path)]) == 0
    assert "http://" in capsys.readouterr().out

    monkeypatch.setitem(sys.modules, "deaddrop_hunter.exporters", None)
    assert main(["export", "--data", str(tmp_path), "--out", str(tmp_path / "feeds")]) == 2


def test_delegation_manager_is_not_a_dead_drop():
    """A watched operator calling MetaMask's DelegationManager must not create a candidate
    contract: three unrelated Polygon operators use it, and union-find would merge their
    clusters into one false cluster."""
    assert keccak_selector("redeemDelegations(bytes[],bytes32[],bytes[])") == "0xcef6d209"
    chain = _cfg().chains["polygon"]
    wallet = "0x19532c0fbaf0fb8c1d0f3fac0b704bf2f4645539"
    tx = {"blockNumber": "95800000", "timeStamp": "1760000000", "hash": "0x" + "ab" * 32,
          "from": wallet, "to": DELEGATION_MANAGER, "input": "0xcef6d209" + "00" * 64,
          "isError": "0", "contractAddress": ""}

    (candidate,) = tx_events(chain, wallet, tx, known=set())
    assert candidate["contract"] == DELEGATION_MANAGER
    assert candidate["selector"] == "0xcef6d209"

    assert tx_events(chain, wallet, tx, known=set(), ignored={DELEGATION_MANAGER}) == []


def test_shipped_config_ignores_delegation_manager():
    cfg = load_config("config/hunts.toml", env={})
    assert ("polygon", DELEGATION_MANAGER) in cfg.ignore_contracts
    # 0xcef6d209 is redeemDelegations, so a chain-wide sweep for it flags legitimate users.
    assert not [h for h in cfg.hunts if h.id == "selector-cef6d209"]
    assert not [h for h in cfg.hunts if h.selector == "0xcef6d209"]


def test_a_newly_watched_wallet_is_read_from_its_first_transaction():
    """The chain-wide cursor cannot say whether *this* wallet was scanned, so a wallet added
    today would otherwise never have its earlier activity fetched: the cursor already claims
    those blocks on behalf of the wallets that were there before."""
    from deaddrop_hunter.collectors import wallet_watch
    from deaddrop_hunter.config import WatchWallet

    calls = []

    class FakeEs:
        def txlist(self, address, from_block, to_block):
            calls.append((address, from_block, to_block))
            return []

    cfg = _cfg()
    ctx = make_context(cfg, rpc_factory=lambda c: None, etherscan_factory=lambda c: FakeEs(),
                       dune_factory=lambda: None)
    chain = cfg.chains["polygon"]
    old = WatchWallet(chain="polygon", address="0x" + "11" * 20, label="known")
    new = WatchWallet(chain="polygon", address="0x" + "22" * 20, label="just added")
    seen = {old.address: 1_000}

    wallet_watch.collect(ctx, chain, [old, new], 5_000, 6_000, seen)
    by_addr = {a: (lo, hi) for a, lo, hi in calls}
    assert by_addr[old.address] == (1_000, 6_000)   # continues from where it got to
    assert by_addr[new.address] == (0, 6_000)       # read from the beginning, once
    assert seen[new.address] == 0                   # and not read from zero again next time
