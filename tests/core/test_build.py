import copy

from deaddrop_hunter.build import UnionFind, build, cluster_id_for, order_contract_events
from deaddrop_hunter.config import parse_config
from deaddrop_hunter.store import dumps

from .fixtures_util import load_fixture

NOW = "2026-10-19T12:00:00Z"

CFG = parse_config({
    "chains": {"polygon": {"chain_id": 137, "rpcs": []}},
    "watch_wallets": [
        {"chain": "polygon", "address": "0x19532C0FBAF0FB8C1D0F3FAC0B704BF2F4645539", "label": "Op A"},
        {"chain": "polygon", "address": "0x0000000000000000000000000000000000000abc", "label": "Idle"},
    ],
}, env={})


def _ev(contract, sender, block, ts, new, old=None, tx=None):
    return {
        "chain": "polygon", "block": block, "timestamp": ts,
        "tx_hash": tx or "0x" + f"{block:064x}", "contract": contract, "from": sender,
        "selector": "0xcef6d209", "hunt_id": "h", "old_raw": old, "new_raw": new,
        "old_decoded": old, "new_decoded": new, "decoder": "plain",
    }


A, B, C = "0x" + "a" * 40, "0x" + "b" * 40, "0x" + "c" * 40
W1, W2, W3 = "0x" + "9" * 40, "0x" + "1" * 40, "0x" + "5" * 40


def test_union_find_and_cluster_ids():
    uf = UnionFind()
    uf.union("x", "y")
    uf.union("y", "z")
    assert uf.find("x") == uf.find("z")
    ops = ["0xde275ad38c3352a7cb6b0d3efcbf45900c9716f2", "0x19532c0fbaf0fb8c1d0f3fac0b704bf2f4645539"]
    assert cluster_id_for(ops) == "c-19532c0f"
    assert cluster_id_for(["TXYZopqrsTUVWxyz1234567890abcdefgh"]) == "c-txyzopqr"
    assert cluster_id_for(["0x" + "AB" * 32]) == "c-abababab"


def test_clustering_by_shared_operator():
    events = [
        _ev(A, W1, 10, "2026-10-01T00:00:00Z", "http://203.0.113.9/a"),
        _ev(B, W1, 11, "2026-10-02T00:00:00Z", "http://evil-one.xyz"),
        _ev(B, W2, 12, "2026-10-03T00:00:00Z", "http://evil-two.xyz"),  # W2 joins via B
        _ev(C, W3, 13, "2026-08-01T00:00:00Z", "http://evil-three.xyz"),
        _ev("0x" + "d" * 40, None, 14, "2026-10-04T00:00:00Z", "zzz"),  # no operator -> unclustered
    ]
    out = build(events, CFG, now=NOW)
    cl = {c["address"]: c["cluster_id"] for c in out["contracts"]}
    assert cl[A] == cl[B] == "c-11111111"  # lowest operator of {W1, W2}
    assert cl[C] == "c-55555555"
    assert cl["0x" + "d" * 40] is None
    clusters = {c["id"]: c for c in out["clusters"]}
    assert set(clusters) == {"c-11111111", "c-55555555"}
    assert clusters["c-11111111"]["wallets"] == [W2, W1]
    assert clusters["c-11111111"]["family"] == "c2-url"
    status = {c["address"]: c["status"] for c in out["contracts"]}
    assert status[C] == "dormant" and status[A] == "active"


def test_latest_value_follows_same_block_chain():
    e1 = _ev(A, W1, 10, "t", "v2", old="v1", tx="0x02")
    e2 = _ev(A, W1, 10, "t", "v3", old="v2", tx="0x01")
    assert [e["new_raw"] for e in order_contract_events([e2, e1])] == ["v2", "v3"]


def test_real_sample_build_and_determinism():
    events = load_fixture("events_sample.json")
    out1 = build(copy.deepcopy(events), CFG, cursors=[], now=NOW)
    out2 = build(list(reversed(copy.deepcopy(events))), CFG, cursors=[], now=NOW)
    for k in out1:
        assert dumps(out1[k]) == dumps(out2[k]), k
    contracts = {c["address"]: c for c in out1["contracts"]}
    xm = contracts["0x2fbd66fe245052d265ca0eda7d01d35b2d8b9feb"]
    assert xm["cluster_id"] == "c-19532c0f"
    assert xm["family"] == "xmrig-stealth"
    assert xm["decoder"] == "xor-1byte:0x5a"
    assert contracts["0x1823a9a0ec8e0c25dd957d0841e3d41a4474badc"]["family"] == "c2-url"
    wallets = {(w["chain"], w["address"]): w for w in out1["wallets"]}
    op = wallets[("polygon", "0x19532c0fbaf0fb8c1d0f3fac0b704bf2f4645539")]
    assert op["watched"] is True and op["label"] == "Op A" and op["role"] == "operator"
    assert wallets[("polygon", "0x" + "0" * 37 + "abc")]["tx_count"] == 0
    iocs = {(i["type"], i["value"], i["port"]) for i in out1["iocs"]}
    assert ("ipv4", "78.40.198.61", 31270) in iocs
    assert ("evm-contract", "0x2fbd66fe245052d265ca0eda7d01d35b2d8b9feb", None) in iocs
    assert not any(v.lower().endswith(".exe") for _t, v, _p in iocs)
    # events newest first, keys in schema order
    ts = [e["timestamp"] for e in out1["events"]]
    assert ts == sorted(ts, reverse=True)
    assert list(out1["events"][0]) == ["chain", "block", "timestamp", "tx_hash", "contract", "from", "selector",
                                       "hunt_id", "old_raw", "new_raw", "old_decoded", "new_decoded", "decoder"]
    assert out1["meta"]["counts"]["events"] == len(events)


def test_enrichment_preserved():
    events = [_ev(A, W1, 10, "2026-10-01T00:00:00Z", "http://8.8.4.4/a")]
    prev = [{"type": "ipv4", "value": "8.8.4.4", "port": None, "enrichment": {"virustotal": {"m": 3}}}]
    out = build(events, CFG, now=NOW, existing_iocs=prev)
    ioc = next(i for i in out["iocs"] if i["value"] == "8.8.4.4")
    assert ioc["enrichment"] == {"virustotal": {"m": 3}}
    assert ioc["current"] is True


def test_nonevm_addresses_not_lowercased_or_evm_typed():
    tron = "TXYZopqrsTUVWxyz1234567890abcdefgh"
    ev = _ev(tron, "TOperatorAAAAAAAAAAAAAAAAAAAAAAAAA", 5, "2026-10-01T00:00:00Z", "http://8.8.8.8")
    ev["chain"] = "tron"
    ev["tx_hash"] = "ab" * 32
    out = build([ev], CFG, now=NOW)
    assert out["contracts"][0]["address"] == tron
    assert out["contracts"][0]["cluster_id"] == "c-toperato"
    assert not any(i["type"].startswith("evm-") for i in out["iocs"])


def test_candidate_contract_scores_below_a_decoded_one():
    """A contract a watched operator merely called, with nothing ever decoded from it, is a
    candidate: reported, but never at the confidence of a decoded dead drop."""
    from deaddrop_hunter.build import CANDIDATE_CONF, build
    from deaddrop_hunter.config import parse_config

    cfg = parse_config({"chains": {"polygon": {"chain_id": 137, "rpcs": []}}})
    op = "0x19532c0fbaf0fb8c1d0f3fac0b704bf2f4645539"
    decoded_c = "0x2fbd66fe245052d265ca0eda7d01d35b2d8b9feb"
    candidate_c = "0xa9c28c5b780c2bc1dd49ddb3ffbdc580a5e6f6e6"
    ev = [
        {"chain": "polygon", "block": 95621219, "timestamp": "2026-10-16T07:52:45Z",
         "tx_hash": "0x" + "11" * 32, "contract": decoded_c, "from": op, "selector": "0x68446ead",
         "hunt_id": "dataupdated-string-string", "old_raw": None, "new_raw": "0x00",
         "old_decoded": None, "new_decoded": "http://185.10.68.110", "decoder": "plain"},
        {"chain": "polygon", "block": 95621300, "timestamp": "2026-10-16T08:00:00Z",
         "tx_hash": "0x" + "22" * 32, "contract": candidate_c, "from": op, "selector": "0xabcdef01",
         "hunt_id": "watch-wallet", "old_raw": None, "new_raw": None,
         "old_decoded": None, "new_decoded": None, "decoder": "undecoded"},
    ]
    out = build(ev, cfg, [], now="2026-10-19T12:00:00Z")
    by_addr = {c["address"]: c for c in out["contracts"]}
    assert by_addr[decoded_c]["evidence"] == "decoded"
    assert by_addr[candidate_c]["evidence"] == "candidate"

    conf = {(i["type"], i["value"]): i["confidence"] for i in out["iocs"]}
    assert conf[("evm-contract", decoded_c)] == 90
    assert conf[("evm-contract", candidate_c)] == CANDIDATE_CONF
