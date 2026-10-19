import urllib.parse

from nonevm_fakes import FakeTransport, load

from deaddrop_hunter.nonevm import collect, tron
from deaddrop_hunter.nonevm.common import tron_address_valid, tron_hex_to_base58

ADDR = "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP"
CFG = {"type": "tron", "api": "https://api.trongrid.io"}
WALLETS = [{"chain": "tron", "address": ADDR, "label": "XCTDH"}]


def _q(url):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))


def _routes():
    p1, p2 = load("tron_page1.json"), load("tron_page2.json")
    return [
        (lambda m, u, b: "fingerprint=" in u, (200, p2)),
        (lambda m, u, b: "/transactions" in u, (200, p1)),
    ]


def test_address_conversion():
    assert tron_hex_to_base58("41803f5d3cc635e5ac3c96c86a6cbe98c9eda82e66") == ADDR
    assert tron_address_valid(ADDR)
    assert not tron_address_valid("TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAQ")


def test_pagination_with_fingerprint_and_cap(fake_sleep):
    t = FakeTransport(_routes())
    events, cursor = collect("tron", dict(CFG, max_txs_per_address=4), WALLETS, None,
                             transport=t, sleep=fake_sleep)
    urls = [c["url"] for c in t.calls]
    assert len(urls) == 2
    assert _q(urls[0])["only_from"] == "true"
    assert _q(urls[1])["fingerprint"] == load("tron_page1.json")["meta"]["fingerprint"]
    assert len(events) == 4  # cap reached even though page 2 has another fingerprint
    e = events[0]
    assert e["tx_hash"] == "baf0056505fac2561c4693d61b2ac48b9abdf269a6143ea3354ee5faa659cdab"
    assert e["new_decoded"] == "0x18a8420f727f2405f9d1805ad887b31029b584b2ff5a7ec0f57c72635183e99d"
    assert e["decoder"] == "hex-utf8+reverse"
    assert e["from"] == ADDR and e["contract"] == ADDR
    assert e["hunt_id"] == f"watch:{ADDR}" and e["selector"] is None
    assert e["block"] == 83837539 and e["timestamp"] == "2026-06-23T02:35:45Z"
    assert cursor["accounts"][ADDR]["last_timestamp"] == 1782182145000
    # newest first
    assert [x["timestamp"] for x in events] == sorted([x["timestamp"] for x in events], reverse=True)


def test_incremental_cursor_uses_min_timestamp_and_skips_seen(fake_sleep):
    p1 = load("tron_page1.json")
    newest = p1["data"][0]
    page = {"data": [newest], "success": True, "meta": {"page_size": 1}}
    t = FakeTransport([(lambda m, u, b: True, (200, page))])
    since = {"accounts": {ADDR: {"last_timestamp": newest["block_timestamp"], "last_txs": [newest["txID"]]}}}
    events, cursor = collect("tron", CFG, WALLETS, since, transport=t, sleep=fake_sleep)
    assert _q(t.calls[0]["url"])["min_timestamp"] == str(newest["block_timestamp"])
    assert events == []
    assert cursor["accounts"][ADDR]["last_timestamp"] == newest["block_timestamp"]


def test_api_key_header(monkeypatch, fake_sleep):
    monkeypatch.setenv("TRONGRID_API_KEY", "test-key")
    t = FakeTransport([(lambda m, u, b: True, (200, {"data": [], "meta": {}}))])
    collect("tron", CFG, WALLETS, None, transport=t, sleep=fake_sleep)
    assert t.calls[0]["headers"]["TRON-PRO-API-KEY"] == "test-key"
    assert t.calls[0]["method"] == "GET"


def _abi_string_call(selector: str, text: str) -> str:
    b = text.encode()
    pad = b + b"\0" * (-len(b) % 32)
    return selector + (32).to_bytes(32, "big").hex() + len(b).to_bytes(32, "big").hex() + pad.hex()


def _trigger_tx(data_hex: str, memo: str | None = None):
    raw = {"contract": [{"type": "TriggerSmartContract", "parameter": {"value": {
        "owner_address": "41803f5d3cc635e5ac3c96c86a6cbe98c9eda82e66",
        "contract_address": "41a614f803b6fd780986a42c78ec9c7f77e6ded13c",
        "data": data_hex}}}], "timestamp": 1782182139000}
    if memo:
        raw["data"] = memo
    return {"txID": "ab" * 32, "blockNumber": 1, "block_timestamp": 1782182145000, "raw_data": raw}


def test_trigger_smart_contract_abi_string():
    data = _abi_string_call("5d4ed4b7", "http://198.51.100.7/gate.php")
    evs = tron.tx_events("tron", _trigger_tx(data), ADDR)
    assert len(evs) == 1
    e = evs[0]
    assert e["selector"] == "0x5d4ed4b7"
    assert e["contract"] == "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # 41a614... = USDT contract
    assert e["new_decoded"] == "http://198.51.100.7/gate.php"
    assert e["decoder"] == "hex-utf8"
    assert e["from"] == ADDR


def test_trigger_plain_token_transfer_is_ignored():
    data = "a9059cbb" + "00" * 12 + "803f5d3cc635e5ac3c96c86a6cbe98c9eda82e66" + (10**6).to_bytes(32, "big").hex()
    assert tron.tx_events("tron", _trigger_tx(data), ADDR) == []


def test_memo_and_trigger_both_emitted():
    data = _abi_string_call("5d4ed4b7", "config-value-1")
    evs = tron.tx_events("tron", _trigger_tx(data, memo="4d787920637573746f6d206d656d6f2074657874"), ADDR)
    assert [e["decoder"] for e in evs] == ["hex-utf8", "hex-utf8"]
    assert evs[0]["contract"] == ADDR and evs[0]["new_decoded"] == "Mxy custom memo text"


def test_plain_transfer_without_data_is_ignored():
    tx = load("tron_page1.json")["data"][0]
    tx = {**tx, "raw_data": {k: v for k, v in tx["raw_data"].items() if k != "data"}}
    assert tron.tx_events("tron", tx, ADDR) == []
