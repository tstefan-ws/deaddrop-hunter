from nonevm_fakes import FakeTransport, load

from deaddrop_hunter.nonevm import aptos, collect

ADDR = "0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3"
API = "https://fullnode.mainnet.aptoslabs.com/v1"
ARCHIVE = "https://archive.mainnet.aptoslabs.com/v1"
CFG = {"type": "aptos", "api": API}
WALLETS = [{"chain": "aptos", "address": ADDR, "label": "XCTDH"}]

CUSTOM_RESOURCE = {"type": f"{ADDR}::cfg::Config", "data": {
    "url": "0x" + b"http://198.51.100.20/c2".hex(), "version": "3", "owner": ADDR, "note": "hello world"}}


def _routes(primary_txs, archive_txs=None, resources=None):
    resources = resources if resources is not None else load("aptos_resources.json")
    return [
        (lambda m, u, b: u.startswith(f"{API}/accounts/{ADDR}/transactions"), primary_txs),
        (lambda m, u, b: u.startswith(f"{ARCHIVE}/accounts/{ADDR}/transactions"), (200, archive_txs or [])),
        (lambda m, u, b: u == f"{API}/accounts/{ADDR}/resources", (200, resources)),
        (lambda m, u, b: u == f"{API}/accounts/{ADDR}", (200, load("aptos_account.json"))),
        (lambda m, u, b: u == f"{API}/", (200, load("aptos_ledger.json"))),
    ]


def test_pruned_history_falls_back_to_archive(fake_sleep):
    t = FakeTransport(_routes((200, []), load("aptos_txs_archive.json")))
    events, cursor = collect("aptos", dict(CFG, max_txs_per_address=3), WALLETS, None,
                             transport=t, sleep=fake_sleep)
    urls = [c["url"] for c in t.calls]
    assert f"{API}/accounts/{ADDR}/transactions?start=7&limit=3" in urls
    assert f"{ARCHIVE}/accounts/{ADDR}/transactions?start=7&limit=3" in urls
    assert len(events) == 3
    e = events[0]
    assert e["new_decoded"] == "0x622bcfd4538f7e68772a1d5a08a48f9f8db82b2ca1babc8d45dba538c6a10e2e"
    assert e["decoder"] == "plain"
    assert e["from"] == ADDR and e["contract"] == ADDR and e["hunt_id"] == f"watch:{ADDR}"
    assert isinstance(e["block"], int) and e["tx_hash"].startswith("0x") and len(e["tx_hash"]) == 66
    assert cursor["accounts"][ADDR]["next_seq"] == 10


def test_version_pruned_error_uses_archival_endpoint_hint(fake_sleep):
    err = {"error_code": "version_pruned", "message": "pruned", "archival_endpoint": ARCHIVE}
    t = FakeTransport(_routes((410, err), load("aptos_txs_archive.json")))
    events, _ = collect("aptos", dict(CFG, max_txs_per_address=3), WALLETS, None, transport=t, sleep=fake_sleep)
    assert len(events) == 3


def test_incremental_nothing_new(fake_sleep):
    t = FakeTransport(_routes((200, [])))
    since = {"accounts": {ADDR: {"next_seq": 10, "resource_digests": {}}}}
    events, cursor = collect("aptos", CFG, WALLETS, since, transport=t, sleep=fake_sleep)
    assert not any("/transactions" in c["url"] for c in t.calls)
    assert events == []
    assert cursor["accounts"][ADDR]["next_seq"] == 10


def test_resource_strings_emitted_once(fake_sleep):
    res = load("aptos_resources.json") + [CUSTOM_RESOURCE]
    cfg = dict(CFG)
    since = {"accounts": {ADDR: {"next_seq": 10}}}
    t = FakeTransport(_routes((200, []), resources=res))
    events, cursor = collect("aptos", cfg, WALLETS, since, transport=t, sleep=fake_sleep)
    assert len(events) == 1
    e = events[0]
    assert e["hunt_id"] == f"watch:{ADDR}:resource"
    assert e["block"] == int(load("aptos_ledger.json")["ledger_version"])
    assert e["tx_hash"] is None
    assert "url=http://198.51.100.20/c2" in e["new_decoded"]
    assert "note=hello world" in e["new_decoded"]
    assert "owner" not in e["new_decoded"]  # plain address field skipped
    # unchanged on the next run -> not emitted again
    t2 = FakeTransport(_routes((200, []), resources=res))
    events2, _ = collect("aptos", cfg, WALLETS, cursor, transport=t2, sleep=fake_sleep)
    assert events2 == []


def test_argument_decoding():
    ef = "entry_function_payload"
    assert aptos.argument_data({"type": ef, "function": "0xabc::m::set",
                                "arguments": ["0x" + b"https://c2.invalid/x".hex(), "5"]}) == [
        ("0x" + b"https://c2.invalid/x".hex(), "https://c2.invalid/x", "hex-utf8")]
    assert aptos.argument_data({"type": ef, "function": "0xabc::m::set",
                                "arguments": [["plain text config"]]}) == [
        ("plain text config", "plain text config", "plain")]
    # normal value transfer: no hidden data
    assert aptos.argument_data({"type": ef, "function": "0x1::aptos_account::transfer",
                                "arguments": [ADDR, "100000"]}) == []
    # zero-value transfer: recipient is the pointer (leading zero restored)
    short = "0x4280a7b37c7b014fc83cf8ccea13070b50166148ab78e2fcb48d258d2e0ddc7"
    out = aptos.argument_data({"type": ef, "function": "0x1::aptos_account::transfer", "arguments": [short, "0"]})
    assert out == [(short, "0x0" + short[2:], "plain")]
    # non-entry payloads (scripts) are ignored
    assert aptos.argument_data({"type": "script_payload", "arguments": ["x"]}) == []


def test_unknown_account_is_skipped(fake_sleep):
    t = FakeTransport([(lambda m, u, b: True, (404, {"error_code": "account_not_found"}))])
    events, cursor = collect("aptos", CFG, WALLETS, None, transport=t, sleep=fake_sleep, log=lambda m: None)
    assert events == [] and ADDR not in cursor["accounts"]
