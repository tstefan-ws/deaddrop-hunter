from nonevm_fakes import FakeTransport, load

from deaddrop_hunter.nonevm import collect, solana

ADDR = "BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC"
CFG = {"type": "solana", "api": "https://api.mainnet-beta.solana.com"}
WALLETS = [{"chain": "solana", "address": ADDR, "label": "GlassWorm"}]


def _routes(sigs=None):
    sigs = sigs if sigs is not None else load("sol_sigs.json")
    tx = load("sol_tx.json")
    first_sig = load("sol_sigs.json")["result"][0]["signature"]

    def get_tx(m, u, b):
        if b["params"][0] == first_sig:
            return 200, tx
        return 200, {"jsonrpc": "2.0", "id": 1, "result": None}

    return [
        (lambda m, u, b: b and b["method"] == "getSignaturesForAddress", (200, sigs)),
        (lambda m, u, b: b and b["method"] == "getTransaction", get_tx),
    ]


def test_memo_extraction_and_decoding(fake_sleep):
    t = FakeTransport(_routes())
    events, cursor = collect("solana", CFG, WALLETS, None, transport=t, sleep=fake_sleep)
    methods = [c["payload"]["method"] for c in t.calls]
    assert methods == ["getSignaturesForAddress"] + ["getTransaction"] * 3
    gt = t.calls[1]["payload"]["params"][1]
    assert gt["encoding"] == "jsonParsed" and gt["maxSupportedTransactionVersion"] == 0
    assert len(events) == 3
    e = events[0]
    assert e["tx_hash"] == load("sol_sigs.json")["result"][0]["signature"]
    assert e["new_raw"] == '{"link":"aHR0cDovLzEzNy4xODQuMTk4LjkxL2NyQ2ZtaDQ5MjJ5UHdqYg=="}'
    assert e["new_decoded"] == '{"link":"http://137.184.198.91/crCfmh4922yPwjb"}'
    assert e["decoder"] == "base64"
    assert e["from"] == "5m49aU7pMecF7WWHi2n2aL7UaAjVCn2mYBnTVMUpHNMQ"  # fee payer from getTransaction
    assert e["contract"] == ADDR and e["hunt_id"] == f"watch:{ADDR}"
    assert e["block"] == load("sol_sigs.json")["result"][0]["slot"]
    # tx details unavailable -> memo from getSignaturesForAddress with "[len] " prefix stripped
    assert events[1]["from"] is None
    assert events[1]["new_raw"] == '{"link":"SSBrbm93IHlvdQ=="}'
    assert events[1]["new_decoded"] == '{"link":"I know you"}'
    assert cursor["accounts"][ADDR]["last_signature"] == e["tx_hash"]


def test_incremental_until_and_no_new(fake_sleep):
    t = FakeTransport(_routes({"jsonrpc": "2.0", "id": 1, "result": []}))
    since = {"accounts": {ADDR: {"last_signature": "SIG0", "last_slot": 1}}}
    events, cursor = collect("solana", CFG, WALLETS, since, transport=t, sleep=fake_sleep)
    assert t.calls[0]["payload"]["params"][1]["until"] == "SIG0"
    assert events == []
    assert cursor["accounts"][ADDR]["last_signature"] == "SIG0"


def test_pagination_with_before(fake_sleep, monkeypatch):
    monkeypatch.setattr(solana, "PAGE_LIMIT", 2)
    pages = {
        None: [{"signature": "S3", "slot": 3, "blockTime": 3, "memo": None},
               {"signature": "S2", "slot": 2, "blockTime": 2, "memo": "[4] test"}],
        "S2": [{"signature": "S1", "slot": 1, "blockTime": 1, "memo": None}],
    }

    def sigs(m, u, b):
        return 200, {"jsonrpc": "2.0", "id": 1, "result": pages[b["params"][1].get("before")]}

    t = FakeTransport([(lambda m, u, b: b["method"] == "getSignaturesForAddress", sigs)])
    events, cursor = collect("solana", dict(CFG, max_txs_per_address=3, fetch_transactions=False),
                             WALLETS, None, transport=t, sleep=fake_sleep)
    assert [c["payload"]["params"][1].get("before") for c in t.calls] == [None, "S2"]
    assert t.calls[0]["payload"]["params"][1]["limit"] == 2
    assert t.calls[1]["payload"]["params"][1]["limit"] == 1
    assert [e["tx_hash"] for e in events] == ["S2"]  # only the tx carrying a memo
    assert events[0]["new_decoded"] == "test" and events[0]["decoder"] == "memo"
    assert cursor["accounts"][ADDR]["last_signature"] == "S3"


def test_env_override_rpc(monkeypatch, fake_sleep):
    monkeypatch.setenv("DDH_RPC_SOLANA", "https://rpc.example.invalid/?api-key=x")
    t = FakeTransport(_routes({"jsonrpc": "2.0", "id": 1, "result": []}))
    collect("solana", CFG, WALLETS, None, transport=t, sleep=fake_sleep)
    assert t.calls[0]["url"] == "https://rpc.example.invalid/?api-key=x"


def test_memos_from_inner_instructions():
    tx = {"transaction": {"message": {"accountKeys": [{"pubkey": "P"}], "instructions": []}},
          "meta": {"innerInstructions": [{"index": 0, "instructions": [
              {"programId": "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVaJwQjqMRbo", "parsed": "inner memo"},
              {"programId": "11111111111111111111111111111111", "parsed": {"type": "transfer"}}]}]}}
    assert solana.memos_from_transaction(tx) == ["inner memo"]
    assert solana.fee_payer(tx) == "P"
