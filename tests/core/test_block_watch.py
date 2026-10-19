"""Birth watch: recognising a dead drop from its code alone, before anyone reports it."""

import json

from deaddrop_hunter.bytecode import (
    code_hash,
    created_address,
    probe_selectors,
    selectors,
    shape_of,
    strip_metadata,
)
from deaddrop_hunter.collectors import block_watch
from deaddrop_hunter.config import parse_config
from deaddrop_hunter.hunt import make_context
from deaddrop_hunter.providers import ProviderUnavailable
from deaddrop_hunter.rpc import RpcClient

GET_URL = "38bcdc1c"      # getURL()
SET_URL = "77343408"      # setURL(string)
ADMIN = "f851a440"        # admin()
ADMIN_OWNER = "8da5cb5b"  # owner()
TRANSFER = "a9059cbb"     # transfer(address,uint256)

DEPLOYER = "0x34c15320d6e8f59f1b66f6c191aaa7f87b894b66"
CREATION_TX = "0x" + "11" * 32


def _code(*sels: str, size: int = 600) -> str:
    """Runtime code whose dispatcher compares against `sels`, padded to `size` bytes."""
    body = "".join("63" + s for s in sels)
    pad = "00" * max(0, size - len(body) // 2)
    return "0x" + body + pad


def _abi_string(text: str) -> str:
    raw = text.encode()
    pad = (32 - len(raw) % 32) % 32
    return ("0x" + (32).to_bytes(32, "big").hex() + len(raw).to_bytes(32, "big").hex()
            + raw.hex() + "00" * pad)


# ---------------------------------------------------------------------------------------
# bytecode primitives
# ---------------------------------------------------------------------------------------

def test_created_address_matches_a_real_deployment():
    """Verified against Polygon: this deployer at nonce 270 really did land on this
    address, so we can name every contract a wallet made without an explorer."""
    assert created_address(DEPLOYER, 270) == "0x4af8048edfe4523953e9907528bf5cef7fa8db09"
    assert created_address(DEPLOYER, 0).startswith("0x")
    assert created_address(DEPLOYER, 127) != created_address(DEPLOYER, 128)   # RLP boundary


def test_selectors_and_metadata_stripping():
    code = _code(GET_URL, ADMIN)
    assert selectors(code) == ("0x38bcdc1c", "0xf851a440")
    # Two builds of one source differing only in trailing metadata share a blueprint hash.
    meta = "a2646970667358221220" + "ab" * 20
    tail = meta + f"{len(bytes.fromhex(meta)):04x}"
    assert code_hash(code + tail) == code_hash(code)
    assert len(strip_metadata(code + tail)) == len(strip_metadata(code))


def test_shape_filter_keeps_drops_and_drops_ordinary_contracts():
    drop = shape_of(_code(GET_URL, SET_URL, ADMIN))
    assert drop.known_family and drop.dead_drop_like
    assert probe_selectors(drop)[0] == "0x38bcdc1c"      # known reader tried first

    generic = shape_of(_code(ADMIN, "12345678"))
    assert not generic.known_family and generic.dead_drop_like   # worth one call, no verdict

    token = shape_of(_code(TRANSFER, "70a08231", "18160ddd"))
    assert not token.dead_drop_like                       # no owner accessor

    # Reported as a false positive on BSC: a small owned contract that moves value. A dead
    # drop stores a string for anyone to read; it does not transfer anything.
    owned_token = shape_of(_code(ADMIN_OWNER, TRANSFER, "23b872dd", "fc0c546a"))
    assert owned_token.token_like and not owned_token.dead_drop_like

    big = shape_of(_code(ADMIN, size=9000))
    assert not big.dead_drop_like                         # routers and proxies are large

    assert not shape_of("0x").dead_drop_like              # a plain account, not a contract


# ---------------------------------------------------------------------------------------
# the collector
# ---------------------------------------------------------------------------------------

class FakeChain:
    """One block holding one creation, plus code and an answer for the new contract."""

    def __init__(self, code: str, answer: str | None):
        self.code = code
        self.answer = answer
        self.calls = []

    def __call__(self, method, url, body, headers, timeout):
        req = json.loads(body)
        m = req["method"]
        self.calls.append(m)
        if m == "eth_getBlockByNumber":
            res = {
                "timestamp": hex(1_792_000_000),
                "transactions": [
                    {"hash": CREATION_TX, "from": DEPLOYER, "to": None, "nonce": hex(270)},
                    {"hash": "0x" + "22" * 32, "from": DEPLOYER, "to": "0x" + "33" * 20,
                     "nonce": hex(271)},        # an ordinary call: must be ignored
                ],
            }
        elif m == "eth_getCode":
            res = self.code
        elif m == "eth_call":
            if self.answer is None:
                return 200, json.dumps({"jsonrpc": "2.0", "id": req["id"],
                                        "error": {"code": -32000, "message": "execution reverted"}}).encode()
            res = self.answer
        else:
            res = None
        return 200, json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": res}).encode()


def _ctx(sim):
    cfg = parse_config({"chains": {"polygon": {"chain_id": 137, "block_time_s": 2.0,
                                               "rpcs": [{"url": "https://fake.invalid"}]}}}, env={})

    def no_key(*_a):
        raise ProviderUnavailable("no key (test)")

    ctx = make_context(cfg, rpc_factory=lambda c: RpcClient(c, transport=sim, sleep=lambda s: None),
                       etherscan_factory=no_key, dune_factory=no_key)
    return ctx, cfg.chains["polygon"]


def test_a_new_contract_that_answers_becomes_a_finding():
    sim = FakeChain(_code(GET_URL, SET_URL, ADMIN), _abi_string("http://198.51.100.7/gate.php"))
    ctx, chain = _ctx(sim)
    (ev,) = block_watch.collect(ctx, chain, 100, 100)
    assert ev["contract"] == "0x4af8048edfe4523953e9907528bf5cef7fa8db09"
    assert ev["hunt_id"] == "block-watch"
    assert ev["from"] == DEPLOYER
    assert ev["selector"] == "0x38bcdc1c"
    assert ev["new_decoded"] == "http://198.51.100.7/gate.php"
    assert ev["timestamp"] == "2026-10-14T17:46:40Z"


def test_a_silent_contract_of_the_right_shape_is_only_a_candidate():
    sim = FakeChain(_code(ADMIN, "0badf00d"), None)
    ctx, chain = _ctx(sim)
    (ev,) = block_watch.collect(ctx, chain, 100, 100)
    assert ev["new_decoded"] is None and ev["new_raw"] is None
    assert ev["selector"] is None          # nothing answered; build() scores it as a candidate


def test_an_ordinary_contract_is_ignored_without_any_call():
    sim = FakeChain(_code(TRANSFER, "70a08231"), _abi_string("should never be read"))
    ctx, chain = _ctx(sim)
    assert block_watch.collect(ctx, chain, 100, 100) == []
    assert "eth_call" not in sim.calls     # the shape filter runs before any probing


# ---------------------------------------------------------------------------------------
# the action scan: any wallet on the chain, not only the ones we watch
# ---------------------------------------------------------------------------------------

def _call_input(selector_hex: str, text: str) -> str:
    raw = text.encode()
    pad = (32 - len(raw) % 32) % 32
    return ("0x" + selector_hex + (32).to_bytes(32, "big").hex()
            + len(raw).to_bytes(32, "big").hex() + raw.hex() + "00" * pad)


STRANGER = "0x" + "ab" * 20
DROP = "0x" + "cd" * 20


def _tx(selector_hex: str, text: str) -> dict:
    return {"hash": "0x" + "44" * 32, "from": STRANGER, "to": DROP, "nonce": "0x1",
            "input": _call_input(selector_hex, text)}


def test_a_known_setter_from_an_unknown_wallet_is_caught():
    chain = _ctx(FakeChain("0x", None))[1]
    ev = block_watch.call_event(chain, _tx(SET_URL, "https://evil.example/c2.php"), block=7, ts=None)
    assert ev["contract"] == DROP and ev["from"] == STRANGER      # nobody we had on file
    assert ev["selector"] == "0x77343408"
    assert ev["new_decoded"] == "https://evil.example/c2.php"


def test_a_renamed_setter_is_caught_when_the_text_carries_an_indicator():
    """The operator in tonight's find had renamed their functions, so matching known
    selectors alone is not enough: what the call writes is the signal."""
    chain = _ctx(FakeChain("0x", None))[1]
    ev = block_watch.call_event(chain, _tx("deadbeef", "stratum+tcp://203.0.113.9:3333"), block=7, ts=None)
    assert ev is not None and ev["selector"] == "0xdeadbeef"


def test_ordinary_text_writes_are_ignored():
    chain = _ctx(FakeChain("0x", None))[1]
    assert block_watch.call_event(chain, _tx("deadbeef", "Digital Pay"), block=7, ts=None) is None
    assert block_watch.call_event(chain, _tx("deadbeef", "ipfs metadata v2"), block=7, ts=None) is None


def test_ignored_contracts_are_skipped():
    chain = _ctx(FakeChain("0x", None))[1]
    tx = _tx(SET_URL, "https://evil.example/c2.php")
    assert block_watch.call_event(chain, tx, block=7, ts=None, ignored={DROP}) is None


# ---------------------------------------------------------------------------------------
# noise found on the first live run, each kept as a regression
# ---------------------------------------------------------------------------------------

def test_token_metadata_is_never_probed():
    """name() answered "Digital Pay" on the first live run: readable, true, and useless."""
    from deaddrop_hunter.bytecode import NEVER_PROBE

    s = shape_of(_code(ADMIN, "06fdde03", "95d89b41", "0badf00d"))
    assert set(probe_selectors(s)).isdisjoint(NEVER_PROBE)
    assert "0x0badf00d" in probe_selectors(s)


def test_calldata_that_merely_contains_an_address_is_not_a_finding():
    """Almost any calldata decodes to something holding an EVM address; a multicall and two
    ordinary setters got in that way before the network-indicator rule."""
    chain = _ctx(FakeChain("0x", None))[1]
    assert block_watch.call_event(
        chain, _tx("ac9650d8", "0x06388a99aafbd5efd02c282cc51a80df8242e723"), block=7, ts=None) is None


def test_a_bare_storage_gateway_link_is_not_a_finding():
    """NFT metadata lives on IPFS gateways by the million. Dual-use, so not a lead on its own."""
    chain = _ctx(FakeChain("0x", None))[1]
    assert block_watch.call_event(
        chain, _tx("a2119377", "https://ipfs.filebase.io/ipfs/QmWXU35vsTmzxyrT3nbe7T3nAoYQ"),
        block=7, ts=None) is None


def test_prose_with_a_link_in_it_is_not_a_finding():
    """A prediction market wrote an 810-character question containing a link. Dead drops
    store pointers and configs: median confirmed value is 25 characters."""
    chain = _ctx(FakeChain("0x", None))[1]
    prose = ("q: title: Bitcoin Up or Down - October 20 description: This market will resolve "
             "according to https://example-oracle.test/feed and other sources. " + "detail. " * 40)
    assert len(prose) > 256
    assert block_watch.call_event(chain, _tx("f4fa9d4a", prose), block=7, ts=None) is None


def test_a_long_json_config_is_still_a_finding():
    """The mining family stores JSON that runs to thousands of characters."""
    chain = _ctx(FakeChain("0x", None))[1]
    cfg = '{"algo":"rx/0","pool":"45.141.233.19:3333","pass":"x","note":"' + "y" * 300 + '"}'
    ev = block_watch.call_event(chain, _tx("deadbeef", cfg), block=7, ts=None)
    assert ev is not None and "45.141.233.19" in ev["new_decoded"]


# ---------------------------------------------------------------------------------------
# values that no reader exposes: storage slots and code-as-data
# ---------------------------------------------------------------------------------------

def _slot_word(text: str) -> str:
    raw = text.encode()
    assert len(raw) <= 31
    return "0x" + (raw + b"\x00" * (31 - len(raw)) + bytes([len(raw) * 2])).hex()


class StorageChain(FakeChain):
    """A contract that exposes no working reader but keeps a string in slot 2."""

    def __init__(self, code: str, slot_values: dict[int, str]):
        super().__init__(code, None)
        self.slots = slot_values

    def __call__(self, method, url, body, headers, timeout):
        import json as _json
        req = _json.loads(body)
        if req["method"] == "eth_getStorageAt":
            slot = int(req["params"][1], 16)
            res = self.slots.get(slot, "0x" + "00" * 32)
            return 200, _json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": res}).encode()
        return super().__call__(method, url, body, headers, timeout)


def test_storage_gives_up_a_value_no_function_exposes():
    """Seven of our ten silent candidates turned out to be holding their value here."""
    sim = StorageChain(_code(ADMIN, "0badf00d"), {2: _slot_word("http://198.51.100.4/x")})
    ctx, chain = _ctx(sim)
    assert block_watch.read_storage_text(ctx, chain, "0x" + "ee" * 20) == b"http://198.51.100.4/x"

    (ev,) = block_watch.collect(ctx, chain, 100, 100)
    assert ev["new_decoded"] == "http://198.51.100.4/x"
    assert ev["selector"] is None          # nothing answered; the value came from storage


def test_a_contract_whose_code_is_the_payload():
    """Storing the text as the contract's own code is cheaper to read than storage."""
    payload = "0x00" + b"http://203.0.113.11/beacon".hex()
    sim = FakeChain(payload, None)
    ctx, chain = _ctx(sim)
    (ev,) = block_watch.collect(ctx, chain, 100, 100)
    assert ev["new_decoded"] == "http://203.0.113.11/beacon"


def test_probe_events_do_not_claim_a_transaction():
    """A value read from storage has no transaction behind it, and must not invent one."""
    from deaddrop_hunter.exporters._common import Dataset

    sim = StorageChain(_code(ADMIN, "0badf00d"), {0: _slot_word("http://198.51.100.4/x")})
    ctx, chain = _ctx(sim)
    ev = block_watch.probe_contract(ctx, chain, "0x" + "ee" * 20, now="2026-10-19T21:00:00Z")
    assert ev["tx_hash"].startswith("probe:")
    ds = Dataset(meta={}, contracts=[], wallets=[], events=[], iocs=[], clusters=[],
                 explorers={"polygon": "https://polygonscan.com"})
    assert ds.explorer_tx_url("polygon", ev["tx_hash"]) is None


def test_a_new_contract_holding_a_plain_label_is_not_recorded():
    """The watcher's first live hour turned up a contract holding "Steve Garrison" and two
    holding decentralised-network node registrations. Readable text with nothing to act on
    is not a lead, so it is dropped rather than filed as a candidate."""
    sim = StorageChain(_code(ADMIN, "0badf00d"), {0: _slot_word("Steve Garrison")})
    ctx, chain = _ctx(sim)
    assert block_watch.collect(ctx, chain, 100, 100) == []


def test_an_opaque_value_is_still_kept():
    """An encrypted payload is exactly what we are looking for, so anything that will not
    decode to text stays, as 0xa9c28c5b's 520 bytes of binary did."""
    sim = StorageChain(_code(ADMIN, "0badf00d"), {0: "0x" + "9f" * 31 + hex(31 * 2)[2:].rjust(2, "0")})
    ctx, chain = _ctx(sim)
    assert len(block_watch.collect(ctx, chain, 100, 100)) == 1


def test_a_write_to_something_that_is_not_drop_shaped_is_dropped():
    """An AI-agent metadata contract on BSC wrote three metadata links in one cycle. The
    text filters cannot tell those from a rotation; the target's own code can."""
    sim = FakeChain(_code(TRANSFER, "70a08231"), None)      # target is a token, not a drop
    ctx, chain = _ctx(sim)
    blk = {"timestamp": hex(1_792_000_000),
           "transactions": [{"hash": "0x" + "55" * 32, "from": STRANGER, "to": DROP,
                             "nonce": "0x1", "input": _call_input("deadbeef",
                                                                  "https://metadata.example/agents/1061804")}]}
    assert block_watch._from_block(ctx, chain, 7, None, blk) == []


def test_a_known_setter_is_kept_even_if_the_target_says_nothing():
    """A confirmed family stays visible behind a proxy whose own code reveals nothing."""
    sim = FakeChain("0x", None)                              # target has no code at all
    ctx, chain = _ctx(sim)
    blk = {"timestamp": hex(1_792_000_000),
           "transactions": [{"hash": "0x" + "66" * 32, "from": STRANGER, "to": DROP,
                             "nonce": "0x1", "input": _call_input(SET_URL, "https://evil.test/c2")}]}
    (ev,) = block_watch._from_block(ctx, chain, 7, None, blk)
    assert ev["new_decoded"] == "https://evil.test/c2"
