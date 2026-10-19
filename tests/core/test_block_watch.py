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
