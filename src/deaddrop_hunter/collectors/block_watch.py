"""Block watch: read the chain itself, with no fingerprint and no wallet to start from.

Every other hunt needs something known in advance - an event name, a selector, an operator
wallet, somebody's report. This one needs nothing, and it watches *everyone*: any wallet on
the chain, not only the ones already on our list.

Each block in the range is fetched once, with its transactions, and read two ways.

**Births.** A contract cannot be created without a transaction. The new address is derived
from deployer and nonce (no receipt lookup), the code is fetched once and judged on shape
alone - a confirmed family's selector, or a small contract with an owner accessor (see
bytecode.Shape) - and survivors are asked what they hold with ``eth_call``. A dead drop has
to answer, because the infected machines calling it carry no credentials.

**Actions.** Every transaction that calls a contract is checked against the write side of the
technique: a known setter such as ``setURL(string)``, or - for operators who renamed theirs -
any call whose arguments decode to text that yields an actual indicator. This is the
chain-wide "who is updating a dead drop right now" search that otherwise needs a paid data
warehouse, and it sees unknown wallets, which the wallet watch by definition cannot.

Shape and action only ever produce candidates; a decoded indicator is what makes a finding.
Cost is dominated by the block fetch, so the caller clamps the range (hunts.toml
``max_blocks``) and a run never runs away.
"""

from __future__ import annotations

import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor

from ..bytecode import (
    SETTERS,
    code_as_text,
    created_address,
    long_string_base,
    probe_selectors,
    shape_of,
    slot_long_string_len,
    slot_short_string,
)
from ..classify import extract_iocs, is_dual_use, parse_json
from ..config import Chain
from ..decoders import AbiError, abi_decode, decode_input_strings, is_printable, raw_text
from ..rpc import RpcError
from ..store import iso, make_event
from . import HuntContext

log = logging.getLogger(__name__)

HUNT_ID = "block-watch"
MIN_VALUE_LEN = 4        # shorter answers carry no indicator worth keeping
MAX_VALUE_LEN = 64 * 1024
# A block with its transactions is ~216 KB on Polygon and each request opens its own
# connection, so serially this runs at ~1.3 s per block. Six at a time brings that to the
# ~0.2 s the network actually costs, which is enough to keep up with the chain and catch
# up after a gap, while staying a polite guest on a free public endpoint.
BLOCK_WORKERS = 6
CHUNK = 60
# Storage is public whether or not a function exposes it. Solidity lays contract variables
# out from slot 0, so the first handful of slots is where a small contract keeps its string.
STORAGE_SLOTS = 8
# An update carries a string argument, so the calldata is at least a selector plus three
# words, and a sane upper bound keeps a blob of compiled code from being decoded as text.
MIN_CALL_LEN = 10 + 192
MAX_CALL_LEN = 10 + 2 * MAX_VALUE_LEN
# Indicator types that mean "a victim connects here". An EVM address on its own does not:
# almost any calldata decodes to something containing one, which is how a multicall and two
# ordinary setters ended up in the data on the first live run.
NETWORK_IOCS = ("url", "domain", "ipv4", "ipv6")
# A dead drop stores a pointer or a config, not prose. Confirmed values run to a median of 25
# characters, and the long ones are JSON mining configs. Free text with a link buried in it is
# something else: the first live run at the head caught a prediction market writing an 810
# character question. Long values are still accepted when they parse as JSON.
MAX_PROSE_LEN = 256


def _read_value(ctx: HuntContext, chain: Chain, address: str, sel: str) -> bytes | None:
    """Call one zero-argument selector and return the text it hands back, if any.

    Most probes revert, which is a deterministic answer: asking a second endpoint would
    only repeat it. So probing stays on one endpoint instead of walking the fallback list.
    """
    rpc = ctx.rpc(chain)
    first = rpc.chain.rpcs[:1] or None
    try:
        raw = rpc.call("eth_call", [{"to": address, "data": sel}, "latest"], endpoints=first)
    except RpcError:
        return None                      # reverts, wrong arity, node refusal: just not it
    if not isinstance(raw, str) or len(raw) < 130:
        return None                      # offset + length + content is 2 words minimum
    try:
        (value,) = abi_decode(["string"], raw)
    except (AbiError, ValueError):
        return None
    if isinstance(value, str):
        value = value.encode("utf-8", "replace")
    if not value or not (MIN_VALUE_LEN <= len(value) <= MAX_VALUE_LEN):
        return None
    return value


def _code_text(code: str) -> bytes | None:
    """The payload stored as the contract's own code rather than inside it."""
    text = code_as_text(code)
    return text.encode() if text else None


def read_storage_text(ctx: HuntContext, chain: Chain, address: str,
                      slots: int = STORAGE_SLOTS) -> bytes | None:
    """Read the opening storage slots and return the first readable string.

    A dead drop that exposes no getter still has to keep the value somewhere, and storage is
    public: anyone can read any slot. Short strings sit inline in their slot; longer ones
    keep their length there and their bytes at a hashed location, which we follow.
    """
    rpc = ctx.rpc(chain)
    first = rpc.chain.rpcs[:1] or None
    for slot in range(slots):
        try:
            word = bytes.fromhex((rpc.get_storage_at(address, slot, endpoints=first) or "0x")[2:])
        except (RpcError, ValueError):
            return None                  # endpoint will not serve storage: give up quietly
        if len(word) != 32 or not any(word):
            continue
        short = slot_short_string(word)
        if short and len(short) >= MIN_VALUE_LEN:
            return short.encode()
        length = slot_long_string_len(word)
        if not length:
            continue
        base = long_string_base(slot)
        out = bytearray()
        for i in range((min(length, MAX_VALUE_LEN) + 31) // 32):
            try:
                chunk = rpc.get_storage_at(address, hex(base + i), endpoints=first)
            except RpcError:
                break
            out += bytes.fromhex((chunk or "0x")[2:].rjust(64, "0"))
        text = bytes(out[:length])
        if len(text) >= MIN_VALUE_LEN:
            return text
    return None


def probe_contract(ctx: HuntContext, chain: Chain, address: str, *, hunt_id: str = HUNT_ID,
                   block: int = 0, ts: str | None = None, tx_hash: str | None = None,
                   sender: str | None = None, now: str | None = None) -> dict | None:
    """Ask one contract what it holds: reader first, then storage, then its own code.

    Returns an event, or None when nothing readable is there. Used both on a fresh creation
    and to re-read contracts already on file that have never given up a value.
    """
    try:
        code = ctx.rpc(chain).get_code(address)
    except RpcError as e:
        log.warning("%s: eth_getCode %s failed: %s", chain.key, address, e)
        return None
    shape = shape_of(code)
    if not shape.is_contract:
        return None
    selector = None
    value = None
    for sel in probe_selectors(shape):
        value = _read_value(ctx, chain, address, sel)
        if value is not None:
            selector = sel
            break
    if value is None:
        value = read_storage_text(ctx, chain, address) or _code_text(code)
    if value is None:
        return None
    return make_event(chain=chain.key, block=block, timestamp=ts or now, tx_hash=tx_hash or
                      f"probe:{hashlib.sha256((chain.key + address).encode()).hexdigest()[:16]}",
                      contract=address, sender=sender, selector=selector, hunt_id=hunt_id,
                      old=None, new=value)


def inspect_creation(ctx: HuntContext, chain: Chain, *, block: int, ts: str | None, tx_hash: str,
                     deployer: str, nonce: int) -> dict | None:
    """One creation -> an event, or None when the contract is not drop-shaped."""
    address = created_address(deployer, nonce)
    try:
        code = ctx.rpc(chain).get_code(address)
    except RpcError as e:
        log.warning("%s: eth_getCode %s failed: %s", chain.key, address, e)
        return None
    shape = shape_of(code)
    if not shape.dead_drop_like:
        return None
    for sel in probe_selectors(shape):
        value = _read_value(ctx, chain, address, sel)
        if value is None:
            continue
        log.info("%s: %s answered %s with %d bytes", chain.key, address, sel, len(value))
        return make_event(chain=chain.key, block=block, timestamp=ts, tx_hash=tx_hash,
                          contract=address, sender=deployer, selector=sel, hunt_id=HUNT_ID,
                          old=None, new=value)
    # No reader answered. Two places left where the value can still be sitting in the open.
    value = read_storage_text(ctx, chain, address) or _code_text(code)
    if value is not None:
        log.info("%s: %s gave up %d bytes without a reader", chain.key, address, len(value))
        return make_event(chain=chain.key, block=block, timestamp=ts, tx_hash=tx_hash,
                          contract=address, sender=deployer, selector=None, hunt_id=HUNT_ID,
                          old=None, new=value)
    # Shape matches, nothing readable anywhere: an encrypted payload, or an ordinary owned
    # contract. Recorded as a candidate rather than thrown away.
    log.info("%s: %s matches the shape but answered nothing (code %dB, hash %s)",
             chain.key, address, shape.size, shape.code_hash)
    return make_event(chain=chain.key, block=block, timestamp=ts, tx_hash=tx_hash,
                      contract=address, sender=deployer, selector=None, hunt_id=HUNT_ID,
                      old=None, new=None)


def _blocks(rpc, numbers: list[int]) -> list[tuple[int, dict | None]]:
    """Fetch a chunk of blocks with their transactions, several at a time."""
    def one(n: int) -> tuple[int, dict | None]:
        try:
            return n, rpc.call("eth_getBlockByNumber", [hex(n), True])
        except RpcError as e:
            log.warning("block %d failed: %s", n, e)
            return n, None

    with ThreadPoolExecutor(max_workers=BLOCK_WORKERS) as pool:
        return sorted(pool.map(one, numbers), key=lambda x: x[0])


def collect(ctx: HuntContext, chain: Chain, from_block: int, to_block: int) -> list[dict]:
    rpc = ctx.rpc(chain)
    ignored = {a for c, a in ctx.config.ignore_contracts if c == chain.key}
    out: list[dict] = []
    creations = 0
    numbers = list(range(from_block, to_block + 1))
    chunks = [numbers[i:i + CHUNK] for i in range(0, len(numbers), CHUNK)]
    for chunk in chunks:
        for number, blk in _blocks(rpc, chunk):
            if not blk:
                continue
            ts_int = int(blk["timestamp"], 16)
            rpc.remember_timestamp(number, ts_int)
            ts = iso(ts_int)
            out.extend(_from_block(ctx, chain, number, ts, blk, ignored))
            creations += sum(1 for t in (blk.get("transactions") or []) if not t.get("to"))
    log.info("%s block-watch: blocks %d-%d, %d creations, %d findings",
             chain.key, from_block, to_block, creations, len(out))
    return out


def call_event(chain: Chain, t: dict, *, block: int, ts: str | None,
               ignored: frozenset[str] | set[str] = frozenset()) -> dict | None:
    """A transaction that writes text to a contract, from any wallet on the chain.

    Two ways in: the call uses a setter we have already confirmed, or it decodes to text that
    carries an indicator. The second arm is what catches an operator who renamed their setter,
    and the indicator requirement is what keeps ordinary contracts that store a name or a note
    out of the data.
    """
    to = (t.get("to") or "").lower()
    inp = t.get("input") or "0x"
    if not to or to in ignored or not (MIN_CALL_LEN <= len(inp) <= MAX_CALL_LEN):
        return None
    sel = inp[:10].lower()
    try:
        _sel, strings = decode_input_strings(inp, ["string"])
    except AbiError:
        return None
    if not strings:
        return None
    value = strings[0]
    if sel not in SETTERS:
        text = raw_text(value)
        if not text or not is_printable(text):
            return None                  # arbitrary calldata that happens to decode
        if len(text) > MAX_PROSE_LEN and parse_json(text) is None:
            return None                  # prose that happens to mention a link
        useful = [i for i in extract_iocs(text)
                  if i.type in NETWORK_IOCS and not is_dual_use(i.type, i.value)]
        if not useful:
            return None                  # text, but nothing a defender could act on
    return make_event(chain=chain.key, block=block, timestamp=ts, tx_hash=t["hash"],
                      contract=to, sender=(t.get("from") or "").lower(), selector=sel,
                      hunt_id=HUNT_ID, old=None, new=value)


def _from_block(ctx: HuntContext, chain: Chain, number: int, ts: str | None, blk: dict,
                ignored: frozenset[str] | set[str] = frozenset()) -> list[dict]:
    found: list[dict] = []
    for t in blk.get("transactions") or []:
        if t.get("to"):
            ev = call_event(chain, t, block=number, ts=ts, ignored=ignored)
            if ev is not None:
                found.append(ev)
            continue                     # a call, not a creation
        try:
            nonce = int(t["nonce"], 16)
        except (KeyError, TypeError, ValueError):
            continue
        ev = inspect_creation(ctx, chain, block=number, ts=ts, tx_hash=t["hash"],
                              deployer=(t.get("from") or "").lower(), nonce=nonce)
        if ev is not None:
            found.append(ev)
    return found
