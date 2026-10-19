"""Birth watch: catch dead drops as they are deployed, with no fingerprint to match.

Every other hunt needs something known in advance - an event name, a selector, an operator
wallet, somebody's report. This one needs nothing. A contract cannot be created without a
transaction, and a dead drop cannot refuse to answer a reader, because the infected machines
calling it carry no credentials. So:

1. read the blocks in the range and pick out contract creations;
2. derive the new address from the deployer and its nonce (no receipt lookup needed);
3. fetch the code once and judge it on shape alone - a confirmed family's selector, or a
   small contract with an owner accessor (see bytecode.Shape);
4. ask the survivors what they hold with eth_call, and decode the answer.

A contract that answers with something decodable becomes an event with a value, exactly like
one caught through its event log. One that matches the shape but stays silent is recorded as
a candidate, which the rest of the pipeline already scores lower than a decoded drop.

Cost is dominated by step 1: every block in the range is fetched with its transactions. The
caller clamps the range (hunts.toml ``max_blocks``) so a run never runs away.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from ..bytecode import created_address, probe_selectors, shape_of
from ..config import Chain
from ..decoders import AbiError, abi_decode
from ..rpc import RpcError
from ..store import iso, make_event
from . import HuntContext

log = logging.getLogger(__name__)

HUNT_ID = "birth-watch"
MIN_VALUE_LEN = 4        # shorter answers carry no indicator worth keeping
MAX_VALUE_LEN = 64 * 1024
# A block with its transactions is ~216 KB on Polygon and each request opens its own
# connection, so serially this runs at ~1.3 s per block. Six at a time brings that to the
# ~0.2 s the network actually costs, which is enough to keep up with the chain and catch
# up after a gap, while staying a polite guest on a free public endpoint.
BLOCK_WORKERS = 6
CHUNK = 60


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
    # Shape matches, nothing readable: an encrypted payload, data kept in storage, or an
    # ordinary owned contract. Recorded as a candidate rather than thrown away.
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
            out.extend(_from_block(ctx, chain, number, ts, blk))
            creations += sum(1 for t in (blk.get("transactions") or []) if not t.get("to"))
    log.info("%s birth-watch: blocks %d-%d, %d creations, %d drop-shaped",
             chain.key, from_block, to_block, creations, len(out))
    return out


def _from_block(ctx: HuntContext, chain: Chain, number: int, ts: str | None, blk: dict) -> list[dict]:
    found: list[dict] = []
    for t in blk.get("transactions") or []:
        if t.get("to"):
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
