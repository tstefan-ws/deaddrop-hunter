"""Event hunts: topic0 sweep via eth_getLogs (RPC) or an indexed provider (Etherscan V2)."""

from __future__ import annotations

import logging

from ..config import Chain, Hunt
from ..decoders import AbiError, decode_log_strings
from ..providers import ProviderUnavailable
from ..providers.dune import DuneError, parse_dune_time
from ..rpc import NoSweepEndpoint
from ..store import iso, make_event
from . import HuntContext

log = logging.getLogger(__name__)


def sweep_source(chain: Chain) -> str:
    """Where topic-only sweeps for this chain come from: an RPC with max_log_span > 0 (config
    or DDH_RPC_<CHAIN> override) wins; otherwise the configured indexed provider."""
    if chain.sweep_rpcs:
        return "rpc"
    if chain.indexed_provider in ("etherscan_v2", "dune"):
        return chain.indexed_provider
    return "none"


def check_available(ctx: HuntContext, chain: Chain) -> None:
    """Raise ProviderUnavailable (without network) if this chain cannot be swept now."""
    src = sweep_source(chain)
    if src == "etherscan_v2":
        ctx.etherscan_factory(chain)
    elif src == "dune":
        ctx.dune_factory()
    elif src == "none":
        raise ProviderUnavailable(
            f"{chain.key}: no RPC accepts topic-only sweeps and no indexed provider "
            f"(set DDH_RPC_{chain.key.upper()}='<url>|<max_log_span>' or configure one)")


def fetch_logs(ctx: HuntContext, hunt: Hunt, chain: Chain, from_block: int, to_block: int) -> list[dict]:
    src = sweep_source(chain)
    if src == "etherscan_v2":
        es = ctx.etherscan_factory(chain)  # raises ProviderUnavailable without a key
        return es.get_logs(hunt.topic0, from_block, to_block)
    if src == "dune":
        dune = ctx.dune_factory()  # raises ProviderUnavailable without a key
        try:
            return dune.topic_logs(chain.key, hunt.topic0, from_block, to_block, chain.dune_chain)
        except DuneError as e:
            raise ProviderUnavailable(f"Dune logs query failed: {e}") from e
    if src == "none":
        check_available(ctx, chain)
    rpc = ctx.rpc(chain)

    def progress(a: int, b: int, n: int) -> None:
        log.info("%s %s: blocks %d-%d -> %d logs", chain.key, hunt.id, a, b, n)

    try:
        return rpc.get_logs_sweep(hunt.topic0, from_block, to_block, on_chunk=progress)
    except NoSweepEndpoint as e:
        raise ProviderUnavailable(str(e)) from e


def log_to_event(ctx: HuntContext, hunt: Hunt, chain: Chain, lg: dict) -> dict | None:
    if lg.get("removed"):
        return None
    try:
        strings = decode_log_strings(lg["data"], hunt.abi)
    except AbiError as e:
        log.warning("%s: cannot ABI-decode log in %s: %s", chain.key, lg.get("transactionHash"), e)
        strings = []
    old = strings[0] if len(strings) >= 2 else None
    new = strings[-1] if strings else None
    block = int(lg["blockNumber"], 16)
    ts = None
    if lg.get("blockTimestamp"):
        try:
            ts = iso(int(lg["blockTimestamp"], 16))
        except (TypeError, ValueError):
            ts = None
    if ts is None and lg.get("blockTime"):
        ts = parse_dune_time(lg["blockTime"])
    if ts is None:
        ts = ctx.block_iso(chain, block)
    tx = ctx.tx(chain, lg["transactionHash"])
    sender = (tx.get("from") if tx else None) or lg.get("txFrom")
    inp = (tx.get("input") or "") if tx else ""
    selector = inp[:10].lower() if len(inp) >= 10 else None
    return make_event(
        chain=chain.key, block=block, timestamp=ts, tx_hash=lg["transactionHash"],
        contract=lg["address"], sender=sender, selector=selector, hunt_id=hunt.id, old=old, new=new,
    )


def collect(ctx: HuntContext, hunt: Hunt, chain: Chain, from_block: int, to_block: int) -> list[dict]:
    logs = fetch_logs(ctx, hunt, chain, from_block, to_block)
    log.info("%s %s: %d logs in %d-%d", chain.key, hunt.id, len(logs), from_block, to_block)
    out = []
    for lg in logs:
        ev = log_to_event(ctx, hunt, chain, lg)
        if ev:
            out.append(ev)
    return out
