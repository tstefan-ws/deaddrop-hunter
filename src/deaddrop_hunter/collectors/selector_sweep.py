"""Selector hunts: transactions whose input starts with a 4-byte selector.

Plain RPC cannot search tx input, so this uses Dune (DUNE_API_KEY). Without Dune it falls back
to Etherscan tx history of contracts already known on that chain (ETHERSCAN_API_KEY). With
neither key it raises ProviderUnavailable and the hunt is skipped.
"""

from __future__ import annotations

import logging

from ..config import Chain, Hunt
from ..decoders import AbiError, decode_input_strings
from ..providers import ProviderUnavailable
from ..providers.dune import DuneError
from ..providers.dune import parse_dune_time as _dune_time
from ..providers.etherscan_v2 import EtherscanError
from ..store import iso, make_event
from . import HuntContext

log = logging.getLogger(__name__)


def tx_to_event(hunt: Hunt, chain: Chain, *, block: int, ts: str | None, tx_hash: str, sender: str | None,
                to: str | None, tx_input: str) -> dict | None:
    if not to or not tx_input.lower().startswith(hunt.selector or "0x"):
        return None
    try:
        sel, strings = decode_input_strings(tx_input, hunt.abi)
    except AbiError as e:
        log.warning("%s: cannot decode input of %s: %s", chain.key, tx_hash, e)
        sel, strings = tx_input[:10].lower(), []
    return make_event(
        chain=chain.key, block=block, timestamp=ts, tx_hash=tx_hash, contract=to, sender=sender,
        selector=sel, hunt_id=hunt.id, old=None, new=strings[-1] if strings else None,
    )


def collect(ctx: HuntContext, hunt: Hunt, chain: Chain, from_block: int, to_block: int,
            days: int) -> list[dict]:
    out: list[dict] = []
    try:
        dune = ctx.dune_factory()
    except ProviderUnavailable as e:
        dune = None
        log.info("%s %s: Dune unavailable (%s); falling back to Etherscan tx history", chain.key, hunt.id, e)
    if dune is not None:
        try:
            rows = dune.selector_txs(chain.key, hunt.selector, days, chain.dune_chain)
        except DuneError as e:
            raise ProviderUnavailable(f"Dune query failed: {e}") from e
        for r in rows:
            if not (from_block <= r["block"] <= to_block):
                continue
            ev = tx_to_event(hunt, chain, block=r["block"], ts=_dune_time(r["time"]), tx_hash=r["hash"],
                             sender=r["from"], to=r["to"], tx_input=r["input"])
            if ev:
                out.append(ev)
        return out

    es = ctx.etherscan_factory(chain)  # raises ProviderUnavailable without a key
    contracts = sorted(ctx.known_contracts.get(chain.key, set()))
    if not contracts:
        log.info("%s %s: no known contracts to scan via Etherscan", chain.key, hunt.id)
        return out
    for addr in contracts:
        try:
            txs = es.txlist(addr, from_block, to_block)
        except EtherscanError as e:
            log.warning("%s %s: txlist %s failed: %s", chain.key, hunt.id, addr, e)
            continue
        for t in txs:
            if str(t.get("isError", "0")) != "0":
                continue
            ev = tx_to_event(hunt, chain, block=int(t["blockNumber"]), ts=iso(int(t["timeStamp"])),
                             tx_hash=t["hash"], sender=t.get("from"), to=t.get("to"),
                             tx_input=t.get("input", "0x"))
            if ev:
                out.append(ev)
    return out
