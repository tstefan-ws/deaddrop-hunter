"""Watch operator wallets: every tx they send (Etherscan V2 txlist).

* contract creations -> event for the new contract (selector null, values null): a candidate
* calls whose input ABI-decodes as ``(string)`` -> event with the decoded value
* calls with other input to contracts not yet known -> candidate event (values null)
"""

from __future__ import annotations

import logging

from ..config import Chain, WatchWallet
from ..decoders import AbiError, decode_input_strings
from ..store import iso, make_event
from . import HuntContext

log = logging.getLogger(__name__)

HUNT_ID = "watch-wallet"


def tx_events(chain: Chain, wallet: str, t: dict, known: set[str]) -> list[dict]:
    if str(t.get("isError", "0")) != "0" or (t.get("from") or "").lower() != wallet:
        return []
    block = int(t["blockNumber"])
    ts = iso(int(t["timeStamp"])) if t.get("timeStamp") else None
    to = (t.get("to") or "").lower()
    inp = t.get("input") or "0x"
    created = (t.get("contractAddress") or "").lower()
    if not to and created:
        return [make_event(chain=chain.key, block=block, timestamp=ts, tx_hash=t["hash"], contract=created,
                           sender=wallet, selector=None, hunt_id=HUNT_ID, old=None, new=None)]
    if not to or len(inp) < 10:
        return []
    try:
        sel, strings = decode_input_strings(inp, ["string"])
    except AbiError:
        sel, strings = inp[:10].lower(), []
    if strings:
        return [make_event(chain=chain.key, block=block, timestamp=ts, tx_hash=t["hash"], contract=to,
                           sender=wallet, selector=sel, hunt_id=HUNT_ID, old=None, new=strings[0])]
    if to not in known:
        return [make_event(chain=chain.key, block=block, timestamp=ts, tx_hash=t["hash"], contract=to,
                           sender=wallet, selector=sel, hunt_id=HUNT_ID, old=None, new=None)]
    return []


def collect(ctx: HuntContext, chain: Chain, wallets: list[WatchWallet], from_block: int,
            to_block: int) -> list[dict]:
    es = ctx.etherscan_factory(chain)  # raises ProviderUnavailable without a key
    known = ctx.known_contracts.get(chain.key, set())
    out: list[dict] = []
    for w in wallets:
        txs = es.txlist(w.address, from_block, to_block)
        log.info("%s watch %s: %d txs", chain.key, w.address, len(txs))
        for t in txs:
            out.extend(tx_events(chain, w.address, t, known))
    return out
