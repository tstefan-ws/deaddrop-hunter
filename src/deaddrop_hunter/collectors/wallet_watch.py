"""Watch operator wallets: every tx they send (Etherscan V2 txlist).

* contract creations -> event for the new contract (selector null, values null): a candidate
* calls whose input ABI-decodes as ``(string)`` -> event with the decoded value
* calls with other input to contracts not yet known -> candidate event (values null)

Calls to contracts listed under ``ignore_contracts`` in the config are dropped: shared public
infrastructure an operator happens to use (MetaMask's DelegationManager, routers, proxies) is not
a dead drop, and recording it as a candidate contract links unrelated operators into one cluster.
"""

from __future__ import annotations

import logging

from ..config import Chain, WatchWallet
from ..decoders import AbiError, decode_input_strings
from ..store import iso, make_event
from . import HuntContext

log = logging.getLogger(__name__)

HUNT_ID = "watch-wallet"


def tx_events(chain: Chain, wallet: str, t: dict, known: set[str],
              ignored: set[str] | frozenset[str] = frozenset()) -> list[dict]:
    if str(t.get("isError", "0")) != "0" or (t.get("from") or "").lower() != wallet:
        return []
    block = int(t["blockNumber"])
    ts = iso(int(t["timeStamp"])) if t.get("timeStamp") else None
    to = (t.get("to") or "").lower()
    inp = t.get("input") or "0x"
    created = (t.get("contractAddress") or "").lower()
    if to and to in ignored:
        return []
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
            to_block: int, seen: dict[str, int] | None = None) -> list[dict]:
    """Every transaction these wallets sent in the range.

    ``seen`` maps wallet -> lowest block already scanned for it, and is updated in place. The
    chain-wide cursor cannot answer "have we scanned *this* wallet", so without it a wallet
    added to the config today would silently never have its earlier activity fetched: the
    cursor already claims those blocks on behalf of the wallets that were there before. A
    wallet we have not seen is therefore read from its first transaction, which costs one
    paginated query.
    """
    es = ctx.etherscan_factory(chain)  # raises ProviderUnavailable without a key
    known = ctx.known_contracts.get(chain.key, set())
    ignored = {a for c, a in ctx.config.ignore_contracts if c == chain.key}
    seen = {} if seen is None else seen
    out: list[dict] = []
    for w in wallets:
        start = from_block
        if w.address not in seen:
            log.info("%s watch %s: new wallet, reading its whole history", chain.key, w.address)
            start = 0
        elif seen[w.address] < from_block:
            start = seen[w.address]
        txs = es.txlist(w.address, start, to_block)
        log.info("%s watch %s: %d txs from block %d", chain.key, w.address, len(txs), start)
        for t in txs:
            out.extend(tx_events(chain, w.address, t, known, ignored))
        seen[w.address] = min(seen.get(w.address, start), start)
    return out
