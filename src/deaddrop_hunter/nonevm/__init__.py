"""Non-EVM collectors (Tron, Solana, Aptos): data hidden in *transactions* of watched accounts.

Public API used by the core CLI::

    events, cursor = collect(chain_key, chain_cfg, watch_wallets, since)

``events`` follow the events.json shape in docs/data-schema.md (newest first); ``cursor`` is an opaque
dict to pass back as ``since`` on the next run. All network access is read-only (HTTP GET and
read-only JSON-RPC). Decoded values are attacker-controlled and are never fetched or resolved.
"""

from __future__ import annotations

import sys

from . import aptos, solana, tron
from .common import now_iso, sort_events

COLLECTORS = {"tron": tron.collect, "solana": solana.collect, "aptos": aptos.collect}

__all__ = ["collect", "COLLECTORS"]


def _stderr_log(msg: str) -> None:
    print(f"[nonevm] {msg}", file=sys.stderr)


def collect(chain_key: str, chain_cfg: dict, watch_wallets: list[dict], since: dict | None,
            *, transport=None, sleep=None, log=_stderr_log) -> tuple[list[dict], dict]:
    """Collect data-carrying transactions of ``watch_wallets`` on a non-EVM chain.

    ``chain_cfg["type"]`` selects the collector (falls back to ``chain_key``). ``transport`` / ``sleep``
    are injection points for tests.
    """
    ctype = (chain_cfg or {}).get("type") or chain_key
    fn = COLLECTORS.get(ctype)
    if fn is None:
        raise ValueError(f"unsupported non-EVM chain type: {ctype!r}")
    wallets = [w for w in watch_wallets if (w.get("chain") or chain_key) == chain_key and w.get("address")]
    events, cursor = fn(chain_key, chain_cfg or {}, wallets, since, transport=transport, sleep=sleep, log=log)
    cursor["updated_at"] = now_iso()
    return sort_events(events), cursor
