"""Collectors turn a (hunt, chain, block range) into event records (see store.make_event)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from ..config import Chain, Config
from ..rpc import RpcClient, RpcError
from ..store import iso

log = logging.getLogger(__name__)


@dataclass
class HuntContext:
    config: Config
    rpc_factory: Callable[[Chain], RpcClient]
    etherscan_factory: Callable[[Chain], object]  # may raise ProviderUnavailable
    dune_factory: Callable[[], object]  # may raise ProviderUnavailable
    known_contracts: dict[str, set[str]] = field(default_factory=dict)  # chain -> addresses
    known_wallets: dict[str, set[str]] = field(default_factory=dict)    # chain -> addresses
    _rpcs: dict[str, RpcClient] = field(default_factory=dict)
    _tx_cache: dict[tuple[str, str], dict | None] = field(default_factory=dict)

    def rpc(self, chain: Chain) -> RpcClient:
        if chain.key not in self._rpcs:
            self._rpcs[chain.key] = self.rpc_factory(chain)
        return self._rpcs[chain.key]

    def tx(self, chain: Chain, tx_hash: str) -> dict | None:
        k = (chain.key, tx_hash)
        if k not in self._tx_cache:
            try:
                self._tx_cache[k] = self.rpc(chain).get_transaction(tx_hash)
            except RpcError as e:
                log.warning("%s: tx lookup %s failed: %s", chain.key, tx_hash, e)
                self._tx_cache[k] = None
        return self._tx_cache[k]

    def block_iso(self, chain: Chain, block: int) -> str | None:
        try:
            return iso(self.rpc(chain).block_timestamp(block))
        except RpcError as e:
            log.warning("%s: block %d timestamp failed: %s", chain.key, block, e)
            return None
