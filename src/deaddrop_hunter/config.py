"""Load ``config/hunts.toml`` into dataclasses."""

from __future__ import annotations

import logging
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .keccak import selector as _selector
from .keccak import topic0 as _topic0

log = logging.getLogger(__name__)

NONEVM_TYPES = frozenset({"tron", "solana", "aptos"})
ENV_RPC_PREFIX = "DDH_RPC_"


@dataclass(frozen=True)
class RpcEndpoint:
    url: str
    max_log_span: int = 0


@dataclass(frozen=True)
class Chain:
    key: str
    chain_id: int = 0
    block_time_s: float = 2.0
    explorer: str = ""
    rpcs: tuple[RpcEndpoint, ...] = ()
    indexed_provider: str | None = None  # "etherscan_v2" | "dune" | "none" | None
    dune_chain: str | None = None
    type: str = "evm"  # "evm" | "tron" | "solana" | "aptos"
    api: str | None = None
    raw: Mapping = field(default_factory=dict, compare=False, hash=False)

    @property
    def is_evm(self) -> bool:
        return self.type == "evm"

    @property
    def sweep_rpcs(self) -> tuple[RpcEndpoint, ...]:
        return tuple(r for r in self.rpcs if r.max_log_span > 0)


@dataclass(frozen=True)
class Hunt:
    id: str
    kind: str  # event | selector | wallet
    chains: tuple[str, ...]
    signature: str | None = None
    topic0: str | None = None
    selector: str | None = None
    abi: tuple[str, ...] = ("string",)
    reference: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class WatchWallet:
    chain: str
    address: str
    label: str = ""


@dataclass
class Config:
    default_lookback_days: int = 90
    data_dir: str = "data"
    chains: dict[str, Chain] = field(default_factory=dict)
    hunts: list[Hunt] = field(default_factory=list)
    watch_wallets: list[WatchWallet] = field(default_factory=list)
    # (chain, address) pairs that are never dead drops: shared public contracts a watched
    # operator happens to call (e.g. MetaMask's DelegationManager). Recording them as
    # candidate contracts links unrelated operators into one cluster.
    ignore_contracts: frozenset[tuple[str, str]] = frozenset()

    def watched(self) -> dict[tuple[str, str], WatchWallet]:
        return {(w.chain, w.address): w for w in self.watch_wallets}


def _lower_hex(v: str | None) -> str | None:
    return v.lower() if isinstance(v, str) else v


def norm_address(a: str) -> str:
    """EVM-style 0x hex addresses are lower-cased; chain-native base58 etc. are kept as-is."""
    return a.lower() if a[:2].lower() == "0x" else a


def parse_env_rpcs(value: str) -> list[RpcEndpoint]:
    """Parse ``url|max_log_span[,url|max_log_span...]`` (``|N`` optional, default 0)."""
    out: list[RpcEndpoint] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        url, _, span = part.rpartition("|") if "|" in part else (part, "", "0")
        try:
            n = int(span or 0)
        except ValueError:
            log.warning("ignoring bad max_log_span %r in RPC override", span)
            n = 0
        out.append(RpcEndpoint(url=url.strip(), max_log_span=n))
    return out


def parse_config(raw: dict, env: Mapping[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    settings = raw.get("settings", {})
    chains: dict[str, Chain] = {}
    for key, c in raw.get("chains", {}).items():
        rpcs: list[RpcEndpoint] = []
        override = env.get(ENV_RPC_PREFIX + key.upper(), "")
        if override:
            rpcs.extend(parse_env_rpcs(override))
        for r in c.get("rpcs", []):
            if isinstance(r, str):
                rpcs.append(RpcEndpoint(url=r))
            else:
                rpcs.append(RpcEndpoint(url=r["url"], max_log_span=int(r.get("max_log_span", 0))))
        chains[key] = Chain(
            key=key,
            chain_id=int(c.get("chain_id", 0)),
            block_time_s=float(c.get("block_time_s", 2.0)),
            explorer=c.get("explorer", ""),
            rpcs=tuple(rpcs),
            indexed_provider=c.get("indexed_provider"),
            dune_chain=c.get("dune_chain"),
            type=c.get("type", "evm"),
            api=c.get("api"),
            raw=dict(c),
        )
    hunts: list[Hunt] = []
    for h in raw.get("hunts", []):
        kind = h.get("kind", "event")
        sig = h.get("signature")
        t0 = _lower_hex(h.get("topic0"))
        sel = _lower_hex(h.get("selector"))
        if kind == "event" and not t0:
            if not sig:
                raise ValueError(f"hunt {h.get('id')}: event hunt needs topic0 or signature")
            t0 = _topic0(sig)
        if kind == "selector" and not sel:
            if not sig:
                raise ValueError(f"hunt {h.get('id')}: selector hunt needs selector or signature")
            sel = _selector(sig)
        hunts.append(Hunt(
            id=h["id"],
            kind=kind,
            chains=tuple(h.get("chains", [])),
            signature=sig,
            topic0=t0,
            selector=sel,
            abi=tuple(h.get("abi", ["string"])),
            reference=h.get("reference"),
            note=h.get("note"),
        ))
    wallets = [
        WatchWallet(chain=w["chain"], address=norm_address(w["address"]), label=w.get("label", ""))
        for w in raw.get("watch_wallets", [])
    ]
    ignored = frozenset(
        (i["chain"], norm_address(i["address"])) for i in raw.get("ignore_contracts", [])
    )
    return Config(
        default_lookback_days=int(settings.get("default_lookback_days", 90)),
        data_dir=settings.get("data_dir", "data"),
        chains=chains,
        hunts=hunts,
        watch_wallets=wallets,
        ignore_contracts=ignored,
    )


def load_config(path: str | Path, env: Mapping[str, str] | None = None) -> Config:
    with open(path, "rb") as fh:
        return parse_config(tomllib.load(fh), env)
