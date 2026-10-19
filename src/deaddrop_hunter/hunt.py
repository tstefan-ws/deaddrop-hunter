"""Hunt orchestration: incremental block ranges via meta.json cursors, merge, rebuild, write."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from .build import build
from .collectors import HuntContext, block_watch, event_sweep, selector_sweep, wallet_watch
from .config import NONEVM_TYPES, Chain, Config
from .providers import ProviderUnavailable
from .providers.dune import Dune
from .providers.etherscan_v2 import EtherscanError, EtherscanV2
from .rpc import RpcClient, RpcError
from .store import load_data, merge_events, now_iso, write_data

log = logging.getLogger(__name__)

# Blocks behind head we treat as final (avoid indexing logs that may be re-orged away).
CONFIRMATIONS = 5
NONEVM_HUNT_ID = "nonevm"


@dataclass
class HuntReport:
    added: int = 0
    ran: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    paths: list[Path] = field(default_factory=list)


def _default_etherscan(chain: Chain) -> EtherscanV2:
    return EtherscanV2(chain.chain_id)


def make_context(config: Config, rpc_factory=None, etherscan_factory=None, dune_factory=None) -> HuntContext:
    return HuntContext(
        config=config,
        rpc_factory=rpc_factory or (lambda c: RpcClient(c)),
        etherscan_factory=etherscan_factory or _default_etherscan,
        dune_factory=dune_factory or (lambda: Dune()),
    )


def plan_ranges(cursor: dict | None, head: int, start: int, explicit_days: bool) -> list[tuple[int, int]]:
    """Block ranges still to scan. Forward from the cursor; with an explicit --days that
    reaches before the cursor, also backfill the gap."""
    if cursor is None:
        return [(start, head)] if start <= head else []
    ranges: list[tuple[int, int]] = []
    if explicit_days and start < cursor["from_block"]:
        ranges.append((start, cursor["from_block"] - 1))
    if cursor["to_block"] + 1 <= head:
        ranges.append((cursor["to_block"] + 1, head))
    return ranges


def run_hunt(
    config: Config,
    data_dir: Path,
    chains: list[str] | None = None,
    days: int | None = None,
    hunt_ids: list[str] | None = None,
    ctx: HuntContext | None = None,
    now: str | None = None,
) -> HuntReport:
    ctx = ctx or make_context(config)
    now = now or now_iso()
    data = load_data(data_dir)
    existing_events: list[dict] = data["events"]
    cursors: dict[tuple[str, str], dict] = {
        (c["chain"], c["hunt_id"]): c for c in data["meta"].get("cursors", [])
    }
    for e in existing_events:
        ctx.known_contracts.setdefault(e["chain"], set()).add(e["contract"])

    lookback = days if days is not None else config.default_lookback_days
    report = HuntReport()
    new_events: list[dict] = []
    heads: dict[str, int | None] = {}

    def head_of(chain: Chain) -> int | None:
        if chain.key not in heads:
            try:
                heads[chain.key] = max(0, ctx.rpc(chain).block_number() - CONFIRMATIONS)
            except RpcError as e:
                log.error("%s: cannot get head block: %s", chain.key, e)
                heads[chain.key] = None
        return heads[chain.key]

    def wanted(chain_key: str) -> bool:
        return chains is None or chain_key in chains

    # Order: event hunts first (they discover contracts), then selector hunts, then wallets.
    hunts = [h for h in config.hunts if hunt_ids is None or h.id in hunt_ids]
    hunts.sort(key=lambda h: {"event": 0, "selector": 1}.get(h.kind, 2))
    def is_evm(chain_key: str) -> bool:
        c = config.chains.get(chain_key)
        return c is None or c.is_evm

    jobs: list[tuple[str, str, object]] = [
        (h.id, ck, h) for h in hunts for ck in h.chains if wanted(ck) and is_evm(ck)
    ]
    if hunt_ids is None or wallet_watch.HUNT_ID in hunt_ids:
        wchains = sorted({w.chain for w in config.watch_wallets if wanted(w.chain) and is_evm(w.chain)})
        jobs += [(wallet_watch.HUNT_ID, ck, None) for ck in wchains]

    if hunt_ids is None or NONEVM_HUNT_ID in hunt_ids:
        for ck, chain in sorted(config.chains.items()):
            if chain.type in NONEVM_TYPES and wanted(ck):
                label = f"{ck}/{NONEVM_HUNT_ID}"
                got, cur = _run_nonevm(config, chain, cursors.get((ck, NONEVM_HUNT_ID)), report, label)
                if got is None:
                    continue
                new_events += got
                if cur is not None:
                    cursors[(ck, NONEVM_HUNT_ID)] = _nonevm_cursor(ck, cur, now)
                report.ran.append(f"{label} ({len(got)} events)")

    for hunt_id, chain_key, hunt in jobs:
        label = f"{chain_key}/{hunt_id}"
        chain = config.chains.get(chain_key)
        if chain is None:
            log.warning("%s: chain not configured; skipping", label)
            report.skipped.append(f"{label} (chain not configured)")
            continue
        # Cheap provider check before any network call so keyless chains skip fast.
        try:
            if hunt is None:
                ctx.etherscan_factory(chain)
            elif hunt.kind == "event":
                event_sweep.check_available(ctx, chain)
            elif hunt.kind == "selector":
                try:
                    ctx.dune_factory()
                except ProviderUnavailable as e1:
                    try:
                        ctx.etherscan_factory(chain)
                    except ProviderUnavailable as e2:
                        raise ProviderUnavailable(f"selector hunts need Dune or Etherscan: {e1}; {e2}") from e2
        except ProviderUnavailable as e:
            log.warning("%s: skipped (%s)", label, e)
            report.skipped.append(f"{label} ({e})")
            continue
        head = head_of(chain)
        if head is None:
            report.failed.append(f"{label} (no head block)")
            continue
        start = max(0, head - int(lookback * 86400 / chain.block_time_s))
        cursor = cursors.get((chain_key, hunt_id))
        ranges = plan_ranges(cursor, head, start, explicit_days=days is not None)
        if hunt is not None and hunt.kind == "block" and hunt.max_blocks:
            # A watcher watches the present. Reading every block is the expensive part, so each
            # run takes the newest max_blocks window: it continues from the cursor when that is
            # still inside the window, and otherwise starts at the head rather than crawling
            # from the lookback start, which would leave it months behind forever. Blocks
            # between a late run and the one before it are reported, not silently claimed.
            lo = max(0, head - hunt.max_blocks + 1)
            if cursor and cursor["to_block"] + 1 <= lo:
                missed = lo - cursor["to_block"] - 1
                log.warning("%s: %d blocks passed unread since the last run", label, missed)
                report.skipped.append(f"{label} (gap of {missed} blocks)")
            elif cursor:
                lo = cursor["to_block"] + 1
            ranges = [(lo, head)] if lo <= head else []
        if not ranges:
            report.ran.append(f"{label} (up to date)")
            continue
        # Per-wallet low-water marks, so adding a wallet backfills just that wallet.
        wallet_seen: dict[str, int] = dict((cursor or {}).get("wallets") or {})
        got: list[dict] = []
        try:
            for lo, hi in ranges:
                if hunt is None:
                    ws = [w for w in config.watch_wallets if w.chain == chain_key]
                    got += wallet_watch.collect(ctx, chain, ws, lo, hi, wallet_seen)
                elif hunt.kind == "event":
                    got += event_sweep.collect(ctx, hunt, chain, lo, hi)
                elif hunt.kind == "selector":
                    got += selector_sweep.collect(ctx, hunt, chain, lo, hi, lookback)
                elif hunt.kind == "block":
                    got += block_watch.collect(ctx, chain, lo, hi)
                else:
                    raise ProviderUnavailable(f"unknown hunt kind {hunt.kind!r}")
        except ProviderUnavailable as e:
            log.warning("%s: skipped (%s)", label, e)
            report.skipped.append(f"{label} ({e})")
            continue
        except (RpcError, EtherscanError, OSError) as e:
            log.error("%s: failed: %s", label, e)
            report.failed.append(f"{label} ({e})")
            continue
        for ev in got:
            ctx.known_contracts.setdefault(ev["chain"], set()).add(ev["contract"])
        new_events += got
        lo_all = min(r[0] for r in ranges)
        hi_all = max(r[1] for r in ranges)
        if cursor and not (hunt is not None and hunt.kind == "block"):
            lo_all = min(lo_all, cursor["from_block"])
            hi_all = max(hi_all, cursor["to_block"])
        elif cursor:
            # A block hunt's cursor is the window it last read, not a claim over everything
            # since the beginning: merging would pretend the skipped months were scanned.
            lo_all = min(lo_all, cursor["to_block"] + 1) if cursor["to_block"] + 1 <= lo_all else lo_all
        cursors[(chain_key, hunt_id)] = {
            "chain": chain_key, "hunt_id": hunt_id, "from_block": lo_all, "to_block": hi_all,
            "updated_at": now,
            **({"wallets": wallet_seen} if wallet_seen else {}),
        }
        report.ran.append(f"{label} ({len(got)} events, blocks {ranges})")

    merged, added = merge_events(existing_events, new_events)
    report.added = added
    built = build(merged, config, list(cursors.values()), now=now, existing_iocs=data["iocs"],
                  previous=data)
    report.paths = write_data(data_dir, built)
    report.counts = built["meta"]["counts"]
    return report


def _run_nonevm(config: Config, chain: Chain, since: dict | None, report: HuntReport,
                label: str) -> tuple[list[dict] | None, dict | None]:
    """Delegate a non-EVM chain to ``deaddrop_hunter.nonevm.collect`` (separate package)."""
    try:
        from .nonevm import collect as nonevm_collect
    except ImportError as e:
        log.warning("%s: skipped (non-EVM collector not available: %s)", label, e)
        report.skipped.append(f"{label} (non-EVM collector not available)")
        return None, None
    wallets = [{"chain": w.chain, "address": w.address, "label": w.label}
               for w in config.watch_wallets if w.chain == chain.key]
    try:
        events, cursor = nonevm_collect(chain.key, dict(chain.raw), wallets, since)
    except Exception as e:  # noqa: BLE001 - third-party collector must not kill the whole hunt
        log.error("%s: failed: %s", label, e)
        report.failed.append(f"{label} ({e})")
        return None, None
    return list(events or []), cursor


def _nonevm_cursor(chain_key: str, cur: dict, now: str) -> dict:
    out = {"chain": chain_key, "hunt_id": NONEVM_HUNT_ID}
    for k in ("from_block", "to_block"):
        if k in cur:
            out[k] = cur[k]
    out["updated_at"] = cur.get("updated_at", now)
    for k in sorted(cur):
        if k not in out:
            out[k] = cur[k]
    return out


def run_probe(config: Config, data_dir: Path, ctx: HuntContext | None = None,
              now: str | None = None, chains: list[str] | None = None) -> HuntReport:
    """Ask every contract we have never decoded a value from what it is holding.

    Reader, then storage slots, then the code itself. Values read this way have no
    transaction behind them, so the event carries a ``probe:`` id rather than pretending to
    one; re-probing an unchanged value adds nothing, while a changed one lands as a rotation.
    """
    from .collectors.block_watch import HUNT_ID as BLOCK_HUNT
    from .collectors.block_watch import contract_blueprint, probe_contract

    now = now or now_iso()
    ctx = ctx or make_context(config)
    data = load_data(data_dir)
    report = HuntReport()
    decoded = {(e["chain"], e["contract"]) for e in data["events"]
               if e.get("new_decoded") is not None or e.get("old_decoded") is not None}
    # Worth a look if we have never decoded a value from it, or if we do not yet know which
    # template it was built from: the blueprint is what links a redeploy to its family.
    targets = [c for c in data["contracts"]
               if ((c["chain"], c["address"]) not in decoded or not c.get("code_hash"))
               and (chains is None or c["chain"] in chains)
               and (config.chains.get(c["chain"]) or Chain(key="")).is_evm]
    new_events: list[dict] = []
    code_hashes: dict[tuple[str, str], str | None] = {}
    for c in targets:
        chain = config.chains[c["chain"]]
        label = f"{c['chain']}/probe {c['address'][:12]}…"
        try:
            ev = probe_contract(ctx, chain, c["address"], hunt_id=BLOCK_HUNT, now=now)
        except (RpcError, OSError) as e:
            report.failed.append(f"{label} ({e})")
            continue
        if ev is None:
            # Nothing to read, but the code still names the template it came from.
            code_hashes[(c["chain"], c["address"])] = contract_blueprint(ctx, chain, c["address"])
            report.skipped.append(f"{label} (nothing readable)")
            continue
        if ev.get("new_raw") is None and (c["chain"], c["address"]) in decoded:
            # Nothing new to say about the value; keep the blueprint and move on.
            code_hashes[(c["chain"], c["address"])] = ev.get("code_hash")
            report.ran.append(f"{label} (blueprint {ev.get('code_hash')})")
            continue
        new_events.append(ev)
        report.ran.append(f"{label} ({len(ev['new_raw'] or '')} chars)")
    merged, added = merge_events(data["events"], new_events)
    report.added = added
    for c in data["contracts"]:                      # carry blueprints learned without a value
        h = code_hashes.get((c["chain"], c["address"]))
        if h:
            c["code_hash"] = h
    built = build(merged, config, data["meta"].get("cursors", []), now=now,
                  existing_iocs=data["iocs"], previous=data)
    report.paths = write_data(data_dir, built)
    report.counts = built["meta"]["counts"]
    return report


def run_rebuild(config: Config, data_dir: Path, now: str | None = None) -> dict:
    data = load_data(data_dir)
    built = build(data["events"], config, data["meta"].get("cursors", []), now=now or now_iso(),
                  existing_iocs=data["iocs"], previous=data)
    write_data(data_dir, built)
    return built["meta"]["counts"]
