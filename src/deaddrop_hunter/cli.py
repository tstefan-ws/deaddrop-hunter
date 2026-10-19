"""Command line interface: hunt, rebuild, read, export."""

from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path

from . import __version__

DEFAULT_CONFIG = "config/hunts.toml"
DEFAULT_DATA = "data"

HUNT_EPILOG = """environment:
  DDH_RPC_<CHAIN>     extra RPC endpoints for a chain, prepended to its config list.
                      Format: url|max_log_span[,url|max_log_span...]; max_log_span is the
                      largest block range accepted for topic-only eth_getLogs (0 = none).
                      e.g. DDH_RPC_BSC="https://bsc-mainnet.nodereal.io/v1/KEY|50000"
  ETHERSCAN_API_KEY   Etherscan V2 (logs/txlist) for chains with indexed_provider=etherscan_v2,
                      wallet watching and the selector-hunt fallback.
  DUNE_API_KEY        Dune SQL for chains with indexed_provider=dune and for selector hunts.
Hunts whose provider is unavailable are skipped with a warning; incremental cursors are
kept in <data>/meta.json. Non-EVM chains (tron/solana/aptos) run via the nonevm collector
(hunt id 'nonevm'); wallet watching uses hunt id 'watch-wallet'.
"""


def _csv(v: str | None) -> list[str] | None:
    if not v:
        return None
    return [x.strip() for x in v.split(",") if x.strip()]


def cmd_hunt(args: argparse.Namespace) -> int:
    from .config import load_config
    from .hunt import run_hunt

    cfg = load_config(args.config)
    data_dir = Path(args.data or cfg.data_dir)
    chains = _csv(args.chains)
    if chains:
        unknown = [c for c in chains if c not in cfg.chains]
        if unknown:
            print(f"error: unknown chain(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
    hunts = _csv(args.hunts)
    rep = run_hunt(cfg, data_dir, chains=chains, days=args.days, hunt_ids=hunts)
    for r in rep.ran:
        print(f"ran      {r}")
    for s in rep.skipped:
        print(f"skipped  {s}")
    for f in rep.failed:
        print(f"FAILED   {f}")
    c = rep.counts
    print(f"new events: {rep.added}; totals: {c['events']} events, {c['contracts']} contracts, "
          f"{c['wallets']} wallets, {c['iocs']} iocs, {c['clusters']} clusters -> {data_dir}")
    return 1 if rep.failed and not rep.ran else 0


def cmd_rebuild(args: argparse.Namespace) -> int:
    from .config import load_config
    from .hunt import run_rebuild

    cfg = load_config(args.config)
    data_dir = Path(args.data or cfg.data_dir)
    c = run_rebuild(cfg, data_dir)
    print(f"rebuilt {data_dir}: {c['events']} events, {c['contracts']} contracts, {c['wallets']} wallets, "
          f"{c['iocs']} iocs, {c['clusters']} clusters")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    try:
        from .exporters import run_exports
    except ImportError as e:
        print(f"error: exporters are not available ({e}). Is the deaddrop_hunter.exporters package "
              "installed?", file=sys.stderr)
        return 2
    formats = _csv(args.formats) or ["stix", "misp", "csv", "txt", "api"]
    paths = run_exports(Path(args.data), Path(args.out), formats)
    for p in paths:
        print(p)
    return 0


def cmd_read(args: argparse.Namespace) -> int:
    from .config import load_config
    from .decoders import AbiError, abi_decode, decode_value, raw_text
    from .store import read_json

    address = args.address.lower()
    if not re.fullmatch(r"0x[0-9a-f]{40}", address):
        print("error: address must be 0x + 40 hex chars", file=sys.stderr)
        return 2
    if not args.selector:
        contracts = read_json(Path(args.data) / "contracts.json", [])
        for c in contracts:
            if c["chain"] == args.chain and c["address"] == address:
                print(f"# from {args.data}/contracts.json (last_seen {c['last_seen']}, decoder {c['decoder']})")
                print(f"raw:     {c['latest_value_raw']}")
                print(f"decoded: {c['latest_value_decoded']}")
                return 0
        print(f"error: {args.chain}:{address} not in {args.data}/contracts.json; pass --selector to eth_call",
              file=sys.stderr)
        return 1
    sel = args.selector.lower()
    if not re.fullmatch(r"0x[0-9a-f]{8}", sel):
        print("error: --selector must be 0x + 8 hex chars", file=sys.stderr)
        return 2
    from .rpc import RpcClient, RpcError

    cfg = load_config(args.config)
    chain = cfg.chains.get(args.chain)
    if chain is None:
        print(f"error: unknown chain {args.chain}", file=sys.stderr)
        return 2
    try:
        result = RpcClient(chain).eth_call(address, sel)
    except RpcError as e:
        print(f"error: eth_call failed: {e}", file=sys.stderr)
        return 1
    try:
        (value,) = abi_decode(["string"], result)
    except AbiError:
        print(f"raw return (not an ABI string): {result}")
        return 0
    decoded, decoder = decode_value(value)
    print(f"raw:     {raw_text(value)}")
    print(f"decoder: {decoder}")
    print(f"decoded: {decoded}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="deaddrop-hunter", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser(
        "hunt", help="sweep chains for known fingerprints and update data/",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HUNT_EPILOG,
    )
    h.add_argument("--config", default=DEFAULT_CONFIG)
    h.add_argument("--data", default=None, help="data dir (default: settings.data_dir)")
    h.add_argument("--chains", help="comma-separated chain keys")
    h.add_argument("--days", type=int, help="lookback window in days (default: settings.default_lookback_days)")
    h.add_argument("--hunts", help="comma-separated hunt ids (use 'watch-wallet' for wallet watching)")
    h.set_defaults(func=cmd_hunt)

    r = sub.add_parser("rebuild", help="recompute derived files from events.json (no network)")
    r.add_argument("--config", default=DEFAULT_CONFIG)
    r.add_argument("--data", default=None)
    r.set_defaults(func=cmd_rebuild)

    e = sub.add_parser("export", help="write threat-intel feeds from data/")
    e.add_argument("--data", default=DEFAULT_DATA)
    e.add_argument("--out", default="site/feeds")
    e.add_argument("--formats", default="stix,misp,csv,txt,api")
    e.set_defaults(func=cmd_export)

    rd = sub.add_parser("read", help="read (eth_call) and decode a contract's stored value")
    rd.add_argument("chain")
    rd.add_argument("address")
    rd.add_argument("--selector", help="4-byte getter selector, e.g. 0x12345678")
    rd.add_argument("--config", default=DEFAULT_CONFIG)
    rd.add_argument("--data", default=DEFAULT_DATA)
    rd.set_defaults(func=cmd_read)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    level = logging.WARNING - 10 * min(args.verbose, 2)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    try:
        return int(args.func(args) or 0)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
