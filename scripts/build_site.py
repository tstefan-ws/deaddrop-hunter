#!/usr/bin/env python3
"""Assemble the static dashboard site (stdlib only).

    python scripts/build_site.py [--out site] [--web web] [--data data]

Result:
    site/               <- copy of web/ (without web/sample-data/)
    site/data/*.json    <- copy of data/*.json
    site/feeds/...      <- left untouched (written earlier by `deaddrop-hunter export`)
    site/.nojekyll

Run order in CI:  deaddrop-hunter export --out site/feeds  ->  build_site.py --out site
so this script must never delete site/feeds/. Everything else in the output directory is
removed first so stale files from older builds do not linger.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

PRESERVE = {"feeds"}            # top-level entries in the out dir that survive a rebuild
EXCLUDE_WEB = {"sample-data"}   # top-level entries in web/ that are not published
REPO_ROOT = Path(__file__).resolve().parent.parent


def _is_safe_out_dir(out: Path) -> bool:
    """Only wipe a directory that is clearly a site output dir inside the repo or cwd."""
    out = out.resolve()
    if out in (Path(out.anchor), Path.home().resolve(), REPO_ROOT, Path.cwd().resolve()):
        return False
    for protected in ("web", "data", "src", "docs", "config", "rules", "scripts", ".git"):
        if out == (REPO_ROOT / protected).resolve():
            return False
    return True


def clean_out_dir(out: Path) -> int:
    """Remove everything in `out` except preserved entries. Returns number removed."""
    if not out.exists():
        out.mkdir(parents=True)
        return 0
    if not _is_safe_out_dir(out):
        raise SystemExit(f"refusing to clean {out}: not a dedicated site output directory")
    removed = 0
    for entry in out.iterdir():
        if entry.name in PRESERVE:
            continue
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()
        removed += 1
    return removed


def copy_web(web: Path, out: Path) -> int:
    count = 0
    for src in sorted(web.rglob("*")):
        rel = src.relative_to(web)
        if rel.parts[0] in EXCLUDE_WEB or rel.parts[0] in PRESERVE:
            continue
        if any(part.startswith(".") for part in rel.parts):
            continue  # skip dotfiles (editor swap files, .DS_Store, ...)
        dst = out / rel
        if src.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        count += 1
    return count


def copy_data(data: Path, out: Path) -> tuple[int, list[str]]:
    dst_dir = out / "data"
    dst_dir.mkdir(parents=True, exist_ok=True)
    copied, bad = 0, []
    for src in sorted(data.glob("*.json")):
        try:
            json.loads(src.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            bad.append(f"{src.name}: {exc}")
            continue
        shutil.copy2(src, dst_dir / src.name)
        copied += 1
    return copied, bad


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="site", help="output directory (default: site)")
    ap.add_argument("--web", default="web", help="dashboard source directory (default: web)")
    ap.add_argument("--data", default="data", help="hunter data directory (default: data)")
    args = ap.parse_args(argv)

    out, web, data = Path(args.out), Path(args.web), Path(args.data)
    if not web.is_dir():
        print(f"error: web directory not found: {web}", file=sys.stderr)
        return 2
    if out.resolve() == web.resolve() or out.resolve() == data.resolve():
        print("error: --out must differ from --web and --data", file=sys.stderr)
        return 2

    removed = clean_out_dir(out)
    n_web = copy_web(web, out)
    if data.is_dir():
        n_data, bad = copy_data(data, out)
    else:
        print(f"warning: data directory not found: {data} (site will have no data)", file=sys.stderr)
        n_data, bad = 0, []
    (out / ".nojekyll").write_text("", encoding="utf-8")

    feeds = out / "feeds"
    n_feeds = sum(1 for p in feeds.rglob("*") if p.is_file()) if feeds.is_dir() else 0

    print(f"site built in {out}")
    print(f"  removed stale entries : {removed}")
    print(f"  web files copied      : {n_web} (excluded: {', '.join(sorted(EXCLUDE_WEB))})")
    print(f"  data files copied     : {n_data} -> {out / 'data'}")
    print(f"  feeds preserved       : {n_feeds} file(s) in {feeds}"
          + ("" if n_feeds else "  (run `deaddrop-hunter export --out site/feeds` first)"))
    for b in bad:
        print(f"  SKIPPED invalid JSON  : {b}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
