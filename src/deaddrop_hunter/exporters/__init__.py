"""Exporters: turn ``data/*.json`` into feeds for threat-intel platforms.

Public API (called by the CLI)::

    run_exports(data_dir, out_dir, formats) -> list[Path]

Formats: ``stix`` (STIX 2.1 bundles), ``misp`` (MISP feed), ``csv``, ``txt``
(blocklists) and ``api`` (static JSON API under ``api/v1/`` plus ``atom.xml``).
``out_dir/index.json`` is always (re)written and lists every feed file
with format, description, size and sha256. Output is deterministic: the same input
produces byte-identical files.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import api, flat, misp, stix
from ._common import PROJECT_NAME, load_dataset, sha256_file, write_json

FORMATS = ("stix", "misp", "csv", "txt", "api")
# What the CLI should export when no --format is given: everything.
DEFAULT_FORMATS = FORMATS

_EXPORTERS = {
    "stix": stix.export,
    "misp": misp.export,
    "csv": flat.export_csv,
    "txt": flat.export_txt,
    "api": api.export,
}

INDEX_NAME = "index.json"


def _write_index(
    out_dir: Path, generated_at: str, schema_version, files: list[tuple[Path, str, str]]
) -> Path:
    entries = []
    for path, fmt, description in files:
        entries.append({
            "path": path.relative_to(out_dir).as_posix(),
            "format": fmt,
            "description": description,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    entries.sort(key=lambda e: (FORMATS.index(e["format"]), e["path"]))
    index = {
        "project": PROJECT_NAME,
        "generated_at": generated_at,
        "schema_version": schema_version,
        "files": entries,
    }
    return write_json(out_dir / INDEX_NAME, index)


def run_exports(data_dir: Path, out_dir: Path, formats: list[str]) -> list[Path]:
    """Export ``data_dir`` into ``out_dir`` in the requested formats; return written paths."""
    data_dir, out_dir = Path(data_dir), Path(out_dir)
    wanted = []
    for f in formats:
        f = f.strip().lower()
        if f not in _EXPORTERS:
            raise ValueError(f"unknown export format {f!r}; choose from {', '.join(FORMATS)}")
        if f not in wanted:
            wanted.append(f)
    ds = load_dataset(data_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    files: list[tuple[Path, str, str]] = []
    for fmt in FORMATS:
        if fmt in wanted:
            files += [(p, fmt, desc) for p, desc in _EXPORTERS[fmt](ds, out_dir)]
    # Keep index entries of formats not exported in this run (if their files still exist),
    # so `export --format csv` does not drop STIX/MISP from the dashboard's Feeds page.
    previous = out_dir / INDEX_NAME
    if previous.exists():
        try:
            old = json.loads(previous.read_text(encoding="utf-8")).get("files", [])
        except (ValueError, AttributeError):
            old = []
        for entry in old:
            fmt, rel = entry.get("format"), entry.get("path")
            if (fmt in FORMATS and fmt not in wanted and isinstance(rel, str)
                    and ".." not in Path(rel).parts and not Path(rel).is_absolute()
                    and (out_dir / rel).is_file()):
                files.append((out_dir / rel, fmt, entry.get("description", "")))
    index = _write_index(out_dir, ds.generated_at, ds.meta.get("schema_version"), files)
    return [p for p, fmt, _ in files if fmt in wanted] + [index]


__all__ = ["DEFAULT_FORMATS", "FORMATS", "run_exports"]
