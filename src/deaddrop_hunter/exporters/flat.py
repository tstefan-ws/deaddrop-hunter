"""Flat exporters: CSV tables and plain-text blocklists."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from ._common import LICENSE_NOTE, PROJECT_NAME, Dataset, ioc_sort_key, write_bytes

IOC_COLUMNS = [
    "type", "value", "port", "family", "cluster_id", "chain",
    "first_seen", "last_seen", "current", "confidence", "dual_use", "contracts",
]
CONTRACT_COLUMNS = [
    "chain", "address", "cluster_id", "family", "status", "evidence", "decoder", "update_count",
    "first_seen", "last_seen", "operator_wallets", "hunt_ids", "explorer_url",
]
WALLET_COLUMNS = [
    "chain", "address", "role", "label", "cluster_id", "tx_count",
    "first_seen", "last_seen", "watched", "contracts",
]

# Multi-valued cells are joined with this separator.
LIST_SEP = ";"

TXT_LISTS = {
    "ipv4.txt": ("ipv4", "IPv4 addresses"),
    "ipv6.txt": ("ipv6", "IPv6 addresses"),
    "domains.txt": ("domain", "domains"),
    "urls.txt": ("url", "URLs"),
}


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return LIST_SEP.join(str(v) for v in value)
    return str(value)


def _csv_bytes(columns: list[str], rows: list[dict]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_cell(row.get(c)) for c in columns])
    return buf.getvalue().encode("utf-8")


def export_csv(ds: Dataset, out_dir: Path) -> list[tuple[Path, str]]:
    csv_dir = out_dir / "csv"
    iocs = sorted(ds.iocs, key=ioc_sort_key)
    contracts = [
        {**c, "explorer_url": ds.explorer_url(c["chain"], c["address"])}
        for c in sorted(ds.contracts, key=lambda x: (x["chain"], x["address"]))
    ]
    wallets = sorted(ds.wallets, key=lambda x: (x["chain"], x["address"]))
    return [
        (write_bytes(csv_dir / "iocs.csv", _csv_bytes(IOC_COLUMNS, iocs)),
         "All IOCs (network and wallet) with family, cluster, chain and first/last seen"),
        (write_bytes(csv_dir / "contracts.csv", _csv_bytes(CONTRACT_COLUMNS, contracts)),
         "Dead-drop smart contracts with cluster, family, decoder and explorer link"),
        (write_bytes(csv_dir / "wallets.csv", _csv_bytes(WALLET_COLUMNS, wallets)),
         "Operator / deployer / funder / payout wallets"),
    ]


def export_txt(ds: Dataset, out_dir: Path) -> list[tuple[Path, str]]:
    txt_dir = out_dir / "txt"
    written = []
    for name, (ioc_type, label) in TXT_LISTS.items():
        rows = [i for i in ds.iocs if i.get("type") == ioc_type and i.get("current")]
        # Dual-use entries (public mining pools and the like) are real, but blocking them hits
        # legitimate users. They stay in the JSON/CSV/STIX feeds and out of the blocklists.
        values = sorted({i["value"] for i in rows if not i.get("dual_use")})
        withheld = len({i["value"] for i in rows if i.get("dual_use")})
        header = [
            f"# {PROJECT_NAME} blocklist: {label} currently served by on-chain dead drops",
            f"# generated_at: {ds.generated_at}",
            f"# entries: {len(values)}",
            f"# dual-use entries withheld (see csv/iocs.csv): {withheld}",
            f"# {LICENSE_NOTE}",
            "# Review before blocking: shared hosting may still cause collateral blocking.",
        ]
        data = "\n".join([*header, *values]) + "\n"
        written.append((write_bytes(txt_dir / name, data.encode("utf-8")),
                        f"Plain-text blocklist of current {label}, one per line"))
    return written
