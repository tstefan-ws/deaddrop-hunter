"""Static, versioned JSON API (served by GitHub Pages) plus an Atom feed.

Layout under ``out_dir``::

    api/v1/index.json                         endpoint list (path, description, count, sha256)
    api/v1/iocs.json                          every IOC
    api/v1/iocs/current.json                  IOCs with current == true
    api/v1/iocs/<type>.json                   IOCs per type (ipv4, domain, url, xmr-wallet, ...)
    api/v1/families/<family>.json             IOCs per family
    api/v1/chains/<chain>.json                IOCs per chain
    api/v1/contracts.json | wallets.json | clusters.json
    api/v1/contracts/<chain>/<address>.json   one contract + its events + its IOCs
    api/v1/changes.json                       newest 200 on-chain rotations (newest first)
    atom.xml                                  newest 100 rotations / new contracts (defanged)

Every JSON file is ``{"schema_version", "generated_at", "license", "count", "data"}``;
``data`` holds raw (not defanged) values for machine use.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ._common import (
    DATA_LICENSE,
    FEEDS_BASE_URL,
    PROJECT_NAME,
    PROJECT_URL,
    Dataset,
    ioc_sort_key,
    safe_name,
    sha256_file,
    stix_ts,
    uid,
    write_bytes,
    write_json,
)

API_DIR = ("api", "v1")
CHANGES_LIMIT = 200
ATOM_LIMIT = 100
SUMMARY_MAX = 400
# Always published (possibly empty) so client URLs never 404.
KNOWN_IOC_TYPES = (
    "ipv4", "ipv6", "domain", "url", "xmr-wallet", "btc-wallet", "evm-contract", "evm-wallet",
)
ATOM_NS = "http://www.w3.org/2005/Atom"

_INVALID_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
_SCHEME = re.compile(r"(?i)\b(h)tt(ps?)(?=://)")


def defang(text: str) -> str:
    """Human-safe rendering: hxxp(s)://, dots as [.], never clickable."""
    text = _SCHEME.sub(lambda m: f"{m.group(1)}xx{m.group(2)}", text)
    return text.replace("://", "[://]").replace(".", "[.]")


def _xml_text(text: str) -> str:
    return _INVALID_XML.sub("�", text)


def _event_key(e: dict) -> tuple:
    return (e.get("timestamp") or "", e.get("block") or 0, e.get("tx_hash") or "", e.get("contract") or "")


def _event_record(e: dict) -> dict:
    return {**e, "first_seen": e.get("timestamp")}


class _Api:
    def __init__(self, ds: Dataset, out_dir: Path):
        self.ds = ds
        self.out_dir = out_dir
        self.root = out_dir.joinpath(*API_DIR)
        self.written: list[tuple[Path, str, int]] = []

    def wrap(self, data, count: int | None = None) -> dict:
        if count is None:
            count = len(data) if isinstance(data, list) else 1
        return {
            "schema_version": self.ds.meta.get("schema_version", 1),
            "generated_at": self.ds.generated_at,
            "license": DATA_LICENSE,
            "count": count,
            "data": data,
        }

    def put(self, rel: str, data, description: str) -> None:
        doc = self.wrap(data)
        path = write_json(self.root / rel, doc)
        self.written.append((path, description, doc["count"]))

    def build(self) -> None:
        ds = self.ds
        iocs = sorted(ds.iocs, key=ioc_sort_key)
        contracts = sorted(ds.contracts, key=lambda c: (c["chain"], c["address"]))
        wallets = sorted(ds.wallets, key=lambda w: (w["chain"], w["address"]))
        clusters = sorted(ds.clusters, key=lambda c: c["id"])
        events = sorted(ds.events, key=_event_key, reverse=True)

        self.put("iocs.json", iocs, "All IOCs")
        self.put("iocs/current.json", [i for i in iocs if i.get("current")],
                 "IOCs currently served by at least one contract")
        for t in sorted(set(KNOWN_IOC_TYPES) | {i["type"] for i in iocs if i.get("type")}):
            self.put(f"iocs/{safe_name(t)}.json", [i for i in iocs if i.get("type") == t],
                     f"IOCs of type {t}")
        for fam in sorted({i.get("family") or "unknown" for i in iocs}):
            self.put(f"families/{safe_name(fam)}.json",
                     [i for i in iocs if (i.get("family") or "unknown") == fam], f"IOCs of family {fam}")
        for chain in sorted({i["chain"] for i in iocs if i.get("chain")}):
            self.put(f"chains/{safe_name(chain)}.json",
                     [i for i in iocs if i.get("chain") == chain], f"IOCs found on chain {chain}")
        self.put("contracts.json", contracts, "Dead-drop contracts / accounts")
        self.put("wallets.json", wallets, "Operator / deployer / funder / payout wallets")
        self.put("clusters.json", clusters, "Clusters of contracts sharing operators")
        for c in contracts:
            key = (c["chain"], c["address"])
            detail = {
                **c,
                "explorer_url": ds.explorer_url(*key),
                "events": [_event_record(e) for e in events if (e.get("chain"), e.get("contract")) == key],
                "iocs": [
                    i for i in iocs
                    if i.get("chain") == c["chain"] and c["address"] in (i.get("contracts") or [])
                ],
            }
            self.put(f"contracts/{safe_name(c['chain'])}/{safe_name(c['address'])}.json", detail,
                     f"Contract {c['address']} on {c['chain']} with its events and IOCs")
        self.put("changes.json", [_event_record(e) for e in events[:CHANGES_LIMIT]],
                 f"Newest {CHANGES_LIMIT} on-chain rotations (newest first)")

    def write_index(self) -> Path:
        endpoints = []
        for path, description, count in self.written:
            endpoints.append({
                "path": path.relative_to(self.root).as_posix(),
                "url": f"{FEEDS_BASE_URL}/{path.relative_to(self.out_dir).as_posix()}",
                "description": description,
                "count": count,
                "sha256": sha256_file(path),
            })
        endpoints.sort(key=lambda e: e["path"])
        return write_json(self.root / "index.json", self.wrap(endpoints))

    def prune(self) -> None:
        keep = {p for p, _, _ in self.written} | {self.root / "index.json"}
        for stale in self.root.rglob("*.json"):
            if stale not in keep:
                stale.unlink()


def _atom_entries(ds: Dataset) -> list[dict]:
    entries = []
    for e in ds.events:
        decoded = e.get("new_decoded") or e.get("new_raw") or ""
        summary = decoded if len(decoded) <= SUMMARY_MAX else decoded[:SUMMARY_MAX] + "..."
        entries.append({
            "id": f"urn:uuid:{uid('atom', 'event', e.get('chain'), e.get('tx_hash'), e.get('contract'))}",
            "updated": e.get("timestamp"),
            "title": f"Dead-drop update on {e.get('chain')} {e.get('contract')}",
            "summary": f"New value ({e.get('decoder') or 'undecoded'}): {defang(summary)}",
            "link": ds.explorer_tx_url(e["chain"], e["tx_hash"]) if e.get("tx_hash") else None,
            "category": e.get("chain"),
        })
    for c in ds.contracts:
        entries.append({
            "id": f"urn:uuid:{uid('atom', 'contract', c['chain'], c['address'])}",
            "updated": c.get("first_seen"),
            "title": (
                f"New dead-drop contract on {c['chain']}: {c['address']} "
                f"({c.get('family') or 'unknown'})"
            ),
            "summary": (
                f"Family {c.get('family') or 'unknown'}, cluster {c.get('cluster_id') or 'none'}, "
                f"decoder {c.get('decoder') or 'undecoded'}, status {c.get('status') or 'unknown'}."
            ),
            "link": ds.explorer_url(c["chain"], c["address"]),
            "category": c["chain"],
        })
    entries = [x for x in entries if x["updated"]]
    entries.sort(key=lambda x: (x["updated"], x["id"]), reverse=True)
    return entries[:ATOM_LIMIT]


def build_atom(ds: Dataset) -> bytes:
    ET.register_namespace("", ATOM_NS)

    def sub(parent, tag, text=None, **attrs):
        el = ET.SubElement(parent, f"{{{ATOM_NS}}}{tag}", {k: _xml_text(v) for k, v in attrs.items()})
        if text is not None:
            el.text = _xml_text(text)
        return el

    feed = ET.Element(f"{{{ATOM_NS}}}feed")
    sub(feed, "id", f"urn:uuid:{uid('atom', 'feed', PROJECT_NAME)}")
    sub(feed, "title", f"{PROJECT_NAME}: on-chain dead-drop rotations")
    sub(feed, "subtitle", "Malware C2/config hidden on public blockchains (EtherHiding). IOCs are defanged.")
    sub(feed, "updated", stix_ts(ds.generated_at, ds.generated_at))
    sub(feed, "link", href=f"{FEEDS_BASE_URL}/atom.xml", rel="self", type="application/atom+xml")
    sub(feed, "link", href=PROJECT_URL, rel="alternate", type="text/html")
    author = sub(feed, "author")
    sub(author, "name", PROJECT_NAME)
    sub(author, "uri", PROJECT_URL)
    sub(feed, "rights", DATA_LICENSE)
    for x in _atom_entries(ds):
        entry = sub(feed, "entry")
        sub(entry, "id", x["id"])
        sub(entry, "title", defang(x["title"]))
        sub(entry, "updated", stix_ts(x["updated"], ds.generated_at))
        if x["link"]:
            sub(entry, "link", href=x["link"], rel="alternate", type="text/html")
        if x["category"]:
            sub(entry, "category", term=x["category"])
        sub(entry, "summary", x["summary"], type="text")
    ET.indent(feed, space="  ")
    return b'<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(feed, encoding="utf-8",
                                                                     xml_declaration=False) + b"\n"


def export(ds: Dataset, out_dir: Path) -> list[tuple[Path, str]]:
    api = _Api(ds, out_dir)
    api.build()
    api.prune()
    index = api.write_index()
    written = [(index, "Static JSON API v1: endpoint index")]
    written += [(p, f"API: {d}") for p, d, _ in api.written]
    written.append((write_bytes(out_dir / "atom.xml", build_atom(ds)),
                    f"Atom feed of the newest {ATOM_LIMIT} rotations / new contracts (defanged)"))
    return written
