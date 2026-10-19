"""MISP feed exporter (standard MISP feed layout, as produced by PyMISP's feed generator).

Output (``misp/``):
    manifest.json     {event_uuid: {Orgc, Tag, info, date, analysis, threat_level_id, timestamp}}
    hashes.csv        ``<md5 of attribute value>,<event uuid>`` per attribute value
                      (composite values such as ``ip-dst|port`` are hashed per part)
    <event_uuid>.json ``{"Event": {...}}`` one per cluster (+ one for unclustered data)
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from ._common import (
    NETWORK_IOC_TYPES,
    PROJECT_NAME,
    Dataset,
    chain_symbol,
    epoch,
    ioc_sort_key,
    parse_ts,
    uid,
    write_bytes,
    write_json,
)

ORG = {"name": PROJECT_NAME, "uuid": uid("misp", "org", PROJECT_NAME)}
UNCLUSTERED = "unclustered"

COIN_ADDRESS_TEMPLATE_UUID = "d0e6997e-78da-4815-a6a1-cfc1c1cb8a46"
COIN_ADDRESS_TEMPLATE_VERSION = "7"

TAG_COLOURS = {"tlp:clear": "#ffffff"}
DEFAULT_TAG_COLOUR = "#1f6feb"


def _tag(name: str) -> dict:
    return {"name": name, "colour": TAG_COLOURS.get(name, DEFAULT_TAG_COLOUR)}


def _misp_dt(value: str | None, fallback: str) -> str:
    dt = parse_ts(value) or parse_ts(fallback)
    assert dt is not None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def _date(value: str | None, fallback: str) -> str:
    dt = parse_ts(value) or parse_ts(fallback)
    assert dt is not None
    return dt.strftime("%Y-%m-%d")


def _network_attribute(ioc: dict) -> tuple[str, str] | None:
    """Map an IOC to (misp type, value)."""
    t, v, port = ioc.get("type"), ioc["value"], ioc.get("port")
    if t in ("ipv4", "ipv6"):
        return ("ip-dst|port", f"{v}|{port}") if port else ("ip-dst", v)
    if t == "domain":
        return ("hostname|port", f"{v}|{port}") if port else ("domain", v)
    if t == "url":
        return ("url", v)
    return None


def _coin_symbol(kind: str, chain: str | None) -> str:
    if kind == "xmr-wallet":
        return "XMR"
    if kind == "btc-wallet":
        return "BTC"
    return chain_symbol(chain)


def _address_relation(symbol: str) -> tuple[str, str]:
    """coin-address object relation + attribute type for a coin symbol."""
    if symbol == "BTC":
        return "address", "btc"
    if symbol == "XMR":
        return "address-xmr", "xmr"
    return "address-crypto", "text"


class _EventBuilder:
    def __init__(self, key: str, info: str, first: str | None, last: str | None, gen: str):
        self.uuid = uid("misp", "event", key)
        self.key = key
        self.info = info
        self.gen = gen
        self.first = first
        self.last = last
        self.families: set[str] = set()
        self.chains: set[str] = set()
        self.attributes: dict[str, dict] = {}
        self.objects: dict[str, dict] = {}

    def _bounds(self, first, last):
        if first and (not self.first or first < self.first):
            self.first = first
        if last and (not self.last or last > self.last):
            self.last = last

    def add_ioc(self, ioc: dict) -> None:
        mapped = _network_attribute(ioc)
        if mapped is None:
            return
        mtype, value = mapped
        first, last = ioc.get("first_seen"), ioc.get("last_seen")
        self._bounds(first, last)
        if ioc.get("family"):
            self.families.add(ioc["family"])
        if ioc.get("chain"):
            self.chains.add(ioc["chain"])
        auuid = uid("misp", "attribute", self.uuid, mtype, value)
        comment = (
            f"family={ioc.get('family') or 'unknown'}; chain={ioc.get('chain')}; "
            f"contracts={','.join(ioc.get('contracts') or []) or 'none'}; "
            f"current={'yes' if ioc.get('current') else 'no'}; "
            f"times_seen={ioc.get('times_seen', 0)}; confidence={ioc.get('confidence', 0)}"
        )
        tags = [_tag(f'{PROJECT_NAME}:current="{"true" if ioc.get("current") else "false"}"')]
        self.attributes[auuid] = {
            "uuid": auuid,
            "type": mtype,
            "category": "Network activity",
            "value": value,
            "to_ids": True,
            "comment": comment,
            "timestamp": str(epoch(last, self.gen)),
            "first_seen": _misp_dt(first, self.gen),
            "last_seen": _misp_dt(last, self.gen),
            "disable_correlation": False,
            "deleted": False,
            "Tag": tags,
        }

    def add_coin(self, address: str, symbol: str, role: str, first, last, comment: str) -> None:
        self._bounds(first, last)
        ouuid = uid("misp", "object", self.uuid, "coin-address", address)
        relation, atype = _address_relation(symbol)
        ts = str(epoch(last, self.gen))
        if ouuid in self.objects:
            obj = self.objects[ouuid]
            roles = set(obj["comment"].split(": ", 1)[0].split("/")) | {role}
            obj["comment"] = "/".join(sorted(roles)) + ": " + obj["comment"].split(": ", 1)[1]
            return

        def attr(rel, typ, value, category, correlate=True):
            return {
                "uuid": uid("misp", "object-attribute", ouuid, rel),
                "object_relation": rel,
                "type": typ,
                "category": category,
                "value": value,
                "to_ids": False,
                "comment": "",
                "timestamp": ts,
                "disable_correlation": not correlate,
                "deleted": False,
            }

        attrs = [
            attr(relation, atype, address, "Financial fraud"),
            attr("symbol", "text", symbol, "Other", correlate=False),
        ]
        if first:
            attrs.append(attr("first-seen", "datetime", _misp_dt(first, self.gen), "Other", False))
        if last:
            attrs.append(attr("last-seen", "datetime", _misp_dt(last, self.gen), "Other", False))
        self.objects[ouuid] = {
            "uuid": ouuid,
            "name": "coin-address",
            "meta-category": "financial",
            "description": "An address used in a cryptocurrency",
            "template_uuid": COIN_ADDRESS_TEMPLATE_UUID,
            "template_version": COIN_ADDRESS_TEMPLATE_VERSION,
            "timestamp": ts,
            "comment": f"{role}: {comment}",
            "deleted": False,
            "Attribute": attrs,
        }

    def tags(self) -> list[dict]:
        names = ["tlp:clear"]
        names += [f'{PROJECT_NAME}:family="{f}"' for f in sorted(self.families)]
        names += [f'{PROJECT_NAME}:chain="{c}"' for c in sorted(self.chains)]
        return [_tag(n) for n in names]

    def event(self) -> dict:
        ts = str(epoch(self.last, self.gen))
        return {
            "uuid": self.uuid,
            "info": self.info,
            "date": _date(self.first, self.gen),
            "threat_level_id": "2",
            "analysis": "1",
            "published": True,
            "timestamp": ts,
            "publish_timestamp": ts,
            "Orgc": dict(ORG),
            "Tag": self.tags(),
            "Attribute": [self.attributes[k] for k in sorted(self.attributes,
                                                            key=lambda k: (self.attributes[k]["type"],
                                                                           self.attributes[k]["value"]))],
            "Object": [
                self.objects[k]
                for k in sorted(self.objects, key=lambda k: self.objects[k]["Attribute"][0]["value"])
            ],
        }

    def manifest_entry(self) -> dict:
        ev = self.event()
        return {
            "Orgc": ev["Orgc"],
            "Tag": ev["Tag"],
            "info": ev["info"],
            "date": ev["date"],
            "analysis": ev["analysis"],
            "threat_level_id": ev["threat_level_id"],
            "timestamp": ev["timestamp"],
        }


def attribute_hashes(event: dict) -> list[str]:
    """MD5 per attribute value part, as PyMISP's ``attributes_hashes('md5')``.

    Composite values (``ip-dst|port``) are hashed per part. Attributes with
    ``disable_correlation`` (coin symbol, first/last-seen) are skipped, and each hash is
    listed once per event, so MISP's feed-correlation cache only sees real IOCs.
    """
    out: list[str] = []
    attrs = list(event.get("Attribute", []))
    for obj in event.get("Object", []):
        attrs += obj.get("Attribute", [])
    for a in attrs:
        if a.get("disable_correlation"):
            continue
        parts = a["value"].split("|") if "|" in a["type"] else [a["value"]]
        for part in parts:
            digest = hashlib.md5(part.encode("utf-8")).hexdigest()
            if digest not in out:
                out.append(digest)
    return out


def build_events(ds: Dataset) -> list[dict]:
    gen = ds.generated_at
    builders: dict[str, _EventBuilder] = {}
    for cl in sorted(ds.clusters, key=lambda x: x["id"]):
        b = _EventBuilder(cl["id"], f"{PROJECT_NAME}: {cl.get('name') or cl['id']}",
                          cl.get("first_seen"), cl.get("last_seen"), gen)
        if cl.get("family"):
            b.families.add(cl["family"])
        b.chains.update(cl.get("chains") or [])
        builders[cl["id"]] = b

    def builder_for(cluster_id: str | None) -> _EventBuilder:
        key = cluster_id if cluster_id in builders else UNCLUSTERED
        if key not in builders:
            builders[key] = _EventBuilder(
                UNCLUSTERED, f"{PROJECT_NAME}: unclustered dead-drop indicators", None, None, gen
            )
        return builders[key]

    for c in sorted(ds.contracts, key=lambda x: (x["chain"], x["address"])):
        b = builder_for(c.get("cluster_id"))
        b.chains.add(c["chain"])
        if c.get("family"):
            b.families.add(c["family"])
        url = ds.explorer_url(c["chain"], c["address"])
        b.add_coin(c["address"], chain_symbol(c["chain"]), "contract",
                   c.get("first_seen"), c.get("last_seen"),
                   f"dead-drop contract on {c['chain']}, family {c.get('family') or 'unknown'}, "
                   f"{c.get('update_count', 0)} updates, decoder {c.get('decoder') or 'undecoded'}"
                   + (f", {url}" if url else ""))
    for w in sorted(ds.wallets, key=lambda x: (x["chain"], x["address"])):
        b = builder_for(w.get("cluster_id"))
        b.add_coin(w["address"], chain_symbol(w["chain"]), w.get("role") or "wallet",
                   w.get("first_seen"), w.get("last_seen"), w.get("label") or f"wallet on {w['chain']}")
    for ioc in sorted(ds.iocs, key=ioc_sort_key):
        b = builder_for(ioc.get("cluster_id"))
        if ioc.get("type") in NETWORK_IOC_TYPES:
            b.add_ioc(ioc)
        elif ioc.get("type") in ("xmr-wallet", "btc-wallet", "evm-contract", "evm-wallet"):
            b.add_coin(ioc["value"], _coin_symbol(ioc["type"], ioc.get("chain")), ioc["type"],
                       ioc.get("first_seen"), ioc.get("last_seen"),
                       f"found in on-chain config of {','.join(ioc.get('contracts') or []) or 'n/a'}")

    events = []
    for b in sorted(builders.values(), key=lambda x: x.uuid):
        if b.attributes or b.objects:
            events.append(b)
    return events


def export(ds: Dataset, out_dir: Path) -> list[tuple[Path, str]]:
    misp_dir = out_dir / "misp"
    builders = build_events(ds)
    keep = {f"{b.uuid}.json" for b in builders} | {"manifest.json"}
    if misp_dir.exists():  # drop events that no longer exist
        for stale in misp_dir.glob("*.json"):
            if stale.name not in keep:
                stale.unlink()
    written: list[tuple[Path, str]] = []
    manifest: dict[str, dict] = {}
    hash_lines: list[str] = []
    for b in builders:
        ev = b.event()
        written.append((write_json(misp_dir / f"{b.uuid}.json", {"Event": ev}),
                        f"MISP event: {b.info}"))
        manifest[b.uuid] = b.manifest_entry()
        hash_lines += [f"{h},{b.uuid}" for h in attribute_hashes(ev)]
    written.insert(0, (write_json(misp_dir / "manifest.json", manifest),
                       "MISP feed manifest (add .../feeds/misp/ as a MISP Feed in MISP)"))
    written.insert(1, (write_bytes(misp_dir / "hashes.csv", "".join(f"{x}\n" for x in hash_lines).encode()),
                       "MISP feed attribute hashes (md5,event_uuid)"))
    return written

