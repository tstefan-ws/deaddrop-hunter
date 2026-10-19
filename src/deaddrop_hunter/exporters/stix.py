"""STIX 2.1 exporter (hand-built JSON, no stix2 dependency).

Output:
    stix/deaddrop-hunter.bundle.json      everything
    stix/clusters/<cluster_id>.json       one bundle per cluster (with a report SDO)

OpenCTI-specific bits (ignored by other STIX consumers):
    - ``cryptocurrency-wallet`` is an OpenCTI custom SCO (property ``value``).
    - ``x_opencti_*`` properties (main observable type, score, detection flag,
      created_by on SCOs, description on SCOs).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from ._common import (
    NETWORK_IOC_TYPES,
    PROJECT_NAME,
    PROJECT_URL,
    STIX_SCO_NAMESPACE,
    WALLET_IOC_TYPES,
    Dataset,
    chain_symbol,
    host_with_port,
    ioc_sort_key,
    safe_name,
    stix_ts,
    uid,
    write_json,
)

TLP_CLEAR_ID = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
TLP_CLEAR = {
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": TLP_CLEAR_ID,
    "created": "2022-10-01T00:00:00.000Z",
    "name": "TLP:CLEAR",
    "extensions": {
        "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
            "extension_type": "property-extension",
            "tlp_2_0": "clear",
        }
    },
}

IDENTITY_ID = f"identity--{uid('stix', 'identity', PROJECT_NAME)}"
# Fixed creation date for the project identity (deterministic, not "now").
IDENTITY_CREATED = "2026-10-19T00:00:00.000Z"
IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": IDENTITY_ID,
    "created": IDENTITY_CREATED,
    "modified": IDENTITY_CREATED,
    "name": PROJECT_NAME,
    "description": (
        "Open-source hunter for malware that hides C2/configuration on public "
        f"blockchains (EtherHiding). {PROJECT_URL}"
    ),
    "identity_class": "organization",
    "contact_information": PROJECT_URL,
    "object_marking_refs": [TLP_CLEAR_ID],
}

SCO_TYPES = {"ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name", "url": "url"}
OPENCTI_MAIN_TYPES = {
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "domain-name": "Domain-Name",
    "url": "Url",
}
SCO_ORDER = ("ipv4-addr", "ipv6-addr", "domain-name", "url", "cryptocurrency-wallet")
TYPE_ORDER = {
    t: i
    for i, t in enumerate(
        (
            "identity",
            "marking-definition",
            "malware",
            "infrastructure",
            "indicator",
            *SCO_ORDER,
            "relationship",
            "report",
        )
    )
}


def sco_id(sco_type: str, value: str) -> str:
    """STIX 2.1 deterministic SCO id: uuid5(SCO namespace, canonical id-contributing props)."""
    name = json.dumps({"value": value}, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    return f"{sco_type}--{uuid.uuid5(STIX_SCO_NAMESPACE, name)}"


def stix_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def pattern_for(sco_type: str, value: str) -> str:
    return f"[{sco_type}:value = '{stix_escape(value)}']"


def malware_identity(family: str | None, cluster: dict | None, cluster_id: str | None):
    """Return (key, name, aliases) for a family, or None to skip (unknown)."""
    if not family or family == "unknown":
        return None
    if family.startswith("xmrig"):
        return ("xmrig", "XMRig", family)
    if family == "c2-url":
        name = cluster["name"] if cluster else f"c2-url ({cluster_id or 'unclustered'})"
        return (f"c2-url|{cluster_id}", name, family)
    return (family, family, None)


class _Builder:
    def __init__(self, ds: Dataset):
        self.ds = ds
        self.gen = ds.generated_at
        self.objects: dict[str, dict] = {}
        self.members: dict[str, set[str]] = {}
        self.clusters = ds.clusters_by_id

    # -- helpers ---------------------------------------------------------------
    def _add(self, obj: dict, cluster_id: str | None) -> str:
        oid = obj["id"]
        existing = self.objects.get(oid)
        if existing is None:
            self.objects[oid] = obj
        else:
            # Merge time bounds for SDOs seen from several sources.
            for key, pick in (("created", min), ("first_seen", min), ("modified", max), ("last_seen", max)):
                if key in existing and key in obj:
                    existing[key] = pick(existing[key], obj[key])
        members = self.members.setdefault(oid, set())
        if cluster_id:
            members.add(cluster_id)
        return oid

    def _sdo(self, type_: str, key: tuple, created: str, modified: str, **props) -> dict:
        created_ts = stix_ts(created, self.gen)
        modified_ts = max(stix_ts(modified, self.gen), created_ts)
        obj = {
            "type": type_,
            "spec_version": "2.1",
            "id": f"{type_}--{uid('stix', type_, *key)}",
            "created_by_ref": IDENTITY_ID,
            "created": created_ts,
            "modified": modified_ts,
        }
        obj.update(props)
        obj["object_marking_refs"] = [TLP_CLEAR_ID]
        return obj

    def _sco(self, sco_type: str, value: str, cluster_id: str | None, description: str | None = None) -> str:
        oid = sco_id(sco_type, value)
        if oid not in self.objects:
            obj = {"type": sco_type, "spec_version": "2.1", "id": oid, "value": value}
            if description:
                obj["x_opencti_description"] = description
            obj["x_opencti_created_by_ref"] = IDENTITY_ID
            obj["object_marking_refs"] = [TLP_CLEAR_ID]
            self.objects[oid] = obj
        elif description and "x_opencti_description" not in self.objects[oid]:
            self.objects[oid]["x_opencti_description"] = description
        self.members.setdefault(oid, set())
        if cluster_id:
            self.members[oid].add(cluster_id)
        return oid

    def _rel(self, rel_type: str, src: str, tgt: str, first: str, last: str, cluster_id: str | None,
             description: str | None = None) -> str:
        props: dict = {"relationship_type": rel_type, "source_ref": src, "target_ref": tgt}
        if description:
            props["description"] = description
        obj = self._sdo("relationship", (rel_type, src, tgt), first, last, **props)
        return self._add(obj, cluster_id)

    # -- builders --------------------------------------------------------------
    def malware(self, family, cluster_id, first, last) -> str | None:
        cluster = self.clusters.get(cluster_id) if cluster_id else None
        ident = malware_identity(family, cluster, cluster_id)
        if ident is None:
            return None
        key, name, alias = ident
        oid = f"malware--{uid('stix', 'malware', key)}"
        if oid in self.objects:
            obj = self.objects[oid]
            if alias and alias != name and alias not in obj.get("aliases", []):
                obj["aliases"] = sorted([*obj.get("aliases", []), alias])
            self._add(self._sdo("malware", (key,), first, last, name=name, is_family=True), cluster_id)
            return oid
        props: dict = {"name": name, "is_family": True}
        if key == "xmrig":
            props["description"] = (
                "XMRig cryptocurrency miner deployed by malware whose mining configuration "
                "is stored on-chain (EtherHiding-style dead drop)."
            )
            props["malware_types"] = ["resource-exploitation"]
        elif family == "c2-url":
            props["description"] = (
                f"Unnamed malware that resolves its C2 URL from an on-chain dead-drop contract "
                f"(deaddrop-hunter cluster {cluster_id or 'unclustered'})."
            )
        else:
            props["description"] = f"Malware family '{family}' as classified by deaddrop-hunter."
        if alias and alias != name:
            props["aliases"] = [alias]
        obj = self._sdo("malware", (key,), first, last, **props)
        return self._add(obj, cluster_id)

    def build(self) -> None:
        ds = self.ds
        infra_by_contract: dict[tuple[str, str], str] = {}

        for c in sorted(ds.contracts, key=lambda x: (x["chain"], x["address"])):
            chain, addr, cid = c["chain"], c["address"], c.get("cluster_id")
            first, last = c.get("first_seen"), c.get("last_seen")
            desc = (
                f"On-chain dead drop (contract/account) on {chain} storing malware configuration/C2 data. "
                f"Family: {c.get('family') or 'unknown'}. Updates observed: {c.get('update_count', 0)}. "
                f"Decoder: {c.get('decoder') or 'undecoded'}. Status: {c.get('status') or 'unknown'}. "
                f"Cluster: {cid or 'none'}."
            )
            props: dict = {
                "name": f"{chain} contract {addr}",
                "description": desc,
                "infrastructure_types": ["command-and-control"],
                "first_seen": stix_ts(first, self.gen),
                "last_seen": stix_ts(last, self.gen),
            }
            url = ds.explorer_url(chain, addr)
            if url:
                host = url.split("/")[2]
                props["external_references"] = [{"source_name": host, "url": url}]
            labels = sorted({chain, *(c.get("tags") or []), *([c["family"]] if c.get("family") else [])})
            props["labels"] = labels
            infra = self._add(self._sdo("infrastructure", (chain, addr), first, last, **props), cid)
            infra_by_contract[(chain, addr)] = infra

            wallet = self._sco("cryptocurrency-wallet", addr, cid,
                               f"{chain_symbol(chain)} dead-drop contract/account on {chain}")
            self._rel("consists-of", infra, wallet, first, last, cid)

            mal = self.malware(c.get("family"), cid, first, last)
            if mal:
                self._rel("uses", mal, infra, first, last, cid)

        def infra_for(chain: str | None, addresses) -> list[str]:
            out = []
            for a in addresses or []:
                hit = infra_by_contract.get((chain, a)) if chain else None
                if hit is None:
                    hit = next((v for (ch, ad), v in infra_by_contract.items() if ad == a), None)
                if hit:
                    out.append(hit)
            return sorted(set(out))

        for w in sorted(ds.wallets, key=lambda x: (x["chain"], x["address"])):
            cid = w.get("cluster_id")
            desc = w.get("label") or f"{w.get('role', 'wallet')} wallet on {w['chain']}"
            wid = self._sco("cryptocurrency-wallet", w["address"], cid, desc)
            contract_chain = None if w.get("role") == "payout" else w["chain"]
            for infra in infra_for(contract_chain, w.get("contracts")):
                self._rel("related-to", wid, infra, w.get("first_seen"), w.get("last_seen"), cid,
                          description=f"Wallet role: {w.get('role', 'unknown')}")

        for ioc in sorted(ds.iocs, key=ioc_sort_key):
            cid = ioc.get("cluster_id")
            first, last = ioc.get("first_seen"), ioc.get("last_seen")
            itype = ioc.get("type")
            infras = infra_for(ioc.get("chain"), ioc.get("contracts"))
            if itype in WALLET_IOC_TYPES:
                wid = self._sco("cryptocurrency-wallet", ioc["value"], cid,
                                f"{itype} found by deaddrop-hunter")
                for infra in infras:
                    self._rel("related-to", wid, infra, first, last, cid)
                continue
            if itype not in NETWORK_IOC_TYPES:
                continue
            sco_type = SCO_TYPES[itype]
            sco = self._sco(sco_type, ioc["value"], cid)
            port = ioc.get("port")
            family = ioc.get("family") or "unknown"
            contracts = ", ".join(ioc.get("contracts") or []) or "none"
            desc = (
                f"{itype} {host_with_port(ioc)} extracted from on-chain dead-drop data "
                f"(chain {ioc.get('chain')}, contracts {contracts}). Family: {family}. "
                f"Cluster: {cid or 'none'}. Seen {ioc.get('times_seen', 0)} times; "
                f"currently {'served' if ioc.get('current') else 'no longer served'} by the contract."
            )
            labels = sorted({x for x in (family, ioc.get("chain"), PROJECT_NAME) if x})
            props = {
                "name": host_with_port(ioc),
                "description": desc,
                "indicator_types": ["malicious-activity"],
                "pattern": pattern_for(sco_type, ioc["value"]),
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": stix_ts(first, self.gen),
                "labels": labels,
                "confidence": int(ioc.get("confidence") or 0),
                "x_opencti_main_observable_type": OPENCTI_MAIN_TYPES[sco_type],
                "x_opencti_score": int(ioc.get("confidence") or 0),
                "x_opencti_detection": bool(ioc.get("current")),
            }
            if port:
                props["x_deaddrop_port"] = int(port)
            ind = self._add(
                self._sdo("indicator", (itype, ioc["value"], port or ""), first, last, **props), cid
            )
            self._rel("based-on", ind, sco, first, last, cid)
            mal = self.malware(ioc.get("family"), cid, first, last)
            if mal:
                self._rel("indicates", ind, mal, first, last, cid)
            for infra in infras:
                self._rel("consists-of", infra, sco, first, last, cid)

        self._reports()

    def _reports(self) -> None:
        for cl in sorted(self.ds.clusters, key=lambda x: x["id"]):
            cid = cl["id"]
            refs = sorted(oid for oid, m in self.members.items() if cid in m)
            if not refs:
                continue
            desc = (
                f"deaddrop-hunter cluster {cid} ({cl.get('family') or 'unknown'}): "
                f"{len(cl.get('contracts') or [])} contract(s) on {', '.join(cl.get('chains') or [])} "
                f"controlled by {len(cl.get('wallets') or [])} wallet(s); {cl.get('ioc_count', 0)} IOC(s). "
                f"Malware configuration / C2 data is stored on-chain (EtherHiding)."
            )
            rep = self._sdo(
                "report", ("cluster", cid), cl.get("first_seen"), cl.get("last_seen"),
                name=f"{PROJECT_NAME}: {cl.get('name') or cid}",
                description=desc,
                report_types=["threat-report"],
                published=stix_ts(cl.get("last_seen"), self.gen),
                labels=sorted({PROJECT_NAME, *(cl.get("chains") or []),
                               *([cl["family"]] if cl.get("family") else [])}),
                object_refs=refs,
            )
            self._add(rep, cid)

    # -- output ----------------------------------------------------------------
    @staticmethod
    def _sorted(objs) -> list[dict]:
        return sorted(objs, key=lambda o: (TYPE_ORDER.get(o["type"], 99), o["id"]))

    def bundle(self, key: str, ids=None) -> dict:
        objs = [IDENTITY, TLP_CLEAR]
        objs += [o for oid, o in self.objects.items() if ids is None or oid in ids]
        return {
            "type": "bundle",
            "id": f"bundle--{uid('stix', 'bundle', key)}",
            "objects": self._sorted(objs),
        }


def build_bundles(ds: Dataset) -> tuple[dict, dict[str, dict]]:
    b = _Builder(ds)
    b.build()
    full = b.bundle("all")
    per_cluster: dict[str, dict] = {}
    for cl in sorted(ds.clusters, key=lambda x: x["id"]):
        cid = cl["id"]
        ids = {oid for oid, m in b.members.items() if cid in m}
        if ids:
            per_cluster[cid] = b.bundle(f"cluster|{cid}", ids)
    return full, per_cluster


def export(ds: Dataset, out_dir: Path) -> list[tuple[Path, str]]:
    stix_dir = out_dir / "stix"
    clusters_dir = stix_dir / "clusters"
    full, per_cluster = build_bundles(ds)
    if clusters_dir.exists():  # drop bundles of clusters that no longer exist
        for stale in clusters_dir.glob("c-*.json"):
            if stale.stem not in {safe_name(c) for c in per_cluster}:
                stale.unlink()
    written = [(write_json(stix_dir / "deaddrop-hunter.bundle.json", full),
                "STIX 2.1 bundle with every indicator, observable, contract and cluster report")]
    for cid, bundle in per_cluster.items():
        written.append((write_json(clusters_dir / f"{safe_name(cid)}.json", bundle),
                        f"STIX 2.1 bundle for cluster {cid}"))
    return written
