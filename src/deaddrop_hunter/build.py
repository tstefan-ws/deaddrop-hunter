"""Aggregate events into contracts / wallets / iocs / clusters / meta (docs/data-schema.md).

Pure and deterministic: same inputs (including ``now``) -> byte-identical output.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import timedelta

from . import __version__
from .classify import FAMILY_BY_SLUG, UNKNOWN, Ioc, classify, extract_iocs, is_dual_use
from .config import Config
from .decoders import decode_value, raw_bytes
from .store import parse_iso

SCHEMA_VERSION = 1
ACTIVE_DAYS = 30


# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------
class UnionFind:
    def __init__(self) -> None:
        self.parent: dict = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            if ra < rb:
                self.parent[rb] = ra
            else:
                self.parent[ra] = rb

    def groups(self) -> dict:
        out: dict = defaultdict(list)
        for x in list(self.parent):
            out[self.find(x)].append(x)
        return out


_EVM_ADDR = re.compile(r"0x[0-9a-f]{40}")


def is_evm_address(a: str | None) -> bool:
    return bool(a) and bool(_EVM_ADDR.fullmatch(a))


def cluster_id_for(wallets: Iterable[str]) -> str:
    """``c-`` + first 8 chars of the lowest operator address (after any ``0x``), lowercased.
    Works for EVM hex, Aptos 0x-64-hex and base58 (Tron/Solana) addresses."""
    low = min(wallets)
    body = low[2:] if low[:2].lower() == "0x" else low
    return "c-" + body[:8].lower()


def _min_ts(vals: Iterable[str | None]) -> str | None:
    v = [x for x in vals if x]
    return min(v) if v else None


def _max_ts(vals: Iterable[str | None]) -> str | None:
    v = [x for x in vals if x]
    return max(v) if v else None


def _top(counter: Counter, default=None):
    """Most common key; ties broken by sort order of the key (None sorts last)."""
    if not counter:
        return default
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0] is None, str(kv[0])))[0][0]


def _event_sort_key(e: dict) -> tuple:
    return (e.get("timestamp") or "", e.get("block") or 0, e["chain"], e["tx_hash"], e["contract"],
            e.get("hunt_id") or "", e.get("new_raw") or "")


def order_contract_events(evs: list[dict]) -> list[dict]:
    """Chronological order. Within one block, follow the old->new value chain so the
    'latest' value is the one no other same-block update overwrote."""
    evs = sorted(evs, key=lambda e: (e.get("block") or 0, e.get("timestamp") or "", e["tx_hash"],
                                     e.get("new_raw") or ""))
    out: list[dict] = []
    i = 0
    while i < len(evs):
        j = i
        while j < len(evs) and evs[j].get("block") == evs[i].get("block"):
            j += 1
        group = evs[i:j]
        if len(group) > 1:
            remaining = list(group)
            news = {e.get("new_raw") for e in remaining}
            starts = [e for e in remaining if e.get("old_raw") not in news] or [remaining[0]]
            cur = starts[0]
            while remaining:
                out.append(cur)
                remaining.remove(cur)
                nxt = [e for e in remaining if e.get("old_raw") == cur.get("new_raw")]
                if nxt:
                    cur = nxt[0]
                elif remaining:
                    cands = [e for e in remaining if e.get("old_raw") not in {r.get("new_raw") for r in remaining}]
                    cur = (cands or remaining)[0]
        else:
            out.extend(group)
        i = j
    return out


def normalize_event(e: dict) -> dict:
    """Re-run value decoders for events stored as undecoded (new decoders may match now)."""
    if e.get("decoder") == "undecoded" and e.get("new_raw") is not None:
        new_dec, dec = decode_value(raw_bytes(e["new_raw"]))
        if new_dec is not None:
            e = dict(e)
            e["new_decoded"], e["decoder"] = new_dec, dec
            if e.get("old_raw") is not None and e.get("old_decoded") is None:
                e["old_decoded"] = decode_value(raw_bytes(e["old_raw"]))[0]
    return e


# ---------------------------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------------------------
# Confidence for an account we have only circumstantial evidence for (a watched operator called
# it, but no value was ever decoded from it).
CANDIDATE_CONF = 55


def build(
    events: list[dict],
    config: Config,
    cursors: list[dict] | None = None,
    now: str = "1970-01-01T00:00:00Z",
    existing_iocs: list[dict] | None = None,
    previous: dict | None = None,
) -> dict:
    events = [normalize_event(e) for e in events]
    now_dt = parse_iso(now)
    assert now_dt is not None
    active_cutoff = (now_dt - timedelta(days=ACTIVE_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_cutoff = (now_dt - timedelta(hours=max(0, config.new_window_hours))).strftime("%Y-%m-%dT%H:%M:%SZ")
    prev = previous or {}
    prev_contracts = {(c.get("chain"), c.get("address")): c for c in prev.get("contracts") or []}
    prev_clusters = {c.get("id"): c for c in prev.get("clusters") or []}
    prev_iocs = {(i.get("type"), i.get("value"), i.get("port") if i.get("port") is not None else -1): i
                 for i in (existing_iocs if existing_iocs is not None else prev.get("iocs") or [])}

    def discovered(old: dict | None, fallback: str | None = None) -> str:
        """When this entry first entered our data, which is not when it appeared on-chain:
        a contract deployed in March but found today is new to the reader, not to the chain."""
        if old and old.get("discovered_at"):
            return old["discovered_at"]
        if old:                       # on file already, from before this field existed
            return old.get("first_seen") or fallback or now
        return now

    def is_new(discovered_at: str | None) -> bool:
        return bool(discovered_at) and discovered_at >= new_cutoff
    watched = config.watched()

    ioc_cache: dict[str, list[Ioc]] = {}

    def iocs_of(text: str | None) -> list[Ioc]:
        if not text:
            return []
        if text not in ioc_cache:
            ioc_cache[text] = extract_iocs(text)
        return ioc_cache[text]

    # --- group by contract -------------------------------------------------------------------
    by_contract: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in events:
        by_contract[(e["chain"], e["contract"])].append(e)

    uf = UnionFind()
    contract_info: dict[tuple[str, str], dict] = {}
    for key, evs in by_contract.items():
        chain, addr = key
        ordered = order_contract_events(evs)
        latest = ordered[-1]
        fam = classify(latest.get("new_decoded"))
        if fam is UNKNOWN:
            for e in reversed(ordered):
                for side in ("new_decoded", "old_decoded"):
                    f = classify(e.get(side))
                    if f is not UNKNOWN:
                        fam = f
                        break
                if fam is not UNKNOWN:
                    break
        operators = sorted({e["from"] for e in evs if e.get("from")})
        uf.find(("c", chain, addr))
        for w in operators:
            uf.union(("c", chain, addr), ("w", w))
        contract_info[key] = {
            "events": ordered,
            "latest": latest,
            "family": fam,
            "operators": operators,
            "first_seen": _min_ts(e.get("timestamp") for e in evs),
            "last_seen": _max_ts(e.get("timestamp") for e in evs),
        }

    # --- clusters (union-find over contract <-> operator wallet) ----------------------------
    node_cluster: dict = {}
    for _root, members in uf.groups().items():
        wallets = [m[1] for m in members if m[0] == "w"]
        if not wallets:
            continue
        cid = cluster_id_for(wallets)
        for m in members:
            node_cluster[m] = cid

    def contract_cluster(chain: str, addr: str) -> str | None:
        return node_cluster.get(("c", chain, addr))

    # --- IOCs from decoded values -------------------------------------------------------------
    agg: dict[tuple, dict] = {}

    def touch(ioc: Ioc, chain: str, contract: str, ts: str | None, ev_id: tuple | None, family: str,
              cluster: str | None) -> None:
        a = agg.setdefault(ioc.key, {
            "ioc": ioc, "contracts": set(), "ts": [], "events": set(), "conf": 0,
            "families": Counter(), "clusters": Counter(), "chains": Counter(),
        })
        a["contracts"].add(contract)
        a["ts"].append(ts)
        if ev_id is not None:
            a["events"].add(ev_id)
        a["conf"] = max(a["conf"], ioc.confidence)
        a["families"][family] += 1
        a["clusters"][cluster] += 1
        a["chains"][chain] += 1

    known_contracts = {addr for (_c, addr) in contract_info}
    for (chain, addr), info in contract_info.items():
        fam = info["family"].family
        cid = contract_cluster(chain, addr)
        for e in info["events"]:
            ev_id = (e["chain"], e["tx_hash"], e["contract"], e.get("new_raw") or "")
            for side in ("old_decoded", "new_decoded"):
                for ioc in iocs_of(e.get(side)):
                    if ioc.type == "evm-wallet" and ioc.value in known_contracts:
                        ioc = Ioc("evm-contract", ioc.value, None, ioc.confidence)
                    touch(ioc, chain, addr, e.get("timestamp"), ev_id, fam, cid)

    current_keys: set[tuple] = set()
    for info in contract_info.values():
        for ioc in iocs_of(info["latest"].get("new_decoded")):
            current_keys.add(ioc.key)
            if ioc.type == "evm-wallet" and ioc.value in known_contracts:
                current_keys.add(("evm-contract", ioc.value, -1))

    # Contracts and operator wallets are IOCs themselves. A contract we have never decoded a
    # value from is only a candidate: a watched operator touched it, nothing more. It is still
    # reported, at a confidence that says so, so it never looks as solid as a decoded dead drop.
    def has_decoded(info: dict) -> bool:
        return any(e.get("new_decoded") is not None or e.get("old_decoded") is not None
                   for e in info["events"])

    decoded_operators = {w for info in contract_info.values() if has_decoded(info)
                         for w in info["operators"]}
    for (chain, addr), info in contract_info.items():
        cid = contract_cluster(chain, addr)
        fam = info["family"].family
        active = (info["last_seen"] or "") >= active_cutoff
        if not is_evm_address(addr):
            continue  # schema IOC types only cover EVM accounts; non-EVM accounts stay in contracts/wallets
        cioc = Ioc("evm-contract", addr, None, 90 if has_decoded(info) else CANDIDATE_CONF)
        for e in info["events"]:
            touch(cioc, chain, addr, e.get("timestamp"), (e["chain"], e["tx_hash"], e["contract"],
                                                           e.get("new_raw") or ""), fam, cid)
        if active:
            current_keys.add(cioc.key)
        for w in info["operators"]:
            if not is_evm_address(w):
                continue
            wioc = Ioc("evm-wallet", w, None, 85 if w in decoded_operators else CANDIDATE_CONF)
            for e in info["events"]:
                if e.get("from") == w:
                    touch(wioc, chain, addr, e.get("timestamp"),
                          (e["chain"], e["tx_hash"], e["contract"], e.get("new_raw") or ""), fam, cid)
            if active:
                current_keys.add(wioc.key)

    enrichment_by_key: dict[tuple, dict] = {}
    for old in existing_iocs or []:
        try:
            k = (old["type"], old["value"], old["port"] if old.get("port") is not None else -1)
        except KeyError:
            continue
        if old.get("enrichment"):
            enrichment_by_key[k] = old["enrichment"]

    iocs_out: list[dict] = []
    for key in sorted(agg):
        a = agg[key]
        ioc: Ioc = a["ioc"]
        iocs_out.append({
            "type": ioc.type,
            "value": ioc.value,
            "port": ioc.port,
            "family": _top(a["families"], "unknown"),
            "cluster_id": _top(a["clusters"]),
            "chain": _top(a["chains"]),
            "contracts": sorted(a["contracts"]),
            "first_seen": _min_ts(a["ts"]),
            "last_seen": _max_ts(a["ts"]),
            "times_seen": len(a["events"]),
            "current": key in current_keys,
            "discovered_at": (_i_disc := discovered(prev_iocs.get(key), _min_ts(a["ts"]))),
            "new": is_new(_i_disc),
            "confidence": a["conf"],
            "dual_use": is_dual_use(ioc.type, ioc.value),
            "enrichment": enrichment_by_key.get(key, {}),
        })

    # --- contracts ----------------------------------------------------------------------------
    contracts_out: list[dict] = []
    for (chain, addr) in sorted(contract_info):
        info = contract_info[(chain, addr)]
        latest = info["latest"]
        fam = info["family"]
        evs = info["events"]
        contracts_out.append({
            "chain": chain,
            "address": addr,
            "cluster_id": contract_cluster(chain, addr),
            "family": fam.family,
            "hunt_ids": sorted({e["hunt_id"] for e in evs}),
            "operator_wallets": info["operators"],
            "selectors": sorted({e["selector"] for e in evs if e.get("selector")}),
            "decoder": latest.get("decoder") or "undecoded",
            "update_count": len(evs),
            "first_seen": info["first_seen"],
            "last_seen": info["last_seen"],
            "status": "active" if (info["last_seen"] or "") >= active_cutoff else "dormant",
            # The template this was compiled from. Survives a fresh wallet, a different
            # chain and a renamed event, which is what makes it worth keeping.
            "code_hash": next((e["code_hash"] for e in reversed(info["events"]) if e.get("code_hash")),
                              (prev_contracts.get((chain, addr)) or {}).get("code_hash")),
            "discovered_at": (_c_disc := discovered(prev_contracts.get((chain, addr)), info["first_seen"])),
            "new": is_new(_c_disc),
            "evidence": "decoded" if has_decoded(info) else "candidate",
            "latest_value_raw": latest.get("new_raw"),
            "latest_value_decoded": latest.get("new_decoded"),
            "tags": list(fam.tags),
        })

    # --- wallets ------------------------------------------------------------------------------
    wallets: dict[tuple[str, str], dict] = {}
    by_wallet: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in events:
        if e.get("from"):
            by_wallet[(e["chain"], e["from"])].append(e)
    for (chain, w), evs in by_wallet.items():
        ww = watched.get((chain, w))
        role = "operator" if any(e.get("new_raw") is not None for e in evs) else "deployer"
        wallets[(chain, w)] = {
            "chain": chain,
            "address": w,
            "role": role,
            "label": ww.label if ww else ("Operator (auto-detected)" if role == "operator"
                                          else "Deployer (auto-detected)"),
            "cluster_id": node_cluster.get(("w", w)),
            "contracts": sorted({e["contract"] for e in evs}),
            "tx_count": len({e["tx_hash"] for e in evs}),
            "first_seen": _min_ts(e.get("timestamp") for e in evs),
            "last_seen": _max_ts(e.get("timestamp") for e in evs),
            "watched": ww is not None,
            "funded_by": [],
        }
    for (chain, w), ww in watched.items():
        if (chain, w) not in wallets:
            wallets[(chain, w)] = {
                "chain": chain, "address": w, "role": "operator", "label": ww.label,
                "cluster_id": node_cluster.get(("w", w)), "contracts": [], "tx_count": 0,
                "first_seen": None, "last_seen": None, "watched": True, "funded_by": [],
            }
    payout_chain = {"xmr-wallet": "monero", "btc-wallet": "bitcoin"}
    for i in iocs_out:
        if i["type"] in payout_chain:
            wallets[(payout_chain[i["type"]], i["value"])] = {
                "chain": payout_chain[i["type"]],
                "address": i["value"],
                "role": "payout",
                "label": "Payout wallet found in decoded config",
                "cluster_id": i["cluster_id"],
                "contracts": i["contracts"],
                "tx_count": i["times_seen"],
                "first_seen": i["first_seen"],
                "last_seen": i["last_seen"],
                "watched": False,
                "funded_by": [],
            }
    wallets_out = [wallets[k] for k in sorted(wallets)]

    # --- clusters -----------------------------------------------------------------------------
    clusters: dict[str, dict] = {}
    for c in contracts_out:
        cid = c["cluster_id"]
        if not cid:
            continue
        cl = clusters.setdefault(cid, {"contracts": set(), "chains": set(), "wallets": set(),
                                       "families": Counter(), "ts": []})
        cl["contracts"].add(c["address"])
        cl["chains"].add(c["chain"])
        cl["wallets"].update(c["operator_wallets"])
        cl["families"][c["family"]] += 1
        cl["ts"] += [c["first_seen"], c["last_seen"]]
    ioc_counts = Counter(i["cluster_id"] for i in iocs_out if i["cluster_id"])
    clusters_out: list[dict] = []
    names = Counter()
    pre: list[tuple[str, dict, str]] = []
    for cid in sorted(clusters):
        cl = clusters[cid]
        fams = Counter({k: v for k, v in cl["families"].items() if k != "unknown"}) or cl["families"]
        family = _top(fams, "unknown")
        name = FAMILY_BY_SLUG.get(family, UNKNOWN).name
        names[name] += 1
        pre.append((cid, cl, family))
    for cid, cl, family in pre:
        name = FAMILY_BY_SLUG.get(family, UNKNOWN).name
        if names[name] > 1:
            name = f"{name} ({cid})"
        clusters_out.append({
            "id": cid,
            "name": name,
            "family": family,
            "chains": sorted(cl["chains"]),
            "contracts": sorted(cl["contracts"]),
            "wallets": sorted(cl["wallets"]),
            "ioc_count": ioc_counts.get(cid, 0),
            "first_seen": _min_ts(cl["ts"]),
            "last_seen": _max_ts(cl["ts"]),
            "discovered_at": (_cl_disc := discovered(prev_clusters.get(cid), _min_ts(cl["ts"]))),
            "new": is_new(_cl_disc),
        })

    events_out = sorted(events, key=_event_sort_key, reverse=True)
    cursors_out = sorted(cursors or [], key=lambda c: (c["chain"], c["hunt_id"]))
    meta = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now,
        "new_window_hours": config.new_window_hours,
        "scan_interval_minutes": config.scan_interval_minutes,
        "tool_version": __version__,
        "cursors": cursors_out,
        "counts": {
            "contracts": len(contracts_out),
            "wallets": len(wallets_out),
            "events": len(events_out),
            "iocs": len(iocs_out),
            "clusters": len(clusters_out),
        },
    }
    return {
        "meta": meta,
        "contracts": contracts_out,
        "wallets": wallets_out,
        "events": events_out,
        "iocs": iocs_out,
        "clusters": clusters_out,
    }
