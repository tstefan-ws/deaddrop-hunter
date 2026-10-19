from __future__ import annotations

import csv
import hashlib
import json
import uuid

from deaddrop_hunter.exporters.misp import COIN_ADDRESS_TEMPLATE_UUID

MANIFEST_KEYS = {"Orgc", "Tag", "info", "date", "analysis", "threat_level_id", "timestamp"}


def _events(out):
    misp = out / "misp"
    return {
        p.stem: json.loads(p.read_text(encoding="utf-8"))
        for p in misp.glob("*.json")
        if p.name != "manifest.json"
    }


def test_manifest_matches_event_files(exported):
    out, _ = exported
    manifest = json.loads((out / "misp" / "manifest.json").read_text(encoding="utf-8"))
    events = _events(out)
    assert set(manifest) == set(events)
    for ev_uuid, entry in manifest.items():
        uuid.UUID(ev_uuid)
        assert set(entry) == MANIFEST_KEYS
        ev = events[ev_uuid]["Event"]
        assert ev["uuid"] == ev_uuid
        for key in MANIFEST_KEYS:
            assert entry[key] == ev[key], key


def test_hashes_csv_consistent(exported):
    out, _ = exported
    events = _events(out)
    rows = list(csv.reader((out / "misp" / "hashes.csv").read_text(encoding="utf-8").splitlines()))
    assert rows
    expected = set()
    for ev_uuid, doc in events.items():
        ev = doc["Event"]
        attrs = list(ev["Attribute"]) + [a for o in ev["Object"] for a in o["Attribute"]]
        for a in attrs:
            if a["disable_correlation"]:
                continue
            parts = a["value"].split("|") if "|" in a["type"] else [a["value"]]
            expected |= {(hashlib.md5(p.encode()).hexdigest(), ev_uuid) for p in parts}
    assert {tuple(r) for r in rows} == expected
    for h, ev_uuid in rows:
        assert len(h) == 32 and ev_uuid in events


def test_event_contents(exported, fixture_data):
    out, _ = exported
    events = {d["Event"]["info"]: d["Event"] for d in _events(out).values()}
    for cl in fixture_data["clusters"]:
        assert f"deaddrop-hunter: {cl['name']}" in events
    stealth = events["deaddrop-hunter: Stealth XMRig config cluster"]
    tags = {t["name"] for t in stealth["Tag"]}
    assert {"tlp:clear", 'deaddrop-hunter:family="xmrig-stealth"', 'deaddrop-hunter:chain="polygon"'} <= tags
    values = {(a["type"], a["value"]) for a in stealth["Attribute"]}
    assert ("ip-dst|port", "78.40.198.61|31270") in values
    assert ("hostname|port", "xmr-eu1.nanopool.org|10343") in values
    assert all(a["to_ids"] for a in stealth["Attribute"])
    # timestamp derived from cluster last_seen (2026-10-18T09:12:44Z)
    assert stealth["timestamp"] == "1792314764" == stealth["publish_timestamp"]
    assert stealth["date"] == "2026-08-01"

    c2 = events["deaddrop-hunter: C2 URL rotation cluster"]
    c2_values = {(a["type"], a["value"]) for a in c2["Attribute"]}
    assert ("ip-dst", "185.10.68.110") in c2_values
    assert ("ip-dst", "144.31.108.193") in c2_values
    assert ("url", "https://144.31.108.193/gate.php") in c2_values

    unclustered = next(e for i, e in events.items() if "unclustered" in i)
    assert {a["type"] for a in unclustered["Attribute"]} >= {"domain", "ip-dst|port", "url"}


def test_coin_address_objects(exported):
    out, _ = exported
    symbols = {}
    for doc in _events(out).values():
        for obj in doc["Event"]["Object"]:
            assert obj["name"] == "coin-address"
            assert obj["template_uuid"] == COIN_ADDRESS_TEMPLATE_UUID
            rel = {a["object_relation"]: a for a in obj["Attribute"]}
            addr_rel = next(r for r in ("address", "address-xmr", "address-crypto") if r in rel)
            symbols[rel[addr_rel]["value"]] = (addr_rel, rel["symbol"]["value"])
    assert symbols["0x17fff8d3f56574a85840d12af91b9d8f4178f85b"] == ("address-crypto", "POL")
    assert symbols["0x19532c0fbaf0fb8c1d0f3fac0b704bf2f4645539"] == ("address-crypto", "POL")
    xmr = next(k for k in symbols if k.startswith("49Fixture"))
    assert symbols[xmr] == ("address-xmr", "XMR")
    sol = next(k for k in symbols if k.startswith("GwrmFixtureDead"))
    assert symbols[sol] == ("address-crypto", "SOL")
    bsc = "0xfeed000000000000000000000000000000000004"
    assert symbols[bsc] == ("address-crypto", "BNB")


def test_uuids_unique(exported):
    out, _ = exported
    seen = set()
    for doc in _events(out).values():
        ev = doc["Event"]
        items = [ev] + ev["Attribute"] + ev["Object"] + [a for o in ev["Object"] for a in o["Attribute"]]
        for item in items:
            assert item["uuid"] not in seen
            seen.add(item["uuid"])
