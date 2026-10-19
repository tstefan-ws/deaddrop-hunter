from __future__ import annotations

import json
import re
import uuid
from collections import Counter

import pytest

from deaddrop_hunter.exporters.stix import TLP_CLEAR_ID, sco_id

SDO_SRO_REQUIRED = ("type", "spec_version", "id", "created", "modified")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
ID_RE = re.compile(r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SCO_TYPES = {"ipv4-addr", "ipv6-addr", "domain-name", "url", "cryptocurrency-wallet"}
PATTERN_RE = re.compile(
    r"^\[(ipv4-addr|ipv6-addr|domain-name|url):value = '((?:[^'\\]|\\['\\])*)'\]$"
)


def _objs(bundle, type_):
    return [o for o in bundle["objects"] if o["type"] == type_]


def test_bundle_shape(bundle):
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert "spec_version" not in bundle  # STIX 2.1 bundles have no spec_version


def test_required_properties_and_ids(bundle):
    ids = [o["id"] for o in bundle["objects"]]
    assert len(ids) == len(set(ids)), "duplicate STIX ids"
    for o in bundle["objects"]:
        assert ID_RE.match(o["id"]), o["id"]
        assert o["id"].split("--")[0] == o["type"]
        assert o["spec_version"] == "2.1"
        if o["type"] in SCO_TYPES:
            assert o["value"]
            assert o["object_marking_refs"] == [TLP_CLEAR_ID]
            continue
        if o["type"] == "marking-definition":
            assert o["id"] == TLP_CLEAR_ID and TS_RE.match(o["created"])
            continue
        for key in SDO_SRO_REQUIRED:
            assert key in o, f"{o['id']} missing {key}"
        assert TS_RE.match(o["created"]) and TS_RE.match(o["modified"])
        assert o["modified"] >= o["created"]
        assert o["object_marking_refs"] == [TLP_CLEAR_ID]
        if o["type"] != "identity":
            assert o["created_by_ref"].startswith("identity--")


def test_all_refs_resolve(bundle):
    ids = {o["id"] for o in bundle["objects"]}
    for o in bundle["objects"]:
        for key, value in o.items():
            refs = value if key.endswith("_refs") else [value] if key.endswith("_ref") else []
            for ref in refs:
                assert ref in ids, f"{o['id']}.{key} -> {ref} does not resolve"


def test_indicators(bundle, fixture_data):
    indicators = _objs(bundle, "indicator")
    network = [i for i in fixture_data["iocs"] if i["type"] in ("ipv4", "ipv6", "domain", "url")]
    assert len(indicators) == len(network)
    for ind in indicators:
        assert ind["pattern_type"] == "stix"
        m = PATTERN_RE.match(ind["pattern"])
        assert m, ind["pattern"]
        assert TS_RE.match(ind["valid_from"])
        assert 0 <= ind["confidence"] <= 100
        assert ind["labels"]
    patterns = {i["pattern"] for i in indicators}
    assert "[ipv4-addr:value = '78.40.198.61']" in patterns
    assert "[domain-name:value = 'xmr-eu1.nanopool.org']" in patterns
    assert "[url:value = 'http://dead-drop-fixture.example/it\\'s?a=1\\\\b']" in patterns
    xmrig = next(i for i in indicators if i["pattern"] == "[ipv4-addr:value = '78.40.198.61']")
    assert {"xmrig-stealth", "polygon"} <= set(xmrig["labels"])
    assert xmrig["valid_from"] == "2026-08-01T10:00:00.000Z"
    assert xmrig["x_opencti_detection"] is True


def test_patterns_parse_with_stix2_patterns(bundle):
    validator = pytest.importorskip("stix2patterns.validator")
    for ind in _objs(bundle, "indicator"):
        assert validator.run_validator(ind["pattern"], stix_version="2.1") == [], ind["pattern"]


def test_sco_ids_follow_spec(bundle):
    for o in bundle["objects"]:
        if o["type"] in SCO_TYPES:
            assert o["id"] == sco_id(o["type"], o["value"])
            assert uuid.UUID(o["id"].split("--")[1]).version == 5


def test_relationships(bundle):
    by_id = {o["id"]: o for o in bundle["objects"]}
    rels = _objs(bundle, "relationship")
    kinds = Counter(r["relationship_type"] for r in rels)
    for kind in ("based-on", "indicates", "consists-of", "uses", "related-to"):
        assert kinds[kind] > 0, kind
    for r in rels:
        src, tgt = by_id[r["source_ref"]]["type"], by_id[r["target_ref"]]["type"]
        allowed = {
            "based-on": ({"indicator"}, SCO_TYPES),
            "indicates": ({"indicator"}, {"malware"}),
            "consists-of": ({"infrastructure"}, SCO_TYPES),
            "uses": ({"malware"}, {"infrastructure"}),
            "related-to": ({"cryptocurrency-wallet"}, {"infrastructure"}),
        }[r["relationship_type"]]
        assert src in allowed[0] and tgt in allowed[1], r


def test_malware_naming(bundle):
    malware = {m["name"]: m for m in _objs(bundle, "malware")}
    assert "XMRig" in malware
    assert {"xmrig", "xmrig-stealth"} <= set(malware["XMRig"]["aliases"])
    assert "C2 URL rotation cluster" in malware  # c2-url named after its cluster
    assert "glassworm" in malware
    assert "unknown" not in malware
    assert all(m["is_family"] is True for m in malware.values())


def test_infrastructure(bundle, fixture_data):
    infra = {i["name"]: i for i in _objs(bundle, "infrastructure")}
    assert len(infra) == len(fixture_data["contracts"])
    poly = infra["polygon contract 0x17fff8d3f56574a85840d12af91b9d8f4178f85b"]
    assert poly["infrastructure_types"] == ["command-and-control"]
    assert "21" in poly["description"] and "xor-1byte:0x5a" in poly["description"]
    assert poly["external_references"][0]["url"] == (
        "https://polygonscan.com/address/0x17fff8d3f56574a85840d12af91b9d8f4178f85b"
    )
    sol = next(v for k, v in infra.items() if k.startswith("solana contract "))
    assert sol["external_references"][0]["url"].startswith("https://solscan.io/account/Gwrm")


def test_wallets_are_opencti_cryptocurrency_wallets(bundle, fixture_data):
    values = {o["value"] for o in _objs(bundle, "cryptocurrency-wallet")}
    for c in fixture_data["contracts"]:
        assert c["address"] in values
    for w in fixture_data["wallets"]:
        assert w["address"] in values


def test_identity_and_reports(bundle, fixture_data):
    ident = _objs(bundle, "identity")
    assert len(ident) == 1 and ident[0]["name"] == "deaddrop-hunter"
    reports = _objs(bundle, "report")
    assert len(reports) == len(fixture_data["clusters"])


def test_cluster_bundles(exported, fixture_data):
    out, _ = exported
    for cl in fixture_data["clusters"]:
        path = out / "stix" / "clusters" / f"{cl['id']}.json"
        b = json.loads(path.read_text(encoding="utf-8"))
        ids = {o["id"] for o in b["objects"]}
        report = next(o for o in b["objects"] if o["type"] == "report")
        assert set(report["object_refs"]) <= ids
        for o in b["objects"]:
            for ref in [o.get("source_ref"), o.get("target_ref"), o.get("created_by_ref")]:
                assert ref is None or ref in ids


def test_stix2_library_parses_bundle(bundle):
    stix2 = pytest.importorskip("stix2")
    parsed = stix2.parse(json.dumps(bundle), allow_custom=True)
    assert len(parsed.objects) == len(bundle["objects"])
    # Standard SCO ids must match what stix2 itself would derive.
    ip = stix2.IPv4Address(value="78.40.198.61")
    assert ip.id == sco_id("ipv4-addr", "78.40.198.61")
