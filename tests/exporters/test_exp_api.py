from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET

from deaddrop_hunter.exporters._common import load_dataset
from deaddrop_hunter.exporters.api import ATOM_NS, build_atom, defang

WRAPPER_KEYS = ["schema_version", "generated_at", "license", "count", "data"]


def _load(out, rel):
    return json.loads((out / "api" / "v1" / rel).read_text(encoding="utf-8"))


def test_all_api_files_valid_and_wrapped(exported):
    out, _ = exported
    files = sorted((out / "api" / "v1").rglob("*.json"))
    assert files
    for path in files:
        doc = json.loads(path.read_text(encoding="utf-8"))
        assert list(doc) == WRAPPER_KEYS, path
        assert doc["schema_version"] == 1
        assert doc["generated_at"] == "2026-10-19T12:00:00Z"
        assert doc["license"] == "TLP:CLEAR, CC0-1.0 data"
        if isinstance(doc["data"], list):
            assert doc["count"] == len(doc["data"])


def test_api_index_consistent(exported):
    out, _ = exported
    root = out / "api" / "v1"
    index = _load(out, "index.json")
    listed = {e["path"] for e in index["data"]}
    on_disk = {p.relative_to(root).as_posix() for p in root.rglob("*.json")} - {"index.json"}
    assert listed == on_disk
    for e in index["data"]:
        assert e["sha256"] == hashlib.sha256((root / e["path"]).read_bytes()).hexdigest()
        assert e["url"] == f"https://tstefan-ws.github.io/deaddrop-hunter/feeds/api/v1/{e['path']}"
        assert e["count"] == _load(out, e["path"])["count"]
    # API files are also in the top-level index.json (dashboard Feeds page)
    top = {e["path"] for e in json.loads((out / "index.json").read_text(encoding="utf-8"))["files"]}
    assert {f"api/v1/{p}" for p in listed} | {"api/v1/index.json", "atom.xml"} <= top


def test_endpoints_match_data(exported, fixture_data):
    out, _ = exported
    iocs = fixture_data["iocs"]
    assert _load(out, "iocs.json")["count"] == len(iocs)
    assert _load(out, "iocs/current.json")["count"] == sum(1 for i in iocs if i["current"])
    for t in {i["type"] for i in iocs}:
        assert {i["value"] for i in _load(out, f"iocs/{t}.json")["data"]} == {
            i["value"] for i in iocs if i["type"] == t
        }
    assert _load(out, "iocs/btc-wallet.json")["count"] == 0  # stable URL, even when empty
    for fam in {i["family"] for i in iocs}:
        assert _load(out, f"families/{fam}.json")["count"] == sum(1 for i in iocs if i["family"] == fam)
    for chain in {i["chain"] for i in iocs}:
        assert _load(out, f"chains/{chain}.json")["count"] == sum(1 for i in iocs if i["chain"] == chain)
    assert _load(out, "contracts.json")["count"] == len(fixture_data["contracts"])
    assert _load(out, "wallets.json")["count"] == len(fixture_data["wallets"])
    assert _load(out, "clusters.json")["count"] == len(fixture_data["clusters"])
    for rec in _load(out, "iocs.json")["data"] + _load(out, "contracts.json")["data"]:
        assert rec["first_seen"]


def test_contract_detail(exported, fixture_data):
    out, _ = exported
    for c in fixture_data["contracts"]:
        doc = _load(out, f"contracts/{c['chain']}/{c['address']}.json")
        d = doc["data"]
        assert d["address"] == c["address"] and doc["count"] == 1
        assert [e["tx_hash"] for e in d["events"]] == [
            e["tx_hash"] for e in fixture_data["events"]
            if e["contract"] == c["address"] and e["chain"] == c["chain"]
        ]
        assert {i["value"] for i in d["iocs"]} == {
            i["value"] for i in fixture_data["iocs"]
            if i["chain"] == c["chain"] and c["address"] in i["contracts"]
        }
    sol = next(c for c in fixture_data["contracts"] if c["chain"] == "solana")
    detail = _load(out, f"contracts/solana/{sol['address']}.json")["data"]
    assert detail["explorer_url"] == f"https://solscan.io/account/{sol['address']}"
    assert detail["events"][0]["old_raw"] is None


def test_changes_newest_first(exported, fixture_data):
    out, _ = exported
    data = _load(out, "changes.json")["data"]
    assert len(data) == len(fixture_data["events"])
    stamps = [e["timestamp"] for e in data]
    assert stamps == sorted(stamps, reverse=True)
    assert all(e["first_seen"] == e["timestamp"] for e in data)


def test_atom_parses_and_is_defanged(exported):
    out, _ = exported
    raw = (out / "atom.xml").read_text(encoding="utf-8")
    root = ET.fromstring(raw.encode("utf-8"))
    ns = {"a": ATOM_NS}
    assert root.tag == f"{{{ATOM_NS}}}feed"
    entries = root.findall("a:entry", ns)
    assert entries
    for entry in entries:
        for tag in ("id", "title", "updated", "summary"):
            assert entry.find(f"a:{tag}", ns) is not None
    texts = " ".join((e.findtext("a:title", "", ns) + " " + e.findtext("a:summary", "", ns)) for e in entries)
    for ioc in ("78.40.198.61", "144.31.108.193", "https://", "http://", "203.0.113.50"):
        assert ioc not in texts
    assert "78[.]40[.]198[.]61" in texts


def test_atom_escapes_hostile_values(data_dir):
    ds = load_dataset(data_dir)
    ds.events = [{
        "chain": "polygon", "block": 1, "timestamp": "2026-10-19T00:00:00Z", "tx_hash": "0x" + "1" * 64,
        "contract": "0xabc", "from": None, "selector": None, "hunt_id": "x", "old_raw": None,
        "new_raw": "00", "old_decoded": None,
        "new_decoded": "</summary><script>alert(1)</script>&amp; \x00\x07 ]]> http://evil.example/x?a=1&b=2",
        "decoder": "plain",
    }]
    xml = build_atom(ds)
    root = ET.fromstring(xml)  # must be well-formed
    summary = root.find(f"{{{ATOM_NS}}}entry/{{{ATOM_NS}}}summary").text
    assert "<script>" in summary  # survived as text, i.e. was escaped
    assert b"<script>" not in xml
    assert "evil[.]example" in summary and "hxxp" in summary


def test_defang():
    assert defang("https://a.b/c") == "hxxps[://]a[.]b/c"
    assert defang("1.2.3.4") == "1[.]2[.]3[.]4"
