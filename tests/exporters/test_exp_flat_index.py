from __future__ import annotations

import csv
import hashlib
import io
import json
import shutil

import pytest

from deaddrop_hunter.exporters import FORMATS, run_exports
from deaddrop_hunter.exporters._common import load_dataset


def _tree(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def test_returned_paths_exist(exported):
    out, written = exported
    assert written[-1] == out / "index.json"
    for p in written:
        assert p.is_file()
    assert set(_tree(out)) == {p.relative_to(out).as_posix() for p in written}


def test_deterministic(tmp_path, data_dir, exported):
    out1, _ = exported
    out2 = tmp_path / "second"
    run_exports(data_dir, out2, list(reversed(FORMATS)))
    assert _tree(out1) == _tree(out2)
    # Re-running into the same directory is also byte-identical.
    run_exports(data_dir, out2, list(FORMATS))
    assert _tree(out1) == _tree(out2)


def test_no_crlf(exported):
    out, _ = exported
    for name, data in _tree(out).items():
        assert b"\r\n" not in data, name


def test_index_sha256_and_size(exported):
    out, _ = exported
    index = json.loads((out / "index.json").read_text(encoding="utf-8"))
    assert index["generated_at"] == "2026-10-19T12:00:00Z"
    paths = set()
    for entry in index["files"]:
        data = (out / entry["path"]).read_bytes()
        assert entry["sha256"] == hashlib.sha256(data).hexdigest()
        assert entry["size"] == len(data)
        assert entry["format"] in FORMATS
        assert entry["description"]
        paths.add(entry["path"])
    assert "stix/deaddrop-hunter.bundle.json" in paths
    assert "misp/manifest.json" in paths and "misp/hashes.csv" in paths
    assert {"csv/iocs.csv", "csv/contracts.csv", "csv/wallets.csv"} <= paths
    assert {"txt/ipv4.txt", "txt/domains.txt", "txt/urls.txt"} <= paths


def test_partial_export_keeps_other_formats_in_index(tmp_path, data_dir):
    out = tmp_path / "feeds"
    run_exports(data_dir, out, list(FORMATS))
    written = run_exports(data_dir, out, ["csv"])
    assert all(p.parts[-2] == "csv" for p in written[:-1])
    index = json.loads((out / "index.json").read_text(encoding="utf-8"))
    assert {e["format"] for e in index["files"]} == set(FORMATS)


def test_stale_cluster_files_removed(tmp_path, data_dir):
    data = tmp_path / "data"
    shutil.copytree(data_dir, data)
    out = tmp_path / "feeds"
    run_exports(data, out, ["stix", "misp"])
    clusters = json.loads((data / "clusters.json").read_text(encoding="utf-8"))
    (data / "clusters.json").write_text(json.dumps(clusters[1:], indent=2) + "\n", encoding="utf-8")
    run_exports(data, out, ["stix", "misp"])
    assert not (out / "stix" / "clusters" / f"{clusters[0]['id']}.json").exists()
    manifest = json.loads((out / "misp" / "manifest.json").read_text(encoding="utf-8"))
    assert {p.stem for p in (out / "misp").glob("*.json")} - {"manifest"} == set(manifest)


def test_unknown_format_rejected(tmp_path, data_dir):
    with pytest.raises(ValueError):
        run_exports(data_dir, tmp_path, ["stix", "yaml"])


def test_csv(exported, fixture_data):
    out, _ = exported
    rows = list(csv.DictReader(io.StringIO((out / "csv" / "iocs.csv").read_text(encoding="utf-8"))))
    assert list(rows[0].keys()) == [
        "type", "value", "port", "family", "cluster_id", "chain",
        "first_seen", "last_seen", "current", "confidence", "dual_use", "contracts",
    ]
    assert len(rows) == len(fixture_data["iocs"])
    ip = next(r for r in rows if r["value"] == "78.40.198.61")
    assert ip["port"] == "31270" and ip["current"] == "true" and ip["cluster_id"] == "c-19532c0f"
    assert len(ip["contracts"].split(";")) == 4
    contracts = list(csv.DictReader(io.StringIO((out / "csv" / "contracts.csv").read_text(encoding="utf-8"))))
    assert len(contracts) == len(fixture_data["contracts"])
    sol = next(c for c in contracts if c["chain"] == "solana")
    assert sol["explorer_url"] == f"https://solscan.io/account/{sol['address']}"
    wallets = list(csv.DictReader(io.StringIO((out / "csv" / "wallets.csv").read_text(encoding="utf-8"))))
    assert len(wallets) == len(fixture_data["wallets"])


def test_txt_blocklists(exported):
    out, _ = exported

    def entries(name):
        lines = (out / "txt" / name).read_text(encoding="utf-8").splitlines()
        assert lines[0].startswith("# deaddrop-hunter")
        assert any(line.startswith("# generated_at: 2026-10-19T12:00:00Z") for line in lines)
        assert any("LICENSE" in line for line in lines if line.startswith("#"))
        return [line for line in lines if line and not line.startswith("#")]

    assert entries("ipv4.txt") == ["144.31.108.193", "203.0.113.50", "78.40.198.61"]
    assert "185.10.68.110" not in entries("ipv4.txt")  # not current
    assert entries("domains.txt") == [
        "dead-drop-fixture.example", "pool.hashvault.pro", "xmr-eu1.nanopool.org",
    ]
    assert entries("urls.txt") == ["http://203.0.113.50/wall", "https://144.31.108.193/gate.php"]


@pytest.mark.parametrize(
    ("chain", "addr", "expected"),
    [
        ("polygon", "0xabc", "https://polygonscan.com/address/0xabc"),
        ("base", "0xabc", "https://basescan.org/address/0xabc"),
        ("avalanche", "0xabc", "https://snowtrace.io/address/0xabc"),
        ("tron", "TXyz", "https://tronscan.org/#/address/TXyz"),
        ("solana", "Sol1", "https://solscan.io/account/Sol1"),
        ("aptos", "0x" + "a" * 64,
         "https://explorer.aptoslabs.com/account/0x" + "a" * 64 + "?network=mainnet"),
        ("monero", "4abc", None),
    ],
)
def test_explorer_urls(data_dir, chain, addr, expected):
    assert load_dataset(data_dir).explorer_url(chain, addr) == expected


def test_explorer_urls_from_project_config(data_dir):
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    if not (root / "config" / "hunts.toml").exists():
        pytest.skip("no project config")
    # A data dir next to config/ picks up explorers (and chain types) from hunts.toml.
    ds = load_dataset(root / "data")
    assert ds.explorer_url("polygon", "0x1") == "https://polygonscan.com/address/0x1"
    assert ds.explorer_url("tron", "T1") == "https://tronscan.org/#/address/T1"
    assert ds.explorer_tx_url("aptos", "0x2") == "https://explorer.aptoslabs.com/txn/0x2?network=mainnet"


def test_dual_use_is_withheld_from_blocklists(tmp_path, data_dir):
    """Public pools stay in the CSV feed and out of domains.txt, with the count declared."""
    src = tmp_path / "data"
    shutil.copytree(data_dir, src)
    iocs = json.loads((src / "iocs.json").read_text())
    pools = [i for i in iocs if i["type"] == "domain" and "nanopool.org" in i["value"]]
    assert pools, "fixture should contain a public pool domain"
    for i in iocs:
        i["dual_use"] = i in pools
        if i in pools:
            i["current"] = True
    (src / "iocs.json").write_text(json.dumps(iocs))

    out = tmp_path / "feeds"
    run_exports(src, out, ["csv", "txt"])
    domains = (out / "txt" / "domains.txt").read_text()
    assert "nanopool.org" not in domains
    assert f"# dual-use entries withheld (see csv/iocs.csv): {len(pools)}" in domains
    assert "nanopool.org" in (out / "csv" / "iocs.csv").read_text()
