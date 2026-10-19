from deaddrop_hunter.classify import classify, extract_iocs, valid_btc_legacy
from deaddrop_hunter.decoders import decode_log_strings, decode_value

from .fixtures_util import load_fixture


def _xor_config_text() -> str:
    logs = load_fixture("polygon_dataupdated_logs.json")
    lg = next(x for x in logs if x["transactionHash"].startswith("0x774e"))
    _old, new = decode_log_strings(lg["data"], ["string", "string"])
    return decode_value(new)[0]


def _keys(iocs):
    return {(i.type, i.value, i.port) for i in iocs}


def test_xmrig_stealth_config_iocs():
    text = _xor_config_text()
    iocs = extract_iocs(text)
    keys = _keys(iocs)
    assert ("ipv4", "78.40.198.61", 31270) in keys
    values = {i.value for i in iocs}
    assert "taskmgr.exe" not in {v.lower() for v in values}
    assert not any(v.lower().endswith(".exe") for v in values)
    assert "login.microsoft.com" not in values  # benign SNI spoof target
    assert classify(text).family == "xmrig-stealth"


def test_nanopool_domain_and_xmr_wallet():
    raw = load_fixture("xmrig_nanopool_value.json")["raw"]
    text, dec = decode_value(raw)
    assert dec == "xor-1byte:0x5a"
    keys = _keys(extract_iocs(text))
    assert ("domain", "xmr-eu1.nanopool.org", 10343) in keys
    assert any(t == "xmr-wallet" and v.startswith("43BPsbHAKf7E") and len(v) == 95 for t, v, _p in keys)
    assert not any(t == "domain" and v.endswith(".exe") for t, v, _p in keys)


def test_single_url_family():
    assert classify("http://144.31.108.193").family == "c2-url"
    keys = _keys(extract_iocs("http://144.31.108.193"))
    assert ("url", "http://144.31.108.193", None) in keys
    assert ("ipv4", "144.31.108.193", None) in keys


def test_private_ips_and_filenames_skipped():
    keys = _keys(extract_iocs("connect 10.0.0.1:80 and 192.168.1.1 then run Taskmgr.exe, psexec.c, Dr.Web"))
    assert keys == set()


def test_text_extraction_misc():
    text = ("fallback evil-c2.xyz:8443 and 2001:4860:4860::8888 pay to "
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq or 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
            "contract 0x1823A9A0EC8E0C25DD957D0841E3D41A4474BADC")
    keys = _keys(extract_iocs(text))
    assert ("domain", "evil-c2.xyz", 8443) in keys
    assert ("ipv6", "2001:4860:4860::8888", None) in keys
    assert ("btc-wallet", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", None) in keys
    assert ("btc-wallet", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", None) in keys
    assert ("evm-wallet", "0x1823a9a0ec8e0c25dd957d0841e3d41a4474badc", None) in keys


def test_md5_is_not_btc():
    assert not valid_btc_legacy("3F79725B31F1982F7DF622E2B351AF95")
    assert extract_iocs("3F79725B31F1982F7DF622E2B351AF95") == []


def test_unknown_family():
    assert classify("just some text").family == "unknown"
    assert classify(None).family == "unknown"
