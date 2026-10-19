from deaddrop_hunter.decoders import (
    abi_decode,
    decode_input_strings,
    decode_log_strings,
    decode_value,
    raw_bytes,
    raw_text,
)
from deaddrop_hunter.keccak import keccak256, selector, topic0

from .fixtures_util import load_fixture


def test_keccak_vectors():
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"DataUpdated(string,string)").hex() == (
        "ee986145c636aca5c6c0b4ce0e9d371e77ab30b3e28fe5c3a8d977f05fc8cf24"
    )
    assert topic0("Transfer(address,address,uint256)") == (
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )
    assert selector("transfer(address,uint256)") == "0xa9059cbb"


def _enc_string(s: bytes) -> bytes:
    pad = (32 - len(s) % 32) % 32
    return len(s).to_bytes(32, "big") + s + b"\0" * pad


def test_abi_two_strings_roundtrip():
    a, b = b"hello", b"x" * 70
    head = (64).to_bytes(32, "big") + (64 + len(_enc_string(a))).to_bytes(32, "big")
    data = "0x" + (head + _enc_string(a) + _enc_string(b)).hex()
    assert decode_log_strings(data, ["string", "string"]) == [a, b]


def test_abi_input_with_selector():
    body = (32).to_bytes(32, "big") + _enc_string(b"http://example.invalid")
    sel, strings = decode_input_strings("0x68446ead" + body.hex(), ["string"])
    assert sel == "0x68446ead"
    assert strings == [b"http://example.invalid"]


def test_abi_static_types():
    addr = "00" * 12 + "ab" * 20
    data = addr + (5).to_bytes(32, "big").hex() + (1).to_bytes(32, "big").hex()
    assert abi_decode(["address", "uint256", "bool"], data) == ["0x" + "ab" * 20, 5, True]


def test_real_polygon_logs_decode():
    logs = load_fixture("polygon_dataupdated_logs.json")
    by_tx = {lg["transactionHash"]: lg for lg in logs}
    url_log = by_tx["0x08233ee528890aec38ef97810e7074d5ebe1b87c72995fd8758c652231bcd53f"]
    old, new = decode_log_strings(url_log["data"], ["string", "string"])
    assert decode_value(old) == ("http://185.10.68.110", "plain")
    assert decode_value(new) == ("http://144.31.108.193", "plain")

    xor_log = by_tx["0x774e03243db1b1c7c972b7f5a9f21b7be23e00a719582b5afdf8b1dea062c53d"]
    _old, new = decode_log_strings(xor_log["data"], ["string", "string"])
    assert new.startswith(b"21783b36")  # hex text of '{"al' XOR 0x5a
    text, dec = decode_value(new)
    assert dec == "xor-1byte:0x5a"
    assert text.startswith('{"algo":"rx/0","pool":"78.40.198.61","port":31270')


def test_value_decoders_order():
    assert decode_value(b"hello world") == ("hello world", "plain")
    assert decode_value("68747470733a2f2f612e6578616d706c65") == ("https://a.example", "hex-utf8")
    assert decode_value("aHR0cHM6Ly9hLmV4YW1wbGUvcGF0aA==") == ("https://a.example/path", "base64")
    xored = bytes(c ^ 0x33 for c in b"http://198.51.100.7/x").hex()
    assert decode_value(xored) == ("http://198.51.100.7/x", "xor-1byte:0x33")
    assert decode_value(b"\x00\x01\x02\xff") == (None, "undecoded")
    assert decode_value(None) == (None, "undecoded")


def test_raw_text_roundtrip():
    for b in (b"plain text", b"\x00\xffbinary", b"21783b36"):
        assert raw_bytes(raw_text(b)) == b
