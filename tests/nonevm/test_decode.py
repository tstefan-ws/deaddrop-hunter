import base64

from deaddrop_hunter.nonevm.decode import (
    decode_bytes,
    decode_hex,
    decode_text,
    is_printable_text,
    split_rpc_memo,
    try_xor1,
)

# real Tron memo of TMfKQEd7... (XCTDH): hex(utf8(reversed BSC tx hash))
TRON_MEMO = (
    "643939653338313533363237633735663063653761356666326234383562393230"
    "313362373838646135303831643966353034326637323766303234386138317830"
)


def test_reversed_hash_pointer():
    text, dec = decode_hex(TRON_MEMO)
    assert dec == "hex-utf8+reverse"
    assert text == "0x18a8420f727f2405f9d1805ad887b31029b584b2ff5a7ec0f57c72635183e99d"


def test_hex_utf8_plain_memo():
    text, dec = decode_hex("4d787920637573746f6d206d656d6f2074657874")
    assert (text, dec) == ("Mxy custom memo text", "hex-utf8")


def test_xor_single_byte_from_leading_brace():
    plain = b'{"pool":"1.2.3.4:443","algo":"rx/0"}'
    enc = bytes(b ^ 0x5A for b in plain)
    assert try_xor1(enc) == (plain.decode(), 0x5A)
    text, dec = decode_bytes(enc)
    assert dec == "xor-1byte:0x5a" and text == plain.decode()


def test_xor_from_leading_h():
    plain = b"https://example.invalid/x"
    enc = bytes(b ^ 0x21 for b in plain)
    assert decode_bytes(enc) == (plain.decode(), "xor-1byte:0x21")


def test_base64_text_and_hex_wrapped_base64():
    b64 = base64.b64encode(b"http://203.0.113.9/payload").decode()
    assert decode_text(b64) == ("http://203.0.113.9/payload", "base64")
    assert decode_hex(b64.encode().hex()) == ("http://203.0.113.9/payload", "base64")


def test_hex_identifier_not_mistaken_for_base64():
    # an ASCII hex string must stay as text, not be base64-decoded "by accident"
    s = "deadbeefcafebabe1234"
    assert decode_hex(s.encode().hex()) == (s, "hex-utf8")


def test_undecoded_random_bytes():
    assert decode_bytes(bytes(range(200, 240))) == (None, "undecoded")
    assert decode_hex("zz") == (None, "undecoded")


def test_split_rpc_memo_multiple():
    memo = '[5] hello; [11] {"a":"b c"}'
    assert split_rpc_memo(memo) == ["hello", '{"a":"b c"}']
    assert split_rpc_memo("no prefix") == ["no prefix"]
    assert split_rpc_memo("") == []


def test_glassworm_json_memo_expanded():
    memo = '{"link":"aHR0cDovLzEzNy4xODQuMTk4LjkxL2NyQ2ZtaDQ5MjJ5UHdqYg=="}'
    text, dec = decode_text(memo, default="memo")
    assert dec == "base64"
    assert text == '{"link":"http://137.184.198.91/crCfmh4922yPwjb"}'


def test_plain_json_memo_kept():
    memo = '{"c2server":"http://198.51.100.1:5000","dht_data":"198.51.100.1:10000"}'
    assert decode_text(memo, default="memo") == (memo, "memo")


def test_printable():
    assert is_printable_text("abcd")
    assert not is_printable_text("ab\x00cd")
    assert not is_printable_text("ab")
