"""Decoding of data hidden in non-EVM transactions (stdlib only).

Everything decoded here is attacker-controlled. This module only transforms bytes/strings;
it never fetches, resolves or executes anything it decodes.

Decoder names (the ``decoder`` field of events.json):
  ``memo``             memo text taken as-is (Solana memo / Tron memo already text)
  ``plain``            printable text / value stored as-is (e.g. an Aptos string argument)
  ``hex-utf8``         hex bytes that are printable UTF-8
  ``hex-utf8+reverse`` hex -> UTF-8 text that is a reversed 0x-hash (Cross-Chain TxDataHiding
                       pointer, Ransom-ISAC 2025: Tron memo "d99e...x0" -> BSC tx "0x...e99d")
  ``base64``           base64 that decodes to printable text (also used when base64 string values
                       inside a JSON memo such as GlassWorm's {"link": "aHR0cDov..."} are expanded)
  ``xor-1byte:0xNN``   single-byte XOR, key recovered from a leading ``{`` or ``h``
  ``undecoded``        carries data, but nothing above produced printable text
"""

from __future__ import annotations

import base64
import binascii
import json
import re

_HEX_RE = re.compile(r"^(0x)?([0-9a-fA-F]{2})+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/_-]{8,}={0,2}$")
_REV_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_MEMO_PREFIX_RE = re.compile(r"^\[(\d+)\] ")

MIN_TEXT_LEN = 4


def is_printable_text(s: str, min_len: int = MIN_TEXT_LEN) -> bool:
    """True when ``s`` looks like human/machine-readable text (no control chars except whitespace)."""
    if s is None or len(s.strip()) < min_len:
        return False
    for ch in s:
        if ch in "\t\r\n":
            continue
        if not ch.isprintable():
            return False
    return True


def _bytes_to_text(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    s2 = s.rstrip("\x00")
    return s2 if is_printable_text(s2) else None


def hex_to_bytes(h: str) -> bytes | None:
    if not isinstance(h, str) or not _HEX_RE.match(h):
        return None
    h = h[2:] if h.startswith(("0x", "0X")) else h
    try:
        return bytes.fromhex(h)
    except ValueError:
        return None


def try_base64(s: str) -> str | None:
    """Decode ``s`` as (url-safe or standard) base64 only if the result is printable text."""
    s = s.strip()
    if not _B64_RE.match(s) or len(s) % 4 == 1:
        return None
    padded = s + "=" * (-len(s) % 4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            out = fn(padded)
        except (binascii.Error, ValueError):
            continue
        text = _bytes_to_text(out)
        if text is not None:
            return text
    return None


def try_xor1(b: bytes) -> tuple[str, int] | None:
    """Single-byte XOR with the key recovered from an expected leading ``{`` or ``h``."""
    if len(b) < MIN_TEXT_LEN:
        return None
    for lead in (ord("{"), ord("h")):
        key = b[0] ^ lead
        if key == 0:
            continue
        text = _bytes_to_text(bytes(x ^ key for x in b))
        if text is not None:
            return text, key
    return None


def _reversed_hash(text: str) -> str | None:
    rev = text.strip()[::-1]
    return rev if _REV_HASH_RE.match(rev) else None


def decode_bytes(b: bytes) -> tuple[str | None, str]:
    """Decode raw bytes. Returns (decoded_text_or_None, decoder_name)."""
    if not b:
        return None, "undecoded"
    text = _bytes_to_text(b)
    if text is not None and not text.startswith(("{", "[", "http")):
        # XOR of ASCII with a small key is often still printable (e.g. '{' ^ 0x5a = '!'):
        # prefer the XOR reading when it yields JSON or a URL and the plain reading does not
        x = try_xor1(b)
        if x is not None and _structured(x[0]):
            return x[0], f"xor-1byte:0x{x[1]:02x}"
    if text is not None:
        rev = _reversed_hash(text)
        if rev:
            return rev, "hex-utf8+reverse"
        inner = try_base64(text) if len(text) >= 12 else None
        if inner is not None and not _looks_like_identifier(text):
            return inner, "base64"
        return text, "hex-utf8"
    x = try_xor1(b)
    if x is not None:
        return x[0], f"xor-1byte:0x{x[1]:02x}"
    return None, "undecoded"


def _structured(text: str) -> bool:
    if text.startswith(("http://", "https://")):
        return True
    if text.startswith("{"):
        try:
            return isinstance(json.loads(text), dict)
        except ValueError:
            return False
    return False


def _looks_like_identifier(text: str) -> bool:
    # plain hex / short alnum tokens decode as base64 "by accident" -> keep them as text
    return bool(re.fullmatch(r"(0x)?[0-9a-fA-F]+", text))


def decode_hex(h: str) -> tuple[str | None, str]:
    b = hex_to_bytes(h)
    if b is None:
        return None, "undecoded"
    return decode_bytes(b)


def split_rpc_memo(memo: str) -> list[str]:
    """Solana getSignaturesForAddress joins memos as ``"[len] text; [len] text"``. Split them."""
    if not memo:
        return []
    out: list[str] = []
    rest = memo
    while rest:
        m = _MEMO_PREFIX_RE.match(rest)
        if not m:
            out.append(rest)
            break
        n = int(m.group(1))
        body = rest[m.end():m.end() + n]
        out.append(body)
        rest = rest[m.end() + n:]
        if rest.startswith("; "):
            rest = rest[2:]
    return out


def _expand_json_b64(obj):
    changed = False
    if isinstance(obj, dict):
        new = {}
        for k, v in obj.items():
            nv, c = _expand_json_b64(v)
            new[k] = nv
            changed |= c
        return new, changed
    if isinstance(obj, list):
        new_l = []
        for v in obj:
            nv, c = _expand_json_b64(v)
            new_l.append(nv)
            changed |= c
        return new_l, changed
    if isinstance(obj, str) and len(obj) >= 8 and not _looks_like_identifier(obj):
        dec = try_base64(obj)
        if dec is not None:
            return dec, True
    return obj, False


def decode_text(s: str, default: str = "plain") -> tuple[str | None, str]:
    """Decode a text value (memo / string argument).

    Order: JSON with base64 string values -> hex -> base64 -> as-is (``default``).
    """
    if s is None:
        return None, "undecoded"
    t = s.strip()
    if not t:
        return None, "undecoded"
    if t[:1] in "{[":
        try:
            obj = json.loads(t)
        except ValueError:
            obj = None
        if obj is not None:
            new, changed = _expand_json_b64(obj)
            if changed:
                return json.dumps(new, ensure_ascii=False, separators=(",", ":")), "base64"
            return t, default
    rev = _reversed_hash(t)
    if rev:
        return rev, "plain+reverse" if default == "plain" else f"{default}+reverse"
    if _HEX_RE.match(t) and len(t) >= 8:
        dec, name = decode_bytes(hex_to_bytes(t) or b"")
        if dec is not None:
            return dec, name
        return t, default
    if len(t) >= 12 and not _looks_like_identifier(t):
        dec = try_base64(t)
        if dec is not None:
            return dec, "base64"
    if is_printable_text(t, 1):
        return t, default
    return None, "undecoded"
