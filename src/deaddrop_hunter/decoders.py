"""ABI decoding of stored values and de-obfuscation of the decoded strings.

Everything decoded here is attacker-controlled data. It is only ever turned into text for
analysis: never executed, never fetched, never resolved.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable, Sequence

WORD = 32

_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")


class AbiError(ValueError):
    pass


# ---------------------------------------------------------------------------------------------
# ABI
# ---------------------------------------------------------------------------------------------
def _hex_to_bytes(data: str | bytes) -> bytes:
    if isinstance(data, bytes | bytearray):
        return bytes(data)
    s = data[2:] if data[:2].lower() == "0x" else data
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise AbiError(f"invalid hex: {e}") from e


def _word_int(buf: bytes, off: int) -> int:
    if off < 0 or off + WORD > len(buf):
        raise AbiError(f"word at {off} out of bounds ({len(buf)})")
    return int.from_bytes(buf[off:off + WORD], "big")


def _dynamic_bytes(buf: bytes, off: int) -> bytes:
    ln = _word_int(buf, off)
    start = off + WORD
    if ln > len(buf) - start:
        raise AbiError(f"length {ln} at {off} exceeds buffer")
    return buf[start:start + ln]


def abi_decode(types: Sequence[str], data: str | bytes) -> list:
    """Decode a (flat) ABI tuple. Supports string, bytes, address, uint*/int*, bool, bytesN.

    ``string``/``bytes`` values are returned as raw ``bytes`` (strings may not be valid UTF-8).
    """
    buf = _hex_to_bytes(data)
    out: list = []
    for i, t in enumerate(types):
        head = i * WORD
        if t in ("string", "bytes"):
            out.append(_dynamic_bytes(buf, _word_int(buf, head)))
        elif t == "address":
            out.append("0x" + buf[head + 12:head + 32].hex())
            if head + WORD > len(buf):
                raise AbiError("address out of bounds")
        elif t.startswith("uint"):
            out.append(_word_int(buf, head))
        elif t.startswith("int"):
            v = _word_int(buf, head)
            out.append(v - (1 << 256) if v >> 255 else v)
        elif t == "bool":
            out.append(bool(_word_int(buf, head)))
        elif re.fullmatch(r"bytes([1-9]|[12][0-9]|3[0-2])", t):
            n = int(t[5:])
            if head + WORD > len(buf):
                raise AbiError("bytesN out of bounds")
            out.append(buf[head:head + n])
        else:
            raise AbiError(f"unsupported ABI type {t!r}")
    return out


def decode_log_strings(data: str | bytes, abi: Sequence[str]) -> list[bytes]:
    """Return the dynamic string/bytes args of a log's data field (non-indexed args)."""
    vals = abi_decode(abi, data)
    return [v for t, v in zip(abi, vals, strict=True) if t in ("string", "bytes")]


def decode_input_strings(tx_input: str | bytes, abi: Sequence[str]) -> tuple[str, list[bytes]]:
    """Split a tx input into (selector, [string args]) using the given ABI for the args."""
    buf = _hex_to_bytes(tx_input)
    if len(buf) < 4:
        raise AbiError("input shorter than a selector")
    sel = "0x" + buf[:4].hex()
    vals = abi_decode(abi, buf[4:])
    return sel, [v for t, v in zip(abi, vals, strict=True) if t in ("string", "bytes")]


def raw_text(b: bytes) -> str:
    """Representation of a stored value for JSON: the UTF-8 text if clean, else ``0x`` + hex."""
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return "0x" + b.hex()
    if is_printable(s):
        return s
    return "0x" + b.hex()


def raw_bytes(raw: str) -> bytes:
    """Inverse of :func:`raw_text`."""
    if raw.startswith("0x") and _HEX_RE.match(raw) and len(raw) % 2 == 0:
        # Ambiguity: a value that is literally "0x..." text. raw_text only emits 0x-hex for
        # non-printable data, so decode as text when the hex itself is not valid binary content.
        b = bytes.fromhex(raw[2:])
        try:
            if is_printable(b.decode("utf-8")):
                return raw.encode()
        except UnicodeDecodeError:
            pass
        return b
    return raw.encode("utf-8")


# ---------------------------------------------------------------------------------------------
# Value de-obfuscation
# ---------------------------------------------------------------------------------------------
def is_printable(s: str) -> bool:
    return all(c.isprintable() or c in "\t\r\n" for c in s)


def _utf8_printable(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if is_printable(s) else None


def _looks_hex(s: str) -> bool:
    t = s[2:] if s[:2].lower() == "0x" else s
    return len(t) >= 8 and len(t) % 2 == 0 and bool(_HEX_RE.match(t))


def _looks_b64(s: str) -> bool:
    return len(s) >= 12 and len(s) % 4 == 0 and bool(_B64_RE.match(s)) and not s.isalpha()


def _b64(s: str) -> bytes | None:
    try:
        if "-" in s or "_" in s:
            return base64.urlsafe_b64decode(s)
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _payload_bytes(b: bytes) -> bytes:
    """If the stored string is hex text, return the bytes it encodes; otherwise the bytes as-is."""
    s = b.decode("ascii", "ignore")
    if len(s) == len(b) and _looks_hex(s):
        return bytes.fromhex(s[2:] if s[:2].lower() == "0x" else s)
    return b


def dec_plain(b: bytes) -> str | None:
    s = _utf8_printable(b)
    if s is None:
        return None
    st = s.strip()
    if _looks_hex(st):
        return None
    if _looks_b64(st):
        decoded = _b64(st)
        if decoded is not None and _utf8_printable(decoded):
            return None
    return s


def dec_hex_utf8(b: bytes) -> str | None:
    s = b.decode("ascii", "ignore").strip()
    if not _looks_hex(s):
        return None
    return _utf8_printable(bytes.fromhex(s[2:] if s[:2].lower() == "0x" else s))


# Expected first characters of a cleartext payload; the XOR key is recovered from them.
XOR_EXPECTED_LEADS = (b"{", b"h")


def xor_decode(b: bytes) -> tuple[str, int] | None:
    data = _payload_bytes(b)
    if not data:
        return None
    for lead in XOR_EXPECTED_LEADS:
        key = data[0] ^ lead[0]
        if key == 0:
            continue
        s = _utf8_printable(bytes(x ^ key for x in data))
        if s is None:
            continue
        if lead == b"h" and not s.lower().startswith(("http", "hxxp")):
            continue
        if lead == b"{" and not s.rstrip().endswith("}"):
            continue
        return s, key
    return None


def dec_base64(b: bytes) -> str | None:
    s = b.decode("ascii", "ignore").strip()
    if not _looks_b64(s):
        return None
    decoded = _b64(s)
    return _utf8_printable(decoded) if decoded is not None else None


def _wrap(name: str, fn: Callable[[bytes], str | None]) -> Callable[[bytes], tuple[str, str] | None]:
    def inner(b: bytes) -> tuple[str, str] | None:
        r = fn(b)
        return (r, name) if r is not None else None

    return inner


def _xor_step(b: bytes) -> tuple[str, str] | None:
    r = xor_decode(b)
    return (r[0], f"xor-1byte:0x{r[1]:02x}") if r else None


# Ordered decoder chain: first match wins. Add new decoders here.
VALUE_DECODERS: list[Callable[[bytes], tuple[str, str] | None]] = [
    _wrap("plain", dec_plain),
    _wrap("hex-utf8", dec_hex_utf8),
    _xor_step,
    _wrap("base64", dec_base64),
]


def decode_value(value: bytes | str | None) -> tuple[str | None, str]:
    """Return ``(decoded_text, decoder_name)``; ``(None, "undecoded")`` if nothing matched."""
    if value is None:
        return None, "undecoded"
    b = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    for dec in VALUE_DECODERS:
        r = dec(b)
        if r is not None:
            return r
    return None, "undecoded"
