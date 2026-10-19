"""EVM bytecode and address primitives used to recognise a dead drop by its shape.

A dead drop has to be readable by anonymous infected machines, so whatever the operator
names their functions, the contract must expose a public reader that returns text and a
write path restricted to one address. That combination, plus a small contract, is what
this module detects - before any value has ever been decoded, and without needing the
contract to emit an event or to be mentioned in anybody's report.

Everything here is pure: no network, no state. The caller supplies the runtime bytecode.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .keccak import keccak256

# Selectors confirmed on-chain in both dead-drop families we have decoded (2026-10-19).
GETTERS = {
    "0x38bcdc1c": "getURL()",
    "0x91906103": "getString()",       # seen in the DataUpdated family
}
SETTERS = {
    "0x77343408": "setURL(string)",
    "0x68446ead": "update(string)",
}
# Standard token metadata and bookkeeping. Readable by anyone and harmless, so probing them
# only ever produces noise: name() is what reported a contract storing "Digital Pay".
NEVER_PROBE = {
    "0x06fdde03": "name()",
    "0x95d89b41": "symbol()",
    "0x313ce567": "decimals()",
    "0x18160ddd": "totalSupply()",
    "0x70a08231": "balanceOf(address)",
}
# Owner/admin accessors. Present in every confirmed drop so far and cheap to test for,
# but far too common on their own: proxies and ordinary owned contracts expose them too.
ADMINS = {
    "0xf851a440": "admin()",
    "0x8da5cb5b": "owner()",
}

# A dispatcher compares calldata against PUSH4 constants; that is where selectors live.
_PUSH4 = re.compile(r"63([0-9a-f]{8})")
# Solidity appends CBOR metadata plus a two-byte big-endian length.
_MAX_METADATA = 200


def normalize(code: str | bytes) -> bytes:
    if isinstance(code, bytes):
        return code
    s = code[2:] if code[:2].lower() == "0x" else code
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def strip_metadata(code: str | bytes) -> bytes:
    """Runtime code without the trailing solc metadata, so two builds of the same source
    with different compiler paths still hash alike."""
    b = normalize(code)
    if len(b) < 3:
        return b
    size = int.from_bytes(b[-2:], "big")
    if 0 < size <= _MAX_METADATA and size + 2 <= len(b):
        return b[: -(size + 2)]
    return b


def code_hash(code: str | bytes) -> str:
    """Short, stable identifier for a blueprint: contracts built from the same template
    share it even when their stored values differ."""
    return hashlib.sha256(strip_metadata(code)).hexdigest()[:16]


def selectors(code: str | bytes) -> tuple[str, ...]:
    """The 4-byte function selectors a contract's dispatcher compares against."""
    b = normalize(code)
    return tuple(sorted({"0x" + m.group(1) for m in _PUSH4.finditer(b.hex())}))


def code_as_text(code: str | bytes, min_len: int = 16) -> str | None:
    """Some operators store the payload as a contract's code rather than inside it, because
    code is cheaper to read. Returns the text when the code is text rather than instructions."""
    b = normalize(code)
    if len(b) < min_len:
        return None
    body = b[1:] if b[:1] == b"\x00" else b          # data contracts often lead with a STOP
    printable = sum(1 for c in body if 32 <= c < 127 or c in (9, 10, 13))
    if printable / len(body) < 0.9:
        return None
    try:
        text = body.decode("utf-8", "ignore").strip("\x00").strip()
    except UnicodeDecodeError:
        return None
    return text if len(text) >= min_len and text.isprintable() else None



@dataclass(frozen=True)
class Shape:
    """What the code alone says about a contract."""

    size: int
    code_hash: str
    selectors: tuple[str, ...] = ()
    getters: tuple[str, ...] = field(default=())
    setters: tuple[str, ...] = field(default=())
    admins: tuple[str, ...] = field(default=())
    # The code is readable text rather than instructions: the payload is the contract.
    is_data: bool = False

    @property
    def is_contract(self) -> bool:
        return self.size > 0

    @property
    def known_family(self) -> bool:
        """Matches a template we have already decoded a value from."""
        return bool(self.getters or self.setters)

    @property
    def dead_drop_like(self) -> bool:
        """Worth asking what it holds.

        Either it carries a selector from a confirmed family, or it has the generic shape:
        a small contract with an owner accessor. The second arm is deliberately loose - it
        is a filter for "worth one eth_call", not a verdict. Nothing here decides that a
        contract is malicious; only a decoded value does that.
        """
        if not self.is_contract:
            return False
        if self.known_family or self.is_data:
            return True
        return bool(self.admins) and self.size <= MAX_CANDIDATE_SIZE


# Both confirmed templates are ~2.4-3.2 kB. Real dead drops stay small because they do
# one thing; the cap keeps routers, tokens and proxies with huge dispatchers out.
MAX_CANDIDATE_SIZE = 6144


def shape_of(code: str | bytes) -> Shape:
    sels = selectors(code)
    b = strip_metadata(code)
    return Shape(
        size=len(normalize(code)),
        code_hash=code_hash(code),
        selectors=sels,
        getters=tuple(s for s in sels if s in GETTERS),
        setters=tuple(s for s in sels if s in SETTERS),
        admins=tuple(s for s in sels if s in ADMINS),
        is_data=code_as_text(code) is not None,
    ) if b is not None else Shape(0, code_hash(b""))


def probe_selectors(shape: Shape, limit: int = 6) -> tuple[str, ...]:
    """Selectors worth calling with empty arguments, best first: known readers, then the
    contract's own selectors that are not known writers (a zero-argument reader cannot be
    told apart from a writer by code alone, but eth_call never changes state, so trying
    one costs nothing but a request)."""
    out = [s for s in shape.getters]
    for s in shape.selectors:
        if len(out) >= limit:
            break
        if s in out or s in SETTERS or s in ADMINS or s in NEVER_PROBE:
            continue
        out.append(s)
    return tuple(out[:limit])


# A Solidity string of 31 bytes or less lives inside its slot, with the length in the last
# byte as 2*len; a longer one keeps 2*len+1 there and the bytes at keccak(slot), word by word.
def slot_short_string(word: bytes) -> str | None:
    """Text stored inline in a slot, or None when the slot holds something else."""
    if len(word) != 32 or word[31] & 1:
        return None
    length = word[31] >> 1
    if not 1 <= length <= 31:
        return None
    raw = word[:length]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text.isprintable() else None


def slot_long_string_len(word: bytes) -> int | None:
    """Length of a string whose bytes live at keccak(slot), or None."""
    if len(word) != 32 or not word[31] & 1:
        return None
    length = (int.from_bytes(word, "big") - 1) // 2
    return length if 32 <= length <= 64 * 1024 else None


def long_string_base(slot: int) -> int:
    """Where the bytes of a long string in `slot` actually start."""
    return int.from_bytes(keccak256(slot.to_bytes(32, "big")), "big")


def _rlp_len(prefix: int, n: int) -> bytes:
    if n < 56:
        return bytes([prefix + n])
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([prefix + 55 + len(nb)]) + nb


def created_address(sender: str, nonce: int) -> str:
    """Address a plain account's CREATE lands on: keccak(rlp([sender, nonce]))[12:].

    Lets us name every contract a wallet has deployed, and the one it will deploy next,
    without an explorer or an index.
    """
    addr = bytes.fromhex(sender[2:] if sender[:2].lower() == "0x" else sender)
    if len(addr) != 20:
        raise ValueError(f"not a 20-byte address: {sender!r}")
    if nonce == 0:
        n = b"\x80"
    elif nonce < 0x80:
        n = bytes([nonce])
    else:
        nb = nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
        n = bytes([0x80 + len(nb)]) + nb
    payload = b"\x94" + addr + n
    return "0x" + keccak256(_rlp_len(0xC0, len(payload)) + payload)[12:].hex()
