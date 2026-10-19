"""IOC extraction and malware-family classification of decoded dead-drop values.

Pure text processing: nothing here resolves, fetches or connects to anything.

To add a family, append a :class:`FamilyRule` to ``FAMILY_RULES`` (first match wins).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit


# ---------------------------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True, order=True)
class Ioc:
    type: str
    value: str
    port: int | None = None
    confidence: int = 50

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.type, self.value, self.port if self.port is not None else -1)


@dataclass
class Context:
    """What a family rule sees: the decoded text and, if it parsed, the JSON object."""

    text: str
    json: object = None
    iocs: list[Ioc] = field(default_factory=list)

    @property
    def obj(self) -> dict:
        return self.json if isinstance(self.json, dict) else {}


@dataclass(frozen=True)
class FamilyRule:
    family: str
    match: Callable[[Context], bool]
    name: str  # human cluster name
    tags: tuple[str, ...] = ()


def _single_url(ctx: Context) -> bool:
    return bool(_URL_FULL.fullmatch(ctx.text.strip()))


FAMILY_RULES: list[FamilyRule] = [
    FamilyRule(
        "xmrig-stealth",
        lambda c: "algo" in c.obj and ("pool" in c.obj or "pools" in c.obj) and c.obj.get("stealth") is True,
        "Stealth XMRig config cluster",
        ("xmrig", "cryptominer", "config-on-chain"),
    ),
    FamilyRule(
        "xmrig",
        lambda c: "algo" in c.obj and ("pool" in c.obj or "pools" in c.obj),
        "XMRig config cluster",
        ("xmrig", "cryptominer", "config-on-chain"),
    ),
    FamilyRule(
        "c2-url",
        _single_url,
        "C2 URL rotation cluster",
        ("c2", "url-rotation", "config-on-chain"),
    ),
]
UNKNOWN = FamilyRule("unknown", lambda c: True, "Unclassified dead-drop cluster", ("config-on-chain",))
FAMILY_BY_SLUG = {r.family: r for r in FAMILY_RULES} | {UNKNOWN.family: UNKNOWN}

# Confidence by extraction source (0-100).
CONF = {
    "json-pool": 85,
    "json-wallet": 90,
    "single-url": 85,
    "url": 75,
    "url-host": 70,
    "text-ip": 60,
    "text-domain": 50,
    "text-wallet": 80,
    "text-evm": 50,
}

# Well-known benign infrastructure that shows up inside configs (e.g. TLS SNI spoofing such as
# ``--ssl-servername login.microsoft.com``). Never reported as IOCs. Suffix match.
BENIGN_DOMAINS = (
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com", "azure.com",
    "google.com", "googleapis.com", "gstatic.com", "cloudflare.com", "github.com", "githubusercontent.com",
    "apple.com", "amazon.com", "amazonaws.com", "mozilla.org", "w3.org", "schema.org", "example.com",
    "example.org", "example.net", "localhost",
)

# File extensions that the domain regex would otherwise accept as TLDs.
FILE_EXTS = frozenset({
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "msi", "scr", "com_", "lnk", "tmp",
    "log", "txt", "ini", "cfg", "conf", "json", "xml", "dat", "bin", "zip", "rar", "7z", "py", "sh",
    "jar", "cs", "rs", "db", "md", "h", "c", "cpp", "png", "jpg", "gif", "ico", "pdf", "doc", "docx",
    "xls", "xlsx", "hta", "wsf", "cpl", "ocx", "drv", "efi", "mui", "inf", "reg", "pf", "etl", "evtx",
})

# Generic/sponsored TLDs accepted (plus every 2-letter ccTLD not in FILE_EXTS).
GTLDS = frozenset("""
com net org info biz name pro aero coop museum mobi asia tel travel jobs cat int edu gov mil arpa
xyz top site online store tech space website fun icu club live life shop app dev io ai cloud host
link click press pw cc tk ml ga cf gq su ru work today world news one vip win bid loan men date
download racing review stream trade party science cricket accountant faith webcam rest bar best
monster cyou buzz sbs cfd lol quest beauty hair makeup skin homes autos boats yachts motorcycles
digital network systems services solutions support agency center company email group global zone
network media studio design codes software tools services pics pictures photo photos video games
fyi wtf rocks ninja guru expert pub social chat page blog wiki run fit kim ltd llc inc gg ws me tv
lat uno best gold money cash finance financial capital fund exchange market markets trading crypto
bond pizza help how gdn ooo onion i2p
""".split())

# ---------------------------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------------------------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_URL_FULL = re.compile(r"(?:https?|hxxps?|wss?|ftp|stratum\+tcp|stratum\+ssl)://[^\s\"'<>]+", re.I)
_URL_RE = re.compile(r"(?<![\w.])(?:https?|hxxps?|wss?|ftp|stratum\+tcp|stratum\+ssl)://[^\s\"'<>,]+", re.I)
_IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?![\w.]*\d)")
_IPV6_RE = re.compile(r"(?<![\w:])\[?((?:[0-9a-fA-F]{1,4}:){2,7}(?::|[0-9a-fA-F]{1,4})(?:[0-9a-fA-F:]*)?)\]?(?![\w:])")
_DOMAIN_RE = re.compile(
    r"(?<![\w@\\/.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?::(\d{1,5}))?(?![\w-]|\.\w)",
    re.I,
)
_XMR_RE = re.compile(rf"(?<![{_B58}])([48][{_B58}]{{94}}(?:[{_B58}]{{11}})?)(?![{_B58}])")
_BTC_LEGACY_RE = re.compile(rf"(?<![{_B58}])([13][{_B58}]{{25,34}})(?![{_B58}])")
_BTC_BECH32_RE = re.compile(r"(?<![a-z0-9])(bc1[ac-hj-np-z02-9]{11,71})(?![a-z0-9])", re.I)
_EVM_RE = re.compile(r"(?<![0-9a-fA-Fx])(0x[0-9a-fA-F]{40})(?![0-9a-fA-F])")


# ---------------------------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------------------------
def valid_public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def _valid_port(p: str | int | None) -> int | None:
    if p is None or p == "":
        return None
    try:
        v = int(p)
    except (TypeError, ValueError):
        return None
    return v if 0 < v < 65536 else None


def valid_domain(d: str) -> bool:
    d = d.lower().rstrip(".")
    labels = d.split(".")
    if len(labels) < 2 or len(d) > 253:
        return False
    tld = labels[-1]
    if tld in FILE_EXTS:
        return False
    if not (tld in GTLDS or (len(tld) == 2 and tld.isalpha())):
        return False
    if all(lbl.isdigit() for lbl in labels[:-1]):
        return False
    return not is_benign_domain(d)


# Public mining pools and other shared services that really do appear in these configs. They say
# something true about the campaign, but thousands of legitimate miners use them too: reported
# with ``dual_use`` set so consumers can keep them out of automated blocking.
DUAL_USE_DOMAINS = (
    "nanopool.org", "hashvault.pro", "herominers.com", "supportxmr.com", "moneroocean.stream",
    "minexmr.com", "2miners.com", "c3pool.com", "xmrpool.eu", "unmineable.com", "f2pool.com",
    "poolin.com", "zergpool.com", "gntl.co.uk", "monero.hashvault.pro", "skypool.org",
    # Content-addressed storage gateways: NFT metadata lives here by the million, and so do
    # the occasional payload links. Reported, never blocked.
    "ipfs.io", "filebase.io", "pinata.cloud", "nftstorage.link", "arweave.net", "w3s.link",
    "dweb.link", "cf-ipfs.com", "infura-ipfs.io", "fleek.co",
    # Decentralised network node registries announce their own endpoints on-chain, by the
    # thousand. Real hosts, published deliberately, nothing to act on.
    "streamr-nodes.xyz", "streamr.network", "pokt.network", "lavanet.xyz", "drpc.org",
)


def url_host(value: str) -> str:
    """Host of a URL-ish string, without scheme, credentials, port or path."""
    s = value.split("://", 1)[-1]
    s = s.split("/", 1)[0].split("?", 1)[0]
    s = s.rsplit("@", 1)[-1]
    if s.startswith("["):                       # [ipv6]:port
        return s[1:].split("]", 1)[0].lower()
    return s.split(":", 1)[0].strip(".").lower()


def is_dual_use(ioc_type: str, value: str) -> bool:
    """True for indicators that are real but shared with legitimate users (public pools)."""
    if ioc_type not in ("domain", "url"):
        return False
    host = value.lower() if ioc_type == "domain" else url_host(value)
    host = host.split(":", 1)[0].strip(".")
    return any(host == d or host.endswith("." + d) for d in DUAL_USE_DOMAINS)


def is_benign_domain(d: str) -> bool:
    d = d.lower().rstrip(".")
    return any(d == b or d.endswith("." + b) for b in BENIGN_DOMAINS)


def _b58decode(s: str) -> bytes | None:
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + full


def valid_btc_legacy(s: str) -> bool:
    raw = _b58decode(s)
    if raw is None or len(raw) != 25:
        return False
    chk = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]
    return chk == raw[-4:] and raw[0] in (0x00, 0x05)


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def valid_bech32(s: str) -> bool:
    s = s.lower()
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    hrp, _, data = s.rpartition("1")
    if hrp != "bc" or len(data) < 6 or any(c not in charset for c in data):
        return False
    vals = [charset.index(c) for c in data]
    hrp_exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    return _bech32_polymod(hrp_exp + vals) in (1, 0x2BC830A3)


# ---------------------------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------------------------
def _host_iocs(host: str, port: int | None, conf: int) -> list[Ioc]:
    host = host.strip().strip("[]").lower().rstrip(".")
    if not host:
        return []
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if not valid_public_ip(host):
            return []
        return [Ioc("ipv4" if ip.version == 4 else "ipv6", str(ip), port, conf)]
    if valid_domain(host):
        return [Ioc("domain", host, port, conf)]
    return []


def _split_host_port(s: str) -> tuple[str, int | None]:
    s = s.strip()
    if "://" in s:
        p = urlsplit(s)
        try:
            return p.hostname or "", p.port
        except ValueError:
            return p.hostname or "", None
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        return host, _valid_port(rest.lstrip(":"))
    if s.count(":") == 1:
        host, _, port = s.partition(":")
        return host, _valid_port(port)
    return s, None


def extract_text(text: str) -> list[Ioc]:
    """Regex IOC extraction from free text."""
    out: list[Ioc] = []
    url_spans: list[tuple[int, int]] = []
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;)]}'\"")
        url_spans.append((m.start(), m.start() + len(url)))
        host, port = _split_host_port(url)
        hosts = _host_iocs(host, port, CONF["url-host"])
        if hosts or host:
            if not host or not is_benign_domain(host):
                out.append(Ioc("url", url, None, CONF["url"]))
        out.extend(hosts)

    def in_url(pos: int) -> bool:
        return any(a <= pos < b for a, b in url_spans)

    for m in _IPV4_RE.finditer(text):
        if in_url(m.start()):
            continue
        ip = m.group(1)
        if valid_public_ip(ip):
            out.append(Ioc("ipv4", ip, _valid_port(m.group(2)), CONF["text-ip"]))
    for m in _IPV6_RE.finditer(text):
        if in_url(m.start()):
            continue
        cand = m.group(1)
        try:
            ip = ipaddress.IPv6Address(cand)
        except ValueError:
            continue
        if valid_public_ip(cand):
            out.append(Ioc("ipv6", str(ip), None, CONF["text-ip"]))
    for m in _DOMAIN_RE.finditer(text):
        if in_url(m.start()):
            continue
        d = m.group(1).lower()
        if valid_domain(d):
            out.append(Ioc("domain", d, _valid_port(m.group(3)), CONF["text-domain"]))
    for m in _XMR_RE.finditer(text):
        if len(m.group(1)) in (95, 106):
            out.append(Ioc("xmr-wallet", m.group(1), None, CONF["text-wallet"]))
    for m in _BTC_LEGACY_RE.finditer(text):
        if valid_btc_legacy(m.group(1)):
            out.append(Ioc("btc-wallet", m.group(1), None, CONF["text-wallet"]))
    for m in _BTC_BECH32_RE.finditer(text):
        if valid_bech32(m.group(1)):
            out.append(Ioc("btc-wallet", m.group(1).lower(), None, CONF["text-wallet"]))
    for m in _EVM_RE.finditer(text):
        out.append(Ioc("evm-wallet", m.group(1).lower(), None, CONF["text-evm"]))
    return out


def _walk_json(node: object, out: list[Ioc]) -> None:
    if isinstance(node, dict):
        lower = {str(k).lower(): v for k, v in node.items()}
        pool = lower.get("pool", lower.get("url"))
        if isinstance(pool, str) and pool:
            host, port = _split_host_port(pool)
            if port is None:
                port = _valid_port(lower.get("port"))
            out.extend(_host_iocs(host, port, CONF["json-pool"]))
        for key in ("wallet", "user"):
            w = lower.get(key)
            if isinstance(w, str) and w:
                base = w.split(".")[0].split("+")[0]
                if _XMR_RE.fullmatch(base) and len(base) in (95, 106):
                    out.append(Ioc("xmr-wallet", base, None, CONF["json-wallet"]))
        for v in node.values():
            _walk_json(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_json(v, out)
    elif isinstance(node, str):
        out.extend(extract_text(node))


def parse_json(text: str) -> object:
    s = text.strip()
    if not s or s[0] not in "{[":
        return None
    try:
        return json.loads(s)
    except ValueError:
        return None


def dedupe(iocs: list[Ioc]) -> list[Ioc]:
    """One IOC per (type, value, port), keeping the highest confidence; drop a port-less
    duplicate when the same value is also seen with a port."""
    best: dict[tuple, Ioc] = {}
    for i in iocs:
        k = i.key
        if k not in best or i.confidence > best[k].confidence:
            best[k] = i
    with_port = {(i.type, i.value) for i in best.values() if i.port is not None}
    res = [i for i in best.values() if i.port is not None or (i.type, i.value) not in with_port]
    return sorted(res, key=lambda i: i.key)


def extract_iocs(text: str | None) -> list[Ioc]:
    if not text:
        return []
    obj = parse_json(text)
    out: list[Ioc] = []
    if obj is not None:
        _walk_json(obj, out)
    else:
        if _single_url(Context(text)):
            out.extend(Ioc(i.type, i.value, i.port, max(i.confidence, CONF["single-url"]))
                       for i in extract_text(text.strip()))
        else:
            out.extend(extract_text(text))
    return dedupe(out)


def classify(text: str | None) -> FamilyRule:
    if text is None:
        return UNKNOWN
    ctx = Context(text=text, json=parse_json(text))
    for rule in FAMILY_RULES:
        try:
            if rule.match(ctx):
                return rule
        except Exception:  # noqa: BLE001 - a buggy contributor rule must not kill the hunt
            continue
    return UNKNOWN
