// Formatting, validation, defanging and explorer links.
import { h, extLink } from './dom.js';

// Per-chain identifier rules and explorers (mirrors docs/data-schema.md "Per-chain identifiers"
// and config/hunts.toml, which is not published with the site).
const B58 = '[1-9A-HJ-NP-Za-km-z]';
const FAMILIES = {
  evm: {
    addr: /^0x[0-9a-f]{40}$/, tx: /^0x[0-9a-f]{64}$/,
    url: (base, kind, v) => `${base}/${kind === 'tx' ? 'tx' : kind === 'block' ? 'block' : 'address'}/${v}`,
  },
  tron: {
    addr: new RegExp(`^T${B58}{33}$`), tx: /^[0-9a-f]{64}$/,
    url: (base, kind, v) => `${base}/${kind === 'tx' ? 'transaction' : kind === 'block' ? 'block' : 'address'}/${v}`,
  },
  solana: {
    addr: new RegExp(`^${B58}{32,44}$`), tx: new RegExp(`^${B58}{86,88}$`),
    url: (base, kind, v) => `${base}/${kind === 'tx' ? 'tx' : kind === 'block' ? 'block' : 'account'}/${v}`,
  },
  aptos: {
    addr: /^0x[0-9a-f]{64}$/, tx: /^0x[0-9a-f]{64}$/,
    // aptos "block" numbers in our data are ledger versions, which the explorer serves under /txn/
    url: (base, kind, v) => `${base}/${kind === 'address' ? 'account' : 'txn'}/${v}?network=mainnet`,
  },
};

// chain key -> [family, explorer base, label]
const CHAINS = new Map([
  ['polygon', ['evm', 'https://polygonscan.com', 'Polygon']],
  ['ethereum', ['evm', 'https://etherscan.io', 'Ethereum']],
  ['arbitrum', ['evm', 'https://arbiscan.io', 'Arbitrum']],
  ['optimism', ['evm', 'https://optimistic.etherscan.io', 'Optimism']],
  ['bsc', ['evm', 'https://bscscan.com', 'BNB Chain']],
  ['bsc_testnet', ['evm', 'https://testnet.bscscan.com', 'BSC Testnet']],
  ['base', ['evm', 'https://basescan.org', 'Base']],
  ['avalanche', ['evm', 'https://snowtrace.io', 'Avalanche']],
  ['tron', ['tron', 'https://tronscan.org/#', 'Tron']],
  ['solana', ['solana', 'https://solscan.io', 'Solana']],
  ['aptos', ['aptos', 'https://explorer.aptoslabs.com', 'Aptos']],
]);
const EXTRA_LABELS = new Map([['monero', 'Monero'], ['bitcoin', 'Bitcoin']]);

export const REPO_URL = 'https://github.com/tstefan-ws/deaddrop-hunter';
export const ISSUES_URL = 'https://github.com/tstefan-ws/deaddrop-hunter/issues/new/choose';

export const RE_CHAIN = /^[a-z0-9_-]{1,32}$/;
export const RE_CLUSTER = /^c-[A-Za-z0-9]{1,64}$/;
// Generic shapes used only for search heuristics, never for link building.
export const RE_ANY_ID = /^(0x[0-9a-fA-F]{40}|0x[0-9a-fA-F]{64}|[0-9a-fA-F]{64}|[1-9A-HJ-NP-Za-km-z]{32,88})$/;

export const str = (v) => (v === null || v === undefined ? '' : String(v));
const fam = (chain) => (CHAINS.has(chain) ? FAMILIES[CHAINS.get(chain)[0]] : null);

/** Validate an address for its chain (unknown chains never validate). */
export const isAddrFor = (chain, v) => { const f = fam(chain); return !!f && typeof v === 'string' && f.addr.test(v); };
export const isTxFor = (chain, v) => { const f = fam(chain); return !!f && typeof v === 'string' && f.tx.test(v); };
export const isEvmChain = (chain) => CHAINS.has(chain) && CHAINS.get(chain)[0] === 'evm';

/** Normalise an identifier from a route/search: EVM-style hex is lowercased, base58 kept as-is. */
export function normId(v) {
  const t = str(v).trim();
  return /^(0x)?[0-9a-fA-F]+$/.test(t) && (t.startsWith('0x') || t.length === 64) ? t.toLowerCase() : t;
}

export function chainLabel(chain) {
  if (CHAINS.has(chain)) return CHAINS.get(chain)[2];
  return EXTRA_LABELS.get(chain) || str(chain) || '—';
}

/** Explorer URL, only for identifiers that pass their chain's regex. */
export function explorerUrl(chain, kind, value) {
  if (!CHAINS.has(chain)) return null;
  const [family, base] = CHAINS.get(chain);
  const f = FAMILIES[family];
  if (kind === 'address' && f.addr.test(str(value))) return f.url(base, kind, value);
  if (kind === 'tx' && f.tx.test(str(value))) return f.url(base, kind, value);
  if (kind === 'block' && Number.isSafeInteger(value) && value >= 0) return f.url(base, kind, String(value));
  return null;
}

export function explorerLink(chain, kind, value, label = 'explorer') {
  const url = explorerUrl(chain, kind, value);
  return url ? extLink(url, label, 'ext') : null;
}

/** Name for the "block" field per chain family. */
export function blockWord(chain) {
  const f = CHAINS.has(chain) ? CHAINS.get(chain)[0] : 'evm';
  return f === 'solana' ? 'slot' : f === 'aptos' ? 'version' : 'block';
}

// --- strings ---------------------------------------------------------------

const MAX_DISPLAY = 20000;
// Control characters, zero-width and bidi overrides are rendered as visible escapes.
const CTRL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F​-‏‪-‮⁠-⁩﻿]/g;

export function sanitize(v) {
  let t = str(v);
  if (t.length > MAX_DISPLAY) t = `${t.slice(0, MAX_DISPLAY)} …[truncated ${t.length - MAX_DISPLAY} chars]`;
  return t.replace(CTRL, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

const NOT_TLD = new Set(['exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'vbs', 'tmp', 'log', 'dat', 'json', 'txt', 'ini', 'cfg', 'conf', 'bin']);

/** Defang any free text: URLs schemes, IPv4, domain-like tokens, e-mails. */
export function defang(v) {
  let t = sanitize(v);
  t = t.replace(/\b(https?):\/\//gi, (m, sch) => `${sch.replace(/^h(tt|TT)p/i, 'hxxp')}://`);
  t = t.replace(/\b([a-z][a-z0-9+.-]{1,20}):\/\//gi, (m, sch) => (/^hxxps?$/i.test(sch) ? m : `${sch}[://]`));
  t = t.replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, (m) => m.replace(/\./g, '[.]'));
  t = t.replace(/\b(?:[a-z0-9_-]+\.)+([a-z][a-z0-9-]{1,23})\b/gi, (m, tld) => (NOT_TLD.has(tld.toLowerCase()) ? m : m.replace(/\./g, '[.]')));
  t = t.replace(/@(?=[a-z0-9-]+\[\.\])/gi, '[@]');
  return t;
}

export function defangIoc(type, value) {
  const v = str(value);
  if (type === 'ipv6') return sanitize(v).replace(/:/g, '[:]');
  if (type === 'ipv4' || type === 'domain' || type === 'url') return defang(v);
  return sanitize(v);
}

export function iocDisplay(ioc) {
  const base = defangIoc(ioc.type, ioc.value);
  return ioc.port !== null && ioc.port !== undefined && ioc.type !== 'url' ? `${base}:${ioc.port}` : base;
}

export function iocRaw(ioc) {
  const v = str(ioc.value);
  return ioc.port !== null && ioc.port !== undefined && ioc.type !== 'url' ? `${v}:${ioc.port}` : v;
}

export function shortHex(v, head = 6, tail = 4) {
  const t = str(v);
  return t.length > head + tail + 2 ? `${t.slice(0, head)}…${t.slice(-tail)}` : t;
}

// --- numbers / dates -------------------------------------------------------

export const fmtNum = (n) => (Number.isFinite(n) ? n.toLocaleString('en-US') : '—');

export function ts(iso) {
  const t = Date.parse(str(iso));
  return Number.isFinite(t) ? t : NaN;
}

export function fmtDate(iso, withTime = true) {
  const t = ts(iso);
  if (!Number.isFinite(t)) return '—';
  const d = new Date(t).toISOString();
  return withTime ? `${d.slice(0, 10)} ${d.slice(11, 16)}Z` : d.slice(0, 10);
}

export function relTime(iso) {
  const t = ts(iso);
  if (!Number.isFinite(t)) return '';
  const s = Math.round((Date.now() - t) / 1000);
  const a = Math.abs(s);
  const f = (n, u) => (s >= 0 ? `${n}${u} ago` : `in ${n}${u}`);
  if (a < 90) return 'just now';
  if (a < 5400) return f(Math.round(a / 60), 'm');
  if (a < 129600) return f(Math.round(a / 3600), 'h');
  if (a < 86400 * 60) return f(Math.round(a / 86400), 'd');
  return f(Math.round(a / (86400 * 30)), 'mo');
}

export function timeEl(iso, withTime = true) {
  const node = h('time', { class: 'num', title: relTime(iso) }, fmtDate(iso, withTime));
  const t = ts(iso);
  if (Number.isFinite(t)) node.setAttribute('datetime', new Date(t).toISOString());
  return node;
}

export function fmtBytes(n) {
  if (!Number.isFinite(n) || n < 0) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
