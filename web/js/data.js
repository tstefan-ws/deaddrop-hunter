// Data loading and indexing. Tries ./data/ (published site) and falls back to ./sample-data/.
import { isTxFor, normId, ts, str } from './fmt.js';

const FILES = ['contracts', 'wallets', 'events', 'iocs', 'clusters'];

async function fetchJson(url) {
  const res = await fetch(url, { cache: 'no-cache', credentials: 'same-origin' });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

const arr = (v) => (Array.isArray(v) ? v : []);
const strs = (v) => arr(v).filter((x) => typeof x === 'string');
const lowerHex = (v) => normId(v);
const int = (v) => (Number.isFinite(Number(v)) && v !== null && v !== '' ? Number(v) : null);
const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

function normContract(c) {
  c = obj(c);
  return {
    chain: str(c.chain), address: lowerHex(c.address), cluster_id: c.cluster_id ? str(c.cluster_id) : null,
    family: str(c.family) || 'unknown', hunt_ids: strs(c.hunt_ids), operator_wallets: strs(c.operator_wallets).map(lowerHex),
    selectors: strs(c.selectors), decoder: str(c.decoder) || 'undecoded', update_count: int(c.update_count) ?? 0,
    first_seen: str(c.first_seen), last_seen: str(c.last_seen), status: c.status === 'active' ? 'active' : 'dormant',
    latest_value_raw: str(c.latest_value_raw), latest_value_decoded: c.latest_value_decoded === null || c.latest_value_decoded === undefined ? null : str(c.latest_value_decoded),
    tags: strs(c.tags),
  };
}

function normWallet(w) {
  w = obj(w);
  return {
    chain: str(w.chain), address: lowerHex(w.address), role: str(w.role) || 'operator', label: str(w.label),
    cluster_id: w.cluster_id ? str(w.cluster_id) : null, contracts: strs(w.contracts).map(lowerHex),
    tx_count: int(w.tx_count) ?? 0, first_seen: str(w.first_seen), last_seen: str(w.last_seen),
    watched: w.watched === true, funded_by: strs(w.funded_by).map(lowerHex),
  };
}

function normEvent(e) {
  e = obj(e);
  return {
    chain: str(e.chain), block: int(e.block) ?? 0, timestamp: str(e.timestamp), tx_hash: lowerHex(e.tx_hash),
    contract: lowerHex(e.contract), from: e.from ? lowerHex(e.from) : null, selector: e.selector ? str(e.selector) : null,
    hunt_id: str(e.hunt_id), old_raw: str(e.old_raw), new_raw: str(e.new_raw),
    old_decoded: e.old_decoded === null || e.old_decoded === undefined ? null : str(e.old_decoded),
    new_decoded: e.new_decoded === null || e.new_decoded === undefined ? null : str(e.new_decoded),
    decoder: str(e.decoder),
  };
}

function normIoc(i) {
  i = obj(i);
  const type = str(i.type);
  return {
    type, value: type.startsWith('evm-') ? lowerHex(i.value) : str(i.value), port: int(i.port),
    family: str(i.family) || 'unknown', cluster_id: i.cluster_id ? str(i.cluster_id) : null, chain: str(i.chain),
    contracts: strs(i.contracts).map(lowerHex), first_seen: str(i.first_seen), last_seen: str(i.last_seen),
    times_seen: int(i.times_seen) ?? 0, current: i.current === true, confidence: int(i.confidence), enrichment: obj(i.enrichment),
  };
}

function normCluster(c) {
  c = obj(c);
  return {
    id: str(c.id), name: str(c.name), family: str(c.family) || 'unknown', chains: strs(c.chains),
    contracts: strs(c.contracts).map(lowerHex), wallets: strs(c.wallets).map(lowerHex), ioc_count: int(c.ioc_count) ?? 0,
    first_seen: str(c.first_seen), last_seen: str(c.last_seen),
  };
}

function normMeta(m) {
  m = obj(m);
  return {
    schema_version: int(m.schema_version), generated_at: str(m.generated_at), tool_version: str(m.tool_version),
    cursors: arr(m.cursors).map((c) => ({
      chain: str(c && c.chain), hunt_id: str(c && c.hunt_id), from_block: int(c && c.from_block),
      to_block: int(c && c.to_block), updated_at: str(c && c.updated_at),
    })),
    counts: obj(m.counts),
  };
}

const push = (map, k, v) => { if (!map.has(k)) map.set(k, []); map.get(k).push(v); };
export const key = (chain, address) => `${chain}:${address}`;

export async function loadData() {
  let base = './data/';
  let sample = false;
  let meta;
  try {
    meta = await fetchJson(`${base}meta.json`);
  } catch {
    base = './sample-data/';
    sample = true;
    meta = await fetchJson(`${base}meta.json`);
  }
  const warnings = [];
  const loaded = await Promise.all(FILES.map((f) => fetchJson(`${base}${f}.json`).catch((err) => {
    warnings.push(String(err.message || err));
    return [];
  })));
  const [contracts, wallets, events, iocs, clusters] = loaded.map(arr);

  const d = {
    base, sample, warnings,
    meta: normMeta(meta),
    contracts: contracts.map(normContract),
    wallets: wallets.map(normWallet),
    // newest first by time: block numbers are not comparable across chains
    events: events.map(normEvent).sort((a, b) => (ts(b.timestamp) || 0) - (ts(a.timestamp) || 0) || b.block - a.block),
    iocs: iocs.map(normIoc),
    clusters: clusters.map(normCluster),
  };
  index(d);
  return d;
}

function index(d) {
  d.contractByKey = new Map(d.contracts.map((c) => [key(c.chain, c.address), c]));
  d.walletByKey = new Map(d.wallets.map((w) => [key(w.chain, w.address), w]));
  d.clusterById = new Map(d.clusters.map((c) => [c.id, c]));
  d.eventsByContract = new Map();
  d.eventsByFrom = new Map();
  d.eventByTx = new Map();
  for (const e of d.events) {
    push(d.eventsByContract, key(e.chain, e.contract), e);
    if (e.from) push(d.eventsByFrom, key(e.chain, e.from), e);
    if (isTxFor(e.chain, e.tx_hash)) d.eventByTx.set(e.tx_hash, e);
  }
  d.iocsByContract = new Map();
  for (const i of d.iocs) for (const c of i.contracts) push(d.iocsByContract, c, i);

  // Stable colour slot per cluster (by id order) for charts.
  const ids = [...new Set([...d.clusters.map((c) => c.id), ...d.contracts.map((c) => c.cluster_id).filter(Boolean)])].sort();
  d.clusterSlot = new Map(ids.map((id, i) => [id, i % 6]));

  const chains = new Set();
  [...d.contracts, ...d.wallets, ...d.meta.cursors].forEach((x) => { if (x.chain) chains.add(x.chain); });
  d.chains = [...chains].sort();
}

export function slotClass(d, clusterId, prefix = 'c') {
  return d.clusterSlot.has(clusterId) ? `${prefix}-${d.clusterSlot.get(clusterId)}` : `${prefix}-x`;
}

/** Events relevant to a wallet: sent by it, or touching contracts it controls. */
export function walletEvents(d, w) {
  const seen = new Set();
  const out = [];
  const add = (e) => { if (!seen.has(e)) { seen.add(e); out.push(e); } };
  (d.eventsByFrom.get(key(w.chain, w.address)) || []).forEach(add);
  const payout = w.role === 'payout';
  for (const addr of w.contracts) {
    // payout wallets live on another chain (e.g. monero) than the contracts that reference them
    const chains = payout ? d.contracts.filter((c) => c.address === addr).map((c) => c.chain) : [w.chain];
    for (const ch of chains) {
      (d.eventsByContract.get(key(ch, addr)) || [])
        .filter((e) => !payout || (e.new_decoded || '').includes(w.address) || (e.old_decoded || '').includes(w.address))
        .forEach(add);
    }
  }
  return out.sort((a, b) => (ts(b.timestamp) || 0) - (ts(a.timestamp) || 0) || b.block - a.block);
}

export function maxBlock(events) {
  return events.reduce((m, e) => Math.max(m, e.block || 0), 0);
}

// --- feeds -----------------------------------------------------------------

const SAFE_PATH = /^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._\-/]{0,200}$/;

/** Reads ./feeds/index.json; returns null when absent. Accepts a few plausible shapes. */
export async function loadFeeds() {
  let raw;
  try {
    const res = await fetch('./feeds/index.json', { cache: 'no-cache', credentials: 'same-origin' });
    if (!res.ok) return null;
    raw = await res.json();
  } catch {
    return null;
  }
  let list = [];
  let generated = '';
  if (Array.isArray(raw)) list = raw;
  else if (raw && typeof raw === 'object') {
    list = arr(raw.files).length ? raw.files : arr(raw.feeds).length ? raw.feeds : arr(raw.items);
    generated = str(raw.generated_at);
  }
  const files = list.map((f) => {
    f = obj(f);
    let path = str(f.path || f.file || f.name).replace(/^\.\//, '');
    if (path.startsWith('feeds/')) path = path.slice(6);
    const ok = SAFE_PATH.test(path);
    const sha = str(f.sha256 || f.hash).toLowerCase();
    const size = int(f.size ?? f.bytes);
    return {
      path, href: ok ? `./feeds/${path}` : null,
      format: str(f.format || f.type) || (path.split('.').pop() || '').toUpperCase(),
      description: str(f.description), size, sha256: /^[0-9a-f]{64}$/.test(sha) ? sha : '',
    };
  }).filter((f) => f.path);
  return { files, generated };
}


const TEMPLATE_PATH = /^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._\-/<>{}]{0,200}$/;

/** Reads ./feeds/api/v1/index.json (static JSON API); returns null when absent. */
export async function loadApiIndex() {
  let raw;
  try {
    const res = await fetch('./feeds/api/v1/index.json', { cache: 'no-cache', credentials: 'same-origin' });
    if (!res.ok) return null;
    raw = await res.json();
  } catch {
    return null;
  }
  let list = [];
  if (Array.isArray(raw)) list = raw;
  else if (raw && typeof raw === 'object') {
    list = [raw.endpoints, raw.files, raw.data, raw.items].find((x) => Array.isArray(x) && x.length) || [];
  }
  const endpoints = list.map((e) => {
    const o = typeof e === 'string' ? { path: e } : obj(e);
    let path = str(o.path || o.endpoint || o.url || o.href || o.file).replace(/^\.\//, '');
    path = path.replace(/^(feeds\/)?api\/v1\//, '');
    if (!TEMPLATE_PATH.test(path)) return null;
    const template = /[<>{}]/.test(path);
    let url = '';
    try { url = new URL('./feeds/api/v1/', window.location.href).href.split('#')[0] + path; } catch { url = ''; }
    return {
      path, template, url, href: template ? null : `./feeds/api/v1/${path}`,
      description: str(o.description || o.title), count: int(o.count ?? o.records),
    };
  }).filter(Boolean);
  return { endpoints, generated: raw && typeof raw === 'object' ? str(raw.generated_at) : '' };
}
