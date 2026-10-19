// Per-browser preferences and the personal watchlist. Every storage access is wrapped:
// private windows / blocked storage just fall back to in-memory state.

const PREFIX = 'ddh:';
const memory = new Map();

function read(key, fallback) {
  try {
    const raw = window.localStorage.getItem(PREFIX + key);
    if (raw !== null) return JSON.parse(raw);
  } catch { /* storage unavailable or corrupt */ }
  return memory.has(key) ? memory.get(key) : fallback;
}

function write(key, value) {
  memory.set(key, value);
  try { window.localStorage.setItem(PREFIX + key, JSON.stringify(value)); } catch { /* ignore */ }
}

export const prefs = {
  get theme() { const t = read('theme', null); return t === 'light' || t === 'dark' ? t : null; },
  set theme(v) { write('theme', v); },
  get chain() { const c = read('chain', ''); return typeof c === 'string' ? c : ''; },
  set chain(v) { write('chain', v); },
};

// Watchlist item: { kind: 'contract'|'wallet', chain, address, added, seenBlock }
const KINDS = new Set(['contract', 'wallet']);
const itemKey = (kind, chain, address) => `${kind}:${chain}:${address}`;

function loadList() {
  const list = read('watchlist', []);
  if (!Array.isArray(list)) return [];
  return list.filter((i) => i && KINDS.has(i.kind) && typeof i.chain === 'string' && typeof i.address === 'string');
}

const listeners = new Set();
export function onWatchChange(fn) { listeners.add(fn); }
function save(list) { write('watchlist', list); listeners.forEach((fn) => fn()); }

export const watchlist = {
  all: loadList,
  has(kind, chain, address) { return loadList().some((i) => itemKey(i.kind, i.chain, i.address) === itemKey(kind, chain, address)); },
  toggle(kind, chain, address, seenBlock) {
    const list = loadList();
    const k = itemKey(kind, chain, address);
    const idx = list.findIndex((i) => itemKey(i.kind, i.chain, i.address) === k);
    if (idx >= 0) list.splice(idx, 1);
    else list.push({ kind, chain, address, added: new Date().toISOString(), seenBlock: Number.isFinite(seenBlock) ? seenBlock : 0 });
    save(list);
    return idx < 0;
  },
  markSeen(kind, chain, address, block) {
    const list = loadList();
    const it = list.find((i) => itemKey(i.kind, i.chain, i.address) === itemKey(kind, chain, address));
    if (!it || !Number.isFinite(block) || (it.seenBlock || 0) >= block) return;
    it.seenBlock = block;
    save(list);
  },
};
