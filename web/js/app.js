// Entry point: theme, data load, hash router, global search and chain filter.
import { h, mount } from './dom.js';
import { loadData } from './data.js';
import { prefs, watchlist, onWatchChange } from './store.js';
import { fmtDate, relTime, ts, RE_CHAIN, chainLabel, sanitize, normId } from './fmt.js';
import { renderOverview } from './pages/overview.js';
import { renderContracts, renderContract } from './pages/contracts.js';
import { renderWallets, renderWallet } from './pages/wallets.js';
import { renderIocs } from './pages/iocs.js';
import { renderClusters, renderCluster } from './pages/clusters.js';
import { renderWatchlist, newSince } from './pages/watchlist.js';
import { renderFeeds } from './pages/feeds.js';
import { renderSearch } from './pages/search.js';
import { notFound, scanHealth } from './ui.js';

const root = document.documentElement;
const main = document.getElementById('main');
let data = null;

// ---- theme ----------------------------------------------------------------
function effectiveTheme() {
  if (root.dataset.theme === 'light' || root.dataset.theme === 'dark') return root.dataset.theme;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
function applyTheme(t) {
  if (t) root.dataset.theme = t; else delete root.dataset.theme;
  const btn = document.getElementById('theme-toggle');
  if (btn) {
    const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
    btn.setAttribute('aria-label', `Switch to ${next} theme`);
    btn.title = `Switch to ${next} theme`;
  }
}
applyTheme(prefs.theme);
document.getElementById('theme-toggle').addEventListener('click', () => {
  const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
  prefs.theme = next;
  applyTheme(next);
});

// ---- routing --------------------------------------------------------------
function parseHash() {
  const raw = window.location.hash.replace(/^#\/?/, '');
  const [path, qs] = raw.split('?');
  const parts = path.split('/').filter(Boolean).map((p) => { try { return decodeURIComponent(p); } catch { return ''; } });
  return { parts, query: new URLSearchParams(qs || '') };
}

const SEG_OK = /^[A-Za-z0-9_.:-]{1,128}$/;

function route(ctx) {
  const [section, a, b] = ctx.parts;
  if (ctx.parts.some((p) => !SEG_OK.test(p))) return ['overview', notFound('Page', ctx.parts.join('/'))];
  switch (section || '') {
    case '': return ['overview', renderOverview(ctx)];
    case 'contracts':
      if (a && b) return ['contracts', RE_CHAIN.test(a) ? renderContract(ctx, a, normId(b)) : notFound('Contract', b)];
      return ['contracts', renderContracts(ctx)];
    case 'wallets':
      if (a && b) return ['wallets', RE_CHAIN.test(a) ? renderWallet(ctx, a, normId(b)) : notFound('Wallet', b)];
      return ['wallets', renderWallets(ctx)];
    case 'iocs': return ['iocs', renderIocs(ctx)];
    case 'clusters':
      if (a) return ['clusters', renderCluster(ctx, a)];
      return ['clusters', renderClusters(ctx)];
    case 'watchlist': return ['watchlist', renderWatchlist(ctx)];
    case 'feeds': return ['feeds', renderFeeds(ctx)];
    case 'search': return ['', renderSearch(ctx)];
    default: return ['', notFound('Page', ctx.parts.join('/'))];
  }
}

let lastPath = null;
function render() {
  if (!data) return;
  const { parts, query } = parseHash();
  const chain = data.chains.includes(prefs.chain) ? prefs.chain : '';
  const ctx = {
    d: data, parts, query, chain,
    inChain: (x) => !chain || x.chain === chain || (x.chain === 'monero' && x.cluster_id && data.contracts.some((c) => c.cluster_id === x.cluster_id && c.chain === chain)),
    rerender: render,
  };
  let navKey; let page;
  try {
    [navKey, page] = route(ctx);
  } catch (err) {
    navKey = '';
    page = h('div', { class: 'panel' }, h('h1', null, 'Something went wrong rendering this page'), h('pre', { class: 'value' }, sanitize(String(err && err.stack ? err.stack : err))));
  }
  mount(main, page);
  document.querySelectorAll('.nav a[data-route]').forEach((a) => {
    if (a.dataset.route === navKey) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  });
  const h1 = main.querySelector('h1');
  document.title = `${h1 ? h1.textContent : 'deaddrop-hunter'} · deaddrop-hunter`;
  const path = parts.join('/');
  if (path !== lastPath) {
    if (!query.get('tx')) window.scrollTo(0, 0);
    if (lastPath !== null && h1) h1.focus({ preventScroll: true });
    lastPath = path;
  }
  updateBadge();
}

function updateBadge() {
  const badge = document.getElementById('watch-badge');
  if (!badge || !data) return;
  let n = 0;
  for (const it of watchlist.all()) n += newSince(data, it).length;
  badge.hidden = n === 0;
  badge.textContent = String(n);
  badge.setAttribute('aria-label', `${n} new rotations`);
}

// ---- global search ----------------------------------------------------------
document.getElementById('search-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  const input = document.getElementById('search-input');
  const q = input.value.trim();
  if (!q || !data) return;
  const id = normId(q);
  const enc = encodeURIComponent;
  // Exact identifier match on any chain (EVM hex is case-insensitive, base58 is not).
  const c = data.contracts.find((x) => x.address === id);
  if (c) { window.location.hash = `#/contracts/${enc(c.chain)}/${enc(id)}`; return; }
  const w = data.wallets.find((x) => x.address === id);
  if (w) { window.location.hash = `#/wallets/${enc(w.chain)}/${enc(id)}`; return; }
  const e = data.eventByTx.get(id);
  if (e) { window.location.hash = `#/contracts/${enc(e.chain)}/${enc(e.contract)}?tx=${enc(id)}`; return; }
  window.location.hash = `#/search?q=${enc(q)}`;
});

document.addEventListener('keydown', (ev) => {
  if (ev.key !== '/' || ev.ctrlKey || ev.metaKey || ev.altKey) return;
  const el = document.activeElement;
  if (el && (el.tagName === 'INPUT' || el.tagName === 'SELECT' || el.tagName === 'TEXTAREA' || el.isContentEditable)) return;
  ev.preventDefault();
  document.getElementById('search-input').focus();
});

// ---- boot -------------------------------------------------------------------
function setupChrome(d) {
  const banner = document.getElementById('banner');
  if (d.sample) {
    banner.replaceChildren(h('strong', null, 'SAMPLE DATA'), ' — ./data/meta.json was not found, showing bundled illustrative data from ./sample-data/. Not real-time intelligence.');
    banner.hidden = false;
  } else if (d.warnings.length) {
    banner.replaceChildren(h('strong', null, 'Partial data'), ` — ${d.warnings.length} file(s) failed to load: ${sanitize(d.warnings.join('; '))}`);
    banner.hidden = false;
  }
  const sel = document.getElementById('chain-filter');
  for (const c of d.chains) sel.append(h('option', { value: c }, chainLabel(c)));
  sel.value = d.chains.includes(prefs.chain) ? prefs.chain : '';
  sel.addEventListener('change', () => { prefs.chain = sel.value; render(); });
  const last = d.meta.cursors.reduce((m, c) => (c.updated_at > m ? c.updated_at : m), d.meta.generated_at || '');
  const chip = document.getElementById('data-chip');
  const chipText = document.getElementById('data-chip-text');
  if (chip && chipText && last) {
    // Say whether scanning is still happening, not just when it last did: a reader cannot
    // tell a quiet chain from a stopped watcher without this.
    const health = d.meta.cursors.map((c) => scanHealth(c, d.meta)).filter(Boolean);
    const state = health.some((x) => x.state === 'stopped') ? 'stopped'
      : health.some((x) => x.state === 'late') ? 'late' : 'live';
    const dueIn = health.length ? Math.min(...health.map((x) => x.dueIn)) : 0;
    const due = state === 'stopped' ? 'scanning stopped'
      : dueIn > 0 ? `next in ${Math.max(1, Math.round(dueIn / 60000))}m`
      : `due ${Math.round(-dueIn / 60000)}m ago`;
    chipText.textContent = `Scan ${state} · ${relTime(last)} · ${due}`;
    chip.title = `Last scan ${fmtDate(last)}; expected every ${d.meta.scan_interval_minutes || 60} minutes`;
    chip.classList.toggle('stale', state !== 'live');
    chip.hidden = false;
  }
  const foot = document.getElementById('footer-meta');
  foot.textContent = `Data generated at ${fmtDate(d.meta.generated_at)} · deaddrop-hunter ${sanitize(d.meta.tool_version || '?')} · schema v${d.meta.schema_version ?? '?'}${d.sample ? ' · sample data' : ''}`;
}

async function boot() {
  try {
    data = await loadData();
  } catch (err) {
    mount(main, h('div', { class: 'panel' },
      h('h1', null, 'Could not load data'),
      h('p', null, 'Neither ./data/meta.json nor ./sample-data/meta.json could be loaded. If you opened index.html from disk, serve the folder over HTTP instead (e.g. python -m http.server).'),
      h('pre', { class: 'value' }, sanitize(String(err && err.message ? err.message : err)))));
    return;
  }
  setupChrome(data);
  onWatchChange(updateBadge);
  window.addEventListener('hashchange', render);
  render();
}

boot();

