import { h } from '../dom.js';
import { fmtNum, shortHex, timeEl, relTime, chainLabel, sanitize, blockWord, explorerLink } from '../fmt.js';
import { key } from '../data.js';
import { activityChart } from '../charts.js';
import { diffValues, diffSummary } from '../diff.js';
import { pageHead, panel, clusterPill, contractLink, clusterHref, statusPill, scanHealth } from '../ui.js';

function stat(label, value, note, href, accent) {
  const inner = [h('div', { class: 'stat-label' }, label), h('div', { class: `stat-value${accent ? ' accent' : ''}` }, value), note ? h('div', { class: 'stat-note' }, note) : null];
  return href ? h('a', { class: 'stat', href }, inner) : h('div', { class: 'stat' }, inner);
}

export function rotationFeed(d, events, limit = 12) {
  if (!events.length) return h('p', { class: 'empty' }, 'No rotations recorded.');
  const ul = h('ul', { class: 'feed' });
  for (const e of events.slice(0, limit)) {
    const c = d.contractByKey.get(key(e.chain, e.contract));
    ul.append(h('li', null,
      h('div', { class: 'meta' },
        timeEl(e.timestamp), h('span', { class: 'faint' }, relTime(e.timestamp)),
        h('span', null, chainLabel(e.chain)),
        h('a', { class: 'addr', href: `#/contracts/${encodeURIComponent(e.chain)}/${encodeURIComponent(e.contract)}?tx=${encodeURIComponent(e.tx_hash)}` }, shortHex(sanitize(e.contract), 8, 4)),
        c ? clusterPill(d, c.cluster_id) : null),
      diffSummary(diffValues(e.old_decoded, e.new_decoded))));
  }
  return ul;
}

export function renderOverview(ctx) {
  const { d, inChain } = ctx;
  const contracts = d.contracts.filter(inChain);
  const wallets = d.wallets.filter(inChain);
  const events = d.events.filter(inChain);
  const iocs = d.iocs.filter(inChain);
  const clusterIds = new Set(contracts.map((c) => c.cluster_id).filter(Boolean));
  const clusters = d.clusters.filter((c) => !ctx.chain || clusterIds.has(c.id) || c.chains.includes(ctx.chain));
  const operators = wallets.filter((w) => w.role === 'operator');
  const active = contracts.filter((c) => c.status === 'active');

  const stats = h('div', { class: 'stats' },
    stat('Contracts', fmtNum(contracts.length), `${fmtNum(events.length)} rotations`, '#/contracts'),
    stat('Active', fmtNum(active.length), 'updated < 30 days', '#/contracts?status=active', true),
    stat('Operator wallets', fmtNum(operators.length), `${wallets.filter((w) => w.watched).length} watched`, '#/wallets'),
    stat('Current IOCs', fmtNum(iocs.filter((i) => i.current).length), `${fmtNum(iocs.length)} total`, '#/iocs?current=1'),
    stat('Clusters', fmtNum(clusters.length), null, '#/clusters'),
    stat('New', fmtNum(contracts.filter((c) => c.new).length),
      `contracts in ${d.meta.new_window_hours || 24}h · ${fmtNum(iocs.filter((i) => i.new).length)} IOCs`,
      '#/contracts?new=1', contracts.some((c) => c.new)));

  // hunt coverage per chain
  const cursors = d.meta.cursors.filter((c) => !ctx.chain || c.chain === ctx.chain);
  const byChain = new Map();
  for (const c of cursors) {
    const cur = byChain.get(c.chain) || { from: Infinity, to: -Infinity, at: '', hunts: [] };
    if (Number.isFinite(c.from_block)) cur.from = Math.min(cur.from, c.from_block);
    if (Number.isFinite(c.to_block)) cur.to = Math.max(cur.to, c.to_block);
    if (c.updated_at > cur.at) cur.at = c.updated_at;
    cur.hunts.push(c.hunt_id);
    byChain.set(c.chain, cur);
  }
  // --- scan status: is this data still being refreshed, and how far behind is it? -------
  const health = d.meta.cursors.map((c) => [c, scanHealth(c, d.meta)]).filter(([, h]) => h);
  const worst = health.reduce((w, [, h]) => (h.state === 'stopped' ? 'stopped'
    : h.state === 'late' && w !== 'stopped' ? 'late' : w), 'live');
  const soonest = health.reduce((m, [, h]) => Math.min(m, h.dueIn), Infinity);
  const scanPanel = health.length ? h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Scan status' },
    h('table', null,
      h('thead', null, h('tr', null, ['Scan', 'Chain', 'State', 'Last run', 'Blocks behind'].map((x) => h('th', { scope: 'col' }, x)))),
      h('tbody', null, health
        .sort((a, b) => (a[1].ranMs < b[1].ranMs ? 1 : -1))
        .map(([c, hh]) => h('tr', null,
          h('td', { class: 'mono' }, sanitize(c.hunt_id)),
          h('td', null, chainLabel(c.chain)),
          h('td', null, h('span', { class: `pill pill-${hh.state === 'live' ? 'active' : 'dormant'}` }, hh.state)),
          h('td', null, timeEl(c.updated_at), ' ', h('span', { class: 'faint' }, relTime(c.updated_at))),
          h('td', { class: 'num' }, hh.behind === null ? '—' : fmtNum(hh.behind)))))))
    : h('p', { class: 'empty' }, 'No scan cursors yet.');

  const dueText = worst === 'stopped' ? 'scanning has stopped'
    : soonest > 0 ? `next scan due in ${Math.max(1, Math.round(soonest / 60000))} min`
    : `next scan overdue by ${Math.round(-soonest / 60000)} min`;

  const coverage = byChain.size ? h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Scanned ranges per chain' },
    h('table', null,
      h('thead', null, h('tr', null, ['Chain', 'Scanned range', 'Hunts', 'Last run'].map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', null, [...byChain].map(([chain, c]) => h('tr', null,
        h('td', null, chainLabel(chain)),
        h('td', { class: 'num mono' }, Number.isFinite(c.from) ? `${blockWord(chain)} ${fmtNum(c.from)} → ${fmtNum(c.to)}` : '—',
          Number.isFinite(c.to) ? explorerLink(chain, 'block', c.to, 'tip') : null),
        h('td', { class: 'mono' }, c.hunts.map(sanitize).join(', ')),
        h('td', null, timeEl(c.at))))))) : h('p', { class: 'empty' }, 'No cursor information in meta.json.');

  const last = d.meta.cursors.reduce((m, c) => (c.updated_at > m ? c.updated_at : m), d.meta.generated_at || '');

  // top clusters: most rotations
  const evCount = new Map();
  for (const e of events) {
    const c = d.contractByKey.get(key(e.chain, e.contract));
    if (c && c.cluster_id) evCount.set(c.cluster_id, (evCount.get(c.cluster_id) || 0) + 1);
  }
  const top = clusters.slice().sort((a, b) => (evCount.get(b.id) || 0) - (evCount.get(a.id) || 0) || (b.last_seen > a.last_seen ? 1 : -1)).slice(0, 5);
  const topList = top.length ? h('ul', { class: 'feed' }, top.map((c) => {
    const cs = d.contracts.filter((x) => x.cluster_id === c.id);
    return h('li', null,
      h('div', { class: 'card-head' }, h('a', { href: clusterHref(c.id) }, sanitize(c.name || c.id)), cs.some((x) => x.status === 'active') ? statusPill('active') : statusPill('dormant')),
      h('div', { class: 'meta' }, clusterPill(d, c.id), h('span', null, `${cs.length} contracts`), h('span', null, `${evCount.get(c.id) || 0} rotations`), h('span', null, `${c.ioc_count} IOCs`), h('span', null, 'last ', timeEl(c.last_seen, false))));
  })) : h('p', { class: 'empty' }, 'No clusters.');

  return h('div', null,
    pageHead({
      title: 'Overview',
      sub: ['Smart contracts used as malware dead drops (EtherHiding): config and C2 rotations observed on-chain. Last hunt ', timeEl(last), ` (${relTime(last)}).`],
    }),
    stats,
    h('div', { class: 'grid grid-2' },
      panel('Config updates per day, by cluster', activityChart(d, events, { byCluster: true, endIso: d.meta.generated_at })),
      panel('Latest rotations', rotationFeed(d, events, 8), h('a', { href: '#/contracts' }, 'all contracts →'))),
    h('div', { class: 'grid grid-2 section' },
      panel('Top clusters', topList, h('a', { href: '#/clusters' }, 'all clusters →')),
      panel(`Scan status · ${sanitize(dueText)}`, scanPanel)),
    h('div', { class: 'grid section' }, panel('Hunt coverage', coverage)),
    h('p', { class: 'faint section' }, 'Recent contracts: ', ...contracts.slice().sort((a, b) => (b.last_seen > a.last_seen ? 1 : -1)).slice(0, 4).flatMap((c, i) => [i ? ', ' : '', contractLink(c.chain, c.address)])));
}
