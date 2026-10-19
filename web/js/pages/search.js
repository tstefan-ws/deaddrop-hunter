import { h } from '../dom.js';
import { sanitize, chainLabel, iocDisplay, timeEl } from '../fmt.js';
import { pageHead, panel, contractLink, walletLink, clusterPill, statusPill, clusterHref } from '../ui.js';
import { diffValues, diffSummary } from '../diff.js';

const LIMIT = 50;

export function renderSearch(ctx) {
  const { d } = ctx;
  const q = (ctx.query.get('q') || '').trim();
  const input = document.getElementById('search-input');
  if (input && input.value !== q) input.value = q;
  const lq = q.toLowerCase();
  const has = (...xs) => xs.some((x) => typeof x === 'string' && x.toLowerCase().includes(lq));
  if (!lq) return h('div', null, pageHead({ title: 'Search', sub: 'Type a contract, wallet, IOC, tx hash, family or cluster in the search box.' }));

  const contracts = d.contracts.filter((c) => has(c.address, c.family, c.cluster_id, c.latest_value_decoded, ...c.operator_wallets, ...c.tags));
  const wallets = d.wallets.filter((w) => has(w.address, w.label, w.cluster_id));
  const iocs = d.iocs.filter((i) => has(i.value, iocDisplay(i)));
  const events = d.events.filter((e) => has(e.tx_hash, e.from, e.new_decoded));
  const clusters = d.clusters.filter((c) => has(c.id, c.name, c.family));
  const total = contracts.length + wallets.length + iocs.length + events.length + clusters.length;

  const list = (items, render) => (items.length ? h('ul', { class: 'feed' }, items.slice(0, LIMIT).map((x) => h('li', null, render(x)))) : h('p', { class: 'empty' }, 'No matches.'));

  return h('div', null,
    pageHead({ title: `Search: ${sanitize(q)}`, sub: `${total} match${total === 1 ? '' : 'es'}` }),
    h('div', { class: 'grid grid-2' },
      panel(`Contracts (${contracts.length})`, list(contracts, (c) => [h('div', { class: 'meta' }, chainLabel(c.chain), statusPill(c.status), clusterPill(d, c.cluster_id)), contractLink(c.chain, c.address, true)])),
      panel(`Wallets (${wallets.length})`, list(wallets, (w) => [h('div', { class: 'meta' }, chainLabel(w.chain), h('span', { class: 'pill' }, sanitize(w.role))), walletLink(d, w.chain, w.address, true)])),
      panel(`IOCs (${iocs.length})`, list(iocs, (i) => [h('div', { class: 'meta' }, h('span', { class: 'mono' }, sanitize(i.type)), clusterPill(d, i.cluster_id)), h('a', { class: 'ioc', href: `#/iocs?q=${encodeURIComponent(i.value)}` }, iocDisplay(i))])),
      panel(`Clusters (${clusters.length})`, list(clusters, (c) => h('a', { href: clusterHref(c.id) }, sanitize(c.name || c.id)))),
      panel(`Rotations (${events.length})`, list(events, (e) => [
        h('div', { class: 'meta' }, timeEl(e.timestamp), h('a', { class: 'addr', href: `#/contracts/${encodeURIComponent(e.chain)}/${encodeURIComponent(e.contract)}?tx=${encodeURIComponent(e.tx_hash)}` }, `tx ${sanitize(e.tx_hash).slice(0, 14)}…`)),
        diffSummary(diffValues(e.old_decoded, e.new_decoded))]))));
}
