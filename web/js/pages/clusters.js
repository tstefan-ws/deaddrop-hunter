import { h } from '../dom.js';
import { sanitize, timeEl, chainLabel, fmtNum, iocDisplay, ts } from '../fmt.js';
import { sortableTable } from '../table.js';
import { activityChart } from '../charts.js';
import { clusterGraph } from '../graph.js';
import {
  pageHead, panel, kv, statusPill, clusterPill, contractLink, walletLink, notFound, clusterHref, watchedPill,
} from '../ui.js';
import { slotClass } from '../data.js';

function clusterEvents(d, cl) {
  const set = new Set(cl.contracts);
  return d.events.filter((e) => set.has(e.contract));
}

export function renderClusters(ctx) {
  const { d } = ctx;
  const list = d.clusters.filter((c) => !ctx.chain || c.chains.includes(ctx.chain));
  const cards = list.slice().sort((a, b) => (ts(b.last_seen) || 0) - (ts(a.last_seen) || 0)).map((c) => {
    const cs = d.contracts.filter((x) => x.cluster_id === c.id);
    const ev = clusterEvents(d, c).length;
    const watched = d.wallets.some((w) => w.cluster_id === c.id && w.watched);
    return h('a', { class: 'card', href: clusterHref(c.id) },
      h('div', { class: 'card-head' },
        h('span', { class: 'id' }, h('span', { class: `swatch ${slotClass(d, c.id, 'sw')}` }), ' ', sanitize(c.id)),
        cs.some((x) => x.status === 'active') ? statusPill('active') : statusPill('dormant')),
      h('h3', { class: 'wrap-any' }, sanitize(c.name || c.id)),
      h('div', { class: 'card-stats' },
        h('span', null, h('b', null, fmtNum(c.contracts.length)), ' contracts'),
        h('span', null, h('b', null, fmtNum(c.wallets.length)), ' wallets'),
        h('span', null, h('b', null, fmtNum(c.ioc_count)), ' IOCs'),
        h('span', null, h('b', null, fmtNum(ev)), ' rotations')),
      h('div', { class: 'card-stats' },
        h('span', { class: 'mono' }, sanitize(c.family)), h('span', null, c.chains.map(chainLabel).join(', ')),
        h('span', null, 'last ', timeEl(c.last_seen, false)), watched ? watchedPill() : null));
  });
  return h('div', null,
    pageHead({ title: 'Clusters', sub: 'Contracts and wallets grouped by shared operator wallet.' }),
    cards.length ? h('div', { class: 'cards' }, cards) : h('p', { class: 'empty' }, 'No clusters.'));
}

export function renderCluster(ctx, id) {
  const { d } = ctx;
  const cl = d.clusterById.get(id);
  if (!cl) return notFound('Cluster', id);
  const contracts = d.contracts.filter((c) => c.cluster_id === id || cl.contracts.includes(c.address));
  const wallets = d.wallets.filter((w) => w.cluster_id === id || cl.wallets.includes(w.address));
  const iocs = d.iocs.filter((i) => i.cluster_id === id);
  const events = clusterEvents(d, cl);

  const ct = sortableTable({
    caption: 'Cluster contracts',
    sort: { key: 'last', dir: 'desc' },
    columns: [
      { key: 'addr', label: 'Contract', sort: (c) => c.address, render: (c) => contractLink(c.chain, c.address) },
      { key: 'chain', label: 'Chain', sort: (c) => c.chain, render: (c) => chainLabel(c.chain) },
      { key: 'status', label: 'Status', sort: (c) => c.status, render: (c) => statusPill(c.status) },
      { key: 'updates', label: 'Updates', num: true, sort: (c) => c.update_count, render: (c) => fmtNum(c.update_count) },
      { key: 'last', label: 'Last seen', sort: (c) => ts(c.last_seen) || 0, render: (c) => timeEl(c.last_seen) },
    ],
  });
  ct.update(contracts);

  const walletList = wallets.length ? h('ul', { class: 'feed' }, wallets.map((w) => h('li', null,
    h('div', { class: 'meta' }, h('span', { class: 'pill' }, sanitize(w.role)), chainLabel(w.chain), w.watched ? watchedPill() : null),
    h('div', null, walletLink(d, w.chain, w.address, true)),
    w.label ? h('div', { class: 'faint' }, sanitize(w.label)) : null))) : h('p', { class: 'empty' }, 'No wallets.');

  const iocList = iocs.length ? h('ul', { class: 'feed' }, iocs.filter((i) => !i.type.startsWith('evm-')).map((i) => h('li', null,
    h('div', { class: 'meta' }, h('span', { class: 'mono' }, sanitize(i.type)), i.current ? h('span', { class: 'pill pill-active' }, 'current') : h('span', { class: 'pill' }, 'historic')),
    h('span', { class: 'ioc' }, iocDisplay(i))))) : h('p', { class: 'empty' }, 'No IOCs.');

  return h('div', null,
    pageHead({
      crumbs: [['Clusters', '#/clusters'], [sanitize(id)]],
      title: sanitize(cl.name || id),
      sub: [clusterPill(d, id), ' ', h('span', { class: 'mono' }, sanitize(cl.family)), ` · ${cl.chains.map(chainLabel).join(', ')} · `, timeEl(cl.first_seen, false), ' → ', timeEl(cl.last_seen, false)],
    }),
    panel('Network: wallet → contract → IOC (click or press Enter on a node)', clusterGraph(d, cl)),
    h('div', { class: 'grid grid-2 section' },
      panel('Summary', kv([
        ['id', h('span', { class: 'mono' }, sanitize(id))],
        ['family', h('span', { class: 'mono' }, sanitize(cl.family))],
        ['chains', cl.chains.map(chainLabel).join(', ')],
        ['contracts', fmtNum(contracts.length)],
        ['wallets', fmtNum(wallets.length)],
        ['IOCs', h('a', { href: `#/iocs?cluster=${encodeURIComponent(id)}` }, fmtNum(cl.ioc_count))],
        ['rotations', fmtNum(events.length)],
      ])),
      panel('Update activity', activityChart(d, events, { title: 'Cluster updates' }))),
    h('div', { class: 'section' }, panel('Contracts', ct.el)),
    h('div', { class: 'grid grid-2 section' }, panel('Wallets', walletList), panel('Network IOCs', iocList)));
}

