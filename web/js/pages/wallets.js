import { h, copyText } from '../dom.js';
import { sanitize, timeEl, chainLabel, explorerLink, fmtNum, ts } from '../fmt.js';
import { key, walletEvents, maxBlock } from '../data.js';
import { sortableTable } from '../table.js';
import { activityChart } from '../charts.js';
import { watchlist } from '../store.js';
import {
  pageHead, panel, kv, statusPill, clusterPill, contractLink, walletLink, starButton, watchedPill, notFound,
} from '../ui.js';
import { selectFilter, syncQuery, timeline } from './contracts.js';

const ROLES = ['operator', 'deployer', 'funder', 'payout'];

export function renderWallets(ctx) {
  const { d, query, inChain } = ctx;
  const rows = d.wallets.filter(inChain);
  const st = { q: query.get('q') || '', role: query.get('role') || '', watched: query.get('watched') || '' };
  const table = sortableTable({
    caption: 'Wallets',
    sort: { key: 'last', dir: 'desc' },
    rowClass: (w) => (w.watched ? 'is-watched' : null),
    columns: [
      { key: 'star', label: '★', render: (w) => starButton(d, 'wallet', w.chain, w.address) },
      { key: 'chain', label: 'Chain', sort: (w) => w.chain, render: (w) => chainLabel(w.chain) },
      { key: 'addr', label: 'Address', sort: (w) => w.address, render: (w) => [walletLink(d, w.chain, w.address), w.watched ? [' ', watchedPill()] : null] },
      { key: 'role', label: 'Role', sort: (w) => w.role, render: (w) => h('span', { class: 'pill' }, sanitize(w.role)) },
      { key: 'label', label: 'Label', sort: (w) => w.label, cls: 'wrap', render: (w) => sanitize(w.label) },
      { key: 'cluster', label: 'Cluster', sort: (w) => w.cluster_id, render: (w) => clusterPill(d, w.cluster_id) },
      { key: 'contracts', label: 'Contracts', num: true, sort: (w) => w.contracts.length, render: (w) => fmtNum(w.contracts.length) },
      { key: 'tx', label: 'Txs', num: true, sort: (w) => w.tx_count, render: (w) => fmtNum(w.tx_count) },
      { key: 'last', label: 'Last seen', sort: (w) => ts(w.last_seen) || 0, render: (w) => timeEl(w.last_seen) },
    ],
  });
  const count = h('span', { class: 'count' });
  const apply = () => {
    const q = st.q.trim().toLowerCase();
    const out = rows.filter((w) => (!st.role || w.role === st.role) && (!st.watched || w.watched)
      && (!q || [w.address, w.label, w.cluster_id || '', ...w.contracts].some((x) => x.toLowerCase().includes(q))));
    table.update(out);
    count.textContent = `${out.length} of ${rows.length}`;
    syncQuery('#/wallets', st);
  };
  const search = h('input', { class: 'input', type: 'search', placeholder: 'Filter: address, label, contract…', 'aria-label': 'Filter wallets', value: st.q });
  search.addEventListener('input', () => { st.q = search.value; apply(); });
  const watchedBox = h('input', { type: 'checkbox', checked: !!st.watched });
  watchedBox.addEventListener('change', () => { st.watched = watchedBox.checked ? '1' : ''; apply(); });
  const roles = [...new Set([...ROLES, ...rows.map((w) => w.role)])].filter((r) => rows.some((w) => w.role === r)).map((r) => [r, sanitize(r)]);
  apply();
  return h('div', null,
    pageHead({ title: 'Wallets', sub: 'Operator wallets send the config updates; payout wallets are mining wallets found inside decoded configs. ★ adds an item to your personal watchlist (stored in this browser only).' }),
    h('div', { class: 'filters' }, search,
      selectFilter('Role', roles, st.role, (e) => { st.role = e.target.value; apply(); }, 'All roles'),
      h('label', { class: 'check' }, watchedBox, 'watched only'), count),
    table.el);
}

export function renderWallet(ctx, chain, address) {
  const { d } = ctx;
  const w = d.walletByKey.get(key(chain, address));
  if (!w) return notFound('Wallet', `${chain}:${address}`);
  const events = walletEvents(d, w);
  const item = watchlist.all().find((i) => i.kind === 'wallet' && i.chain === chain && i.address === address);
  const seenBlock = item ? item.seenBlock || 0 : undefined;
  if (item) watchlist.markSeen('wallet', chain, address, maxBlock(events));

  // contracts it controls (or, for payout wallets, whose configs reference it)
  const controlled = d.contracts.filter((c) => w.contracts.includes(c.address) || c.operator_wallets.includes(w.address));
  const contractTable = sortableTable({
    caption: 'Contracts',
    sort: { key: 'last', dir: 'desc' },
    columns: [
      { key: 'addr', label: 'Contract', sort: (c) => c.address, render: (c) => contractLink(c.chain, c.address) },
      { key: 'status', label: 'Status', sort: (c) => c.status, render: (c) => statusPill(c.status) },
      { key: 'family', label: 'Family', sort: (c) => c.family, render: (c) => h('span', { class: 'mono' }, sanitize(c.family)) },
      { key: 'updates', label: 'Updates', num: true, sort: (c) => c.update_count, render: (c) => fmtNum(c.update_count) },
      { key: 'last', label: 'Last seen', sort: (c) => ts(c.last_seen) || 0, render: (c) => timeEl(c.last_seen) },
    ],
    empty: 'No contracts linked.',
  });
  contractTable.update(controlled);

  const funders = w.funded_by.map((f) => h('div', null, walletLink(d, chain, f, true), explorerLink(chain, 'address', f)));
  const funds = d.wallets.filter((x) => x.funded_by.includes(w.address));

  return h('div', null,
    pageHead({
      crumbs: [['Wallets', '#/wallets'], [chainLabel(chain)]],
      title: sanitize(address), titleClass: 'mono wrap-any',
      sub: [h('span', { class: 'pill' }, sanitize(w.role)), ' ', w.watched ? [watchedPill(), ' '] : null, clusterPill(d, w.cluster_id), ' ', sanitize(w.label)],
      actions: [
        starButton(d, 'wallet', chain, address, ctx.rerender),
        h('button', { type: 'button', class: 'btn btn-sm', onclick: () => copyText(address, 'address') }, 'Copy address'),
        explorerLink(chain, 'address', address, `view on ${chainLabel(chain)} explorer`),
      ],
    }),
    h('div', { class: 'grid grid-2' },
      panel('Details', kv([
        ['chain', chainLabel(chain)],
        ['role', sanitize(w.role)],
        ['label', sanitize(w.label)],
        ['cluster', clusterPill(d, w.cluster_id)],
        ['transactions', fmtNum(w.tx_count)],
        ['first seen', timeEl(w.first_seen)],
        ['last seen', timeEl(w.last_seen)],
        ['watched', w.watched ? watchedPill() : 'no'],
        ['funded by', funders.length ? funders : null],
        ['funds', funds.length ? funds.map((x) => h('div', null, walletLink(d, x.chain, x.address, true))) : undefined],
      ])),
      panel('Update activity', activityChart(d, events, { title: 'Updates sent by / touching this wallet' }))),
    h('div', { class: 'section' }, panel(w.role === 'payout' ? 'Contracts whose configs reference this wallet' : 'Contracts controlled', contractTable.el)),
    h('div', { class: 'section' }, panel(`Recent rotations (${events.length})`, timeline(d, events.slice(0, 30), { seenBlock, showContract: true, compact: true }))));
}
