import { h, copyText } from '../dom.js';
import { sanitize, defang, timeEl, chainLabel, explorerLink, fmtNum, iocDisplay, iocRaw, ts, blockWord, isAddrFor, RE_CHAIN } from '../fmt.js';
import { key, maxBlock } from '../data.js';
import { sortableTable } from '../table.js';
import { activityChart } from '../charts.js';
import { diffValues, diffBlock, diffSummary, pretty } from '../diff.js';
import { watchlist } from '../store.js';
import {
  pageHead, panel, kv, statusPill, clusterPill, contractLink, walletLink, txLink, starButton, familyTag, notFound,
} from '../ui.js';

/** Keep list filters in the URL without triggering a re-render. */
export function syncQuery(base, params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) q.set(k, v);
  const qs = q.toString();
  try { history.replaceState(null, '', `${base}${qs ? `?${qs}` : ''}`); } catch { /* ignore */ }
}

export function selectFilter(label, values, current, onChange, allLabel = 'All') {
  const sel = h('select', { 'aria-label': label, value: current },
    h('option', { value: '' }, `${allLabel}`),
    values.map((v) => h('option', { value: v[0] }, v[1])));
  sel.addEventListener('change', onChange);
  return sel;
}

export function renderContracts(ctx) {
  const { d, query, inChain } = ctx;
  const rows = d.contracts.filter(inChain);
  const st = {
    q: query.get('q') || '', family: query.get('family') || '', status: query.get('status') || '', cluster: query.get('cluster') || '',
  };
  const families = [...new Set(rows.map((c) => c.family))].sort().map((f) => [f, sanitize(f)]);
  const clusters = [...new Set(rows.map((c) => c.cluster_id).filter(Boolean))].sort().map((id) => [id, sanitize(id)]);

  const table = sortableTable({
    caption: 'Contracts',
    sort: { key: 'last', dir: 'desc' },
    rowClass: (c) => (c.operator_wallets.some((w) => (d.walletByKey.get(key(c.chain, w)) || {}).watched) ? 'is-watched' : null),
    columns: [
      { key: 'star', label: '★', render: (c) => starButton(d, 'contract', c.chain, c.address) },
      { key: 'chain', label: 'Chain', sort: (c) => c.chain, render: (c) => chainLabel(c.chain) },
      { key: 'addr', label: 'Contract', sort: (c) => c.address, render: (c) => contractLink(c.chain, c.address) },
      { key: 'family', label: 'Family', sort: (c) => c.family, render: (c) => familyTag(c.family) },
      { key: 'status', label: 'Status', sort: (c) => c.status, render: (c) => statusPill(c.status) },
      { key: 'cluster', label: 'Cluster', sort: (c) => c.cluster_id, render: (c) => clusterPill(d, c.cluster_id) },
      { key: 'op', label: 'Operator', sort: (c) => c.operator_wallets[0] || '', render: (c) => (c.operator_wallets.length ? [walletLink(d, c.chain, c.operator_wallets[0]), c.operator_wallets.length > 1 ? ` +${c.operator_wallets.length - 1}` : ''] : h('span', { class: 'faint' }, '—')) },
      { key: 'updates', label: 'Updates', num: true, sort: (c) => c.update_count, render: (c) => fmtNum(c.update_count) },
      { key: 'last', label: 'Last seen', sort: (c) => ts(c.last_seen) || 0, render: (c) => timeEl(c.last_seen) },
    ],
  });

  const count = h('span', { class: 'count' });
  const apply = () => {
    const q = st.q.trim().toLowerCase();
    const out = rows.filter((c) => (!st.family || c.family === st.family) && (!st.status || c.status === st.status)
      && (!st.cluster || c.cluster_id === st.cluster)
      && (!q || [c.address, c.family, c.cluster_id || '', c.decoder, ...c.operator_wallets, ...c.tags, c.latest_value_decoded || ''].some((x) => x.toLowerCase().includes(q))));
    table.update(out);
    count.textContent = `${out.length} of ${rows.length}`;
    syncQuery('#/contracts', st);
  };
  const search = h('input', { class: 'input', type: 'search', placeholder: 'Filter: address, family, operator, value…', 'aria-label': 'Filter contracts', value: st.q });
  search.addEventListener('input', () => { st.q = search.value; apply(); });
  const filters = h('div', { class: 'filters' }, search,
    selectFilter('Family', families, st.family, (e) => { st.family = e.target.value; apply(); }, 'All families'),
    selectFilter('Status', [['active', 'active'], ['dormant', 'dormant']], st.status, (e) => { st.status = e.target.value; apply(); }, 'Any status'),
    selectFilter('Cluster', clusters, st.cluster, (e) => { st.cluster = e.target.value; apply(); }, 'All clusters'),
    count);
  apply();
  return h('div', null,
    pageHead({ title: 'Contracts', sub: 'Accounts and contracts whose on-chain data carries malware configuration. Rows with a left accent bar are controlled by a watched operator.' }),
    filters, table.el);
}

function valuePanel(c) {
  const val = c.latest_value_decoded;
  if (val === null || val === '') {
    return h('div', null, h('p', { class: 'empty' }, c.decoder === 'undecoded' ? 'Value could not be decoded.' : 'No decoded value.'),
      c.latest_value_raw ? h('pre', { class: 'value' }, sanitize(c.latest_value_raw)) : null);
  }
  return h('div', null,
    h('pre', { class: 'value', 'aria-label': 'Current decoded value (defanged)' }, defang(pretty(val))),
    h('div', { class: 'btn-row section' },
      h('button', { type: 'button', class: 'btn btn-sm', onclick: () => copyText(defang(pretty(val)), 'defanged value') }, 'Copy defanged'),
      h('button', { type: 'button', class: 'btn btn-sm', onclick: () => copyText(val, 'raw value') }, 'Copy raw'),
      h('span', { class: 'faint' }, 'Shown defanged. Never connect to these endpoints.')),
    c.latest_value_raw ? h('details', { class: 'raw' }, h('summary', null, `On-chain bytes (${sanitize(c.decoder)})`), h('pre', { class: 'value' }, sanitize(c.latest_value_raw))) : null);
}

export function timeline(d, events, opts = {}) {
  if (!events.length) return h('p', { class: 'empty' }, 'No events recorded.');
  const ol = h('ol', { class: 'timeline' });
  events.forEach((e, i) => {
    const diff = diffValues(e.old_decoded, e.new_decoded);
    const li = h('li', { class: [i === 0 ? 'first' : null, opts.seenBlock !== undefined && e.block > opts.seenBlock ? 'is-new' : null, opts.target === e.tx_hash ? 'target' : null].filter(Boolean).join(' ') || null, id: `tx-${sanitize(e.tx_hash).slice(0, 90)}` },
      h('div', { class: 'tl-head' },
        h('span', { class: 'when' }, timeEl(e.timestamp)),
        opts.seenBlock !== undefined && e.block > opts.seenBlock ? h('span', { class: 'pill pill-new' }, 'new') : null,
        opts.showContract ? contractLink(e.chain, e.contract) : null,
        h('span', { class: 'mono faint' }, `${blockWord(e.chain)} ${fmtNum(e.block)}`),
        h('span', null, 'tx ', txLink(e.chain, e.tx_hash)),
        h('span', null, 'from ', e.from ? walletLink(d, e.chain, e.from) : h('span', { class: 'faint', title: 'transaction lookup failed' }, 'unknown')),
        e.selector ? h('span', { class: 'mono faint' }, sanitize(e.selector)) : null),
      opts.compact ? diffSummary(diff) : h('div', { class: 'tl-body' }, diffBlock(diff)),
      opts.compact ? null : h('details', { class: 'raw' }, h('summary', null, 'Raw values'),
        e.old_raw !== '' && e.old_raw !== null ? h('pre', { class: 'value' }, `old: ${sanitize(e.old_raw)}`) : null,
        h('pre', { class: 'value' }, `new: ${sanitize(e.new_raw)}`)));
    ol.append(li);
  });
  return ol;
}

export function renderContract(ctx, chain, address) {
  const { d, query } = ctx;
  const c = d.contractByKey.get(key(chain, address));
  if (!c) return notFound('Contract', `${chain}:${address}`);
  const events = d.eventsByContract.get(key(chain, address)) || [];
  const item = watchlist.all().find((i) => i.kind === 'contract' && i.chain === chain && i.address === address);
  const seenBlock = item ? item.seenBlock || 0 : undefined;
  if (item) watchlist.markSeen('contract', chain, address, maxBlock(events));
  const target = query.get('tx') || '';

  const iocs = (d.iocsByContract.get(address) || []).filter((i) => !i.type.startsWith('evm-') || i.value !== address);
  const iocList = iocs.length ? h('ul', { class: 'feed' }, iocs.sort((a, b) => Number(b.current) - Number(a.current)).map((i) => h('li', null,
    h('div', { class: 'meta' }, h('span', { class: 'mono' }, sanitize(i.type)), i.current ? h('span', { class: 'pill pill-active' }, 'current') : h('span', { class: 'pill' }, 'historic'), h('span', null, `seen ${i.times_seen}×`)),
    h('div', { class: 'btn-row' }, h('span', { class: 'ioc' }, iocDisplay(i)),
      h('button', { type: 'button', class: 'btn btn-sm btn-ghost', 'aria-label': 'Copy defanged IOC', onclick: () => copyText(iocDisplay(i), 'defanged') }, 'copy'),
      h('button', { type: 'button', class: 'btn btn-sm btn-ghost', 'aria-label': 'Copy raw IOC', onclick: () => copyText(iocRaw(i), 'raw') }, 'raw'))))) : h('p', { class: 'empty' }, 'No IOCs extracted.');

  const page = h('div', null,
    pageHead({
      crumbs: [['Contracts', '#/contracts'], [chainLabel(chain)]],
      title: sanitize(address), titleClass: 'mono wrap-any',
      sub: [statusPill(c.status), ' ', clusterPill(d, c.cluster_id), ' ', h('span', { class: 'mono' }, sanitize(c.family)), ` · ${c.update_count} updates · last `, timeEl(c.last_seen)],
      actions: [
        starButton(d, 'contract', chain, address, ctx.rerender),
        // static JSON API file (published by the exporter; not present in sample mode)
        !d.sample && RE_CHAIN.test(chain) && isAddrFor(chain, address)
          ? h('a', { class: 'btn btn-sm', href: `./feeds/api/v1/contracts/${chain}/${address}.json`, title: 'This contract as JSON (static API)' }, 'JSON') : null,
        explorerLink(chain, 'address', address, `view on ${chainLabel(chain)} explorer`),
      ],
    }),
    h('div', { class: 'grid grid-2' },
      panel('Details', kv([
        ['chain', chainLabel(chain)],
        ['family', familyTag(c.family)],
        ['status', statusPill(c.status)],
        ['decoder', h('span', { class: 'mono' }, sanitize(c.decoder))],
        ['selectors', c.selectors.length ? h('span', { class: 'mono' }, c.selectors.map(sanitize).join(', ')) : null],
        ['hunts', c.hunt_ids.length ? h('span', { class: 'mono' }, c.hunt_ids.map(sanitize).join(', ')) : null],
        ['operators', c.operator_wallets.length ? h('div', null, c.operator_wallets.map((w) => h('div', null, walletLink(d, chain, w, true), explorerLink(chain, 'address', w)))) : null],
        ['cluster', clusterPill(d, c.cluster_id)],
        ['first seen', timeEl(c.first_seen)],
        ['last seen', timeEl(c.last_seen)],
        ['tags', c.tags.length ? h('div', { class: 'pills' }, c.tags.map((t) => h('span', { class: 'pill' }, sanitize(t)))) : null],
      ])),
      panel('Current decoded value', valuePanel(c))),
    h('div', { class: 'grid grid-2 section' },
      panel('Extracted IOCs', iocList, h('a', { href: `#/iocs?q=${encodeURIComponent(address)}` }, 'in IOC table →')),
      panel('Update activity', activityChart(d, events, { title: 'Updates to this contract' }))),
    h('div', { class: 'section' }, panel(`Rotation timeline (${events.length})`, timeline(d, events, { seenBlock, target }))));

  if (target) {
    requestAnimationFrame(() => {
      const el = page.querySelector('li.target');
      if (el) el.scrollIntoView({ block: 'center' });
    });
  }
  return page;
}

