import { h, copyText, downloadBlob } from '../dom.js';
import { sanitize, timeEl, chainLabel, fmtNum, iocDisplay, iocRaw, ts, fmtDate, str } from '../fmt.js';
import { sortableTable } from '../table.js';
import { pageHead, clusterPill, contractLink } from '../ui.js';
import { selectFilter, syncQuery } from './contracts.js';

// CSV cell: quote, and neutralise spreadsheet formula injection (values are attacker-controlled).
function csvCell(v) {
  let t = str(v);
  if (/^[=+\-@\t\r]/.test(t)) t = `'${t}`;
  return `"${t.replace(/"/g, '""')}"`;
}

export function renderIocs(ctx) {
  const { d, query, inChain } = ctx;
  const rows = d.iocs.filter(inChain);
  const st = {
    q: query.get('q') || '', type: query.get('type') || '', cluster: query.get('cluster') || '', current: query.get('current') || '',
  };
  const table = sortableTable({
    caption: 'Indicators of compromise',
    sort: { key: 'last', dir: 'desc' },
    columns: [
      { key: 'type', label: 'Type', sort: (i) => i.type, render: (i) => h('span', { class: 'mono' }, sanitize(i.type)) },
      { key: 'value', label: 'Value (defanged)', sort: (i) => i.value, cls: 'wrap', render: (i) => h('span', { class: 'ioc' }, iocDisplay(i)) },
      { key: 'copy', label: 'Copy', render: (i) => h('span', { class: 'btn-row' },
        h('button', { type: 'button', class: 'btn btn-sm', title: 'Copy defanged value', 'aria-label': `Copy defanged ${i.type}`, onclick: () => copyText(iocDisplay(i), 'defanged') }, 'copy'),
        h('button', { type: 'button', class: 'btn btn-sm btn-ghost', title: 'Copy raw (live) value: handle with care', 'aria-label': `Copy raw ${i.type}`, onclick: () => copyText(iocRaw(i), 'raw value') }, 'raw')) },
      { key: 'port', label: 'Port', num: true, sort: (i) => i.port, render: (i) => (i.port === null ? '' : String(i.port)) },
      { key: 'current', label: 'Current', sort: (i) => (i.current ? 1 : 0), render: (i) => (i.current ? h('span', { class: 'pill pill-active' }, 'current') : h('span', { class: 'pill' }, 'historic')) },
      { key: 'family', label: 'Family', sort: (i) => i.family, render: (i) => h('span', { class: 'mono' }, sanitize(i.family)) },
      { key: 'cluster', label: 'Cluster', sort: (i) => i.cluster_id, render: (i) => clusterPill(d, i.cluster_id) },
      { key: 'chain', label: 'Chain', sort: (i) => i.chain, render: (i) => chainLabel(i.chain) },
      { key: 'contracts', label: 'Contracts', sort: (i) => i.contracts.length, render: (i) => (i.contracts.length ? [contractLink(i.chain, i.contracts[0]), i.contracts.length > 1 ? ` +${i.contracts.length - 1}` : ''] : '') },
      { key: 'seen', label: 'Seen', num: true, sort: (i) => i.times_seen, render: (i) => fmtNum(i.times_seen) },
      { key: 'conf', label: 'Conf.', num: true, sort: (i) => i.confidence, render: (i) => (i.confidence === null ? '' : String(i.confidence)) },
      { key: 'first', label: 'First seen', sort: (i) => ts(i.first_seen) || 0, render: (i) => timeEl(i.first_seen, false) },
      { key: 'last', label: 'Last seen', sort: (i) => ts(i.last_seen) || 0, render: (i) => timeEl(i.last_seen, false) },
    ],
  });

  const count = h('span', { class: 'count' });
  const apply = () => {
    const q = st.q.trim().toLowerCase();
    const out = rows.filter((i) => (!st.type || i.type === st.type) && (!st.cluster || i.cluster_id === st.cluster) && (!st.current || i.current)
      && (!q || [i.value, iocDisplay(i), i.family, i.cluster_id || '', ...i.contracts, i.port === null ? '' : String(i.port)].some((x) => x.toLowerCase().includes(q))));
    table.update(out);
    count.textContent = `${out.length} of ${rows.length}`;
    syncQuery('#/iocs', st);
  };

  const exportCsv = () => {
    const vis = table.visibleRows();
    const head = ['type', 'value_defanged', 'value_raw', 'port', 'current', 'family', 'cluster_id', 'chain', 'contracts', 'times_seen', 'confidence', 'first_seen', 'last_seen'];
    const lines = [head.join(',')].concat(vis.map((i) => [i.type, iocDisplay(i), i.value, i.port ?? '', i.current, i.family, i.cluster_id || '', i.chain, i.contracts.join(' '), i.times_seen, i.confidence ?? '', i.first_seen, i.last_seen].map(csvCell).join(',')));
    downloadBlob(`deaddrop-iocs-${fmtDate(new Date().toISOString(), false)}.csv`, 'text/csv;charset=utf-8', `${lines.join('\r\n')}\r\n`);
  };

  const search = h('input', { class: 'input', type: 'search', placeholder: 'Filter: value, family, contract, port…', 'aria-label': 'Filter IOCs', value: st.q });
  search.addEventListener('input', () => { st.q = search.value; apply(); });
  const cur = h('input', { type: 'checkbox', checked: !!st.current });
  cur.addEventListener('change', () => { st.current = cur.checked ? '1' : ''; apply(); });
  const types = [...new Set(rows.map((i) => i.type))].sort().map((t) => [t, sanitize(t)]);
  const clusters = [...new Set(rows.map((i) => i.cluster_id).filter(Boolean))].sort().map((c) => [c, sanitize(c)]);
  apply();

  return h('div', null,
    pageHead({
      title: 'IOCs',
      sub: 'Indicators extracted from decoded on-chain values. Displayed defanged; never browse to them. "raw" copies the live value for blocklists.',
      actions: [h('button', { type: 'button', class: 'btn btn-primary', onclick: exportCsv }, 'Export visible rows (CSV)')],
    }),
    h('div', { class: 'filters' }, search,
      selectFilter('Type', types, st.type, (e) => { st.type = e.target.value; apply(); }, 'All types'),
      selectFilter('Cluster', clusters, st.cluster, (e) => { st.cluster = e.target.value; apply(); }, 'All clusters'),
      h('label', { class: 'check' }, cur, 'current only'), count),
    table.el);
}
