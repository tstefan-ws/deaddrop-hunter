// Sortable table component (keyboard accessible header buttons, aria-sort).
import { h } from './dom.js';

/**
 * @param {{columns: Array<{key:string,label:string,sort?:Function,render:Function,num?:boolean,cls?:string}>,
 *          sort?: {key:string, dir:'asc'|'desc'}, rowClass?: Function, empty?: string, caption?: string}} opts
 */
export function sortableTable(opts) {
  const state = { key: opts.sort ? opts.sort.key : null, dir: opts.sort ? opts.sort.dir : 'asc', rows: [] };
  const tbody = h('tbody');
  const ths = new Map();
  const headRow = h('tr');
  for (const col of opts.columns) {
    const th = h('th', { scope: 'col', class: col.num ? 'num' : null });
    if (col.sort) {
      const btn = h('button', { type: 'button', class: 'sort', onclick: () => setSort(col.key) },
        col.label, h('span', { class: 'arrow', 'aria-hidden': 'true' }, '↕'));
      th.append(btn);
    } else th.append(col.label);
    ths.set(col.key, th);
    headRow.append(th);
  }
  const table = h('table', null,
    opts.caption ? h('caption', { class: 'visually-hidden' }, opts.caption) : null,
    h('thead', null, headRow), tbody);
  const el = h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': opts.caption || 'Table' }, table);

  function setSort(k) {
    if (state.key === k) state.dir = state.dir === 'asc' ? 'desc' : 'asc';
    else { state.key = k; state.dir = opts.columns.find((c) => c.key === k).num ? 'desc' : 'asc'; }
    render();
  }

  function cmp(a, b) {
    if (a === b) return 0;
    if (a === null || a === undefined || a === '') return 1;
    if (b === null || b === undefined || b === '') return -1;
    if (typeof a === 'number' && typeof b === 'number') return a - b;
    return String(a).localeCompare(String(b), 'en', { numeric: true });
  }

  function render() {
    for (const [k, th] of ths) {
      if (k === state.key) th.setAttribute('aria-sort', state.dir === 'asc' ? 'ascending' : 'descending');
      else th.removeAttribute('aria-sort');
      const arrow = th.querySelector('.arrow');
      if (arrow) arrow.textContent = k === state.key ? (state.dir === 'asc' ? '↑' : '↓') : '↕';
    }
    let rows = state.rows.slice();
    const col = opts.columns.find((c) => c.key === state.key);
    if (col && col.sort) {
      const sign = state.dir === 'asc' ? 1 : -1;
      const nullsLast = (x, y) => {
        const ex = x === null || x === undefined || x === '';
        const ey = y === null || y === undefined || y === '';
        if (ex || ey) return ex && ey ? 0 : ex ? 1 : -1;
        return sign * cmp(x, y);
      };
      rows = rows.map((r) => [col.sort(r), r]).sort((a, b) => nullsLast(a[0], b[0])).map((x) => x[1]);
    }
    const frag = document.createDocumentFragment();
    if (!rows.length) {
      frag.append(h('tr', null, h('td', { colspan: String(opts.columns.length), class: 'empty' }, opts.empty || 'No rows match.')));
    }
    for (const r of rows) {
      const tr = h('tr', { class: opts.rowClass ? opts.rowClass(r) : null });
      for (const c of opts.columns) tr.append(h('td', { class: [c.num ? 'num' : null, c.cls].filter(Boolean).join(' ') || null }, c.render(r)));
      frag.append(tr);
    }
    tbody.replaceChildren(frag);
    state.sorted = rows;
  }

  return {
    el,
    update(rows) { state.rows = rows; render(); },
    visibleRows() { return state.sorted || []; },
  };
}
