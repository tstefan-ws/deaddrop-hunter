// Diffs between old and new decoded values. JSON configs get a key-level diff,
// anything else a line diff. All output is rendered defanged via textContent.
import { h } from './dom.js';
import { defang, str } from './fmt.js';

export function parseObj(v) {
  if (typeof v !== 'string' || !v.trim().startsWith('{')) return null;
  try {
    const o = JSON.parse(v);
    return o && typeof o === 'object' && !Array.isArray(o) ? o : null;
  } catch { return null; }
}

export function pretty(v) {
  if (v === null || v === undefined) return '';
  try {
    const t = v.trim();
    if (t.startsWith('{') || t.startsWith('[')) return JSON.stringify(JSON.parse(t), null, 2);
  } catch { /* not JSON */ }
  return v;
}

const valStr = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

/** @returns {{kind:'json'|'text', initial:boolean, same:boolean, changes:Array, old:string, new:string}} */
export function diffValues(oldV, newV) {
  const noOld = oldV === null || oldV === undefined; // non-EVM tx data: no previous value
  const o = str(oldV);
  const n = str(newV);
  const initial = o === '';
  const no = parseObj(n);
  const oo = initial ? {} : parseObj(o);
  if (no && oo) {
    const keys = [...Object.keys(no), ...Object.keys(oo).filter((k) => !has(no, k))];
    const changes = [];
    for (const k of keys) {
      if (!has(oo, k)) changes.push({ key: k, type: 'added', new: valStr(no[k]) });
      else if (!has(no, k)) changes.push({ key: k, type: 'removed', old: valStr(oo[k]) });
      else if (valStr(oo[k]) !== valStr(no[k])) changes.push({ key: k, type: 'changed', old: valStr(oo[k]), new: valStr(no[k]) });
    }
    return { kind: 'json', initial, noOld, same: !noOld && changes.length === 0, changes, old: o, new: n };
  }
  return { kind: 'text', initial, noOld, same: !noOld && o === n, changes: [], old: o, new: n };
}

const clip = (t, n = 64) => (t.length > n ? `${t.slice(0, n - 1)}…` : t);

/** One-line summary, e.g. "pool: xmr-eu1[.]nanopool[.]org → 78[.]40[.]198[.]61 · port: 10343 → 27031". */
export function diffSummary(diff, max = 3) {
  const el = h('div', { class: 'diff-summary' });
  if (diff.same) { el.append('no change (identical value re-published)'); return el; }
  if (diff.noOld) { el.append('value ', h('span', { class: 'n' }, clip(defang(diff.new)))); return el; }
  if (diff.kind === 'text') {
    if (!diff.initial) el.append(h('span', { class: 'o' }, clip(defang(diff.old))), ' → ');
    else el.append('set ');
    el.append(h('span', { class: 'n' }, clip(defang(diff.new))));
    return el;
  }
  if (diff.initial) {
    el.append(`initial config (${diff.changes.length} keys)`);
    const pool = diff.changes.find((c) => c.key === 'pool');
    if (pool) el.append(' · pool ', h('span', { class: 'n' }, clip(defang(pool.new))));
    return el;
  }
  diff.changes.slice(0, max).forEach((c, i) => {
    if (i) el.append(' · ');
    el.append(h('span', { class: 'k' }, `${defang(c.key)}: `));
    if (c.type !== 'added') el.append(h('span', { class: 'o' }, clip(defang(c.old || '""'), 40)));
    if (c.type === 'changed') el.append(' → ');
    if (c.type !== 'removed') el.append(h('span', { class: 'n' }, clip(defang(c.new || '""'), 40)));
    if (c.type === 'removed') el.append(' (removed)');
  });
  if (diff.changes.length > max) el.append(` · +${diff.changes.length - max} more`);
  return el;
}

/** Full diff block for the rotation timeline. */
export function diffBlock(diff) {
  if (diff.noOld) {
    return h('div', null,
      h('p', { class: 'faint diff-note' }, 'Transaction data: no previous value on this chain, showing the new value only.'),
      h('div', { class: 'diff-text' }, h('div', { class: 'new' }, defang(pretty(diff.new)))));
  }
  if (diff.kind === 'json') {
    if (diff.same) return h('p', { class: 'empty' }, 'Identical value re-published (no key changed).');
    const rows = diff.changes.map((c) => h('tr', null,
      h('td', { class: 'key' }, defang(c.key)),
      h('td', { class: c.type === 'added' ? '' : 'old' }, c.type === 'added' ? '' : defang(c.old || '""')),
      h('td', { class: 'arrow-cell', 'aria-hidden': 'true' }, '→'),
      h('td', { class: c.type === 'removed' ? '' : 'new' }, c.type === 'removed' ? '(removed)' : defang(c.new || '""'))));
    return h('table', { class: 'diff' },
      h('caption', { class: 'visually-hidden' }, 'Changed keys: key, old value, new value'),
      h('tbody', null, rows));
  }
  if (diff.same) return h('p', { class: 'empty' }, 'Identical value re-published.');
  return h('div', { class: 'diff-text' },
    diff.initial ? null : h('div', { class: 'old' }, defang(diff.old)),
    h('div', { class: 'new' }, defang(diff.new)));
}
