// Hand-made SVG charts.
import { h, s } from './dom.js';
import { ts } from './fmt.js';
import { slotClass } from './data.js';

const DAY = 86400000;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const dayLabel = (t) => { const d = new Date(t); return `${MONTHS[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, '0')}`; };

function niceMax(v) {
  if (v <= 4) return Math.max(1, v);
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return v;
}

/**
 * Stacked bar chart of config updates per day (or week for long ranges).
 * @param d data, @param events list, @param opts {byCluster?: boolean, endIso?: string, title?: string}
 */
export function activityChart(d, events, opts = {}) {
  const wrap = h('figure', { class: 'chart-fig' });
  const times = events.map((e) => ts(e.timestamp)).filter(Number.isFinite);
  if (!times.length) {
    wrap.append(h('p', { class: 'empty' }, 'No update events in range.'));
    return wrap;
  }
  const end = Math.max(...times, Number.isFinite(ts(opts.endIso)) ? ts(opts.endIso) : 0);
  const start = Math.min(...times);
  const day0 = Math.floor(start / DAY) * DAY;
  const spanDays = Math.floor(end / DAY) - Math.floor(start / DAY) + 1;
  const bucket = spanDays > 150 ? 7 : 1;
  const n = Math.max(Math.ceil(spanDays / bucket), opts.minBins || 1);

  const bins = Array.from({ length: n }, () => new Map());
  const series = new Set();
  for (const e of events) {
    const t = ts(e.timestamp);
    if (!Number.isFinite(t)) continue;
    const i = Math.min(n - 1, Math.floor((t - day0) / DAY / bucket));
    const c = d.contractByKey.get(`${e.chain}:${e.contract}`);
    const sk = opts.byCluster ? (c && c.cluster_id) || '' : 'all';
    series.add(sk);
    bins[i].set(sk, (bins[i].get(sk) || 0) + 1);
  }
  const order = [...series].sort();
  const totals = bins.map((b) => [...b.values()].reduce((a, x) => a + x, 0));
  const maxV = niceMax(Math.max(...totals));

  const W = 800; const H = opts.height || 190;
  const m = { l: 30, r: 6, t: 8, b: 22 };
  const pw = W - m.l - m.r; const ph = H - m.t - m.b;
  const bw = pw / n;
  const gap = bw > 4 ? Math.min(2, bw * 0.25) : 0;
  const y = (v) => m.t + ph - (v / maxV) * ph;

  const peakIdx = totals.indexOf(Math.max(...totals));
  const total = totals.reduce((a, x) => a + x, 0);
  const unit = bucket === 7 ? 'week' : 'day';
  const svg = s('svg', {
    class: 'chart', viewBox: `0 0 ${W} ${H}`, role: 'img', preserveAspectRatio: 'xMidYMid meet',
    'aria-label': `${opts.title || 'Config updates'}: ${total} events over ${spanDays} days, peak ${totals[peakIdx]} per ${unit} (${dayLabel(day0 + peakIdx * bucket * DAY)}).`,
  });

  for (const v of [0, maxV / 2, maxV]) {
    const yy = y(v);
    svg.append(s('line', { class: v === 0 ? 'axis' : 'grid-line', x1: m.l, x2: W - m.r, y1: yy, y2: yy }));
    if (Number.isInteger(v)) svg.append(s('text', { x: m.l - 6, y: yy + 3, 'text-anchor': 'end' }, String(v)));
  }

  // x labels: first of each month (daily) or every ~4th bucket
  let lastLabelX = -100;
  for (let i = 0; i < n; i++) {
    const t = day0 + i * bucket * DAY;
    const dt = new Date(t);
    const isTick = bucket === 1 ? (dt.getUTCDate() === 1 || i === 0) : i % 4 === 0;
    const x = m.l + i * bw;
    if (isTick && x - lastLabelX > 46) {
      svg.append(s('line', { class: 'axis', x1: x, x2: x, y1: m.t + ph, y2: m.t + ph + 4 }));
      svg.append(s('text', { x, y: H - 6, 'text-anchor': 'start' }, dayLabel(t)));
      lastLabelX = x;
    }
  }

  const readout = h('div', { class: 'chart-readout', 'aria-live': 'off' }, `${total} updates · hover a bar for detail`);
  const nameOf = (sk) => {
    if (!opts.byCluster) return 'updates';
    if (!sk) return 'unclustered';
    const c = d.clusterById.get(sk);
    return c && c.name ? `${sk} ${c.name}` : sk;
  };

  bins.forEach((b, i) => {
    if (!totals[i]) return;
    const x = m.l + i * bw + gap / 2;
    const g = s('g');
    let acc = 0;
    const parts = [];
    for (const sk of order) {
      const v = b.get(sk) || 0;
      if (!v) continue;
      const y1 = y(acc + v); const y0 = y(acc);
      g.append(s('rect', {
        class: `bar ${opts.byCluster ? slotClass(d, sk) : 'acc'}`, x: x.toFixed(2), y: y1.toFixed(2),
        width: Math.max(1, bw - gap).toFixed(2), height: Math.max(0.5, y0 - y1).toFixed(2),
      }));
      acc += v;
      parts.push(`${nameOf(sk)}: ${v}`);
    }
    const label = `${dayLabel(day0 + i * bucket * DAY)}${bucket > 1 ? ' (week)' : ''}: ${totals[i]} update${totals[i] > 1 ? 's' : ''}${opts.byCluster ? ` (${parts.join(', ')})` : ''}`;
    g.append(s('title', null, label));
    g.append(s('rect', { x: m.l + i * bw, y: m.t, width: bw, height: ph, fill: 'transparent' }));
    g.addEventListener('mouseenter', () => { readout.textContent = label; });
    svg.append(g);
  });

  wrap.append(svg, readout);
  if (opts.byCluster) {
    const legend = h('div', { class: 'legend' });
    for (const sk of order) {
      legend.append(h('span', null, h('span', { class: `swatch ${slotClass(d, sk, 'sw')}` }), nameOf(sk)));
    }
    wrap.append(legend);
  }
  return wrap;
}
