// Cluster network graph: wallet -> contract -> IOC, small deterministic force layout in SVG.
// Each node is an icon badge (see the g-* symbols in index.html) rather than a bare circle:
// the glyph says what kind of thing it is, the colour says which, and a dashed ring marks
// anything still live (an active contract, a current IOC).
import { h, s } from './dom.js';
import { defangIoc, shortHex, iocRaw } from './fmt.js';
import { key } from './data.js';

const enc = encodeURIComponent;

export function buildClusterGraph(d, cluster) {
  const nodes = new Map();
  const edges = [];
  const addNode = (id, n) => { if (!nodes.has(id)) nodes.set(id, { id, ...n }); return nodes.get(id); };
  const addEdge = (a, b) => { if (nodes.has(a) && nodes.has(b) && a !== b) edges.push([a, b]); };

  const contracts = cluster.contracts.map((a) => d.contracts.find((c) => c.address === a && cluster.chains.includes(c.chain)) || d.contracts.find((c) => c.address === a)).filter(Boolean);
  const walletAddrs = new Set(cluster.wallets);
  contracts.forEach((c) => c.operator_wallets.forEach((w) => walletAddrs.add(w)));

  for (const addr of walletAddrs) {
    const w = d.wallets.find((x) => x.address === addr);
    const chain = w ? w.chain : (contracts[0] && contracts[0].chain) || '';
    addNode(`w:${addr}`, {
      kind: w && w.role === 'funder' ? 'funder' : 'wallet', label: shortHex(addr),
      title: `${w ? w.role : 'wallet'} ${addr}`, href: `#/wallets/${enc(chain)}/${enc(addr)}`,
    });
  }
  for (const c of contracts) {
    addNode(`c:${c.address}`, {
      kind: 'contract', label: shortHex(c.address), title: `contract ${c.address} (${c.update_count} updates)`,
      href: `#/contracts/${enc(c.chain)}/${enc(c.address)}`, live: c.status === 'active',
    });
    c.operator_wallets.forEach((w) => addEdge(`w:${w}`, `c:${c.address}`));
  }
  for (const w of d.wallets) {
    if (!nodes.has(`w:${w.address}`)) continue;
    w.funded_by.forEach((f) => addEdge(`w:${f}`, `w:${w.address}`));
  }
  const iocs = d.iocs.filter((i) => i.cluster_id === cluster.id && !i.type.startsWith('evm-'));
  for (const i of iocs) {
    const id = `i:${i.type}:${iocRaw(i)}`;
    const disp = defangIoc(i.type, i.value);
    const isWallet = i.type.endsWith('-wallet');
    const wk = key(i.type === 'xmr-wallet' ? 'monero' : 'bitcoin', i.value);
    addNode(id, {
      kind: isWallet ? 'payout' : 'ioc',
      label: isWallet ? shortHex(i.value, 6, 4) : (i.port !== null && i.type !== 'url' ? `${disp}:${i.port}` : disp).slice(0, 34),
      title: `${i.type} ${disp}${i.port !== null && i.type !== 'url' ? `:${i.port}` : ''}${i.current ? ' (current)' : ''}`,
      href: isWallet && d.walletByKey.has(wk) ? `#/wallets/${enc(wk.split(':')[0])}/${enc(i.value)}` : `#/iocs?q=${enc(i.value)}`,
      live: !!i.current,
    });
    i.contracts.forEach((c) => addEdge(`c:${c}`, id));
  }
  return { nodes: [...nodes.values()], edges };
}

function layout(nodes, edges) {
  const ring = { wallet: 0, funder: 0.5, contract: 1, ioc: 2, payout: 2 };
  const byKind = new Map();
  nodes.forEach((n) => { const r = ring[n.kind] ?? 2; if (!byKind.has(r)) byKind.set(r, []); byKind.get(r).push(n); });
  for (const [r, list] of byKind) {
    list.forEach((n, i) => {
      const a = (i / list.length) * Math.PI * 2 + r * 0.7;
      const rad = r === 0 && list.length === 1 ? 0 : 60 + r * 120;
      n.x = Math.cos(a) * rad; n.y = Math.sin(a) * rad;
    });
  }
  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  const E = edges.map(([a, b]) => [idx.get(a), idx.get(b)]);
  const k = 85;
  let temp = 60;
  for (let it = 0; it < 350; it++) {
    const dx = new Float64Array(nodes.length);
    const dy = new Float64Array(nodes.length);
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        let vx = nodes[i].x - nodes[j].x; let vy = nodes[i].y - nodes[j].y;
        let dist = Math.hypot(vx, vy);
        if (dist < 0.01) { vx = 0.1 * (i - j); vy = 0.1; dist = 0.15; }
        const f = (k * k) / dist;
        dx[i] += (vx / dist) * f; dy[i] += (vy / dist) * f;
        dx[j] -= (vx / dist) * f; dy[j] -= (vy / dist) * f;
      }
    }
    for (const [a, b] of E) {
      const vx = nodes[a].x - nodes[b].x; const vy = nodes[a].y - nodes[b].y;
      const dist = Math.max(0.01, Math.hypot(vx, vy));
      const f = (dist * dist) / k;
      dx[a] -= (vx / dist) * f; dy[a] -= (vy / dist) * f;
      dx[b] += (vx / dist) * f; dy[b] += (vy / dist) * f;
    }
    for (let i = 0; i < nodes.length; i++) {
      // gentle gravity keeps disconnected nodes in frame
      dx[i] -= nodes[i].x * 0.02; dy[i] -= nodes[i].y * 0.02;
      const len = Math.hypot(dx[i], dy[i]) || 1;
      const step = Math.min(len, temp);
      nodes[i].x += (dx[i] / len) * step; nodes[i].y += (dy[i] / len) * step;
    }
    temp = Math.max(1, temp * 0.985);
  }
}

const RADIUS = { wallet: 14, funder: 12, contract: 13, ioc: 11, payout: 11 };

/** The kind's glyph, knocked out of the badge (symbols live in index.html). */
function nodeIcon(kind, r) {
  const size = r * 1.15;
  return s('use', { class: 'node-icon', href: `#g-${kind}`, x: -size / 2, y: -size / 2, width: size, height: size });
}

function legendChip(kind, cls) {
  return h('span', { class: `lg ${cls}` }, s('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true' }, s('use', { href: `#g-${kind}` })));
}

export function clusterGraph(d, cluster) {
  const { nodes, edges } = buildClusterGraph(d, cluster);
  const fig = h('figure', { class: 'chart-fig' });
  if (!nodes.length) { fig.append(h('p', { class: 'empty' }, 'Nothing to draw.')); return fig; }
  layout(nodes, edges);
  const pad = 60;
  const xs = nodes.map((n) => n.x); const ys = nodes.map((n) => n.y);
  const minX = Math.min(...xs) - pad; const minY = Math.min(...ys) - pad;
  const w = Math.max(320, Math.max(...xs) - minX + pad); const hgt = Math.max(240, Math.max(...ys) - minY + pad);
  const svg = s('svg', {
    class: 'graph', viewBox: `${minX.toFixed(1)} ${minY.toFixed(1)} ${w.toFixed(1)} ${hgt.toFixed(1)}`,
    // Render at 1:1 scale so label font sizes stay as specified in CSS; the wrapper scrolls if wider.
    width: w.toFixed(0), height: hgt.toFixed(0),
    role: 'group', 'aria-label': `Cluster graph: ${nodes.length} nodes, ${edges.length} links. Tab through nodes; Enter opens.`,
  });
  const pos = new Map(nodes.map((n) => [n.id, n]));
  const gEdges = s('g');
  for (const [a, b] of edges) {
    const A = pos.get(a); const B = pos.get(b);
    gEdges.append(s('line', { class: A.live && B.live ? 'edge edge-live' : 'edge', x1: A.x.toFixed(1), y1: A.y.toFixed(1), x2: B.x.toFixed(1), y2: B.y.toFixed(1) }));
  }
  svg.append(gEdges);
  const order = { wallet: 0, funder: 1, contract: 2, payout: 3, ioc: 4 };
  for (const n of nodes.slice().sort((a, b) => order[a.kind] - order[b.kind])) {
    const g = s('g', { class: 'node', tabindex: '0', role: 'link', 'aria-label': `${n.title}${n.live ? ' (live)' : ''}`, transform: `translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})` });
    const r = RADIUS[n.kind] || 11;
    if (n.live) {
      const o = r + 4;
      g.append(s('rect', { class: 'live-ring', x: -o, y: -o, width: o * 2, height: o * 2, rx: (r * 0.55 + 4).toFixed(1) }));
    }
    g.append(s('rect', { class: `badge-bg n-${n.kind}`, x: -r, y: -r, width: r * 2, height: r * 2, rx: (r * 0.55).toFixed(1) }));
    g.append(nodeIcon(n.kind, r));
    g.append(s('title', null, `${n.title}${n.live ? ' — live' : ''}`));
    g.append(s('text', { y: r + 13, 'text-anchor': 'middle' }, n.label));
    const go = () => { window.location.hash = n.href; };
    g.addEventListener('click', go);
    g.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); go(); } });
    svg.append(g);
  }
  fig.append(h('div', { class: 'graph-wrap' }, svg));
  fig.append(h('div', { class: 'legend' },
    h('span', null, legendChip('wallet', 'lg-wallet'), 'operator wallet'),
    h('span', null, legendChip('funder', 'lg-wallet'), 'funder'),
    h('span', null, legendChip('contract', 'lg-contract'), 'contract'),
    h('span', null, legendChip('ioc', 'lg-ioc'), 'network IOC'),
    h('span', null, legendChip('payout', 'lg-payout'), 'payout wallet'),
    h('span', { class: 'faint' }, 'dashed ring = still live')));
  return fig;
}
