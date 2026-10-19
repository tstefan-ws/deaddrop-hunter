// Shared UI pieces.
import { h } from './dom.js';
import { explorerLink, shortHex, sanitize, chainLabel, isTxFor, isAddrFor } from './fmt.js';
import { slotClass, key, walletEvents, maxBlock } from './data.js';
import { watchlist } from './store.js';

const enc = encodeURIComponent;

export const contractHref = (chain, addr) => `#/contracts/${enc(chain)}/${enc(addr)}`;
export const walletHref = (chain, addr) => `#/wallets/${enc(chain)}/${enc(addr)}`;
export const clusterHref = (id) => `#/clusters/${enc(id)}`;

export function pageHead({ crumbs = [], title, sub, actions, titleClass }) {
  const crumbEl = crumbs.length ? h('nav', { class: 'crumbs', 'aria-label': 'Breadcrumb' },
    crumbs.map(([label, href], i) => [i ? ' / ' : '', href ? h('a', { href }, label) : label])) : null;
  return h('div', { class: 'page-head' },
    h('div', { class: 'wrap-any' }, crumbEl, h('h1', { class: titleClass || null, tabindex: '-1' }, title), sub ? h('p', { class: 'sub' }, sub) : null),
    actions ? h('div', { class: 'btn-row' }, actions) : null);
}

export function panel(title, children, action) {
  return h('section', { class: 'panel' }, h('h2', null, h('span', null, title), action || null), children);
}

export function kv(pairs) {
  const dl = h('dl', { class: 'kv' });
  for (const [k, v] of pairs) {
    if (v === undefined) continue;
    dl.append(h('dt', null, k), h('dd', null, v === null || v === '' ? h('span', { class: 'faint' }, '—') : v));
  }
  return dl;
}

export function statusPill(status) {
  return h('span', { class: `pill pill-${status === 'active' ? 'active' : 'dormant'}` }, status === 'active' ? 'active' : 'dormant');
}

/** A contract nobody has decoded a value from yet: a watched operator touched it, nothing more. */
export function evidencePill(evidence) {
  if (evidence !== 'candidate') return null;
  return h('span', { class: 'pill pill-candidate', title: 'Candidate: a watched operator deployed or called this contract, but no value has been decoded from it yet' }, 'candidate');
}

/** Entered our data inside the new-window (see meta.new_window_hours), not newly deployed. */
export function newPill(isNew, discoveredAt) {
  if (!isNew) return null;
  return h('span', { class: 'pill pill-new', title: discoveredAt ? `First seen by this hunter at ${sanitize(discoveredAt)}` : null }, 'new');
}

/** Real indicator, shared with legitimate users (public mining pools and the like). */
export function dualUsePill(on) {
  if (!on) return null;
  return h('span', { class: 'pill pill-dual', title: 'Dual-use: a shared public service. Real, but withheld from the plain-text blocklists because blocking it hits legitimate users.' }, 'dual-use');
}

export function watchedPill() {
  return h('span', { class: 'pill pill-watched', title: 'Watched operator wallet (configured in hunts.toml)' }, '◉ watched');
}

export function clusterPill(d, id) {
  if (!id) return h('span', { class: 'faint' }, '—');
  const c = d.clusterById.get(id);
  return h('a', { class: 'pill pill-cluster', href: clusterHref(id), title: c ? sanitize(c.name) : null },
    h('span', { class: `swatch ${slotClass(d, id, 'sw')}`, 'aria-hidden': 'true' }), sanitize(id));
}

export function contractLink(chain, addr, full = false) {
  return h('a', { class: 'addr', href: contractHref(chain, addr), title: sanitize(addr) }, full ? sanitize(addr) : shortHex(sanitize(addr)));
}

export function walletLink(d, chain, addr, full = false) {
  const w = d.walletByKey.get(key(chain, addr));
  if (!w && !isAddrFor(chain, addr)) return h('span', { class: 'addr' }, full ? sanitize(addr) : shortHex(sanitize(addr)));
  return h('a', { class: 'addr', href: walletHref(chain, addr), title: sanitize(addr) }, full ? sanitize(addr) : shortHex(sanitize(addr)));
}

export function txLink(chain, hash, label) {
  if (!isTxFor(chain, hash)) return h('span', { class: 'faint mono' }, hash ? shortHex(sanitize(hash), 10, 6) : '—');
  return explorerLink(chain, 'tx', hash, label || shortHex(hash, 10, 6)) || h('span', { class: 'mono' }, shortHex(hash, 10, 6));
}

export function chainTag(chain) {
  return h('span', { class: 'mono' }, chainLabel(chain));
}

export function seenBlockFor(d, kind, chain, address) {
  if (kind === 'contract') return maxBlock(d.eventsByContract.get(key(chain, address)) || []);
  const w = d.walletByKey.get(key(chain, address));
  return w ? maxBlock(walletEvents(d, w)) : 0;
}

export function starButton(d, kind, chain, address, onChange) {
  const btn = h('button', { type: 'button', class: 'btn btn-ghost star' });
  const sync = () => {
    const on = watchlist.has(kind, chain, address);
    btn.setAttribute('aria-pressed', on ? 'true' : 'false');
    btn.setAttribute('aria-label', `${on ? 'Remove from' : 'Add to'} watchlist: ${kind} ${address}`);
    btn.title = on ? 'In your watchlist (click to remove)' : 'Add to your watchlist';
    btn.textContent = on ? '★' : '☆';
  };
  btn.addEventListener('click', () => {
    watchlist.toggle(kind, chain, address, seenBlockFor(d, kind, chain, address));
    sync();
    if (onChange) onChange();
  });
  sync();
  return btn;
}

export function familyTag(f) {
  return h('span', { class: 'mono' }, sanitize(f || 'unknown'));
}

export function notFound(what, detail) {
  return h('div', null,
    pageHead({ title: `${what} not found`, sub: detail ? `No entry for ${sanitize(detail)} in the current dataset.` : null }),
    h('p', null, h('a', { href: '#/' }, '← Back to overview')));
}
