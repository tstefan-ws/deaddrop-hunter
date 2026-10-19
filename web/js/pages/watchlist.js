import { h } from '../dom.js';
import { sanitize, timeEl, chainLabel } from '../fmt.js';
import { key, walletEvents, maxBlock } from '../data.js';
import { watchlist } from '../store.js';
import { diffValues, diffSummary } from '../diff.js';
import { pageHead, panel, statusPill, clusterPill, contractLink, walletLink, starButton, watchedPill } from '../ui.js';

function itemEvents(d, it) {
  if (it.kind === 'contract') return d.eventsByContract.get(key(it.chain, it.address)) || [];
  const w = d.walletByKey.get(key(it.chain, it.address));
  return w ? walletEvents(d, w) : [];
}

/** Events newer than the block stored when the item was last viewed. */
export function newSince(d, it) {
  return itemEvents(d, it).filter((e) => e.block > (it.seenBlock || 0));
}

export function renderWatchlist(ctx) {
  const { d } = ctx;
  const items = watchlist.all();
  const head = pageHead({
    title: 'Watchlist',
    sub: 'Your starred contracts and wallets, stored only in this browser. Opening an item marks its rotations as seen.',
    actions: items.length ? [h('button', {
      type: 'button', class: 'btn',
      onclick: () => { items.forEach((it) => watchlist.markSeen(it.kind, it.chain, it.address, maxBlock(itemEvents(d, it)))); ctx.rerender(); },
    }, 'Mark all as seen')] : null,
  });
  if (!items.length) {
    return h('div', null, head, panel('Nothing starred yet', h('p', { class: 'empty' },
      'Use ☆ on any contract or wallet (', h('a', { href: '#/contracts' }, 'contracts'), ', ', h('a', { href: '#/wallets' }, 'wallets'), ') to track it here.')));
  }
  const cards = items.map((it) => {
    const fresh = newSince(d, it);
    const evs = itemEvents(d, it);
    const c = it.kind === 'contract' ? d.contractByKey.get(key(it.chain, it.address)) : null;
    const w = it.kind === 'wallet' ? d.walletByKey.get(key(it.chain, it.address)) : null;
    const missing = !c && !w;
    return h('div', { class: 'card' },
      h('div', { class: 'card-head' },
        h('span', { class: 'id' }, `${it.kind} · ${chainLabel(it.chain)}`),
        h('span', { class: 'btn-row' },
          fresh.length ? h('span', { class: 'pill pill-new' }, `${fresh.length} new rotation${fresh.length > 1 ? 's' : ''}`) : h('span', { class: 'pill' }, 'no changes'),
          starButton(d, it.kind, it.chain, it.address, ctx.rerender))),
      h('div', { class: 'wrap-any' }, it.kind === 'contract' ? contractLink(it.chain, it.address, true) : walletLink(d, it.chain, it.address, true)),
      missing ? h('p', { class: 'empty' }, 'No longer present in the dataset.') : h('div', { class: 'card-stats' },
        c ? statusPill(c.status) : h('span', { class: 'pill' }, sanitize(w.role)),
        w && w.watched ? watchedPill() : null,
        clusterPill(d, (c || w).cluster_id),
        h('span', null, `${evs.length} rotations`),
        evs[0] ? h('span', null, 'last ', timeEl(evs[0].timestamp, false)) : null),
      fresh.length ? h('div', null, fresh.slice(0, 3).map((e) => h('div', null, h('span', { class: 'faint' }, timeEl(e.timestamp), ' '), diffSummary(diffValues(e.old_decoded, e.new_decoded), 2)))) : null,
      h('div', { class: 'faint' }, 'starred ', timeEl(it.added, false)));
  });
  return h('div', null, head, h('div', { class: 'cards' }, cards));
}
