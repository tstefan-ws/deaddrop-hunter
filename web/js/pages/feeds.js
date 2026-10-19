import { h, copyText } from '../dom.js';
import { sanitize, fmtBytes, fmtDate, fmtNum } from '../fmt.js';
import { loadFeeds, loadApiIndex } from '../data.js';
import { pageHead, panel } from '../ui.js';

const NOTES = [
  ['STIX 2.1', 'OpenCTI: Data → Import → upload the bundle (or point the "STIX file import" / TAXII-less HTTP connector at the URL). Indicators carry TLP:CLEAR markings and link to malware and infrastructure objects.'],
  ['MISP', 'MISP: Sync Actions → Feeds → Add feed, type "MISP Feed", URL = the misp/ directory; or Events → Import from → MISP JSON for a single event file.'],
  ['CSV', 'SIEM lookups (Splunk lookup table, Elastic enrich policy, Sentinel watchlist). Values are raw: import, don\'t click.'],
  ['TXT', 'One indicator per line for firewall blocklists: Palo Alto External Dynamic List, FortiGate external threat feed, pfBlockerNG, OPNsense aliases (URL table).'],
];

function curlExample(url) {
  return `curl -s '${url.replace(/'/g, '%27')}'`;
}

function apiSection(api) {
  if (!api || !api.endpoints.length) {
    return panel('JSON API', h('p', { class: 'empty' }, 'No static API published at ./feeds/api/v1/index.json (expected in sample/local mode).'));
  }
  const ul = h('ul', { class: 'feed' });
  for (const e of api.endpoints) {
    const curl = curlExample(e.url);
    ul.append(h('li', null,
      h('div', { class: 'btn-row' },
        e.href ? h('a', { class: 'mono wrap-any', href: e.href }, sanitize(e.url)) : h('span', { class: 'mono wrap-any' }, sanitize(e.url)),
        e.template ? h('span', { class: 'pill' }, 'template') : null),
      h('div', { class: 'meta' },
        e.count !== null ? h('span', null, `${fmtNum(e.count)} records`) : null,
        e.description ? h('span', null, sanitize(e.description)) : null),
      h('div', { class: 'btn-row' },
        h('code', { class: 'wrap-any faint' }, sanitize(curl)),
        h('button', { type: 'button', class: 'btn btn-sm btn-ghost', 'aria-label': `Copy curl command for ${e.path}`, onclick: () => copyText(curl, 'curl command') }, 'copy'))));
  }
  return panel('JSON API', h('div', null,
    h('p', { class: 'muted' }, 'Every endpoint returns {schema_version, generated_at, license, count, data:[…]}. Static files: safe to poll, cache-friendly.',
      api.generated ? ` Generated ${fmtDate(api.generated)}.` : ''),
    ul));
}

function filesSection(feeds) {
  if (!feeds) {
    return panel('Download feeds', h('div', null,
      h('p', { class: 'empty' }, 'No feeds published yet: ./feeds/index.json is not available on this deployment.'),
      h('p', { class: 'muted' }, 'Feeds are produced by the exporter step of the hunt pipeline and appear here automatically once published.')));
  }
  if (!feeds.files.length) return panel('Download feeds', h('p', { class: 'empty' }, 'The feed index is empty.'));
  const ul = h('ul', { class: 'feed' });
  for (const f of feeds.files) {
    ul.append(h('li', null,
      h('div', { class: 'btn-row' },
        h('span', { class: 'pill' }, sanitize(f.format || '?')),
        f.href ? h('a', { href: f.href, download: '' }, sanitize(f.path)) : h('span', { class: 'mono' }, sanitize(f.path))),
      f.description ? h('div', null, sanitize(f.description)) : null,
      h('div', { class: 'meta' },
        f.size !== null ? h('span', null, fmtBytes(f.size)) : null,
        f.sha256 ? h('span', { class: 'mono wrap-any', title: 'SHA-256' }, `sha256 ${f.sha256}`) : null,
        f.sha256 ? h('button', { type: 'button', class: 'btn btn-sm btn-ghost', onclick: () => copyText(f.sha256, 'sha256') }, 'copy hash') : null)));
  }
  return panel('Download feeds', h('div', null,
    feeds.generated ? h('p', { class: 'muted' }, `Generated ${fmtDate(feeds.generated)}.`) : null, ul));
}

export function renderFeeds() {
  const body = h('div', null, h('p', { class: 'loading' }, 'Looking for published feeds…'));
  const page = h('div', null,
    pageHead({ title: 'Feeds', sub: 'Machine-readable exports of the current dataset (TLP:CLEAR). Indicators are raw in these files: do not open them in a browser that may auto-link.' }),
    body);
  Promise.all([loadFeeds(), loadApiIndex()]).then(([feeds, api]) => {
    const published = !!(feeds || api);
    body.replaceChildren(
      h('div', { class: 'grid grid-2' },
        filesSection(feeds),
        panel('Subscribe', h('div', null,
          published
            ? h('p', null, h('a', { href: './feeds/atom.xml', type: 'application/atom+xml' }, 'Atom feed of new rotations'), ' (works in any RSS/Atom reader).')
            : h('p', { class: 'empty' }, 'The Atom feed (./feeds/atom.xml) is published together with the other feeds.'),
          h('h3', { class: 'section' }, 'Usage notes'),
          h('dl', { class: 'kv section' }, NOTES.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]))))),
      h('div', { class: 'section' }, apiSection(api)));
  });
  return page;
}
