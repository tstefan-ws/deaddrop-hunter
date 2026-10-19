// Safe DOM construction. Everything from data goes through textContent / text nodes.
// Never use innerHTML / insertAdjacentHTML / outerHTML in this project.

const SVG_NS = 'http://www.w3.org/2000/svg';

function append(el, child) {
  if (child === null || child === undefined || child === false) return;
  if (Array.isArray(child)) { child.forEach((c) => append(el, c)); return; }
  if (child instanceof Node) { el.appendChild(child); return; }
  el.appendChild(document.createTextNode(String(child)));
}

function applyAttrs(el, attrs, isSvg) {
  if (!attrs) return;
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.setAttribute('class', Array.isArray(v) ? v.filter(Boolean).join(' ') : v);
    else if (k === 'text') el.textContent = String(v);
    else if (k === 'dataset') Object.entries(v).forEach(([dk, dv]) => { el.dataset[dk] = String(dv); });
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'href') {
      // Only internal hash routes and same-origin relative paths. External links use extLink().
      const s = String(v);
      if (s.startsWith('#') || s.startsWith('./')) el.setAttribute('href', s);
    } else if (k === 'style') {
      throw new Error('inline style attributes are not allowed (CSP)');
    } else if (!isSvg && k === 'value') {
      el.value = String(v);
    } else if (!isSvg && k in el && typeof v !== 'string' && k !== 'role') {
      el[k] = v;
    } else el.setAttribute(k, v === true ? '' : String(v));
  }
}

/** h('div', {class: 'x'}, 'text', child, [children]) */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  applyAttrs(el, attrs, false);
  append(el, children);
  if (tag === 'select' && attrs && attrs.value !== undefined) el.value = String(attrs.value);
  return el;
}

/** SVG element builder. */
export function s(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  applyAttrs(el, attrs, true);
  append(el, children);
  return el;
}

export function clear(el) { el.replaceChildren(); return el; }

export function mount(el, ...children) { el.replaceChildren(); append(el, children); return el; }

/** External link. Caller must have validated the URL (explorer links only). */
export function extLink(url, label, cls) {
  const a = document.createElement('a');
  a.href = url;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  a.referrerPolicy = 'no-referrer';
  if (cls) a.className = cls;
  a.textContent = label;
  return a;
}

let toastTimer = null;
export function toast(msg) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1800);
}

export async function copyText(text, label) {
  let ok = false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      ok = true;
    }
  } catch { ok = false; }
  if (!ok) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.className = 'visually-hidden';
    document.body.appendChild(ta);
    ta.select();
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
  }
  toast(ok ? `Copied ${label || ''}`.trim() : 'Copy failed: select and copy manually');
  return ok;
}

export function downloadBlob(filename, mime, content) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
