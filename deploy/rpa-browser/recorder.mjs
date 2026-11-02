// M16-T3: recording steps by showing. Pure parts only (no Playwright), so
// they are tested on their own (`node --test recorder.test.mjs`):
//
// - `selectorFor` turns what the page says about the element under a click
//   into the steadiest selector it can: a test id, an id, a name, an ARIA
//   label, a button's or link's text, and only then a CSS path.
// - `ELEMENT_INFO` is the function the service evaluates in the page at the
//   clicked point to gather that description.
// - `checkStart` checks a recording's start.

/** The most recordings one service holds at once. */
export const MAX_SESSIONS = 2;
/** A recording nobody touched for this long is closed, in milliseconds. */
export const IDLE_MS = 5 * 60_000;
/** The recording viewport: clicks arrive in these pixels. */
export const VIEWPORT = { width: 1280, height: 800 };

const IDENT = /^[A-Za-z][\w-]*$/;

function quoted(value) {
  return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/**
 * The selector for an element described as
 * `{ tag, id, testid, name, ariaLabel, text, path }`. Pure.
 */
export function selectorFor(info) {
  const tag = String(info?.tag ?? '').toLowerCase() || '*';
  if (info?.testid) return `[data-testid=${quoted(info.testid)}]`;
  if (info?.id && IDENT.test(info.id)) return `#${info.id}`;
  if (info?.name) return `${tag}[name=${quoted(info.name)}]`;
  if (info?.ariaLabel) return `${tag}[aria-label=${quoted(info.ariaLabel)}]`;
  const text = String(info?.text ?? '').trim().replace(/\s+/g, ' ');
  if ((tag === 'button' || tag === 'a') && text && text.length <= 40) {
    return `${tag}:has-text(${quoted(text)})`;
  }
  return info?.path || tag;
}

/**
 * Evaluated in the page with `{ x, y }`: the interactive element at that
 * point (or the element itself), described for `selectorFor`, and whether
 * it is a password field.
 */
export function ELEMENT_INFO({ x, y }) {
  const hit = document.elementFromPoint(x, y);
  if (!hit) return null;
  const el = hit.closest('a,button,input,select,textarea,label,[role=button],[role=link],[data-testid]') ?? hit;
  const path = [];
  for (let n = el; n && n.nodeType === 1 && path.length < 5; n = n.parentElement) {
    if (n.id && /^[A-Za-z][\w-]*$/.test(n.id)) {
      path.unshift(`#${n.id}`);
      break;
    }
    const same = n.parentElement
      ? [...n.parentElement.children].filter((c) => c.tagName === n.tagName)
      : [n];
    const tag = n.tagName.toLowerCase();
    path.unshift(same.length > 1 ? `${tag}:nth-of-type(${same.indexOf(n) + 1})` : tag);
  }
  return {
    tag: el.tagName.toLowerCase(),
    id: el.id || null,
    testid: el.getAttribute('data-testid'),
    name: el.getAttribute('name'),
    ariaLabel: el.getAttribute('aria-label'),
    text: (el.innerText ?? '').slice(0, 80),
    path: path.join(' > '),
    password: el.tagName === 'INPUT' && el.type === 'password',
  };
}

/** A recording's start, checked: `{ url, allowed_hosts }`. Pure. */
export function checkStart(body, hostAllowed) {
  const allowed = body?.allowed_hosts;
  if (!Array.isArray(allowed) || allowed.length === 0 || !allowed.every((h) => typeof h === 'string' && h.length > 0)) {
    return { ok: false, error: 'allowed_hosts names at least one host' };
  }
  if (typeof body.url !== 'string' || !hostAllowed(body.url, allowed)) {
    return { ok: false, error: 'url is on an allowed host' };
  }
  return { ok: true, start: { url: body.url, allowed } };
}

/** Whether a click at `{x, y}` is inside the viewport. Pure. */
export function pointOk(point) {
  return Number.isFinite(point?.x) && Number.isFinite(point?.y)
    && point.x >= 0 && point.y >= 0 && point.x < VIEWPORT.width && point.y < VIEWPORT.height;
}
