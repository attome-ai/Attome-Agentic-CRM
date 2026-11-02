// M16-T1: the step list a run takes, checked before a browser starts, and
// the host allow-list every request of the run is held to. Pure; no
// Playwright here, so it is tested on its own (`node --test`).

/** The most steps one run takes. */
export const MAX_STEPS = 50;
/** The longest a run may take, in milliseconds. */
export const MAX_RUN_MS = 120_000;

/** Each step kind and the fields it needs. */
export const STEP_KINDS = {
  goto: ['url'],
  click: ['selector'],
  fill: ['selector', 'value'],
  press: ['selector', 'key'],
  wait_for: ['selector'],
  text: ['selector'],
  screenshot: [],
};

/** Whether `url` is http(s) on an allow-listed host (exact, or a subdomain of a `.`-prefixed entry). */
export function hostAllowed(url, allowed) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
  const host = parsed.hostname.toLowerCase();
  return allowed.some((entry) => {
    const e = String(entry).toLowerCase();
    return e.startsWith('.') ? host.endsWith(e) || host === e.slice(1) : host === e;
  });
}

/**
 * The run as given, checked: `{ steps, allowed_hosts, timeout_ms }`.
 * Answers `{ ok: true, run }` or `{ ok: false, error }`. Pure.
 */
export function checkRun(body) {
  if (!body || typeof body !== 'object') return { ok: false, error: 'the body is a JSON object' };
  const { steps, allowed_hosts: allowed, timeout_ms: timeout = 30_000 } = body;
  if (!Array.isArray(allowed) || allowed.length === 0 || !allowed.every((h) => typeof h === 'string' && h.length > 0)) {
    return { ok: false, error: 'allowed_hosts names at least one host' };
  }
  if (!Array.isArray(steps) || steps.length === 0 || steps.length > MAX_STEPS) {
    return { ok: false, error: `steps is a list of 1 to ${MAX_STEPS} steps` };
  }
  if (!Number.isInteger(timeout) || timeout < 1_000 || timeout > MAX_RUN_MS) {
    return { ok: false, error: `timeout_ms is 1000 to ${MAX_RUN_MS}` };
  }
  for (const [i, step] of steps.entries()) {
    const need = STEP_KINDS[step?.kind];
    if (!need) return { ok: false, error: `step ${i + 1}: kind is one of ${Object.keys(STEP_KINDS).join(', ')}` };
    for (const field of need) {
      if (typeof step[field] !== 'string' || step[field].length === 0 || step[field].length > 2_000) {
        return { ok: false, error: `step ${i + 1}: ${step.kind} needs ${field}` };
      }
    }
    if (step.kind === 'goto' && !hostAllowed(step.url, allowed)) {
      return { ok: false, error: `step ${i + 1}: ${step.url} is not on an allowed host` };
    }
  }
  return { ok: true, run: { steps, allowed, timeout } };
}
