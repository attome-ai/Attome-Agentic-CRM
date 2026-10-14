// Shared helpers for every scenario script. Base URLs come in as a
// comma-separated env var so k6 can spread load across N app-node
// processes without needing a real load balancer in front of them (they're
// stateless/identical per the platform's multi-node architecture rule —
// picking one per VU is equivalent to a round-robin LB for this exercise).
import http from 'k6/http';
import { check } from 'k6';

export function baseUrls() {
  const raw = __ENV.BASE_URLS || 'http://localhost:7900';
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

// Stable per-VU assignment (not per-iteration) — a real client stays on
// whichever node a load balancer picked until its connection drops.
export function pickBaseUrl() {
  const urls = baseUrls();
  return urls[(__VU - 1) % urls.length];
}

// Logs in once and returns the `session_token=...` cookie string k6 can
// send back on subsequent requests without carrying a full CookieJar.
export function login(baseUrl, email, password) {
  const res = http.post(
    `${baseUrl}/api/v1/auth/login`,
    JSON.stringify({ email, password }),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'login' } }
  );
  check(res, { 'login succeeded': (r) => r.status === 200 });
  const setCookie = res.headers['Set-Cookie'];
  if (!setCookie) {
    throw new Error(`login did not return Set-Cookie (status ${res.status}): ${res.body}`);
  }
  // k6 folds multiple Set-Cookie response headers into one comma-joined
  // string. Capture the full cookie name: a secure deployment issues
  // __Host-session_token, and authn ignores the bare name there (security
  // contract I1), so dropping the prefix would turn every request into a 401.
  const match = /(?:__Host-)?session_token=[^;,]+/.exec(setCookie);
  if (!match) {
    throw new Error(`login response Set-Cookie had no session_token: ${setCookie}`);
  }
  return match[0];
}

// P1.8d step 10 finding: `attome_server::middleware::csrf` (P-cookie-csrf-hardening)
// rejects a cookie-authenticated POST/PUT/PATCH/DELETE whose `Sec-Fetch-Site`
// is missing/cross-site AND whose `Origin` isn't in the CORS allow-list —
// `security.csrf_enforce` defaults `true` (`SecuritySection::default`,
// attome-config/src/config.rs) and the loadtest config generator
// (scripts/common.ps1's New-LoadtestConfig) never overrides it, so a raw k6
// mutating request carrying only `Cookie` (no browser-supplied
// `Sec-Fetch-Site`) is exactly `csrf.rs`'s
// `cookie_present_unsafe_method_no_metadata_at_all_is_blocked` case — a 403,
// not the intended request. `Sec-Fetch-Site: same-origin` is what a real
// same-origin browser tab sends automatically, so adding it here makes k6
// behave like the real client this harness is simulating, not a workaround.
// TODO-014's pre-run pass extended this to every scenario that predates the
// middleware — including crud_read.js/list_query.js, whose `query/execute`
// POSTs are reads but are still cookie-authenticated unsafe methods and were
// missed by step 10's original finding, which named only the two mutating
// scenarios.
export function jsonHeaders(cookie, extra = {}) {
  return {
    'Content-Type': 'application/json',
    Cookie: cookie,
    'Sec-Fetch-Site': 'same-origin',
    ...extra,
  };
}
