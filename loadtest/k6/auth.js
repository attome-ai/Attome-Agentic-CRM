// Request class: Auth (login + cookie-validated request).
// guidelines §14.5 budget: P50 <50ms, P99 <200ms.
import http from 'k6/http';
import { check, sleep } from 'k6';
import { pickBaseUrl } from './lib/http.js';
import { thresholdsFor } from './lib/slo.js';

export const options = {
  vus: Number(__ENV.VUS || 10),
  duration: __ENV.DURATION || '30s',
  // Generated from observability/slo-catalogue.json (attome slo generate).
  thresholds: { ...thresholdsFor('S2'), ...thresholdsFor('S1') },
};

const EMAIL = __ENV.TEST_EMAIL;
const PASSWORD = __ENV.TEST_PASSWORD;

export default function () {
  const baseUrl = pickBaseUrl();

  const loginRes = http.post(
    `${baseUrl}/api/v1/auth/login`,
    JSON.stringify({ email: EMAIL, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'login', slo_class: 'S2' } }
  );
  check(loginRes, { 'login 200': (r) => r.status === 200 });

  const setCookie = loginRes.headers['Set-Cookie'] || '';
  // Match the full cookie name: a secure deployment issues
  // __Host-session_token and ignores the bare name (security contract I1).
  const match = /(?:__Host-)?session_token=[^;,]+/.exec(setCookie);
  if (match) {
    // whoami (attome-security) is any-authenticated-user, not admin-gated —
    // the "cookie-validated request" half of this class: one Redis GET
    // (JWT-denylist check) + the authz L1/L2 resolution path.
    const whoRes = http.get(`${baseUrl}/api/v1/admin/security/whoami`, {
      headers: { Cookie: match[0] },
      tags: { name: 'whoami', slo_class: 'S1' },
    });
    check(whoRes, { 'whoami 200': (r) => r.status === 200 });
  }

  sleep(0.1);
}
