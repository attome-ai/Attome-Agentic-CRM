// Request class: Notification poll.
// guidelines §14.5 has no dedicated row for this class; included per the
// plan's step 2 request-class list anyway (it's a plain-read, session-gated,
// no-body endpoint — a useful low-end latency floor to compare the others against).
import http from 'k6/http';
import { check } from 'k6';
import { baseUrls, pickBaseUrl, login } from './lib/http.js';

export const options = {
  vus: Number(__ENV.VUS || 20),
  duration: __ENV.DURATION || '30s',
};

const TEST_EMAIL = __ENV.TEST_EMAIL;
const TEST_PASSWORD = __ENV.TEST_PASSWORD;

export function setup() {
  const baseUrl = baseUrls()[0];
  const cookie = login(baseUrl, TEST_EMAIL, TEST_PASSWORD);
  return { cookie };
}

export default function (data) {
  const baseUrl = pickBaseUrl();
  // POST with no body, so not lib/http.js's jsonHeaders (which would claim a
  // Content-Type this request doesn't have) — but the same reason that helper
  // exists applies: `csrf_protect` fails closed on a cookie-authenticated
  // unsafe method carrying no browser-supplied Sec-Fetch-Site, so without this
  // header the scenario measures 403s. Fixed in TODO-014's pre-run pass.
  const res = http.post(`${baseUrl}/api/v1/notification/poll`, null, {
    headers: { Cookie: data.cookie, 'Sec-Fetch-Site': 'same-origin' },
    tags: { name: 'notification_poll' },
  });
  check(res, { 'poll 200': (r) => r.status === 200 });
}
