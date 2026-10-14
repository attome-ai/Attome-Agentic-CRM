// Request class: CRUD read (DB).
// guidelines §14.5 budget: P50 <30ms, P99 <100ms.
import http from 'k6/http';
import { check } from 'k6';
import { baseUrls, pickBaseUrl, login, jsonHeaders } from './lib/http.js';

export const options = {
  vus: Number(__ENV.VUS || 20),
  duration: __ENV.DURATION || '30s',
};

const TEST_EMAIL = __ENV.TEST_EMAIL;
const TEST_PASSWORD = __ENV.TEST_PASSWORD;
const BULK_ENTITY = __ENV.BULK_ENTITY || 'loadtest_bulk';
const BULK_QUERY_ID = __ENV.BULK_QUERY_ID;

export function setup() {
  const baseUrl = baseUrls()[0];
  const cookie = login(baseUrl, TEST_EMAIL, TEST_PASSWORD);

  // Sample a page of real ids via query/execute, by query_id (not entity
  // name) -- create_entity auto-generates its own default query per entity,
  // and the entity-name lookup always resolves to that auto-generated one
  // (earliest created_at wins), which has no required_privilege and so
  // demands admin -- the test user only has a real path in via the specific
  // query seed.ps1 created (required_privilege=loadtest_bulk.read).
  const res = http.post(
    `${baseUrl}/api/v1/query/execute`,
    JSON.stringify({ query_id: BULK_QUERY_ID, page: 1, page_size: 200 }),
    // query/execute is a read, but it is a cookie-authenticated POST — an
    // unsafe method as far as `csrf_protect` is concerned, so it needs the
    // same browser signal the mutating scenarios do (TODO-014 pre-run pass).
    { headers: jsonHeaders(cookie) }
  );
  if (res.status !== 200) {
    throw new Error(`setup: query/execute sampling failed (${res.status}): ${res.body}`);
  }
  const ids = JSON.parse(res.body).data.records.map((r) => r.id);
  return { cookie, ids };
}

export default function (data) {
  const baseUrl = pickBaseUrl();
  const id = data.ids[(__VU + __ITER) % data.ids.length];
  const res = http.get(`${baseUrl}/api/v1/${BULK_ENTITY}/${id}`, {
    headers: { Cookie: data.cookie },
    tags: { name: 'crud_read' },
  });
  check(res, { 'crud read 200': (r) => r.status === 200 });
}
