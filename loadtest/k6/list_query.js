// Request class: List query via query/execute (DB, <=1k rows).
// guidelines §14.5 budget: P50 <80ms, P99 <300ms.
import http from 'k6/http';
import { check } from 'k6';
import { baseUrls, pickBaseUrl, login, jsonHeaders } from './lib/http.js';

export const options = {
  vus: Number(__ENV.VUS || 20),
  duration: __ENV.DURATION || '30s',
};

const TEST_EMAIL = __ENV.TEST_EMAIL;
const TEST_PASSWORD = __ENV.TEST_PASSWORD;
const BULK_QUERY_ID = __ENV.BULK_QUERY_ID;
const BULK_ROW_COUNT = Number(__ENV.BULK_ROW_COUNT || 20000);

export function setup() {
  const baseUrl = baseUrls()[0];
  const cookie = login(baseUrl, TEST_EMAIL, TEST_PASSWORD);
  return { cookie };
}

export default function (data) {
  const baseUrl = pickBaseUrl();
  // A filtered, sorted, paginated read against the stored query created by
  // seed.ps1 (required_privilege=loadtest_bulk.read, so the non-admin test
  // user reaches it) — the same shape a real list view issues.
  const threshold = Math.floor(Math.random() * BULK_ROW_COUNT * 0.9);
  const res = http.post(
    `${baseUrl}/api/v1/query/execute`,
    JSON.stringify({
      query_id: BULK_QUERY_ID,
      page: 1,
      page_size: 100,
      order_by: 'seq',
      order_dir: 'asc',
      filters: [{ field: 'seq', op: 'gt', value: String(threshold) }],
    }),
    // Cookie-authenticated POST — `csrf_protect` treats it as an unsafe method
    // regardless of it being a read, so jsonHeaders' Sec-Fetch-Site is what
    // keeps this measuring the query engine instead of a 403 (TODO-014).
    { headers: jsonHeaders(data.cookie), tags: { name: 'list_query' } }
  );
  check(res, { 'list query 200': (r) => r.status === 200 });
}
