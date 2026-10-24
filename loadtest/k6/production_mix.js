// AA1-T3: the production-shaped mix. Six weighted scenarios, one per
// operation class (read 50%, list 20%, query 10%, write 12%, search 6%,
// bulk 2% of RATE requests a second), each tagged `op` so the summary
// splits p50/p95/p99 per class. Requests run as the profile's users from
// seed.ps1's `seed-<profile>.json` (SEED_FILE), in rotation, so many roles
// are exercised; without a seed file, as the test user.
//
// Warm by default: a WARMUP window (30s) of the same mix runs first and is
// tagged `phase: warmup`, so the per-class numbers (`phase: measure`) leave
// it out. run-matrix.ps1 -Cold restarts the server, empties the cache and
// sets WARMUP=0s.
//
//   k6 run -e BASE_URLS=http://localhost:7900 -e BULK_QUERY_ID=... \
//     -e SEED_FILE=results/seed-solo.json k6/production_mix.js
import http from 'k6/http';
import { check } from 'k6';
import { API_KEY, authHeaders, baseUrls, pickBaseUrl, login, jsonHeaders } from './lib/http.js';

export const WEIGHTS = { read: 50, list: 20, query: 10, write: 12, search: 6, bulk: 2 };
const OPS = Object.keys(WEIGHTS);

const RATE = Number(__ENV.RATE || 50);
const DURATION = __ENV.DURATION || '60s';
const WARMUP = __ENV.WARMUP || '30s';
const MAX_VUS = Number(__ENV.VUS || 50);
const BULK_ENTITY = __ENV.BULK_ENTITY || 'loadtest_bulk';
const BULK_QUERY_ID = __ENV.BULK_QUERY_ID;
const BULK_ROW_COUNT = Number(__ENV.BULK_ROW_COUNT || 100000);
const PROFILE_PASSWORD = __ENV.PROFILE_USER_PASSWORD || 'Loadtest-Profile-Pw1';
const MAX_SESSIONS = Number(__ENV.MAX_SESSIONS || 20);
const BULK_BATCH = Number(__ENV.BULK_BATCH || 10);

const SEED = __ENV.SEED_FILE ? JSON.parse(open(__ENV.SEED_FILE)) : null;
const WARM = WARMUP !== '0s' && WARMUP !== '0';

function scenario(op) {
  return {
    executor: 'constant-arrival-rate',
    rate: Math.max(1, Math.round((RATE * WEIGHTS[op]) / 100)),
    timeUnit: '1s',
    duration: DURATION,
    preAllocatedVUs: Math.max(1, Math.ceil((MAX_VUS * WEIGHTS[op]) / 100)),
    maxVUs: MAX_VUS,
    startTime: WARM ? WARMUP : '0s',
    exec: op,
    tags: { op, phase: 'measure' },
  };
}

const scenarios = Object.fromEntries(OPS.map((op) => [op, scenario(op)]));
if (WARM) {
  scenarios.warmup = {
    executor: 'constant-arrival-rate',
    rate: RATE,
    timeUnit: '1s',
    duration: WARMUP,
    preAllocatedVUs: Math.max(1, Math.ceil(MAX_VUS / 2)),
    maxVUs: MAX_VUS,
    exec: 'mixed',
    tags: { phase: 'warmup' },
  };
}

export const options = {
  scenarios,
  summaryTrendStats: ['p(50)', 'p(95)', 'p(99)', 'max'],
  // A threshold per class is what makes k6 report the class's own trend in
  // the summary; the limits themselves come from the SLO catalogue, not
  // from here.
  thresholds: Object.fromEntries(
    OPS.map((op) => [`http_req_duration{op:${op},phase:measure}`, ['max>=0']])
  ),
};

export function setup() {
  const baseUrl = baseUrls()[0];
  const accounts = [];
  if (SEED && Array.isArray(SEED.user_emails)) {
    for (const email of SEED.user_emails.slice(0, MAX_SESSIONS)) {
      accounts.push([email, PROFILE_PASSWORD]);
    }
  }
  if (accounts.length === 0 && !API_KEY) {
    accounts.push([__ENV.TEST_EMAIL, __ENV.TEST_PASSWORD]);
  }
  // AA1-T9: with an API key no one logs in; every request carries the key.
  const cookies = API_KEY ? [''] : accounts.map(([email, password]) => login(baseUrl, email, password));
  const res = http.post(
    `${baseUrl}/api/v1/query/execute`,
    JSON.stringify({ query_id: BULK_QUERY_ID, page: 1, page_size: 200 }),
    { headers: jsonHeaders(cookies[0]) }
  );
  if (res.status !== 200) {
    throw new Error(`setup: sampling record ids failed (${res.status}): ${res.body}`);
  }
  const ids = JSON.parse(res.body).data.records.map((r) => r.id);
  return { cookies, ids };
}

function cookieFor(data) {
  return data.cookies[(__VU - 1) % data.cookies.length];
}

function someSeq() {
  return Math.floor(Math.random() * BULK_ROW_COUNT * 0.9);
}

export function read(data) {
  const id = data.ids[(__VU + __ITER) % data.ids.length];
  const res = http.get(`${pickBaseUrl()}/api/v1/${BULK_ENTITY}/${id}`, {
    headers: authHeaders(cookieFor(data)),
    tags: { name: 'mix_read', op: 'read' },
  });
  check(res, { 'read 200': (r) => r.status === 200 });
}

export function list(data) {
  const res = http.post(
    `${pickBaseUrl()}/api/v1/query/execute`,
    JSON.stringify({
      query_id: BULK_QUERY_ID,
      page: 1,
      page_size: 50,
      order_by: 'seq',
      order_dir: 'asc',
      filters: [{ field: 'seq', op: 'gt', value: String(someSeq()) }],
    }),
    { headers: jsonHeaders(cookieFor(data)), tags: { name: 'mix_list', op: 'list' } }
  );
  check(res, { 'list 200': (r) => r.status === 200 });
}

export function query(data) {
  const from = someSeq();
  const res = http.post(
    `${pickBaseUrl()}/api/v1/query/execute`,
    JSON.stringify({
      query_id: BULK_QUERY_ID,
      page: 1,
      page_size: 100,
      order_by: 'seq',
      order_dir: 'desc',
      filters: [
        { field: 'seq', op: 'gt', value: String(from) },
        { field: 'seq', op: 'lt', value: String(from + 1000) },
      ],
    }),
    { headers: jsonHeaders(cookieFor(data)), tags: { name: 'mix_query', op: 'query' } }
  );
  check(res, { 'query 200': (r) => r.status === 200 });
}

export function write(data) {
  const seq = BULK_ROW_COUNT + Math.floor(Math.random() * 1e9);
  const res = http.post(
    `${pickBaseUrl()}/api/v1/${BULK_ENTITY}`,
    JSON.stringify({ title: `mix-write-${seq}`, seq }),
    { headers: jsonHeaders(cookieFor(data)), tags: { name: 'mix_write', op: 'write' } }
  );
  check(res, { 'write 201': (r) => r.status === 201 });
}

export function search(data) {
  const q = `bulk-row-${someSeq()}`;
  const res = http.get(
    `${pickBaseUrl()}/api/v1/search?q=${encodeURIComponent(q)}&page_size=10`,
    { headers: authHeaders(cookieFor(data)), tags: { name: 'mix_search', op: 'search' } }
  );
  check(res, { 'search 200': (r) => r.status === 200 });
}

export function bulk(data) {
  const base = BULK_ROW_COUNT + Math.floor(Math.random() * 1e9);
  const records = Array.from({ length: BULK_BATCH }, (_, i) => ({
    data: { title: `mix-bulk-${base + i}`, seq: base + i },
  }));
  const res = http.post(
    `${pickBaseUrl()}/api/v1/${BULK_ENTITY}/bulk`,
    JSON.stringify({ operation: 'create', records }),
    { headers: jsonHeaders(cookieFor(data)), tags: { name: 'mix_bulk', op: 'bulk' } }
  );
  check(res, { 'bulk accepted': (r) => r.status === 201 || r.status === 202 });
}

const BY_OP = { read, list, query, write, search, bulk };

// The warm-up window: one operation per iteration, picked by weight.
export function mixed(data) {
  let roll = Math.random() * 100;
  for (const op of OPS) {
    roll -= WEIGHTS[op];
    if (roll < 0) {
      BY_OP[op](data);
      return;
    }
  }
  read(data);
}
