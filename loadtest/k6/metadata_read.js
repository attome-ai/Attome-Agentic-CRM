// Request class: Metadata read.
// guidelines §14.5 budget: P50 <5ms, P99 <20ms.
//
// CAVEAT (read before trusting this number): GET /api/v1/schema/{logicalname}
// is the only standalone "read entity metadata" HTTP endpoint that exists —
// but it queries core_entity_info/core_attribute_info directly on every call
// (attome-api/src/schema.rs), not the arc-swap EntityMetaRegistry the
// "cache hit" framing in §14.5 actually describes (that registry is read
// internally by entity CRUD's resolve_entity, with no dedicated endpoint of
// its own). This scenario therefore measures a small, indexed metadata DB
// read, not a true L1 arc-swap cache-hit path — flagged here rather than
// silently mislabeled; see the LOADTEST results doc's findings section.
import http from 'k6/http';
import { check } from 'k6';
import { baseUrls, pickBaseUrl, login } from './lib/http.js';

export const options = {
  vus: Number(__ENV.VUS || 20),
  duration: __ENV.DURATION || '30s',
};

const ADMIN_EMAIL = __ENV.ADMIN_EMAIL;
const ADMIN_PASSWORD = __ENV.ADMIN_PASSWORD;
const WIDE_ENTITY = __ENV.WIDE_ENTITY || 'loadtest_wide';

export function setup() {
  // setup() runs once, outside any VU context (__VU is 0 there) — pick a
  // fixed base URL rather than pickBaseUrl()'s per-VU logic. The session
  // cookie itself is valid against every node (shared jwt_secret + Redis),
  // so which node issued it doesn't matter.
  const baseUrl = baseUrls()[0];
  const cookie = login(baseUrl, ADMIN_EMAIL, ADMIN_PASSWORD);
  return { cookie };
}

export default function (data) {
  const baseUrl = pickBaseUrl();
  const res = http.get(`${baseUrl}/api/v1/schema/${WIDE_ENTITY}`, {
    headers: { Cookie: data.cookie },
    tags: { name: 'schema_read' },
  });
  check(res, { 'schema 200': (r) => r.status === 200 });
}
