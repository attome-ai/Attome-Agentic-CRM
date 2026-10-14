// Request class: Mutating write (with lock).
// guidelines §14.5 budget: P50 <50ms, P99 <200ms (measured today, at 50-way
// concurrency against a single-instance dev-shaped Postgres, not this N-node
// matrix: sync path ~470-530ms P50, cutover path ~200-210ms P50 — see
// audit_throughput_load.rs / D-045. This scenario exercises the same PATCH
// path over real HTTP + N app nodes rather than in-process oneshot calls.)
//
// Each VU owns one dedicated loadtest_mut record (seed.ps1 creates
// MutRecordCount of them, comfortably more than any VU count this harness
// runs) so PATCHes never collide on row_version/If-Match across VUs. Module
// scope state persists across iterations within a VU (k6 runs a VU's
// default() in a loop after its own init), so the first iteration reads the
// current row_version and every iteration after reuses whatever the
// previous PATCH response returned.
import http from 'k6/http';
import { check } from 'k6';
import { baseUrls, pickBaseUrl, login, jsonHeaders } from './lib/http.js';
import { thresholdsFor } from './lib/slo.js';

export const options = {
  vus: Number(__ENV.VUS || 10),
  duration: __ENV.DURATION || '30s',
  // Generated from observability/slo-catalogue.json (attome slo generate).
  thresholds: thresholdsFor('S6'),
};

const TEST_EMAIL = __ENV.TEST_EMAIL;
const TEST_PASSWORD = __ENV.TEST_PASSWORD;
const MUT_ENTITY = __ENV.MUT_ENTITY || 'loadtest_mut';

// A ~300-UUID JSON blob as a single -e env var value was getting mangled
// somewhere in Windows/docker CLI argument passing (k6 saw invalid JSON);
// reading it as a file inside the mounted loadtest dir sidesteps that.
// k6's open() only works at init/global scope, not inside setup().
const MUT_IDS = JSON.parse(open(__ENV.MUT_RECORD_IDS_FILE || '/work/.generated/mut-record-ids.json'));

export function setup() {
  const baseUrl = baseUrls()[0];
  const cookie = login(baseUrl, TEST_EMAIL, TEST_PASSWORD);
  if (MUT_IDS.length === 0) {
    throw new Error('MUT_RECORD_IDS_FILE is empty — run-matrix.ps1 must write seed-info.json\'s mut_record_ids there first');
  }
  return { cookie, ids: MUT_IDS };
}

let recordId = null;
let rowVersion = null;

export default function (data) {
  const baseUrl = pickBaseUrl();
  if (recordId === null) {
    recordId = data.ids[(__VU - 1) % data.ids.length];
    const getRes = http.get(`${baseUrl}/api/v1/${MUT_ENTITY}/${recordId}`, {
      headers: { Cookie: data.cookie },
    });
    check(getRes, { 'initial read 200': (r) => r.status === 200 });
    rowVersion = JSON.parse(getRes.body).row_version;
  }

  const res = http.patch(
    `${baseUrl}/api/v1/${MUT_ENTITY}/${recordId}`,
    JSON.stringify({ counter: Math.floor(Math.random() * 1e9) }),
    {
      // jsonHeaders, not a hand-rolled object: this PATCH is the exact case
      // `csrf_protect` fails closed on (cookie auth, unsafe method, no
      // browser-supplied Sec-Fetch-Site) — it 403'd rather than measuring the
      // write path from P-cookie-csrf-hardening until TODO-014's pre-run pass.
      headers: jsonHeaders(data.cookie, { 'If-Match': String(rowVersion) }),
      tags: { name: 'mutating_write', slo_class: 'S6' },
    }
  );
  const ok = check(res, { 'patch 200': (r) => r.status === 200 });
  if (ok) {
    rowVersion = JSON.parse(res.body).row_version;
  } else {
    // A 409 here would mean two VUs collided on the same record — a bug in
    // the record-assignment above, not a finding about the platform. Reset
    // so the next iteration re-reads the current version rather than
    // spinning on a stale one.
    recordId = null;
  }
}
