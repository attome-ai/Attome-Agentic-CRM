// P1.8d step 10 — Load-test runtime DDL under representative concurrency.
//
// Unlike every other scenario in this directory (one request class per
// file), this one deliberately mixes TWO concurrent VU roles in a single
// k6 run, because the question this exercise answers is inherently about
// interaction between them:
//
//   ddl_toggle       — an admin session repeatedly PATCHing
//                       is_required true/false on one attribute
//                       (`loadtest_ddl.title`) of the seeded loadtest_ddl
//                       table. Every `is_required: true` request is
//                       scan-bearing (`classify_schema_change`'s
//                       `needs_full_scan = max_length.is_some() ||
//                       is_required`, provision/schema_change.rs) — at/under
//                       SCHEMA_CHANGE_INLINE_ROW_LIMIT (10,000 rows,
//                       admin.rs) it runs inline via `exec_ddl_locked`
//                       (`SET NOT NULL`, ACCESS EXCLUSIVE, full scan) on the
//                       request thread; over that threshold it queues
//                       `ApplySchemaChangePlan` instead and the terminal
//                       ALTER (still `exec_ddl_locked`) runs later on a
//                       worker. `is_required: false` alone is always cheap
//                       (`DROP NOT NULL`, metadata-only) — so this VU
//                       naturally alternates between the two statement
//                       classes exec_ddl_locked exists to guard
//                       (crates/engine/attome-metadata/src/provision/ddl.rs).
//                       Two DDL VUs by default deliberately race each other
//                       toward opposite target values on the SAME
//                       attribute/table — the actual conflicting-lock
//                       scenario exec_ddl_locked's lock_timeout+55P03-retry
//                       exists for, not a synthetic single-writer case.
//
//   concurrent_write — ordinary non-admin traffic (PATCH counter) against
//                       the SAME table, dedicated one loadtest_ddl row per
//                       VU (never touches `title`, so it never fails on the
//                       is_required toggle itself) — this is the "does one
//                       admin's routine schema click degrade everyone
//                       else's traffic against that table" question
//                       P-online-schema-change.md's problem statement
//                       (§1, "concrete failure shape") describes.
//
// concurrent_write runs for the whole DURATION; ddl_toggle starts
// DDL_START_OFFSET into that window and runs for DDL_DURATION, so the
// summary-export naturally has a write-only warm-up, a during-DDL window,
// and a write-only tail — see run-ddl-contention-exercise.ps1's
// pre/during/post split of the concurrent_write_duration trend.
//
// Both request classes get their own custom Trend (k6's aggregate
// http_req_duration would otherwise conflate the two very different
// latency shapes) — see run-ddl-contention-exercise.ps1 for what reads
// them back out of --summary-export.
import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';
import { Trend, Counter } from 'k6/metrics';
import { baseUrls, pickBaseUrl, login, jsonHeaders } from './lib/http.js';

const ADMIN_EMAIL = __ENV.ADMIN_EMAIL;
const ADMIN_PASSWORD = __ENV.ADMIN_PASSWORD;
const TEST_EMAIL = __ENV.TEST_EMAIL;
const TEST_PASSWORD = __ENV.TEST_PASSWORD;
const DDL_ENTITY = __ENV.DDL_ENTITY || 'loadtest_ddl';
const DDL_ENTITY_ID = __ENV.DDL_ENTITY_ID;
const DDL_FIELD_ID = __ENV.DDL_FIELD_ID;

const DURATION = __ENV.DURATION || '30s';
const DDL_START_OFFSET = __ENV.DDL_START_OFFSET || '5s';
const DDL_DURATION = __ENV.DDL_DURATION || '20s';

// Same file-not-env-var reasoning as mutating_write.js's MUT_RECORD_IDS_FILE
// — a ~500-UUID blob mangles somewhere in Windows/docker CLI argument
// passing when passed as a single -e value.
const DDL_RECORD_IDS = JSON.parse(open(__ENV.DDL_RECORD_IDS_FILE || '/work/.generated/ddl-record-ids.json'));

export const options = {
  scenarios: {
    concurrent_write: {
      executor: 'constant-vus',
      vus: Number(__ENV.WRITE_VUS || 10),
      duration: DURATION,
      exec: 'concurrentWrite',
    },
    ddl_toggle: {
      executor: 'constant-vus',
      vus: Number(__ENV.DDL_VUS || 2),
      duration: DDL_DURATION,
      startTime: DDL_START_OFFSET,
      exec: 'ddlToggle',
    },
  },
};

function parseDurationMs(s) {
  const m = /^(\d+(?:\.\d+)?)(ms|s|m)$/.exec(String(s).trim());
  if (!m) {
    throw new Error(`bad duration string (want e.g. "20s"): ${s}`);
  }
  const n = parseFloat(m[1]);
  if (m[2] === 'ms') return n;
  if (m[2] === 's') return n * 1000;
  return n * 60000;
}

const DDL_WINDOW_START_MS = parseDurationMs(DDL_START_OFFSET);
const DDL_WINDOW_END_MS = DDL_WINDOW_START_MS + parseDurationMs(DDL_DURATION);

export const ddlToggleDuration = new Trend('ddl_toggle_duration');
export const ddlToggleFailures = new Counter('ddl_toggle_failures');
// Split by whether the request landed inside the DDL window, not just one
// aggregate — the whole point of this exercise is the *difference* between
// baseline and during-DDL write latency, which a single blended trend would
// hide.
export const concurrentWriteDuration = new Trend('concurrent_write_duration');
export const concurrentWriteDuringDdl = new Trend('concurrent_write_duration_during_ddl');
export const concurrentWriteOutsideDdl = new Trend('concurrent_write_duration_outside_ddl');
export const concurrentWriteFailures = new Counter('concurrent_write_failures');

export function setup() {
  const baseUrl = baseUrls()[0];
  if (!DDL_ENTITY_ID || !DDL_FIELD_ID) {
    throw new Error('DDL_ENTITY_ID/DDL_FIELD_ID env vars are required — read them from seed-info.json\'s ddl_entity_id/ddl_field_id (run seed.ps1 first).');
  }
  if (DDL_RECORD_IDS.length === 0) {
    throw new Error('DDL_RECORD_IDS_FILE is empty — run seed.ps1 (it now provisions loadtest_ddl) first.');
  }
  const adminCookie = login(baseUrl, ADMIN_EMAIL, ADMIN_PASSWORD);
  const writeCookie = login(baseUrl, TEST_EMAIL, TEST_PASSWORD);
  return { adminCookie, writeCookie, ids: DDL_RECORD_IDS };
}

// Per-VU state (k6 runs a VU's exec function in a loop after its own init,
// module scope persists across iterations within a VU — same pattern as
// mutating_write.js).
let ddlRequired = false;

export function ddlToggle(data) {
  const baseUrl = pickBaseUrl();
  ddlRequired = !ddlRequired;
  const res = http.patch(
    `${baseUrl}/api/v1/admin/entities/${DDL_ENTITY_ID}/fields/${DDL_FIELD_ID}`,
    JSON.stringify({ is_required: ddlRequired }),
    {
      headers: jsonHeaders(data.adminCookie),
      tags: { name: 'schema_change_toggle' },
    }
  );
  ddlToggleDuration.add(res.timings.duration);
  const ok = check(res, { 'schema change toggle 200': (r) => r.status === 200 });
  if (!ok) {
    ddlToggleFailures.add(1);
    // Not treated as fatal — with DDL_VUS >= 2 racing opposite target
    // values on the same attribute, an occasional non-200 (e.g. a
    // concurrent-update conflict surfaced by the metadata write, not by
    // exec_ddl_locked itself) is an expected artifact of the race this
    // scenario deliberately creates, not a harness bug. The next iteration
    // just tries again.
  }
}

let recordId = null;
let rowVersion = null;

export function concurrentWrite(data) {
  const baseUrl = pickBaseUrl();
  if (recordId === null) {
    recordId = data.ids[(__VU - 1) % data.ids.length];
    const getRes = http.get(`${baseUrl}/api/v1/${DDL_ENTITY}/${recordId}`, {
      headers: { Cookie: data.writeCookie },
    });
    check(getRes, { 'initial read 200': (r) => r.status === 200 });
    rowVersion = JSON.parse(getRes.body).row_version;
  }

  const nowMs = exec.instance.currentTestRunDuration;
  const duringDdl = nowMs >= DDL_WINDOW_START_MS && nowMs <= DDL_WINDOW_END_MS;

  const res = http.patch(
    `${baseUrl}/api/v1/${DDL_ENTITY}/${recordId}`,
    JSON.stringify({ counter: Math.floor(Math.random() * 1e9) }),
    {
      headers: jsonHeaders(data.writeCookie, { 'If-Match': String(rowVersion) }),
      tags: { name: 'concurrent_write_during_ddl' },
    }
  );
  concurrentWriteDuration.add(res.timings.duration);
  (duringDdl ? concurrentWriteDuringDdl : concurrentWriteOutsideDdl).add(res.timings.duration);

  const ok = check(res, { 'patch 200': (r) => r.status === 200 });
  if (ok) {
    rowVersion = JSON.parse(res.body).row_version;
  } else {
    concurrentWriteFailures.add(1);
    // Same reset-and-retry reasoning as mutating_write.js: a 409 here would
    // mean a genuine row_version collision, not expected from this
    // scenario's own traffic (each VU owns a dedicated record) — but a
    // request-thread timeout while exec_ddl_locked's ACCESS EXCLUSIVE ALTER
    // holds the table (the exact risk this exercise measures) could also
    // surface here as a non-200; re-reading current state is the correct
    // recovery either way.
    recordId = null;
  }
}
