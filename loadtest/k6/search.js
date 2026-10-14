// Request class: search (TODO-027).
//
// P-search-and-retrieval §11 budgets, as k6 thresholds. The existing harness
// has ZERO thresholds (FINAL-ENTERPRISE H-5) — every prior scenario reports
// numbers a human has to compare against a table by eye, which means a
// regression is caught only if someone remembers to look. These gate.
//
// ## Why this script refuses to run as an admin
//
// `build_predicate` returns `None` for an admin or a Global-level grant
// (`rls.rs`), and `PolymorphicVisibility::push` then emits **nothing at all**.
// So an admin-run search benchmark measures a query the product never
// executes for the users the permission design exists to protect: no
// `array_position` map lookup, no organization fast tier, no
// `record_share` EXISTS, no extra planner work. It is fast, it is
// reproducible, and it is meaningless.
//
// The natural failure here is not malice, it is convenience: an admin cookie
// is the one every other scenario already has. So `setup()` **asserts** the
// principal is narrowed by probing an admin-only route and requiring a
// refusal. A run that cannot prove it is narrowed aborts rather than
// publishing a number nobody can trust.
//
// ## The share-only caller (TODO-053)
//
// `SEARCH_SHARE_ONLY_EMAIL` runs the same lexical queries as a principal whose
// visibility comes entirely from `record_share` rows. That caller gets
// no organization fast tier at all, so the standard predicate re-checks the
// share table once per candidate the text scan produces — §8.1's worst case,
// and the population the whole permission design exists to protect. It is
// budgeted against the SAME §11 lexical numbers as everyone else, deliberately:
// a separate, looser threshold for the narrowed caller would institutionalize
// the exact gap TODO-053 closes. Set the variable to include the scenario; it
// is skipped rather than failed when unset, because seeding a share-only
// principal is a deployment-specific step.
//
// ## Why it asserts results are non-empty
//
// A search that matches nothing is extremely fast. A misconfigured corpus, an
// unseeded index, a normalization mismatch, or a permission filter that
// excludes everything all produce a beautiful p95 and a broken product. Every
// iteration checks that the query it issued actually returned rows, and the
// check rate is itself a threshold — so an empty index fails the run instead
// of winning it.

import http from 'k6/http';
import { check, fail } from 'k6';
import { Rate } from 'k6/metrics';
import { baseUrls, pickBaseUrl, login } from './lib/http.js';

const TEST_EMAIL = __ENV.TEST_EMAIL;
const TEST_PASSWORD = __ENV.TEST_PASSWORD;

// Terms that must match the seeded corpus. Override per deployment.
const EXACT_KEYS = (__ENV.SEARCH_EXACT_KEYS || 'loadtest-key-1,loadtest-key-2').split(',');
const PREFIXES = (__ENV.SEARCH_PREFIXES || 'loadt,loadte,loadtes').split(',');
const TERMS = (__ENV.SEARCH_TERMS || 'loadtest record,bulk title,seq value').split(',');
// Optional. When unset the share-only scenario does not run at all.
const SHARE_ONLY_EMAIL = __ENV.SEARCH_SHARE_ONLY_EMAIL || '';
const SHARE_ONLY_PASSWORD = __ENV.SEARCH_SHARE_ONLY_PASSWORD || TEST_PASSWORD;

// Wall-clock allowance over the server-side budget.
//
// §11's numbers are server-side; k6 measures the round trip. On loopback the
// difference is under a millisecond, so the default is 0 — but a run against a
// remote host must set this to that host's RTT rather than quietly failing
// every threshold, or (worse) quietly relaxing them all in the file and
// leaving the next reader unable to tell which numbers were measured against
// which budget.
const RTT = Number(__ENV.RTT_ALLOWANCE_MS || 0);
const p = (ms) => ms + RTT;

const emptyResults = new Rate('search_empty_results');

export const options = {
  scenarios: {
    // Separate scenarios rather than one mixed function: §11 budgets a route
    // at a time, and averaging a 5 ms exact hit with a 120 ms hybrid produces
    // a number that satisfies neither budget and describes nothing.
    exact: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS_EXACT || 5),
      duration: __ENV.DURATION || '60s',
      exec: 'exactKey',
      tags: { name: 'search_exact' },
    },
    typeahead: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS_TYPEAHEAD || 20),
      duration: __ENV.DURATION || '60s',
      exec: 'typeahead',
      tags: { name: 'search_typeahead' },
    },
    lexical: {
      executor: 'constant-vus',
      vus: Number(__ENV.VUS_LEXICAL || 10),
      duration: __ENV.DURATION || '60s',
      exec: 'lexical',
      tags: { name: 'search_lexical' },
    },
    // Zero VUs when the variable is unset, which k6 accepts as "do not run"
    // — a skipped scenario, rather than a failed run, for a deployment that
    // has not seeded a share-only principal.
    shareOnly: {
      executor: 'constant-vus',
      vus: SHARE_ONLY_EMAIL ? Number(__ENV.VUS_SHARE_ONLY || 10) : 0,
      duration: __ENV.DURATION || '60s',
      exec: 'shareOnly',
      tags: { name: 'search_share_only' },
    },
  },
  thresholds: {
    // Same budget as `search_lexical`, on purpose. See the header.
    'http_req_duration{name:search_share_only}': [`p(50)<${p(60)}`, `p(95)<${p(150)}`],
    // P-search-and-retrieval §11, verbatim. `abortOnFail` on the empty-result
    // and error rates: continuing a 60-second run whose corpus is empty wastes
    // the window and produces a results file that looks like a pass.
    'http_req_duration{name:search_exact}': [`p(50)<${p(5)}`, `p(95)<${p(15)}`],
    'http_req_duration{name:search_typeahead}': [`p(50)<${p(20)}`, `p(95)<${p(50)}`],
    'http_req_duration{name:search_lexical}': [`p(50)<${p(60)}`, `p(95)<${p(150)}`],
    'http_req_failed{name:search_exact}': ['rate<0.001'],
    'http_req_failed{name:search_typeahead}': ['rate<0.001'],
    'http_req_failed{name:search_lexical}': ['rate<0.001'],
    // A search matching nothing is fast and worthless. This is the guard that
    // stops an unseeded index from reporting a record-setting p95.
    search_empty_results: [{ threshold: 'rate<0.01', abortOnFail: true }],
  },
};

export function setup() {
  const baseUrl = baseUrls()[0];
  const cookie = login(baseUrl, TEST_EMAIL, TEST_PASSWORD);

  // **The guard this whole scenario exists for.** An admin skips the entire
  // visibility fragment, so an admin-run number is not a measurement of the
  // product. Probing an admin-only route and requiring a refusal is the only
  // check available from outside — there is no "am I an admin" endpoint, and
  // adding one to satisfy a load test would be the wrong direction.
  const probe = http.get(`${baseUrl}/api/v1/admin/entities`, {
    headers: { Cookie: cookie },
    tags: { name: 'admin_probe' },
  });
  if (probe.status === 200) {
    fail(
      `TEST_EMAIL=${TEST_EMAIL} is an admin (or holds a Global grant): ` +
        `/api/v1/admin/entities returned 200. build_predicate returns None for ` +
        `such a caller, so this run would measure a query with NO permission ` +
        `filter at all — the opposite of what §15's first risk row asks for. ` +
        `Seed a narrowed principal (seed.ps1 -SearchNarrowedUser) and re-run.`,
    );
  }
  if (probe.status !== 403 && probe.status !== 401) {
    fail(`admin probe returned an unexpected ${probe.status}: ${probe.body}`);
  }

  // Prove the corpus is reachable for THIS principal before spending the run.
  // A narrowed user with no grant on the indexed entities sees zero rows for
  // everything, which is a legitimate product behaviour and a useless
  // benchmark.
  const warmup = search(baseUrl, cookie, TERMS[0], 'warmup');
  if (warmup.status !== 200) {
    fail(`warm-up search failed (${warmup.status}): ${warmup.body}`);
  }
  if (countItems(warmup) === 0) {
    fail(
      `warm-up search for "${TERMS[0]}" returned no results for the narrowed ` +
        `principal. Either the index is empty or this user has no grant on the ` +
        `indexed entities — both produce excellent latency and no information.`,
    );
  }

  // The share-only principal, if one was configured. Same admin guard: a
  // share-only caller who is secretly an admin measures nothing at all.
  let shareCookie = null;
  if (SHARE_ONLY_EMAIL) {
    shareCookie = login(baseUrl, SHARE_ONLY_EMAIL, SHARE_ONLY_PASSWORD);
    const shareProbe = http.get(`${baseUrl}/api/v1/admin/entities`, {
      headers: { Cookie: shareCookie },
      tags: { name: 'admin_probe' },
    });
    if (shareProbe.status === 200) {
      fail(`SEARCH_SHARE_ONLY_EMAIL=${SHARE_ONLY_EMAIL} is an admin`);
    }
    const shareWarmup = search(baseUrl, shareCookie, TERMS[0], 'warmup');
    if (countItems(shareWarmup) === 0) {
      fail(
        `the share-only principal reaches no records for "${TERMS[0]}". The ` +
          `scenario would then measure an empty result set, which is fast and ` +
          `says nothing about the predicate cost it exists to measure.`,
      );
    }
  }

  return { cookie, shareCookie };
}

function search(baseUrl, cookie, q, tag) {
  return http.get(`${baseUrl}/api/v1/search?q=${encodeURIComponent(q)}&page_size=10`, {
    headers: { Cookie: cookie },
    tags: { name: tag },
  });
}

function countItems(res) {
  try {
    return (JSON.parse(res.body).items || []).length;
  } catch {
    return 0;
  }
}

/** Records whether this response was usefully non-empty, and returns it. */
function assess(res, label) {
  const ok = check(res, { [`${label} 200`]: (r) => r.status === 200 });
  const items = ok ? countItems(res) : 0;
  emptyResults.add(items === 0);
  return items;
}

export function exactKey(data) {
  const baseUrl = pickBaseUrl();
  const key = EXACT_KEYS[(__VU + __ITER) % EXACT_KEYS.length];
  assess(search(baseUrl, data.cookie, key, 'search_exact'), 'exact');
}

export function typeahead(data) {
  const baseUrl = pickBaseUrl();
  // Walk the prefixes in order, as a real user's keystrokes arrive. Picking a
  // prefix at random would give every iteration the same cache temperature,
  // which is not what typing looks like.
  const prefix = PREFIXES[__ITER % PREFIXES.length];
  assess(search(baseUrl, data.cookie, prefix, 'search_typeahead'), 'typeahead');
}

export function lexical(data) {
  const baseUrl = pickBaseUrl();
  const term = TERMS[(__VU + __ITER) % TERMS.length];
  assess(search(baseUrl, data.cookie, term, 'search_lexical'), 'lexical');
}

export function shareOnly(data) {
  const baseUrl = pickBaseUrl();
  const term = TERMS[(__VU + __ITER) % TERMS.length];
  assess(search(baseUrl, data.shareCookie, term, 'search_share_only'), 'share-only');
}
