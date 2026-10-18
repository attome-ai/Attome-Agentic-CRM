# Testing

## `attome test`

```sh
attome test                          # unit tests of the whole workspace
attome test --changed                # only the crates (and web libraries) the working tree touches
attome test --tier db --changed      # their integration targets, against a throwaway database
attome test --tier security          # the fixed access-control suite
attome test --release                # every tier, unscoped; a missing service fails instead of skipping
attome test --dry-run --changed      # print the commands, run nothing
attome test --coverage               # line coverage per crate (needs cargo-llvm-cov)
```

Tiers: `unit`, `db`, `contract`, `security`, `browser`, `all`. A tier that needs PostgreSQL starts a
throwaway PostgreSQL (pgvector) and Redis in Docker on ports 5556 and 6380 when `DATABASE_URL` is
not set; `--no-stack` skips that. Logs go to `target/attome-test/<time>/`.

A failing test is rerun once on its own. One that then passes is reported FLAKY (and listed in
`target/attome-test/flaky.json`); the run still fails. `tests/quarantine.json` skips a test while it
is being fixed:

```json
{ "tests": [ { "target": "attome-api::lib", "name": "module::test_name",
               "owner": "Name", "until": "2026-11-30", "reason": "why, and the issue" } ] }
```

An entry past its `until` date, or without an owner, fails the run.

## Tags and the coverage map

Tag a test in the comment lines just above it:

```rust
// feature: A1, A2            feature ids from docs/features.json
// op: createRecord           API operations it calls (operationId, or `POST /api/v1/x`)
// negative: createRecord     operations whose refusal path it checks
// regression: D-123          the defect or decision it guards
#[tokio::test]
async fn creating_without_a_name_is_refused() { /* ... */ }
```

The same comments work above `it(`/`test(` in `.spec.ts` files. `attome test map` writes
`target/coverage-map/map.json` and `index.html`: per feature, its tests by tier (a feature with none
is a gap), and per API operation, whether a test tags it and, for a mutating one, whether a
`negative:` test does. `attome test map --scan-only` prints the test count per tier.

Tests that need PostgreSQL, Redis or an object store skip without them, printing `SKIP`; the
`ATTOME_TEST_REQUIRE_DB`, `ATTOME_TEST_REQUIRE_REDIS` and `ATTOME_TEST_REQUIRE_S3` switches (set
by `--release` and by CI) turn a skip into a failure.

## Harness

Integration tests build the whole API in process with `attome_testapp::TestApp` (crate
`crates/engine/attome-testapp`): one shared app per test binary, a seeded administrator, and
`request`/`request_as`/`request_with` helpers that send through the full middleware stack.

```rust
let Some(app) = TestApp::start().await else { return }; // no test database: SKIP
let (status, body) = app.request(Method::POST, "/api/v1/account", Some(json!({ "name": "Acme" }))).await;
let user = attome_testapp::seed_user(app.db(), "plain").await;    // no privileges
let (status, _) = app.request_as(&user.cookie, Method::GET, "/api/v1/admin/settings", None).await;
```

- **Records for any entity:** `attome_testapp::fixtures::record_for(&meta, seed, token)` returns a
  body with every required attribute set, deterministic in `seed` (the generated CRUD and
  permission tests use it).
- **Faults:** `attome_testapp::faults::FakeS3::start(FaultPlan { fail_on_call: Some(1), .. })` is an
  object store that fails on demand (point `storage.s3_endpoint` at `fake.url()` through
  `TestApp::start_with`); `faults::dead_redis_url()` names a Redis nothing listens on.
- **A model server:** `attome_inference::testing::FakeModelServer::start(vec![json(body)])` (feature
  `test-support`) answers OpenAI-compatible requests in order and records them
  (`fake.requests()`); set the inference base URL to `fake.base_url()`. No test calls a real model
  provider.

Every change that adds behaviour adds the test that proves it, tagged as above: a new mutating
route ships with its `negative:` test and a fix with its `regression:` test.

## Customer tests

A customer test is a builder's own check of their configuration, written without code: records to
start from (`given`), writes to make (`when`, optionally as a role with `as_role`) and what must
hold afterwards (`expect`: an attribute's value, or an error a step must meet: `validation`,
`forbidden`, `conflict`, `not_found`).

```json
{ "as_role": "Sales Rep",
  "given":  [{ "entity": "account", "ref": "a", "record": { "name": "Acme" } }],
  "when":   [{ "op": "delete", "entity": "account", "ref": "a" }],
  "expect": [{ "error": "forbidden" }] }
```

A run applies the steps through the same record engine a real write uses, inside one transaction
that is always rolled back: it never leaves records behind. Write and run them on the
**Customer tests** admin screen, or through `/api/v1/admin/customer-tests` (list, create, PATCH
with `If-Match`, delete, `/{id}/run`, `/{id}/runs`, `/run-all`, and `/export` and `/import` of an
`attome-customer-tests/v1` document, which carries tests only; configuration travels as
changesets).

Mark a test **blocking** and turn on the deployment setting
`customer_tests.require_pass_before_publish` to make every changeset apply, model publish and
blueprint apply run the blocking tests first; a failure refuses the publish with
`422 customer_tests_failed`, naming the tests in `tests`.
