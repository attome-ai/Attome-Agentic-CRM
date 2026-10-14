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
