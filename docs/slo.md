# Service-level objectives

`observability/slo-catalogue.json` is the single source for every SLO class (roadmap AA13). The
`attome-slo` Prometheus rule group in `observability/alerts.yml`, the k6 thresholds in
`loadtest/k6/lib/slo.js` and the table below are generated from it:

```sh
attome slo generate          # rewrite the three outputs
attome slo generate --check  # exit 2 when any of them has drifted (a release-gate step)
```

Edit the catalogue, never the outputs. The numbers are the `solo` profile's; every class is a
`target` until a dated load-test result moves it to `measured_reference`. A class with no p99
(S8 search) has k6 thresholds but no burn-rate rules, which are built on the p99 bucket.

## Release evidence

`attome release --check --slo-evidence` also runs the load-test matrix at one node
(`loadtest/scripts/run-matrix.ps1 -NodeCounts 1 -RunTag release`, which needs Docker, PowerShell
and the load-test stack in `loadtest/README.md`) and writes `target/release-gate/slo-report.json`
and the release-notes fragment `slo.md`. On its own, from an existing run:

```sh
attome slo report loadtest/results/matrix-summary-release.json
```

Each class is met, missed (naming the percentile over target) or not measured. A class without a
measurement is never reported as met, and a missed class does not fail the gate: the notes simply
cannot claim it. The report is unsigned until the release signing key exists (AC4-T9).

## Targets

<!-- BEGIN GENERATED slo-table -->
| Class | Name | Route | p50 ms | p95 ms | p99 ms | Error objective | Status | k6 scenario |
|---|---|---|---|---|---|---|---|---|
| S1 | Authenticated read, no DB work | `GET /api/v1/admin/security/whoami` | 10 | 30 | 60 | 0.001 | target | `auth.js` |
| S2 | Login (password KDF) | `POST /api/v1/auth/login` | 150 | 300 | 500 | 0.001 | target | `auth.js` |
| S3 | Metadata read | `GET /api/v1/schema/{logicalname}` | 10 | 20 | 40 | 0.001 | target | `metadata_read.js` |
| S4 | Record read | `GET /api/v1/{entity}/{id}` | 15 | 40 | 100 | 0.001 | target | `crud_read.js` |
| S5 | List page, cursor, up to 100 rows | `POST /api/v1/query/execute` | 40 | 120 | 300 | 0.001 | target | `list_query.js` |
| S6 | Mutating write | `PATCH /api/v1/{entity}/{id}` | 30 | 100 | 200 | 0.001 | target | `mutating_write.js` |
| S7 | Notification poll | `POST /api/v1/notification/poll` | 15 | 40 | 100 | 0.001 | target | `notification_poll.js` |
| S8 | Search (lexical) | `GET /api/v1/search` | 60 | 150 | — | 0.001 | target | `search.js` |
<!-- END GENERATED slo-table -->
