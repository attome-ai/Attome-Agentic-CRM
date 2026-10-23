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
cannot claim it. The gate reports are signed when the release is tagged ([release signing](release-signing.md)).

## Targets

<!-- BEGIN GENERATED slo-table -->
| Class | Name | Measures | p50 ms | p95 ms | p99 ms | Objective | 5xx objective | Status | k6 scenario |
|---|---|---|---|---|---|---|---|---|---|
| S1 | Authenticated read, no DB work | `GET /api/v1/admin/security/whoami` | 10 | 30 | 60 | — | 0.001 | target | `auth.js` |
| S2 | Login (password KDF) | `POST /api/v1/auth/login` | 150 | 300 | 500 | — | 0.001 | target | `auth.js` |
| S3 | Metadata read | `GET /api/v1/schema/{logicalname}` | 10 | 20 | 40 | — | 0.001 | target | `metadata_read.js` |
| S4 | Record read | `GET /api/v1/{entity}/{id}` | 15 | 40 | 100 | — | 0.001 | target | `crud_read.js` |
| S5 | List page, cursor, up to 100 rows | `POST /api/v1/query/execute` | 40 | 120 | 300 | — | 0.001 | target | `list_query.js` |
| S6 | Mutating write | `PATCH /api/v1/{entity}/{id}` | 30 | 100 | 200 | — | 0.001 | target | `mutating_write.js` |
| S7 | Notification poll | `POST /api/v1/notification/poll` | 15 | 40 | 100 | — | 0.001 | target | `notification_poll.js` |
| S8 | Search (lexical) | `GET /api/v1/search` | 60 | 150 | — | — | 0.001 | target | `search.js` |
| S9 | MCP tool call | `POST /api/v1/mcp` | 100 | 300 | 1000 | — | 0.001 | target | — |
| S10 | Job queue delay | `apalis_oldest_pending_age_seconds` | — | — | — | queue=interactive ≤ 30 seconds; queue=batch ≤ 300 seconds | — | target | — |
| S11 | Change-feed lag | `events_subscription_lag_max` | — | — | — | all ≤ 1000 rows | — | target | — |
| S12 | Frontend vitals | the browser (Core Web Vitals) | — | — | — | LCP p75 ≤ 2500 ms, INP p75 ≤ 200 ms, CLS p75 ≤ 0.1 | — | target | — |
<!-- END GENERATED slo-table -->

## Monthly reports and fast burns

On the first day of each month, from 02:00 UTC, the server writes the month just finished as one
report: per class, its good and failed (5xx) requests, error ratio and the share of its budget left,
from the built-in metrics store. Read them at `GET /api/v1/admin/slo/reports` (newest first) and
`GET /api/v1/admin/slo/reports/{YYYY-MM}`. Latency is not in the report: the release gate's load
tests and Prometheus judge latency targets.

Every five minutes the server checks each class for a fast burn: more than 14.4 times its allowed
failure share over both the last hour and the last five minutes (with at least 20 requests in the
five minutes), the same rule as `observability/alerts.yml`. A burning class notifies every
administrator, at most once per class per hour.

## Latency regressions after an upgrade

The built-in store keeps the request-duration histogram of the nine routes the `http` classes
measure (S1 to S9), summed across status codes, so a p95 per class can be read back from it; every
other histogram keeps only its sum and count. Once a day the server compares each class's p95 since
the last upgrade (the first start of the version now running, from the deploy history; at most the
last seven days) with the seven days before the upgrade. When p95 rose more than 20% with at least
1,000 requests in each window, the built-in alert `PerfRegression:<class>` fires (severity
`warning`) and is sent like any built-in alert; it resolves when the class no longer regresses or a
week after the upgrade.
