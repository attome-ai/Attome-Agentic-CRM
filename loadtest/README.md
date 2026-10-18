# Load-testing harness (P1.8d)

Measures guidelines §14.5's latency budgets with real numbers instead of
"TARGET — unenforced". Full design: `attome-base/document_v2/docs/detailed-plans/P1.8d-load-testing.md`.

**Steps 1-4** (the reusable harness + an N=1/4/12 matrix) ran 2026-07-19 —
see `document_v2/docs/general/LOADTEST-2026-07-19.md`. **Steps 5-6** (the P1.12 20+-node
pgbouncer exercise, the P1.13 chainer re-run) ran 2026-07-21 — see
`document_v2/docs/general/LOADTEST-2026-07-21.md`. **Step 7** (non-gating CI job) shipped
2026-07-21 as `.github/workflows/loadtest-smoke.yml`. All of it ran on this
same single Windows dev machine, not the dedicated production-shaped host
the plan calls for — every results doc carries that caveat explicitly; treat
relative shape (does X change with Y) as more trustworthy than absolute
milliseconds, and re-run on a real host before quoting numbers to a
customer.

**2026-07-30 addition (code-only, not run — see the "Not yet executed" note
below):** `run-p112-exercise.ps1` gained `-ChainerEnabled` so the P1.12
(connection-capacity) and P1.13 (queue-saturation/chainer) exercises can
finally run combined at N=20+, and a new `run-soak-test.ps1` adds a sustained-
duration soak test (long-lived node set, back-to-back k6 windows, a
connection-count time series, and a first-window-vs-last-window drift
verdict) — nothing prior held load for longer than 30s. This environment has
no Docker daemon/Postgres/built release binary to execute either against;
both are unexecuted code, TODO on a real host (see
`document_v2/docs/detailed-plans/P1.8d-load-testing.md`'s addendum).

**2026-08-04 addition (step 10, code-only, not run):** `exec_ddl_locked`
(`crates/engine/attome-metadata/src/provision/ddl.rs`) — the `lock_timeout`+bounded-
55P03-retry executor every provisioning ALTER routes through, including
`evolve_attribute_schema` since P-online-schema-change Step 1 — had never
been load-tested under real concurrency, only reasoned about. `seed.ps1`
gained a third dedicated entity (`loadtest_ddl`) and a new
`run-ddl-contention-exercise.ps1` + `k6/schema_change_ddl.js` mix admin
schema-toggle traffic (racing another DDL VU toward the opposite
`is_required` value on the same attribute — genuine conflicting-lock
contention) with ordinary concurrent writes against the same table, then
report DDL-request latency, concurrent-write latency split
before/during/after the DDL window, peak lock-blocked Postgres sessions, and
a direct count of `exec_ddl_locked`'s own retry-warning log lines. Same "no
Docker daemon/Postgres/built release binary here" gap as the 2026-07-30
addition — unexecuted code, TODO on a real host. While wiring this in, found
that `P-cookie-csrf-hardening`'s `csrf_protect` middleware (added after this
harness's mutating scenarios were first written) rejects a cookie-
authenticated POST/PUT/PATCH/DELETE that carries neither `Sec-Fetch-Site` nor
an allow-listed `Origin` — `security.csrf_enforce` defaults `true` and
`common.ps1`'s generated config never overrides it, so `mutating_write.js`
and `notification_poll.js`'s existing PATCH/POST calls likely now 403 if run
today. `schema_change_ddl.js` sends `Sec-Fetch-Site: same-origin` (via the
new `lib/http.js::jsonHeaders` helper) so it isn't affected, but the two
older scenarios were left as-is — fixing them is a small, separate, one-line-
per-call-site change out of this addition's own scope; flagged here rather
than fixed silently, per the "known deviations" convention below.

**2026-08-12 addition (TODO-014 pre-run pass — rehearsed, not yet the
qualifying run):** the harness had drifted badly out of sync with the platform
and **could not complete a single run**; six defects, each of which alone would
have produced either no result or a worthless one. The first three were found
by reading the harness against the platform as it stands today rather than as
it stood in July; the last three only surfaced by actually running it. (1) The
CSRF finding above was real and wider than it said —
`seed.ps1` and the two `query/execute` scenarios were broken too; see the
"Known deviations" entry, now marked FIXED. (2) `-ChainerEnabled` only ever
flipped a config flag: since D-316 the chainer is a **separate process**
(`attome audit-chainer`) and the sole writer of
`audit_header`, and nothing here started it, so a chainer-on run never
drained `audit_ingest` — harmless in a 15s window, decisive in a 10-minute
one, where the backlog crosses `audit.ingest_backlog_threshold` and the
mutation gate starts answering 503. `Start-LoadtestNodes` now starts and
supervises it, `Stop-LoadtestNodes` stops it, and `run-matrix.ps1` samples the
backlog per scenario. (3) Node startup passed `-WindowStyle`, which PowerShell
7 rejects on Linux — the harness could not have started a single node on the
dedicated host it is written for. (4) `New-LoadtestConfig` still emitted
`rate_limit.per_endpoint_limits`, which `AppConfig` now rejects as a
`DeprecatedField`: **no node could boot at all**, on any platform, until this
was replaced with D-145's `categories` shape. (5) `auth.registration_mode`
defaults to `disabled` (D-128), so `seed.ps1`'s two `/api/v1/auth/register`
calls 403'd and the seed died at its first step; the generated config now sets
`public` explicitly, safe only because this config is per-run and pinned to the
throwaway `attome_loadtest` database. (6) This k6 image exports a Rate metric
as `{passes, fails, value}` with **no `rate` key** — the failure-rate column
added in this same pass initially read `.rate`, got `$null`, and rounded it to
a clean `0.0`. Measured and corrected: it now reads `.value`, records the
absolute `failed_requests` count beside it, and warns instead of reporting a
zero when neither key is present.

`run-matrix.ps1` also records `checks_failed` per row. Together with
`failed_rate`/`failed_requests` this is what stops defect (1) from publishing
as clean percentiles: a 403 has a perfectly good latency.

**Rehearsal evidence (2026-08-12, Windows dev box, NOT a qualifying run):**
2,000-row seed, N=1, 5 VUs, 15-20s windows. All six scenarios completed with
0 failed requests — including 4,253 `query/execute` POSTs, 1,334 PATCHes and
3,637 notification POSTs that would every one have been a 403 before fix (1) —
and the chainer-on pass showed `audit_chainer` actually draining
(`event_count` 101/221/481 batches, lag ≤1s, empty stderr). These numbers are
**not** evidence about platform performance: single node, 5 VUs, 20 seconds, on
a laptop running a dozen other containers. They are evidence that the harness
works. See "The production-shape run (TODO-014)" below for the runbook.

## Safety — read before running anything here

Every script requires `$env:LOADTEST_ACK = "yes"` and refuses to run
otherwise. This is **not** the shared dev stack (`docker-compose.dev.yml`,
Postgres @5555/`attomedb`/`attome_dev`) and never touches it — this harness's
own `docker-compose.loadtest.yml` stands up an isolated Postgres @5556
(`attome_loadtest`) and Dragonfly @6380. Never point `common.ps1`'s
`$script:LoadtestDbName` anywhere that doesn't contain the substring
"loadtest" — that's the guard against ever running this against a real
deployment by accident.

## Environment this was actually run against

**Not** the dedicated, non-dev, production-shaped host the plan calls for —
this pass ran on a single Windows dev machine via Docker Desktop, because
that's what was available this session. Every number in the results doc
carries that caveat explicitly; treat the *relative* shape (does latency grow
with concurrency, does N=12 nodes change anything) as more trustworthy than
the *absolute* milliseconds. Re-run on a real dedicated host before quoting
these numbers to a customer.

k6 isn't installed natively — it runs via the official `grafana/k6` Docker
image. Docker Desktop for Windows containers can't reach the host's
`localhost`, so `run-matrix.ps1` points k6 at `host.docker.internal` while
this machine's own app-node processes bind `localhost`/`0.0.0.0` directly (no
container involved for the server itself — building N copies of the Rust
binary in Docker for a local exercise isn't worth the extra layer). A real
Linux dedicated host would run k6 natively and use `localhost` throughout;
adjust `run-matrix.ps1`'s `$baseUrlsDocker` construction if/when that happens.

"N app nodes" here means N copies of the same release binary bound to
sequential ports (7900, 7901, ...), all pointed at the one shared loadtest
Postgres/Dragonfly — not a real load balancer. Since every node is stateless
and identical (the platform's hard multi-node rule), each k6 VU pinning to
one node for its lifetime is equivalent to a load balancer's sticky
connection for this exercise; there's no nginx/reverse-proxy layer to stand
up just to prove that. The P1.12 pgbouncer/replica exercise (step 5, out of
scope here) is the one that actually needs a real topology in front.

## Reference profiles

`profiles.json` names the reference machine and dataset for each deployment profile (`solo`,
`team`, `ha`, `scale`): CPU and memory, a cloud example, records per entity, users, roles and the
concurrency levels a run steps through. The seeder and the run matrix read it. Every size is marked
`"status": "proposal"`: these are targets to test, not measurements, until the AA2 runs replace
them with measured numbers.

## Layout

```
docker-compose.loadtest.yml   isolated Postgres :5556 + Dragonfly :6380
docker-compose.pgbouncer.yml  P1.8d step 5 overlay: pgbouncer-loadtest :6433, fronting
                               postgres-loadtest only (see pgbouncer/pgbouncer.ini's
                               header for how this differs from the real ../pgbouncer/
                               deployment recipe) — bring up with
                               `docker compose -f docker-compose.loadtest.yml -f docker-compose.pgbouncer.yml up -d --build pgbouncer-loadtest`
pgbouncer/                    Dockerfile + pgbouncer.ini for the overlay above
scripts/
  common.ps1                 shared: safety guard, config generation, node start/stop/wait.
                              New-LoadtestConfig/Start-LoadtestNodes take -Topology
                              (direct|pgbouncer) and -ChainerEnabled (audit.chainer_enabled)
  start-nodes.ps1             starts N server processes (same -Topology/-ChainerEnabled)
  stop-nodes.ps1              stops them
  seed.ps1                    two-phase bootstrap admin + entities/fields/data/grants
  run-matrix.ps1               runs every k6 scenario at N=1/4/12 (or -NodeCounts/-Scenarios),
                                writes results/matrix-summary<-RunTag>.json. Accepts
                                -Topology/-ChainerEnabled/-RunTag for step 5/6 re-runs.
  run-p112-exercise.ps1         P1.8d step 5 — runs crud_read/list_query/mutating_write at
                                N=20 (default) direct vs pgbouncer, sampling Postgres
                                connection count under load; writes
                                results/p112-exercise-{raw,comparison}<-chainer>.json.
                                Accepts -ChainerEnabled (new, unexecuted) to combine with
                                the P1.13 cutover path in one N=20+ pass.
  run-soak-test.ps1             new, unexecuted — sustained-duration soak: one long-lived
                                node set (-NodeCount, -Topology, -ChainerEnabled), N
                                back-to-back k6 windows (-Windows x -WindowMinutes) against
                                one scenario (-Scenario), a Postgres connection-count time
                                series sampled throughout, and a first-quarter-vs-last-
                                quarter drift verdict (connection growth, P99 growth, error
                                rate). Writes results/<RunTag>-<scenario>-summary.json.
  bloat-measurement.ps1         P-db-maintenance step 1 — pure Postgres (psql+pgbench, no
                                 app nodes) storage-parameter A/B: stock vs.
                                 provision_table's actual reloptions under sustained write
                                 churn, snapshotting pg_stat_user_tables throughout. See
                                 sql/bloat_setup.sql and document_v2/docs/general/BLOAT-MEASUREMENT-2026-07-21.md.
  run-ddl-contention-exercise.ps1  P1.8d step 10 — new, unexecuted: runs
                                schema_change_ddl.js, samples
                                Get-PgLoadtestBlockedSessionCount throughout, and greps
                                node logs for exec_ddl_locked's own 55P03-retry warning.
                                Writes results/ddl-contention-{summary,k6-summary}.json.
k6/
  lib/http.js                 shared: base-URL picking, login, jsonHeaders (CSRF-safe
                               mutating-request headers, added for schema_change_ddl.js —
                               see the 2026-08-04 addition note above)
  auth.js                     login + cookie-validated read (whoami)
  metadata_read.js             GET /api/v1/schema/{entity} — see the caveat inside the file
  crud_read.js                 GET /api/v1/{entity}/{id}
  list_query.js                 POST /api/v1/query/execute (filtered/sorted/paginated)
  mutating_write.js             PATCH with If-Match/row_version
  notification_poll.js          POST /api/v1/notification/poll
  schema_change_ddl.js          new, unexecuted — mixed ddl_toggle (admin PATCH
                                 is_required on loadtest_ddl.title, racing another DDL VU)
                                 + concurrent_write (ordinary PATCH counter) scenarios in
                                 one run; see the file's own header for the full design.
.generated/, logs/, results/    all gitignored — regenerated every run
```

## Running it

```powershell
$env:LOADTEST_ACK = "yes"

# 1. Bring up isolated infra (once; `down -v` between from-scratch reseeds)
docker compose -f docker-compose.loadtest.yml up -d

# 2. Seed: bootstrap admin, test entities + data, a stored query, a
#    non-admin test user with real grants, and the profile's users and
#    roles (AA1-T2). -Profile (default solo) sizes loadtest_bulk from
#    profiles.json's records_per_entity; -RowCount overrides it. Each
#    500-record chunk is posted by the next profile user, so ownership is
#    spread across them. The summary lands in results/seed-<profile>.json,
#    and a re-run whose summary matches the API's count skips seeding.
./scripts/seed.ps1 -Profile solo -DryRun   # the plan, no HTTP call
./scripts/seed.ps1 -RowCount 5000          # a quick dev-laptop seed
# ./scripts/seed.ps1 -Profile solo         # 1,000,000 rows: hours through the bulk API

# 3. Run the matrix (N=1/4/12, all 6 scenarios, 30s each ~= 18min total)
./scripts/run-matrix.ps1

# Ad-hoc: start/stop nodes by hand, e.g. to poke around at a given N
./scripts/start-nodes.ps1 -Count 4
./scripts/stop-nodes.ps1

# 4. Step 6 — re-run the matrix with the P1.13 cutover path on, tagged so it
#    doesn't overwrite the step-4 baseline files
./scripts/run-matrix.ps1 -ChainerEnabled -RunTag chainer

# 5. Step 5 — P1.12 exercise: N=20 direct vs N=20 through pgbouncer
docker compose -f docker-compose.loadtest.yml -f docker-compose.pgbouncer.yml up -d --build pgbouncer-loadtest
./scripts/run-p112-exercise.ps1
# Combined P1.12+P1.13 pass (new, unexecuted — the one combination never yet measured):
# ./scripts/run-p112-exercise.ps1 -ChainerEnabled

# 6. Soak test (new, unexecuted) — 30min default; scale -Windows/-WindowMinutes
#    for a real certification pass (e.g. -Windows 24 -WindowMinutes 15 for 6h)
./scripts/run-soak-test.ps1

# 7. Step 10 — DDL-contention exercise (new, unexecuted): admin schema-toggle
#    traffic concurrent with ordinary writes against the same table. Default
#    -DdlRowCount (seed.ps1, 500) stays under the 10,000-row
#    SCHEMA_CHANGE_INLINE_ROW_LIMIT, exercising exec_ddl_locked's INLINE path
#    only; pass -DdlRowCount 20000 (or higher) to seed.ps1 to also exercise
#    the ApplySchemaChangePlan ASYNC job path (P-online-schema-change).
./scripts/run-ddl-contention-exercise.ps1
```

Results land in `results/matrix-summary<-RunTag>.json` (one row per
scenario x N) and per-run raw k6 summaries in
`results/<scenario>-n<N><-RunTag>.json`. The P1.12 exercise writes
`results/p112-exercise-{raw,comparison}<-chainer>.json` instead, and the soak
test writes `results/<RunTag>-<scenario>-summary.json`. The step 10
DDL-contention exercise writes `results/ddl-contention-summary.json` (the
interpreted rows/verdict) and `results/ddl-contention-k6-summary.json` (the
raw k6 `--summary-export`). Turning any of this
into `document_v2/docs/LOADTEST-<date>.md` (guidelines' closing-checklist format,
same pattern as `AUDIT-<date>.md`) is a manual step — the numbers need a
human reading against §14.5's budgets and this environment's caveats, not
just a table dump.

## The production-shaped mix (AA1-T3)

`k6/production_mix.js` runs six weighted scenarios at `RATE` requests a second (default 50): read 50%,
list 20%, query 10%, write 12%, search 6%, bulk 2%. Every request is tagged `op`, so the summary has
p50/p95/p99 per class (`http_req_duration{op:read,phase:measure}` and so on). It logs in as the
profile's users named in `results/seed-<profile>.json` (`user_emails`, from `seed.ps1 -Profile`), up
to `MAX_SESSIONS` (20), in rotation. Without a seed file it runs as the test user.

`k6/mcp_tools.js` is agent traffic: an MCP session per VU, then `tools/call` for `record.get` and
`search.records`, tagged `op: mcp`. It runs as `MCP_EMAIL`, or the admin by default.

Runs are warm by default: the first `WARMUP` (30 s) is tagged `phase: warmup` and left out of the
per-class numbers. `run-matrix.ps1 -Cold` restarts the nodes and empties the cache before each
scenario and runs with no warm-up:

```powershell
./scripts/run-matrix.ps1 -Scenarios production_mix,mcp_tools -NodeCounts 1 -Profile solo
./scripts/run-matrix.ps1 -Scenarios production_mix -NodeCounts 1 -Cold
```

## The production-shape run (TODO-014) — runbook for a dedicated Linux host

Both existing results docs were produced on a Windows dev machine via Docker
Desktop and say so. TODO-014 is the qualifying re-run: a dedicated Linux host,
≥100k-row seed, ≥100 VUs, ≥10 min windows, chainer on **and** off, published as
`document_v2/docs/LOADTEST-<date>.md` with the same honesty as the existing two.

### Host prerequisites

- A Linux host running **nothing else** — a co-tenant container stack is the
  single biggest reason the existing numbers aren't quotable. Record its CPU
  model/core count, RAM, and disk type; the results doc's environment section
  needs them.
- Docker Engine (for the isolated Postgres/Dragonfly stack), a Rust toolchain,
  **PowerShell 7** (`pwsh` — these scripts are PowerShell, not bash), `curl`,
  and **k6 on `PATH`**. On Linux the harness shells out to a native `k6` and
  addresses nodes as `localhost`; the `grafana/k6` container is Windows-only
  (`common.ps1`'s `$script:IsWindowsHost`).
- Host ports **5556** and **6380** free. On a machine that also runs this
  repo's root `docker-compose.yml --profile test`, they collide:
  `attome-postgres-test`/`attome-redis-test` bind exactly those ports. Stop
  that profile first.
- Disk for a 100k-row seed plus its audit trail — the run writes one
  `audit_ingest` row per mutation, and a 10-minute × 100-VU write window
  produces a lot of them.

### The run

```powershell
$env:LOADTEST_ACK = "yes"
docker compose -f docker-compose.loadtest.yml up -d          # from loadtest/
cargo build --release -p attome

# Seed at the qualifying size (this is the slow part; minutes, not seconds)
pwsh ./scripts/seed.ps1 -RowCount 100000

# Pass A — all six scenarios at N=4, 100 VUs, 10min each. Sync path first,
# then the D-316 cutover path. ~1h per invocation, ~2h total.
pwsh ./scripts/run-matrix.ps1 -NodeCounts 4 -Vus 100 -Duration 10m -RunTag prodshape-sync
pwsh ./scripts/run-matrix.ps1 -NodeCounts 4 -Vus 100 -Duration 10m -ChainerEnabled -RunTag prodshape-chainer

# Pass B — the node-count comparison the chainer finding rests on, one
# scenario only so it stays affordable: ~1h total.
pwsh ./scripts/run-matrix.ps1 -NodeCounts 1,4,12 -Scenarios mutating_write -Vus 100 -Duration 10m -RunTag prodshape-sync-mut
pwsh ./scripts/run-matrix.ps1 -NodeCounts 1,4,12 -Scenarios mutating_write -Vus 100 -Duration 10m -ChainerEnabled -RunTag prodshape-chainer-mut
```

Running the whole default matrix (6 scenarios × N=1/4/12) at 10-minute windows
is ~3h **per** pass, ~6h for both — do that only if the host is free for a day.
Passes A and B above are the smallest shape that still satisfies TODO-014's
stated minimums and preserves the chainer-vs-node-count comparison.

### Before trusting the output

- **`failed_requests` must be 0** on every row of every
  `matrix-summary-*.json` (and `failed_rate` alongside it must be present, not
  `null`). They are recorded per row precisely because a scenario that 403s or
  503s every request still produces respectable-looking percentiles — they are
  the latency of the rejection. A non-zero count means the run measured
  nothing; `run-matrix.ps1` prints a warning per affected row. Note the
  non-zero path itself has not been exercised end to end — the rehearsal only
  ever produced clean runs — so treat a warning as a prompt to open the raw k6
  export, not as a calibrated signal.
- **`audit_ingest_backlog` must not climb** across the chainer-on rows. The
  chainer is a separate process (D-316) that `Start-LoadtestNodes` now starts
  alongside the nodes; a backlog that grows over a 10-minute window means it
  isn't keeping up with the write rate, and the deployment was heading for the
  `audit.ingest_backlog_threshold` 503 gate rather than running steadily.
- `loadtest/logs/chainer.err.log` should be empty of exits. The binary
  hard-exits on a bad audit-stage combination, and the harness fails the run
  if it dies within 3s of start — but a later crash only shows up here.

### What to hand back for the results doc

`loadtest/results/*.json` (all four `matrix-summary-prodshape-*.json` plus the
per-scenario raw exports), the host facts listed above, `k6 version`,
`psql -c 'show max_connections'` (and any Postgres tuning applied — the
existing runs used the stock `postgres:18` image with no overrides), and
`loadtest/logs/chainer.out.log`. `document_v2/docs/LOADTEST-<date>.md` is written by
hand from those against §14.5's budgets (P50 <50ms / P99 <200ms), the same as
the existing two docs — a table dump is not the deliverable.

## Known deviations from the plan doc (documented, not silent)

- **Row count**: the plan asks for a 1M-row entity; `seed.ps1` defaults to a
  smaller `-RowCount` for a single dev machine's actual run this session.
  The harness itself is unchanged — pass `-RowCount 1000000` on a real host.
- **Metadata read**: `GET /api/v1/schema/{logicalname}` queries
  `core_entity_info`/`core_attribute_info` directly, not the arc-swap
  `EntityMetaRegistry` §14.5's "cache hit" framing describes — there's no
  dedicated HTTP endpoint for that internal cache today. Flagged in
  `k6/metadata_read.js` and the results doc, not silently relabeled.
- **No load balancer**: see the environment section above.
- **Soak test / combined P1.12+P1.13 exercise**: added 2026-07-30 as harness
  code only — this environment has no Docker daemon, no Postgres, and no
  built release binary to actually execute either `run-soak-test.ps1` or
  `run-p112-exercise.ps1 -ChainerEnabled` against. Neither has ever produced a
  real result; treat both as unverified until run on a real host (dedicated,
  per the plan's existing ask — not this dev-machine caveat again, a genuinely
  separate TODO). `run-soak-test.ps1`'s `http_req_failed` field extraction
  (`.value` vs `.rate`) was flagged as an unconfirmed guess — **the guess was
  right**: the 2026-08-12 rehearsal read a real export and a Rate metric is
  `{passes, fails, value}` with no `.rate` key at all. `run-soak-test.ps1`
  needs no change on this point; `run-matrix.ps1`, which guessed `.rate`, did.
- **DDL-contention exercise**: added 2026-08-04 as harness code only, same
  "no Docker daemon/Postgres/built release binary here" gap as the soak
  test/combined exercise above — never produced a real result.
  `run-ddl-contention-exercise.ps1`'s custom-Trend `.count` field read is an
  unconfirmed guess at k6's `--summary-export` shape for a *user-defined*
  Trend metric specifically (every prior script here only ever read the
  built-in `http_req_duration`), same disclosed-guess posture as the soak
  test's `.value`/`.rate` guess.
- **CSRF headers on existing scenarios — FIXED 2026-08-11 (TODO-014 pre-run
  pass)**: the 2026-08-04 finding was real and understated. `csrf_protect`
  rejects *any* cookie-authenticated unsafe-method request, so it took down
  more than the two mutating scenarios it named: `crud_read.js`'s setup and
  `list_query.js`'s hot path both POST to `/api/v1/query/execute` (reads, but
  still POSTs), and `seed.ps1`'s `Invoke-Api` — every entity, field, record,
  and grant call the seed makes — carried no `Sec-Fetch-Site` either, so the
  harness would have failed at `/api/v1/auth/register` before k6 ever ran.
  All five now send `Sec-Fetch-Site: same-origin`, the header a real
  same-origin browser tab sends. This was never observed as a failure because
  nothing has run this harness since the middleware landed.
- **`pgbouncer/userlist.txt` untracked, 2026-08-07 (incomplete — breaks the
  step-5 build as of this commit, TODO)**: this file was committed with the
  md5 hash of `loadtest-throwaway-pw` (itself already cleartext in
  `docker-compose.loadtest.yml`) while the real deployment's
  `../pgbouncer/userlist.txt` is gitignored — flagged as a policy
  inconsistency (not a new exposure: same throwaway secret, same repo,
  isolated stack). Fixed by adding it to the root `.gitignore` and
  `git rm --cached`, mirroring `../pgbouncer/`'s convention. Unlike
  `../pgbouncer/Dockerfile` (which COPYs a real, gitignored `userlist.txt`
  that every deployer is told to create from `userlist.txt.example`),
  `pgbouncer/Dockerfile` here has no `.example` template and no doc telling
  a fresh clone to recreate the file — so `docker compose -f
  docker-compose.loadtest.yml -f docker-compose.pgbouncer.yml up -d --build
  pgbouncer-loadtest` (step 5 above) will fail on a clean checkout after
  this change ("no such file or directory" on the Dockerfile's `COPY
  userlist.txt`). Not fixed in this session (code-only environment, no
  Docker daemon to verify the build failure or a fix against). Needed to
  actually close this out — pick one:
  1. Add `pgbouncer/userlist.txt.example` (same one-line md5 entry, since
     this is a throwaway non-secret value, not a real credential needing
     `SCRAM-SHA-256$...` treatment) and a step-5 doc note to copy it before
     building; matches `../pgbouncer/`'s pattern exactly, or
  2. Revert the gitignore/untrack and instead document the policy exception
     inline (a comment at the top of `pgbouncer/userlist.txt` and/or here)
     — simpler, since the value is disposable and already public, and
     avoids adding a template file for a secret that isn't actually secret.
  Whichever is picked, verify the step-5 `--build pgbouncer-loadtest` command
  actually succeeds afterward — unverified in this session either way.
