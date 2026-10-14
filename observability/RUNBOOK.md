# Alert runbook

One section per rule in [`alerts.yml`](alerts.yml). Each rule's `runbook_url` points at its
section here, and its `owner` label names who is paged (M86 O2). The four `Email*` rules link to
[`deploy/email/README.md`](../deploy/email/README.md) instead.

The rule's own comment in `alerts.yml` carries the metric's source and known blind spots. Read it
when a section here says "see the rule". A request id in the logs is the thread from an alert to
the failing request (`/prod-observability`'s incident workflow).

## Owners and escalation

| `owner` | Covers | Escalate to |
|---|---|---|
| `platform` | HTTP and SLO burn rates, Redis/Dragonfly, job queues, object storage, disk, capability gate, portal grant drift | the platform on-call |
| `db` | Postgres pools, partitions, backups, WAL, replicas | the database on-call |
| `security` | audit chain, security rejections, coordination-store durability, S2S access log, portal logins and access-cache freshness | the security on-call; treat as a possible incident until ruled out |
| `integration` | outbound email, event-bus delivery | the integration owner (`deploy/email/README.md`) |

A deployment maps each owner to a receiver in its Alertmanager config. The repo ships none.

---

## HTTP

### HighHttpErrorRate

More than 2% of requests returned 5xx over 5 minutes. Group the failing requests by path in the
request-id-tagged logs. One path points to a code or data defect. Every path at once points to a
dependency, so check `RedisDown`, `DbPoolNearExhaustion` and `ObjectStorageDown`, which fire for
the common causes.

## SLOs (burn rate)

`observability/slo-catalogue.json` is the single source for the SLO classes; `docs/slo.md` has the
generated table and `attome slo generate` writes the `attome-slo` group from it (edit the
catalogue, never the group). For each `http` class the group records the share of requests slower
than the class p99 budget and the share that returned 5xx, over 5m, 30m, 1h and 6h. The objectives
are 99% within budget and under 0.1% 5xx over 30 days. Every burn alert carries `slo_class`,
`slo_route` (method and matched path) and `slo_p99_ms`. The recorded series are
`attome:slo_latency_bad:ratio_rate<window>` and `attome:slo_errors:ratio_rate<window>`; graph them
by `slo_class` to see when the burn started.

A `gauge` class (S10 job queue delay, S11 change-feed lag) records
`attome:slo_gauge_bad:ratio_rate5m` per objective: the share of one-minute samples over the
ceiling in the last five minutes, labelled `slo_class`, `slo_metric`, `slo_series` and
`slo_objective`. A `browser` class (S12) is a target only; nothing here measures it.

### SloLatencyBurnFast

More than 14.4% of the class's requests were over budget in both the last hour and the last 5
minutes, with more than 1 request/s. That rate spends the 30-day budget in about two days, so this
pages. Find what changed: a release, a config or metadata change (a new view, stored query or
field on a hot entity), or load. Then read the slow requests' request ids in the logs
(`/prod-observability` "Slow requests"). S1 and S2 point at the middleware (Redis latency:
`RedisCoordinationLatencyHigh`; for S2, the password KDF). S4, S5 and S6 point at the database
(`DbPoolNearExhaustion`, `ReplicaLagHigh`, a query plan). S6 also slows when the audit chainer
backs up (`AuditChainerLagHigh`).

### SloLatencyBurnSlow

More than 6% over budget in both the last 6 hours and the last 30 minutes, with more than 1
request/s. The 30-day budget runs out in about five days. File a ticket, not a page. Work it the
same way as `SloLatencyBurnFast`, starting from the time the 6h ratio began to climb.

### SloErrorBurnFast

More than 1.44% of the class's requests returned 5xx in both the last hour and the last 5 minutes,
with more than 1 request/s. Group the failures by status and request id in the logs. If
`HighHttpErrorRate` is also firing, the fault is platform-wide, so check dependencies first
(`RedisDown`, `DbPoolNearExhaustion`, `ObjectStorageDown`). If it fires alone, the class's own
code path or data is failing.

### SloErrorBurnSlow

More than 0.6% 5xx in both the last 6 hours and the last 30 minutes. It is a ticket. A small,
steady 5xx share on one route is usually one bad record or one caller's malformed request that
reaches a 500 path, so find the common request shape in the logs.

### SloLatencyBucketMissing

The class is serving traffic, but the request histogram has no `le` bucket at its p99 budget, so
its latency burn alerts cannot measure anything. Since M86 O1 the build exports an explicit bucket at
every class budget (`attome_server::metrics::HTTP_DURATION_BUCKETS`, pinned by `attome-server`'s
`the_duration_histogram_has_every_slo_bucket` test), so this firing means the bucket list and the
§1.1 budgets have drifted apart: add the missing boundary. Check the exporter output
with `curl <node>:9464/metrics | grep 'axum_http_requests_duration_seconds_bucket' | grep -o 'le="[^"]*"' | sort -u`.

### SloGaugeOverObjective

A gauge SLO class has been over its objective for most of the last five minutes, for 15 minutes.
`slo_series` names the series and `slo_objective` the ceiling.

- **S10, job queue delay** (`apalis_oldest_pending_age_seconds`): the oldest ready job has waited
  longer than the lane allows (30 s interactive, 300 s batch). Check that a worker is running
  (`apalis_worker_last_seen_age_seconds`), the backlog (`apalis_pending_jobs`) and whether one job kind
  floods the lane; add a worker or fix the stuck kind.
- **S11, change-feed lag** (`events_subscription_lag_max`): an active subscription is more than
  1000 feed rows behind. `EventDeliveryBacklogGrowing` usually fires with it; follow that entry.

## Redis / Dragonfly

### RedisDown

The general Redis pool fails its ping. S2S and session checks fail closed (D-027), so treat this
as a full outage. Check the container (`docker compose ps`, its logs), then network reachability
from the app node. `/scale-out-ops` covers failover.

### RedisCoordinationDown

The coordination pool (`cache.roles.coordination`) fails its ping. S2S nonce and rate-limit
checks, the HTTP rate limiter and the idempotency gate all fail closed, so expect S2S 401/500 and
429/500 on ordinary requests. On a deployment that has not split the role, this fires together
with `RedisDown` for the same cause. Recovery is the same as `RedisDown`, on the coordination
endpoint.

### RedisCoordinationLatencyHigh

The coordination ping is above 150 ms (warning) or 300 ms (critical). The fail-closed timeout on
the controls it gates is 300 ms, so at critical, real requests are already being refused. Check
host CPU and network between the app and the store, and a large or blocking command in the
store's slow log. Two rules share this name on purpose: one per severity.

### RedisCoordinationMemoryHigh

The coordination store is above 80% of `maxmemory`. It runs `noeviction`, so at 100% its writes
fail and the controls behind it refuse requests. Find what grew (the profiler keyspace is the
usual runaway), then raise the ceiling or delete deliberately.

### RedisCoordinationNoMemoryCeiling

`maxmemory` is unset on the coordination store, so it grows until the host kills it (BCA-F4), and
`RedisCoordinationMemoryHigh` cannot fire. Set `maxmemory` on the coordination service and
restart it.

## Database

### DbPoolNearExhaustion

More than 90% of the primary pool's connections are busy for 5 minutes. Look for a slow-query
regression first (`pg_stat_activity` for long-running statements, `/prod-observability` "Slow
requests"), and a transaction held across I/O. If the load is real, raise
`database.connection_number` within Postgres's own `max_connections`, or add pgbouncer
(`/scale-out-ops`).

### PartitionedTableDeadTupleRatioHigh

One of the four partitioned audit and access-log tables is more than 20% dead tuples for 30
minutes. Check `last_autovacuum` on its partitions. If autovacuum runs but loses ground, the
storage parameters need tuning against real load (see the rule and `/prod-observability`
"Audit, bloat, partitions").

### PartitionBloatMetricMissing

No `db_bloat_total_bytes` sample in an hour. Either the refresh loop is failing (server logs:
"metrics refresh: partition bloat query failed") or a partitioned table is missing. Confirm the
`EnsureAuditPartitions` job still runs (`JobScheduleStale` would also fire).

### BackupTooOld

No successful pgbackrest backup in 26 hours. On a single primary, read
`/var/log/pgbackrest-cron.log` in `postgres-primary` and confirm `/etc/cron.d/pgbackrest` exists.
On Patroni, find the leader first, then read the same log and `/etc/cron.d/pgbackrest-patroni`
there. Check `attome_backup_repo_reachable`, because an unreadable repo raises this same alert.
Procedure: `deploy/backup/README.md`.

### WalArchiveLagHigh

`pg_stat_archiver.last_archived_time` is more than 15 minutes old. On a single primary this is
sampled at each cron tick, so the stall may be older than it looks. Look for "archive_command
failed" in the primary's logs, and for repo credentials that were rotated (`deploy/backup/README.md`).
On Patroni, a 0 reading is ambiguous: check `attome_backup_monitor_pg_reachable`.

### ReplicaLagHigh

The read replica is more than 30 s behind. The sticky-primary pin (about 5 s) only protects a
user's own recent writes, so other readers see stale data. Check the replica's host and logs
(`docker compose logs postgres-replica`). A replica lag that never fires may mean
`database.readonly` does not point at a real standby (see the rule).

### ReplicaLagCritical

The same lag, sustained 5 minutes. Route reads back to the primary until the replica recovers:
set `database.readonly.host`/`.port` to null (or to the primary) and restart (D-155).
`database.replica_max_lag_secs` is reserved and does not route anything yet. `/scale-out-ops`
covers the replica.

## Jobs

### ApalisBacklogGrowing

More than 100 jobs pending on the fast queue for 10 minutes. The worker is down or saturated.
Check `ApalisWorkerStale`, the worker's logs and `jobs.worker_concurrency`.

### ApalisBatchBacklogGrowing

More than 1,000 jobs pending on the batch queue for 10 minutes. A large import or rewrap can do
this legitimately. If `ApalisWorkerStale{queue="batch"}` is not firing and the backlog is
falling, wait. Otherwise check `jobs.batch_worker_concurrency` and the batch worker's logs.

### ApalisDeadLetterGrowing

Jobs exhausted their retries and sit `Killed`, and nothing retries them. List them with
`GET /api/v1/admin/jobs/dead-letter?queue=<queue>`; `last_error` names the failure. Fix the
cause, then replay (`POST /api/v1/admin/jobs/{id}/replay`) or discard
(`DELETE /api/v1/admin/jobs/{id}`, audited).

### ApalisWorkerStale

No heartbeat from a queue's worker for more than 90 s, so that queue has stopped. Restart the
worker service (`docker compose ps`, its logs). apalis reclaims orphaned rows once a worker of
that queue is back.

### ApalisWorkerNeverSeen

No worker of the fast or batch queue has ever registered. Background jobs, including
verification and password-reset email, file scanning and retention, are not running at all.
Usually the `worker` service was never started (a `worker-split` deployment without that
profile), or `jobs.run_worker_inline` is `false` with no standalone worker.

### PlatformJobFailures

A job kind (the `kind` label) fails repeatedly for 15 minutes. Read the worker logs for that kind.
A payload this build cannot decode settles as `Killed`, so check `ApalisDeadLetterGrowing` too.

### ApalisOldestPendingAgeHigh

The oldest pending job in a queue is older than 15 minutes. The worker is not draining it: check
the worker is running and whether one slow kind holds all its concurrency.

### JobScheduleStale

A periodic sweep (the `name` label) has not succeeded in two hours. Read the worker logs for that
schedule. A schedule that never succeeded emits no sample, so check `job_schedule` if a
sweep seems silent. The two-hour floor is generic: narrow it per schedule in the deployment's
overlay.

### WorkflowTriggerDeadLettered

An entity change event failed workflow dispatch at least 5 times over at least 15 minutes, so
the dispatcher skipped it to keep later events flowing. The workflows it matched did not start,
and any Wait-for-Event it matched did not resume. List them with
`GET /api/v1/workflow/trigger-dead-letters` (newest first; `last_error` names the failure, and the
worker logs carry the same `event_id`). Fix the cause, then replay
(`POST /api/v1/workflow/trigger-dead-letters/{event_id}/replay`): it starts only what the event
missed, never a second instance, and removes the dead letter. It never resumes a Wait-for-Event:
replay cannot tell a wait pending at the change from a later one, so handle a stuck wait on its
instance. A replay that still fails keeps it and is audited as failed. Discard one you have handled another way with
`DELETE /api/v1/workflow/trigger-dead-letters/{event_id}`. Both are audited.

## Object storage and files

### ObjectStorageDown

The configured `storage.s3_endpoint` fails its HEAD probe for 2 minutes. Uploads, downloads and
reads of stored objects fail. Check RustFS or MinIO health and connectivity from the node. The
capability gate (`CapabilityUnavailable`) will be refusing object-storage routes.

### StoragePresignFailures

Signing presigned URLs is failing, and each failure is a 500 on an upload or download route.
Check the S3 credentials (rotation applies on restart, D-549), the configured expiry range, and
the object key being signed.

### ObjectStorageProbeLatencyHigh

The storage probe takes over 1.5 s against a 2 s hard timeout. One more slowdown trips the
object-storage capability gate. Check storage host load and the network path.

### UploadScanBacklogStale

An upload has waited more than 15 minutes for its virus scan. Confirm `storage.clamd_address`
points at a live clamd (the compose `clamav` profile) and the worker is running. Unscanned
uploads are rejected by the 24-hour sweep.

## Host

### DiskSpaceLow

A filesystem is below 10% free (needs a host node_exporter). Postgres, RustFS and the audit
partitions write locally. Find what grew (WAL, backups, logs, object data) and free or extend
space before `DiskSpaceCritical`.

### DiskSpaceCritical

Below 5% free. Postgres refuses writes when its data filesystem fills, so treat this as an
imminent outage: free space now.

## Capability gate (D-344)

### CapabilityUnavailable

A capability (the `capability` label) is unavailable on at least one node, and routes that need
it answer 503 `capability_unavailable`. Ordinary CRUD is unaffected and the node stays in
rotation. `GET /health/dependencies` (administrator API key) shows the live probe and what the gate enforces. Fix the
underlying dependency; this alert is not about the node.

### CapabilityRejectingTraffic

The same outage, with callers being refused. Fix the dependency. If the probe itself is proven
wrong, `capability.enforcement_enabled = false` stops the rejections and keeps the reporting.

## Security and audit

### AuditChainerLagHigh

The audit chainer is more than 5 minutes behind. Events are captured in `audit_ingest` but not
chained, and there is no automatic fallback (D-029). Check the `audit_chainer` service is running
and its logs. Left alone, the backlog crosses `audit.ingest_backlog_threshold` and writes start
returning 503. `/prod-observability` "Audit, bloat, partitions" covers the chain.

### SecurityAnomalyRateHigh

A security rejection reason (the `reason` label) sustained above 5/s for 5 minutes: S2S replay or
rate limit, HTTP 429, CSRF 403, a revoked token, or a portal gate. Read the request-id-tagged logs
next to the rejections for the source IP or client. A misconfigured integration replaying a
revoked token looks identical to an attack at this signal, so identify the client before acting.

### RedisPersistenceDisabled

The coordination store has no persistence policy, so a restart drops in-window S2S replay nonces
and unflushed access-log entries. Set `--snapshot_cron` on Dragonfly, or `save`/`appendonly` on
Redis, and restart. Dragonfly still loses up to one snapshot interval.

### RedisSnapshotStale

Persistence is configured but no snapshot has completed in 10 minutes. Check disk space and
permissions on the store's `--dir` volume, and
`redis_coordination_persistence_changes_since_save` for how much is unsaved.

### S2sAccessLogBacklogGrowing

More than 1,000 S2S access-log entries are waiting in Redis, unflushed, for 10 minutes. Each one
is an accepted machine request whose only record is in Redis. Look for "s2s access-log flush"
errors in the server logs and check the Postgres write path. If `RedisPersistenceDisabled` is
also firing, a restart now loses those records.

## Portal (web-portal-users §5)

The portal's rejection reasons (`portal_origin`, `portal_budget`, `portal_cidr`, `portal_epoch`,
`portal_host`) are `security_rejection_total` reasons, so `SecurityAnomalyRateHigh` already covers
them by reason. The rules below read the portal's own counters in
`crates/engine/attome-portal/src/telemetry.rs`. No label carries a portal, user or address.

### PortalLoginFailureRatioHigh

More than half of portal password logins ended `bad_credentials` or `locked` over 15 minutes,
across at least 20 attempts. Look at the `portal_request` spans and warn logs. Many attempts on a
few accounts, or from a few sources, is credential stuffing: tighten the portal's CIDR allow-list
or budget and check `SecurityAnomalyRateHigh{reason="portal_budget"}`. A jump across every account
right after a release or a portal config change is a login defect or a broken credential import,
so compare against the last change.

### PortalGrantDrift

A portal access grant's condition no longer renders (an unknown operator, or a field that drifted
or was removed), so the portal users under it see nothing through that grant. The warn log next
to each increment names the role and the grant. Fix the condition through the portal admin API.
A null `value_ref` is not drift and never fires this.

### PortalCacheInvalidationFailed

A portal admin write committed, but bumping `attome-portal:access-version:global` on the cache Redis
failed. Other nodes can serve the previous grant for up to 30 seconds, including a grant that was
just revoked. It heals by itself once the cache entry expires. Check `RedisDown` and the cache pool.
If it keeps firing, every portal revocation is lagging by the cache TTL, so fix Redis before
making further access changes.

## Event bus (M62)

`attome-events` delivery metrics, `crates/engine/attome-events/src/telemetry.rs`. `kind` is `webhook`,
`audit`, `connector` or `unknown`. The per-subscription detail is not a label. Read it from
`GET /api/v1/admin/events/subscriptions/{id}/deliveries`.

### EventDeliveryBacklogGrowing

An active subscription of this `kind` has been more than 1,000 feed rows behind for 10 minutes.
This is the outbound twin of `S2sAccessLogBacklogGrowing`. Check that the worker runs the dispatch
tick (`ApalisWorkerStale`, `ApalisBacklogGrowing`) and whether `events_dispatch_failures_total` is
rising for the kind, which means one subscription's tick keeps failing: the worker logs name it.
A value pinned at 10,000 is the gauge's cap, so the real lag is at least that. Once the M62 E2
per-subscription cap ships, a high-volume subscription held at its cap also shows here: raise its
cap through the admin API.

### EventDeliveryDeadLettered

At least one delivery gave up in the last hour for a reason that needs a person. For
`attempts_exhausted`, the receiver was down past every retry: confirm it is back, then replay from
the deliveries route. For `bad_url`, `ssrf_rejected` or `no_target`, the subscription's target is
wrong or points inward: fix it through the admin API. `subscription_gone` and
`subscription_inactive` follow an admin change and never fire this.

---

## Signals without an alert yet

No rule in `alerts.yml` reads these series yet, so nothing pages on them. They are listed here so a
dashboard or a future rule has one place to start. Every label is a closed set: none carries a
conversation, session, user or subscription id, or any free text. A counter is read as
`rate(...[5m])`, and a histogram as `histogram_quantile` over `rate(..._bucket[5m])`.

### Chatbot loop (`attome-ai`, chatbot plan C13.1)

Sources: `crates/engine/attome-ai/src/turn_metrics.rs` and, for the switch counter,
`crates/engine/attome-core/src/ai_runtime_switch.rs`. `surface` is `internal`, `webchat` or
`workflow`. Token spend and budget refusals are `attome_inference_tokens_total` and
`attome_inference_budget_rejected_total`, not repeated here.

| Series | Labels | What moves it, and what to do |
|---|---|---|
| `ai_turns_total` | `surface`, `terminal_state` | One per finished turn. Watch the share that is not `completed`. `model_failure`: check the provider and `ai_model_step_seconds`. `kill_switch`: chat, a module or an action went dark: the runtime switch or config has AI off (see the switch counter below), or a module, external effect or session allow-list closed. `budget_exceeded`: see the budget metrics. `max_steps` or `invalid_tool_call`: a prompt or tool-surface regression, so compare against the last release. |
| `ai_turn_steps` | `surface` | Model steps per turn (histogram). A rising p95 means turns loop longer. Read it next to `max_steps` turns. |
| `ai_model_step_seconds` | `surface` | Wall time of one model call (histogram). A rise with no change in steps is the provider. Check its status and the inference logs. |
| `ai_tool_calls_total` | `action_id` (a registry id, or `unregistered`), `outcome` | One per tool call the model asked for. A growing `failed` count on one `action_id` is that action's defect, so read its logs. A growing `unregistered`/`invalid` count means the model is naming tools it was not offered: a prompt or model regression. `world_changed` means budget, session or gate changed mid-turn. |
| `ai_gate_refusals_total` | `variant` | Refusals at the dispatch-time gate. A jump in `forbidden` or `not_in_session_allow_list` after a role or pack change is that change. Otherwise it is a model probing for tools it cannot use. Read it with the security logs. |
| `ai_delta_publish_failures_total` | `reason` (`error`, `timeout`) | A turn's live stream gave up on Redis. The answer is still stored, but the client sees it only on reload. Check `RedisDown` and `RedisCoordinationLatencyHigh`. |
| `ai_tool_call_sweep_total` | `transition` (`reclaimed`, `expired`, `reconciled`) | Rows the `AiToolCallSweep` job moved. Steady `expired` means proposals nobody confirms, a UX question. Any `reconciled` means an approval result reached its conversation only through recovery, so check the approval path's logs. |
| `ai_runtime_switch_read_failures_total` | `reason` (`error`, `timeout`) | A failed reread of `ai_runtime_switch`. After 5 s without a good read, **every AI surface fails closed on that node**. A sustained rate is an AI outage caused by the database: check `DbPoolNearExhaustion` and the node's DB connectivity, not the switch. The switch state itself is at `GET /api/v1/admin/ai/runtime-switch`. |

### Event bus (`attome-events`, M62 E1)

Source: `crates/engine/attome-events/src/telemetry.rs`. `kind` is `webhook`, `audit`, `connector` or
`unknown` (a delivery whose subscription row is gone). Per-subscription detail is not a label.
Read it from `GET /api/v1/admin/events/subscriptions/{id}/deliveries`. Two of these now have a
rule: `events_subscription_lag_max` (`EventDeliveryBacklogGrowing`) and `events_dead_lettered_total`
(`EventDeliveryDeadLettered`), both under "Event bus (M62)" above. The rest stay unalerted.

| Series | Labels | What moves it, and what to do |
|---|---|---|
| `events_dispatched_total` | `kind` | Deliveries each dispatch tick created. If it goes flat while entities change, the dispatcher is not running, so check the worker. |
| `events_dispatch_failures_total` | `kind` | One subscription's tick failed. Its cursor did not advance and the next tick retries it. A sustained count means one subscription is stuck, so read the worker logs. |
| `events_deliveries_total` | `kind`, `outcome` (`delivered`, `failed`, `dead_letter`) | One per delivery attempt that reached an outcome. A rising `failed` share means receivers are failing. apalis retries them. |
| `events_dead_lettered_total` | `kind`, `reason` | Why a delivery gave up. `attempts_exhausted`: the receiver has been down past every retry. `bad_url` or `ssrf_rejected`: the subscription's target is misconfigured or points inward, so fix it through the admin API. `subscription_gone`/`subscription_inactive`: expected after an admin change. |
| `events_delivery_seconds` | `kind` | Row created to delivered, retries included (histogram). This is the end-to-end latency receivers see. |
| `events_delivery_attempt_seconds` | `kind` | One outbound HTTP attempt (histogram). A rise here with no rise in failures means a slow receiver. |
| `events_subscription_lag_max` | `kind` | Gauge: the most unread feed rows behind any active subscription of that kind, capped at 10,000. Set by whichever node ran the tick, so read it as `max by (kind) (events_subscription_lag_max)`. A value that keeps growing means dispatch is not keeping up. A value pinned at 10,000 means it is at least that far behind. |
| `events_dead_letters` | `kind` | Gauge: delivery rows now in `dead_letter`. Read it as `max by (kind)`. A rising value is lost deliveries. Find them per subscription through the deliveries route. |
| `events_deliveries_retrying` | `kind` | Gauge: delivery rows in `failed`, waiting for an apalis retry. Read it as `max by (kind)`. If it grows alongside `ApalisBacklogGrowing`, the worker is the bottleneck. |
