# Alert runbook

Every rule in [`alerts.yml`](alerts.yml) and [`builtin-alerts.json`](builtin-alerts.json) has its own
runbook in [`runbooks/`](runbooks/), `runbooks/<Alert>.md`: what it means, what to check, how to fix it
and whom to escalate to (AB10-T3). Each rule's `runbook_url` (or `runbook`) points at its file, and its
`owner` label names who is paged (M86 O2). `{{name}}` placeholders in a runbook are filled with this
deployment's addresses (never a secret) when it is rendered: a built-in alert's email carries the filled
runbook, and `attome runbook <Alert>` prints it. `attome_server::runbooks` lists the placeholders, and its
tests fail when an alert has no runbook or a runbook lacks a section.

The rule's own comment in `alerts.yml` carries the metric's source and known blind spots. A request id in
the logs is the thread from an alert to the failing request (`/prod-observability`'s incident workflow).
This page keeps what is shared across alerts: owners, the SLO background, and the signals that have no
alert yet.

## Owners and escalation

| `owner` | Covers | Escalate to |
|---|---|---|
| `platform` | HTTP and SLO burn rates, Redis/Dragonfly, job queues, object storage, disk, capability gate, portal grant drift | the platform on-call |
| `db` | Postgres pools, partitions, backups, WAL, replicas | the database on-call |
| `security` | audit chain, security rejections, coordination-store durability, S2S access log, portal logins and access-cache freshness | the security on-call; treat as a possible incident until ruled out |
| `integration` | outbound email, event-bus delivery | the integration owner |

A deployment maps each owner to a receiver in its Alertmanager config. The repo ships none.

---

## HTTP

- [HighHttpErrorRate](runbooks/HighHttpErrorRate.md)

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

- [SloLatencyBurnFast](runbooks/SloLatencyBurnFast.md)
- [SloLatencyBurnSlow](runbooks/SloLatencyBurnSlow.md)
- [SloErrorBurnFast](runbooks/SloErrorBurnFast.md)
- [SloErrorBurnSlow](runbooks/SloErrorBurnSlow.md)
- [SloLatencyBucketMissing](runbooks/SloLatencyBucketMissing.md)
- [SloGaugeOverObjective](runbooks/SloGaugeOverObjective.md)

### Changing an SLO

Edit `observability/slo-catalogue.json` (its schema is `slo-catalogue.schema.json`), then:

```sh
attome slo generate          # rewrite the attome-slo rule group, the k6 thresholds and docs/slo.md
attome slo generate --check  # exit 2 when an output has drifted; the release gate runs this
```

Never edit the generated outputs. Every class keeps its honesty label: `target` until a dated
load-test result in `docs/evidence/` moves it to `measured_reference`. A deployment changes its own
latency targets at `/api/v1/admin/slo/targets/{class_id}`, not in the catalogue. Monthly reports
and the fast-burn notification are described in `docs/slo.md`.

## Redis / Dragonfly

- [RedisDown](runbooks/RedisDown.md)
- [RedisCoordinationDown](runbooks/RedisCoordinationDown.md)
- [RedisCoordinationLatencyHigh](runbooks/RedisCoordinationLatencyHigh.md)
- [RedisCoordinationMemoryHigh](runbooks/RedisCoordinationMemoryHigh.md)
- [RedisCoordinationNoMemoryCeiling](runbooks/RedisCoordinationNoMemoryCeiling.md)

## Database

- [DbPoolNearExhaustion](runbooks/DbPoolNearExhaustion.md)
- [PartitionedTableDeadTupleRatioHigh](runbooks/PartitionedTableDeadTupleRatioHigh.md)
- [PartitionBloatMetricMissing](runbooks/PartitionBloatMetricMissing.md)
- [BackupTooOld](runbooks/BackupTooOld.md)
- [WalArchiveLagHigh](runbooks/WalArchiveLagHigh.md)
- [ReplicaLagHigh](runbooks/ReplicaLagHigh.md)
- [ReplicaLagCritical](runbooks/ReplicaLagCritical.md)

## Jobs

- [ApalisBacklogGrowing](runbooks/ApalisBacklogGrowing.md)
- [ApalisBatchBacklogGrowing](runbooks/ApalisBatchBacklogGrowing.md)
- [ApalisDeadLetterGrowing](runbooks/ApalisDeadLetterGrowing.md)
- [ApalisWorkerStale](runbooks/ApalisWorkerStale.md)
- [ApalisWorkerNeverSeen](runbooks/ApalisWorkerNeverSeen.md)
- [PlatformJobFailures](runbooks/PlatformJobFailures.md)
- [ApalisOldestPendingAgeHigh](runbooks/ApalisOldestPendingAgeHigh.md)
- [JobScheduleStale](runbooks/JobScheduleStale.md)
- [WorkflowTriggerDeadLettered](runbooks/WorkflowTriggerDeadLettered.md)
- [ChangeFeedConsumerLagging](runbooks/ChangeFeedConsumerLagging.md)

## Object storage and files

- [ObjectStorageDown](runbooks/ObjectStorageDown.md)
- [StoragePresignFailures](runbooks/StoragePresignFailures.md)
- [ObjectStorageProbeLatencyHigh](runbooks/ObjectStorageProbeLatencyHigh.md)
- [UploadScanBacklogStale](runbooks/UploadScanBacklogStale.md)
- [IdempotencyKeysStuckPending](runbooks/IdempotencyKeysStuckPending.md)

## Host

- [DiskSpaceLow](runbooks/DiskSpaceLow.md)
- [DiskSpaceCritical](runbooks/DiskSpaceCritical.md)

## Built-in alerts (no Prometheus)

`observability/builtin-alerts.json` is evaluated by the server itself every minute on the built-in
metrics store when `observability.builtin_store` is on (the default on Solo). Each rule's state is in
`ops_alert`, every firing and resolution in `ops_alert_event`. Several share a name and runbook with a
Prometheus rule above; these are only built in (four are the built-in twins of a Prometheus rule):

- [AuditChainerLag](runbooks/AuditChainerLag.md)
- [ChangesPaused](runbooks/ChangesPaused.md)
- [DbPoolAcquireTimeouts](runbooks/DbPoolAcquireTimeouts.md)
- [JobBacklogOld](runbooks/JobBacklogOld.md)
- [JobsInDeadLetter](runbooks/JobsInDeadLetter.md)
- [NodeStoppedReporting](runbooks/NodeStoppedReporting.md)

## Capability gate (D-344)

- [CapabilityUnavailable](runbooks/CapabilityUnavailable.md)
- [CapabilityRejectingTraffic](runbooks/CapabilityRejectingTraffic.md)

## Security and audit

- [AuditChainerLagHigh](runbooks/AuditChainerLagHigh.md)
- [HttpRejectionsSpike](runbooks/HttpRejectionsSpike.md)
- [SecurityAnomalyRateHigh](runbooks/SecurityAnomalyRateHigh.md)
- [RedisPersistenceDisabled](runbooks/RedisPersistenceDisabled.md)
- [RedisSnapshotStale](runbooks/RedisSnapshotStale.md)
- [S2sAccessLogBacklogGrowing](runbooks/S2sAccessLogBacklogGrowing.md)

## Email

- [EmailRelayFailureRatioHigh](runbooks/EmailRelayFailureRatioHigh.md)
- [EmailSendOutcomeUnknown](runbooks/EmailSendOutcomeUnknown.md)
- [EmailSuppressionSpike](runbooks/EmailSuppressionSpike.md)
- [EmailSendSlow](runbooks/EmailSendSlow.md)

## Portal (web-portal-users §5)

The portal's rejection reasons (`portal_origin`, `portal_budget`, `portal_cidr`, `portal_epoch`,
`portal_host`) are `security_rejection_total` reasons, so `SecurityAnomalyRateHigh` already covers
them by reason. The rules below read the portal's own counters in
`crates/engine/attome-portal/src/telemetry.rs`. No label carries a portal, user or address.

- [PortalLoginFailureRatioHigh](runbooks/PortalLoginFailureRatioHigh.md)
- [PortalGrantDrift](runbooks/PortalGrantDrift.md)
- [PortalCacheInvalidationFailed](runbooks/PortalCacheInvalidationFailed.md)

## Event bus (M62)

`attome-events` delivery metrics, `crates/engine/attome-events/src/telemetry.rs`. `kind` is `webhook`,
`audit`, `connector` or `unknown`. The per-subscription detail is not a label. Read it from
`GET /api/v1/admin/events/subscriptions/{id}/deliveries`.

- [EventDeliveryBacklogGrowing](runbooks/EventDeliveryBacklogGrowing.md)
- [EventDeliveryDeadLettered](runbooks/EventDeliveryDeadLettered.md)

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
