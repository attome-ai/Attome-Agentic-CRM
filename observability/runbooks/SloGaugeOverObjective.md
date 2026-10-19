# SloGaugeOverObjective

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

A gauge SLO class has been over its objective for most of the last five minutes, for 15 minutes. `slo_series` names the series and `slo_objective` the ceiling.

## Checks

1. S10, job queue delay (`apalis_oldest_pending_age_seconds`): check a worker is running (`apalis_worker_last_seen_age_seconds`), the backlog (`apalis_pending_jobs`), and whether one job kind floods the lane.
2. S11, change-feed lag (`events_subscription_lag_max`): `EventDeliveryBacklogGrowing` usually fires with it.

## Fix

Add a worker or fix the stuck job kind (S10); follow `EventDeliveryBacklogGrowing` (S11).

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
