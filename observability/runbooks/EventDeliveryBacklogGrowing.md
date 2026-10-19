# EventDeliveryBacklogGrowing

Severity: warning. Owner: `integration`. Reported by {{node}}.

## Meaning

An active subscription of this `kind` has been more than 1,000 feed rows behind for 10 minutes.

## Checks

1. Check that the worker runs the dispatch tick (`ApalisWorkerStale`, `ApalisBacklogGrowing`).
2. A rising `events_dispatch_failures_total` for the kind means one subscription's tick keeps failing; the worker logs name it.
3. A value pinned at 10,000 is the gauge's cap: the real lag is at least that.

## Fix

Fix the failing subscription or the worker; raise a high-volume subscription's cap through the admin API.

## Escalation

Escalate to the integration owner (outbound email, webhooks and connectors). This deployment's alert recipients: {{alert_emails}}.
