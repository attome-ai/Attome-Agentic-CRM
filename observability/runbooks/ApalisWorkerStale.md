# ApalisWorkerStale

Severity: critical. Owner: `platform`. Reported by {{node}}.

## Meaning

No heartbeat from a queue's worker for more than 90 s, so that queue has stopped.

## Checks

1. Check the worker service (`docker compose ps`, `attome status`) and its logs.

## Fix

Restart the worker. Orphaned rows are reclaimed once a worker of that queue is back.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
