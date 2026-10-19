# ApalisBacklogGrowing

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

More than 100 jobs pending on the fast queue for 10 minutes: the worker is down or saturated.

## Checks

1. Check `ApalisWorkerStale`, the worker's logs and `jobs.worker_concurrency`.

## Fix

Restart the worker, add one, or raise its concurrency.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
