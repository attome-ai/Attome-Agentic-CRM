# ApalisWorkerNeverSeen

Severity: critical. Owner: `platform`. Reported by {{node}}.

## Meaning

No worker of the fast or batch queue has ever registered. Background jobs, including verification and password-reset email, file scanning and retention, are not running at all.

## Checks

1. Is the `worker` service started? A worker-split deployment needs that profile.
2. Is `jobs.run_worker_inline` `false` with no standalone worker?

## Fix

Start a worker, or set `jobs.run_worker_inline` to `true` and restart.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
