# ApalisBatchBacklogGrowing

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

More than 1,000 jobs pending on the batch queue for 10 minutes. A large import or rewrap can do this legitimately.

## Checks

1. If `ApalisWorkerStale{queue="batch"}` is not firing and the backlog is falling, wait.
2. Otherwise check `jobs.batch_worker_concurrency` and the batch worker's logs.

## Fix

Restart or scale the batch worker.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
