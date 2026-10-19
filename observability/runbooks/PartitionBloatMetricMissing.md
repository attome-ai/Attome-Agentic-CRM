# PartitionBloatMetricMissing

Severity: warning. Owner: `db`. Reported by {{node}}.

## Meaning

No `db_bloat_total_bytes` sample in an hour: the refresh loop is failing or a partitioned table is missing.

## Checks

1. Look for "metrics refresh: partition bloat query failed" in the server logs on {{node}}.
2. Confirm the `EnsureAuditPartitions` job still runs (`JobScheduleStale` would also fire).

## Fix

Fix the failing query or recreate the missing partition through the job.

## Escalation

Escalate to the database on-call. This deployment's alert recipients: {{alert_emails}}.
