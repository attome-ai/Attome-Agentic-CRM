# RedisSnapshotStale

Severity: warning. Owner: `security`. Reported by {{node}}.

## Meaning

Persistence is configured but no snapshot has completed in 10 minutes.

## Checks

1. Check disk space and permissions on the store's `--dir` volume.
2. `redis_coordination_persistence_changes_since_save` shows how much is unsaved.

## Fix

Free the disk or fix the permissions; confirm the next snapshot completes.

## Escalation

Escalate to the security on-call; treat it as a possible incident until ruled out. This deployment's alert recipients: {{alert_emails}}.
