# WalArchiveLagHigh

Severity: warning. Owner: `db`. Reported by {{node}}.

## Meaning

`pg_stat_archiver.last_archived_time` on {{database}} is more than 15 minutes old.

## Checks

1. Look for "archive_command failed" in the primary's logs.
2. Check whether the repository credentials were rotated.
3. On Patroni a 0 reading is ambiguous: check `attome_backup_monitor_pg_reachable`.

## Fix

Restore the archive command's access; WAL piles up on the primary's disk until it does.

## Escalation

Escalate to the database on-call. This deployment's alert recipients: {{alert_emails}}.
