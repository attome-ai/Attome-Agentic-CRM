# BackupTooOld

Severity: critical. Owner: `db`. Reported by {{node}}.

## Meaning

No successful pgbackrest backup of {{database}} in 26 hours.

## Checks

1. On a single primary read `/var/log/pgbackrest-cron.log` in `postgres-primary` and confirm `/etc/cron.d/pgbackrest` exists.
2. On Patroni find the leader first, then read the same log and `/etc/cron.d/pgbackrest-patroni` there.
3. Check `attome_backup_repo_reachable`: an unreadable repo raises this same alert.
4. The backup screen: `{{app_url}}` → Administration → Backup, or `{{api_base}}/api/v1/admin/backup`.

## Fix

Fix the cron or the repository access and take a backup now; confirm it on the backup screen.

## Escalation

Escalate to the database on-call. This deployment's alert recipients: {{alert_emails}}.
