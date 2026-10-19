# DiskSpaceLow

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

A filesystem is below 10% free (needs a host node_exporter). Postgres, the file store and the audit partitions write locally.

## Checks

1. Find what grew: WAL, backups, logs or file data.

## Fix

Free or extend space before `DiskSpaceCritical`.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
