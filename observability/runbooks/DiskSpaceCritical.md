# DiskSpaceCritical

Severity: critical. Owner: `platform`. Reported by {{node}}.

## Meaning

A filesystem is below 5% free. Postgres refuses writes when its data filesystem fills.

## Checks

1. Find what grew: WAL, backups, logs or file data.

## Fix

Free space now; treat it as an imminent outage.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
