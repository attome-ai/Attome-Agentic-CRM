# UploadScanBacklogStale

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

An upload has waited more than 15 minutes for its virus scan.

## Checks

1. Confirm `storage.clamd_address` points at a live clamd (the compose `clamav` profile).
2. Confirm the worker is running.

## Fix

Start clamd or the worker. Unscanned uploads are refused by the 24-hour sweep.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
