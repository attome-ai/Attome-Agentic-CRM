# AuditChainerLagHigh

Severity: warning. Owner: `security`. Reported by {{node}}.

## Meaning

The audit chainer is more than 5 minutes behind. Events are captured in `audit_ingest` but not chained, and there is no automatic fallback.

## Checks

1. Check the `audit_chainer` service is running and read its logs.

## Fix

Restart the chainer. Left alone the backlog crosses `audit.ingest_backlog_threshold` and writes start answering 503.

## Escalation

Escalate to the security on-call; treat it as a possible incident until ruled out. This deployment's alert recipients: {{alert_emails}}.
