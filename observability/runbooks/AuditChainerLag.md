# AuditChainerLag

Severity: critical. Owner: `security`. Reported by {{node}}.

## Meaning

Audit events wait more than 5 minutes to be sealed into the chain. This is the built-in twin of `AuditChainerLagHigh`.

## Checks

1. Check the chainer is running (`attome status`) and read its logs on {{node}}.

## Fix

Restart the chainer. Left alone the backlog crosses `audit.ingest_backlog_threshold` and writes start answering 503.

## Escalation

Escalate to the security on-call; treat it as a possible incident until ruled out. This deployment's alert recipients: {{alert_emails}}.
