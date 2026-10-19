# ApalisOldestPendingAgeHigh

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

The oldest pending job in a queue is older than 15 minutes: the worker is not draining it.

## Checks

1. Check the worker is running and whether one slow kind holds all its concurrency.

## Fix

Restart or scale the worker; fix or pause the slow kind.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
