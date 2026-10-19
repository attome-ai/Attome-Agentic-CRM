# JobBacklogOld

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

The oldest waiting background job has waited more than 15 minutes. This is the built-in twin of `ApalisOldestPendingAgeHigh`.

## Checks

1. Check the worker is running (`attome status`, the ops overview screen) and its logs on {{node}}.
2. Check whether one slow job kind holds all the worker's concurrency.

## Fix

Restart or scale the worker; fix or pause the slow kind.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
