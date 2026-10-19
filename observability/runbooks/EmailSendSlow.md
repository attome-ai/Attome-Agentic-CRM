# EmailSendSlow

Severity: warning. Owner: `integration`. Reported by {{node}}.

## Meaning

The p95 email send time is above 60 s, half of the 120 s whole-send deadline. Sends that cross the deadline end as `unknown` and are not retried.

## Checks

1. Check the relay's latency and the network path from {{node}}.

## Fix

Fix the relay or switch to a faster one before sends start ending `unknown`.

## Escalation

Escalate to the integration owner (outbound email, webhooks and connectors). This deployment's alert recipients: {{alert_emails}}.
