# EmailSendOutcomeUnknown

Severity: critical. Owner: `integration`. Reported by {{node}}.

## Meaning

At least one send timed out at or after DATA in the last 15 minutes. The relay may have accepted it, so it is never retried automatically.

## Checks

1. List the deliveries with status `unknown`: `{{api_base}}/api/v1/admin/email/deliveries`.
2. Check the relay's own logs for each message id.

## Fix

Resend (`POST /api/v1/admin/email/deliveries/{id}/resend`) only what the relay did not accept.

## Escalation

Escalate to the integration owner (outbound email, webhooks and connectors). This deployment's alert recipients: {{alert_emails}}.
