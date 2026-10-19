# EmailRelayFailureRatioHigh

Severity: warning. Owner: `integration`. Reported by {{node}}.

## Meaning

More than 20% of email sends over 15 minutes failed at the relay (`transient` or `permanent_relay`, for example a 535 after a password rotation).

## Checks

1. Run `attome preflight` against the relay.
2. Check the relay's credentials and its sender policy.
3. Recent sends and their replies: `{{api_base}}/api/v1/admin/email/deliveries`.

## Fix

Fix the credentials or the relay; failed sends retry on their own while transient.

## Escalation

Escalate to the integration owner (outbound email, webhooks and connectors). This deployment's alert recipients: {{alert_emails}}.
