# EventDeliveryDeadLettered

Severity: warning. Owner: `integration`. Reported by {{node}}.

## Meaning

At least one delivery gave up in the last hour for a reason that needs a person.

## Checks

1. `attempts_exhausted`: the receiver was down past every retry.
2. `bad_url`, `ssrf_rejected` or `no_target`: the subscription's target is wrong or points inward.
3. Per-subscription detail: `{{api_base}}/api/v1/admin/events/subscriptions/{id}/deliveries`.

## Fix

Confirm the receiver is back and replay from the deliveries route, or fix the target through the admin API.

## Escalation

Escalate to the integration owner (outbound email, webhooks and connectors). This deployment's alert recipients: {{alert_emails}}.
