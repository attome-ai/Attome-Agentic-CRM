# EmailSuppressionSpike

Severity: warning. Owner: `integration`. Reported by {{node}}.

## Meaning

More than 25 addresses were added to the suppression list by hard bounces or complaints in the last hour.

## Checks

1. List the new suppressions: `{{api_base}}/api/v1/admin/email/suppressions` and group them by detail.
2. One identical relay reply across many addresses is a relay fault answered with a recipient-shaped code: a false suppression.

## Fix

Remove false suppressions (`DELETE /api/v1/admin/email/suppressions/{id}`, audited); a real list-quality problem goes to the list owner.

## Escalation

Escalate to the integration owner (outbound email, webhooks and connectors). This deployment's alert recipients: {{alert_emails}}.
