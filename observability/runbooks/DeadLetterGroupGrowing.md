# DeadLetterGroupGrowing

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

A dead-letter group gained ten or more items since the last hourly sweep: something keeps failing the same way.

## Checks

1. Open the inbox: `{{api_base}}/api/v1/admin/dead-letters/groups`; the group is near the top (largest first).
2. Read its `sample_message`, then the logs on {{node}} for one item.

## Fix

Stop the cause first (pause the flow, deactivate the webhook subscription, fix the target), then replay the group at a pace the target can take (`rate_per_minute`), or discard items with a reason.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
