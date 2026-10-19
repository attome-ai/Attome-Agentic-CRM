# ChangeFeedConsumerLagging

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

A change-feed consumer (a workflow trigger dispatcher, the search indexer, a webhook subscription) has an unread event older than 5 minutes.

## Checks

1. `{{api_base}}/api/v1/admin/change-feed/consumers` (the Events monitor screen) shows which one, its lag and when it last read.
2. An internal consumer that stopped reading usually means its job is failing: look in the dead-letter list and the logs.

## Fix

Fix the failing job. A consumer that missed work can be rewound with `POST /api/v1/admin/change-feed/consumers/{name}/rewind`; it skips events it already applied.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
