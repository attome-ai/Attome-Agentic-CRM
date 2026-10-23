# DeadLetterGroupNew

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

Work started failing for good in a new way: the hourly dead-letter sweep found a group (source, step and error kind) that was not there an hour ago.

## Checks

1. Open the inbox: `{{api_base}}/api/v1/admin/dead-letters/groups`; new groups have a recent `first_seen`.
2. Read the group's `sample_message` and the logs on {{node}} for one of its items.

## Fix

Fix the cause (a target that is down, a changed field, an expired credential), then replay the group: `POST /api/v1/admin/dead-letters/groups/replay` with its `cause_group`. Its oldest item runs first as a preview; the rest follow at `rate_per_minute`. Discard items that will never succeed with a reason (`POST /api/v1/admin/dead-letters/{source}/{id}/discard`).

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
