# JobsInDeadLetter

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

Background jobs failed for good and wait in the dead-letter queue. This is the built-in twin of `ApalisDeadLetterGrowing`.

## Checks

1. List them: `{{api_base}}/api/v1/admin/jobs/dead-letter`; `last_error` names the failure.
2. Read the worker logs on {{node}} for the same job id.

## Fix

Fix the cause, then replay (`POST /api/v1/admin/jobs/{id}/replay`) or discard (`DELETE /api/v1/admin/jobs/{id}`, audited).

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
