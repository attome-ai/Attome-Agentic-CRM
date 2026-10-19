# ApalisDeadLetterGrowing

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

Jobs exhausted their retries and sit `Killed`; nothing retries them.

## Checks

1. List them: `{{api_base}}/api/v1/admin/jobs/dead-letter?queue=<queue>`; `last_error` names the failure.

## Fix

Fix the cause, then replay (`POST /api/v1/admin/jobs/{id}/replay`) or discard (`DELETE /api/v1/admin/jobs/{id}`, audited).

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
