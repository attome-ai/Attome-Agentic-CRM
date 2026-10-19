# WorkflowTriggerDeadLettered

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

An entity change failed workflow dispatch at least 5 times over at least 15 minutes, so the dispatcher skipped it. The workflows it matched did not start, and a Wait-for-Event it matched did not resume.

## Checks

1. List them: `{{api_base}}/api/v1/workflow/trigger-dead-letters` (newest first; `last_error` names the failure, the worker logs carry the same `event_id`).

## Fix

Fix the cause, then replay (`POST /api/v1/workflow/trigger-dead-letters/{event_id}/replay`): it starts only what the event missed. Replay never resumes a Wait-for-Event; handle a stuck wait on its instance. Discard one handled another way with `DELETE /api/v1/workflow/trigger-dead-letters/{event_id}`. Both are audited.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
