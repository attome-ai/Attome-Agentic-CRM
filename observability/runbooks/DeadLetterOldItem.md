# DeadLetterOldItem

Severity: info. Owner: `platform`. Reported by {{node}}.

## Meaning

A dead letter has waited more than seven days without being replayed or discarded. Items older than `jobs.dead_letter_retention_days` are discarded by the sweep, with the reason on their audit event.

## Checks

1. List the oldest: `{{api_base}}/api/v1/admin/dead-letters?source=<source>`; the source is the alert's `source` label.
2. Decide per group whether the cause is fixed.

## Fix

Replay what can succeed now; discard the rest with a reason, so the inbox only holds work someone still has to look at.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
