# PlatformJobFailures

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

A job kind (the `kind` label) has failed repeatedly for 15 minutes.

## Checks

1. Read the worker logs for that kind.
2. A payload this build cannot decode settles as `Killed`: check `ApalisDeadLetterGrowing` too.

## Fix

Fix what the job depends on, then replay its dead letters.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
