# JobScheduleStale

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

A periodic sweep (the `name` label) has not succeeded in two hours.

## Checks

1. Read the worker logs for that schedule.
2. A schedule that never succeeded emits no sample: check `job_schedule` if a sweep seems silent.

## Fix

Fix the sweep's failure. The two-hour floor is generic; narrow it per schedule in the deployment's overlay.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
