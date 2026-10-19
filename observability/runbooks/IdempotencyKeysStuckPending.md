# IdempotencyKeysStuckPending

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

A request on a mandatory-idempotency route has held its key as `pending` for more than ten minutes: it died mid-flight, so whether its change committed is unknown, and every retry with that key answers `idempotency_outcome_unknown`.

## Checks

1. Look up the operation and principal in the audit log to see whether the change landed.
2. `idempotency_replays_total`, `idempotency_mismatch_total` and `idempotency_unknown_total` show which operations retries hit.

## Fix

Have the caller retry with a new key only if the change did not land.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
