# DbPoolNearExhaustion

Severity: warning. Owner: `db`. Reported by {{node}}.

## Meaning

More than 90% of the primary pool's connections to {{database}} have been busy for 5 minutes.

## Checks

1. Look for long-running statements in `pg_stat_activity`.
2. Look for slow requests in the request-id-tagged server logs on {{node}}, and for a transaction held across outside I/O.

## Fix

Fix the slow query or the held transaction. If the load is real, raise `database.connection_number` within Postgres's `max_connections`, or add pgbouncer (`/scale-out-ops`).

## Escalation

Escalate to the database on-call. This deployment's alert recipients: {{alert_emails}}.
