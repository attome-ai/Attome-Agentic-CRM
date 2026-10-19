# DbPoolAcquireTimeouts

Severity: warning. Owner: `db`. Reported by {{node}}.

## Meaning

Requests timed out waiting for a database connection to {{database}}: the pool was empty for longer than its acquire timeout. This is the built-in twin of `DbPoolNearExhaustion`, past the point of exhaustion.

## Checks

1. Look for long-running statements in `pg_stat_activity`.
2. Find the requests that waited in the request-id-tagged server logs on {{node}} (`overloaded` / `db_unavailable` answers).
3. Check whether a batch job or an import holds many connections at once.

## Fix

Fix the slow query or held transaction first. If the load is real, raise `database.connection_number` within Postgres's `max_connections`.

## Escalation

Escalate to the database on-call. This deployment's alert recipients: {{alert_emails}}.
