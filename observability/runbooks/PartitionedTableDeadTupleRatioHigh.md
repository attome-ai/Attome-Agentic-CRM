# PartitionedTableDeadTupleRatioHigh

Severity: warning. Owner: `db`. Reported by {{node}}.

## Meaning

One of the partitioned audit and access-log tables on {{database}} is more than 20% dead tuples for 30 minutes.

## Checks

1. Check `last_autovacuum` and `n_dead_tup` on its partitions in `pg_stat_user_tables`.

## Fix

If autovacuum runs but loses ground, tune the table's storage parameters against real load (`/prod-observability` "Audit, bloat, partitions").

## Escalation

Escalate to the database on-call. This deployment's alert recipients: {{alert_emails}}.
