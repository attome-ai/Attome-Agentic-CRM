# ReplicaLagHigh

Severity: warning. Owner: `db`. Reported by {{node}}.

## Meaning

The read replica is more than 30 s behind the primary ({{database}}). The sticky-primary pin protects a user's own recent writes only, so other readers see stale data.

## Checks

1. Check the replica's host and logs (`docker compose logs postgres-replica`).
2. A lag that never fires may mean `database.readonly` does not point at a real standby.

## Fix

Fix the replica's host or network; if it keeps growing, see `ReplicaLagCritical`.

## Escalation

Escalate to the database on-call. This deployment's alert recipients: {{alert_emails}}.
