# ReplicaLagCritical

Severity: critical. Owner: `db`. Reported by {{node}}.

## Meaning

The replica lag stayed above its ceiling for 5 minutes.

## Checks

1. Confirm the replica is still replaying (`pg_stat_replication` on the primary).

## Fix

Route reads back to the primary until the replica recovers: set `database.readonly.host` and `.port` to null (or to the primary) and restart. `/scale-out-ops` covers the replica.

## Escalation

Escalate to the database on-call. This deployment's alert recipients: {{alert_emails}}.
