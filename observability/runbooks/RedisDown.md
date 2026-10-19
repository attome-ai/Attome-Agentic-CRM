# RedisDown

Severity: critical. Owner: `platform`. Reported by {{node}}.

## Meaning

The general cache pool ({{cache}}) fails its ping. Session and S2S checks fail closed, so treat this as a full outage.

## Checks

1. Check the store's process or container and its logs (`docker compose ps`).
2. Check network reachability from {{node}} to {{cache}}.

## Fix

Restart or repair the store. `/scale-out-ops` covers failover to a standby.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
