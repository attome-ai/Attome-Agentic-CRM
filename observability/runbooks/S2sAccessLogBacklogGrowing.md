# S2sAccessLogBacklogGrowing

Severity: warning. Owner: `security`. Reported by {{node}}.

## Meaning

More than 1,000 S2S access-log entries have waited in Redis, unflushed, for 10 minutes. Each one is an accepted machine request whose only record is in Redis.

## Checks

1. Look for "s2s access-log flush" errors in the server logs on {{node}}.
2. Check the write path to {{database}}.

## Fix

Fix the flush. If `RedisPersistenceDisabled` also fires, do not restart the store until the backlog drains.

## Escalation

Escalate to the security on-call; treat it as a possible incident until ruled out. This deployment's alert recipients: {{alert_emails}}.
