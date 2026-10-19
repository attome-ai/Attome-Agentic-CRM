# PortalCacheInvalidationFailed

Severity: warning. Owner: `security`. Reported by {{node}}.

## Meaning

A portal admin change committed, but bumping the portal access version on the cache ({{cache}}) failed. Other nodes can serve the previous grant, including a just-revoked one, for up to 30 seconds.

## Checks

1. Check `RedisDown` and the cache pool.

## Fix

It heals once the cache entry expires. If it keeps firing, fix the cache before making further access changes.

## Escalation

Escalate to the security on-call; treat it as a possible incident until ruled out. This deployment's alert recipients: {{alert_emails}}.
