# RedisCoordinationNoMemoryCeiling

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

`maxmemory` is unset on the coordination store, so it grows until the host kills it, and `RedisCoordinationMemoryHigh` cannot fire.

## Checks

1. `CONFIG GET maxmemory` on the coordination store answers 0.

## Fix

Set `maxmemory` on the coordination service and restart it.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
