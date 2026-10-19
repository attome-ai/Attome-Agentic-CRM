# RedisCoordinationMemoryHigh

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

The coordination store is above 80% of `maxmemory`. It runs `noeviction`, so at 100% its writes fail and the controls behind it refuse requests.

## Checks

1. Find what grew: `INFO keyspace` and a `--bigkeys` scan. The profiler keyspace is the usual runaway.

## Fix

Raise `maxmemory`, or delete the runaway keys deliberately.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
