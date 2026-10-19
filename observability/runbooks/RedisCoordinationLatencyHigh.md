# RedisCoordinationLatencyHigh

Severity: warning or critical. Owner: `platform`. Reported by {{node}}.

## Meaning

The coordination ping is above 150 ms (warning) or 300 ms (critical). The fail-closed timeout on the controls it gates is 300 ms, so at critical real requests are already being refused.

## Checks

1. Check host CPU and the network between {{node}} and the store.
2. Look for a large or blocking command in the store's slow log.

## Fix

Remove the blocking command or the load on the host; move the store closer to the app if the network is the cause.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
