# ObjectStorageProbeLatencyHigh

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

The storage probe of {{storage}} takes over 1.5 s against a 2 s hard timeout; one more slowdown trips the capability gate.

## Checks

1. Check the storage host's load and the network path from {{node}}.

## Fix

Remove the load or move the store closer to the app.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
