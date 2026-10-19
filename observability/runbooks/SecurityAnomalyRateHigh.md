# SecurityAnomalyRateHigh

Severity: warning. Owner: `security`. Reported by {{node}}.

## Meaning

A security rejection reason (the `reason` label) stayed above 5 per second for 5 minutes: S2S replay or rate limit, HTTP 429, CSRF 403, a revoked token, or a portal gate.

## Checks

1. Find the source address or client next to the rejections in the request-id-tagged server logs on {{node}}.
2. A misconfigured integration replaying a revoked token looks the same as an attack here.

## Fix

Identify the client before acting: fix the integration, or block the source.

## Escalation

Escalate to the security on-call; treat it as a possible incident until ruled out. This deployment's alert recipients: {{alert_emails}}.
