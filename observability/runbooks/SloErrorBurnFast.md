# SloErrorBurnFast

Severity: critical. Owner: `platform`. Reported by {{node}}.

## Meaning

More than 1.44% of one SLO class's requests returned 5xx in both the last hour and the last 5 minutes, with more than one request a second.

## Checks

1. Group the failures by status and request id in the request-id-tagged server logs on {{node}}.
2. If `HighHttpErrorRate` also fires, the fault is platform-wide: read `{{api_base}}/health/dependencies` (administrator API key).
3. If it fires alone, the class's own code path or data is failing.

## Fix

Fix the dependency or the failing path; roll back the last release if it started the burn.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
