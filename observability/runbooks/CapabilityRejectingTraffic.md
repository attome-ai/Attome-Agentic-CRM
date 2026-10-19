# CapabilityRejectingTraffic

Severity: critical. Owner: `platform`. Reported by {{node}}.

## Meaning

A capability is unavailable and callers are being refused.

## Checks

1. Read `{{api_base}}/health/dependencies` (administrator API key).

## Fix

Fix the dependency. If the probe itself is proven wrong, `capability.enforcement_enabled = false` stops the refusals and keeps the reporting.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
