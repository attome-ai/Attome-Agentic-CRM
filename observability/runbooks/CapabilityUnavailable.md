# CapabilityUnavailable

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

A capability (the `capability` label) is unavailable on at least one node, and routes that need it answer `503 capability_unavailable`. Ordinary record work is unaffected and the node stays in rotation.

## Checks

1. Read `{{api_base}}/health/dependencies` (administrator API key): the live probe and what the gate enforces.

## Fix

Fix the underlying dependency; this alert is not about the node.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
