# HighHttpErrorRate

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

More than 2% of requests to {{app_url}} returned a 5xx status over 5 minutes.

## Checks

1. Group the failing requests by path in the request-id-tagged server logs on {{node}}.
2. One path failing points to a code or data defect on that path; every path failing points to a dependency.
3. Read `{{api_base}}/health/dependencies` (administrator API key), and look for `RedisDown`, `DbPoolNearExhaustion` or `ObjectStorageDown` firing at the same time.

## Fix

Fix the failing dependency first. For a single path, find the request shape in the logs and fix or roll back the change that broke it.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
