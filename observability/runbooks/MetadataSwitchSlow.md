# MetadataSwitchSlow

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

The p95 time from a metadata version becoming current (a publish, a switch or a rollback) to a node serving it is above 30 s for 10 minutes. Until a node switches, it serves the previous version, so users on different nodes see different forms, fields and rules.

## Checks

1. Find the current version and list the nodes that serve it: `{{api_base}}/api/v1/admin/metadata/versions/{version}/nodes`. A node missing from the list has not switched yet.
2. On a slow or missing node, search the logs for "could not switch to the current metadata version"; the error names the artefact or query that failed.
3. Check database latency and pool pressure from that node (`{{metrics_url}}`): a node loads the version's artefacts from {{database}}.

## Fix

Fix the cause in the logs (usually a slow or unreachable database). A node retries on every metadata catch-up; a node that never switches can be restarted, and it loads the current version at start.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
