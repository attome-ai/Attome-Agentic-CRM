# SloErrorBurnSlow

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

More than 0.6% of one SLO class's requests returned 5xx in both the last 6 hours and the last 30 minutes.

## Checks

1. Find the common request shape among the 500s in the request-id-tagged server logs on {{node}}: a small steady share on one route is usually one bad record or one caller's malformed request.

## Fix

Fix the record or the code path that answers 500 to it. File a ticket, not a page.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
