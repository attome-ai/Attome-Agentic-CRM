# NodeStoppedReporting

Severity: critical. Owner: `platform`. Reported by {{node}}.

## Meaning

A node that sent its heartbeat in the last hour has not for three minutes.

## Checks

1. Check the node's process and logs (`attome status`, the ops overview screen).

## Fix

Restart the node. A node taken out on purpose stops being reported an hour later.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
