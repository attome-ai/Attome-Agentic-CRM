# PortalGrantDrift

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

A portal access grant's condition no longer renders (an unknown operator, or a field that drifted or was removed), so portal users under it see nothing through that grant.

## Checks

1. The warn log next to each increment names the role and the grant.

## Fix

Fix the condition through the portal admin API. A null `value_ref` is not drift and never fires this.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
