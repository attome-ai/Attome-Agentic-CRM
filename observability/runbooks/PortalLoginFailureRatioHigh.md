# PortalLoginFailureRatioHigh

Severity: warning. Owner: `security`. Reported by {{node}}.

## Meaning

More than half of portal password logins over 15 minutes, across at least 20 attempts, ended `bad_credentials` or `locked`.

## Checks

1. Read the `portal_request` spans and warn logs.
2. Many attempts on a few accounts or from a few sources is credential stuffing (`SecurityAnomalyRateHigh{reason="portal_budget"}`).
3. A jump across every account right after a release or portal config change is a login defect or a broken credential import.

## Fix

Tighten the portal's address allow-list or budget against stuffing; roll back the change behind a defect.

## Escalation

Escalate to the security on-call; treat it as a possible incident until ruled out. This deployment's alert recipients: {{alert_emails}}.
