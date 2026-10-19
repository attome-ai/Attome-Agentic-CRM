# ChangesPaused

Severity: info. Owner: `platform`. Reported by {{node}}.

## Meaning

The deployment is read-only: an operator paused changes, or the database reached `deployment.read_only_at_database_bytes`. Reads work; writes answer `503 read_only`.

## Checks

1. The server log on {{node}} names the reason when the mode turns on.
2. The status banner at {{app_url}} shows it too.

## Fix

Free database space or raise the ceiling, or lift the operator's pause.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
