# RedisPersistenceDisabled

Severity: critical. Owner: `security`. Reported by {{node}}.

## Meaning

The coordination store has no persistence policy, so a restart drops in-window S2S replay nonces and unflushed access-log entries.

## Checks

1. `CONFIG GET save` / `appendonly` on Redis, or the `--snapshot_cron` flag on Dragonfly.

## Fix

Set `--snapshot_cron` on Dragonfly, or `save`/`appendonly` on Redis, and restart. Dragonfly still loses up to one snapshot interval.

## Escalation

Escalate to the security on-call; treat it as a possible incident until ruled out. This deployment's alert recipients: {{alert_emails}}.
