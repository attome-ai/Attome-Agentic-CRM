# SloLatencyBurnSlow

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

More than 6% of one SLO class's requests were over budget in both the last 6 hours and the last 30 minutes. The 30-day budget runs out in about five days.

## Checks

1. Graph `attome:slo_latency_bad:ratio_rate6h` by `slo_class` and find when it began to climb.
2. Work it like `SloLatencyBurnFast` from that time.

## Fix

File a ticket, not a page, and fix the slow path before the budget is gone.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
