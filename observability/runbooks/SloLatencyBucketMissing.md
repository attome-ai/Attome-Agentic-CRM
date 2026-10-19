# SloLatencyBucketMissing

Severity: warning. Owner: `platform`. Reported by {{node}}.

## Meaning

An SLO class is serving traffic but the request histogram has no `le` bucket at its p99 budget, so its latency burn alerts cannot measure anything.

## Checks

1. List the exported buckets: `curl {{metrics_url}} | grep axum_http_requests_duration_seconds_bucket | grep -o 'le="[^"]*"' | sort -u`.
2. Compare them with the budgets in `observability/slo-catalogue.json`.

## Fix

Add the missing boundary to `attome_server::metrics::HTTP_DURATION_BUCKETS` (its test pins every SLO budget) and release.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
