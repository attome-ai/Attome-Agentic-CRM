# SloLatencyBurnFast

Severity: critical. Owner: `platform`. Reported by {{node}}.

## Meaning

More than 14.4% of one SLO class's requests were over its p99 budget in both the last hour and the last 5 minutes, with more than one request a second. That spends the 30-day budget in about two days. The alert carries `slo_class`, `slo_route` and `slo_p99_ms`.

## Checks

1. Find what changed: a release, a config or metadata change (a new view, stored query or field on a hot entity), or load.
2. Read the slow requests' request ids in the request-id-tagged server logs on {{node}}.
3. S1 and S2 point at the middleware (`RedisCoordinationLatencyHigh`; for S2 the password hashing). S4, S5 and S6 point at the database (`DbPoolNearExhaustion`, `ReplicaLagHigh`, a query plan). S6 also slows when the audit chainer backs up (`AuditChainerLagHigh`).
4. Graph `attome:slo_latency_bad:ratio_rate1h` by `slo_class` to see when the burn started.

## Fix

Undo or fix the change that started the burn. A deployment changes its own latency target at `{{api_base}}/api/v1/admin/slo/targets/{class_id}`, never in the catalogue.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
