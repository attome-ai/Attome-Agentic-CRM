# RedisCoordinationDown

Severity: critical. Owner: `platform`. Reported by {{node}}.

## Meaning

The coordination pool (`cache.roles.coordination`) fails its ping. S2S nonce and rate-limit checks, the HTTP rate limiter and the idempotency gate fail closed: expect 401, 429 and 500 answers on ordinary requests.

## Checks

1. On a deployment that has not split the role this fires with `RedisDown` for the same cause ({{cache}}).
2. Check the coordination store's process, logs and network path from {{node}}.

## Fix

Recover it as for `RedisDown`, on the coordination endpoint.

## Escalation

Escalate to the platform on-call. This deployment's alert recipients: {{alert_emails}}.
