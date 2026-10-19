# HttpRejectionsSpike

Severity: warning. Owner: `security`. Reported by {{node}}.

## Meaning

One protective layer (`waf`, `flood`, `pre_auth_rate_limit`, `rate_limit`, `body_limit`, `host_gate`, `csrf` or `auth`) is refusing more than ten times its one-hour average, and over one request a second, for five minutes.

## Checks

1. Break it down by `reason` in `http_rejections_total`.
2. `auth`/`invalid_session` right after a release is a broken sign-in or a rotated key, not an attack.
3. `waf`, `flood` or `pre_auth_rate_limit` from a few addresses is a scan or a flood.
4. `csrf`/`cross_site` is a page posting from another origin, or an origin missing from `cors.allowed_origins`.
5. No label carries a path, address or user: use the request-id-tagged server logs on {{node}}.

## Fix

Fix the release or key for an `auth` spike; block the source at the edge if a flood persists; add the missing origin for `csrf`.

## Escalation

Escalate to the security on-call; treat it as a possible incident until ruled out. This deployment's alert recipients: {{alert_emails}}.
