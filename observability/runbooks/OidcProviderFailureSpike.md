# OidcProviderFailureSpike

Severity: warning. Owner: `security`. Reported by {{node}}.

## Meaning

Sign-ins through one OpenID Connect provider are failing more than ten times their one-hour average, and over once a minute, for five minutes. People who sign in with that provider cannot get in.

## Checks

1. Break it down by `kind` in `oidc_provider_failures_total`: `discovery`, `jwks`, `token_exchange`, `id_token_rejected` or `clock_skew`.
2. `GET /api/v1/admin/security/oidc-providers/{id}/health` shows the provider's last failure and its counts on the answering node.
3. `discovery` or `jwks`: the provider is unreachable from {{node}}, or its address changed; check the issuer URL and outbound access.
4. `token_exchange`: the client secret was rotated at the provider, or the redirect address is no longer registered there.
5. `clock_skew`: this node's clock or the provider's has drifted; check time synchronisation.
6. `id_token_rejected`: the audience, issuer or signing key no longer matches the provider's configuration.

## Fix

Update the provider's issuer, client secret or keys in the provider admin (or `oidc.providers` for a configured one), restore outbound access, or fix the clock. People can still sign in with a password or another provider meanwhile.

## Escalation

Escalate to the security on-call if the provider itself is down or the failures look like someone probing the sign-in. This deployment's alert recipients: {{alert_emails}}.
