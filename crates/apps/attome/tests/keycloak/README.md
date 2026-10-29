# Keycloak test IdP (D-108)

Throwaway identity provider for `../keycloak_oidc.rs` — the live-IdP verification
P2.8 (`document/detailed-plans/P2.8-identity-mfa-sso.md`) had flagged as still owed.
Not a production topology recipe; see `docker-compose.yml`'s own header comment.

SAML was removed from the platform (OIDC is the sole federation protocol, V2-D471):
Attome never reads a SAML message. A SAML identity provider reaches Attome through a
broker that speaks OIDC, which `../keycloak_saml_broker.rs` (Q2-T3) proves with a
second realm, below.

## Running it

```powershell
docker compose -f crates/server/tests/keycloak/docker-compose.yml up -d
# ... run the tests (see keycloak_oidc.rs's header) ...
docker compose -f crates/server/tests/keycloak/docker-compose.yml down -v
```

`realm-export.json` defines:
- realm `attome-test`
- one user, `attome-test-user` / `attome-test-Passw0rd!`, email
  `attome-test-user@attome-test.invalid`, pre-verified
- one OIDC confidential client `attome-oidc-test` (secret
  `oidc-test-client-secret-throwaway`, redirect URI
  `http://localhost:9999/api/v1/auth/oidc/keycloak/callback`)

`realm-export.json` also brokers identity provider `saml-idp` (Q2-T3): the
`saml-idp` realm in `saml-idp-realm.json`, by HTTP-Redirect, unsigned, email as the
NameID; its email, first and last name are imported, and a SAML `groups` value of
`sales` puts the person in the `sales` group (`saml-advanced-group-idp-mapper`), so the
OIDC client's `groups` claim carries it. `saml-idp-realm.json` defines:
- realm `saml-idp`, with group `sales`
- one user, `saml.user` / `saml-user-Passw0rd!`, email `saml.user@example.test`, in `sales`
- one SAML client `attome-test-broker` (the `attome-test` realm's broker), passing
  `email`, `firstName`, `lastName` and `groups`

The broker's URLs name `http://localhost:8090`, the port this compose file maps;
with another `KEYCLOAK_BASE_URL` the SAML tests need those URLs changed too.

`http://localhost:9999` is a fixed, never-bound placeholder `frontend_url` — the tests
reach their own backend entirely via in-process `tower::ServiceExt::oneshot`, never a
real socket on that port.
