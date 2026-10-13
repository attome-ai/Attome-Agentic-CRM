# Keycloak test IdP (D-108)

Throwaway identity provider for `../keycloak_oidc.rs` — the live-IdP verification
P2.8 (`document/detailed-plans/P2.8-identity-mfa-sso.md`) had flagged as still owed.
Not a production topology recipe; see `docker-compose.yml`'s own header comment.

SAML was removed from the platform (OIDC is the sole federation protocol), so this
realm no longer carries a SAML client or the frozen assertion fixtures that once
lived under `fixtures/`.

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

`http://localhost:9999` is a fixed, never-bound placeholder `frontend_url` — the tests
reach their own backend entirely via in-process `tower::ServiceExt::oneshot`, never a
real socket on that port.
