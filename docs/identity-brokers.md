# Signing in with a SAML identity provider through a broker

Attome signs people in with **OpenID Connect only**. It has no SAML endpoint: it never
receives a SAML assertion and never publishes SAML metadata. A customer whose identity
provider speaks only SAML puts an **identity broker** between the two: the broker trusts
the SAML provider, and Attome trusts the broker over OpenID Connect.

```
person ──▶ Attome ──OIDC──▶ broker (Entra ID, Okta, AD FS or Keycloak) ──SAML──▶ customer IdP
```

Single logout through the broker is not designed: signing out of Attome ends the Attome
session only, and signing out at the SAML provider does not end it.

## What every broker needs

**Redirect URI.** Register exactly:

```
https://<your-attome-host>/api/v1/auth/oidc/<provider>/callback
```

`<provider>` is the key you choose for the broker in Attome's configuration (`entra`,
`okta`, `adfs`, `keycloak`, ...). It must match on both sides.

**Claims.** Attome reads these from the ID token:

| Claim | Why |
|---|---|
| `sub` | the person's identity at the broker, linked to their Attome account |
| `email` (or the claim named by `email_claim`) | matches the person's Attome account by email on first sign-in, or creates it (a licence seat is needed) |
| `email_verified` | required by default; a provider that never sends it needs `"require_email_verified_claim": false`, and only if you trust its email values |
| `amr` or `acr` | counts the provider's multi-factor sign-in as MFA in Attome (see below) |
| `auth_time` | how fresh the sign-in is, for step-up |

Attome reads no `name` or `groups` claim today: names and roles are kept in Attome.
Releasing them does no harm.

**Attome configuration.** In `config.json`, under `oidc.providers` (secrets come from the
environment, never the file):

```json
"oidc": {
  "providers": {
    "keycloak": {
      "display_name": "Company sign-in",
      "issuer": "https://sso.example.com/realms/attome",
      "client_id": "attome",
      "client_secret": "${OIDC_KEYCLOAK_SECRET}",
      "scopes": ["openid", "email", "profile"],
      "mfa_acr_values": ["mfa"],
      "trust_idp_mfa": true
    }
  }
}
```

`issuer` has no trailing slash, and `<issuer>/.well-known/openid-configuration` must
answer. Restart Attome after a change; the login page then shows the provider's button.

**MFA and step-up.** When `trust_idp_mfa` is true and the ID token's `amr` contains, or its
`acr` equals, one of `mfa_acr_values`, the sign-in counts as multi-factor, so a policy
that requires MFA is met without Attome's own factor. For a sensitive action Attome asks
for a fresh sign-in (step-up): it sends the broker `prompt=login` and `max_age`, and
accepts only a token whose `auth_time` is fresh. The broker must pass that on to the SAML
provider as a forced authentication (`ForceAuthn`); a broker that only re-checks its own
session proves a fresh sign-in at the broker, not at the SAML provider.

**Email-first sign-in and domains.** A provider added on screen (Security > Sign-in
providers) signs in only people whose email domain is verified for it. A configured provider
in `config.json` needs no domain.
1. Add the domain: `POST /api/v1/admin/security/oidc-domains` with `provider_id` and
   `domain`. The answer gives a TXT record name, `_attome-verify.<domain>`, and its value,
   `attome-verify=<token>`.
2. Publish that record at your DNS host.
3. Check it: `POST /api/v1/admin/security/oidc-domains/{id}/verify` looks the record up
   (at most 5 seconds) and marks the domain verified, or says why not.

Once a domain is verified, `POST /api/v1/auth/oidc/discover` with an email on that domain
answers the provider's key, so the sign-in page can send the person straight to it. Any
other email answers `null`. The route never says whether an account exists.

**Groups to teams and roles.** A provider added on screen can map values of its groups
claim (named by `claim_map.groups`, `groups` by default) to a team or a role:
`POST /api/v1/admin/security/oidc-providers/{id}/group-mappings` with `claim_value` and
`team_id` or `role_id`.

- **At each sign-in** the person gets what their groups map to, and loses what this
  provider gave earlier that their groups no longer map to.
- **Administrator grants stay.** A team or role an administrator gave is never removed,
  and when an administrator grants one the provider gave, it becomes theirs.
- **Never administration.** A mapping to a role with system administration, or to a team
  with such a role, is refused (`mapping_cannot_grant_admin`), and skipped at sign-in if
  the role gains it later.
- **Exempt accounts.** Break-glass and service accounts are left alone.
- **Profile.** The `name` and `phone` claims in the claim map update the person's name and
  phone. Attome has no title, department or manager field to fill.

**Entra tenants.** A provider's `tenant_allowlist` limits it to those tenants. A token
whose `tid` is missing or not listed is refused, and the person lands on the login page
with `tenant_not_allowed`.

**Sign-out.** Two settings on the broker's client make signing out work both ways.

- **Post-logout redirect URI:** register `https://<your-attome-host>`. When someone
  signs out of Attome, Attome ends its own session first. If the broker's discovery
  document has an `end_session_endpoint`, the browser then goes there with `client_id`
  and this URI, so the broker ends its session too and sends the person back.
- **Back-channel logout URL:** register
  `https://<your-attome-host>/api/v1/auth/oidc/<provider>/backchannel-logout`. When the
  person signs out at the broker, the broker posts a signed logout token there. Attome
  ends every session signed in through that broker for the token's `sid`, or for its
  `sub` when it names no session. Those sessions stop at once, not when their access
  token expires.
  - Attome checks the token's signature against the broker's keys, its issuer and
    audience, an `iat` within five minutes and the back-channel logout event, and
    refuses a token used before.
  - Sessions from a password or from another provider stay signed in.
  - Ask the broker to put `sid` in ID tokens (Keycloak and Entra ID do). Without it, a
    logout ends every session the person has through that broker.

## Microsoft Entra ID

Use this when the SAML provider is federated into Entra ID (External Identities, SAML/WS-Fed
identity provider federation) or Entra ID is the company directory itself.

1. **App registrations → New registration**: a *Web* platform with the redirect URI above
   (`<provider>` = `entra`).
2. **Certificates & secrets**: add a client secret; put it in the environment.
3. **Token configuration**: add the optional claims `email` and, for users without a
   mailbox, `upn` (then set `email_claim` to `upn`).
4. Entra ID sends no `email_verified` claim: set `"require_email_verified_claim": false`
   only for a tenant whose email values you trust.
5. For MFA, Entra ID puts `mfa` in `amr`: `"mfa_acr_values": ["mfa"]`.
6. Issuer: `https://login.microsoftonline.com/<tenant-id>/v2.0`.
7. Step-up: Entra ID honours `prompt=login`; with a federated SAML provider it forwards a
   forced sign-in to it.

## Okta

1. **Security → Identity Providers → Add identity provider → SAML 2.0**: import the customer
   provider's metadata, map `NameID` or the email attribute to the Okta username, and add
   a routing rule that sends the customer's domain to it.
2. **Applications → Create App Integration → OIDC → Web Application**: sign-in redirect URI
   as above (`<provider>` = `okta`); grant type *Authorization Code*.
3. Assign the people or groups that may use Attome.
4. Issuer: `https://<your-org>.okta.com` (org authorization server) or
   `https://<your-org>.okta.com/oauth2/default`.
5. Okta sends `email_verified`. For MFA it puts `mfa` in `amr`: `"mfa_acr_values": ["mfa"]`.
6. Step-up: Okta honours `prompt=login`; in the SAML identity provider's settings turn on
   *Force authentication* so the customer provider asks again.

## AD FS (2016 or later)

AD FS speaks OpenID Connect through an application group, and can itself trust a SAML
claims provider.

1. **Claims Provider Trusts**: add the customer's SAML provider (if AD FS is not the
   provider itself).
2. **Application Groups → Add → Server application accessing a web API**: the redirect URI
   as above (`<provider>` = `adfs`), and generate a shared secret.
3. In the web API part, grant `openid`, `email` and `profile`, and add an issuance transform
   rule that sends `email` (from *E-Mail-Addresses*).
4. AD FS sends no `email_verified`: set `"require_email_verified_claim": false` if you trust
   the directory's email values.
5. For MFA, AD FS puts `http://schemas.microsoft.com/claims/multipleauthn` in `amr`:
   `"mfa_acr_values": ["http://schemas.microsoft.com/claims/multipleauthn"]`.
6. Issuer: `https://<adfs-host>/adfs`.
7. Step-up: AD FS honours `prompt=login`, and forwards a forced sign-in to a trusted SAML
   claims provider.

## Keycloak

1. In the realm, **Identity providers → SAML v2.0**: import the customer provider's metadata
   (or its descriptor URL); set the first-broker-login flow; turn on *Force authentication*
   if every step-up must reach the SAML provider; map the email attribute to `email` and
   mark it verified (*Trust email*) when the provider's email values are trusted.
2. **Clients → Create client → OpenID Connect**: client ID `attome`, *Client
   authentication* on, *Standard flow* on; valid redirect URI as above
   (`<provider>` = `keycloak`); copy the secret from *Credentials*.
3. For MFA, map a level of authentication to an `acr` value in the client's
   *ACR to LoA mapping* (for example `mfa` → 2) and set `"mfa_acr_values": ["mfa"]`.
4. Issuer: `https://<keycloak-host>/realms/<realm>`.

### Running Keycloak as the broker

Keycloak is a separate service the customer runs and keeps up to date; Attome does not
ship, start or upgrade it.

- **Natively** (Java 21, on Windows or Linux): unpack the Keycloak distribution, then
  ```
  bin/kc.sh start --hostname=https://sso.example.com --https-certificate-file=... --https-certificate-key-file=...
  ```
  (`bin\kc.bat` on Windows). Run it as a service with the system's service manager
  (systemd on Linux, a Windows service wrapper on Windows), backed by its own PostgreSQL
  database (`--db=postgres --db-url=...`), not Attome's.
- **In a container**:
  ```
  docker run -p 8443:8443 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=... \
    quay.io/keycloak/keycloak:26.0 start --hostname=https://sso.example.com
  ```
- **Import a realm** prepared elsewhere: `bin/kc.sh import --file realm.json` (stopped
  server), or *Realm settings → Partial import* in the console.

Then add the customer's SAML provider and the Attome client as above, and point
`oidc.providers.keycloak.issuer` at the realm.

## Checking the setup

1. Open Attome's login page: the provider's button shows `display_name`.
2. Sign in: the broker sends you to the SAML provider and back to
   `/api/v1/auth/oidc/<provider>/callback`.
3. If Attome refuses the sign-in, check that the ID token carries `email` (and
   `email_verified`, unless it is turned off), that the issuer matches exactly, and that the
   redirect URI matches on both sides.
