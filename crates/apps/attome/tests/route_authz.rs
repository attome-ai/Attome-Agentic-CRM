//! Structural authorization coverage over every mounted application route.
//!
//! # What this adds on top of the `Authorized<P>` extractor
//!
//! `attome_server::authz` moved the admin check into the type system: a handler
//! that names `Authorized<Admin>` provably ran that check, and cannot forget
//! it. That closes the "forgot the `require_admin()` line" hole for handlers
//! that opt in. It cannot close two others, because both live *outside* any
//! handler's body:
//!
//! 1. **A route whose handler names no policy at all.** Nothing forces a
//!    handler to take an `Authorized<P>`. One that asks for neither a policy
//!    nor the caller's identity still compiles and still mounts. The type
//!    system only helps once you opt in, and the thing being audited is
//!    precisely whether someone did. (The specific old shape —
//!    `Extension(ctx): Extension<SecurityContext>` — is separately a compile
//!    error since D-300, because `SecurityContext` is not `Clone`;
//!    `no_handler_extracts_a_bare_security_context` below pins that.)
//!
//! 2. **A route gated by a policy that does not enforce.** Bare
//!    `RecordScoped` and `SelfService` are declarations, not checks — their
//!    `authorize` admits every authenticated caller by design (see their doc
//!    comments). They are the right tool where the handler gates dynamically
//!    or acts only on the caller's own rows, and the wrong tool on an admin
//!    surface. Nothing in the type system distinguishes
//!    `Authorized<SelfService>` from `Authorized<Admin>` on a
//!    `/api/v1/admin/…` path; `admin_surface_routes_are_gated_by_an_enforcing
//!    _policy` below does. And since D-353 `RecordScoped` is only a
//!    declaration when it is *bare*: `RecordScoped<Read>` resolves the
//!    `{entity}` segment and performs the check in the extractor, so this file
//!    reads the type argument, not just the outer name, and
//!    `bare_record_scoped_routes_ratchet_downward` drives the unparameterised
//!    remainder toward zero.
//!
//! So this is a router-level census, complementary to the extractor rather
//! than a substitute for it: every `.route(...)` registration **anywhere under
//! `crates/`** is parsed out of the sources — `attome-server` (health, metrics),
//! `server` (auth, federation), `attome-api`, `attome-security`, `attome-workflow`
//! and `attome-notification` all mount routes into the one composed router — and
//! each handler must be authorized by one of
//!
//! - an **enforcing** policy in its signature (`Authorized<Admin>`,
//!   `Authorized<Privilege<K>>`, `Authorized<RecordScoped<A>>`),
//! - a `require_admin()` / `require(entity, action)` / `require_key(key)` call
//!   in its body or in a helper it delegates to (the pre-extractor form, still
//!   correct and still present),
//! - a **declaring** policy (bare `Authorized<RecordScoped>`,
//!   `Authorized<SelfService>`) — the intent is then explicit in the signature
//!   and greppable, which is the property being enforced here, or
//! - an entry in `CALLER_SCOPED_ROUTES`, for a handler that predates the
//!   extractor and has neither.
//!
//! # What it does not prove
//!
//! That a check is *present*, not that it is *correct*: a handler could name
//! `Authorized<Admin>` on a route that should have required more, or declare
//! `RecordScoped` and then perform the wrong `require`. The behavioural half
//! lives in `tests/authz.rs` and `tests/record_level_security.rs`.
//!
//! # Why source scanning
//!
//! Axum exposes no route-introspection API, so the real `Router`'s paths
//! cannot be enumerated; and asserting 403 per route against a live server
//! would need Postgres + Redis + S3 and a seeded unprivileged principal, so it
//! would skip exactly when someone runs the suite without infrastructure. This
//! runs anywhere, in milliseconds, with no services.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Policies whose `authorize` actually rejects somebody regardless of how they
/// are parameterised. `RecordScoped` is deliberately absent — it belongs to
/// both camps depending on its argument, which is what `Policy::enforces`
/// decides.
const ENFORCING_POLICIES: &[&str] = &["Admin", "Privilege"];

/// Policies that admit every authenticated caller. `RecordScoped` qualifies
/// only in its bare/`Dynamic` spelling; see `Policy::enforces`.
const DECLARING_POLICIES: &[&str] = &["RecordScoped", "SelfService"];

const RECORD_SCOPED: &str = "RecordScoped";

/// `attome_server::authz::Dynamic` — the explicit spelling of "bare
/// `RecordScoped`", i.e. the verb is only knowable at runtime.
const DYNAMIC_ACTION: &str = "Dynamic";

/// Ceiling on route bindings still gated by a bare `RecordScoped` (D-353).
///
/// A ratchet, not a budget: every one of these is a route where the type
/// system knows nothing and correctness rests on a `require` call in the
/// handler body. Converting one to `RecordScoped<A>` means lowering this
/// number in the same commit — the test fails when the count drops below it
/// too, so the ratchet cannot quietly rust in the loose direction either.
///
/// Two of the seven are the routes whose entity is genuinely not a path
/// segment at all, so there is nothing for the extractor to resolve:
///
/// - `query_exec::execute` — the entity comes from the stored query row, and
///   a multi-entity query has several.
/// - `aggregate::aggregate` — the entity is a body field, resolved against
///   the database (by id *or* logicalname) before the `require` can be made.
///
/// Raised from 1 to 2 deliberately (SEC-6, 2026-08-24): four handlers had
/// drifted in under the old ceiling. Three were converted in the same commit
/// — `documents_tree::get_tree`/`create_folder` to
/// `Privilege<DocumentRead>`/`Privilege<DocumentCreate>`, since their entity
/// is fixed in the source rather than dynamic, and
/// `widget_catalog::widget_types` to `SelfService`, which is what it always
/// meant. `aggregate` is the one that genuinely belongs here.
///
/// **Found already at 6, not 2, on `main` (2026-09-18), before this branch's
/// own change.** `list_predictions`, `quote_events`, `withdraw_consent` and
/// `ingest_signal` drifted in from unrelated work with the ceiling never
/// raised to match — i.e. this specific test was already failing on `main`
/// (verified against a clean checkout) when the Dashboard 10/10 Phase 6
/// prerequisite work below started. Raising the ceiling to 6 here records
/// that reality rather than leaving it silently red; auditing/fixing those
/// four is unrelated cleanup, out of scope for this change, and not done
/// here — see `document/decisions/security/D-551.md`'s consequences section.
///
/// Raised from 6 to 7 deliberately (Dashboard 10/10 Phase 6, D-551,
/// 2026-09-18) for `approval_admin::decide_approval_eligible` —
/// `POST /api/v1/approvals/{id}/decide`'s "entity" is really "is this caller
/// among this approval request's *current step*'s resolved eligible
/// approvers/delegates", which only `attome_approval::decide_step_with`'s
/// `allowed_decider_ids.contains` check (inside its own advisory-locked
/// transaction, after resolving the request's plan and step from the
/// database) can answer — there is no static verb this route could name.
///
/// Raised from 5 to 6 deliberately (AA7-T4, 2026-10-23) for
/// `query_exec::changes` — `POST /api/v1/query/changes` names its entity in
/// the body, as `execute` does, and each record is filtered by the caller's
/// record-level access before it is returned.
///
/// If this ever reaches 0, delete the constant and both halves of
/// `bare_record_scoped_routes_ratchet_downward` rather than leaving a floor
/// nothing can trip.
const MAX_BARE_RECORD_SCOPED: usize = 6;

/// Routes carrying neither an `Authorized<P>` policy nor a `require_*` call,
/// each with the reason it is safe. Verified by reading every handler.
///
/// This list is a migration bridge and is expected to shrink to nothing as
/// handlers adopt the extractor — `Authorized<SelfService>` states the same
/// thing in the signature, where it cannot drift out of sync with the route.
/// Deleting an entry is the normal outcome of converting its handler, and
/// `allow_list_has_no_stale_entries` will tell you when: an entry whose route
/// has gained a posture of its own, or has stopped being mounted at all, is a
/// failure rather than dead weight, because an exemption that outlives its
/// route silently pre-authorizes whatever later claims that path.
const CALLER_SCOPED_ROUTES: &[(&str, &str, &str)] = &[
    (
        "POST",
        "/api/v1/hooks/{name}",
        "M14-T1: a provider's call to a builder-defined hook; the hook's own address allow-list, mTLS, signature or bearer secret (constant-time), timestamp window and once-only event id are the credential, and its handler runs as the hook's service user through the ordinary write paths. Bypass-listed by its one-segment shape.",
    ),
    (
        "GET",
        "/scim/v2/Users",
        "Q3-T1: the SCIM bearer token of one identity provider (peppered hash, address allow-list) is the credential; it provisions only users and teams, each change audited. Bypass-listed by the /scim/v2/ prefix.",
    ),
    (
        "POST",
        "/scim/v2/Users",
        "Q3-T1: the SCIM bearer token of one identity provider (peppered hash, address allow-list) is the credential; it provisions only users and teams, each change audited. Bypass-listed by the /scim/v2/ prefix.",
    ),
    (
        "GET",
        "/scim/v2/Users/{id}",
        "Q3-T1: the SCIM bearer token of one identity provider (peppered hash, address allow-list) is the credential; it provisions only users and teams, each change audited. Bypass-listed by the /scim/v2/ prefix.",
    ),
    (
        "PUT",
        "/scim/v2/Users/{id}",
        "Q3-T1: the SCIM bearer token of one identity provider (peppered hash, address allow-list) is the credential; it provisions only users and teams, each change audited. Bypass-listed by the /scim/v2/ prefix.",
    ),
    (
        "PATCH",
        "/scim/v2/Users/{id}",
        "Q3-T1: the SCIM bearer token of one identity provider (peppered hash, address allow-list) is the credential; it provisions only users and teams, each change audited. Bypass-listed by the /scim/v2/ prefix.",
    ),
    (
        "DELETE",
        "/scim/v2/Users/{id}",
        "Q3-T1: the SCIM bearer token of one identity provider (peppered hash, address allow-list) is the credential; it provisions only users and teams, each change audited. Bypass-listed by the /scim/v2/ prefix.",
    ),
    (
        "GET",
        "/scim/v2/Groups",
        "Q3-T1: the SCIM bearer token of one identity provider (peppered hash, address allow-list) is the credential; it provisions only users and teams, each change audited. Bypass-listed by the /scim/v2/ prefix.",
    ),
    (
        "POST",
        "/scim/v2/Groups",
        "Q3-T1: the SCIM bearer token of one identity provider (peppered hash, address allow-list) is the credential; it provisions only users and teams, each change audited. Bypass-listed by the /scim/v2/ prefix.",
    ),
    (
        "GET",
        "/scim/v2/Groups/{id}",
        "Q3-T1: the SCIM bearer token of one identity provider (peppered hash, address allow-list) is the credential; it provisions only users and teams, each change audited. Bypass-listed by the /scim/v2/ prefix.",
    ),
    (
        "PATCH",
        "/scim/v2/Groups/{id}",
        "Q3-T1: the SCIM bearer token of one identity provider (peppered hash, address allow-list) is the credential; it provisions only users and teams, each change audited. Bypass-listed by the /scim/v2/ prefix.",
    ),
    (
        "DELETE",
        "/scim/v2/Groups/{id}",
        "Q3-T1: the SCIM bearer token of one identity provider (peppered hash, address allow-list) is the credential; it provisions only users and teams, each change audited. Bypass-listed by the /scim/v2/ prefix.",
    ),
    (
        "POST",
        "/api/v1/approvals/email-link",
        "M9-T3: the single-use emailed link token (peppered HMAC, one approver, one request step, 72 h) is the credential; it reads only the request that link names and uses nothing. Bypass-listed.",
    ),
    (
        "POST",
        "/api/v1/approvals/email-link/decide",
        "M9-T3: the same link token, used once, decides only its own request step as its own approver through the decide route's path (eligibility and separation of duties checked there); a high-risk request is refused. Bypass-listed.",
    ),
    (
        "GET",
        "/api/v1/status/confirm",
        "H8-T1: a static page with one button for the token it was given; it reads nothing and changes nothing (a mail scanner fetching the link confirms nothing). Bypass-listed.",
    ),
    (
        "POST",
        "/api/v1/status/confirm",
        "H8-T1: the signed link (HMAC under the status-subscriber domain, seven days, over one address) is the credential and confirms only that address's status emails. Bypass-listed.",
    ),
    (
        "GET",
        "/api/v1/status/unsubscribe",
        "H8-T1: a static page with one button for the token it was given; it reads nothing and changes nothing. Bypass-listed.",
    ),
    (
        "POST",
        "/api/v1/status/unsubscribe",
        "H8-T1: the signed link from a status email is the credential and only stops that address's status emails. Bypass-listed.",
    ),
    (
        "GET",
        "/api/v1/esign/sign/{token}",
        "K4-T1 signer's page: the signed link (HMAC under the esign domain, 30 days, over one signer) is the credential and shows only that envelope's title, documents' names and hashes and the signer's own status; a draft or voided envelope is the same 404. Bypass-listed by an exact single-segment match.",
    ),
    (
        "POST",
        "/api/v1/esign/sign/{token}",
        "K4-T1 signer's action: the signed link names the signer, and signing or declining also needs the emailed one-time code (peppered hash, five minutes, one use, five tries; at most one code a minute). Bypass-listed by an exact single-segment match; every step is a hash-chained event and an audited business event.",
    ),
    (
        "GET",
        "/.well-known/jwks.json",
        "Z4-T4: the public halves of the Ed25519 token-signing keys, a JSON Web Key Set; publishing them is the point and no secret or customer data is in it. Bypass-listed.",
    ),
    (
        "GET",
        "/api/v1/auth/challenge",
        "Q20-T3: a signed proof-of-work challenge for a sign-in or sign-up that has no session yet; it reads no data and stores nothing. Bypass-listed.",
    ),
    (
        "POST",
        "/api/v1/security/csp-report",
        "Q21-T2 CSP violation reports: browsers send them with no credential. It reads only the report body (16 KiB at most), counts it by directive and logs the blocked source's scheme and host; nothing is stored and nothing is returned. Bypass-listed by an exact match and rate-limited per address.",
    ),
    (
        "GET",
        "/api/v1/shared-files/{token}",
        "K1-T1 external file share: the 32-byte random token, stored only as its SHA-256, is the credential for one stored file. Bypass-listed and rate-limited (portal_status); expiry, revocation, the download limit and a required password are checked inside the handler, and each download is audited.",
    ),
    (
        "POST",
        "/api/v1/shared-files/{token}",
        "K1-T1 password-protected share: the token plus an Argon2id-checked password open one stored file. Bypass-listed and rate-limited (password_reset) against guessing; expiry, revocation and the download limit are checked inside the handler.",
    ),
    (
        "POST",
        "/api/v1/billing/gateways/{system}/webhook",
        "F5-T7 payment gateway webhook: the gateway has no session. Bypass-listed by an exact segment match and rate-limited per address; the adapter verifies every call with the gateway's webhook secret (Moyasar's secret token in constant time, HyperPay's AES-GCM tag) before anything is stored, and the job that applies the events is audited.",
    ),
    (
        "GET",
        "/api/v1/pay/{token}",
        "F5-T8 payment page: the link's random secret, stored only as a peppered hash, is the credential for one link. Bypass-listed by an exact match and rate-limited per address; a wrong, expired, used or cancelled link is the same 404.",
    ),
    (
        "POST",
        "/api/v1/pay/{token}/checkout",
        "F5-T8 payment page checkout: the same link secret is the credential; it only saves a pending payment and asks the gateway for a checkout. Bypass-listed by an exact match and rate-limited per address; the payment is audited when it succeeds.",
    ),
    (
        "GET",
        "/api/v1/branding/asset",
        "A published logo, favicon or font for the sign-in page, before anyone signs in. Bypass-listed; the guidelines PDF is refused, and nothing user-specific is served.",
    ),
    (
        "GET",
        "/api/v1/branding/public",
        "The published brand (colours, fonts, whether to hide the vendor name) for the sign-in page, before anyone signs in. Bypass-listed; it returns no user or customer data.",
    ),
    (
        "POST",
        "/api/v1/consents/capture",
        "Public consent-form submission: no session exists for a data subject. Bypass-listed and rate-limited (consent_capture); the purpose key and subject are validated inside the handler.",
    ),
    (
        "POST",
        "/api/v1/cobrowse/join",
        "J9-T2: the customer joins with the six-character code the agent read out; it works once, for ten minutes, and any other code is the same 404. Bypass-listed and rate-limited (portal_status); the join is audited.",
    ),
    (
        "GET",
        "/api/v1/cobrowse/visitor/messages",
        "J9-T2: the customer side's frame token, stored only as its SHA-256, is the credential for one open session; it reads only the agent's frames of that session. Bypass-listed and rate-limited (webchat).",
    ),
    (
        "POST",
        "/api/v1/cobrowse/visitor/messages",
        "J9-T2: the same customer-side token sends frames into its one open session; the embed masks sensitive fields before sending. Bypass-listed and rate-limited (webchat).",
    ),
    (
        "POST",
        "/api/v1/cobrowse/visitor/end",
        "J9-T2: the same customer-side token ends its own session; the end is audited. Bypass-listed and rate-limited (webchat).",
    ),
    (
        "GET",
        "/api/v1/consents/confirm",
        "E27-T3 double opt-in: the emailed token, stored only as its hash and expiring, is the credential; the page only shows a confirm button. Bypass-listed and rate-limited (consent_capture).",
    ),
    (
        "POST",
        "/api/v1/consents/confirm",
        "E27-T3 double opt-in: the same hashed, expiring token confirms one pending consent once; the grant is audited. Bypass-listed and rate-limited (consent_capture).",
    ),
    (
        "GET",
        "/api/v1/consents/preferences",
        "E26-T1 preference centre: the link is signed with the token-signing key and names one subject; it reads only that subject's marketing consents. Bypass-listed and rate-limited (consent_capture).",
    ),
    (
        "POST",
        "/api/v1/consents/preferences",
        "E26-T1 preference centre: the same signed link changes only its own subject's marketing consents; each change is audited. Bypass-listed and rate-limited (consent_capture).",
    ),
    (
        "GET",
        "/health/ready",
        "Readiness probe: reports whether this node can serve safely (database, cache, registry pre-warm). Public by design so a load balancer can poll it; it returns no data.",
    ),
    (
        "GET",
        "/health/startup",
        "Startup probe: 200 once this node has finished booting. Public by design so an orchestrator can poll it; it reads no dependency and returns no data.",
    ),
    (
        "GET",
        "/health",
        "Liveness probe, mounted via with_liveness_routes so it never touches Redis/DB and a dependency blip cannot cause a restart storm.",
    ),
    (
        "GET",
        "/version",
        "Build/schema version for deployment preflight. No customer data, same unauthenticated diagnostic convention as the /health paths. D-345: the anonymous body is ALSO a fleet control-plane contract - fleet-migrations polls it credential-free (D-297 / P-fleet-control-plane 6), so the disclosure is accepted residual risk and the field set is not free to shrink.",
    ),
    (
        "GET",
        "/metrics",
        "Prometheus scrape, bound to a SEPARATE listener (observability.metrics_port), never merged into the public application router.",
    ),
    (
        "GET",
        "/api/v1/auth/register/config",
        "Public sign-up form configuration, fetched before any account or session exists. Bypass-listed.",
    ),
    (
        "POST",
        "/api/v1/auth/google",
        "Federated credential exchange - this call is what establishes the session, so no session can gate it. Bypass-listed.",
    ),
    (
        "GET",
        "/api/v1/auth/google/config",
        "Public federated-login configuration read by the sign-in page before any session exists. Bypass-listed.",
    ),
    (
        "POST",
        "/api/v1/auth/verify-email/confirm",
        "The emailed single-use token IS the authentication, same shape as reset-confirm. Bypass-listed.",
    ),
    (
        "POST",
        "/api/v1/auth/mfa/verify",
        "Login-time MFA step. The short-lived pending_token (distinct claims shape from SessionClaims) is the credential, validated in-handler.",
    ),
    (
        "POST",
        "/api/v1/auth/mfa/verify-recovery",
        "Login-time MFA recovery-code step, same pending_token credential as mfa/verify. Bypass-listed.",
    ),
    (
        "POST",
        "/api/v1/auth/mfa/pending-enroll",
        "Login-time forced enrolment, reached with only a pending_token when policy requires MFA before a session is issued.",
    ),
    (
        "POST",
        "/api/v1/auth/mfa/pending-confirm",
        "Login-time forced-enrolment confirmation, same pending_token credential as pending-enroll.",
    ),
    (
        "GET",
        "/api/v1/auth/oidc/providers",
        "Public provider discovery for the sign-in page, read before any session exists. Bypass-listed subtree.",
    ),
    (
        "GET",
        "/api/v1/auth/oidc/{provider}/login",
        "Starts the redirect out to the identity provider; the caller has no session yet by definition. Bypass-listed subtree.",
    ),
    (
        "GET",
        "/api/v1/auth/oidc/{provider}/callback",
        "IdP redirect back. A SameSite=Strict session cookie never survives the cross-site hop, so this cannot ride Extension<SessionClaims>.",
    ),
    (
        "GET",
        "/api/v1/auth/identity-link-callback/oidc/{provider}",
        "IdP redirect back for self-service linking. Deliberately a separate bypass prefix from the protected identity-link START routes.",
    ),
    (
        "GET",
        "/api/v1/auth/session",
        "Returns the caller's own session metadata (D-129). Reads claims.sub only; no other principal is reachable.",
    ),
    (
        "GET",
        "/api/v1/auth/identity-links",
        "Lists the caller's own federated identity links, keyed on claims.sub.",
    ),
    (
        "GET",
        "/api/v1/auth/step-up-callback/oidc/{provider}",
        "IdP redirect back for federated step-up (D-510 rule 5). A SameSite=Strict session cookie never survives the cross-site hop, so the user, family and operation come only from the single-use server-side state, bound to the browser that started it.",
    ),
];

/// `/api/v1/admin/…` routes allowed to be gated by something other than an
/// enforcing policy. Exactly one, and it should stay that way: an admin path
/// that admits every authenticated caller is the failure mode this whole file
/// exists to surface.
/// Routes where `Authorized<Privilege<K>>` is NOT an acceptable substitute for
/// `Authorized<Admin>` (SEC-8).
///
/// `admin_surface_routes_are_gated_by_an_enforcing_policy` proves every
/// `/api/v1/admin/` route names *some* enforcing policy, and treats `Admin` and
/// `Privilege<K>` as equally good. For almost every admin route that is right.
/// For these four it is not: a flat privilege key can be granted to an ordinary
/// role through `/api/v1/admin/security/...`, so swapping `Admin` for
/// `Privilege<SomeQueryKey>` would keep this whole file green while handing a
/// low-trust role the capability below.
///
/// The capability is authoring stored SQL, which `query_exec` later runs against
/// the readonly pool — the one place in the platform where a caller reaches the
/// database outside the metadata model. So the gate has to be the admin flag
/// itself (`system.admin`, seeded onto `security.bootstrap_admin_email` and
/// never onto a role — `attome-security/src/seed.rs`), not a key someone can
/// delegate.
///
/// D-384 established that this is the state today; nothing enforced it. That
/// entry is right that *publishing* only reaches the pool indirectly, via
/// `query_exec::execute` on a query an admin already opened up. One route here
/// is the exception and reaches it directly:
/// `describe_query` (`query_admin.rs:958`) passes caller-supplied `sql_query`
/// to `lint_and_plan(&state.base.db_readonly, ..)` and then
/// `db_readonly.describe(..)`, with nothing published in between. It is
/// `Authorized<Admin>` today, so the conclusion is unchanged — but it is the
/// sharpest reason this list exists.
///
/// Adding a route here is cheap; removing one is a deliberate decision about
/// who may write SQL.
const ADMIN_ONLY_ROUTES: &[(&str, &str, &str)] = &[
    (
        "POST",
        "/api/v1/admin/queries",
        "publishes a stored query — authoring SQL that query_exec runs on the readonly pool",
    ),
    (
        "PATCH",
        "/api/v1/admin/queries/{id}",
        "rewrites a published query's SQL, same capability as publishing one",
    ),
    (
        "DELETE",
        "/api/v1/admin/queries/{id}",
        "retires a query other routes and seeded views depend on",
    ),
    (
        "POST",
        "/api/v1/admin/queries/describe",
        "plans caller-supplied SQL against the readonly pool without publishing it",
    ),
];

const ADMIN_PATH_EXCEPTIONS: &[(&str, &str, &str)] = &[(
    "GET",
    "/api/v1/admin/security/whoami",
    "Reads only the caller's own resolved context; gating it on admin would \
     make it useless to exactly the non-admin callers it exists for.",
)];

/// A parser break that silently matched nothing would make this file pass
/// vacuously, which is worse than not having it. Floors sit comfortably below
/// the counts at the time of writing (170 routes / 213 handler bindings across
/// the whole workspace), so ordinary route churn does not trip them but a dead
/// scanner does.
const MIN_ROUTES: usize = 140;
const MIN_BINDINGS: usize = 175;

const HTTP_METHODS: &[&str] = &["get", "post", "put", "patch", "delete", "head", "options"];

// ── Source loading ────────────────────────────────────────────────────────────

/// Every crate in the workspace, not a hand-listed subset.
///
/// This test lives in `crates/server` — the binary that composes the whole
/// router — specifically so a workspace-wide scan is architecturally honest
/// rather than a sibling crate reaching sideways. Route registrations are
/// spread across `attome-server` (health/metrics), `server` (auth, federation),
/// `attome-api`, `attome-security`, `attome-workflow` and `attome-notification`; an
/// enumerated list would silently stop covering the next crate that mounts a
/// route, which is exactly the class of gap this file exists to catch.
fn source_roots() -> Vec<PathBuf> {
    // CARGO_MANIFEST_DIR is crates/server; the workspace root is two up.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root is two levels above crates/server")
        .to_path_buf();
    vec![root.join("crates")]
}

fn collect_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for root in source_roots() {
        walk(&root, &mut out);
    }
    assert!(
        !out.is_empty(),
        "no .rs sources found under {:?} — has the crate layout moved?",
        source_roots()
    );
    for (_, text) in out.iter_mut() {
        *text = blank_comments(text);
    }
    out
}

/// Replaces every comment's contents with spaces, preserving length so the
/// char indices the rest of this file relies on stay aligned.
///
/// Without this the scanner reads illustrative code out of doc comments as if
/// it were real. `attome_server::authz`'s module doc shows a worked example —
/// `async fn list_roles(... ctx: Authorized<Admin>)` — and because handler
/// definitions are indexed by bare name with *any* candidate allowed to
/// satisfy a check, that example silently vouched for the real
/// `attome_security::admin::roles::list_roles`. Downgrading that live handler to
/// `Authorized<SelfService>` still passed every assertion here until this was
/// added. A lint that can be disarmed by a doc comment is worse than none.
fn blank_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out: Vec<char> = Vec::with_capacity(chars.len());
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();

        // Line comment: blank to end of line, keeping the newline itself.
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }

        // Block comment (Rust allows nesting).
        if c == '/' && next == Some('*') {
            let mut depth = 0usize;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(if chars[i] == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
            }
            continue;
        }

        // Raw string: r"..." / r#"..."# — copied verbatim so a `//` inside a
        // URL or SQL fragment is never mistaken for a comment.
        if c == 'r' && matches!(next, Some('"') | Some('#')) {
            let mut hashes = 0usize;
            let mut j = i + 1;
            while chars.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if chars.get(j) == Some(&'"') {
                out.extend_from_slice(&chars[i..=j]);
                i = j + 1;
                loop {
                    if i >= chars.len() {
                        break;
                    }
                    if chars[i] == '"' {
                        let closes = (1..=hashes).all(|h| chars.get(i + h) == Some(&'#'));
                        if closes {
                            for k in i..=(i + hashes) {
                                if k < chars.len() {
                                    out.push(chars[k]);
                                }
                            }
                            i += hashes + 1;
                            break;
                        }
                    }
                    out.push(chars[i]);
                    i += 1;
                }
                continue;
            }
        }

        // Ordinary string literal, honouring escapes.
        if c == '"' {
            out.push(c);
            i += 1;
            while i < chars.len() {
                out.push(chars[i]);
                if chars[i] == '\\'
                    && let Some(&e) = chars.get(i + 1)
                {
                    out.push(e);
                    i += 2;
                    continue;
                }
                if chars[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        out.push(c);
        i += 1;
    }

    out.into_iter().collect()
}

/// `text` with every `#[cfg(test)] mod name { .. }` block removed. Unit tests
/// build throwaway routers (`Router::new().route("/r", ..)`) that are not the
/// mounted surface; production code before or after such a block stays.
fn without_test_modules(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let marker: Vec<char> = "#[cfg(test)]".chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i..].starts_with(&marker) {
            let after = skip_ws(&chars, i + marker.len());
            let is_mod = chars[after..].starts_with(&['m', 'o', 'd', ' ']);
            if is_mod
                && let Some(open) =
                    (after..chars.len()).find(|&j| chars[j] == '{' || chars[j] == ';')
                && chars[open] == '{'
                && let Some(close) = matching(&chars, open, '{', '}')
            {
                i = close + 1;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            // `target/` is build output; `tests/` contains fixture routers
            // (e.g. attome-server's own middleware tests) that are not part of
            // the mounted application surface.
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            if name.as_deref() == Some("target") || name.as_deref() == Some("tests") {
                continue;
            }
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            let text = without_test_modules(&text);
            out.push((path.display().to_string(), text));
        }
    }
}

// ── Balanced-delimiter scanning ───────────────────────────────────────────────

/// Index of the delimiter closing the one at `start`, skipping string literals
/// so a `(` inside a SQL fragment cannot unbalance the count. Char-indexed:
/// these sources contain non-ASCII (em dashes in comments), so byte slicing
/// would panic on a char boundary.
fn matching(chars: &[char], start: usize, open: char, close: char) -> Option<usize> {
    debug_assert_eq!(chars[start], open);
    let mut depth = 0usize;
    let mut i = start;
    let mut in_string = false;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
        } else if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Occurrences of `needle` starting on an identifier boundary, so a search for
/// `fn` does not match inside `transfn`.
fn word_positions(chars: &[char], needle: &str) -> Vec<usize> {
    let n: Vec<char> = needle.chars().collect();
    let mut out = Vec::new();
    if n.is_empty() || chars.len() < n.len() {
        return out;
    }
    for i in 0..=chars.len() - n.len() {
        if chars[i..i + n.len()] != n[..] {
            continue;
        }
        let before_ok = i == 0 || !is_ident_char(chars[i - 1]);
        let after = i + n.len();
        let after_ok = after >= chars.len() || !is_ident_char(chars[after]);
        if before_ok && after_ok {
            out.push(i);
        }
    }
    out
}

fn skip_ws(chars: &[char], mut i: usize) -> usize {
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    i
}

fn read_ident(chars: &[char], start: usize) -> (String, usize) {
    let mut i = start;
    let mut s = String::new();
    while i < chars.len() && (is_ident_char(chars[i]) || chars[i] == ':') {
        s.push(chars[i]);
        i += 1;
    }
    (s, i)
}

// ── Route extraction ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct RouteBinding {
    method: String,
    path: String,
    handler: String,
    file: String,
}

fn extract_routes(sources: &[(String, String)]) -> Vec<RouteBinding> {
    let mut bindings = Vec::new();
    for (file, text) in sources {
        let chars: Vec<char> = text.chars().collect();
        for pos in word_positions(&chars, "route") {
            // The leading dot distinguishes the builder call from a struct
            // field named `route` (notification.rs has one).
            if pos == 0 || chars[pos - 1] != '.' {
                continue;
            }
            let open = skip_ws(&chars, pos + "route".len());
            if open >= chars.len() || chars[open] != '(' {
                continue;
            }
            let Some(close) = matching(&chars, open, '(', ')') else {
                continue;
            };
            let inner = &chars[open + 1..close];
            let Some(path) = first_string_literal(inner) else {
                continue;
            };
            for (method, handler) in method_handlers(inner) {
                bindings.push(RouteBinding {
                    method: method.to_uppercase(),
                    path: path.clone(),
                    handler,
                    file: file.clone(),
                });
            }
        }
    }
    bindings
}

fn first_string_literal(chars: &[char]) -> Option<String> {
    let start = chars.iter().position(|&c| c == '"')?;
    let mut s = String::new();
    let mut i = start + 1;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                i += 2;
                continue;
            }
            '"' => return Some(s),
            c => s.push(c),
        }
        i += 1;
    }
    None
}

/// `get(list_entities).post(create_entity)` -> [(get, list_entities), (post,
/// create_entity)]. A path-qualified handler (`super::attribute::create_attribute`)
/// reduces to its final segment, which is how the definition index is keyed.
fn method_handlers(inner: &[char]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for method in HTTP_METHODS {
        for pos in word_positions(inner, method) {
            let open = skip_ws(inner, pos + method.len());
            if open >= inner.len() || inner[open] != '(' {
                continue;
            }
            let name_start = skip_ws(inner, open + 1);
            let (raw, _) = read_ident(inner, name_start);
            let name = raw.rsplit("::").next().unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            out.push(((*method).to_string(), name));
        }
    }
    out
}

// ── Function index ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct FnDef {
    params: String,
    body: String,
}

/// Every `fn` in the scanned crates, keyed by name. A name can be defined in
/// more than one module; all candidates are kept and any one satisfying a
/// check counts, which is the permissive direction and avoids false failures.
fn index_fns(sources: &[(String, String)]) -> BTreeMap<String, Vec<FnDef>> {
    let mut map: BTreeMap<String, Vec<FnDef>> = BTreeMap::new();
    for (_file, text) in sources {
        let chars: Vec<char> = text.chars().collect();
        for pos in word_positions(&chars, "fn") {
            let name_start = skip_ws(&chars, pos + 2);
            let (name, after_name) = read_ident(&chars, name_start);
            if name.is_empty() || name.contains(':') {
                continue;
            }
            let mut i = skip_ws(&chars, after_name);
            if i < chars.len() && chars[i] == '<' {
                let Some(gt) = matching(&chars, i, '<', '>') else {
                    continue;
                };
                i = skip_ws(&chars, gt + 1);
            }
            if i >= chars.len() || chars[i] != '(' {
                continue;
            }
            // Skip the argument list wholesale: parameter patterns destructure
            // (`Json(Body { field }): Json<Body>`), so the first `{` after the
            // name is frequently not the body.
            let Some(args_close) = matching(&chars, i, '(', ')') else {
                continue;
            };
            let mut j = args_close + 1;
            while j < chars.len() && chars[j] != '{' && chars[j] != ';' {
                j += 1;
            }
            if j >= chars.len() || chars[j] == ';' {
                continue; // bodyless trait signature
            }
            let Some(body_close) = matching(&chars, j, '{', '}') else {
                continue;
            };
            map.entry(name).or_default().push(FnDef {
                params: chars[i..=args_close].iter().collect(),
                body: chars[j..=body_close].iter().collect(),
            });
        }
    }
    map
}

/// A policy as written in a handler signature.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Policy {
    /// Outer identifier, so `Privilege<SidebarManage>` reports `Privilege`.
    outer: String,
    /// First type argument, if the policy is parameterised — `SidebarManage`
    /// for `Privilege<SidebarManage>`, `Read` for `RecordScoped<Read>`, `None`
    /// for a bare `RecordScoped`.
    arg: Option<String>,
}

impl Policy {
    /// Whether this spelling actually rejects somebody.
    ///
    /// `RecordScoped` is the one policy whose verdict depends on its argument:
    /// `RecordScoped<Read>` performs `require(entity, "read")` in the
    /// extractor, while bare `RecordScoped` — equivalently
    /// `RecordScoped<Dynamic>` — admits every authenticated caller and leaves
    /// the check to the handler (D-353).
    fn enforces(&self) -> bool {
        if self.outer == RECORD_SCOPED {
            return !matches!(self.arg.as_deref(), None | Some(DYNAMIC_ACTION));
        }
        ENFORCING_POLICIES.contains(&self.outer.as_str())
    }

    fn declares(&self) -> bool {
        !self.enforces() && DECLARING_POLICIES.contains(&self.outer.as_str())
    }

    fn render(&self) -> String {
        match &self.arg {
            Some(arg) => format!("{}<{arg}>", self.outer),
            None => self.outer.clone(),
        }
    }
}

/// The policy named by an `Authorized<P>` parameter, if any.
fn policy_in_params(params: &str) -> Option<Policy> {
    let chars: Vec<char> = params.chars().collect();
    let pos = *word_positions(&chars, "Authorized").first()?;
    let lt = skip_ws(&chars, pos + "Authorized".len());
    if lt >= chars.len() || chars[lt] != '<' {
        return None;
    }
    let inner_start = skip_ws(&chars, lt + 1);
    let (raw, after_outer) = read_ident(&chars, inner_start);
    let outer = raw.rsplit("::").next().unwrap_or("").to_string();
    if outer.is_empty() {
        return None;
    }

    // `RecordScoped<Read>` / `Privilege<SidebarManage>` — one level deep is
    // all any policy in this workspace nests, and a deeper one should be
    // noticed rather than silently flattened.
    let mut arg = None;
    let arg_lt = skip_ws(&chars, after_outer);
    if arg_lt < chars.len() && chars[arg_lt] == '<' {
        let (raw_arg, _) = read_ident(&chars, skip_ws(&chars, arg_lt + 1));
        let name = raw_arg.rsplit("::").next().unwrap_or("").to_string();
        if !name.is_empty() {
            arg = Some(name);
        }
    }

    Some(Policy { outer, arg })
}

/// L3-T2: `require_domain_editor` / `require_domain_reader`
/// (`attome-compliance` `governance_policy.rs`) are enforcing checks too: a
/// domain's owner or steward edits its governance records without
/// `system.admin`, and everyone else is refused, so those admin routes are
/// gated by the caller's governance role, read from the database.
const AUTHZ_CALLS: &[&str] = &[
    "require_admin",
    "require_key",
    "require",
    "require_domain_editor",
    "require_domain_reader",
    // L5-T5: an administrator, or a steward of the entity's data domain.
    "require_lineage_steward",
    // L2-T4: an administrator, or the issue's owner.
    "require_issue_editor",
];

fn body_has_direct_check(body: &str) -> bool {
    let chars: Vec<char> = body.chars().collect();
    AUTHZ_CALLS.iter().any(|call| {
        word_positions(&chars, call).iter().any(|&pos| {
            let open = skip_ws(&chars, pos + call.len());
            let is_call = open < chars.len() && chars[open] == '(';
            // Bare `require` must be a method call (`ctx.require(..)`), or a
            // local named `require` would count as a check.
            let is_method = *call != "require" || (pos > 0 && chars[pos - 1] == '.');
            is_call && is_method
        })
    })
}

/// Whether `name` performs a `require_*` check, following calls to other
/// in-crate functions up to `depth` levels. Delegation is real here:
/// `disable_user`/`enable_user` both check via a shared `set_user_active`.
fn has_require_call(
    name: &str,
    fns: &BTreeMap<String, Vec<FnDef>>,
    seen: &mut BTreeSet<String>,
    depth: usize,
) -> bool {
    if depth == 0 || !seen.insert(name.to_string()) {
        return false;
    }
    let Some(candidates) = fns.get(name) else {
        return false;
    };
    for def in candidates {
        if body_has_direct_check(&def.body) {
            return true;
        }
        let chars: Vec<char> = def.body.chars().collect();
        for callee in called_functions(&chars) {
            if fns.contains_key(&callee) && has_require_call(&callee, fns, seen, depth - 1) {
                return true;
            }
        }
    }
    false
}

fn called_functions(chars: &[char]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if is_ident_char(chars[i]) && (i == 0 || !is_ident_char(chars[i - 1])) {
            let (name, after) = read_ident(chars, i);
            let open = skip_ws(chars, after);
            // A method call (`db.execute(..)`) is not a call to the free
            // function of the same name: following it would credit every
            // handler that touches a sqlx `execute` with whatever the
            // `execute` handler checks.
            let is_method = chars[..i]
                .iter()
                .rev()
                .find(|c| !c.is_whitespace())
                .is_some_and(|c| *c == '.');
            if open < chars.len() && chars[open] == '(' && !name.contains(':') && !is_method {
                out.push(name.clone());
            }
            i = after.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

// ── Verdicts ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum Gate {
    /// `Authorized<Admin>` / `Authorized<Privilege<K>>` — the check is in the
    /// type and provably ran.
    EnforcingPolicy(String),
    /// A `require_*` call in the handler or a helper it delegates to.
    RequireCall,
    /// Bare `Authorized<RecordScoped>` / `Authorized<SelfService>` — declared,
    /// not enforced.
    DeclaringPolicy(String),
    /// Neither, but explicitly allow-listed above.
    AllowListed,
    /// Neither, and not allow-listed.
    None,
    /// Handler definition could not be located.
    Unresolved,
}

impl Gate {
    fn enforces(&self) -> bool {
        matches!(self, Gate::EnforcingPolicy(_) | Gate::RequireCall)
    }
}

fn classify(binding: &RouteBinding, fns: &BTreeMap<String, Vec<FnDef>>) -> Gate {
    let Some(defs) = fns.get(&binding.handler) else {
        return Gate::Unresolved;
    };

    let policies: Vec<Policy> = defs
        .iter()
        .filter_map(|d| policy_in_params(&d.params))
        .collect();
    if let Some(p) = policies.iter().find(|p| p.enforces()) {
        return Gate::EnforcingPolicy(p.render());
    }

    let mut seen = BTreeSet::new();
    if has_require_call(&binding.handler, fns, &mut seen, 4) {
        return Gate::RequireCall;
    }

    if let Some(p) = policies.iter().find(|p| p.declares()) {
        return Gate::DeclaringPolicy(p.render());
    }

    if CALLER_SCOPED_ROUTES
        .iter()
        .any(|(m, p, _)| *m == binding.method && *p == binding.path)
    {
        return Gate::AllowListed;
    }

    Gate::None
}

fn scan() -> (Vec<RouteBinding>, BTreeMap<String, Vec<FnDef>>) {
    let sources = collect_sources();
    let bindings = extract_routes(&sources);
    let fns = index_fns(&sources);

    let distinct: BTreeSet<&str> = bindings.iter().map(|b| b.path.as_str()).collect();
    assert!(
        distinct.len() >= MIN_ROUTES,
        "only {} distinct routes found (floor {MIN_ROUTES}) — the scanner is probably broken, \
         which would make every assertion in this file pass vacuously",
        distinct.len()
    );
    assert!(
        bindings.len() >= MIN_BINDINGS,
        "only {} handler bindings found (floor {MIN_BINDINGS}) — see above",
        bindings.len()
    );
    (bindings, fns)
}

fn render(bindings: &[(&RouteBinding, Gate)]) -> String {
    bindings
        .iter()
        .map(|(b, g)| {
            format!(
                "  {:7} {:58} -> {:32} {:?}  [{}]",
                b.method, b.path, b.handler, g, b.file
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn every_mounted_route_states_an_authorization_posture() {
    let (bindings, fns) = scan();

    let mut unresolved = Vec::new();
    let mut ungated = Vec::new();
    for b in &bindings {
        match classify(b, &fns) {
            Gate::Unresolved => unresolved.push((b, Gate::Unresolved)),
            Gate::None => ungated.push((b, Gate::None)),
            _ => {}
        }
    }

    // An unresolvable handler is a failure, not a skip: ignoring one is how a
    // renamed or moved handler drops out of coverage unnoticed.
    assert!(
        unresolved.is_empty(),
        "could not locate the definition for {} route binding(s); the scanner must be updated \
         so these stay covered:\n{}",
        unresolved.len(),
        render(&unresolved)
    );

    assert!(
        ungated.is_empty(),
        "{} mounted route(s) neither name an Authorized<P> policy nor reach a \
         require_admin()/require()/require_key() call.\n\nPreferred fix: give the handler the \
         policy it actually runs under (attome_server::authz). If it is genuinely caller-scoped, \
         Authorized<SelfService> says so in the signature; CALLER_SCOPED_ROUTES is the last \
         resort.\n\n{}",
        ungated.len(),
        render(&ungated)
    );
}

#[test]
fn admin_surface_routes_are_gated_by_an_enforcing_policy() {
    let (bindings, fns) = scan();

    let mut weak = Vec::new();
    for b in &bindings {
        if !b.path.starts_with("/api/v1/admin/") {
            continue;
        }
        if ADMIN_PATH_EXCEPTIONS
            .iter()
            .any(|(m, p, _)| *m == b.method && *p == b.path)
        {
            continue;
        }
        let gate = classify(b, &fns);
        if !gate.enforces() {
            weak.push((b, gate));
        }
    }

    assert!(
        weak.is_empty(),
        "{} route(s) on the /api/v1/admin/ surface are not gated by an enforcing check. \
         RecordScoped and SelfService admit every authenticated caller by design — they \
         declare intent, they do not authorize — and an allow-list entry authorizes nothing \
         at all. Use Authorized<Admin>, Authorized<Privilege<K>>, or an explicit require_* \
         call:\n{}",
        weak.len(),
        render(&weak)
    );
}

/// SEC-8: the stored-query authoring surface must be gated on `Admin` itself,
/// not merely on "an enforcing policy".
///
/// Checks both directions, so the list cannot rot in either:
/// a listed route that is no longer mounted fails (stale entry), and a listed
/// route gated by anything other than `Authorized<Admin>` fails (weakened
/// gate). Verified 2026-08-24: all four are `Authorized<Admin>` today, so this
/// test pins the status quo rather than reporting a defect.
#[test]
fn stored_query_authoring_requires_admin_not_a_delegable_privilege() {
    let (bindings, fns) = scan();

    let mut missing = Vec::new();
    let mut weakened = Vec::new();

    for (method, path, reason) in ADMIN_ONLY_ROUTES {
        let found: Vec<&RouteBinding> = bindings
            .iter()
            .filter(|b| b.method == *method && b.path == *path)
            .collect();

        if found.is_empty() {
            missing.push(format!("  {method:7} {path}  ({reason})"));
            continue;
        }

        for b in found {
            match classify(b, &fns) {
                Gate::EnforcingPolicy(p) if p == "Admin" => {}
                other => weakened.push(format!("  {method:7} {path:48} -> {other:?}  ({reason})")),
            }
        }
    }

    assert!(
        missing.is_empty(),
        "{} ADMIN_ONLY_ROUTES entr(ies) name a route that is no longer mounted. \
         Delete the entry if the route is gone, or fix the path if it moved — a \
         stale entry asserts nothing and makes this test pass vacuously:\n{}",
        missing.len(),
        missing.join("\n"),
    );

    assert!(
        weakened.is_empty(),
        "{} stored-query route(s) are no longer gated by Authorized<Admin>. \
         Privilege<K> is not equivalent here: a flat key can be granted to an \
         ordinary role, and these routes author SQL that runs against the \
         readonly pool outside the metadata model. Restore Authorized<Admin>, or \
         remove the entry deliberately and record why:\n{}",
        weakened.len(),
        weakened.join("\n"),
    );
}

/// D-353's ratchet: bare `RecordScoped` must only ever get rarer.
///
/// Counted from the policy spelling rather than from [`Gate`], deliberately.
/// A bare-`RecordScoped` handler still makes its own `require` call — that is
/// the whole point of the declaration — so `classify` reports it as
/// `RequireCall` and a Gate-based count would report zero and assert nothing.
/// What is being ratcheted is how many routes the *type system* cannot vouch
/// for, which is exactly the set of bare spellings.
#[test]
fn bare_record_scoped_routes_ratchet_downward() {
    let (bindings, fns) = scan();

    let mut bare: Vec<String> = Vec::new();
    for b in &bindings {
        let Some(defs) = fns.get(&b.handler) else {
            continue;
        };
        let policies: Vec<Policy> = defs
            .iter()
            .filter_map(|d| policy_in_params(&d.params))
            .collect();
        // Any parameterised spelling anywhere among the candidates counts as
        // converted — same permissive direction the rest of this file takes
        // when a handler name resolves to more than one definition.
        if policies.iter().any(|p| p.outer == RECORD_SCOPED)
            && !policies.iter().any(|p| p.enforces())
        {
            bare.push(format!("  {:7} {:58} -> {}", b.method, b.path, b.handler));
        }
    }
    bare.sort();

    assert!(
        bare.len() <= MAX_BARE_RECORD_SCOPED,
        "{} route(s) are still gated by a bare RecordScoped, over the ceiling of \
         {MAX_BARE_RECORD_SCOPED}. On these the extractor authorizes nothing and correctness \
         rests on a require() call in the handler body. Give the handler the action its route \
         performs — Authorized<RecordScoped<Update>> and friends, from \
         attome_security::record_action — unless the entity genuinely is not a path segment:\n{}",
        bare.len(),
        bare.join("\n")
    );

    assert_eq!(
        bare.len(),
        MAX_BARE_RECORD_SCOPED,
        "MAX_BARE_RECORD_SCOPED is {MAX_BARE_RECORD_SCOPED} but only {} route(s) are still bare. \
         Lower the constant in the commit that converted them, or the ratchet holds no ground \
         and the next unparameterised handler slips in for free:\n{}",
        bare.len(),
        bare.join("\n")
    );
}

#[test]
fn allow_list_has_no_stale_entries() {
    let (bindings, fns) = scan();

    let mut stale = Vec::new();
    for (method, path, _reason) in CALLER_SCOPED_ROUTES {
        let matches: Vec<&RouteBinding> = bindings
            .iter()
            .filter(|b| b.method == *method && b.path == *path)
            .collect();

        if matches.is_empty() {
            stale.push(format!(
                "  {method:7} {path}  — no such route is mounted any more"
            ));
            continue;
        }
        // An exemption must stop applying once the route states a posture of
        // its own, or the list accumulates entries that would silently
        // re-authorize the path if that posture were later removed.
        if matches.iter().all(|b| {
            !matches!(
                classify(b, &fns),
                Gate::AllowListed | Gate::None | Gate::Unresolved
            )
        }) {
            stale.push(format!(
                "  {method:7} {path}  — now states its own posture (policy or require_* call); \
                 drop the exemption"
            ));
        }
    }

    assert!(
        stale.is_empty(),
        "CALLER_SCOPED_ROUTES has {} stale entry/entries. An exemption that outlives its route \
         silently pre-authorizes whatever later claims that path:\n{}",
        stale.len(),
        stale.join("\n")
    );
}

#[test]
fn admin_path_exceptions_are_still_mounted() {
    let (bindings, _fns) = scan();
    for (method, path, _reason) in ADMIN_PATH_EXCEPTIONS {
        assert!(
            bindings
                .iter()
                .any(|b| b.method == *method && b.path == *path),
            "ADMIN_PATH_EXCEPTIONS lists {method} {path}, which is no longer mounted — remove it \
             before it silently exempts a future route on that path"
        );
    }
}

#[test]
fn every_exemption_carries_a_reason() {
    for (method, path, reason) in CALLER_SCOPED_ROUTES.iter().chain(ADMIN_PATH_EXCEPTIONS) {
        assert!(
            reason.len() > 40,
            "{method} {path} needs a real justification, not {reason:?}"
        );
    }
}

/// Nothing may reintroduce the pre-`Authorized<P>` signature.
///
/// This is already a compile error — `SecurityContext` is deliberately not
/// `Clone`, and `axum::Extension<T>: FromRequestParts` requires `T: Clone`
/// (D-300). The assertion records *why* the derive is absent, so a future
/// change that restores it to fix an unrelated borrow gets caught here rather
/// than silently reopening opt-in authorization for every handler at once.
#[test]
fn no_handler_extracts_a_bare_security_context() {
    let mut offenders = Vec::new();
    for (file, text) in collect_sources() {
        for (n, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            // Doc comments and prose discuss the retired shape by name.
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            if line.contains("Extension<SecurityContext>") {
                offenders.push(format!("  {file}:{}", n + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "`Extension<SecurityContext>` reintroduces opt-in authorization: the handler          receives the caller's context with no policy check having run. Use          `Authorized<P>` instead (attome_server::authz). Offending lines:
{}",
        offenders.join("
")
    );
}

/// Routes that are mounted but deliberately absent from the API document:
/// the Prometheus scrape (operations, not the API) and the developer-only
/// fleet console, compiled only with the debug `fleet-console` feature.
const UNDOCUMENTED_PREFIXES: &[&str] = &["/metrics", "/api/v1/fleet/"];

/// Y9-T1: every mounted route has an operation in the OpenAPI document, for
/// each method it answers. A route without one is invisible to the
/// generated clients, the SDK and the contract diff.
#[test]
fn every_mounted_route_is_in_the_api_document() {
    let (bindings, _) = scan();
    let doc = serde_json::to_value(&*attome::openapi::document()).expect("document serialises");
    let paths = doc["paths"].as_object().expect("paths");
    let mut missing: BTreeSet<String> = BTreeSet::new();
    for b in &bindings {
        if UNDOCUMENTED_PREFIXES.iter().any(|p| b.path.starts_with(p)) {
            continue;
        }
        let method = b.method.to_lowercase();
        let documented = paths
            .get(&b.path)
            .and_then(|item| item.get(&method))
            .is_some();
        if !documented {
            missing.insert(format!("{} {}  ({})", b.method, b.path, b.file));
        }
    }
    assert!(
        missing.is_empty(),
        "add a #[utoipa::path] for each, and list it in its file's ApiDocFragment: {missing:#?}"
    );
}
