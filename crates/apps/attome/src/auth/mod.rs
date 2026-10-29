//! Auth route wiring — parse the request, call the engine (`attome_auth` for
//! credential flows, `attome_security` for account management), set/clear cookies,
//! shape the response. No business logic here (Plan 1.6a) — see
//! `attome_auth::accounts`/`attome_auth::refresh`/`attome_security::accounts` for the
//! actual implementations, and `attome_security::api_keys` for api-key management
//! (mounted separately via `EngineSystem::core_routes`, not from this crate).
//!
//! Split by use case / policy boundary (file-size cleanup item 25): `dto` (wire
//! types), `session` (issuance/refresh/logout/introspection, shared by every
//! login path), `local` (password auth + MFA + reset/verify), `google`
//! (Google OAuth credential flow), `oidc` (generic OIDC federation). This
//! file owns only the two composition functions every other route bundle is
//! built from.

use arc_swap::ArcSwap;
use attome_modules::ModuleSet;
use attome_server::AppState;
use axum::{
    Router,
    extract::Extension,
    routing::{get, post},
};
use std::sync::Arc;

mod address_throttle;
mod challenge;
mod dto;
/// Audit plan 3.5 (D-541 rule 6): failed-login coalescing and its sweep.
pub mod failed_login;
mod google;
mod jwks;
mod local;
mod login_guard;
mod oidc;
mod session;
mod step_up;

/// This crate is a thin routing shell (guidelines/CLAUDE.md: parse → call
/// engine → respond) — the credential/account logic these handlers call into
/// already has its own unit + integration coverage in `attome_auth`/
/// `attome_security`. What's local and worth pinning here is the wire shape of
/// this file's own request/response DTOs: a field rename or an accidental
/// `Option` becoming required breaks every client of this API without
/// necessarily failing a handler-level integration test that only exercises
/// the happy path with hand-built structs.
#[cfg(test)]
mod tests;

/// P-license-enforcement-hardening Phase 5 (d) — the license handle
/// `register`/`google_login` need for seat-limit enforcement. Threaded in via
/// `Extension`, not `State<AppState>`, because `AppState` (attome-server) must
/// stay free of `xrm-*` knowledge (guidelines §1); only `crates/server`
/// (which already depends on both layers) knows about `ModuleSet`. See
/// `public_routes`'s doc comment for how this gets attached to the router.
pub(super) type LicenseHandle = Arc<ArcSwap<ModuleSet>>;

pub(super) const REFRESH_COOKIE_PATH: &str = "/api/v1/auth";

// ── Routes ────────────────────────────────────────────────────────────────────

/// P-api-contract Phase 1 — this sub-tree's slice of the workspace OpenAPI
/// document. Covers both `public_routes` and `protected_routes` below; the
/// bypass-listed ones are emitted without a `security` requirement, which is
/// how a generated client learns it may call them with no credential.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = local::openapi_fragment();
    for fragment in [
        google::openapi_fragment(),
        session::openapi_fragment(),
        oidc::openapi_fragment(),
        step_up::openapi_fragment(),
        jwks::openapi_fragment(),
        challenge::openapi_fragment(),
    ] {
        doc.merge(fragment);
    }
    doc
}

/// Public auth routes — no session required (all bypass-listed).
///
/// `license` (P-license-enforcement-hardening Phase 5 (d)) is attached as an
/// `Extension` over the whole router rather than added to `AppState` itself
/// — `AppState` lives in `attome-server` and must stay free of `xrm-*`
/// knowledge (guidelines §1); only `register`/`google_login` actually
/// extract it, every other route here ignores the extension. Every call
/// site of this function must supply `system.state().modules.clone()` (or
/// an equivalent handle) — see `main.rs` for the canonical wiring.
///
/// `auditor` (audit plan 3.4, D-542 rule 4) is attached the same way: the
/// login, logout, refresh, reset and MFA-completion handlers write their
/// mandatory `Security`/`Credential` events through it. Build it with
/// `attome_audit::security::SecurityAuditor::from_state(system.state())`.
pub fn public_routes(
    license: LicenseHandle,
    auditor: attome_audit::security::SecurityAuditor,
) -> Router<AppState> {
    Router::new()
        // Z4-T4: the public signing keys.
        .route("/.well-known/jwks.json", get(jwks::get_jwks))
        // Q20-T3: a proof-of-work challenge for a challenged sign-in.
        .route("/api/v1/auth/challenge", get(challenge::get_challenge))
        .route("/api/v1/auth/google", post(google::google_login))
        .route("/api/v1/auth/google/config", get(google::google_config))
        .route("/api/v1/auth/register", post(local::register))
        .route("/api/v1/auth/register/config", get(google::register_config))
        .route("/api/v1/auth/login", post(local::login))
        .route("/api/v1/auth/logout", post(session::logout))
        .route("/api/v1/auth/refresh", post(session::refresh_session))
        .route("/api/v1/auth/reset-request", post(local::reset_request))
        .route("/api/v1/auth/reset-confirm", post(local::reset_confirm))
        .route(
            "/api/v1/auth/verify-email/confirm",
            post(local::verify_email_confirm),
        )
        .route("/api/v1/auth/oidc/providers", get(oidc::oidc_providers))
        // Q1-T6: email-first sign-in; `discover` is not a provider key.
        .route("/api/v1/auth/oidc/discover", post(oidc::oidc_discover))
        .route("/api/v1/auth/oidc/{provider}/login", get(oidc::oidc_login))
        // Q1-T5: an administrator's test sign-in through a provider.
        .route(
            "/api/v1/admin/security/oidc-providers/{id}/test",
            post(oidc::oidc_provider_test),
        )
        // Q1-T10: under the `/api/v1/auth/oidc/` bypass subtree, which is
        // CSRF-exempt: the provider posts here server to server.
        .route(
            "/api/v1/auth/oidc/{provider}/backchannel-logout",
            post(oidc::oidc_backchannel_logout),
        )
        .route(
            "/api/v1/auth/oidc/{provider}/callback",
            get(oidc::oidc_callback),
        )
        // P-federation-linking-policy §4.3(a) — callbacks only. Deliberately
        // NOT under `/api/v1/auth/oidc/`: that prefix
        // is a bypass subtree, and the matching *start* routes
        // below (in protected_routes()) must never be swept into bypass by
        // sharing a prefix with them (guidelines §3).
        .route(
            "/api/v1/auth/identity-link-callback/oidc/{provider}",
            get(oidc::identity_link_oidc_callback),
        )
        // Base-auth hardening 2.1c (D-510 rule 5) — federated step-up
        // callbacks, under their own bypass prefix so no protected step-up
        // route is ever swept into bypass.
        .route(
            "/api/v1/auth/step-up-callback/oidc/{provider}",
            get(step_up::oidc_step_up_callback),
        )
        .route("/api/v1/auth/mfa/verify", post(local::mfa_verify))
        .route(
            "/api/v1/auth/mfa/verify-recovery",
            post(local::mfa_recovery),
        )
        .route(
            "/api/v1/auth/mfa/pending-enroll",
            post(local::mfa_pending_enroll),
        )
        .route(
            "/api/v1/auth/mfa/pending-confirm",
            post(local::mfa_pending_confirm),
        )
        .route(
            // Q5-T3: put required enrolment off within the grace period.
            "/api/v1/auth/mfa/postpone",
            post(local::mfa_postpone),
        )
        .route(
            // Q5-T5: a one-time code as the weaker second factor.
            "/api/v1/auth/mfa/code/send",
            post(local::mfa_code_send),
        )
        .route("/api/v1/auth/mfa/code/verify", post(local::mfa_code_verify))
        .layer(Extension(license))
        .layer(Extension(auditor))
}

/// Protected auth routes — require a valid session. Separate from
/// `public_routes()` so the distinction is visible at this file's call site
/// in `main.rs`, even though the only thing that actually enforces it is
/// `middleware::bypass`'s compile-time list (guidelines §3), not which
/// `Router` a route is attached to — `/api/v1/auth/session` is deliberately
/// absent from that list.
///
/// `auditor` backs the mandatory events of the identity-link and step-up
/// routes (audit plan 3.4), exactly as for [`public_routes`].
pub fn protected_routes(auditor: attome_audit::security::SecurityAuditor) -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/session", get(session::session_info))
        // P-federation-linking-policy §4.3(a) UI support — self-scoped read,
        // not a start/callback route; grouped here since it's protected like
        // session_info, not bypass-listed like the OIDC login routes.
        .route("/api/v1/auth/identity-links", get(session::identity_links))
        // Q8-T4: the caller's own sessions. `end-others` is a static
        // segment, so it never matches the `{id}` route.
        .route("/api/v1/auth/sessions", get(session::list_sessions))
        .route(
            "/api/v1/auth/sessions/end-others",
            post(session::end_other_sessions),
        )
        .route(
            "/api/v1/auth/sessions/{id}",
            axum::routing::delete(session::end_session),
        )
        // P-federation-linking-policy §4.3(a) — start routes only; their
        // callbacks live in public_routes() (see the comment there for why).
        .route(
            "/api/v1/auth/identity-link/oidc/{provider}",
            get(oidc::identity_link_oidc_start),
        )
        // Google's single-POST analog of the OIDC start routes above —
        // see `identity_link_google`'s doc comment for why it needs no
        // separate callback route.
        .route(
            "/api/v1/auth/identity-link/google",
            post(google::identity_link_google),
        )
        // Base-auth hardening 2.1b (D-510 rule 6) — step-up challenges on the
        // caller's own session. Protected, never bypass-listed: the family
        // comes from the validated session token. The GET (2.1d, rule 9) reads
        // the guard's decision without starting a challenge.
        .route(
            "/api/v1/auth/step-up/{operation}",
            get(step_up::step_up_status).post(step_up::start_step_up),
        )
        .route(
            "/api/v1/auth/step-up/{operation}/verify",
            post(step_up::verify_step_up),
        )
        // BAU-8c (owner ruling 2026-09-25): a Google-only account answers a
        // challenge by POSTing a fresh Google ID token. Protected, never under
        // the `/api/v1/auth/google` bypass prefix.
        .route(
            "/api/v1/auth/step-up/{operation}/google",
            post(step_up::google_step_up),
        )
        // Base-auth hardening 2.1c (D-510 rule 5) — federated step-up starts.
        // Their callbacks live in public_routes(), under a separate bypass
        // prefix, for the same reason as the identity-link callbacks.
        .route(
            "/api/v1/auth/step-up/{operation}/oidc/{provider}",
            get(step_up::start_oidc_step_up),
        )
        .layer(Extension(auditor))
}
