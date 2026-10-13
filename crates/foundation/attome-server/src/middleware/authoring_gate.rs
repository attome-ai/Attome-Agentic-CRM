//! P-environment-promotion Phase 0 step 1 — the metadata authoring gate.
//!
//! Authoring is derived from the deployment profile, never configured: on
//! `app.deployment_profile = "production"` every *mutating* request to a
//! metadata-authoring route prefix (`METADATA_AUTHORING_PREFIXES`) is refused
//! with `AppError::AuthoringLocked` (403, code `metadata_authoring_locked`);
//! on `development` this layer is a no-op. There is no `change_control`
//! field to misconfigure — test and production both run the production
//! profile and are promoted to by bundle, development runs the development
//! profile and is authored (plan §4 "Production change control").
//!
//! Same shape as `mutation_gate.rs`: a pure `should_reject` decision that
//! unit tests cover without infrastructure, and a thin
//! `from_fn_with_state` middleware composed at the single central point
//! (`app::apply_authoring_gate`, called from `ServerBuilder::build`) — never
//! around a route bundle (guidelines §3).
//!
//! Two exceptions, both narrow:
//!
//! - **The bundle import/apply path** (`/api/v1/admin/metadata/…`) is how
//!   metadata *reaches* a production deployment, so it is exempt by prefix
//!   even though it does not exist yet — the gate must never be the thing
//!   that blocks a promotion.
//! - **Break-glass.** An approved `metadata.break_glass` action opens a Redis
//!   window key (`BREAK_GLASS_WINDOW_KEY`, with a TTL set by the opener);
//!   while that key exists, authoring writes pass. Redis is consulted only
//!   after the cheap checks (profile × verb × prefix) have already said
//!   "reject", so the normal request path never pays for it. A Redis error
//!   or timeout **fails closed** (rejects, logs at `warn`) — the same posture
//!   every other coordination gate in this crate takes (rate limit,
//!   idempotency, S2S nonce).
//!
//! Reads are never affected — only `is_mutating` verbs, mirroring
//! `mutation_gate`/`idempotency`'s exact scoping.

use attome_types::AppError;
use axum::{
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::{IntoResponse, Response},
};
use fred::prelude::*;
use std::time::Duration;

use crate::state::AppState;

use super::is_mutating;

/// Route prefixes whose mutating verbs author metadata. Segment-bounded: a
/// prefix matches the path itself or the path followed by `/…` — so
/// `/api/v1/admin/entities-export` would NOT match `/api/v1/admin/entities`.
/// Every entry is a real mounted prefix (verified against the routers in
/// `xrm-server`/`xrm-security`/`xrm-workflow` at the time of writing);
/// `/api/v1/admin/security/users` (user role assignment/grants), API keys,
/// S2S clients, and the license are deliberately absent — those are
/// per-deployment state, not promotable metadata (plan §4 / CONTRACTS).
pub const METADATA_AUTHORING_PREFIXES: &[&str] = &[
    "/api/v1/admin/entities",
    "/api/v1/admin/queries",
    "/api/v1/admin/views",
    "/api/v1/sidebar/admin",
    "/api/v1/admin/security/roles",
    "/api/v1/admin/security/role-grants",
    "/api/v1/admin/security/field-profiles",
    "/api/v1/admin/security/role-entity-access",
    "/api/v1/workflow/definitions",
    // BSV-F02 / BSV-D2 (B4): bundle-applied metadata, so production changes it
    // only through a promoted bundle.
    "/api/v1/admin/relationships",
    "/api/v1/admin/state-models",
    "/api/v1/admin/apps",
    "/api/v1/admin/calendars",
    "/api/v1/admin/business-rules",
    // D-785 (Solution 7 Phase 1): changeset authoring (open, close, abandon).
    // Changesets are authored in development; production applies them through
    // `/api/v1/admin/metadata/changesets` (the exempt import prefix).
    "/api/v1/admin/changesets",
];

/// Prefixes that are ALWAYS allowed through this gate regardless of profile
/// — the bundle import/apply surface. Checked before
/// `METADATA_AUTHORING_PREFIXES`, so it wins even if a future protected
/// prefix were to overlap it.
pub(crate) const METADATA_IMPORT_PREFIXES: &[&str] = &["/api/v1/admin/metadata"];

/// The Redis key an approved `metadata.break_glass` action sets (with a TTL)
/// to open a temporary authoring window on the production profile. This
/// crate only ever reads it (`EXISTS`); the opener lives above attome-server.
pub const BREAK_GLASS_WINDOW_KEY: &str = "attome-server:break-glass:window";

/// Same bound every other coordination-gate Redis call in this crate uses
/// (`idempotency::OP_TIMEOUT`, attome-cache's rate limiter): the request-path bound.
const OP_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;

/// `path` is `prefix` itself or `prefix` followed by another segment.
fn matches_prefix(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// True iff `path` is a metadata-authoring path that this gate protects
/// (and not an import/apply path, which is always exempt).
pub fn is_metadata_authoring_path(path: &str) -> bool {
    if METADATA_IMPORT_PREFIXES
        .iter()
        .any(|prefix| matches_prefix(path, prefix))
    {
        return false;
    }
    METADATA_AUTHORING_PREFIXES
        .iter()
        .any(|prefix| matches_prefix(path, prefix))
}

/// The cheap, I/O-free half of the decision: does this request even need the
/// gate to think about it? True iff the profile is production AND the verb
/// mutates AND the path is a protected authoring path. Only when this is
/// true does the middleware go on to consult the break-glass window.
fn is_gated(deployment_profile: &str, method: &Method, path: &str) -> bool {
    deployment_profile == "production" && is_mutating(method) && is_metadata_authoring_path(path)
}

/// Pure decision, split out from the `State<AppState>`-extracting middleware
/// fn below so it's unit-testable without constructing a full `AppState`
/// (same reasoning as `mutation_gate::should_reject`). `break_glass_open` is
/// the already-resolved answer to "does the window key exist" — `None` means
/// the lookup itself failed (Redis error/timeout), which rejects: a
/// coordination gate fails closed.
fn should_reject(
    deployment_profile: &str,
    method: &Method,
    path: &str,
    break_glass_open: Option<bool>,
) -> bool {
    is_gated(deployment_profile, method, path) && break_glass_open != Some(true)
}

/// `Some(true)`/`Some(false)` — the window key does/doesn't exist; `None` —
/// Redis errored or timed out (logged at `warn`; the caller fails closed).
/// Whether an approved break-glass window is open. `None` when the lookup
/// failed or timed out; callers treat that as closed (fail closed). Also used
/// by the generic entity engine's metadata-table lock.
pub async fn break_glass_window_open(state: &AppState) -> Option<bool> {
    match tokio::time::timeout(
        OP_TIMEOUT,
        state
            .redis_coordination
            .exists::<bool, _>(BREAK_GLASS_WINDOW_KEY),
    )
    .await
    {
        Ok(Ok(exists)) => Some(exists),
        Ok(Err(e)) => {
            tracing::warn!(
                error = %e,
                key = BREAK_GLASS_WINDOW_KEY,
                "authoring gate: break-glass window lookup failed — failing closed"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                key = BREAK_GLASS_WINDOW_KEY,
                timeout_ms = OP_TIMEOUT.as_millis() as u64,
                "authoring gate: break-glass window lookup timed out — failing closed"
            );
            None
        }
    }
}

pub async fn authoring_gate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let profile = state.config.app.deployment_profile.as_str();
    // The overwhelmingly common outcome (development profile, or a read, or
    // an unrelated path) is decided here with zero I/O.
    if !is_gated(profile, req.method(), req.uri().path()) {
        return next.run(req).await;
    }
    let break_glass_open = break_glass_window_open(&state).await;
    if should_reject(profile, req.method(), req.uri().path(), break_glass_open) {
        return AppError::AuthoringLocked.into_response();
    }
    tracing::info!(
        method = %req.method(),
        path = req.uri().path(),
        "authoring gate: metadata write admitted through an open break-glass window"
    );
    next.run(req).await
}

// ── Tests ──────────────────────────────────────────────────────────────────
//
// `should_reject`/`is_metadata_authoring_path` are pure and covered directly
// below — no live infrastructure needed (same stance as `mutation_gate.rs`).
// The end-to-end coverage — this layer wired to a real `AppState` at its
// intended point in `ServerBuilder::build` — lives in
// `crates/server/tests/middleware_pipeline.rs`
// (`authoring_gate_refuses_metadata_write_on_production_profile`,
// `authoring_gate_never_blocks_reads`,
// `authoring_gate_allows_metadata_import_prefix`), which needs live
// Postgres + Redis per that file's header.
#[cfg(test)]
mod tests {
    use super::*;

    const PROD: &str = "production";
    const DEV: &str = "development";

    #[test]
    fn every_protected_prefix_is_recognized_at_its_root_and_below() {
        for prefix in METADATA_AUTHORING_PREFIXES {
            assert!(is_metadata_authoring_path(prefix), "{prefix}");
            let nested = format!("{prefix}/0190a1b2-0000-7000-8000-000000000000/fields");
            assert!(is_metadata_authoring_path(&nested), "{nested}");
        }
    }

    #[test]
    fn bundle_applied_metadata_is_gated_on_production() {
        for path in [
            "/api/v1/admin/relationships",
            "/api/v1/admin/state-models/0190/transitions/0191",
            "/api/v1/admin/apps/0190",
            "/api/v1/admin/calendars/0190/holidays",
            "/api/v1/admin/calendars/0190/exceptions/0191",
            "/api/v1/admin/business-rules/0190/publish",
            "/api/v1/admin/changesets",
            "/api/v1/admin/changesets/0190/close",
            "/api/v1/admin/changesets/0190/abandon",
        ] {
            assert!(
                should_reject("production", &Method::POST, path, Some(false)),
                "{path} must be gated (BSV-F02)"
            );
            assert!(!should_reject(
                "development",
                &Method::POST,
                path,
                Some(false)
            ));
            assert!(!should_reject(
                "production",
                &Method::GET,
                path,
                Some(false)
            ));
        }
    }

    #[test]
    fn prefix_match_is_segment_bounded() {
        assert!(!is_metadata_authoring_path("/api/v1/admin/entities-export"));
        assert!(!is_metadata_authoring_path("/api/v1/admin/viewsx"));
        assert!(is_metadata_authoring_path("/api/v1/admin/views/abc"));
    }

    #[test]
    fn import_prefix_and_unrelated_paths_are_never_authoring_paths() {
        assert!(!is_metadata_authoring_path("/api/v1/admin/metadata"));
        assert!(!is_metadata_authoring_path("/api/v1/admin/metadata/import"));
        assert!(!is_metadata_authoring_path(
            "/api/v1/admin/metadata/plans/123/apply"
        ));
        // Changeset apply lives under the import prefix, so production can
        // apply what development authored (D-785).
        assert!(!is_metadata_authoring_path(
            "/api/v1/admin/metadata/changesets/apply"
        ));
        assert!(!is_metadata_authoring_path("/api/v1/admin/changesets-x"));
        // Per-deployment state, not promotable metadata.
        assert!(!is_metadata_authoring_path("/api/v1/admin/security/users"));
        assert!(!is_metadata_authoring_path("/api/v1/admin/security/grants"));
        assert!(!is_metadata_authoring_path("/api/v1/auth/api-keys"));
        assert!(!is_metadata_authoring_path("/api/v1/admin/s2s/clients"));
        // Ordinary record CRUD.
        assert!(!is_metadata_authoring_path("/api/v1/account"));
        assert!(!is_metadata_authoring_path("/api/v1/query/execute"));
        // Reads of the sidebar (non-admin route) and workflow instances.
        assert!(!is_metadata_authoring_path("/api/v1/sidebar/get"));
        assert!(!is_metadata_authoring_path("/api/v1/workflow/instances"));
    }

    #[test]
    fn rejects_a_mutating_authoring_write_on_production_with_no_window() {
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(
                should_reject(PROD, &method, "/api/v1/admin/entities", Some(false)),
                "{method}"
            );
        }
        assert!(should_reject(
            PROD,
            &Method::POST,
            "/api/v1/workflow/definitions",
            Some(false)
        ));
    }

    #[test]
    fn never_rejects_on_the_development_profile() {
        assert!(!should_reject(
            DEV,
            &Method::POST,
            "/api/v1/admin/entities",
            Some(false)
        ));
        assert!(!should_reject(
            DEV,
            &Method::DELETE,
            "/api/v1/sidebar/admin/abc",
            None
        ));
    }

    #[test]
    fn never_rejects_a_read_even_on_production() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(
                !should_reject(PROD, &method, "/api/v1/admin/entities", Some(false)),
                "{method}"
            );
            assert!(
                !should_reject(PROD, &method, "/api/v1/admin/queries/abc", None),
                "{method}"
            );
        }
    }

    #[test]
    fn never_rejects_an_unprotected_or_import_path_on_production() {
        assert!(!should_reject(
            PROD,
            &Method::POST,
            "/api/v1/admin/metadata/import",
            Some(false)
        ));
        assert!(!should_reject(PROD, &Method::POST, "/api/v1/account", None));
        assert!(!should_reject(
            PROD,
            &Method::POST,
            "/api/v1/auth/api-keys",
            None
        ));
    }

    #[test]
    fn an_open_break_glass_window_admits_the_write() {
        assert!(!should_reject(
            PROD,
            &Method::POST,
            "/api/v1/admin/entities",
            Some(true)
        ));
    }

    #[test]
    fn a_failed_window_lookup_fails_closed() {
        assert!(should_reject(
            PROD,
            &Method::POST,
            "/api/v1/admin/entities",
            None
        ));
    }

    #[test]
    fn redis_is_only_consulted_for_gated_requests() {
        // `is_gated` is the predicate the middleware uses to decide whether
        // to touch Redis at all — it must be false for everything that is
        // not (production ∧ mutating ∧ authoring path).
        assert!(is_gated(PROD, &Method::POST, "/api/v1/admin/entities"));
        assert!(!is_gated(DEV, &Method::POST, "/api/v1/admin/entities"));
        assert!(!is_gated(PROD, &Method::GET, "/api/v1/admin/entities"));
        assert!(!is_gated(PROD, &Method::POST, "/api/v1/account"));
        assert!(!is_gated(
            PROD,
            &Method::POST,
            "/api/v1/admin/metadata/import"
        ));
    }
}
