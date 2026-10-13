//! P-audit-chain-hardening item (e) — ingest circuit breaker.
//!
//! Closes a documented, deliberately-unmitigated gap: nothing today stops
//! `xrm_audit_ingest` from growing unbounded if `audit_chainer` falls behind
//! or dies (the developer guide already states plainly that there is no
//! automatic fallback to the synchronous path, by design). This is the
//! application-level backstop for when that operational mitigation itself
//! fails — a cheap atomic-load check, not a query, so it costs nothing on
//! every request except the one lookup.
//!
//! Generic mechanism, XRM-specific trigger — same split as
//! `AppState::registry_ready`/`AppState::security`: this crate has zero
//! `xrm-*` dependencies (workspace rule, guidelines §1), so it only owns the
//! flag and the gate; `xrm_server::spawn_ingest_backlog_refresh` (the only
//! writer) is the piece that actually knows what "backlog" means for audit
//! ingest.
//!
//! Reads are never affected — only `is_mutating` verbs, mirroring
//! `idempotency`'s exact scoping (both key off the same shared helper, see
//! `middleware::is_mutating`). A tripped breaker returns
//! `AppError::Overloaded` (503), distinct from `TooManyRequests` (429, a
//! per-client rate limit) — this is a system-wide protective state, not a
//! statement about the calling client.

use attome_types::AppError;
use axum::{
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::atomic::Ordering;

use crate::state::AppState;

use super::is_mutating;

/// Pure decision, split out from the `State<AppState>`-extracting middleware
/// fn below purely so it's unit-testable without constructing a full
/// `AppState` (which — see this crate's other middleware tests, e.g.
/// `auth.rs`'s `test_state` — needs a live Postgres/Redis/object-store
/// connection; none of that is available in every environment this code is
/// authored in, and this decision has no I/O of its own to justify paying
/// that cost in a unit test).
fn should_reject(method: &Method, backlog_exceeded: bool) -> bool {
    is_mutating(method) && backlog_exceeded
}

pub async fn mutation_gate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let tripped = state.audit_ingest_backlog_exceeded.load(Ordering::Relaxed);
    if should_reject(req.method(), tripped) {
        return AppError::Overloaded("audit_ingest_backlog").into_response();
    }
    next.run(req).await
}

// ── Tests ──────────────────────────────────────────────────────────────────
//
// `should_reject` is pure and covered directly below — no live infrastructure
// needed for this file's own unit tests (this crate has zero xrm-*
// dependencies and no live Postgres/Redis/object-store connection available
// in every environment this code is authored in, per `auth.rs`'s own
// `test_state` helper).
//
// The end-to-end integration coverage this module's decision feeds into —
// `mutation_gate` wired to a real `AppState`, and confirmation this layer
// sits at the intended point in the composed pipeline (`ServerBuilder::
// build`, see `app.rs`'s `apply_pre_auth_rate_limit`) without being shadowed
// — already exists: `crates/server/tests/middleware_pipeline.rs`'s
// `tripped_backlog_breaker_rejects_a_mutating_request_with_503` and
// `tripped_backlog_breaker_never_blocks_a_read`, plus
// `the_mutation_gate_and_the_pre_auth_limiter_both_answer_before_authn` for
// its position. They need live Postgres and Redis; run them by hand with
// `cargo test -p server --test middleware_pipeline` (there is no CI).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_only_when_both_mutating_and_the_breaker_is_tripped() {
        assert!(should_reject(&Method::POST, true));
        assert!(should_reject(&Method::PUT, true));
        assert!(should_reject(&Method::PATCH, true));
        assert!(should_reject(&Method::DELETE, true));
    }

    #[test]
    fn never_rejects_a_read_even_when_the_breaker_is_tripped() {
        assert!(!should_reject(&Method::GET, true));
        assert!(!should_reject(&Method::HEAD, true));
        assert!(!should_reject(&Method::OPTIONS, true));
    }

    #[test]
    fn never_rejects_anything_when_the_breaker_is_not_tripped() {
        assert!(!should_reject(&Method::POST, false));
        assert!(!should_reject(&Method::DELETE, false));
        assert!(!should_reject(&Method::GET, false));
    }
}
