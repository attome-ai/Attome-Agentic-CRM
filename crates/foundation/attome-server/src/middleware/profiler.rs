//! Wires `attome_profiler` into the Axum pipeline — the write side of the
//! "Profiler" admin dashboard (`xrm-server`'s `profiler_admin` serves the
//! read side).
//!
//! Applied as an extra **outermost** layer in `crates/server/src/main.rs`,
//! right alongside the Prometheus metrics layer, gated on
//! `observability.profiler_enabled` (default false — no layer applied, zero
//! behavior change, same "dark unless configured" posture as
//! `metrics_port == 0`). Deliberately NOT threaded into
//! `apply_inner_layers`/`apply_outer_layers` (`app.rs`): by the time
//! `main.rs` composes this, `XrmSystem::core_routes` has already called
//! `.with_state(state)` on the router, so it's a bare `Router` with no
//! `State<AppState>` left to extract — the same reason
//! `body_limit::reject_declared_oversized_body` captures `max_bytes` via a
//! closure instead of `from_fn_with_state`.
//!
//! Records one top-level probe per request, named `"{METHOD} {route}"`
//! (`MatchedPath`, so `/api/v1/entities/{id}` stays one probe regardless of
//! how many distinct `{id}`s are requested). A request that matched no route
//! collapses to **one** name per method — `"{METHOD} (unmatched)"` — instead
//! of contributing the raw URI, which is attacker-controlled and would blow
//! the profiler's 2,000-name cluster cap from a single scanner (BPR-11); a
//! non-standard verb is recorded as `OTHER`. This is a separate namespace
//! from whatever dotted, developer-chosen names a handler's own `measure!`
//! calls use (e.g. `"entity.create.db_insert"`); the two coexist as
//! independent top-level rows in the dashboard rather than being forced to
//! nest under one another.

use attome_cache::Store;
use attome_profiler::Flusher;
use axum::{
    Router,
    extract::{MatchedPath, Request},
    middleware::{self, Next},
    response::Response,
};

/// `redis` is the general pool (`state.redis`), never `redis_coordination`
/// (BPR-16). Starts one bounded `Flusher` for the layer, so must be called
/// inside a Tokio runtime.
pub fn apply_profiler_layer(router: Router, redis: Store) -> Router {
    let flusher = Flusher::new(redis);
    router.layer(middleware::from_fn(move |matched_path, req, next| {
        profiler_middleware(flusher.clone(), matched_path, req, next)
    }))
}

/// The probe name for one request (BPR-11).
///
/// `matched` is the routing template (`MatchedPath`) when the request reached
/// a route. When it did not, the probe name must not fall back to the request
/// URI: that is attacker-controlled, so any scanner probing random paths would
/// create a distinct Redis key per request and exhaust the profiler's
/// cluster-wide name cap (and the memory behind it). One name per method is the
/// bounded answer. A non-standard verb collapses to `OTHER` for the same
/// reason.
pub fn probe_name(method: &axum::http::Method, matched: Option<&str>) -> String {
    const STANDARD: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
    let verb = if STANDARD.contains(&method.as_str()) {
        method.as_str()
    } else {
        "OTHER"
    };
    match matched {
        Some(path) => format!("{verb} {path}"),
        None => format!("{verb} (unmatched)"),
    }
}

async fn profiler_middleware(
    flusher: Flusher,
    matched_path: Option<MatchedPath>,
    req: Request,
    next: Next,
) -> Response {
    let name = probe_name(req.method(), matched_path.as_ref().map(MatchedPath::as_str));

    let start = std::time::Instant::now();
    let (response, parts) = attome_profiler::scope(next.run(req)).await;
    let total = start.elapsed();

    // Off the response path and bounded (BPR-22): a full queue drops the point.
    // Every failure is counted and rate-limit-logged inside attome-profiler
    // (BPR-23), so there is nothing to log per request here.
    flusher.try_send(name, total, parts);

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_matched_route_keeps_its_template() {
        assert_eq!(
            probe_name(&axum::http::Method::GET, Some("/api/v1/entities/{id}")),
            "GET /api/v1/entities/{id}"
        );
    }

    #[test]
    fn two_unmatched_paths_collapse_to_one_probe_name() {
        let a = probe_name(&axum::http::Method::GET, None);
        let b = probe_name(&axum::http::Method::GET, None);
        assert_eq!(a, b, "unmatched paths must not become distinct probe names");
        assert_eq!(a, "GET (unmatched)");
    }

    #[test]
    fn a_nonstandard_verb_is_recorded_as_other() {
        let method = axum::http::Method::from_bytes(b"FOO").expect("valid token");
        assert_eq!(probe_name(&method, Some("/x")), "OTHER /x");
        assert_eq!(probe_name(&method, None), "OTHER (unmatched)");
    }
}
