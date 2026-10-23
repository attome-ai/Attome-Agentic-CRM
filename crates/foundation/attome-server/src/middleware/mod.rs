/// S8-T1 — which API version a request is answered at.
pub mod api_version;
pub mod auth;
pub mod authoring_gate;
pub mod body_limit;
pub mod bypass;
/// AA7-T1 — every API response says how it may be cached.
pub mod cache_policy;
pub mod client_ip;
pub mod csrf;
/// AB6-T2 — a request's deadline for the outside calls it makes.
pub mod deadline;
pub mod deprecation;
/// AB2-T3: retry-safe requests run again across a database failover.
pub mod failover_retry;
pub mod flood;
pub mod host_gate;
pub mod idempotency;
pub mod idempotency_durable;
pub mod ip_allowlist;
pub mod json_shape;
/// Y8-T6 — a builder sees their own metadata write on every node.
pub mod metadata_pin;
pub mod mutation_gate;
/// Z5-T1 — a debug-only trace of the layers a request passes.
pub mod pipeline_trace;
pub mod profiler;
pub mod rate_limit;
pub mod request_id_body;
pub mod request_meta;
pub mod security_headers;
pub mod server_timing;
/// AB5-T7 — priority load shedding.
pub mod shed;
pub mod trace_context;
/// S8-T2 — request and response adapters between API versions.
pub mod version_adapters;
pub mod waf;

/// Shared by `idempotency`, `mutation_gate` and `authoring_gate` — all key
/// off "is this request trying to change something," not any auth/route-
/// specific detail.
pub(crate) fn is_mutating(method: &axum::http::Method) -> bool {
    matches!(
        *method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn is_mutating_accepts_only_the_four_mutating_verbs() {
        assert!(is_mutating(&Method::POST));
        assert!(is_mutating(&Method::PUT));
        assert!(is_mutating(&Method::PATCH));
        assert!(is_mutating(&Method::DELETE));
        assert!(!is_mutating(&Method::GET));
        assert!(!is_mutating(&Method::HEAD));
        assert!(!is_mutating(&Method::OPTIONS));
    }
}
