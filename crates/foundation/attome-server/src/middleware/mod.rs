pub mod auth;
pub mod authoring_gate;
pub mod body_limit;
pub mod bypass;
pub mod client_ip;
pub mod csrf;
pub mod deprecation;
pub mod host_gate;
pub mod idempotency;
pub mod idempotency_durable;
pub mod ip_allowlist;
pub mod mutation_gate;
pub mod profiler;
pub mod rate_limit;
pub mod request_id_body;
pub mod request_meta;
pub mod security_headers;
pub mod trace_context;

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
