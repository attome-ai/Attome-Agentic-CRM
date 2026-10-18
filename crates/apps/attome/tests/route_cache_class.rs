//! AA7-T1: every documented operation has a cache class, the credential
//! routes are never stored, and every listed override names a real route.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_server::middleware::cache_policy::{CACHE_CLASSES, CacheClass, class_for};
use axum::http::Method;

fn operations() -> Vec<(Method, String)> {
    let doc = serde_json::to_value(&*attome::openapi::document()).expect("document serialises");
    let paths = doc["paths"].as_object().expect("paths");
    let mut out = Vec::new();
    for (path, item) in paths {
        for method in ["get", "head", "post", "put", "patch", "delete"] {
            if item.get(method).is_some() {
                let method = Method::from_bytes(method.to_uppercase().as_bytes()).unwrap();
                out.push((method, path.clone()));
            }
        }
    }
    assert!(out.len() > 100, "the document lists every route");
    out
}

#[test]
fn every_route_has_cache_class() {
    for (method, path) in operations() {
        let class = class_for(&method, &path);
        if class == CacheClass::Immutable {
            assert!(
                CACHE_CLASSES.iter().any(|(m, t, c)| *t == path
                    && *m == method.as_str()
                    && *c == CacheClass::Immutable),
                "{method} {path} is immutable without being listed"
            );
        }
        let lower = path.to_ascii_lowercase();
        if method == Method::GET
            && ["/auth/", "token", "api-key", "/secrets", "/sessions"]
                .iter()
                .any(|w| lower.contains(w))
        {
            assert_eq!(
                class,
                CacheClass::NoStore,
                "{method} {path} must not be stored"
            );
        }
        if method != Method::GET && method != Method::HEAD {
            assert_eq!(class, CacheClass::NoStore, "{method} {path} changes state");
        }
    }
}

#[test]
fn every_listed_override_names_a_documented_route() {
    let ops = operations();
    for (method, template, _) in CACHE_CLASSES {
        assert!(
            ops.iter()
                .any(|(m, p)| m.as_str() == *method && p == template),
            "CACHE_CLASSES lists {method} {template}, which the API document does not have"
        );
    }
}

/// AA7-T12: the credential routes answer `Cache-Control: no-store`.
#[test]
fn no_store_routes_send_no_store() {
    for (method, path) in [
        (Method::POST, "/api/v1/auth/login"),
        (Method::POST, "/api/v1/auth/api-keys"),
        (Method::GET, "/api/v1/auth/api-keys"),
        (Method::GET, "/api/v1/auth/challenge"),
    ] {
        assert!(
            operations().iter().any(|(m, p)| *m == method && p == path),
            "{method} {path} is a documented route"
        );
        assert_eq!(
            class_for(&method, path),
            CacheClass::NoStore,
            "{method} {path}"
        );
    }
}
