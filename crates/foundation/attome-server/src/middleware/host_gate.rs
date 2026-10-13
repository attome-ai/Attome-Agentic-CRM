//! D-585 host sets: the staff API answers only on `deployment.staff_hosts`,
//! audience routers (web portals) only on `deployment.portal_hosts`.
//!
//! A portal page and the staff app therefore never share an origin, so a
//! script injected into a portal page can't read or drive the staff API as a
//! staff user who has that page open. The CSRF narrowing in `csrf.rs` closes
//! the remaining same-site write path.
//!
//! A request on the wrong host set gets a uniform 404 before any
//! authentication runs, so it learns nothing about the other audience's
//! routes.

use std::{net::SocketAddr, sync::Arc};

use attome_config::AppConfig;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Which router a gate protects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostAudience {
    Staff,
    Portal,
}

/// The request's host, lowercase and without a port. `X-Forwarded-Host` is
/// honoured only when the socket peer is a trusted proxy (the same trust rule
/// `client_ip` uses); otherwise `Host`.
pub(crate) fn request_host(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    config: &AppConfig,
) -> Option<String> {
    let trusted = peer.is_some_and(|p| config.is_trusted_proxy(p.ip()));
    host_from_headers(trusted, headers)
}

fn host_from_headers(trusted_peer: bool, headers: &HeaderMap) -> Option<String> {
    let forwarded = trusted_peer
        .then(|| {
            // BSV-F18 (B7): the nearest trusted proxy appends last, so the
            // last header line (and the last value in it) wins; a
            // client-supplied first line never does.
            headers
                .get_all("x-forwarded-host")
                .iter()
                .next_back()
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .map(str::trim)
        })
        .flatten();
    let raw = forwarded.or_else(|| {
        headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
    })?;
    normalise_host(raw)
}

fn normalise_host(raw: &str) -> Option<String> {
    let raw = raw.trim();
    // IPv6 literal: keep the bracketed address, drop any port.
    let host = if let Some(rest) = raw.strip_prefix('[') {
        rest.split(']').next()?
    } else {
        raw.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

pub(crate) fn host_admits(audience: HostAudience, host: Option<&str>, config: &AppConfig) -> bool {
    let (hosts, empty_admits_all) = match audience {
        HostAudience::Staff => (&config.deployment.staff_hosts, true),
        // An unconfigured portal host set serves nothing in production, so a
        // deployment can't expose portals on the staff host by omission.
        HostAudience::Portal => (
            &config.deployment.portal_hosts,
            config.app.deployment_profile != "production",
        ),
    };
    admits(hosts, empty_admits_all, host)
}

/// Pure decision, unit-tested below.
fn admits(hosts: &[String], empty_admits_all: bool, host: Option<&str>) -> bool {
    if hosts.is_empty() {
        return empty_admits_all;
    }
    host.is_some_and(|h| hosts.iter().any(|allowed| allowed == h))
}

pub async fn gate(
    State((config, audience)): State<(Arc<AppConfig>, HostAudience)>,
    req: Request,
    next: Next,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let host = request_host(peer, req.headers(), &config);
    if host_admits(audience, host.as_deref(), &config) {
        return next.run(req).await;
    }
    // Portal-audience refusals get their own reason (web portal plan §5), so
    // a probe of portal paths on the staff host set is told apart from a
    // staff-route one.
    let reason = match audience {
        HostAudience::Staff => "host_gate",
        HostAudience::Portal => "portal_host",
    };
    metrics::counter!("security_rejection_total", "reason" => reason).increment(1);
    rejection()
}

/// BSV-F09: the same JSON 404 the staff fallback answers, so a wrong host is
/// indistinguishable from an unknown path.
fn rejection() -> Response {
    attome_types::AppError::NotFound.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(h: &[&str]) -> Vec<String> {
        h.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_empty_set_admits_everything_only_when_told_to() {
        assert!(admits(&[], true, Some("any.example")));
        // Portal in production: unconfigured means no portal anywhere.
        assert!(!admits(&[], false, Some("any.example")));
    }

    #[test]
    fn a_configured_set_admits_only_its_hosts() {
        let staff = hosts(&["app.example.com"]);
        assert!(admits(&staff, true, Some("app.example.com")));
        assert!(!admits(&staff, true, Some("portal.example.com")));
        assert!(!admits(&staff, true, None));
    }

    #[test]
    fn host_is_normalised() {
        assert_eq!(
            normalise_host("App.Example.com:8443").as_deref(),
            Some("app.example.com")
        );
        assert_eq!(normalise_host("[::1]:7865").as_deref(), Some("::1"));
        assert_eq!(normalise_host(""), None);
    }

    #[test]
    fn the_last_forwarded_host_line_wins() {
        let mut h = HeaderMap::new();
        h.insert("host", "portal.example.com".parse().unwrap());
        h.append("x-forwarded-host", "app.example.com".parse().unwrap());
        h.append("x-forwarded-host", "portal.example.com".parse().unwrap());
        assert_eq!(
            host_from_headers(true, &h).as_deref(),
            Some("portal.example.com"),
            "a forged first line must not pick the audience"
        );
    }

    #[tokio::test]
    async fn a_rejected_host_gets_the_json_not_found_envelope() {
        let resp = rejection();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "not_found");
    }

    #[test]
    fn forwarded_host_counts_only_from_a_trusted_peer() {
        let mut h = HeaderMap::new();
        h.insert("host", "portal.example.com".parse().unwrap());
        h.insert(
            "x-forwarded-host",
            "evil.example, app.example.com".parse().unwrap(),
        );
        assert_eq!(
            host_from_headers(false, &h).as_deref(),
            Some("portal.example.com")
        );
        assert_eq!(
            host_from_headers(true, &h).as_deref(),
            Some("app.example.com")
        );
    }
}
