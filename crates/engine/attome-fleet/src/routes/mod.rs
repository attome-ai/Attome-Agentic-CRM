//! `/api/v1/fleet/**` — the console's own routes (design §6).
//!
//! Every route here:
//! - exists only in the router [`router`] builds, which only the gated boot
//!   path calls — there is no per-route gate check to forget (§2.5);
//! - refuses a non-loopback peer with 403 `fleet_console_loopback_only`,
//!   judged on the connection's peer address, never `X-Forwarded-For`, and
//!   failing closed when it is unknown ([`require_loopback`]);
//! - takes `Authorized<Admin>` and a human cookie session ([`HumanSession`]):
//!   API-key and S2S callers are refused, the console is a human tool;
//! - when it mutates, declares `x-audit` (D-542), writes a security event in
//!   its own transaction and an append-only `fleet_action` row whose id
//!   travels to the customer as `x-correlation-id` (§6.7).
//!
//! Publish (rollout start, target apply, resume) and credential changes also
//! require a fresh MFA step-up (§2.5) — see [`require_step_up`].

pub mod deployments;
pub mod reports;
pub mod rollouts;

use std::net::{IpAddr, SocketAddr};

use attome_audit::security::{SecurityEvent, SecurityTx};
use attome_auth::step_up::{Caller, Operation};
use attome_server::step_up::StepUpCaller;
use attome_types::AppError;
use axum::Router;
use axum::extract::{ConnectInfo, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::middleware::{self, Next};
use axum::response::Response;
use uuid::Uuid;

use crate::runtime::FleetState;
use crate::store::{self, ActionWrite};

/// The OpenAPI tag of every console route.
pub const TAG: &str = "fleet";

/// The step-up operation publish and credential changes require. Base-auth
/// knows four elevation operations; the console reuses the 15-minute
/// `api_key_create` elevation (the same step-up API-key creation uses,
/// design §2.5) until attome-auth gains a dedicated `fleet_publish` operation.
pub const STEP_UP_OPERATION: Operation = Operation::ApiKeyCreate;

/// True only for a known loopback peer (IPv4-mapped IPv6 included).
pub fn peer_is_loopback(peer: Option<IpAddr>) -> bool {
    peer.is_some_and(|ip| ip.to_canonical().is_loopback())
}

/// Refuses every request whose TCP peer is not loopback (design §2.5).
pub async fn require_loopback(request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip());
    if peer_is_loopback(peer) {
        next.run(request).await
    } else {
        tracing::warn!(peer = ?peer, path = %request.uri().path(), "fleet console: refused a non-loopback peer");
        crate::error::loopback_refusal()
    }
}

/// A human cookie session (design §2.5): API-key and S2S callers get 403.
#[derive(Debug, Clone, Copy)]
pub struct HumanSession(pub Caller);

impl<S> FromRequestParts<S> for HumanSession
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let StepUpCaller(caller) = match StepUpCaller::from_request_parts(parts, state).await {
            Ok(caller) => caller,
            Err(never) => match never {},
        };
        if caller == Caller::NonSession {
            return Err(AppError::Forbidden);
        }
        Ok(Self(caller))
    }
}

/// A fresh MFA step-up on the caller's own session (design §2.5).
pub async fn require_step_up(
    state: &FleetState,
    session: HumanSession,
    user_id: Uuid,
) -> Result<(), AppError> {
    attome_auth::step_up::require_recent_auth(
        &state.xrm.base.db,
        session.0,
        user_id,
        STEP_UP_OPERATION,
        state.xrm.base.config.refresh_absolute_lifetime_secs(),
    )
    .await
}

/// Writes one console action: its security event and its action-log row in
/// one transaction (design §6.7).
pub async fn record(
    state: &FleetState,
    event: SecurityEvent,
    action: &ActionWrite,
) -> Result<(), AppError> {
    let mut stx = SecurityTx::begin(&state.xrm, event).await?;
    store::insert_action(&mut stx, action).await?;
    stx.commit().await?;
    Ok(())
}

/// `If-Match`-style optimistic concurrency, carried in the body as
/// `row_version` (the console's own rows).
pub fn version_conflict_if_none<T>(value: Option<T>) -> Result<T, AppError> {
    value.ok_or(AppError::VersionConflict)
}

/// The console's router, with its state and the loopback guard. Called only
/// by the gated boot path ([`crate::mount`]).
pub fn router(state: FleetState) -> Router {
    Router::new()
        .merge(deployments::routes())
        .merge(reports::routes())
        .merge(rollouts::routes())
        .layer(middleware::from_fn(require_loopback))
        .with_state(state)
}

/// The console's slice of the OpenAPI document. `crates/server/src/openapi.rs`
/// must merge it under `#[cfg(feature = "fleet-console")]` (integrator step,
/// outside lane FC-B's write surface) for `generate:api` to see it.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut document = deployments::openapi_fragment();
    document.merge(reports::openapi_fragment());
    document.merge(rollouts::openapi_fragment());
    document
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::get;
    use tower::ServiceExt;

    fn guarded() -> Router {
        Router::new()
            .route("/api/v1/fleet/ping", get(|| async { "ok" }))
            .layer(middleware::from_fn(require_loopback))
    }

    async fn call(peer: Option<&str>) -> (StatusCode, serde_json::Value) {
        let mut request = axum::http::Request::builder()
            .uri("/api/v1/fleet/ping")
            .body(Body::empty())
            .expect("request");
        if let Some(peer) = peer {
            let address: SocketAddr = peer.parse().expect("socket address");
            request.extensions_mut().insert(ConnectInfo(address));
        }
        let response = guarded().oneshot(request).await.expect("answers");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, body)
    }

    #[tokio::test]
    async fn a_loopback_peer_passes() {
        assert_eq!(call(Some("127.0.0.1:50000")).await.0, StatusCode::OK);
        assert_eq!(call(Some("[::1]:50000")).await.0, StatusCode::OK);
        assert_eq!(
            call(Some("[::ffff:127.0.0.1]:50000")).await.0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn any_other_peer_is_refused_with_the_named_code() {
        for peer in ["192.168.1.20:50000", "10.0.0.5:443", "[2001:db8::1]:50000"] {
            let (status, body) = call(Some(peer)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{peer}");
            assert_eq!(body["error"], crate::error::LOOPBACK_ONLY, "{peer}");
        }
    }

    #[tokio::test]
    async fn an_unknown_peer_fails_closed() {
        let (status, body) = call(None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], crate::error::LOOPBACK_ONLY);
    }

    #[test]
    fn every_mutating_route_declares_its_audit_event() {
        let document = serde_json::to_value(openapi()).expect("serializes");
        let mut mutating = 0;
        for (path, operations) in document["paths"].as_object().expect("paths") {
            for (method, operation) in operations.as_object().expect("operations") {
                if method == "get" {
                    continue;
                }
                mutating += 1;
                assert!(
                    operation["x-audit"]["events"].is_array(),
                    "{method} {path} declares no x-audit"
                );
                assert!(
                    operation["security"].to_string().contains("session_cookie"),
                    "{method} {path} must be session-only"
                );
            }
        }
        assert!(mutating >= 14, "{mutating} mutating routes");
    }
}
