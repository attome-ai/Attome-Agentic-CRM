//! `RecordingCtx` — the axum extractor that builds a
//! [`Recording::Request`](super::Recording) for a metadata admin handler
//! (design §4.1). Handlers add `recording: RecordingCtx` to their arguments.
//!
//! It reads, and never trusts anything else:
//! - `X-Attome-Changeset` (a malformed value is a 422, never ignored);
//! - the authenticated principal from the extension `authz` attached (the
//!   same source `Authorized<_>` reads; absent is a 401, as there);
//! - the request id (`x-request-id`, set by `SetRequestIdLayer`);
//! - the matched route template;
//! - `metadata.changesets` from config;
//! - whether a break-glass window admitted the request. That is derived, not
//!   read from a flag: on the production profile the authoring gate refuses
//!   every mutating request to a metadata-authoring path unless a window is
//!   open, so such a request reaching a handler was admitted by one.

use attome_server::AppState;
use attome_server::authz::AuthorizedContext;
use attome_server::middleware::authoring_gate::is_metadata_authoring_path;
use attome_types::AppError;
use axum::extract::{FromRef, FromRequestParts, MatchedPath};
use axum::http::{Method, request::Parts};
use uuid::Uuid;

use super::recorder::{Recording, RequestContext};

/// The request header naming the changeset to record into.
pub const CHANGESET_HEADER: &str = "x-attome-changeset";

/// The S2S client-id header; its presence means `s2s_authn` verified (or
/// would have rejected) the request's signature.
const S2S_CLIENT_HEADER: &str = "x-s2s-client-id";

/// A request's [`Recording`]. Derefs to it.
#[derive(Debug)]
pub struct RecordingCtx(pub Recording);

impl std::ops::Deref for RecordingCtx {
    type Target = Recording;

    fn deref(&self) -> &Recording {
        &self.0
    }
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// The pure half of the extractor, split out so it is testable without an
/// `AppState`.
fn request_context(
    parts: &Parts,
    config: &attome_config::AppConfig,
) -> Result<RequestContext, AppError> {
    // The header sits outside the S2S canonical message (SEC-10), so on a
    // signed S2S request a tampered value could redirect the recorded op into
    // another open changeset. Refuse it there: S2S writes record into the
    // caller's own open changeset or an automatic one. This keeps the header
    // inert for S2S (`attome-s2s/tests/signed_header_coverage.rs`).
    if parts.headers.contains_key(CHANGESET_HEADER) && parts.headers.contains_key(S2S_CLIENT_HEADER)
    {
        return Err(AppError::Validation(
            "X-Attome-Changeset is not accepted on server-to-server requests".into(),
        ));
    }
    let header = match parts.headers.get(CHANGESET_HEADER) {
        None => None,
        Some(value) => Some(
            value
                .to_str()
                .ok()
                .and_then(|s| Uuid::parse_str(s.trim()).ok())
                .ok_or_else(|| {
                    AppError::Validation("X-Attome-Changeset must be a changeset id (UUID)".into())
                })?,
        ),
    };

    let Some(authorized) = parts.extensions.get::<AuthorizedContext>() else {
        tracing::error!(
            path = %parts.uri.path(),
            "changeset recording: no authorization context on a metadata write; check the \
             route composition"
        );
        return Err(AppError::Unauthorized);
    };
    let actor = authorized.get().user_id;

    let request_id = parts
        .headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let template = parts
        .extensions
        .get::<MatchedPath>()
        .map_or_else(|| parts.uri.path().to_owned(), |m| m.as_str().to_owned());
    let route = format!("{} {template}", parts.method);

    let profile = config.app.deployment_profile.as_str();
    let changesets = &config.metadata.changesets;
    let break_glass = profile == "production"
        && is_mutating(&parts.method)
        && is_metadata_authoring_path(parts.uri.path());

    Ok(RequestContext {
        header,
        actor: Some(actor),
        actor_label: format!("user:{actor}"),
        request_id,
        route,
        mode: changesets.effective_mode(profile),
        auto_layer: changesets.auto_layer,
        break_glass,
    })
}

impl<S> FromRequestParts<S> for RecordingCtx
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = AppState::from_ref(state);
        let ctx = request_context(parts, &app.config)?;
        Ok(Self(Recording::for_request(ctx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_config::{ChangesetMode, ChangesetsSection};
    use attome_server::security::SecurityContext;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;

    fn config(profile: &str, mode: Option<ChangesetMode>) -> attome_config::AppConfig {
        let mut value: serde_json::Value =
            serde_json::from_str(include_str!("../../../../../config.example.json"))
                .expect("config.example.json parses");
        value["app"]["deployment_profile"] = serde_json::json!(profile);
        let mut config: attome_config::AppConfig =
            serde_json::from_value(value).expect("config.example.json deserializes");
        config.metadata.changesets = ChangesetsSection {
            mode,
            ..ChangesetsSection::default()
        };
        config
    }

    fn context_for(user: Uuid) -> AuthorizedContext {
        let ctx: SecurityContext = serde_json::from_value(serde_json::json!({
            "user_id": user,
            "is_admin": true,
            "privileges": ["system.admin"],
        }))
        .expect("a minimal security context deserializes");
        AuthorizedContext::new(Arc::new(ctx))
    }

    fn parts(method: Method, path: &str, header: Option<&str>, user: Option<Uuid>) -> Parts {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("x-request-id", "req-1");
        if let Some(h) = header {
            builder = builder.header(CHANGESET_HEADER, h);
        }
        let mut request = builder.body(Body::empty()).expect("request");
        if let Some(user) = user {
            request.extensions_mut().insert(context_for(user));
        }
        request.into_parts().0
    }

    #[test]
    fn reads_the_header_actor_request_id_and_mode() {
        let user = Uuid::now_v7();
        let id = Uuid::now_v7();
        let ctx = request_context(
            &parts(
                Method::PATCH,
                "/api/v1/admin/views/1",
                Some(&id.to_string()),
                Some(user),
            ),
            &config("development", None),
        )
        .expect("context");
        assert_eq!(ctx.header, Some(id));
        assert_eq!(ctx.actor, Some(user));
        assert_eq!(ctx.request_id.as_deref(), Some("req-1"));
        assert_eq!(ctx.route, "PATCH /api/v1/admin/views/1");
        // An unset mode means `auto` on every profile (L2); development sets
        // `required` explicitly in its config.
        assert_eq!(ctx.mode, ChangesetMode::Auto);
        assert!(!ctx.break_glass);
    }

    #[test]
    fn a_malformed_header_is_refused_not_ignored() {
        let err = request_context(
            &parts(
                Method::POST,
                "/api/v1/admin/views",
                Some("not-a-uuid"),
                Some(Uuid::now_v7()),
            ),
            &config("development", None),
        )
        .expect_err("malformed header");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn the_changeset_header_is_refused_on_an_s2s_request() {
        let mut p = parts(
            Method::POST,
            "/api/v1/admin/views",
            Some(&Uuid::now_v7().to_string()),
            Some(Uuid::now_v7()),
        );
        p.headers.insert(
            S2S_CLIENT_HEADER,
            axum::http::HeaderValue::from_static("client-a"),
        );
        let err = request_context(&p, &config("development", None))
            .expect_err("changeset header on an S2S request");
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn an_s2s_request_without_the_header_still_records() {
        let mut p = parts(
            Method::POST,
            "/api/v1/admin/views",
            None,
            Some(Uuid::now_v7()),
        );
        p.headers.insert(
            S2S_CLIENT_HEADER,
            axum::http::HeaderValue::from_static("client-a"),
        );
        let ctx = request_context(&p, &config("development", None)).expect("context");
        assert_eq!(ctx.header, None);
    }

    #[test]
    fn no_authorization_context_is_a_401() {
        let err = request_context(
            &parts(Method::POST, "/api/v1/admin/views", None, None),
            &config("development", None),
        )
        .expect_err("no context");
        assert!(matches!(err, AppError::Unauthorized));
    }

    #[test]
    fn a_production_authoring_write_is_a_break_glass_write() {
        let cfg = config("production", None);
        let user = Some(Uuid::now_v7());
        let ctx = request_context(
            &parts(Method::POST, "/api/v1/admin/views", None, user),
            &cfg,
        )
        .expect("context");
        assert_eq!(ctx.mode, ChangesetMode::Auto);
        assert!(ctx.break_glass);
        // The import prefix is exempt from the gate, so it is no break-glass.
        let ctx = request_context(
            &parts(Method::POST, "/api/v1/admin/metadata/import", None, user),
            &cfg,
        )
        .expect("context");
        assert!(!ctx.break_glass);
    }
}
