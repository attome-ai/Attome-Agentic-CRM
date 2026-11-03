//! T5-T3: requests naming a Develop workspace.
//!
//! A request carrying [`WORKSPACE_HEADER`] is served by that workspace's own
//! process (`attome serve --workspace <id>`), never by live: the engine keeps
//! process-wide caches a workspace must not share. [`to_workspace`] runs in
//! the core routes after authentication and before any route: it checks the
//! workspace is open and the caller may enter it (the data-model area, or the
//! workspace's owner), then hands the request to the installed
//! [`WorkspaceForwarder`], which `attome serve` provides on live. A
//! workspace's own process installs none, so there the layer serves the
//! request itself.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use attome_core::EngineState;
use attome_core::changeset::CHANGESET_HEADER;
use attome_server::authz::{AdminArea, AuthorizedContext};
use attome_types::AppError;
use axum::{
    body::Body,
    extract::{Request, State},
    http::HeaderValue,
    middleware::Next,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

/// The request header naming the workspace a request runs in.
pub const WORKSPACE_HEADER: &str = "x-attome-workspace";

/// What forwards a request to a workspace's process.
pub trait WorkspaceForwarder: Send + Sync {
    /// Sends `request` (its workspace header already removed) to the process
    /// of `workspace`, starting it when it is not running, and answers its
    /// response.
    fn forward(
        &self,
        workspace: Uuid,
        request: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = Result<Response, AppError>> + Send>>;
}

static FORWARDER: OnceLock<Arc<dyn WorkspaceForwarder>> = OnceLock::new();

/// Installs the forwarder; once per process. `false` when one already was.
pub fn install(forwarder: Arc<dyn WorkspaceForwarder>) -> bool {
    FORWARDER.set(forwarder).is_ok()
}

/// The workspace id a header value names. Pure.
pub fn parse_header(value: &HeaderValue) -> Result<Uuid, AppError> {
    value
        .to_str()
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| AppError::Validation("X-Attome-Workspace is not a workspace id".into()))
}

/// The layer: a request naming a workspace goes to that workspace's process;
/// every other request, and every request inside a workspace's own process,
/// carries on.
pub async fn to_workspace(
    State(state): State<EngineState>,
    request: Request,
    next: Next,
) -> Response {
    if !request.headers().contains_key(WORKSPACE_HEADER) {
        return next.run(request).await;
    }
    let Some(forwarder) = FORWARDER.get() else {
        return next.run(request).await;
    };
    match route(&state, forwarder.as_ref(), request).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn route(
    state: &EngineState,
    forwarder: &dyn WorkspaceForwarder,
    mut request: Request,
) -> Result<Response, AppError> {
    let id = request
        .headers()
        .get(WORKSPACE_HEADER)
        .map(parse_header)
        .transpose()?
        .ok_or(AppError::NotFound)?;
    let ctx = request
        .extensions()
        .get::<AuthorizedContext>()
        .map(AuthorizedContext::to_inner)
        .ok_or(AppError::Unauthorized)?;
    let (owner, changeset): (Uuid, Option<Uuid>) = sqlx::query_as(
        "SELECT owner_ref, changeset_ref FROM develop_workspace WHERE id = $1 AND status = 'open'",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    if !(AdminArea::DataModel.held_by(&ctx) || ctx.user_id == owner) {
        return Err(AppError::Forbidden);
    }
    if let Err(error) =
        sqlx::query("UPDATE develop_workspace SET last_used_at = now() WHERE id = $1")
            .bind(id)
            .execute(&state.base.db)
            .await
    {
        tracing::warn!(workspace = %id, %error, "workspace: last use not recorded");
    }
    request.headers_mut().remove(WORKSPACE_HEADER);
    // T5-T4: every metadata write inside records into the workspace's
    // changeset, whatever the caller named.
    match changeset.map(|c| HeaderValue::from_str(&c.to_string())) {
        Some(Ok(value)) => {
            request.headers_mut().insert(CHANGESET_HEADER, value);
        }
        Some(Err(error)) => return Err(AppError::internal(error)),
        None => {
            request.headers_mut().remove(CHANGESET_HEADER);
        }
    }
    forwarder.forward(id, request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_names_a_workspace_id() {
        let id = Uuid::now_v7();
        let value = HeaderValue::from_str(&format!(" {id} ")).unwrap();
        assert_eq!(parse_header(&value).unwrap(), id);
        assert!(parse_header(&HeaderValue::from_static("live")).is_err());
    }
}
