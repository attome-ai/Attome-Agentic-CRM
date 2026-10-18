//! AA7-T5: cooked artefacts at hash-named URLs.
//!
//! `GET /api/v1/cooked/{kind}` lists the current version's artefacts of a
//! kind as `(key, hash)`; it changes with every publish, so it revalidates.
//! `GET /api/v1/cooked/{kind}/{hash}` serves one artefact's bytes. A hash
//! names one content forever, so that route's cache class is
//! `PrivateImmutable` (`private, max-age=31536000, immutable`, set by the
//! cache-policy layer): a browser downloads each
//! artefact once per version and never asks again, and no shared cache
//! keeps it (the caller is signed in). Brotli comes from the server's
//! compression layer for bodies over 1 KiB; since each client fetches a hash
//! once, no compressed copy is stored.
//!
//! Only kinds every signed-in user may already read are served
//! ([`SHARED_KINDS`]: forms, which `/api/v1/model/forms/{id}/plan` serves
//! too, and option sets, which choice fields expose). Agents, prompts,
//! navigation (filtered per user when served), environment variables and
//! the rest answer 404, as does a hash that is not in the current version.
//! Both routes read only memory once the registry is loaded.

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use utoipa::ToSchema;

use super::{cooked, refresh_cooked};

/// The kinds a signed-in caller may fetch: their artefacts hold nothing a
/// user cannot already read.
pub const SHARED_KINDS: &[&str] = &["form", "option_set"];

/// One artefact of the current version.
#[derive(Debug, Serialize, ToSchema)]
pub struct CookedRef {
    /// The artefact key, `<kind>:<object id>`.
    pub key: String,
    /// SHA-256 of the artefact's bytes, lowercase hex.
    pub hash: String,
    /// Where to fetch it: `/api/v1/cooked/{kind}/{hash}`.
    pub url: String,
}

fn shared(kind: &str) -> Result<(), AppError> {
    if SHARED_KINDS.contains(&kind) {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// Whether `hash` is a SHA-256 in lowercase hex.
fn is_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

async fn ensure_loaded(state: &EngineState) -> Result<(), AppError> {
    if cooked().snapshot().version == 0 {
        // Cold start: build the cooked registry from the published store.
        refresh_cooked(state).await?;
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/v1/cooked/{kind}",
    tag = "model",
    operation_id = "list_cooked_artefacts",
    params(("kind" = String, Path, description = "Artefact kind: `form` or `option_set`")),
    responses(
        (status = 200, description = "The current version's artefacts of the kind, with their hash-named URLs", body = PaginatedResponse<CookedRef>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Not a kind served here", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// The current version's artefacts of a kind.
///
/// Each artefact's key, content hash and URL. The list changes with every
/// publish; the artefacts behind it never change.
async fn list_cooked(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
    Path(kind): Path<String>,
) -> Result<Json<PaginatedResponse<CookedRef>>, AppError> {
    shared(&kind)?;
    ensure_loaded(&state).await?;
    let items: Vec<CookedRef> = cooked()
        .hashes(&kind)
        .into_iter()
        .map(|(key, hash)| CookedRef {
            url: format!("/api/v1/cooked/{kind}/{hash}"),
            key,
            hash,
        })
        .collect();
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

#[utoipa::path(
    get,
    path = "/api/v1/cooked/{kind}/{hash}",
    tag = "model",
    operation_id = "get_cooked_artefact",
    params(
        ("kind" = String, Path, description = "Artefact kind: `form` or `option_set`"),
        ("hash" = String, Path, description = "The artefact's SHA-256, lowercase hex"),
        ("If-None-Match" = Option<String>, Header, description = "The artefact's hash in quotes, when the client holds it"),
    ),
    responses(
        (status = 200, description = "The artefact's JSON, cached as immutable", body = serde_json::Value),
        (status = 304, description = "The client already holds this artefact"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Not a kind served here, or no artefact with this hash in the current version", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// One cooked artefact by its content hash.
///
/// The bytes never change under this URL, so the response may be kept for
/// a year without asking again.
async fn get_cooked(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
    Path((kind, hash)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    shared(&kind)?;
    if !is_hash(&hash) {
        return Err(AppError::NotFound);
    }
    ensure_loaded(&state).await?;
    let payload = cooked()
        .payload_by_hash(&kind, &hash)
        .ok_or(AppError::NotFound)?;
    let etag = HeaderValue::from_str(&format!("\"{hash}\"")).map_err(AppError::internal)?;
    let held = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|tag| tag.trim().trim_start_matches("W/") == etag)
        });
    if held {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
    }
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::ETAG, etag),
        ],
        payload.to_vec(),
    )
        .into_response())
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/cooked/{kind}", get(list_cooked))
        .route("/api/v1/cooked/{kind}/{hash}", get(get_cooked))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_cooked, get_cooked), components(schemas(CookedRef)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_shared_kinds_are_served() {
        assert!(shared("form").is_ok());
        assert!(shared("option_set").is_ok());
        for kind in [
            "agent",
            "navigation",
            "environment_variable",
            "prompt_override",
        ] {
            assert!(shared(kind).is_err(), "{kind}");
        }
    }

    #[test]
    fn a_hash_is_64_lowercase_hex() {
        assert!(is_hash(&"a1".repeat(32)));
        assert!(!is_hash(&"A1".repeat(32)));
        assert!(!is_hash("abc"));
        assert!(!is_hash(&"g1".repeat(32)));
    }
}
