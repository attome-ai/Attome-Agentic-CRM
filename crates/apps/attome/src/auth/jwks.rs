//! Z4-T4: the public half of the token-signing keys, as a JSON Web Key Set
//! (RFC 7517), so another service can verify this deployment's EdDSA tokens
//! without holding a shared secret. Public and bypass-listed: a public key
//! is meant to be published. HS256 secrets are never listed; with no
//! Ed25519 ring configured the set is empty.

use axum::{
    Json,
    http::header,
    response::{IntoResponse, Response},
};

/// Public token-signing keys.
///
/// The Ed25519 keys this deployment signs session tokens with
/// (`auth.jwt_signing_keys`), public halves only, each with its `kid`.
/// Cacheable for five minutes; a rotated-in key appears here before it signs.
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    tag = "auth",
    operation_id = "get_jwks",
    responses(
        (status = 200, description = "A JSON Web Key Set (RFC 7517) of the public signing keys", content_type = "application/json"),
    ),
)]
pub(super) async fn get_jwks() -> Response {
    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Json(attome_auth::jwt::jwks()),
    )
        .into_response()
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_jwks))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
