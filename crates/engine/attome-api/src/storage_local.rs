//! Z6-T1: the server route that stands in for a bucket's presigned URLs when
//! `storage.backend = "local"`.
//!
//! `attome_storage::presign_upload`/`presign_download` hand out links to
//! `/api/v1/storage/local?key=…&expires=…&signature=…` on that backend. The
//! link is the credential, exactly as a presigned bucket URL is: the engine
//! that minted it already checked the caller's permission on that object, and
//! the HMAC binds the method, the key and the expiry. So the path is listed in
//! `attome_server::middleware::bypass::EXACT_BYPASS_PATHS` and this handler
//! runs no session check of its own. An expired, altered or foreign link, a
//! missing object, and a deployment on any other backend all answer the same
//! 404.
//!
//! A download is always served as an attachment with `nosniff` and a
//! sandboxing CSP: the file comes from the application's own origin, and the
//! folder keeps no stored content type, so a browser must never render it.
//! An upload is read whole, bounded by `app.max_body_size_bytes` and the
//! request timeout like every request; the upload session's finalize step
//! still checks the stored size against `storage.max_upload_size_bytes`.

use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Query, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::StreamExt;
use object_store::{ObjectStoreExt, PutPayload};
use serde::Deserialize;
use utoipa::IntoParams;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct LinkQuery {
    /// The object key the link was signed for.
    key: String,
    /// When the link stops working, in seconds since 1970 (UTC).
    expires: u64,
    /// HMAC-SHA256 of the method, key and expiry, in hex.
    signature: String,
}

/// The object a link opens, or the one 404 every refusal shares.
fn open(
    state: &EngineState,
    method: &Method,
    q: &LinkQuery,
) -> Result<object_store::path::Path, AppError> {
    attome_storage::verify_local_link(&state.base.storage, method, &q.key, q.expires, &q.signature)
        .map_err(|_| AppError::NotFound)
}

/// The last key segment as an ASCII file name for `Content-Disposition`.
fn file_name(key: &str) -> String {
    let name: String = key
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    if name.is_empty() {
        "download".to_owned()
    } else {
        name
    }
}

/// Download a file through a local-disk storage link
///
/// Z6-T1: the stand-in for a presigned bucket download when files are kept
/// on the server's disk. The signed link is the credential; the file is sent
/// as an attachment and never rendered.
#[utoipa::path(
    get,
    path = "/api/v1/storage/local",
    tag = "entity",
    operation_id = "download_local_object",
    params(LinkQuery),
    responses(
        (status = 200, description = "The stored file, as an attachment", content_type = "application/octet-stream"),
        (status = 404, description = "The link is expired or altered, the file is gone, or this deployment does not keep files on local disk", body = ErrorResponse),
    ),
)]
async fn download_local_object(
    State(state): State<EngineState>,
    Query(q): Query<LinkQuery>,
) -> Result<Response, AppError> {
    let path = open(&state, &Method::GET, &q)?;
    let object = match state.base.storage.store().get(&path).await {
        Ok(object) => object,
        Err(object_store::Error::NotFound { .. }) => return Err(AppError::NotFound),
        Err(e) => return Err(AppError::internal(e)),
    };
    let size = object.meta.size;
    let body = Body::from_stream(
        object
            .into_stream()
            .map(|chunk| chunk.map_err(axum::Error::new)),
    );
    let disposition = format!("attachment; filename=\"{}\"", file_name(&q.key));
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox; default-src 'none'"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// Upload a file through a local-disk storage link
///
/// Z6-T1: the stand-in for a presigned bucket upload when files are kept on
/// the server's disk. The signed link names the one object an upload session
/// was created for; finalize and the malware scan check what was written.
#[utoipa::path(
    put,
    path = "/api/v1/storage/local",
    tag = "entity",
    operation_id = "upload_local_object",
    params(LinkQuery),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The file's bytes"),
    responses(
        (status = 200, description = "Stored"),
        (status = 404, description = "The link is expired or altered, or this deployment does not keep files on local disk", body = ErrorResponse),
        (status = 413, description = "Larger than app.max_body_size_bytes", body = ErrorResponse),
    ),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("files_scan.rs / entity_crud update"),
        "writes the bytes of an upload session to quarantine, as a presigned bucket PUT does; the scan result (FileScanned) and field promotion (Entity/Update) are audited on their own paths",
    )))),
)]
async fn upload_local_object(
    State(state): State<EngineState>,
    Query(q): Query<LinkQuery>,
    body: Bytes,
) -> Result<Response, AppError> {
    let path = open(&state, &Method::PUT, &q)?;
    state
        .base
        .storage
        .store()
        .put(&path, PutPayload::from(body))
        .await
        .map_err(AppError::internal)?;
    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
    )
        .into_response())
}

pub fn routes() -> Router<EngineState> {
    // A literal (it equals `attome_storage::LOCAL_LINK_PATH`, which the
    // test below pins) so the route census in `tests/route_authz.rs` sees it.
    Router::new().route(
        "/api/v1/storage/local",
        get(download_local_object).put(upload_local_object),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(download_local_object, upload_local_object))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_route_is_the_path_storage_links_point_at() {
        assert_eq!(attome_storage::LOCAL_LINK_PATH, "/api/v1/storage/local");
    }

    #[test]
    fn file_name_keeps_the_last_segment_in_plain_ascii() {
        assert_eq!(file_name("tenants/t1/files/report.pdf"), "report.pdf");
        assert_eq!(file_name("a/b/\"x\";y.csv"), "xy.csv");
        assert_eq!(file_name("a/b/"), "download");
    }
}
