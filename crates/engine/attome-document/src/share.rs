//! K1-T1: external sharing links for stored files.
//!
//! Someone who may change a record can hand one of its stored files to a
//! person outside the deployment: a link that expires (at most
//! [`MAX_SHARE_HOURS`] out), may need a password and may allow only so many
//! downloads. The link names the object stored when it was made, so a later
//! upload to the field does not change what it serves; deleting the record or
//! revoking the link ends it.
//!
//! **Token.** 32 random bytes (two v4 UUIDs, from the OS generator) shown
//! once, as hex; only its SHA-256 is stored (`file_share_link.token_hash`).
//! A high-entropy token needs no slow hash; the optional password, chosen by
//! a person, is an Argon2id hash like an account password.
//!
//! **Download.** `GET /api/v1/shared-files/{token}` answers `303` to a
//! five-minute presigned GET (the object already carries
//! `Content-Disposition: attachment` and a sniffed type from its promotion);
//! a link with a password is opened with `POST` and `{ "password": … }`,
//! which answers the URL as JSON. Every served download counts against the
//! link's limit inside one guarded `UPDATE` and is audited
//! (`Attachment`/`Export`) in the same transaction. An unknown, revoked,
//! expired or used-up link, or one whose record is gone, is a plain `404`.
//! The two routes are public (`bypass.rs`) and rate limited like the other
//! anonymous token routes.

use std::time::Duration;

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
    fetch_audit_ctx,
};
use attome_core::{EngineState, quote_ident};
use attome_records::entity_crud::require_record_access;
use attome_security::RecordAction;
use attome_security::record_action::{Read, Update};
use attome_server::authz::{Authorized, RecordScoped};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

/// The longest a link may live: 30 days.
pub const MAX_SHARE_HOURS: i64 = 30 * 24;
/// A link's lifetime when the request names none: three days.
pub const DEFAULT_SHARE_HOURS: i64 = 72;
/// How long the presigned URL a download answers with stays valid.
const DOWNLOAD_URL_TTL: Duration = Duration::from_secs(5 * 60);
/// The most links one field of one record may have at once.
const MAX_LIVE_LINKS_PER_FIELD: i64 = 50;

/// `POST /api/v1/{entity}/{id}/files/{field}/share-links`.
#[derive(Default, Deserialize, ToSchema)]
pub struct CreateShareLinkRequest {
    /// For a multi-file field, which stored object to share (one of the
    /// field's keys); ignored for a single-file field.
    pub key: Option<String>,
    /// Hours until the link stops working, 1 to 720 (30 days); 72 when absent.
    pub expires_in_hours: Option<i64>,
    /// Optional; whoever opens the link must give it. The same strength
    /// rules as an account password apply.
    pub password: Option<String>,
    /// Optional limit on downloads, at least 1.
    pub max_downloads: Option<i32>,
}

impl std::fmt::Debug for CreateShareLinkRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateShareLinkRequest")
            .field("expires_in_hours", &self.expires_in_hours)
            .field("has_password", &self.password.is_some())
            .field("max_downloads", &self.max_downloads)
            .finish_non_exhaustive()
    }
}

/// A new link. `token` and `path` are shown this once.
#[derive(Serialize, ToSchema)]
pub struct CreatedShareLink {
    pub id: Uuid,
    pub token: String,
    /// The public path to hand out: `/api/v1/shared-files/{token}`.
    pub path: String,
    pub expires_at: DateTime<Utc>,
    pub max_downloads: Option<i32>,
    pub has_password: bool,
}

impl std::fmt::Debug for CreatedShareLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedShareLink")
            .field("id", &self.id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// One link of a field, as its owner sees it (never the token).
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct ShareLinkSummary {
    pub id: Uuid,
    pub object_key: String,
    pub expires_at: DateTime<Utc>,
    pub max_downloads: Option<i32>,
    pub download_count: i32,
    pub has_password: bool,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// `POST /api/v1/shared-files/{token}`.
#[derive(Default, Deserialize, ToSchema)]
pub struct OpenShareLinkRequest {
    pub password: Option<String>,
}

impl std::fmt::Debug for OpenShareLinkRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenShareLinkRequest")
            .finish_non_exhaustive()
    }
}

/// What opening a password link answers.
#[derive(Serialize, ToSchema)]
pub struct SharedFileUrl {
    pub download_url: String,
    pub expires_in_secs: u64,
}

impl std::fmt::Debug for SharedFileUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedFileUrl")
            .field("expires_in_secs", &self.expires_in_secs)
            .finish_non_exhaustive()
    }
}

/// A fresh link secret: 32 bytes from the OS generator, as 64 hex digits.
fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// The stored form of a token.
fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A token has the shape [`new_token`] makes; anything else is not looked up.
fn plausible_token(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The link lifetime a request asks for, checked.
fn lifetime_hours(requested: Option<i64>) -> Result<i64, AppError> {
    let hours = requested.unwrap_or(DEFAULT_SHARE_HOURS);
    if !(1..=MAX_SHARE_HOURS).contains(&hours) {
        return Err(AppError::Validation(format!(
            "expires_in_hours must be between 1 and {MAX_SHARE_HOURS}"
        )));
    }
    Ok(hours)
}

/// The object a new link may share: the single-file field's value, or for a
/// multi-file field the named one of its keys. Always a key this record and
/// field own.
async fn shareable_key(
    state: &EngineState,
    entity: &str,
    record_id: Uuid,
    field: &str,
    requested: Option<&str>,
) -> Result<String, AppError> {
    let stored: Option<Option<serde_json::Value>> = sqlx::query_scalar(&format!(
        "SELECT to_jsonb({}) FROM {} WHERE id = $1 AND is_active = true",
        quote_ident(field),
        quote_ident(entity)
    ))
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let stored = stored.ok_or(AppError::NotFound)?;
    let key = match stored {
        Some(serde_json::Value::String(key)) => key,
        Some(serde_json::Value::Array(keys)) => {
            let wanted = requested
                .map(str::trim)
                .filter(|k| !k.is_empty())
                .ok_or_else(|| {
                    AppError::Validation("key is required for a multi-file field".into())
                })?;
            keys.iter()
                .filter_map(serde_json::Value::as_str)
                .find(|k| *k == wanted)
                .map(str::to_owned)
                .ok_or_else(|| AppError::Validation(format!("{field} holds no such file")))?
        }
        _ => {
            return Err(AppError::Validation(format!(
                "{field} has no file to share"
            )));
        }
    };
    if !crate::files::is_owned_file_key(entity, record_id, field, &key) {
        return Err(AppError::Validation(format!(
            "{field} contains an object key not owned by this record"
        )));
    }
    Ok(key)
}

async fn resolve(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    entity_input: &str,
    record_id: Uuid,
    field_input: &str,
    action: RecordAction,
) -> Result<(String, String), AppError> {
    let (entity_id, entity, field) =
        crate::files::resolve_file_field(state, entity_input, field_input).await?;
    require_record_access(state, ctx, entity_id, &entity, record_id, action).await?;
    Ok((entity, field))
}

#[allow(clippy::too_many_arguments)]
async fn write_audit(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    actor: Uuid,
    operation: AuditOperation,
    entity: &str,
    record_id: Uuid,
    field: &str,
    comment: String,
) -> Result<(), AppError> {
    let (user_context, organization_ref) = fetch_audit_ctx(state, actor).await;
    audit_service(state)
        .write_in_tx(
            tx,
            AuditEvent {
                organization_ref,
                category: AuditCategory::Attachment,
                entity_name: Some(entity.to_owned()),
                record_id: Some(record_id),
                operation,
                version_before: None,
                version_after: None,
                user_context,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some(field.to_owned()),
                event_comment: Some(comment),
                changed_fields: Vec::new(),
                snapshot_json: None,
            },
        )
        .await?;
    Ok(())
}

/// Share a file outside the deployment
///
/// A link to the file as stored now, for someone without an account: it expires, may need a password
/// and may allow only so many downloads. The token is shown once. Needs update rights on the record.
/// Audited.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/files/{field}/share-links",
    tag = "entity",
    operation_id = "create_file_share_link",
    params(("entity" = String, Path, description = "The entity's logical name"), ("id" = Uuid, Path, description = "The record"), ("field" = String, Path, description = "The file field")),
    request_body = CreateShareLinkRequest,
    responses(
        (status = 201, description = "The link; its token is shown only now", body = CreatedShareLink),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not change the record", body = ErrorResponse),
        (status = 404, description = "No such record or field", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Attachment, attome_audit::AuditOperation::Create)])))),
)]
async fn create_share_link(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity_input, record_id, field_input)): Path<(String, Uuid, String)>,
    Json(body): Json<CreateShareLinkRequest>,
) -> Result<Response, AppError> {
    let (entity, field) = resolve(
        &state,
        &ctx,
        &entity_input,
        record_id,
        &field_input,
        RecordAction::Update,
    )
    .await?;
    let hours = lifetime_hours(body.expires_in_hours)?;
    if body.max_downloads.is_some_and(|n| n < 1) {
        return Err(AppError::Validation(
            "max_downloads must be at least 1".into(),
        ));
    }
    let password_hash = match body.password.as_deref() {
        Some(password) => {
            let checked = attome_auth::password::NewPassword::validate(password)?;
            Some(attome_auth::password::hash_password_async(checked).await?)
        }
        None => None,
    };
    let object_key = shareable_key(&state, &entity, record_id, &field, body.key.as_deref()).await?;
    let token = new_token();
    let expires_at = Utc::now() + chrono::Duration::hours(hours);

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM file_share_link \
         WHERE entity = $1 AND record_id = $2 AND field = $3 \
           AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(&entity)
    .bind(record_id)
    .bind(&field)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if live >= MAX_LIVE_LINKS_PER_FIELD {
        return Err(AppError::Validation(format!(
            "{field} already has {MAX_LIVE_LINKS_PER_FIELD} live links; revoke one first"
        )));
    }
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO file_share_link \
             (entity, record_id, field, object_key, token_hash, password_hash, expires_at, \
              max_downloads, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(&entity)
    .bind(record_id)
    .bind(&field)
    .bind(&object_key)
    .bind(token_hash(&token))
    .bind(&password_hash)
    .bind(expires_at)
    .bind(body.max_downloads)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_audit(
        &state,
        &mut tx,
        ctx.user_id,
        AuditOperation::Create,
        &entity,
        record_id,
        &field,
        format!("share link {id} made, expires {expires_at}"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;

    let created = CreatedShareLink {
        id,
        path: format!("/api/v1/shared-files/{token}"),
        token,
        expires_at,
        max_downloads: body.max_downloads,
        has_password: password_hash.is_some(),
    };
    Ok((StatusCode::CREATED, Json(created)).into_response())
}

/// List a file's share links
///
/// The external links to the file, newest first; never their tokens. Anyone who may read the record.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/files/{field}/share-links",
    tag = "entity",
    operation_id = "list_file_share_links",
    params(("entity" = String, Path, description = "The entity's logical name"), ("id" = Uuid, Path, description = "The record"), ("field" = String, Path, description = "The file field")),
    responses(
        (status = 200, description = "The field's links, newest first (page 1 holds them all)", body = PaginatedResponse<ShareLinkSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not read the record", body = ErrorResponse),
        (status = 404, description = "No such record or field", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_share_links(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id, field_input)): Path<(String, Uuid, String)>,
) -> Result<Json<PaginatedResponse<ShareLinkSummary>>, AppError> {
    let (entity, field) = resolve(
        &state,
        &ctx,
        &entity_input,
        record_id,
        &field_input,
        RecordAction::Read,
    )
    .await?;
    let links: Vec<ShareLinkSummary> = sqlx::query_as(
        "SELECT id, object_key, expires_at, max_downloads, download_count, \
                password_hash IS NOT NULL AS has_password, created_by, created_at, revoked_at \
           FROM file_share_link \
          WHERE entity = $1 AND record_id = $2 AND field = $3 \
          ORDER BY created_at DESC, id DESC LIMIT 200",
    )
    .bind(&entity)
    .bind(record_id)
    .bind(&field)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = links.len() as i64;
    Ok(Json(PaginatedResponse {
        items: links,
        total,
        page: 1,
        page_size: 200,
        warnings: Vec::new(),
    }))
}

/// Revoke a share link
///
/// The link stops working at once. Needs update rights on the record. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/{entity}/{id}/files/{field}/share-links/{link_id}",
    tag = "entity",
    operation_id = "revoke_file_share_link",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("field" = String, Path, description = "The file field"),
        ("link_id" = Uuid, Path, description = "The link"),
    ),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not change the record", body = ErrorResponse),
        (status = 404, description = "No such live link on this field", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Attachment, attome_audit::AuditOperation::SoftDelete)])))),
)]
async fn revoke_share_link(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity_input, record_id, field_input, link_id)): Path<(String, Uuid, String, Uuid)>,
) -> Result<StatusCode, AppError> {
    let (entity, field) = resolve(
        &state,
        &ctx,
        &entity_input,
        record_id,
        &field_input,
        RecordAction::Update,
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let revoked = sqlx::query(
        "UPDATE file_share_link SET revoked_at = now(), revoked_by = $5 \
          WHERE id = $1 AND entity = $2 AND record_id = $3 AND field = $4 \
            AND revoked_at IS NULL",
    )
    .bind(link_id)
    .bind(&entity)
    .bind(record_id)
    .bind(&field)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if revoked == 0 {
        return Err(AppError::NotFound);
    }
    write_audit(
        &state,
        &mut tx,
        ctx.user_id,
        AuditOperation::SoftDelete,
        &entity,
        record_id,
        &field,
        format!("share link {link_id} revoked"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// One link as the public routes read it.
#[derive(sqlx::FromRow)]
struct LiveLink {
    id: Uuid,
    entity: String,
    record_id: Uuid,
    field: String,
    password_hash: Option<String>,
    created_by: Option<Uuid>,
}

/// Opens a link: checks the password, then counts the download, audits it
/// and signs a short GET, or answers `NotFound` (unknown, revoked, expired,
/// used up, or its record gone) / `Unauthorized` (password missing or
/// wrong).
async fn open_link(
    state: &EngineState,
    token: &str,
    password: Option<&str>,
) -> Result<String, AppError> {
    if !plausible_token(token) {
        return Err(AppError::NotFound);
    }
    let link: Option<LiveLink> = sqlx::query_as(
        "SELECT id, entity, record_id, field, password_hash, created_by FROM file_share_link \
          WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now() \
            AND (max_downloads IS NULL OR download_count < max_downloads)",
    )
    .bind(token_hash(token))
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let link = link.ok_or(AppError::NotFound)?;
    if let Some(hash) = &link.password_hash {
        let given = password.ok_or(AppError::Unauthorized)?;
        if !attome_auth::password::verify_password_async(given, hash).await? {
            return Err(AppError::Unauthorized);
        }
    }
    // The registry, not the row, says which table the entity is: a link
    // whose entity is gone serves nothing.
    let table = {
        let registry = state.entities.load();
        registry
            .get(&link.entity)
            .map(|meta| meta.logicalname.clone())
            .ok_or(AppError::NotFound)?
    };

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let record_live: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM {} WHERE id = $1 AND is_active = true)",
        quote_ident(&table)
    ))
    .bind(link.record_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !record_live {
        return Err(AppError::NotFound);
    }
    // The count is taken in the same guarded statement that checks the
    // limit, so two downloads racing for the last one cannot both win.
    let object_key: Option<String> = sqlx::query_scalar(
        "UPDATE file_share_link SET download_count = download_count + 1 \
          WHERE id = $1 AND revoked_at IS NULL AND expires_at > now() \
            AND (max_downloads IS NULL OR download_count < max_downloads) \
          RETURNING object_key",
    )
    .bind(link.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let object_key = object_key.ok_or(AppError::NotFound)?;
    write_audit(
        state,
        &mut tx,
        link.created_by.unwrap_or(Uuid::nil()),
        AuditOperation::Export,
        &link.entity,
        link.record_id,
        &link.field,
        format!("downloaded through share link {}", link.id),
    )
    .await?;
    attome_db::tx::commit(tx).await?;

    attome_storage::presign_download(&state.base.storage, &object_key, DOWNLOAD_URL_TTL)
        .await
        .map_err(AppError::internal)
}

#[utoipa::path(
    get,
    path = "/api/v1/shared-files/{token}",
    tag = "entity",
    operation_id = "download_shared_file",
    params(("token" = String, Path)),
    responses(
        (status = 303, description = "To a five-minute download URL"),
        (status = 401, description = "The link needs a password: open it with POST", body = ErrorResponse),
        (status = 404, description = "No such live link", body = ErrorResponse),
    ),
)]
async fn download_shared_file(
    State(state): State<EngineState>,
    Path(token): Path<String>,
) -> Result<Response, AppError> {
    let url = open_link(&state, &token, None).await?;
    Ok((
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, url),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
    )
        .into_response())
}

#[utoipa::path(
    post,
    path = "/api/v1/shared-files/{token}",
    tag = "entity",
    operation_id = "open_shared_file",
    params(("token" = String, Path)),
    request_body = OpenShareLinkRequest,
    responses(
        (status = 200, description = "A five-minute download URL", body = SharedFileUrl),
        (status = 401, description = "Password missing or wrong", body = ErrorResponse),
        (status = 404, description = "No such live link", body = ErrorResponse),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Attachment, attome_audit::AuditOperation::Export)])))),
)]
async fn open_shared_file(
    State(state): State<EngineState>,
    Path(token): Path<String>,
    Json(body): Json<OpenShareLinkRequest>,
) -> Result<Response, AppError> {
    let download_url = open_link(&state, &token, body.password.as_deref()).await?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(SharedFileUrl {
            download_url,
            expires_in_secs: DOWNLOAD_URL_TTL.as_secs(),
        }),
    )
        .into_response())
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/{entity}/{id}/files/{field}/share-links",
            get(list_share_links).post(create_share_link),
        )
        .route(
            "/api/v1/{entity}/{id}/files/{field}/share-links/{link_id}",
            delete(revoke_share_link),
        )
        .route(
            "/api/v1/shared-files/{token}",
            get(download_shared_file).post(open_shared_file),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        create_share_link,
        list_share_links,
        revoke_share_link,
        download_shared_file,
        open_shared_file,
    ),
    components(schemas(
        CreateShareLinkRequest,
        CreatedShareLink,
        ShareLinkSummary,
        OpenShareLinkRequest,
        SharedFileUrl,
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_long_random_hex_and_only_their_hash_is_kept() {
        let (a, b) = (new_token(), new_token());
        assert_ne!(a, b);
        assert!(plausible_token(&a), "{}", a.len());
        assert_eq!(token_hash(&a).len(), 64);
        assert_ne!(token_hash(&a), a);
        assert!(!plausible_token("short"));
        assert!(!plausible_token(&format!("{}zz", &a[..62])));
    }

    #[test]
    fn link_lifetime_is_bounded() {
        assert_eq!(lifetime_hours(None).unwrap(), DEFAULT_SHARE_HOURS);
        assert_eq!(lifetime_hours(Some(720)).unwrap(), 720);
        assert!(lifetime_hours(Some(0)).is_err());
        assert!(lifetime_hours(Some(721)).is_err());
    }
}
