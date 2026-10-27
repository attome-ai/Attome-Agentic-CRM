//! K5-T1: page versions. Every publish — by hand, by the schedule sweep, or
//! after an approval — keeps a numbered `content_page_version` row with the
//! published title, SEO text and blocks ([`record_version_in_tx`], in the
//! publish's own transaction). An editor lists a page's versions, reads one,
//! compares two block by block ([`compare`]), and restores an old one:
//! restore copies it into the page's draft and publishes it as a new version
//! that names the one it came from. In a space with `require_approval`, a
//! publish (and so a restore) waits for Z10's approval engine
//! ([`ACTION_CONTENT_PUBLISH`]); scheduled publishing does not apply there.

use std::collections::{HashMap, HashSet};

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::types::Json as SqlxJson;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The approval action a publish in a space with `require_approval` waits
/// for; `attome-api`'s approval dispatcher runs [`crate::admin::do_publish_page`]
/// once it is approved.
pub const ACTION_CONTENT_PUBLISH: &str = "content.page_publish";

/// The approval payload of [`ACTION_CONTENT_PUBLISH`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishPayload {
    pub page_id: Uuid,
    /// The version a restore came from.
    #[serde(default)]
    pub restored_from: Option<i32>,
}

/// One version in a page's list.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct PageVersionSummary {
    pub version_number: i32,
    pub title: String,
    pub published_by: Uuid,
    pub published_at: DateTime<Utc>,
    /// The version this one restored, if it was a restore.
    pub restored_from: Option<i32>,
}

/// One version with its content.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct PageVersion {
    pub version_number: i32,
    pub title: String,
    #[schema(value_type = Vec<Object>)]
    pub blocks: SqlxJson<Vec<Value>>,
    pub seo_title: Option<String>,
    pub seo_description: Option<String>,
    pub published_by: Uuid,
    pub published_at: DateTime<Utc>,
    pub restored_from: Option<i32>,
}

const VERSION_COLUMNS: &str = "version_number, title, blocks, seo_title, seo_description, \
                               published_by, published_at, restored_from";

/// What happened to one block between two versions, by block `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockChange {
    Added,
    Removed,
    Changed,
    Moved,
}

/// One block's change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct BlockDiff {
    pub block_id: String,
    pub change: BlockChange,
    /// Its position in the older version, if it was there.
    pub from_index: Option<usize>,
    /// Its position in the newer version, if it is there.
    pub to_index: Option<usize>,
}

/// Two versions compared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct VersionDiff {
    pub from_version: i32,
    pub to_version: i32,
    pub title_changed: bool,
    pub seo_changed: bool,
    pub blocks: Vec<BlockDiff>,
}

/// A block's id, or its position when it has none.
fn block_key(block: &Value, index: usize) -> String {
    block
        .get("id")
        .and_then(Value::as_str)
        .map_or_else(|| format!("#{index}"), str::to_owned)
}

/// Compares two versions block by block. Pure. A block in both whose content
/// differs is `changed`; one whose content is the same but whose position
/// among the shared blocks differs is `moved`.
pub fn compare(from: &PageVersion, to: &PageVersion) -> VersionDiff {
    let old: Vec<(String, &Value)> = from
        .blocks
        .0
        .iter()
        .enumerate()
        .map(|(i, b)| (block_key(b, i), b))
        .collect();
    let new: Vec<(String, &Value)> = to
        .blocks
        .0
        .iter()
        .enumerate()
        .map(|(i, b)| (block_key(b, i), b))
        .collect();
    let old_index: HashMap<&str, usize> = old
        .iter()
        .enumerate()
        .map(|(i, (k, _))| (k.as_str(), i))
        .collect();
    let new_index: HashMap<&str, usize> = new
        .iter()
        .enumerate()
        .map(|(i, (k, _))| (k.as_str(), i))
        .collect();
    let shared: HashSet<&str> = old_index
        .keys()
        .filter(|k| new_index.contains_key(*k))
        .copied()
        .collect();
    // Order of the shared blocks alone, so an insertion elsewhere is not a move.
    let old_order: Vec<&str> = old
        .iter()
        .map(|(k, _)| k.as_str())
        .filter(|k| shared.contains(k))
        .collect();
    let new_order: Vec<&str> = new
        .iter()
        .map(|(k, _)| k.as_str())
        .filter(|k| shared.contains(k))
        .collect();
    let shared_position = |order: &[&str], key: &str| order.iter().position(|k| *k == key);

    let mut blocks = Vec::new();
    for (i, (key, block)) in old.iter().enumerate() {
        match new_index.get(key.as_str()) {
            None => blocks.push(BlockDiff {
                block_id: key.clone(),
                change: BlockChange::Removed,
                from_index: Some(i),
                to_index: None,
            }),
            Some(&j) => {
                let change = if new[j].1 != *block {
                    Some(BlockChange::Changed)
                } else if shared_position(&old_order, key) != shared_position(&new_order, key) {
                    Some(BlockChange::Moved)
                } else {
                    None
                };
                if let Some(change) = change {
                    blocks.push(BlockDiff {
                        block_id: key.clone(),
                        change,
                        from_index: Some(i),
                        to_index: Some(j),
                    });
                }
            }
        }
    }
    for (j, (key, _)) in new.iter().enumerate() {
        if !old_index.contains_key(key.as_str()) {
            blocks.push(BlockDiff {
                block_id: key.clone(),
                change: BlockChange::Added,
                from_index: None,
                to_index: Some(j),
            });
        }
    }
    VersionDiff {
        from_version: from.version_number,
        to_version: to.version_number,
        title_changed: from.title != to.title,
        seo_changed: from.seo_title != to.seo_title || from.seo_description != to.seo_description,
        blocks,
    }
}

/// Records the page's just-published content as its next version, in the
/// publish's transaction. The page row is locked by the publish's `UPDATE`,
/// so two publishes of one page number their versions in turn.
pub async fn record_version_in_tx(
    tx: &mut attome_db::Tx<'_>,
    page_id: Uuid,
    actor: Uuid,
    restored_from: Option<i32>,
) -> Result<i32, AppError> {
    let version: i32 = sqlx::query_scalar(
        "INSERT INTO content_page_version \
             (page_id, version_number, title, blocks, seo_title, seo_description, \
              published_by, restored_from) \
         SELECT p.id, \
                COALESCE((SELECT max(v.version_number) FROM content_page_version v \
                           WHERE v.page_id = p.id), 0) + 1, \
                p.title, COALESCE(p.blocks_published, '[]'::jsonb), p.seo_title, \
                p.seo_description, $2, $3 \
           FROM content_page p WHERE p.id = $1 \
         RETURNING version_number",
    )
    .bind(page_id)
    .bind(actor)
    .bind(restored_from)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    // G11-T1: a published article is projected into the knowledge index.
    crate::article::enqueue_sync_in_tx(tx, page_id).await?;
    Ok(version)
}

/// Whether the page's space asks for approval before a publish.
pub async fn space_requires_approval(
    db: &attome_db::DbPool,
    page_id: Uuid,
) -> Result<bool, AppError> {
    let required: Option<bool> = sqlx::query_scalar(
        "SELECT s.require_approval FROM content_page p \
           JOIN content_space s ON s.id = p.content_space_id \
          WHERE p.id = $1 AND p.is_deleted = FALSE",
    )
    .bind(page_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    required.ok_or(AppError::NotFound)
}

async fn load_version(
    db: &attome_db::DbPool,
    page_id: Uuid,
    number: i32,
) -> Result<PageVersion, AppError> {
    sqlx::query_as(&format!(
        "SELECT {VERSION_COLUMNS} FROM content_page_version \
          WHERE page_id = $1 AND version_number = $2"
    ))
    .bind(page_id)
    .bind(number)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// A page's versions, newest first (K5-T1).
///
/// Every published version of the page with who published it and when, and
/// which version a restore came from.
#[utoipa::path(
    get,
    path = "/api/v1/admin/content/pages/{id}/versions",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The page's id")),
    responses(
        (status = 200, description = "The page's versions, newest first", body = PaginatedResponse<PageVersionSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_versions(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Communication>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<PageVersionSummary>>, AppError> {
    let items: Vec<PageVersionSummary> = sqlx::query_as(
        "SELECT version_number, title, published_by, published_at, restored_from \
           FROM content_page_version WHERE page_id = $1 \
          ORDER BY version_number DESC LIMIT 500",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// One version of a page with its content (K5-T1).
///
/// The title, SEO text and blocks exactly as that version was published.
#[utoipa::path(
    get,
    path = "/api/v1/admin/content/pages/{id}/versions/{number}",
    operation_id = "get_content_page_version",
    tag = "admin-content",
    params(
        ("id" = Uuid, Path, description = "The page's id"),
        ("number" = i32, Path, description = "The version number"),
    ),
    responses(
        (status = 200, description = "The version", body = PageVersion),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "No such version", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_version(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Communication>>,
    Path((id, number)): Path<(Uuid, i32)>,
) -> Result<Json<PageVersion>, AppError> {
    Ok(Json(load_version(&state.base.db, id, number).await?))
}

/// `GET .../versions/compare`'s two versions.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CompareQuery {
    /// The older version.
    pub from: i32,
    /// The newer version.
    pub to: i32,
}

/// Compares two versions of a page (K5-T1).
///
/// Whether the title or SEO text changed, and each block added, removed,
/// changed or moved between `from` and `to`, by block id.
#[utoipa::path(
    get,
    path = "/api/v1/admin/content/pages/{id}/versions/compare",
    tag = "admin-content",
    params(("id" = Uuid, Path, description = "The page's id"), CompareQuery),
    responses(
        (status = 200, description = "The differences", body = VersionDiff),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "No such version", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn compare_versions(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Communication>>,
    Path(id): Path<Uuid>,
    Query(q): Query<CompareQuery>,
) -> Result<Json<VersionDiff>, AppError> {
    let from = load_version(&state.base.db, id, q.from).await?;
    let to = load_version(&state.base.db, id, q.to).await?;
    Ok(Json(compare(&from, &to)))
}

/// Restores an old version of a page (K5-T1).
///
/// The version's title, SEO text and blocks become the page's draft and are
/// published as a new version that names the restored one. In a space that
/// requires approval the restored draft waits for approval (202 with the
/// request's id) like any other publish.
#[utoipa::path(
    post,
    path = "/api/v1/admin/content/pages/{id}/versions/{number}/restore",
    operation_id = "restore_content_page_version",
    tag = "admin-content",
    params(
        ("id" = Uuid, Path, description = "The page's id"),
        ("number" = i32, Path, description = "The version to restore"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Restored and published as a new version", body = crate::admin::PublishResult),
        (status = 202, description = "Restored to the draft; the publish waits for approval", body = crate::admin::PublishResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or Content Management is not licensed", body = ErrorResponse),
        (status = 404, description = "No such page or version", body = ErrorResponse),
        (status = 422, description = "The restored blocks fail today's block validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn restore_version(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Communication>>,
    Path((id, number)): Path<(Uuid, i32)>,
) -> Result<(StatusCode, Json<crate::admin::PublishResult>), AppError> {
    let version = load_version(&state.base.db, id, number).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let updated = sqlx::query(
        "UPDATE content_page SET title = $2, blocks_draft = $3, seo_title = $4, \
             seo_description = $5, row_version = row_version + 1, updated_at = NOW(), \
             updated_by = $6 \
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .bind(&version.title)
    .bind(&version.blocks)
    .bind(&version.seo_title)
    .bind(&version.seo_description)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "content_page",
            Some(id),
        )
        .named("content_page.restore")
        .comment(format!("draft restored from version {number}")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    crate::admin::publish_or_submit(&state, id, ctx.user_id, Some(number)).await
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/content/pages/{id}/versions",
            get(list_versions),
        )
        .route(
            "/api/v1/admin/content/pages/{id}/versions/compare",
            get(compare_versions),
        )
        .route(
            "/api/v1/admin/content/pages/{id}/versions/{number}",
            get(get_version),
        )
        .route(
            "/api/v1/admin/content/pages/{id}/versions/{number}/restore",
            post(restore_version),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_versions, get_version, compare_versions, restore_version))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(number: i32, title: &str, blocks: Value) -> PageVersion {
        PageVersion {
            version_number: number,
            title: title.to_owned(),
            blocks: SqlxJson(match blocks {
                Value::Array(items) => items,
                _ => Vec::new(),
            }),
            seo_title: None,
            seo_description: None,
            published_by: Uuid::nil(),
            published_at: Utc::now(),
            restored_from: None,
        }
    }

    fn change_of(diff: &VersionDiff, id: &str) -> Option<BlockChange> {
        diff.blocks
            .iter()
            .find(|b| b.block_id == id)
            .map(|b| b.change.clone())
    }

    #[test]
    fn compare_names_added_removed_changed_and_moved_blocks() {
        let old = version(
            1,
            "Pricing",
            serde_json::json!([
                {"id": "a", "kind": "heading", "props": {"text": "Plans"}},
                {"id": "b", "kind": "text", "props": {"text": "Monthly"}},
                {"id": "c", "kind": "text", "props": {"text": "Yearly"}},
                {"id": "d", "kind": "text", "props": {"text": "FAQ"}}
            ]),
        );
        let new = version(
            2,
            "Pricing 2027",
            serde_json::json!([
                {"id": "a", "kind": "heading", "props": {"text": "Plans"}},
                {"id": "c", "kind": "text", "props": {"text": "Yearly"}},
                {"id": "b", "kind": "text", "props": {"text": "Monthly, billed in SAR"}},
                {"id": "e", "kind": "text", "props": {"text": "Contact us"}}
            ]),
        );
        let diff = compare(&old, &new);
        assert!(diff.title_changed);
        assert!(!diff.seo_changed);
        assert_eq!(change_of(&diff, "a"), None);
        assert_eq!(change_of(&diff, "b"), Some(BlockChange::Changed));
        assert_eq!(change_of(&diff, "c"), Some(BlockChange::Moved));
        assert_eq!(change_of(&diff, "d"), Some(BlockChange::Removed));
        assert_eq!(change_of(&diff, "e"), Some(BlockChange::Added));
    }

    #[test]
    fn an_insertion_elsewhere_is_not_a_move() {
        let old = version(
            1,
            "T",
            serde_json::json!([{"id": "a", "kind": "text", "props": {}}, {"id": "b", "kind": "text", "props": {}}]),
        );
        let new = version(
            2,
            "T",
            serde_json::json!([
                {"id": "x", "kind": "text", "props": {}},
                {"id": "a", "kind": "text", "props": {}},
                {"id": "b", "kind": "text", "props": {}}
            ]),
        );
        let diff = compare(&old, &new);
        assert_eq!(diff.blocks.len(), 1, "{diff:?}");
        assert_eq!(change_of(&diff, "x"), Some(BlockChange::Added));
        assert!(!diff.title_changed);
    }

    #[test]
    fn the_approval_payload_round_trips() {
        let payload = PublishPayload {
            page_id: Uuid::nil(),
            restored_from: Some(3),
        };
        let back: PublishPayload =
            serde_json::from_value(serde_json::to_value(&payload).unwrap_or_default())
                .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(back.restored_from, Some(3));
        let plain: PublishPayload =
            serde_json::from_value(serde_json::json!({"page_id": Uuid::nil()}))
                .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(plain.restored_from, None);
    }
}
