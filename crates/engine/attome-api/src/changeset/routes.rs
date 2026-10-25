//! `/api/v1/admin/changesets` — open, list, show, close, abandon, export
//! (design §7, D-785).
//!
//! All `Authorized<Admin>` (`system.admin`), session or API key. Lists are
//! `PaginatedResponse` over `OnePageQuery` (one-based, D-731). The prefix is
//! in `METADATA_AUTHORING_PREFIXES`, so on the production profile the
//! authoring gate refuses the mutating routes outside a break-glass window —
//! changesets are authored in development and applied elsewhere.
//!
//! Every mutating route declares `x-audit` and writes its `Configuration`
//! security event in the mutation's own transaction: open (`Create`), close
//! (`Closed`), abandon (`Cancelled`). The two reads that seal an automatic
//! changeset write derived data only (see `close`'s module doc).
//!
//! **Concurrency.** Open relies on the partial unique index
//! `uq_core_changeset_open_name` (one open changeset per layer, scope and
//! name): the loser of a race is `409 changeset_name_taken`. Close and abandon
//! lock the changeset row `FOR UPDATE` — the same lock every recorded write
//! takes last — so a close cannot interleave with a write into the changeset.
//! Close requires `If-Match: "<row_version>"`: every recorded operation bumps
//! the version, so a reviewer closes exactly what they reviewed (a write that
//! landed after is `409 version_conflict`). Abandon accepts it optionally.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_core::changeset::errors;
use attome_core::changeset::{ChangesetRow, ChangesetStatus, Layer, NewChangeset, store};
use attome_records::entity_crud::optional_expected_row_version;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::close::{self, CloseWarning};

/// `changeset_not_closed`: only a closed changeset has a document.
const CHANGESET_NOT_CLOSED: &str =
    "changeset_not_closed: only a closed changeset can be exported; close it first";

/// The most operations one detail response carries (a changeset is a unit of
/// review, so this is far above any real one; the count is always exact).
const MAX_DETAIL_OPERATIONS: usize = 5_000;

// ── Wire types ───────────────────────────────────────────────────────────────

/// `POST /api/v1/admin/changesets`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OpenChangesetBody {
    /// `platform`, `product` or `project` (the customer layer is Phase 3).
    pub layer: String,
    /// Lowercase letters and digits joined by `-` or `_`; `platform` for a
    /// platform changeset.
    pub scope: String,
    /// Kebab-case, at most 60 characters; becomes the file name.
    pub name: String,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    /// `{ platform?: ">=X.Y.Z", after?: ["<layer>/<scope>/<NNNN>-<name>"],
    /// modules?: [module key] }`; `platform` defaults to this binary.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub requires: Option<Value>,
}

/// A changeset without its document or operations.
#[derive(Debug, Serialize, ToSchema)]
pub struct ChangesetSummary {
    pub id: Uuid,
    pub layer: String,
    pub scope: String,
    pub name: String,
    pub title: String,
    pub description: String,
    /// `authored`, `auto` or `break_glass`.
    pub origin: String,
    /// `open`, `closed` or `abandoned`.
    pub status: String,
    #[schema(value_type = Object)]
    pub requires: Value,
    pub op_count: i32,
    pub author_ref: Option<Uuid>,
    pub author_label: String,
    pub opened_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    /// Set once the changeset is closed (an automatic one: once sealed).
    pub checksum: Option<String>,
    /// Send as `If-Match` to close or abandon.
    pub row_version: i64,
}

impl From<&ChangesetRow> for ChangesetSummary {
    fn from(r: &ChangesetRow) -> Self {
        Self {
            id: r.id,
            layer: r.layer.as_str().to_owned(),
            scope: r.scope.clone(),
            name: r.name.clone(),
            title: r.title.clone(),
            description: r.description.clone(),
            origin: r.origin.as_str().to_owned(),
            status: r.status.as_str().to_owned(),
            requires: r.requires.clone(),
            op_count: r.op_count,
            author_ref: r.author_ref,
            author_label: r.author_label.clone(),
            opened_at: r.opened_at,
            closed_at: r.closed_at,
            checksum: r.checksum.clone(),
            row_version: r.row_version,
        }
    }
}

/// One recorded operation as the review sees it (the raw row snapshot stays
/// server-side; `args` is set once the changeset is closed).
#[derive(Debug, Serialize, ToSchema)]
pub struct ChangesetOperation {
    pub seq: i32,
    pub op: String,
    /// `expand` or `contract`.
    pub phase: String,
    pub object_kind: String,
    /// The live row, for diagnostics; never exported.
    pub object_ref: Option<Uuid>,
    /// The object's logical key.
    #[schema(value_type = Object)]
    pub target: Value,
    #[schema(value_type = Option<Object>)]
    pub args: Option<Value>,
    pub changed: Vec<String>,
    /// `"PATCH /api/v1/admin/views/{id}"`.
    pub route: String,
    pub request_id: Option<String>,
    pub actor_ref: Option<Uuid>,
    pub recorded_at: DateTime<Utc>,
}

/// `GET /api/v1/admin/changesets/{id}`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ChangesetDetail {
    pub changeset: ChangesetSummary,
    /// The `attome-changeset/v1` document once closed (or sealed).
    #[schema(value_type = Option<Object>)]
    pub document: Option<Value>,
    pub operations: Vec<ChangesetOperation>,
}

/// `POST /api/v1/admin/changesets/{id}/close`.
#[derive(Debug, Serialize, ToSchema)]
pub struct CloseResponse {
    /// The `attome-changeset/v1` document; write it into the repository with
    /// `node scripts/changesets/write-closed.mjs --dir <folder>`.
    #[schema(value_type = Object)]
    pub changeset: Value,
    /// Plain-language review text (the same wording as
    /// `scripts/changesets/summarize.mjs`).
    pub summary: String,
    pub warnings: Vec<CloseWarning>,
}

/// List filters (paging is `OnePageQuery`).
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ChangesetFilter {
    /// `open`, `closed` or `abandoned`.
    pub status: Option<String>,
    /// `platform`, `product`, `project` or `customer`.
    pub layer: Option<String>,
    /// Only this scope (`platform`, or the product, project or customer name).
    pub scope: Option<String>,
    /// The author's user id.
    pub author: Option<Uuid>,
}

// ── Validation ───────────────────────────────────────────────────────────────

/// `>=MAJOR.MINOR.PATCH`.
fn is_platform_floor(value: &str) -> bool {
    value.strip_prefix(">=").is_some_and(|v| {
        let parts: Vec<&str> = v.split('.').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    })
}

/// `<layer>/<scope>/<NNNN>-<name>`.
fn is_changeset_ref(value: &str) -> bool {
    let parts: Vec<&str> = value.split('/').collect();
    let [layer, scope, file] = parts.as_slice() else {
        return false;
    };
    let Some((number, name)) = file.split_once('-') else {
        return false;
    };
    Layer::parse(layer).is_some()
        && store::is_valid_scope(scope)
        && number.len() == 4
        && number.chars().all(|c| c.is_ascii_digit())
        && store::is_valid_name(name)
}

/// `^[a-z][a-z0-9_]*$`.
fn is_module_key(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The `requires` object the v1 format accepts (`validate.mjs`'s rules).
fn validate_requires(requires: &Value) -> Result<(), String> {
    let Some(map) = requires.as_object() else {
        return Err("requires: must be an object".into());
    };
    for (key, value) in map {
        match key.as_str() {
            "platform" => {
                if !value.as_str().is_some_and(is_platform_floor) {
                    return Err("requires.platform: must be \">=MAJOR.MINOR.PATCH\"".into());
                }
            }
            "after" => {
                let ok = value
                    .as_array()
                    .is_some_and(|a| a.iter().all(|v| v.as_str().is_some_and(is_changeset_ref)));
                if !ok {
                    return Err(
                        "requires.after: must be an array of \"<layer>/<scope>/<NNNN>-<name>\""
                            .into(),
                    );
                }
            }
            "modules" => {
                let ok = value
                    .as_array()
                    .is_some_and(|a| a.iter().all(|v| v.as_str().is_some_and(is_module_key)));
                if !ok {
                    return Err("requires.modules: must be an array of module keys".into());
                }
            }
            other => return Err(format!("requires: unknown member {other:?}")),
        }
    }
    Ok(())
}

/// Builds the store's `NewChangeset` from the body, refusing what the table
/// or the v1 format would.
fn new_changeset(
    body: OpenChangesetBody,
    author_ref: Uuid,
    author_label: String,
) -> Result<NewChangeset, AppError> {
    let layer = close::authorable_layer(&body.layer).ok_or_else(|| {
        AppError::Validation("layer: must be platform, product or project".into())
    })?;
    if layer == Layer::Platform && body.scope != "platform" {
        return Err(AppError::Validation(
            "scope: a platform changeset has the scope \"platform\"".into(),
        ));
    }
    let requires = body
        .requires
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    validate_requires(&requires).map_err(AppError::Validation)?;
    let new = NewChangeset {
        layer,
        scope: body.scope,
        name: body.name,
        title: body.title.trim().to_owned(),
        description: body.description.unwrap_or_default(),
        requires,
        author_ref: Some(author_ref),
        author_label,
    };
    store::validate_new(&new)?;
    Ok(new)
}

/// `If-Match` is mandatory on close.
fn required_row_version(headers: &HeaderMap) -> Result<i64, AppError> {
    optional_expected_row_version(headers)?.ok_or_else(|| {
        AppError::Validation("If-Match: \"<row_version>\" is required to close a changeset".into())
    })
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// How the document names its author: the user's email, else user name,
/// else `user:<id>`.
async fn author_label(state: &EngineState, user_id: Uuid) -> Result<String, AppError> {
    let label: Option<Option<String>> = sqlx::query_scalar(
        "SELECT COALESCE(NULLIF(email, ''), NULLIF(user_name, '')) \
         FROM user_account WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(label.flatten().unwrap_or_else(|| format!("user:{user_id}")))
}

/// Open a changeset
///
/// Open a changeset. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/changesets",
    tag = "admin-changesets",
    request_body = OpenChangesetBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The changeset is open; metadata writes by its author now record into it", body = ChangesetSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin, or the production authoring gate refused the write", body = ErrorResponse),
        (status = 409, description = "changeset_name_taken: an open changeset with this layer, scope and name exists", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn open_changeset(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<OpenChangesetBody>,
) -> Result<(StatusCode, Json<ChangesetSummary>), AppError> {
    let label = author_label(&state, ctx.user_id).await?;
    let new = new_changeset(body, ctx.user_id, label)?;
    let id = Uuid::now_v7();
    let mut stx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "changeset",
            Some(id),
        )
        .named("changeset.open"),
    )
    .await?;
    sqlx::query(
        "INSERT INTO changeset \
             (id, layer, scope, name, title, description, origin, status, requires, \
              opened_log_id, author_ref, author_label) \
         VALUES ($1, $2, $3, $4, $5, $6, 'authored', 'open', $7, \
                 (SELECT COALESCE(MAX(id), 0) FROM metadata_change_log), $8, $9)",
    )
    .bind(id)
    .bind(new.layer.as_str())
    .bind(&new.scope)
    .bind(&new.name)
    .bind(&new.title)
    .bind(&new.description)
    .bind(&new.requires)
    .bind(new.author_ref)
    .bind(&new.author_label)
    .execute(&mut *stx)
    .await
    .map_err(|e| {
        if attome_db::is_unique_violation(&e) {
            AppError::Conflict(errors::CHANGESET_NAME_TAKEN)
        } else {
            AppError::internal(e)
        }
    })?;
    let row = store::get(&mut *stx, id)
        .await?
        .ok_or_else(|| AppError::internal("changeset vanished inside its own transaction"))?;
    stx.commit().await?;
    tracing::info!(
        changeset_id = %id,
        layer = row.layer.as_str(),
        scope = %row.scope,
        name = %row.name,
        "changeset opened"
    );
    Ok((StatusCode::CREATED, Json(ChangesetSummary::from(&row))))
}

#[derive(sqlx::FromRow)]
struct ListRow {
    id: Uuid,
    layer: String,
    scope: String,
    name: String,
    title: String,
    description: String,
    origin: String,
    status: String,
    requires: Value,
    op_count: i32,
    author_ref: Option<Uuid>,
    author_label: String,
    opened_at: DateTime<Utc>,
    closed_at: Option<DateTime<Utc>>,
    checksum: Option<String>,
    row_version: i64,
}

impl From<ListRow> for ChangesetSummary {
    fn from(r: ListRow) -> Self {
        Self {
            id: r.id,
            layer: r.layer,
            scope: r.scope,
            name: r.name,
            title: r.title,
            description: r.description,
            origin: r.origin,
            status: r.status,
            requires: r.requires,
            op_count: r.op_count,
            author_ref: r.author_ref,
            author_label: r.author_label,
            opened_at: r.opened_at,
            closed_at: r.closed_at,
            checksum: r.checksum,
            row_version: r.row_version,
        }
    }
}

const LIST_FILTER: &str = "($1::text IS NULL OR status = $1) \
     AND ($2::text IS NULL OR layer = $2) \
     AND ($3::text IS NULL OR scope = $3) \
     AND ($4::uuid IS NULL OR author_ref = $4)";

/// List changesets
///
/// List changesets. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/changesets",
    tag = "admin-changesets",
    params(ChangesetFilter, OnePageQuery),
    responses(
        (status = 200, description = "Changesets, newest first", body = PaginatedResponse<ChangesetSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 422, description = "An unknown status or layer", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_changesets(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(filter): Query<ChangesetFilter>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ChangesetSummary>>, AppError> {
    if let Some(s) = filter.status.as_deref()
        && ChangesetStatus::parse(s).is_none()
    {
        return Err(AppError::Validation(
            "status: must be open, closed or abandoned".into(),
        ));
    }
    if let Some(l) = filter.layer.as_deref()
        && Layer::parse(l).is_none()
    {
        return Err(AppError::Validation(
            "layer: must be platform, product, project or customer".into(),
        ));
    }
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let sql = format!(
        "SELECT id, layer, scope, name, title, description, origin, status, requires, op_count, \
                author_ref, author_label, opened_at, closed_at, checksum, row_version \
         FROM changeset WHERE {LIST_FILTER} \
         ORDER BY opened_at DESC, id DESC LIMIT $5 OFFSET $6"
    );
    let rows: Vec<ListRow> = sqlx::query_as(&sql)
        .bind(&filter.status)
        .bind(&filter.layer)
        .bind(&filter.scope)
        .bind(filter.author)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM changeset WHERE {LIST_FILTER}"
    ))
    .bind(&filter.status)
    .bind(&filter.layer)
    .bind(&filter.scope)
    .bind(filter.author)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        rows.into_iter().map(ChangesetSummary::from).collect(),
        total,
        page,
        page_size,
    )))
}

/// The changeset, sealing an automatic one first.
async fn load(state: &EngineState, id: Uuid) -> Result<ChangesetRow, AppError> {
    let row = store::get(&state.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    close::seal_if_automatic(state, row).await
}

/// One changeset
///
/// One changeset. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/changesets/{id}",
    tag = "admin-changesets",
    params(("id" = Uuid, Path, description = "Changeset id")),
    responses(
        (status = 200, description = "The changeset, its document once closed, and its operations in order (an automatic changeset is sealed on first read)", body = ChangesetDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such changeset", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_changeset(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<ChangesetDetail>, AppError> {
    let row = load(&state, id).await?;
    let ops = store::operations(&state.base.db, id).await?;
    if ops.len() > MAX_DETAIL_OPERATIONS {
        tracing::warn!(
            changeset_id = %id,
            operations = ops.len(),
            "changeset detail truncated to its first {MAX_DETAIL_OPERATIONS} operations"
        );
    }
    let operations = ops
        .into_iter()
        .take(MAX_DETAIL_OPERATIONS)
        .map(|o| ChangesetOperation {
            seq: o.seq,
            op: o.op,
            phase: o.phase,
            object_kind: o.object_kind,
            object_ref: o.object_ref,
            target: o.target,
            args: o.args,
            changed: o.changed,
            route: o.route,
            request_id: o.request_id,
            actor_ref: o.actor_ref,
            recorded_at: o.recorded_at,
        })
        .collect();
    Ok(Json(ChangesetDetail {
        changeset: ChangesetSummary::from(&row),
        document: row.document.clone(),
        operations,
    }))
}

/// Close a changeset
///
/// Close a changeset. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/changesets/{id}/close",
    tag = "admin-changesets",
    params(
        ("id" = Uuid, Path, description = "Changeset id"),
        ("If-Match" = String, Header, description = "The changeset's row_version, quoted (\"3\")"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Closed)])))),
    responses(
        (status = 200, description = "Closed: the v1 document, its review summary and any warnings", body = CloseResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin, or the production authoring gate refused the write", body = ErrorResponse),
        (status = 404, description = "No such changeset", body = ErrorResponse),
        (status = 409, description = "changeset_not_open, changeset_empty, or version_conflict (a write landed after the version you reviewed)", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn close_changeset(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<CloseResponse>, AppError> {
    let expected = required_row_version(&headers)?;
    let closed = close::close(&state, ctx.user_id, id, expected).await?;
    let document = closed
        .row
        .document
        .ok_or_else(|| AppError::internal("a closed changeset has no document"))?;
    Ok(Json(CloseResponse {
        changeset: document,
        summary: closed.summary,
        warnings: closed.warnings,
    }))
}

/// Abandon a changeset
///
/// Abandon a changeset. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/changesets/{id}/abandon",
    tag = "admin-changesets",
    params(
        ("id" = Uuid, Path, description = "Changeset id"),
        ("If-Match" = Option<String>, Header, description = "Optional: the changeset's row_version, quoted"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Cancelled)])))),
    responses(
        (status = 200, description = "Abandoned", body = ChangesetSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin, or the production authoring gate refused the write", body = ErrorResponse),
        (status = 404, description = "No such changeset", body = ErrorResponse),
        (status = 409, description = "changeset_not_open, changeset_not_empty, or version_conflict", body = ErrorResponse),
        (status = 422, description = "If-Match malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn abandon_changeset(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ChangesetSummary>, AppError> {
    let expected = optional_expected_row_version(&headers)?;
    let row = close::abandon(&state, ctx.user_id, id, expected).await?;
    Ok(Json(ChangesetSummary::from(&row)))
}

/// Export a changeset
///
/// Export a changeset. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/changesets/{id}/export",
    tag = "admin-changesets",
    params(("id" = Uuid, Path, description = "Changeset id")),
    responses(
        (status = 200, description = "The attome-changeset/v1 document", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such changeset", body = ErrorResponse),
        (status = 409, description = "changeset_not_closed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn export_changeset(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    let row = load(&state, id).await?;
    if row.status != ChangesetStatus::Closed {
        return Err(AppError::Conflict(CHANGESET_NOT_CLOSED));
    }
    row.document
        .map(Json)
        .ok_or_else(|| AppError::internal("a closed changeset has no document"))
}

/// The changeset authoring routes. Mounted with the other admin metadata
/// surfaces in `system::EngineSystem::core_routes`.
pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/changesets",
            get(list_changesets).post(open_changeset),
        )
        .route("/api/v1/admin/changesets/{id}", get(get_changeset))
        .route("/api/v1/admin/changesets/{id}/close", post(close_changeset))
        .route(
            "/api/v1/admin/changesets/{id}/abandon",
            post(abandon_changeset),
        )
        .route(
            "/api/v1/admin/changesets/{id}/export",
            get(export_changeset),
        )
}

/// This file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    open_changeset,
    list_changesets,
    get_changeset,
    close_changeset,
    abandon_changeset,
    export_changeset,
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(layer: &str, scope: &str, requires: Option<Value>) -> OpenChangesetBody {
        OpenChangesetBody {
            layer: layer.into(),
            scope: scope.into(),
            name: "acme-contracts".into(),
            title: "  Acme contracts ".into(),
            description: None,
            requires,
        }
    }

    #[test]
    fn requires_follows_the_v1_format() {
        assert!(validate_requires(&json!({})).is_ok());
        assert!(
            validate_requires(&json!({
                "platform": ">=4.2.0",
                "after": ["platform/platform/0001-service-desk-priority"],
                "modules": ["service", "crm_2"],
            }))
            .is_ok()
        );
        for bad in [
            json!([]),
            json!({ "platform": "4.2.0" }),
            json!({ "platform": ">=4.2" }),
            json!({ "after": ["platform/0001-x"] }),
            json!({ "after": ["tenant/acme/0001-x"] }),
            json!({ "after": ["project/acme/01-x"] }),
            json!({ "modules": ["Service"] }),
            json!({ "before": [] }),
        ] {
            assert!(validate_requires(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_new_changeset_is_checked_before_it_reaches_the_table() {
        let user = Uuid::now_v7();
        let new = new_changeset(body("project", "acme", None), user, "a@b".into()).expect("valid");
        assert_eq!(new.layer, Layer::Project);
        assert_eq!(new.title, "Acme contracts");
        assert_eq!(new.requires, json!({}));
        assert_eq!(new.author_ref, Some(user));

        for (layer, scope) in [
            ("customer", "acme"),
            ("tenant", "acme"),
            ("platform", "acme"),
        ] {
            assert!(
                matches!(
                    new_changeset(body(layer, scope, None), user, "a".into()),
                    Err(AppError::Validation(_))
                ),
                "{layer}/{scope}"
            );
        }
        assert!(new_changeset(body("platform", "platform", None), user, "a".into()).is_ok());
        assert!(
            new_changeset(
                body("project", "acme", Some(json!({ "platform": "x" }))),
                user,
                "a".into()
            )
            .is_err()
        );
    }

    #[test]
    fn close_requires_if_match() {
        let mut headers = HeaderMap::new();
        assert!(matches!(
            required_row_version(&headers),
            Err(AppError::Validation(_))
        ));
        headers.insert(axum::http::header::IF_MATCH, "\"7\"".parse().expect("hv"));
        assert_eq!(required_row_version(&headers).expect("parsed"), 7);
    }

    #[test]
    fn the_fragment_documents_every_route_with_x_audit_on_the_mutating_ones() {
        let value = serde_json::to_value(openapi_fragment()).expect("serializes");
        for path in [
            "/api/v1/admin/changesets",
            "/api/v1/admin/changesets/{id}",
            "/api/v1/admin/changesets/{id}/close",
            "/api/v1/admin/changesets/{id}/abandon",
            "/api/v1/admin/changesets/{id}/export",
        ] {
            assert!(value["paths"][path].is_object(), "{path}");
        }
        for (path, method) in [
            ("/api/v1/admin/changesets", "post"),
            ("/api/v1/admin/changesets/{id}/close", "post"),
            ("/api/v1/admin/changesets/{id}/abandon", "post"),
        ] {
            let audit = &value["paths"][path][method]["x-audit"];
            assert_eq!(audit["policy"], "mandatory", "{method} {path}");
            assert_eq!(
                audit["events"][0]["category"], "configuration",
                "{method} {path}"
            );
        }
    }
}
