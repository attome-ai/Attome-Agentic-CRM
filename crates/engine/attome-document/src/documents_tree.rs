//! D-36x — the system-wide Documents folder browser's one bespoke read
//! endpoint. `attome_document` rows are flat; the browser needs grouped counts
//! (distinct entities -> distinct records -> distinct folders/files), which
//! the generic `/api/v1/query/execute` engine (filter + flat list only) has
//! no way to produce. Everything else the Documents feature needs — create,
//! read, soft delete, hard delete, bulk create — reuses the ordinary generic
//! entity-CRUD routes against `attome_document` directly; this file exists only
//! for the grouping this one UI needs.
//!
//! Record-level visibility reuses the same generalized polymorphic-reference
//! predicate `query_exec.rs`'s single-entity list path applies to
//! `attome_document` (`access.rs::POLYMORPHIC_AUDIT_ENTITIES`) — a caller who
//! can't read the parent record can't see its documents here either. Entity-
//! level visibility is the ordinary `"attome_document.read"` privilege check.

use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

/// `attome_document.read` — the entity-level privilege both of this file's
/// reads need. Minted automatically by `entity_privileges::seed_all` once
/// `document_seed` registers the `attome_document` entity, same
/// `{logicalname}.{action}` convention every entity's privileges follow.
///
/// A compile-time key rather than a bare `Authorized<RecordScoped>` plus an
/// in-body `ctx.require(..)`: the entity these routes act on is fixed in the
/// source, not read from a `{entity}` path segment, so `Privilege<K>` is the
/// spelling that lets the extractor perform the whole check (D-353 —
/// `route_authz.rs`'s bare-`RecordScoped` ratchet).
pub(crate) struct DocumentRead;

impl PrivilegeKey for DocumentRead {
    const KEY: &'static str = "attome_document.read";
}

/// `attome_document.create` — see [`DocumentRead`]. Creating a folder writes an
/// `attome_document` row, so it takes the create verb rather than read; the
/// *parent* record's read access is a separate, record-level check the
/// handler still makes against `require_record_access`.
pub(crate) struct DocumentCreate;

impl PrivilegeKey for DocumentCreate {
    const KEY: &'static str = "attome_document.create";
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct TreeQuery {
    /// Only this entity (its logical name).
    entity_name: Option<String>,
    /// Only this record.
    record_id: Option<Uuid>,
    /// The folder to list; the root when absent.
    folder: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateFolderRequest {
    entity_name: String,
    record_id: Uuid,
    folder: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct CreatedFolder {
    id: Uuid,
    folder: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct EntityGroup {
    entity_name: String,
    display_name: String,
    document_count: i64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct RecordGroup {
    record_id: Uuid,
    display_name: String,
    document_count: i64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct FolderGroup {
    /// Full path from the record's root, e.g. `uploads/Contracts` — pass
    /// straight back as the next request's `folder` param to drill in.
    folder: String,
    document_count: i64,
    /// A folder is a virtual grouping, not a single row, so this is the
    /// earliest timestamp among everything that makes the folder exist: the
    /// explicit `document_folder.created_at` if it was created
    /// empty, and/or the earliest `created_at` of any document living under
    /// it. `NULL` only when the folder path predates the standard
    /// `created_at` column on some pre-provisioned tables.
    created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub(crate) struct DocumentFile {
    id: Uuid,
    name: String,
    /// `NULL` for a row whose two-phase create (empty row -> upload session
    /// -> PATCH the key on, see the Angular component's doc comment) never
    /// reached the PATCH — an abandoned or failed upload. Decoding this as a
    /// plain `String` used to panic on exactly that row and abort the whole
    /// connection (D-36x follow-up), taking every other document in the
    /// folder down with it. The UI renders a `null` file as a failed row the
    /// caller can still select and delete.
    file: Option<String>,
    source_field: Option<String>,
    /// Some pre-provisioned `attome_document` tables predate the standard
    /// `created_at` system column. Keep the tree endpoint usable for those
    /// tables; the UI renders an unavailable date as `--`.
    created_at: Option<DateTime<Utc>>,
    modified_at: Option<DateTime<Utc>>,
    size_bytes: Option<i64>,
    row_version: i64,
}

#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
pub(crate) struct TreeResponse {
    /// Populated only at the root (no query params).
    entities: Vec<EntityGroup>,
    /// Populated only when `entity_name` is given without `record_id`.
    records: Vec<RecordGroup>,
    /// Populated once `entity_name` + `record_id` are both given — the
    /// subfolders directly under `folder` (root of the record's document
    /// space when `folder` is omitted).
    folders: Vec<FolderGroup>,
    /// Files whose `folder` matches exactly — only when `folder` is given
    /// (there is no such thing as a folder-less document, so this is always
    /// empty at the record level without a `folder` param).
    files: Vec<DocumentFile>,
}

/// Builds the same generalized polymorphic-reference predicate
/// `query_exec.rs` applies to `attome_document` in its single-entity list path
/// (`access.rs::POLYMORPHIC_AUDIT_ENTITIES`), for use as an ad hoc WHERE
/// fragment in this file's own grouped queries. `Ok((String::new(), vec![]))`
/// for an admin caller — `polymorphic_audit_predicate` always evaluates to a
/// real (if cheap) SQL fragment, but skipping it entirely for the one caller
/// class it can never narrow anything for avoids computing
/// `resolve_all_entity_access_levels` (one query) on every admin request.
async fn document_rls_fragment(
    state: &EngineState,
    ctx: &SecurityContext,
    first_placeholder: usize,
) -> Result<(String, Vec<String>), AppError> {
    if ctx.is_admin {
        return Ok((String::new(), Vec::new()));
    }
    let access_by_entity = attome_security::resolve_all_entity_access_levels(
        &state.base.db,
        ctx.user_id,
        attome_security::RecordAction::Read,
    )
    .await?;
    let default_share_entities = attome_security::resolve_default_share_entities(
        &state.base.db,
        ctx.user_id,
        &ctx.team_ids,
        attome_security::RecordAction::Read
            .share_capability()
            .as_i16(),
    )
    .await?;
    let pred = attome_security::polymorphic_audit_predicate(
        ctx,
        &access_by_entity,
        &default_share_entities,
        // No BusinessUnit fast tier: `attome_document` rows carry no
        // `organization_ref` of their own — same reasoning `query_exec.rs`
        // gives for the audit entities.
        None,
        "t.entity_name",
        "t.record_id::uuid",
        first_placeholder,
    );
    Ok((pred.sql, pred.binds.to_text_params()))
}

/// Browse documents
///
/// The documents the caller may read, grouped by entity, record and folder with counts, for the
/// documents browser.
#[utoipa::path(
    get,
    path = "/api/v1/documents/tree",
    tag = "documents",
    params(TreeQuery),
    responses(
        (status = 200, description = "Success", body = TreeResponse),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_tree(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DocumentRead>>,
    Query(q): Query<TreeQuery>,
) -> Result<Json<TreeResponse>, AppError> {
    // D-766: this work escapes the S2S entity ceiling (it re-resolves the
    // caller later, or reads across entities by role), so a capped caller
    // is refused until the ceiling is carried through.
    ctx.refuse_if_capped()?;
    match (q.entity_name, q.record_id) {
        (None, _) => Ok(Json(TreeResponse {
            entities: entity_groups(&state, &ctx).await?,
            ..Default::default()
        })),
        (Some(entity_name), None) => Ok(Json(TreeResponse {
            records: record_groups(&state, &ctx, &entity_name).await?,
            ..Default::default()
        })),
        (Some(entity_name), Some(record_id)) => {
            let entity_id = state
                .entities
                .load()
                .get(&entity_name)
                .map(|meta| meta.entity_id)
                .ok_or(AppError::NotFound)?;
            attome_records::entity_crud::require_record_access(
                &state,
                &ctx,
                entity_id,
                &entity_name,
                record_id,
                RecordAction::Read,
            )
            .await?;
            let folder = q.folder;
            let (folders, files) =
                folder_level(&state, &ctx, &entity_name, record_id, folder.as_deref()).await?;
            Ok(Json(TreeResponse {
                folders,
                files,
                ..Default::default()
            }))
        }
    }
}

/// Create a document folder
///
/// A named folder on one record for its documents. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/documents/folders",
    tag = "documents",
    request_body = CreateFolderRequest,
    responses(
        (status = 200, description = "Folder saved", body = CreatedFolder),
        (status = 400, description = "Invalid folder path", body = attome_types::ErrorResponse),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = attome_types::ErrorResponse)
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn create_folder(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DocumentCreate>>,
    Json(body): Json<CreateFolderRequest>,
) -> Result<Json<CreatedFolder>, AppError> {
    let folder = body.folder.trim();
    if folder.is_empty()
        || folder.len() > 500
        || folder.starts_with('/')
        || folder.ends_with('/')
        || folder.contains("//")
        || folder.contains('\\')
    {
        return Err(AppError::Validation("invalid folder path".into()));
    }
    let entity_id = state
        .entities
        .load()
        .get(&body.entity_name)
        .map(|meta| meta.entity_id)
        .ok_or(AppError::NotFound)?;
    attome_records::entity_crud::require_record_access(
        &state,
        &ctx,
        entity_id,
        &body.entity_name,
        body.record_id,
        RecordAction::Read,
    )
    .await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO document_folder (entity_name, record_id, folder, created_by) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (entity_name, record_id, folder) DO UPDATE SET folder = EXCLUDED.folder \
         RETURNING id",
    )
    .bind(&body.entity_name)
    .bind(body.record_id)
    .bind(folder)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::business::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::business::BusinessEvent::new(
            body.entity_name.clone(),
            body.record_id,
            attome_audit::AuditOperation::Create,
            "document_folder.create",
            ctx.user_id,
        )
        .comment(format!("folder \"{folder}\" created")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(CreatedFolder {
        id,
        folder: folder.to_owned(),
    }))
}

async fn entity_groups(
    state: &EngineState,
    ctx: &SecurityContext,
) -> Result<Vec<EntityGroup>, AppError> {
    let (poly_sql, poly_params) = document_rls_fragment(state, ctx, 1).await?;
    let sql = format!(
        "SELECT t.entity_name AS entity_name, COUNT(*) AS document_count \
         FROM attome_document t WHERE t.is_active = true {poly_sql} \
         GROUP BY t.entity_name ORDER BY t.entity_name"
    );
    let mut query = sqlx::query(&sql);
    for p in &poly_params {
        query = query.bind(p);
    }
    let rows = query
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let names: Vec<String> = rows
        .iter()
        .map(|r| r.get::<String, _>("entity_name"))
        .collect();
    let display_names: std::collections::HashMap<String, String> = if names.is_empty() {
        std::collections::HashMap::new()
    } else {
        sqlx::query_as::<_, (String, String)>(
            "SELECT logicalname, name FROM entity_info WHERE logicalname = ANY($1)",
        )
        .bind(&names)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .collect()
    };

    Ok(rows
        .into_iter()
        .map(|r| {
            let entity_name: String = r.get("entity_name");
            let document_count: i64 = r.get("document_count");
            let display_name = display_names
                .get(&entity_name)
                .cloned()
                .unwrap_or_else(|| entity_name.clone());
            EntityGroup {
                entity_name,
                display_name,
                document_count,
            }
        })
        .collect())
}

async fn record_groups(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
) -> Result<Vec<RecordGroup>, AppError> {
    let (poly_sql, poly_params) = document_rls_fragment(state, ctx, 2).await?;
    let sql = format!(
        "SELECT t.record_id::uuid AS record_id, COUNT(*) AS document_count \
         FROM attome_document t WHERE t.is_active = true AND t.entity_name = $1 {poly_sql} \
         GROUP BY t.record_id ORDER BY t.record_id"
    );
    let mut query = sqlx::query(&sql).bind(entity_name);
    for p in &poly_params {
        query = query.bind(p);
    }
    let rows = query
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let ids: Vec<Uuid> = rows.iter().map(|r| r.get::<Uuid, _>("record_id")).collect();
    let display_names = resolve_record_display_names(state, ctx, entity_name, &ids).await;

    Ok(rows
        .into_iter()
        .map(|r| {
            let record_id: Uuid = r.get("record_id");
            let document_count: i64 = r.get("document_count");
            let display_name = display_names
                .get(&record_id)
                .cloned()
                .unwrap_or_else(|| record_id.to_string());
            RecordGroup {
                record_id,
                display_name,
                document_count,
            }
        })
        .collect())
}

/// Same batched-lookup shape `query_exec.rs::attach_lookup_display_names`
/// uses for a `lookup` field's target — generalized to key off a row's own
/// `entity_name` column instead of a fixed attribute's `lookup_entity_ref`,
/// since `attome_document.record_id` is a polymorphic reference, not a typed
/// lookup (see `access.rs::polymorphic_audit_target`'s comment). Routes
/// through `entity_crud::resolve_visible` (M01-core C-05) exactly like that
/// function now does, so a record this caller's RLS on `entity_name`
/// excludes is omitted here too — belt-and-suspenders with `record_groups`'
/// own `document_rls_fragment` filter on `ids` (which already scopes them to
/// records whose `attome_document` rows this caller can see via the polymorphic
/// predicate), rather than relying solely on that upstream filter staying in
/// sync with this one. Best-effort: a resolution failure falls back to the
/// raw id, same as that function's own `continue`-on-error posture.
async fn resolve_record_display_names(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
    ids: &[Uuid],
) -> std::collections::HashMap<Uuid, String> {
    if ids.is_empty() {
        return std::collections::HashMap::new();
    }
    let Some(target_entity_id) = state.entities.load().get(entity_name).map(|m| m.entity_id) else {
        return std::collections::HashMap::new();
    };

    attome_records::entity_crud::resolve_visible(state, ctx, target_entity_id, ids)
        .await
        .into_iter()
        .filter_map(|(id, resolved)| resolved.name.map(|name| (id, name)))
        .collect()
}

async fn folder_level(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
    record_id: Uuid,
    folder: Option<&str>,
) -> Result<(Vec<FolderGroup>, Vec<DocumentFile>), AppError> {
    let record_id_text = record_id.to_string();
    let prefix = folder.map(|f| format!("{f}/")).unwrap_or_default();

    let (poly_sql, poly_params) = document_rls_fragment(state, ctx, 4).await?;
    let folders_sql = format!(
        "WITH folder_paths AS ( \
           SELECT t.folder, 1::bigint AS document_count, t.created_at AS created_at \
             FROM attome_document t \
            WHERE t.is_active = true AND t.entity_name = $1 AND t.record_id = $2 \
              AND t.folder LIKE ($3 || '%') {poly_sql} \
           UNION ALL \
           SELECT f.folder, 0::bigint, f.created_at FROM document_folder f \
            WHERE f.entity_name = $1 AND f.record_id::text = $2 AND f.folder LIKE ($3 || '%') \
         ) \
         SELECT ($3 || split_part(substring(folder from length($3) + 1), '/', 1)) AS folder, \
                SUM(document_count)::bigint AS document_count, \
                MIN(created_at) AS created_at \
         FROM folder_paths GROUP BY 1 ORDER BY 1"
    );
    let mut query = sqlx::query(&folders_sql)
        .bind(entity_name)
        .bind(&record_id_text)
        .bind(&prefix);
    for p in &poly_params {
        query = query.bind(p);
    }
    let folder_rows = query
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let folders = folder_rows
        .into_iter()
        .map(|r| FolderGroup {
            folder: r.get("folder"),
            document_count: r.get("document_count"),
            created_at: r.get("created_at"),
        })
        .collect();

    let files = match folder {
        None => Vec::new(),
        Some(folder) => {
            let files_sql = format!(
                "SELECT t.id, t.name, t.file, t.source_field, t.created_at, t.modified_at, \
                        s.actual_size_bytes AS size_bytes, t.row_version \
                 FROM attome_document t \
                 LEFT JOIN upload_session s ON s.final_key = t.file AND s.is_deleted = false \
                 WHERE t.is_active = true AND t.entity_name = $1 AND t.record_id = $2 \
                   AND t.folder = $3 {poly_sql} \
                 ORDER BY t.name"
            );
            let mut query = sqlx::query(&files_sql)
                .bind(entity_name)
                .bind(&record_id_text)
                .bind(folder);
            for p in &poly_params {
                query = query.bind(p);
            }
            query
                .fetch_all(&state.base.db)
                .await
                .map_err(AppError::internal)?
                .into_iter()
                .map(|r| DocumentFile {
                    id: r.get("id"),
                    name: r.get("name"),
                    file: r.get("file"),
                    source_field: r.get("source_field"),
                    created_at: r.get("created_at"),
                    modified_at: r.get("modified_at"),
                    size_bytes: r.get("size_bytes"),
                    row_version: r.get("row_version"),
                })
                .collect()
        }
    };

    Ok((folders, files))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/documents/tree", get(get_tree))
        .route("/api/v1/documents/folders", post(create_folder))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by `crate::openapi::openapi_document`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(get_tree, create_folder))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
