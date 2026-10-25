//! M12 (data management) — `POST /api/v1/admin/data/profile`: a background
//! job that computes null %, distinct counts, min/max, and pattern samples
//! per field for one entity, written as a snapshot row to
//! `data_profile`; this file's `GET` routes browse those snapshots.
//! Feeds M14's completeness scoring later — this plan only produces and
//! browses the snapshot itself.
//!
//! `system.admin` only, mounted with `strict_authz` (same posture as
//! `profiler_admin.rs`, which this module's shape otherwise mirrors).
//! Runs as a job (guidelines §10: never a full-table scan on the request
//! thread) — `POST` only enqueues and returns 202; the actual per-field
//! statistics run in [`process`], called from
//! `crates/server/src/jobs.rs`'s `EngineJob::DataProfile` arm.

use attome_auth::SessionClaims;
use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Admin, Authorized, Privilege, PrivilegeKey};
use attome_server::capability::{Available, BatchJobs};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
};
use attome_records::entity_crud;
use attome_records::entity_mutation::sql_cast;

/// L6-T2: the one sampled scan.
mod scan;

/// L6-T3: pattern shapes and Arabic-aware measures.
mod patterns;

/// L6-T5: drift between snapshots, scheduled profiles, retention.
pub mod drift;

/// L6-T4: personal data found in unlabelled attributes.
mod pii;

/// L6-T6: reading data profiles (and profiling a staged import) without
/// `system.admin`: a holder reads the profiles of entities they may read,
/// without the attributes their field security hides.
#[derive(Debug)]
pub struct MetadataRead;

impl PrivilegeKey for MetadataRead {
    const KEY: &'static str = "metadata.read";
}

/// L6-T6: the most staged rows a file profile reads.
const FILE_PROFILE_ROWS: i64 = 100_000;
/// L6-T6: the most columns a file profile keeps.
const FILE_PROFILE_COLUMNS: usize = 500;

/// How long the profile scan may run.
const SCAN_TIMEOUT: &str = "120s";

#[derive(Deserialize, ToSchema)]
struct ProfileRequestBody {
    entity: String,
    /// L6-T2: read every row; by default a table of more than 100,000 rows
    /// is sampled.
    #[serde(default)]
    full_scan: bool,
}

#[derive(Serialize, ToSchema)]
struct ProfileEnqueueResponse {
    id: Uuid,
    status: String,
}

/// Start a data profile
///
/// Start a data profile. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/data/profile",
    tag = "admin",
    request_body = ProfileRequestBody,
    responses(
        (status = 202, description = "Success", body = ProfileEnqueueResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Create)])))),
)]
async fn enqueue_profile(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    _jobs: Available<BatchJobs>,
    axum::Extension(claims): axum::Extension<SessionClaims>,
    Json(body): Json<ProfileRequestBody>,
) -> Result<(StatusCode, Json<ProfileEnqueueResponse>), AppError> {
    let (_, entity_name, _, _) = entity_crud::resolve_entity(&state, &body.entity).await?;

    let profile_id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO data_profile (id, entity_logicalname, status, created_by) \
         VALUES ($1, $2, 'pending', $3)",
    )
    .bind(profile_id)
    .bind(&entity_name)
    .bind(claims.sub)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, claims.sub).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::BusinessEvent,
                entity_name: Some(entity_name.clone()),
                record_id: Some(profile_id),
                operation: AuditOperation::Create,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("data_profile_requested".to_owned()),
                event_comment: None,
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;

    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::DataProfile(attome_core::jobs::DataProfilePayload {
            profile_id,
            entity_logicalname: entity_name,
            user_id: claims.sub,
            full_scan: body.full_scan,
            import_job_id: None,
        }),
    )
    .await
    .map_err(AppError::internal)?;

    attome_db::tx::commit(tx).await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(ProfileEnqueueResponse {
            id: profile_id,
            status: "pending".into(),
        }),
    ))
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct DataProfileRow {
    id: Uuid,
    entity_logicalname: String,
    status: String,
    row_count: Option<i64>,
    fields: Value,
    /// L6-T2: rows the statistics were computed from.
    sample_size: Option<i64>,
    full_scan: bool,
    error: Option<String>,
    created_by: Uuid,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    /// L6-T6: the import whose staged rows this profile read.
    import_job_ref: Option<Uuid>,
}

#[derive(Deserialize, IntoParams)]
struct ListProfilesQuery {
    entity: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

/// List data profiles
///
/// List data profiles. Needs metadata.read.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/profile",
    tag = "admin",
    params(ListProfilesQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<DataProfileRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_profiles(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetadataRead>>,
    Query(query): Query<ListProfilesQuery>,
) -> Result<Json<PaginatedResponse<DataProfileRow>>, AppError> {
    // L6-T6: the entities the caller may read (every one for an admin).
    let readable: Option<Vec<String>> = (!ctx.is_admin).then(|| {
        state
            .entities
            .load()
            .iter()
            .filter(|m| ctx.require(&m.logicalname, "read").is_ok())
            .map(|m| m.logicalname.clone())
            .collect()
    });
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(
        query.page,
        query.page_size,
        PageBase::One,
        DEFAULT_PAGE_SIZE,
    );

    let items: Vec<DataProfileRow> = sqlx::query_as(
        "SELECT id, entity_logicalname, status, row_count, fields, sample_size, full_scan, error, created_by, created_at, completed_at, import_job_ref \
           FROM data_profile \
          WHERE is_deleted = false AND ($1::text IS NULL OR entity_logicalname = $1) \
            AND ($4::text[] IS NULL OR entity_logicalname = ANY($4)) \
          ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&query.entity)
    .bind(page_size)
    .bind(offset)
    .bind(&readable)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut shown = Vec::with_capacity(items.len());
    for row in items {
        shown.push(hide_unreadable(&state, &ctx, row).await);
    }
    let items = shown;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM data_profile \
          WHERE is_deleted = false AND ($1::text IS NULL OR entity_logicalname = $1) \
            AND ($2::text[] IS NULL OR entity_logicalname = ANY($2))",
    )
    .bind(&query.entity)
    .bind(&readable)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// One data profile
///
/// One data profile. Needs metadata.read.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/profile/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The profile")),
    responses(
        (status = 200, description = "Success", body = DataProfileRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_profile(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetadataRead>>,
    Path(id): Path<Uuid>,
) -> Result<Json<DataProfileRow>, AppError> {
    let row: Option<DataProfileRow> = sqlx::query_as(
        "SELECT id, entity_logicalname, status, row_count, fields, sample_size, full_scan, error, created_by, created_at, completed_at, import_job_ref \
           FROM data_profile WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;
    // L6-T6: a profile of an entity the caller may not read does not exist
    // for them.
    if ctx.require(&row.entity_logicalname, "read").is_err() {
        return Err(AppError::NotFound);
    }
    Ok(Json(hide_unreadable(&state, &ctx, row).await))
}

/// L6-T6: keeps only the field summaries of attributes the caller may read:
/// a sensitive attribute needs a field-read grant. The attributes come from
/// the registry, and from the database when the registry does not know a
/// summarised field yet (just added). A field neither knows is dropped:
/// fail closed rather than show a column nobody checked.
async fn hide_unreadable(
    state: &EngineState,
    ctx: &SecurityContext,
    mut row: DataProfileRow,
) -> DataProfileRow {
    if ctx.is_admin {
        return row;
    }
    let entity = row.entity_logicalname.clone();
    let Value::Array(fields) = &mut row.fields else {
        return row;
    };
    let names: Vec<String> = fields
        .iter()
        .filter_map(|f| f["field"].as_str().map(str::to_owned))
        .collect();
    let mut attrs = state
        .entities
        .load()
        .get(&entity)
        .map(|meta| meta.attrs.clone())
        .unwrap_or_default();
    if names
        .iter()
        .any(|n| !attrs.iter().any(|a| &a.logicalname == n))
        && let Ok((_, _, fresh, _)) =
            entity_crud::resolve_entity_from_db(&state.base.db, &entity).await
    {
        attrs = fresh;
    }
    fields.retain(|f| {
        f["field"].as_str().is_some_and(|name| {
            attrs.iter().any(|a| {
                a.logicalname == name
                    && (!a.is_sensitive || ctx.has_field_read_grant(&entity, &a.logicalname))
            })
        })
    });
    row
}

#[derive(Deserialize, ToSchema)]
struct FileProfileBody {
    /// The import job whose staged rows to profile.
    import_job_id: Uuid,
}

/// Profiles a staged import before it is applied.
///
/// L6-T6: reads the import's staged rows (as mapped, else as uploaded) in a
/// job, with the same statistics, pattern shapes and masking as an entity
/// profile, up to 100,000 rows. The import's creator or an administrator,
/// holding `metadata.read` and allowed to read the import's entity.
#[utoipa::path(
    post,
    path = "/api/v1/data/profile:file",
    tag = "admin",
    operation_id = "data_profile_file",
    request_body = FileProfileBody,
    responses(
        (status = 202, description = "Queued", body = ProfileEnqueueResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks metadata.read, or may not read the entity", body = ErrorResponse),
        (status = 404, description = "No such import of the caller's", body = ErrorResponse),
        (status = 422, description = "The import is not staged", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Create)])))),
)]
async fn enqueue_file_profile(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetadataRead>>,
    _jobs: Available<BatchJobs>,
    Json(body): Json<FileProfileBody>,
) -> Result<(StatusCode, Json<ProfileEnqueueResponse>), AppError> {
    let job: Option<(String, Uuid, String)> = sqlx::query_as(
        "SELECT entity_logicalname, created_by, status FROM import_job WHERE id = $1",
    )
    .bind(body.import_job_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (entity, created_by, status) = job.ok_or(AppError::NotFound)?;
    if created_by != ctx.user_id && !ctx.is_admin {
        return Err(AppError::NotFound);
    }
    ctx.require(&entity, "read")?;
    if status == "uploaded" {
        return Err(AppError::Validation(
            "the import is not staged yet: its rows have not been read".into(),
        ));
    }
    let profile_id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO data_profile (id, entity_logicalname, status, created_by, import_job_ref) \
         VALUES ($1, $2, 'pending', $3, $4)",
    )
    .bind(profile_id)
    .bind(&entity)
    .bind(ctx.user_id)
    .bind(body.import_job_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    audit_service(&state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::BusinessEvent,
                entity_name: Some(entity.clone()),
                record_id: Some(profile_id),
                operation: AuditOperation::Create,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: Some(body.import_job_id),
                event_name: Some("data_profile_file_requested".to_owned()),
                event_comment: None,
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::DataProfile(attome_core::jobs::DataProfilePayload {
            profile_id,
            entity_logicalname: entity,
            user_id: ctx.user_id,
            full_scan: true,
            import_job_id: Some(body.import_job_id),
        }),
    )
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(ProfileEnqueueResponse {
            id: profile_id,
            status: "pending".into(),
        }),
    ))
}

/// L6-T6: profiles an import's staged rows into `profile_id`.
async fn process_file(
    state: &EngineState,
    profile_id: Uuid,
    entity: &str,
    import_job: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE data_profile SET status = 'running', row_version = row_version + 1 WHERE id = $1",
    )
    .bind(profile_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<Value> = match sqlx::query_scalar(
        "SELECT COALESCE(mapped, raw) FROM import_stage WHERE job_id = $1 \
          ORDER BY row_no LIMIT $2",
    )
    .bind(import_job)
    .bind(FILE_PROFILE_ROWS)
    .fetch_all(state.base.long_pool(&state.base.db))
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            mark_failed(
                state,
                profile_id,
                &format!("staged rows could not be read: {e}"),
            )
            .await?;
            return Ok(());
        }
    };
    let mut attrs: Vec<attome_core::AttrInfo> = state
        .entities
        .load()
        .get(entity)
        .map(|m| m.attrs.clone())
        .unwrap_or_default();
    // A column the registry does not know yet (an attribute just added) is
    // looked up in the database, so its label still decides its masking.
    let unknown = rows
        .iter()
        .flat_map(|r| r.as_object().into_iter().flat_map(|m| m.keys()))
        .any(|k| !attrs.iter().any(|a| &a.logicalname == k));
    if unknown
        && let Ok((_, _, fresh, _)) =
            entity_crud::resolve_entity_from_db(&state.base.db, entity).await
    {
        attrs = fresh;
    }
    let (columns, fields) = profile_rows(&rows, &attrs);
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM import_stage WHERE job_id = $1")
        .bind(import_job)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    tracing::info!(%profile_id, columns, rows = rows.len(), "file profile computed");
    sqlx::query(
        "UPDATE data_profile \
            SET status = 'completed', row_count = $2, fields = $3, sample_size = $4, \
                full_scan = $5, completed_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(profile_id)
    .bind(total)
    .bind(Value::Array(fields))
    .bind(rows.len() as i64)
    .bind(total <= rows.len() as i64)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// L6-T6: the field summaries of staged rows, one per column (the union of
/// the rows' keys, at most 500), with an attribute of the same name's label
/// deciding the masking (a column no attribute names is masked: nothing says
/// it is safe to show); and the column count.
fn profile_rows(rows: &[Value], attrs: &[attome_core::AttrInfo]) -> (usize, Vec<Value>) {
    let mut columns: Vec<String> = Vec::new();
    for row in rows {
        for key in row.as_object().into_iter().flat_map(|m| m.keys()) {
            if columns.len() >= FILE_PROFILE_COLUMNS {
                break;
            }
            if !columns.contains(key) {
                columns.push(key.clone());
            }
        }
    }
    columns.sort();
    let fields = columns
        .iter()
        .map(|column| {
            let attr = attrs.iter().find(|a| &a.logicalname == column);
            let numeric = rows
                .iter()
                .filter_map(|r| r.get(column))
                .find(|v| !v.is_null())
                .is_some_and(Value::is_number);
            let kind = if numeric {
                scan::FieldKind::Number
            } else {
                scan::FieldKind::Text
            };
            let mut stats = scan::FieldStats::new(kind);
            if kind == scan::FieldKind::Text {
                stats = stats.with_patterns(patterns::PatternStats::new(
                    attr.and_then(|a| attome_field::format_matcher(a.options.as_ref())),
                    column.contains("name"),
                ));
            }
            for row in rows {
                let text = match row.get(column) {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(other) => Some(other.to_string()),
                };
                stats.push(text.as_deref());
            }
            stats.finish(column, shape_of, attr.is_none_or(is_labelled))
        })
        .collect();
    (columns.len(), fields)
}

/// L6-T4: writes this profile's label proposals, counts only. An open
/// proposal of the same attribute and detector is updated in place; an open
/// one this profile no longer finds (the attribute was labelled, or its
/// values changed) is resolved.
async fn store_proposals(
    state: &EngineState,
    entity: &str,
    profile_id: Uuid,
    found: &[(String, Vec<pii::Proposal>)],
) -> Result<(), AppError> {
    let keys: Vec<String> = found
        .iter()
        .flat_map(|(attribute, proposals)| {
            proposals
                .iter()
                .map(move |p| format!("{attribute}:{}", p.detector.as_str()))
        })
        .collect();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "UPDATE data_label_proposal SET status = 'resolved', resolved_at = now() \
          WHERE entity_logicalname = $1 AND status = 'open' \
            AND NOT (attribute || ':' || detector = ANY($2))",
    )
    .bind(entity)
    .bind(&keys)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for (attribute, proposals) in found {
        for p in proposals {
            sqlx::query(
                "INSERT INTO data_label_proposal \
                     (entity_logicalname, attribute, detector, proposed_label, matches, sampled, \
                      share_pct, profile_ref) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (entity_logicalname, attribute, detector) WHERE status = 'open' \
                 DO UPDATE SET matches = EXCLUDED.matches, sampled = EXCLUDED.sampled, \
                               share_pct = EXCLUDED.share_pct, profile_ref = EXCLUDED.profile_ref, \
                               updated_at = now()",
            )
            .bind(entity)
            .bind(attribute)
            .bind(p.detector.as_str())
            .bind(pii::PROPOSED_LABEL)
            .bind(i64::try_from(p.matches).unwrap_or(i64::MAX))
            .bind(i64::try_from(p.sampled).unwrap_or(i64::MAX))
            .bind(p.share_pct)
            .bind(profile_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
    }
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// L6-T4: one label proposal. Counts only, never a matched value.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct LabelProposalRow {
    id: Uuid,
    entity_logicalname: String,
    attribute: String,
    /// `saudi_national_id`, `iqama`, `iban`, `phone` or `email`.
    detector: String,
    /// The label proposed for a builder to decide on.
    proposed_label: String,
    matches: i64,
    sampled: i64,
    share_pct: f64,
    /// `open` until the profile no longer finds it (`resolved`).
    status: String,
    profile_ref: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize, IntoParams)]
struct ListProposalsQuery {
    entity: Option<String>,
    /// `open` (the default) or `resolved`.
    status: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

/// Personal-data label proposals
///
/// Lists personal-data label proposals.
///
/// L6-T4: a profile proposes the `personal` label for an unlabelled text
/// attribute when more than 5% of its sampled values look like a Saudi
/// national ID, an Iqama, an IBAN, a phone or an email address. Only the
/// counts are kept. Nothing is labelled automatically: a builder sets the
/// label on the attribute, and the next profile resolves the proposal.
#[utoipa::path(
    get,
    path = "/api/v1/admin/data/label-proposals",
    tag = "admin",
    params(ListProposalsQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<LabelProposalRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Unknown status", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_label_proposals(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<ListProposalsQuery>,
) -> Result<Json<PaginatedResponse<LabelProposalRow>>, AppError> {
    let status = query.status.as_deref().unwrap_or("open");
    if !matches!(status, "open" | "resolved") {
        return Err(AppError::Validation("status is open or resolved".into()));
    }
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(
        query.page,
        query.page_size,
        PageBase::One,
        DEFAULT_PAGE_SIZE,
    );
    let items: Vec<LabelProposalRow> = sqlx::query_as(
        "SELECT id, entity_logicalname, attribute, detector, proposed_label, matches, sampled, \
                share_pct, status, profile_ref, created_at, updated_at, resolved_at \
           FROM data_label_proposal \
          WHERE status = $1 AND ($2::text IS NULL OR entity_logicalname = $2) \
          ORDER BY share_pct DESC, id LIMIT $3 OFFSET $4",
    )
    .bind(status)
    .bind(&query.entity)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM data_label_proposal \
          WHERE status = $1 AND ($2::text IS NULL OR entity_logicalname = $2)",
    )
    .bind(status)
    .bind(&query.entity)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

async fn mark_failed(state: &EngineState, profile_id: Uuid, message: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE data_profile SET status = 'failed', error = $2, completed_at = NOW(), \
                row_version = row_version + 1 WHERE id = $1",
    )
    .bind(profile_id)
    .bind(message)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Worker-side processing for `EngineJob::DataProfile`. Re-reads the
/// entity's *current* live attributes (not an enqueue-time snapshot — same
/// re-derive-current-metadata discipline `BuildAttributeIndex`'s handler
/// follows) and runs one bounded, best-effort statistics pass per field.
/// Not permission-filtered like `data_export`: this is an admin-only
/// operational tool over the raw table, not a caller-scoped data egress
/// path — the admin API surface itself (`Authorized<Admin>` above) is the
/// access control.
pub async fn process(
    state: &EngineState,
    payload: attome_core::jobs::DataProfilePayload,
) -> Result<(), AppError> {
    let profile_id = payload.profile_id;
    if let Some(import_job) = payload.import_job_id {
        return process_file(state, profile_id, &payload.entity_logicalname, import_job).await;
    }
    let (_, entity_name, attrs, _) =
        match entity_crud::resolve_entity(state, &payload.entity_logicalname).await {
            Ok(v) => v,
            Err(e) => {
                mark_failed(state, profile_id, &format!("entity resolution failed: {e}")).await?;
                return Ok(());
            }
        };

    sqlx::query(
        "UPDATE data_profile SET status = 'running', row_version = row_version + 1 WHERE id = $1",
    )
    .bind(profile_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let table = attome_core::quote_ident(&entity_name);
    let row_count: i64 =
        match sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&state.base.db)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                mark_failed(state, profile_id, &format!("row count failed: {e}")).await?;
                return Ok(());
            }
        };

    // L6-T2: one scan reads every attribute's text form; a big table is
    // sampled, and the scan is bounded by a statement timeout.
    let percent = scan::sample_percent(row_count, payload.full_scan);
    let scanned = match one_scan(state, &table, &attrs, percent).await {
        Ok(v) => v,
        Err(e) => {
            mark_failed(state, profile_id, &format!("profile scan failed: {e}")).await?;
            return Ok(());
        }
    };
    let (sample_size, mut stats) = scanned;
    let found: Vec<(String, Vec<pii::Proposal>)> = stats
        .iter_mut()
        .zip(&attrs)
        .filter_map(|(s, attr)| {
            s.take_pii()
                .map(|p| (attr.logicalname.clone(), p.proposals()))
        })
        .collect();
    let fields: Vec<Value> = stats
        .into_iter()
        .zip(&attrs)
        .map(|(s, attr)| s.finish(&attr.logicalname, shape_of, is_labelled(attr)))
        .collect();

    sqlx::query(
        "UPDATE data_profile \
            SET status = 'completed', row_count = $2, fields = $3, sample_size = $4, \
                full_scan = $5, completed_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(profile_id)
    .bind(row_count)
    .bind(Value::Array(fields))
    .bind(sample_size)
    .bind(percent.is_none())
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    // L6-T4: label proposals for personal data found. A failure here never
    // fails the profile itself.
    if let Err(error) = store_proposals(state, &entity_name, profile_id, &found).await {
        tracing::warn!(%profile_id, entity = %entity_name, %error, "data label proposals failed");
    }

    // L6-T5: compare with the previous snapshot and alert on drift. A
    // failure here never fails the profile itself.
    if let Err(error) = drift::after_run(state, &entity_name, profile_id).await {
        tracing::warn!(%profile_id, entity = %entity_name, %error, "data profile drift check failed");
    }
    Ok(())
}

/// L6-T2: the rows read and one [`scan::FieldStats`] per attribute, from a
/// single `SELECT` of every attribute as text (`TABLESAMPLE SYSTEM` when
/// `percent` is set), streamed under [`SCAN_TIMEOUT`].
async fn one_scan(
    state: &EngineState,
    table: &str,
    attrs: &[attome_core::AttrInfo],
    percent: Option<f64>,
) -> Result<(i64, Vec<scan::FieldStats>), AppError> {
    use futures_util::TryStreamExt;
    use sqlx::Row;

    let mut stats: Vec<scan::FieldStats> = attrs
        .iter()
        .map(|a| {
            let kind = scan::FieldKind::of_cast(sql_cast(a));
            let stats = scan::FieldStats::new(kind);
            if kind == scan::FieldKind::Text {
                let stats = stats.with_patterns(patterns::PatternStats::new(
                    attome_field::format_matcher(a.options.as_ref()),
                    a.logicalname.contains("name"),
                ));
                if is_labelled(a) {
                    stats
                } else {
                    stats.with_pii()
                }
            } else {
                stats
            }
        })
        .collect();
    if attrs.is_empty() {
        return Ok((0, stats));
    }
    let columns = attrs
        .iter()
        .map(|a| format!("{}::text", attome_core::quote_ident(&a.logicalname)))
        .collect::<Vec<_>>()
        .join(", ");
    // The percentage is computed here, never caller text.
    let sample = percent
        .map(|p| format!(" TABLESAMPLE SYSTEM ({p:.4})"))
        .unwrap_or_default();
    let sql = format!("SELECT {columns} FROM {table}{sample}");

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(&format!("SET LOCAL statement_timeout = '{SCAN_TIMEOUT}'"))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let mut rows_read: i64 = 0;
    {
        let mut rows = sqlx::query(&sql).fetch(&mut *tx);
        while let Some(row) = rows.try_next().await.map_err(AppError::internal)? {
            rows_read += 1;
            for (i, s) in stats.iter_mut().enumerate() {
                let value: Option<String> = row.try_get(i).map_err(AppError::internal)?;
                s.push(value.as_deref());
            }
        }
    }
    attome_db::tx::commit(tx).await?;
    Ok((rows_read, stats))
}

/// L6-T1: an attribute whose values a profile must not keep.
fn is_labelled(attr: &attome_core::AttrInfo) -> bool {
    attr.is_sensitive || attr.data_classification != attome_core::DataClassification::General
}

/// L6-T1: a value's shape: digits become `9`, letters `A`, the rest stays
/// (`+966 50 123 4567` → `+999 99 999 9999`).
fn shape_of(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_numeric() {
                '9'
            } else if c.is_alphabetic() {
                'A'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod shape_tests {
    use super::shape_of;

    #[test]
    fn shapes_keep_no_value() {
        assert_eq!(shape_of("+966 50 123 4567"), "+999 99 999 9999");
        assert_eq!(shape_of("ahmed@x.sa"), "AAAAA@A.AA");
        assert_eq!(shape_of("محمد ١٢"), "AAAA 99");
    }
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/data/profile",
            post(enqueue_profile).get(list_profiles),
        )
        .route("/api/v1/admin/data/profile/{id}", get(get_profile))
        .route("/api/v1/data/profile:file", post(enqueue_file_profile))
        .route(
            "/api/v1/admin/data/label-proposals",
            get(list_label_proposals),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    enqueue_profile,
    list_profiles,
    get_profile,
    list_label_proposals,
    enqueue_file_profile
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
