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
use attome_server::authz::{Admin, Authorized};
use attome_server::capability::{Available, BatchJobs};
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
}

#[derive(Deserialize, IntoParams)]
struct ListProfilesQuery {
    entity: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

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
    _ctx: Authorized<Admin>,
    Query(query): Query<ListProfilesQuery>,
) -> Result<Json<PaginatedResponse<DataProfileRow>>, AppError> {
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
        "SELECT id, entity_logicalname, status, row_count, fields, sample_size, full_scan, error, created_by, created_at, completed_at \
           FROM data_profile \
          WHERE is_deleted = false AND ($1::text IS NULL OR entity_logicalname = $1) \
          ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&query.entity)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM data_profile \
          WHERE is_deleted = false AND ($1::text IS NULL OR entity_logicalname = $1)",
    )
    .bind(&query.entity)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/data/profile/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
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
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<DataProfileRow>, AppError> {
    let row: Option<DataProfileRow> = sqlx::query_as(
        "SELECT id, entity_logicalname, status, row_count, fields, sample_size, full_scan, error, created_by, created_at, completed_at \
           FROM data_profile WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(row.ok_or(AppError::NotFound)?))
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
    let (sample_size, stats) = scanned;
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
        .map(|a| scan::FieldStats::new(scan::FieldKind::of_cast(sql_cast(a))))
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
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(enqueue_profile, list_profiles, get_profile))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
