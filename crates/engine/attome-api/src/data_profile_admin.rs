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
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
};
use attome_records::entity_crud;
use attome_records::entity_mutation::sql_cast;

const SAMPLE_LIMIT: i64 = 5;

#[derive(Deserialize, ToSchema)]
struct ProfileRequestBody {
    entity: String,
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
        "SELECT id, entity_logicalname, status, row_count, fields, error, created_by, created_at, completed_at \
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
        "SELECT id, entity_logicalname, status, row_count, fields, error, created_by, created_at, completed_at \
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

    let mut fields = Vec::with_capacity(attrs.len());
    for attr in &attrs {
        match profile_field(&state.base.db, &table, attr, row_count).await {
            Ok(stats) => fields.push(stats),
            Err(e) => {
                // A single field's stats query failing (e.g. a type that
                // doesn't support MIN/MAX) must not fail the whole profile —
                // record it as that field's own outcome and keep going.
                fields.push(json!({
                    "field": attr.logicalname,
                    "error": e.to_string(),
                }));
            }
        }
    }

    sqlx::query(
        "UPDATE data_profile \
            SET status = 'completed', row_count = $2, fields = $3, completed_at = NOW(), \
                row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(profile_id)
    .bind(row_count)
    .bind(Value::Array(fields))
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(())
}

async fn profile_field(
    db: &attome_db::DbPool,
    table: &str,
    attr: &attome_core::AttrInfo,
    total_rows: i64,
) -> Result<Value, AppError> {
    let col = attome_core::quote_ident(&attr.logicalname);
    let is_array_or_jsonb = matches!(sql_cast(attr), "::text[]" | "::jsonb");

    let (nulls, distinct_count): (i64, i64) = sqlx::query_as(&format!(
        "SELECT COUNT(*) FILTER (WHERE {col} IS NULL), COUNT(DISTINCT {col}) FROM {table}"
    ))
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let null_pct = if total_rows > 0 {
        (nulls as f64 / total_rows as f64) * 100.0
    } else {
        0.0
    };

    let (min_val, max_val): (Option<String>, Option<String>) = if is_array_or_jsonb {
        (None, None)
    } else {
        sqlx::query_as(&format!(
            "SELECT MIN({col})::text, MAX({col})::text FROM {table} WHERE {col} IS NOT NULL"
        ))
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?
    };

    let samples: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT DISTINCT {col}::text FROM {table} WHERE {col} IS NOT NULL LIMIT {SAMPLE_LIMIT}"
    ))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    // L6-T1: a personal, special-category or masked attribute keeps only
    // the shapes of its values, never the values.
    let labelled = is_labelled(attr);
    let (min_val, max_val, samples) = if labelled {
        let mut shapes: Vec<String> = samples.iter().map(|v| shape_of(v)).collect();
        shapes.sort();
        shapes.dedup();
        (
            min_val.map(|v| shape_of(&v)),
            max_val.map(|v| shape_of(&v)),
            shapes,
        )
    } else {
        (min_val, max_val, samples)
    };

    Ok(json!({
        "field": attr.logicalname,
        "null_pct": null_pct,
        "distinct_count": distinct_count,
        "min": min_val,
        "max": max_val,
        "samples": samples,
        "masked": labelled,
    }))
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
