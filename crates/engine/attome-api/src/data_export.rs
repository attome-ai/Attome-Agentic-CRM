//! M12 (data management) — `POST /api/v1/{entity}/export`: a durable,
//! permission-filtered record export.
//!
//! Security model (coding-guidelines §7, `/security-model`): export is data
//! egress, so it is filtered through **exactly** the same row- and
//! field-level security `query_exec.rs` applies to an ordinary read —
//! [`plan_export`] below builds its `WHERE` clause with the identical
//! `attome_security::rls_predicate` call query_exec's single-entity branch
//! uses, and derives its column whitelist with the identical
//! `is_sensitive && !ctx.has_field_read_grant(..)` gate query_exec applies
//! before it ever builds SQL (see that file's `execute_stored_query`,
//! ~line 1000). A caller with no field-read grant on a column therefore
//! never has that column appear in the exported file — not merely
//! stripped from the response, never selected at all. An S2S caller
//! additionally needs `can_export` on `s2s_permission` for the entity
//! (`attome_s2s::db::client_can_export`) — previously stored but never
//! checked anywhere in this codebase; this closes that gap for export.
//!
//! Shape: `POST` validates, pre-counts the result set against the same
//! predicate (rate/size cap), writes the `data_export` ledger row and
//! the `EngineJob::DataExport` job in one transaction (mirrors
//! `bulk::enqueue`), and returns 202. The worker
//! ([`process`]) re-resolves the caller's `SecurityContext` from Postgres
//! (never trusting an enqueue-time snapshot — same discipline
//! `bulk::process` uses), re-derives the plan, streams the result into the
//! requested format, and uploads it via `attome-storage`. `GET
//! .../export/{id}` polls status and, once `completed`, returns a
//! presigned download URL.
//!
//! Row serialization reuses `attome_compliance::retention`'s streaming
//! upload+checksum primitive (`stream_masked_export_to_store`) verbatim for
//! the `json`/`csv` formats — both are line-oriented, and that function's
//! contract ("one line in, one line + '\n' out, running SHA-256, adaptive
//! multipart") is exactly what both need; only what a "line" contains
//! (a JSON object, or a CSV row) differs. `xlsx` cannot be produced
//! line-by-line (an XLSX file is a single zip archive with a manifest that
//! isn't known until every row is written), so it is built in memory,
//! bounded by [`MAX_EXPORT_ROWS`], and uploaded as one object.

use attome_audit::{AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource};
use attome_auth::SessionClaims;
use attome_core::filter::{FieldCastError, FilterSchema, cast_for_attr, is_multi_choice_attr};
use attome_core::{AttrInfo, EngineState, Filter, quote_ident};
use attome_s2s::S2SClaims;
use attome_security::SecurityContextExt;
use attome_security::record_action::Read;
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::capability::{Available, BatchJobs};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use utoipa::ToSchema;
use uuid::Uuid;

use attome_records::entity_crud;

/// Hard row-count cap enforced *before* a job is even enqueued (a `COUNT(*)`
/// against the same predicate the export itself will use). No measured
/// production-shaped throughput exists yet for a full-format streamed
/// export (coding-guidelines §14) — capped at a value comfortably inside
/// what `stream_masked_export_to_store`'s existing bounded-memory design
/// already handles for the partition-archive export it was built for, not
/// raised until that measurement exists.
const MAX_EXPORT_ROWS: i64 = 200_000;

/// Rate cap: how many of a caller's own exports may be `pending`/`running`
/// at once. A simple concurrency ceiling rather than a token-bucket rate
/// limiter — export is comparatively rare and already bounded by
/// [`MAX_EXPORT_ROWS`] per request, so the risk this guards against is a
/// caller (or a buggy client) queuing many large exports back to back, not
/// request-per-second abuse.
const MAX_CONCURRENT_EXPORTS_PER_USER: i64 = 3;

const DOWNLOAD_URL_TTL: Duration = Duration::from_secs(15 * 60);

fn valid_format(format: &str) -> bool {
    matches!(format, "csv" | "xlsx" | "json")
}

#[derive(Deserialize, ToSchema)]
struct ExportRequestBody {
    #[serde(default)]
    filter: Vec<Filter>,
    /// Requested column projection. Empty means "every column the caller
    /// can currently read" — resolved fresh by the worker, not frozen at
    /// request time.
    #[serde(default)]
    columns: Vec<String>,
    format: String,
}

#[derive(Serialize, ToSchema)]
struct ExportEnqueueResponse {
    id: Uuid,
    status: String,
    /// How many rows matched the filter when the export was accepted (the
    /// worker re-resolves the caller's scope when it runs, so the file can be
    /// smaller if access was revoked in between).
    matching_rows: i64,
}

#[derive(Serialize, ToSchema)]
struct ExportStatusResponse {
    id: Uuid,
    entity_logicalname: String,
    format: String,
    status: String,
    row_count: Option<i64>,
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in_secs: Option<u64>,
}

#[derive(sqlx::FromRow)]
struct ExportRow {
    id: Uuid,
    entity_logicalname: String,
    format: String,
    status: String,
    row_count: Option<i64>,
    object_key: Option<String>,
    error: Option<String>,
}

/// The permission-filtered query plan for one export: the final column list
/// (already stripped of anything the caller lacks a field-read grant on)
/// and a `WHERE` clause carrying the identical row-security predicate
/// `query_exec.rs`'s single-entity branch builds. Shared by the enqueue
/// handler's pre-count and the worker's actual read loop so the two can
/// never disagree about what's in scope.
struct ExportPlan {
    columns: Vec<String>,
    where_sql: String,
    params: Vec<String>,
}

/// Bundles the resolved entity so `plan_export` stays under clippy's
/// `too_many_arguments` limit — same reasoning as `bulk.rs`'s
/// `EntityMutationTarget`.
struct ExportTarget<'a> {
    entity_id: Uuid,
    entity_name: &'a str,
    attrs: &'a [AttrInfo],
    is_append_only: bool,
}

/// C-15 (M01 §7): this endpoint's own [`FilterSchema`] adapter over
/// `plan_export`'s `attrs`/`allowed_fields` — the filter -> WHERE fragment
/// itself is `attome_core::filter::compile` now, shared with
/// `query_exec.rs`, `attome-search::aggregate`, and `legal_matter_admin.rs`. A
/// field absent from `allowed_fields` (unknown, or known but sensitive
/// without a read grant) reports `Unknown` either way — same masking
/// `plan_export`'s own column-projection loop above already applies, never
/// distinguishing "doesn't exist" from "you can't read it" to the client.
struct DataExportFilterSchema<'a> {
    attrs: &'a [AttrInfo],
    allowed_fields: &'a std::collections::HashSet<&'a str>,
}

impl FilterSchema for DataExportFilterSchema<'_> {
    fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
        // Dashboard 10/10 Phase 3.4: the system columns every provisioned
        // table carries (`created_at`, `owner_ref`, ...) are filterable too, so
        // a drill-through export can reproduce a `created_at` month bucket.
        if !self.attrs.iter().any(|a| a.logicalname == field)
            && let Some(field_type) = attome_core::data_definition::system_column_type(field)
        {
            return attome_core::parameter_cast(field_type.as_str())
                .ok_or(FieldCastError::UnsupportedType);
        }
        if !self.allowed_fields.contains(field) {
            return Err(FieldCastError::Unknown);
        }
        let attr = self
            .attrs
            .iter()
            .find(|a| a.logicalname == field)
            .ok_or(FieldCastError::Unknown)?;
        cast_for_attr(attr)
    }

    fn is_multi_choice(&self, field: &str) -> bool {
        self.attrs
            .iter()
            .find(|a| a.logicalname == field)
            .is_some_and(is_multi_choice_attr)
    }
}

/// Mirrors `query_exec::execute_stored_query`'s single-entity RLS + field
/// security exactly (see that file's ~line 1000/~line 1292), scoped down to
/// what export needs: no search, no custom multi-entity path (export always
/// has exactly one entity, from the `{entity}` path segment), and no
/// pagination cursor (the caller does that separately).
async fn plan_export(
    state: &EngineState,
    ctx: &SecurityContext,
    target: &ExportTarget<'_>,
    requested_columns: &[String],
    filters: &[Filter],
) -> Result<ExportPlan, AppError> {
    let ExportTarget {
        entity_id,
        entity_name,
        attrs,
        is_append_only,
    } = *target;
    if entity_crud::POLYMORPHIC_AUDIT_ENTITIES.contains(&entity_name) {
        // The audit family's row security is a per-row OR of two predicates
        // resolved against the *referenced* record (see query_exec.rs's own
        // long comment on this) — export does not replicate that; these
        // entities are exported through the DSR/retention surfaces instead.
        return Err(AppError::Forbidden);
    }
    // U1 (basic-units plan B-R1): a note/communication/tag/follow is readable
    // only with its parent record, a per-row predicate this bulk path does not
    // replicate either. Admins export them; nobody else does.
    if entity_crud::POLYMORPHIC_CHILD_ENTITIES.contains(&entity_name) && !ctx.is_admin {
        return Err(AppError::Forbidden);
    }

    // D-589: export is a bulk surface.
    let primary_name = state
        .entities
        .load()
        .get(entity_name)
        .and_then(|m| m.primary_name_attribute.clone());
    let allowed_fields: std::collections::HashSet<&str> = attrs
        .iter()
        .filter(|attr| {
            attome_security::field_gate::readable(
                ctx,
                entity_name,
                attr,
                primary_name.as_deref(),
                attome_security::field_gate::Surface::Bulk,
            )
        })
        .map(|attr| attr.logicalname.as_str())
        .collect();

    let columns: Vec<String> = if requested_columns.is_empty() {
        attrs
            .iter()
            .filter(|attr| allowed_fields.contains(attr.logicalname.as_str()))
            .map(|attr| attr.logicalname.clone())
            .collect()
    } else {
        let mut out = Vec::with_capacity(requested_columns.len());
        for name in requested_columns {
            if !attrs.iter().any(|attr| &attr.logicalname == name) {
                return Err(AppError::Validation(format!("unknown column: {name}")));
            }
            // A column that exists but the caller can't read is silently
            // dropped, not rejected — the whole point is that it must never
            // appear, and an explicit "field security" error would still
            // leak that the column exists and is sensitive.
            if allowed_fields.contains(name.as_str()) {
                out.push(name.clone());
            }
        }
        out
    };

    let mut conds: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();
    // The one shared live-row rule (dashboard 10/10 Phase 0 spike S8): NULL
    // `is_active` counts as live, exactly as dashboard counts and their
    // records drill apply it, so an export of a drill reproduces its rows. An
    // append-only table has no soft-delete lifecycle and no predicate.
    if let Some(live) = attome_core::live_row_predicate("t", is_append_only) {
        conds.push(live);
    }

    let filter_schema = DataExportFilterSchema {
        attrs,
        allowed_fields: &allowed_fields,
    };
    for f in filters {
        let (cond, binds) = attome_core::filter::compile(f, &filter_schema, params.len() + 1)?;
        conds.push(cond);
        params.extend(binds);
    }

    let access_level = attome_security::resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        entity_name,
        attome_security::RecordAction::Read,
    )
    .await?;
    if let Some(pred) = attome_security::rls_predicate(
        ctx,
        entity_id,
        "t",
        access_level,
        attome_security::RecordAction::Read.share_capability(),
        params.len() + 1,
    ) {
        conds.push(pred.sql.trim_start_matches("AND ").to_owned());
        params.extend(pred.binds.to_text_params());
    }

    let where_sql = if conds.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conds.join(" AND "))
    };

    Ok(ExportPlan {
        columns,
        where_sql,
        params,
    })
}

async fn count_matching(
    db: &attome_db::DbPool,
    entity_name: &str,
    plan: &ExportPlan,
) -> Result<i64, AppError> {
    let table = quote_ident(entity_name);
    let sql = format!("SELECT COUNT(*) FROM {table} t {}", plan.where_sql);
    let mut q = sqlx::query_scalar::<_, i64>(&sql);
    for p in &plan.params {
        q = q.bind(p.clone());
    }
    q.fetch_one(db).await.map_err(AppError::internal)
}

#[utoipa::path(
    post,
    path = "/api/v1/{entity}/export",
    tag = "entity",
    params(("entity" = String, Path)),
    request_body = ExportRequestBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("EngineJob::DataExport"),
        "the route only enqueues an export; the job writes entity+export in the export's completion transaction",
    )))),
    responses(
        (status = 202, description = "Success", body = ExportEnqueueResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn enqueue_export(
    State(state): State<EngineState>,
    // `{entity}` is a path segment, so `RecordScoped<Read>` alone already
    // enforces `ctx.require(entity, "read")` — see the security-model
    // skill's checklist and `bulk::get_status`'s identical policy for the
    // same shape of route.
    ctx: Authorized<RecordScoped<Read>>,
    _jobs: Available<BatchJobs>,
    Extension(claims): Extension<SessionClaims>,
    // Present only when this request authenticated via S2S HMAC
    // (`attome_s2s::middleware`) — `None` for a session/API-key caller.
    s2s_claims: Option<Extension<S2SClaims>>,
    Path(entity_input): Path<String>,
    Json(body): Json<ExportRequestBody>,
) -> Result<(StatusCode, Json<ExportEnqueueResponse>), AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        entity_crud::resolve_entity(&state, &entity_input).await?;

    if !valid_format(&body.format) {
        return Err(AppError::Validation(
            "format must be csv, xlsx, or json".into(),
        ));
    }

    if let Some(Extension(s2s)) = &s2s_claims {
        let allowed =
            attome_s2s::db::client_can_export(&state.base.db, s2s.client_db_id, &entity_name)
                .await?;
        if !allowed {
            return Err(AppError::Forbidden);
        }
    }

    let plan = plan_export(
        &state,
        &ctx,
        &ExportTarget {
            entity_id,
            entity_name: &entity_name,
            attrs: &attrs,
            is_append_only,
        },
        &body.columns,
        &body.filter,
    )
    .await?;

    let matching = count_matching(&state.base.db, &entity_name, &plan).await?;
    if matching > MAX_EXPORT_ROWS {
        return Err(AppError::Validation(format!(
            "export would return {matching} rows, over the {MAX_EXPORT_ROWS}-row cap — narrow the filter"
        )));
    }

    let running: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM data_export \
          WHERE created_by = $1 AND status IN ('pending', 'running') AND is_deleted = false",
    )
    .bind(claims.sub)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if running >= MAX_CONCURRENT_EXPORTS_PER_USER {
        return Err(AppError::Conflict(
            "too many exports already in progress for this account — wait for one to finish",
        ));
    }

    let export_id = Uuid::now_v7();
    let columns_json = serde_json::to_value(&plan.columns).map_err(AppError::internal)?;
    let filters_json = serde_json::to_value(&body.filter).map_err(AppError::internal)?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO data_export \
            (id, entity_logicalname, format, columns, filters, status, created_by) \
         VALUES ($1, $2, $3, $4, $5, 'pending', $6)",
    )
    .bind(export_id)
    .bind(&entity_name)
    .bind(&body.format)
    .bind(&columns_json)
    .bind(&filters_json)
    .bind(claims.sub)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let filters_payload = body
        .filter
        .iter()
        .map(|f| serde_json::to_value(f).map_err(AppError::internal))
        .collect::<Result<Vec<Value>, AppError>>()?;

    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::DataExport(attome_jobs::DataExportPayload {
            export_id,
            entity_logicalname: entity_name.clone(),
            format: body.format.clone(),
            columns: plan.columns.clone(),
            filters: filters_payload,
            user_id: claims.sub,
        }),
    )
    .await
    .map_err(AppError::internal)?;

    attome_db::tx::commit(tx).await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(ExportEnqueueResponse {
            id: export_id,
            status: "pending".into(),
            matching_rows: matching,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/{entity}/export/{id}",
    tag = "entity",
    params(("entity" = String, Path), ("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = ExportStatusResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn export_status(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Extension(claims): Extension<SessionClaims>,
    Path((entity_input, export_id)): Path<(String, Uuid)>,
) -> Result<Json<ExportStatusResponse>, AppError> {
    let (_, entity_name, _, _) = entity_crud::resolve_entity(&state, &entity_input).await?;
    let row: Option<ExportRow> = sqlx::query_as(
        "SELECT id, entity_logicalname, format, status, row_count, object_key, error \
           FROM data_export \
          WHERE id = $1 AND entity_logicalname = $2 AND is_deleted = false \
            AND (created_by = $3 OR $4)",
    )
    .bind(export_id)
    .bind(&entity_name)
    .bind(claims.sub)
    .bind(ctx.is_admin)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;

    let (download_url, expires_in_secs) = if row.status == "completed" {
        if let Some(key) = &row.object_key {
            let url = attome_storage::presign_download(&state.base.storage, key, DOWNLOAD_URL_TTL)
                .await
                .map_err(AppError::internal)?;
            (Some(url), Some(DOWNLOAD_URL_TTL.as_secs()))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    Ok(Json(ExportStatusResponse {
        id: row.id,
        entity_logicalname: row.entity_logicalname,
        format: row.format,
        status: row.status,
        row_count: row.row_count,
        error: row.error,
        download_url,
        expires_in_secs,
    }))
}

async fn mark_failed(state: &EngineState, export_id: Uuid, message: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE data_export \
            SET status = 'failed', error = $2, updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(export_id)
    .bind(message)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Worker-side processing for `EngineJob::DataExport`. Re-resolves the
/// caller's `SecurityContext` directly from Postgres (never trusting the
/// enqueue-time snapshot — a grant revoked between enqueue and the worker
/// picking up the job must not apply, same discipline `bulk::process`
/// follows) and re-derives the export plan from that fresh context, so the
/// exported file always reflects the caller's *current* row/field
/// visibility, not what it was when the request was made.
pub async fn process(
    state: &EngineState,
    payload: attome_jobs::DataExportPayload,
) -> Result<(), AppError> {
    let export_id = payload.export_id;

    let (entity_id, entity_name, attrs, is_append_only) =
        match entity_crud::resolve_entity(state, &payload.entity_logicalname).await {
            Ok(v) => v,
            Err(e) => {
                mark_failed(state, export_id, &format!("entity resolution failed: {e}")).await?;
                return Ok(());
            }
        };

    let security = attome_security::resolve_uncached(&state.base.db, payload.user_id).await?;
    if security.require(&entity_name, "read").is_err() {
        mark_failed(
            state,
            export_id,
            "export authorization was revoked before processing",
        )
        .await?;
        return Ok(());
    }

    let filters: Vec<Filter> = payload
        .filters
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(AppError::internal)?;

    let plan = match plan_export(
        state,
        &security,
        &ExportTarget {
            entity_id,
            entity_name: &entity_name,
            attrs: &attrs,
            is_append_only,
        },
        &payload.columns,
        &filters,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            mark_failed(state, export_id, &format!("{e}")).await?;
            return Ok(());
        }
    };

    sqlx::query(
        "UPDATE data_export SET status = 'running', updated_at = NOW(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(export_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let table = quote_ident(&entity_name);
    let mut header = vec!["id".to_string()];
    header.extend(plan.columns.clone());
    let select_list = header
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");

    let object_key = format!(
        "data-exports/{}/{export_id}.{}",
        entity_name,
        match payload.format.as_str() {
            "xlsx" => "xlsx",
            "csv" => "csv",
            _ => "ndjson",
        }
    );
    let path = ObjectPath::parse(&object_key)
        .map_err(|e| AppError::internal(format!("invalid export object key: {e}")))?;

    let result = match payload.format.as_str() {
        "json" => {
            run_query_and_stream(state, &table, &select_list, &plan, &path, None, |row| {
                row.to_string()
            })
            .await
        }
        "csv" => {
            let header_line = attome_report::render::csv_header_line(&header);
            let header_for_rows = header.clone();
            run_query_and_stream(
                state,
                &table,
                &select_list,
                &plan,
                &path,
                Some(header_line),
                move |row| attome_report::render::csv_line(&header_for_rows, &row),
            )
            .await
        }
        _ => export_xlsx(state, &table, &select_list, &plan, &header, &path).await,
    };

    let (row_count, checksum) = match result {
        Ok(v) => v,
        Err(e) => {
            mark_failed(state, export_id, &format!("export failed: {e}")).await?;
            return Ok(());
        }
    };

    // D-062 / audit plan 3.6: the `completed` transition (which is what makes
    // the file downloadable) and its Entity+Export audit event commit in one
    // transaction, opened only after the streamed upload finished (no
    // external I/O inside it). A failed audit write rolls the transition back.
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(state, payload.user_id).await;
    let event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.clone()),
        record_id: None,
        operation: AuditOperation::Export,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: Some(export_id),
        event_name: None,
        event_comment: Some(format!(
            "exported {row_count} row(s) of {entity_name} as {}",
            payload.format
        )),
        changed_fields: vec![],
        snapshot_json: None,
    };

    if let Err(e) =
        complete_export(state, export_id, row_count, &object_key, &checksum, event).await
    {
        // Record the failure durably so a row whose retries run out never
        // sits in `running` holding one of the caller's
        // MAX_CONCURRENT_EXPORTS_PER_USER slots, then return the error so
        // the queue retries. This worker has no status guard: a retry
        // re-plans, re-streams to the same object key (overwriting it), and
        // completes the same row. No download URL is offered for a
        // non-`completed` row, so nothing was delivered without evidence.
        mark_failed(
            state,
            export_id,
            &format!("completion could not be recorded: {e}"),
        )
        .await?;
        return Err(e);
    }

    Ok(())
}

/// Moves an export to `completed` and writes its audit event in one
/// transaction (D-062): either both commit or neither does.
async fn complete_export(
    state: &EngineState,
    export_id: Uuid,
    row_count: i64,
    object_key: &str,
    checksum: &str,
    event: AuditEvent,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "UPDATE data_export \
            SET status = 'completed', row_count = $2, object_key = $3, checksum = $4, \
                completed_at = NOW(), updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(export_id)
    .bind(row_count)
    .bind(object_key)
    .bind(checksum)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::audit_service(state)
        .write_in_tx(&mut tx, event)
        .await?;
    attome_db::tx::commit(tx).await
}

/// Runs the export's `SELECT row_to_json(...)::text` query as one streamed
/// read (sqlx never buffers the whole result set — rows arrive off the wire
/// as consumed, same as `retention.rs::execute_partition_archive`'s own
/// `.fetch(db)` streaming call), renders each JSON row through `render`, and
/// pipes the result (an optional header line first, then one rendered line
/// per row) through `attome_compliance::retention::stream_masked_export_to_store`
/// — genuine reuse of the DSR portability export's own
/// stream-with-running-checksum primitive, not a second copy of it. `LIMIT`
/// is [`MAX_EXPORT_ROWS`] + 1 as a defensive bound (the enqueue-time
/// `COUNT(*)` can be stale by the time the worker actually runs); exceeding
/// it fails the export rather than silently truncating it.
///
/// The returned row count is the number of *data* rows actually rendered
/// (tracked via `row_counter`, incremented only inside `render`'s call
/// site) — not `stream_masked_export_to_store`'s own line count, which
/// would over-count by one whenever a header line is present.
async fn run_query_and_stream(
    state: &EngineState,
    table: &str,
    select_list: &str,
    plan: &ExportPlan,
    path: &ObjectPath,
    header_line: Option<String>,
    render: impl Fn(Value) -> String + Send + Sync + 'static,
) -> Result<(i64, String), AppError> {
    use futures_util::StreamExt;

    let sql = format!(
        "SELECT row_to_json(xexp)::text FROM (SELECT {select_list} FROM {table} t {} \
         ORDER BY t.id ASC LIMIT {}) xexp",
        plan.where_sql,
        MAX_EXPORT_ROWS + 1,
    );
    let mut q = sqlx::query_scalar::<_, String>(&sql);
    for p in &plan.params {
        q = q.bind(p.clone());
    }
    let row_stream = q.fetch(&state.base.db);

    let row_counter = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let counter_for_map = row_counter.clone();
    let rendered = row_stream.map(move |item: Result<String, sqlx::Error>| {
        item.and_then(|raw| {
            serde_json::from_str::<Value>(&raw)
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))
                .map(|value| {
                    counter_for_map.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    render(value)
                })
        })
    });

    let header_stream =
        futures_util::stream::iter(header_line.into_iter().map(Ok::<String, sqlx::Error>));
    let combined = header_stream.chain(rendered);

    let (_lines, checksum) = attome_compliance::retention::stream_masked_export_to_store(
        combined,
        state.base.storage.store_arc(),
        path.clone(),
    )
    .await?;

    let row_count = row_counter.load(std::sync::atomic::Ordering::Relaxed);
    if row_count > MAX_EXPORT_ROWS {
        return Err(AppError::internal(format!(
            "export exceeded the {MAX_EXPORT_ROWS}-row cap while processing (the result set grew \
             after the request was accepted) — re-run the export with a narrower filter"
        )));
    }
    Ok((row_count, checksum))
}

/// `xlsx` cannot be produced line-by-line — a workbook is one zip archive
/// whose manifest isn't known until every row is written — so this builds
/// the whole file in memory (bounded by [`MAX_EXPORT_ROWS`] rows, same cap
/// as the streamed formats) and uploads it as one object.
async fn export_xlsx(
    state: &EngineState,
    table: &str,
    select_list: &str,
    plan: &ExportPlan,
    header: &[String],
    path: &ObjectPath,
) -> Result<(i64, String), AppError> {
    let sql = format!(
        "SELECT row_to_json(xexp)::text FROM (SELECT {select_list} FROM {table} t {} \
         ORDER BY t.id ASC LIMIT {}) xexp",
        plan.where_sql,
        MAX_EXPORT_ROWS + 1,
    );
    let mut q = sqlx::query_scalar::<_, String>(&sql);
    for p in &plan.params {
        q = q.bind(p.clone());
    }
    let rows: Vec<String> = q
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    if rows.len() as i64 > MAX_EXPORT_ROWS {
        return Err(AppError::internal(format!(
            "export exceeded the {MAX_EXPORT_ROWS}-row cap while processing (the result set grew \
             after the request was accepted) — re-run the export with a narrower filter"
        )));
    }

    let row_count = rows.len() as i64;
    let values = rows
        .into_iter()
        .map(|raw| serde_json::from_str::<Value>(&raw))
        .collect::<Result<Vec<Value>, _>>()
        .map_err(AppError::internal)?;
    let buffer = attome_report::render::render_xlsx(header, &values)?;
    drop(values);

    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let checksum = hex::encode(hasher.finalize());

    state
        .base
        .storage
        .store()
        .put(path, buffer.into())
        .await
        .map_err(AppError::internal)?;

    Ok((row_count, checksum))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/{entity}/export", post(enqueue_export))
        .route("/api/v1/{entity}/export/{id}", get(export_status))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(enqueue_export, export_status))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
