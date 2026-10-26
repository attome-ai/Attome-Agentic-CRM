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
    matches!(format, "csv" | "xlsx" | "json" | "parquet")
}

/// A23-T10: rows per Parquet row group.
const PARQUET_ROW_GROUP: usize = 50_000;

/// A23-T10: rows per file part when the request names no `split_rows`.
const DEFAULT_SPLIT_ROWS: i64 = 1_000_000;

/// A23-T10: one file of an export.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ExportPart {
    object_key: String,
    row_count: i64,
    checksum: String,
}

/// A23-T10: one file of a completed export, to download.
#[derive(Serialize, ToSchema)]
struct ExportPartLink {
    row_count: i64,
    download_url: String,
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
    /// `csv`, `xlsx`, `json` or `parquet`.
    format: String,
    /// A23-T10: CSV and XLSX headers in the requester's language (`id` and
    /// `row_version` keep their names).
    #[serde(default)]
    labels: bool,
    /// A23-T10: rows per file part of a Parquet export, 1 000 000 by default;
    /// the status lists every part.
    #[serde(default)]
    split_rows: Option<i64>,
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
    /// L7-T5: a change-stream cursor that continues from the export's own
    /// snapshot: reading a subscription from it yields exactly the changes
    /// the export did not see.
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_token: Option<String>,
    /// A23-T10: every file of the export (one unless it was split).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    parts: Vec<ExportPartLink>,
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
    stream_token: Option<String>,
    parts: Option<Value>,
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

/// B11-T3: how date columns read in a file a person opens (CSV, XLSX): in
/// their own `core.calendar` (gregorian, hijri, both) and `core.digits`
/// (latn, arab), with the deployment's Hijri corrections. JSON keeps ISO
/// dates for machines.
#[derive(Clone)]
struct DatePresentation {
    calendar: String,
    arab_digits: bool,
    date_columns: Vec<String>,
    hijri: std::sync::Arc<attome_core::calendar::hijri::HijriCalendar>,
}

impl DatePresentation {
    /// The person's settings, resolved as `/api/v1/settings/me` resolves them.
    async fn for_user(state: &EngineState, user_id: Uuid, attrs: &[attome_core::AttrInfo]) -> Self {
        let (_, org_ref) = entity_crud::fetch_audit_ctx(state, user_id).await;
        let snapshot = state.settings.load();
        let registry = attome_core::setting_registry();
        let setting = |key: &str| {
            registry
                .get(key)
                .map(|d| snapshot.resolve(d, Some(user_id), Some(org_ref)).0)
        };
        let calendar = setting("core.calendar")
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| "gregorian".to_owned());
        let arab_digits = setting("core.digits").is_some_and(|v| v == "arab");
        Self {
            calendar,
            arab_digits,
            date_columns: attrs
                .iter()
                .filter(|a| a.field_type().is_temporal())
                .map(|a| a.logicalname.clone())
                .collect(),
            hijri: state.hijri.load_full(),
        }
    }

    fn apply(&self, mut row: Value) -> Value {
        if self.calendar == "gregorian" && !self.arab_digits {
            return row;
        }
        if let Value::Object(map) = &mut row {
            for column in &self.date_columns {
                if let Some(Value::String(text)) = map.get_mut(column) {
                    *text = self.text(text);
                }
            }
        }
        row
    }

    /// One stored date as the person reads it: `1447-09-01`,
    /// `2026-02-18 (1447-09-01)`, with Arabic-Indic digits when chosen.
    fn text(&self, raw: &str) -> String {
        let day = raw.get(..10).unwrap_or(raw);
        let hijri = chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d")
            .ok()
            .and_then(|d| self.hijri.to_hijri(d).ok())
            .map(|h| h.to_string());
        let text = match (self.calendar.as_str(), hijri) {
            ("hijri", Some(h)) => h,
            ("both", Some(h)) => format!("{raw} ({h})"),
            _ => raw.to_owned(),
        };
        if self.arab_digits {
            text.chars()
                .map(|c| {
                    c.to_digit(10)
                        .and_then(|d| char::from_u32(0x0660 + d))
                        .unwrap_or(c)
                })
                .collect()
        } else {
            text
        }
    }
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

    // R1-T1: a record whose subject restricted its processing is not
    // exported in bulk (the subject's own DSR exports are a separate path).
    params.push(entity_name.to_owned());
    conds.push(attome_core::processing_restriction::exclusion_sql(
        &format!("${}", params.len()),
        "t.id",
    ));

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

/// Start a data export
///
/// Start a data export. Needs read access to the entity's records.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/export",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name")),
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
            "format must be csv, xlsx, json or parquet".into(),
        ));
    }
    if body.split_rows.is_some_and(|n| n <= 0) {
        return Err(AppError::Validation(
            "split_rows is a positive number".into(),
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
            (id, entity_logicalname, format, columns, filters, status, created_by, labels, \
             split_rows) \
         VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8)",
    )
    .bind(export_id)
    .bind(&entity_name)
    .bind(&body.format)
    .bind(&columns_json)
    .bind(&filters_json)
    .bind(claims.sub)
    .bind(body.labels)
    .bind(body.split_rows)
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
        attome_core::jobs::EngineJob::DataExport(attome_core::jobs::DataExportPayload {
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

/// A data export's status
///
/// A data export's status. Needs read access to the entity's records.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/export/{id}",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name"), ("id" = Uuid, Path, description = "The export")),
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
        "SELECT id, entity_logicalname, format, status, row_count, object_key, error, \
                stream_token, parts \
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

    // A23-T10: every part, each with its own link.
    let mut parts = Vec::new();
    if row.status == "completed"
        && let Some(stored) = row.parts.clone()
    {
        let stored: Vec<ExportPart> = serde_json::from_value(stored).map_err(AppError::internal)?;
        for part in stored {
            let url = attome_storage::presign_download(
                &state.base.storage,
                &part.object_key,
                DOWNLOAD_URL_TTL,
            )
            .await
            .map_err(AppError::internal)?;
            parts.push(ExportPartLink {
                row_count: part.row_count,
                download_url: url,
            });
        }
    }
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
        stream_token: row.stream_token,
        parts,
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
    payload: attome_core::jobs::DataExportPayload,
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

    // A23-T10: the export's own options.
    let (labels, split_rows): (bool, Option<i64>) =
        sqlx::query_as("SELECT labels, split_rows FROM data_export WHERE id = $1")
            .bind(export_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let split_rows = split_rows.unwrap_or(DEFAULT_SPLIT_ROWS).max(1);

    let table = quote_ident(&entity_name);
    // A23-T10: id and row_version first, so a file read back can be matched
    // to its records and refused when one changed since.
    let mut header = vec!["id".to_string(), "row_version".to_string()];
    header.extend(
        plan.columns
            .iter()
            .filter(|c| *c != "id" && *c != "row_version")
            .cloned(),
    );
    let display = if labels {
        header_labels(state, payload.user_id, &entity_name, &header).await
    } else {
        header.clone()
    };
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
            "parquet" => "part-0001.parquet",
            _ => "ndjson",
        }
    );
    let path = ObjectPath::parse(&object_key)
        .map_err(|e| AppError::internal(format!("invalid export object key: {e}")))?;

    // L7-T5: the snapshot of a statement before the export's, kept only
    // when the export reads no row (its statement then names no snapshot).
    let pre_snapshot: Option<String> = sqlx::query_scalar("SELECT pg_current_snapshot()::text")
        .fetch_one(state.base.long_pool(&state.base.db))
        .await
        .ok();
    let result = match payload.format.as_str() {
        "json" => run_query_and_stream(state, &table, &select_list, &plan, &path, None, |row| {
            row.to_string()
        })
        .await
        .map(|(rows, checksum, snapshot)| (rows, checksum, snapshot, Vec::new())),
        "csv" => {
            // B21-T3: a byte-order mark first, so Excel reads Arabic as UTF-8.
            let header_line = format!(
                "{}{}",
                attome_report::render::CSV_BOM,
                attome_report::render::csv_header_line(&display)
            );
            let header_for_rows = header.clone();
            let dates = DatePresentation::for_user(state, payload.user_id, &attrs).await;
            // P4-T1: formula-like text is written as text unless the
            // deployment turned the guard off.
            let guard = attome_report::render::formula_guard_enabled(state);
            run_query_and_stream(
                state,
                &table,
                &select_list,
                &plan,
                &path,
                Some(header_line),
                move |row| {
                    attome_report::render::csv_line_with(&header_for_rows, &dates.apply(row), guard)
                },
            )
            .await
            .map(|(rows, checksum, snapshot)| (rows, checksum, snapshot, Vec::new()))
        }
        "parquet" => {
            export_parquet(
                state,
                XlsxQuery {
                    table: &table,
                    select_list: &select_list,
                    plan: &plan,
                    header: &header,
                    path: &path,
                },
                &entity_name,
                export_id,
                split_rows,
            )
            .await
        }
        _ => {
            let dates = DatePresentation::for_user(state, payload.user_id, &attrs).await;
            export_xlsx(
                state,
                XlsxQuery {
                    table: &table,
                    select_list: &select_list,
                    plan: &plan,
                    header: &header,
                    path: &path,
                },
                &dates,
                &display,
            )
            .await
            .map(|(rows, checksum, snapshot)| (rows, checksum, snapshot, Vec::new()))
        }
    };
    // A single-file export reaches here with its one file; restate it as
    // the export's only part.
    let result = result.map(|(rows, checksum, snapshot, parts)| {
        let parts = if parts.is_empty() {
            vec![ExportPart {
                object_key: object_key.clone(),
                row_count: rows,
                checksum: checksum.clone(),
            }]
        } else {
            parts
        };
        (rows, checksum, snapshot, parts)
    });

    let (row_count, checksum, snapshot, parts) = match result {
        Ok(v) => v,
        Err(e) => {
            mark_failed(state, export_id, &format!("export failed: {e}")).await?;
            return Ok(());
        }
    };
    let stream_token = snapshot
        .or(pre_snapshot)
        .and_then(|snap| crate::change_stream::export_token(&snap).ok());

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

    let first_key = parts
        .first()
        .map_or_else(|| object_key.clone(), |p| p.object_key.clone());
    if let Err(e) = complete_export(
        state,
        export_id,
        row_count,
        &first_key,
        &checksum,
        stream_token.as_deref(),
        &parts,
        event,
    )
    .await
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
    stream_token: Option<&str>,
    parts: &[ExportPart],
    event: AuditEvent,
) -> Result<(), AppError> {
    let parts = serde_json::to_value(parts).map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "UPDATE data_export \
            SET status = 'completed', row_count = $2, object_key = $3, checksum = $4, \
                stream_token = $5, parts = $6, completed_at = NOW(), updated_at = NOW(), \
                row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(export_id)
    .bind(row_count)
    .bind(object_key)
    .bind(checksum)
    .bind(stream_token)
    .bind(parts)
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
) -> Result<(i64, String, Option<String>), AppError> {
    use futures_util::StreamExt;

    // L7-T5: every row carries its statement's snapshot, the one the export
    // reads in.
    let sql = format!(
        "SELECT row_to_json(xexp)::text, pg_current_snapshot()::text \
           FROM (SELECT {select_list} FROM {table} t {} \
         ORDER BY t.id ASC LIMIT {}) xexp",
        plan.where_sql,
        MAX_EXPORT_ROWS + 1,
    );
    let mut q = sqlx::query_as::<_, (String, String)>(&sql);
    for p in &plan.params {
        q = q.bind(p.clone());
    }
    // AB6-T6: the long pool, so a minutes-long stream never holds an
    // interactive request's connection.
    let row_stream = q.fetch(state.base.long_pool(&state.base.db));

    let row_counter = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let counter_for_map = row_counter.clone();
    let snapshot = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let snapshot_for_map = snapshot.clone();
    let rendered = row_stream.map(move |item: Result<(String, String), sqlx::Error>| {
        item.and_then(|(raw, snap)| {
            if let Ok(mut kept) = snapshot_for_map.lock()
                && kept.is_none()
            {
                *kept = Some(snap);
            }
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
    let snapshot = snapshot.lock().ok().and_then(|mut s| s.take());
    Ok((row_count, checksum, snapshot))
}

/// `xlsx` cannot be produced line-by-line — a workbook is one zip archive
/// whose manifest isn't known until every row is written — so this builds
/// the whole file in memory (bounded by [`MAX_EXPORT_ROWS`] rows, same cap
/// as the streamed formats) and uploads it as one object.
/// What one XLSX export selects and where it goes.
struct XlsxQuery<'a> {
    table: &'a str,
    select_list: &'a str,
    plan: &'a ExportPlan,
    header: &'a [String],
    path: &'a ObjectPath,
}

async fn export_xlsx(
    state: &EngineState,
    query: XlsxQuery<'_>,
    dates: &DatePresentation,
    display: &[String],
) -> Result<(i64, String, Option<String>), AppError> {
    let XlsxQuery {
        table,
        select_list,
        plan,
        header,
        path,
    } = query;
    let sql = format!(
        "SELECT row_to_json(xexp)::text, pg_current_snapshot()::text \
           FROM (SELECT {select_list} FROM {table} t {} \
         ORDER BY t.id ASC LIMIT {}) xexp",
        plan.where_sql,
        MAX_EXPORT_ROWS + 1,
    );
    let mut q = sqlx::query_as::<_, (String, String)>(&sql);
    for p in &plan.params {
        q = q.bind(p.clone());
    }
    let rows: Vec<(String, String)> = q
        .fetch_all(state.base.long_pool(&state.base.db))
        .await
        .map_err(AppError::internal)?;
    if rows.len() as i64 > MAX_EXPORT_ROWS {
        return Err(AppError::internal(format!(
            "export exceeded the {MAX_EXPORT_ROWS}-row cap while processing (the result set grew \
             after the request was accepted) — re-run the export with a narrower filter"
        )));
    }

    let row_count = rows.len() as i64;
    let snapshot = rows.first().map(|(_, snap)| snap.clone());
    let values = rows
        .into_iter()
        .map(|(raw, _)| {
            serde_json::from_str::<Value>(&raw)
                .map(|row| relabel(dates.apply(row), header, display))
        })
        .collect::<Result<Vec<Value>, _>>()
        .map_err(AppError::internal)?;
    let buffer = attome_report::render::render_xlsx_with(
        display,
        &values,
        attome_report::render::formula_guard_enabled(state),
    )?;
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

    Ok((row_count, checksum, snapshot))
}

/// A23-T10: `row` keyed by the display header instead of the column
/// names (the XLSX renderer reads cells by header). Pure.
fn relabel(row: Value, header: &[String], display: &[String]) -> Value {
    if header == display {
        return row;
    }
    let mut out = serde_json::Map::new();
    if let Value::Object(map) = &row {
        for (name, label) in header.iter().zip(display) {
            out.insert(label.clone(), map.get(name).cloned().unwrap_or(Value::Null));
        }
    }
    Value::Object(out)
}

/// A23-T10: the header in the requester's language: each attribute's
/// `attribute` label in their `core.locale` (or the deployment's), else its
/// name; `id` and `row_version` keep theirs, and a label two columns share
/// gets the column name after it.
async fn header_labels(
    state: &EngineState,
    user_id: Uuid,
    entity: &str,
    header: &[String],
) -> Vec<String> {
    let (_, org_ref) = entity_crud::fetch_audit_ctx(state, user_id).await;
    let deployment = state.deployment_locale();
    let locale = attome_core::setting_registry()
        .get("core.locale")
        .map(|d| {
            state
                .settings
                .load()
                .resolve(d, Some(user_id), Some(org_ref))
                .0
        })
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| deployment.clone());
    let labels = state.labels.load();
    let mut seen = std::collections::HashSet::new();
    header
        .iter()
        .map(|column| {
            if column == "id" || column == "row_version" {
                return column.clone();
            }
            let label = labels
                .resolve(
                    "attribute",
                    &format!("{entity}.{column}"),
                    Some(&locale),
                    &deployment,
                )
                .map(|row| row.display_name.clone())
                .unwrap_or_else(|| column.clone());
            if seen.insert(label.clone()) {
                label
            } else {
                format!("{label} ({column})")
            }
        })
        .collect()
}

/// A23-T10: one batch of rows as an Arrow record batch, every column text
/// (a number, flag or list as its JSON text), so a file read back is the
/// values as stored.
fn record_batch(
    schema: &std::sync::Arc<arrow_schema::Schema>,
    header: &[String],
    rows: &[serde_json::Map<String, Value>],
) -> Result<arrow_array::RecordBatch, AppError> {
    let columns: Vec<arrow_array::ArrayRef> = header
        .iter()
        .map(|column| {
            let mut builder =
                arrow_array::builder::StringBuilder::with_capacity(rows.len(), rows.len() * 16);
            for row in rows {
                match row.get(column) {
                    None | Some(Value::Null) => builder.append_null(),
                    Some(Value::String(text)) => builder.append_value(text),
                    Some(other) => builder.append_value(other.to_string()),
                }
            }
            std::sync::Arc::new(builder.finish()) as arrow_array::ArrayRef
        })
        .collect();
    arrow_array::RecordBatch::try_new(schema.clone(), columns).map_err(AppError::internal)
}

/// A23-T10: the open Parquet part being written.
struct OpenPart {
    writer: parquet::arrow::ArrowWriter<Vec<u8>>,
    rows: i64,
}

fn open_part(schema: &std::sync::Arc<arrow_schema::Schema>) -> Result<OpenPart, AppError> {
    let props = parquet::file::properties::WriterProperties::builder()
        .set_compression(parquet::basic::Compression::SNAPPY)
        .set_max_row_group_row_count(Some(PARQUET_ROW_GROUP))
        .build();
    Ok(OpenPart {
        writer: parquet::arrow::ArrowWriter::try_new(Vec::new(), schema.clone(), Some(props))
            .map_err(AppError::internal)?,
        rows: 0,
    })
}

/// Closes `part` and stores it as part `number` of the export.
async fn store_part(
    state: &EngineState,
    entity: &str,
    export_id: Uuid,
    number: usize,
    part: OpenPart,
) -> Result<ExportPart, AppError> {
    let bytes = part.writer.into_inner().map_err(AppError::internal)?;
    let object_key = format!("data-exports/{entity}/{export_id}.part-{number:04}.parquet");
    let path = ObjectPath::parse(&object_key)
        .map_err(|e| AppError::internal(format!("invalid export object key: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let checksum = hex::encode(hasher.finalize());
    state
        .base
        .storage
        .store()
        .put(&path, bytes.into())
        .await
        .map_err(AppError::internal)?;
    Ok(ExportPart {
        object_key,
        row_count: part.rows,
        checksum,
    })
}

/// A23-T10: a Parquet export, streamed from the same query as the others:
/// rows go to the open part in row groups of [`PARQUET_ROW_GROUP`], and a
/// part that reaches `split_rows` rows is closed and stored before the next
/// opens. Only one part is held at a time (bounded by [`MAX_EXPORT_ROWS`]).
async fn export_parquet(
    state: &EngineState,
    query: XlsxQuery<'_>,
    entity: &str,
    export_id: Uuid,
    split_rows: i64,
) -> Result<(i64, String, Option<String>, Vec<ExportPart>), AppError> {
    use futures_util::StreamExt;
    let XlsxQuery {
        table,
        select_list,
        plan,
        header,
        path: _,
    } = query;
    let sql = format!(
        "SELECT row_to_json(xexp)::text, pg_current_snapshot()::text \
           FROM (SELECT {select_list} FROM {table} t {} \
         ORDER BY t.id ASC LIMIT {}) xexp",
        plan.where_sql,
        MAX_EXPORT_ROWS + 1,
    );
    let mut q = sqlx::query_as::<_, (String, String)>(&sql);
    for p in &plan.params {
        q = q.bind(p.clone());
    }
    let mut stream = q.fetch(state.base.long_pool(&state.base.db));
    let schema = std::sync::Arc::new(arrow_schema::Schema::new(
        header
            .iter()
            .map(|c| arrow_schema::Field::new(c.as_str(), arrow_schema::DataType::Utf8, true))
            .collect::<Vec<_>>(),
    ));

    let mut parts = Vec::new();
    let mut total = 0_i64;
    let mut snapshot = None;
    let mut group: Vec<serde_json::Map<String, Value>> = Vec::with_capacity(PARQUET_ROW_GROUP);
    let mut open: Option<OpenPart> = None;
    loop {
        let next = stream.next().await;
        let done = next.is_none();
        if let Some(item) = next {
            let (raw, snap) = item.map_err(AppError::internal)?;
            if snapshot.is_none() {
                snapshot = Some(snap);
            }
            let value: Value = serde_json::from_str(&raw).map_err(AppError::internal)?;
            group.push(value.as_object().cloned().unwrap_or_default());
            total += 1;
            if total > MAX_EXPORT_ROWS {
                return Err(AppError::internal(format!(
                    "export exceeded the {MAX_EXPORT_ROWS}-row cap while processing (the result set grew \
                     after the request was accepted) — re-run the export with a narrower filter"
                )));
            }
        }
        let in_part = open.as_ref().map_or(0, |p| p.rows) + group.len() as i64;
        let part_full = in_part >= split_rows;
        if !group.is_empty() && (done || part_full || group.len() >= PARQUET_ROW_GROUP) {
            let batch = record_batch(&schema, header, &group)?;
            if open.is_none() {
                open = Some(open_part(&schema)?);
            }
            if let Some(part) = open.as_mut() {
                part.writer.write(&batch).map_err(AppError::internal)?;
                part.rows += group.len() as i64;
            }
            group.clear();
        }
        if (part_full || done)
            && let Some(part) = open.take()
        {
            parts.push(store_part(state, entity, export_id, parts.len() + 1, part).await?);
        }
        if done {
            break;
        }
    }
    // No rows: one empty file with the columns, so a reader still sees them.
    if parts.is_empty() {
        let part = open_part(&schema)?;
        parts.push(store_part(state, entity, export_id, 1, part).await?);
    }
    let checksum = parts
        .first()
        .map(|p| p.checksum.clone())
        .unwrap_or_default();
    Ok((total, checksum, snapshot, parts))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn presentation(calendar: &str, arab_digits: bool) -> DatePresentation {
        DatePresentation {
            calendar: calendar.to_owned(),
            arab_digits,
            date_columns: vec!["closed_on".to_owned()],
            hijri: std::sync::Arc::new(
                attome_core::calendar::hijri::HijriCalendar::umm_al_qura().clone(),
            ),
        }
    }

    /// B11-T3: a Hijri user's export shows Hijri dates; other columns and a
    /// Gregorian user's export are untouched.
    #[test]
    fn export_uses_hijri_dates_for_a_hijri_user() {
        let row = serde_json::json!({"closed_on": "2026-02-18", "name": "2026-02-18"});
        let hijri = presentation("hijri", false).apply(row.clone());
        assert_eq!(hijri["closed_on"], "1447-09-01");
        assert_eq!(hijri["name"], "2026-02-18", "only date columns change");
        assert_eq!(
            presentation("both", false).apply(row.clone())["closed_on"],
            "2026-02-18 (1447-09-01)"
        );
        assert_eq!(
            presentation("hijri", true).apply(row.clone())["closed_on"],
            "١٤٤٧-٠٩-٠١"
        );
        assert_eq!(presentation("gregorian", false).apply(row.clone()), row);
    }
}
