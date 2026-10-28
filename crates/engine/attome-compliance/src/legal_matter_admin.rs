//! M23 Records Management (D-456) — legal discovery: the two workflow
//! operations `audit_legal_matter`'s generic entity CRUD
//! (`legal_matter_seed.rs`) can't express — "collect" (run the matter's
//! scope query, place a hold on every hit, export a collection package) and
//! "release" (release every hold the collect placed) — plus a
//! deployment-wide records posture report. Same M24/D-428 "generic CRUD for
//! reads/creates, a dedicated admin surface only for the workflow" split
//! `consent_admin.rs` uses.
//!
//! "Run the scope query under an admin principal" (module plan §3): this
//! module builds and runs the `WHERE` clause itself, with no
//! `SecurityContext`/row- or field-security filtering applied at all — an
//! e-discovery collection is deliberately exhaustive, not scoped to what any
//! one caller could see through the ordinary read path. The admin who
//! triggers `collect` is authorized at the *operation* boundary
//! (`Authorized<Admin>`), not per matched record.
//!
//! Hold placement is bounded and idempotent, never a single unbounded
//! `INSERT ... SELECT`: [`run_collect_job`] walks `scope_entity` in fixed-size
//! batches by id, same `WHERE id > $cursor ORDER BY id LIMIT N` keyset shape
//! `attome_api::entity_mutation::run_cascade_deactivate_job` uses for its own
//! size-gated batch job, and each batch's hold insert is an
//! `INSERT ... SELECT ... WHERE NOT EXISTS` so re-running the same batch
//! (a crash-and-retry apalis attempt) never double-places a hold. Unlike
//! that job this one has no persisted cursor across attempts — a retried
//! job attempt re-scans from the start, which stays correct (every batch is
//! idempotent) at the cost of re-doing the anti-join check for
//! already-processed ids; the same full-rescan-on-retry shape several other
//! periodic/sweep jobs in this workspace already accept (`WorkflowSlaSweep`,
//! `ComputeMetricSnapshots`) rather than a persisted-cursor design, given
//! this module's effort budget.

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
};
use attome_core::filter::{FieldCastError, FilterSchema, cast_for_attr, is_multi_choice_attr};
use attome_core::jobs::EngineJob;
use attome_core::{AttrInfo, EngineState, Filter, quote_ident};
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::AppError;
use attome_types::ErrorResponse;
use object_store::path::Path as ObjectPath;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};

/// Both jobs below write one summary `AuditEvent` on completion — the
/// deployment's audit ledger is itself hash-chained (`bin/audit_chainer`),
/// which is what the module plan's "audit-chained, hashed collection
/// package" asks for: the package's own checksum lives on
/// `audit_legal_matter.package_checksum`, and *that* fact (this matter
/// collected N holds into package P with checksum C) is what this event
/// commits into the tamper-evident audit chain.
fn matter_audit_service(state: &EngineState) -> AuditService<'_> {
    AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone())
}

/// Rows scanned/considered per hold-placement batch. Small enough that each
/// batch's statement (a keyset SELECT plus an anti-join INSERT) stays a
/// short transaction; large enough that a matter spanning millions of
/// records still finishes in a bounded number of iterations. Same order of
/// magnitude as `run_cascade_deactivate_job::BATCH_SIZE`.
const HOLD_BATCH_SIZE: i64 = 500;

/// Hard cap on the collection package's row count — same reasoning and same
/// order of magnitude as `attome_api::data_export::MAX_EXPORT_ROWS`: no
/// measured production-shaped throughput exists yet for a single-file
/// streamed export this large, so this is a conservative ceiling, not a
/// tuned one. A matter whose scope exceeds it fails collection with an
/// actionable message rather than silently truncating the package.
const MAX_COLLECTION_ROWS: i64 = 200_000;

/// C-15 (M01 §7): this module's own [`FilterSchema`] adapter over a
/// validated `attrs` list — no `allowed_fields` masking here, since this
/// module's own doc comment already establishes that a discovery scope has
/// no `SecurityContext`/field-security filtering at all (deliberately
/// exhaustive, admin-authorized at the operation boundary, not per field).
struct ScopeFilterSchema<'a> {
    attrs: &'a [AttrInfo],
}

impl FilterSchema for ScopeFilterSchema<'_> {
    fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
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

/// Builds the scope query's `WHERE` clause from a validated `(entity, attrs)`
/// pair and a caller-authored filter list, via the shared
/// `attome_core::filter::compile` writer (C-15, M01 §7) — this module
/// used to hand-copy the same scalar operator set
/// `attome_api::data_export::plan_export` does; migrating onto the shared
/// compiler additionally gains this scope the multi-select array operators
/// (`contains_any`/`contains_all`) it never had before, at no extra cost.
/// Identifiers only from `attrs` (validated metadata), values always bound
/// (guidelines §4).
fn build_scope_predicate(
    attrs: &[AttrInfo],
    filters: &[Filter],
) -> Result<(String, Vec<String>), AppError> {
    let mut conds: Vec<String> = vec!["t.is_active = true".to_owned()];
    let mut params: Vec<String> = Vec::new();

    let schema = ScopeFilterSchema { attrs };
    for f in filters {
        let (cond, binds) = attome_core::filter::compile(f, &schema, params.len() + 1)?;
        conds.push(cond);
        params.extend(binds);
    }

    Ok((conds.join(" AND "), params))
}

#[derive(sqlx::FromRow)]
struct MatterRow {
    reference: String,
    scope_entity: String,
    scope_filter: Option<String>,
    status: String,
}

async fn load_matter(db: &DbPool, matter_id: Uuid) -> Result<MatterRow, AppError> {
    sqlx::query_as(
        "SELECT reference, scope_entity, scope_filter, status \
           FROM audit_legal_matter WHERE id = $1 AND is_active = true",
    )
    .bind(matter_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

fn parse_scope_filter(raw: Option<&str>) -> Result<Vec<Filter>, AppError> {
    match raw {
        None => Ok(Vec::new()),
        Some(s) if s.trim().is_empty() => Ok(Vec::new()),
        Some(s) => serde_json::from_str(s).map_err(|e| {
            AppError::Validation(format!("scope_filter is not a valid filter list: {e}"))
        }),
    }
}

/// One bounded hold-placement pass: scans up to `HOLD_BATCH_SIZE` matching
/// ids after `cursor`, places a hold on any that don't already carry an
/// active one under this exact `matter_reference` (idempotent — see this
/// module's top doc comment), and returns `(new_cursor, scanned_count,
/// placed_count)`. `scanned_count < HOLD_BATCH_SIZE` (including `0`) means
/// this was the last batch.
async fn place_holds_batch(
    db: &DbPool,
    scope_entity: &str,
    where_sql: &str,
    params: &[String],
    matter_reference: &str,
    placed_by: Uuid,
    cursor: Uuid,
) -> Result<(Option<Uuid>, i64, i64), AppError> {
    let table = quote_ident(scope_entity);
    // Bind order: the matter's own scope-filter values ($1..$P), then
    // cursor, batch size, matter_reference, placed_by, scope_entity —
    // computed explicitly rather than string-substituted so every
    // placeholder's number is visible at its own use site.
    let p = params.len();
    let cursor_n = p + 1;
    let batch_n = p + 2;
    let matter_ref_n = p + 3;
    let placed_by_n = p + 4;
    let entity_n = p + 5;
    let sql = format!(
        "WITH batch AS ( \
             SELECT t.id FROM {table} t \
              WHERE {where_sql} AND t.id > ${cursor_n} \
              ORDER BY t.id LIMIT ${batch_n} \
         ), inserted AS ( \
             INSERT INTO legal_hold (entity_logicalname, record_id, matter_reference, placed_by) \
             SELECT ${entity_n}, b.id, ${matter_ref_n}, ${placed_by_n} FROM batch b \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM legal_hold h \
                  WHERE h.entity_logicalname = ${entity_n} AND h.record_id = b.id \
                    AND h.matter_reference = ${matter_ref_n} \
                    AND h.released_at IS NULL AND h.is_deleted = false \
             ) \
             RETURNING record_id \
         ) \
         SELECT (SELECT max(id) FROM batch), (SELECT count(*) FROM batch)::bigint, \
                (SELECT count(*) FROM inserted)::bigint"
    );

    let mut q = sqlx::query_as::<_, (Option<Uuid>, i64, i64)>(&sql);
    for param in params {
        q = q.bind(param.clone());
    }
    q = q
        .bind(cursor)
        .bind(HOLD_BATCH_SIZE)
        .bind(matter_reference)
        .bind(placed_by)
        .bind(scope_entity);

    let (max_id, scanned, placed) = q.fetch_one(db).await.map_err(AppError::internal)?;
    Ok((max_id, scanned, placed))
}

/// `EngineJob::LegalMatterCollect`'s worker: bounded hold placement
/// (see [`place_holds_batch`]) followed by one full, unmasked export of the
/// matched set as the collection package.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub async fn run_collect_job(
    state: &EngineState,
    matter_id: Uuid,
    collected_by: Uuid,
) -> Result<(), AppError> {
    let db = &state.base.db;
    let matter = load_matter(db, matter_id).await?;
    if matter.status != "collecting" {
        tracing::info!(
            matter_id = %matter_id, status = %matter.status,
            "legal matter collect: matter is not in 'collecting' state, skipping (already \
             processed, or a re-delivered job)"
        );
        return Ok(());
    }

    let registry = state.entities.load();
    let meta = registry.get(&matter.scope_entity).ok_or_else(|| {
        AppError::Validation(format!(
            "legal matter collect: scope_entity {} is not a registered entity",
            matter.scope_entity
        ))
    })?;
    let attrs = meta.attrs.clone();
    drop(registry);

    let filters = parse_scope_filter(matter.scope_filter.as_deref())?;
    let (where_sql, params) = build_scope_predicate(&attrs, &filters)?;

    let mut cursor = Uuid::nil();
    let mut total_placed = 0i64;
    loop {
        let (max_id, scanned, placed) = place_holds_batch(
            db,
            &matter.scope_entity,
            &where_sql,
            &params,
            &matter.reference,
            collected_by,
            cursor,
        )
        .await?;
        total_placed += placed;
        if scanned < HOLD_BATCH_SIZE || max_id.is_none() {
            break;
        }
        cursor = max_id.expect("checked above");
    }

    // Package: one full, unmasked export of the current matching set —
    // separate read from the hold-placement loop above (a record inserted
    // between the two would get a hold from the loop but might not appear
    // in the package if it also races the export; a matter's scope is
    // expected to be a stable snapshot of at-rest data at collection time,
    // not a live join against concurrent writes).
    let table = quote_ident(&matter.scope_entity);
    let count_sql = format!("SELECT COUNT(*) FROM {table} t WHERE {where_sql}");
    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql);
    for p in &params {
        count_q = count_q.bind(p.clone());
    }
    let matching = count_q.fetch_one(db).await.map_err(AppError::internal)?;
    if matching > MAX_COLLECTION_ROWS {
        return Err(AppError::internal(format!(
            "legal matter collect: scope matches {matching} rows, over the {MAX_COLLECTION_ROWS}-row \
             collection-package cap — narrow the matter's scope_filter"
        )));
    }

    let export_sql = format!(
        "SELECT row_to_json(t)::text FROM {table} t WHERE {where_sql} ORDER BY t.id ASC LIMIT {}",
        MAX_COLLECTION_ROWS + 1
    );
    let mut export_q = sqlx::query_scalar::<_, String>(&export_sql);
    for p in &params {
        export_q = export_q.bind(p.clone());
    }
    let rows = export_q.fetch(db);

    let package_key = format!("legal-hold-packages/{matter_id}/collection.ndjson");
    let package_path = ObjectPath::parse(&package_key)
        .map_err(|e| AppError::internal(format!("invalid package object key: {e}")))?;
    let (row_count, checksum) = crate::retention::stream_masked_export_to_store(
        rows,
        state.base.storage.store_arc(),
        package_path,
    )
    .await?;

    // D-062 / audit plan 3.6: the `collected` transition and its audit event
    // commit in one transaction, opened only after the package upload. A
    // failed audit write rolls the transition back, leaving the matter
    // `collecting`, so the job's retry passes its own status guard and
    // re-runs: hold placement is idempotent (anti-join) and the package is
    // re-streamed to the same key.
    let (user_ctx, organization_ref) = attome_audit::fetch_audit_ctx(state, collected_by).await;
    let event = AuditEvent {
        organization_ref,
        category: AuditCategory::Security,
        entity_name: Some("audit_legal_matter".to_string()),
        record_id: Some(matter_id),
        operation: AuditOperation::Export,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some("legal_matter_collect".to_string()),
        event_comment: Some(format!(
            "M23: legal matter {} ({matter_id}) collected — {total_placed} hold(s) placed on \
             {}, package {package_key} (sha256={checksum}, rows={row_count})",
            matter.reference, matter.scope_entity
        )),
        changed_fields: vec![],
        snapshot_json: None,
    };
    let mut tx = attome_db::tx::begin(db).await?;
    update_matter_after_collect(&mut tx, matter_id, row_count, &package_key, &checksum).await?;
    matter_audit_service(state)
        .write_in_tx(&mut tx, event)
        .await?;
    attome_db::tx::commit(tx).await?;

    tracing::info!(
        matter_id = %matter_id, holds_placed = total_placed, collected_rows = row_count,
        "legal matter collect: run complete"
    );

    Ok(())
}

async fn update_matter_after_collect(
    tx: &mut attome_db::Tx<'_>,
    matter_id: Uuid,
    row_count: i64,
    package_key: &str,
    checksum: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE audit_legal_matter \
            SET status = 'collected', collected_record_count = $2::numeric, package_ref = $3, \
                package_checksum = $4, collected_at = NOW(), modified_at = NOW(), \
                row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(matter_id)
    // `collected_record_count` is a "number" generic-entity field -> a
    // NUMERIC column; bound as text + `::numeric` cast, the same convention
    // every filter/write in this codebase uses for that column type
    // (`attome_core::scalar_filter_value`'s callers, `sql_cast`) rather
    // than a native f64 bind.
    .bind(row_count.to_string())
    .bind(package_key)
    .bind(checksum)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// `EngineJob::LegalMatterRelease`'s worker: releases every active hold
/// tagged with this matter's `reference`, in bounded batches — same
/// `FOR UPDATE SKIP LOCKED` shape `run_cascade_deactivate_job` uses, so this
/// is also safe to run concurrently with itself (though the release
/// endpoint's dedup-keyed enqueue already keeps at most one live per
/// matter).
pub async fn run_release_job(
    state: &EngineState,
    matter_id: Uuid,
    released_by: Uuid,
) -> Result<(), AppError> {
    const BATCH_SIZE: i64 = 1_000;
    let db = &state.base.db;
    let matter = load_matter(db, matter_id).await?;
    if matter.status != "releasing" {
        tracing::info!(
            matter_id = %matter_id, status = %matter.status,
            "legal matter release: matter is not in 'releasing' state, skipping"
        );
        return Ok(());
    }

    let mut total_released = 0i64;
    loop {
        let result = sqlx::query(
            "UPDATE legal_hold SET released_at = NOW(), updated_at = NOW(), \
                row_version = row_version + 1 \
              WHERE id IN ( \
                  SELECT id FROM legal_hold \
                   WHERE matter_reference = $1 AND released_at IS NULL AND is_deleted = false \
                   LIMIT $2 \
                   FOR UPDATE SKIP LOCKED \
              )",
        )
        .bind(&matter.reference)
        .bind(BATCH_SIZE)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        let affected = result.rows_affected() as i64;
        total_released += affected;
        if affected == 0 {
            break;
        }
    }

    // D-062 / audit plan 3.6: the `released` transition and its audit event
    // commit in one transaction. A failed audit write rolls the transition
    // back, leaving the matter `releasing`, so the job's retry passes its own
    // status guard, finds no holds left to release (the batches above
    // already committed and are idempotent), and completes the transition.
    let (user_ctx, organization_ref) = attome_audit::fetch_audit_ctx(state, released_by).await;
    let event = AuditEvent {
        organization_ref,
        category: AuditCategory::Security,
        entity_name: Some("audit_legal_matter".to_string()),
        record_id: Some(matter_id),
        operation: AuditOperation::Update,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some("legal_matter_release".to_string()),
        event_comment: Some(format!(
            "M23: legal matter {} ({matter_id}) released — {total_released} hold(s) released",
            matter.reference
        )),
        changed_fields: vec![],
        snapshot_json: None,
    };
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query(
        "UPDATE audit_legal_matter \
            SET status = 'released', released_at = NOW(), modified_at = NOW(), \
                row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(matter_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    matter_audit_service(state)
        .write_in_tx(&mut tx, event)
        .await?;
    attome_db::tx::commit(tx).await?;

    tracing::info!(
        matter_id = %matter_id, holds_released = total_released,
        "legal matter release: run complete"
    );
    Ok(())
}

// ── Admin routes ────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
struct CollectTriggered {
    matter_id: Uuid,
    status: String,
    enqueued: bool,
}

/// Collect a legal matter's records
///
/// Moves the matter to collecting and queues the collection job in the same transaction; asking again
/// before it starts queues nothing more. Compliance administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/legal/matters/{id}/collect",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The legal matter")),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("EngineJob::LegalMatterCollect"),
        "the route only moves the matter to collecting and enqueues the job; the job writes security+export in the collected-transition transaction",
    )))),
    responses(
        (status = 202, description = "Success", body = CollectTriggered),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Matter is not eligible to collect", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn collect(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<CollectTriggered>), AppError> {
    // Validate the matter's scope up front, before transitioning it to
    // `collecting` — a bad `scope_entity`/`scope_filter` must 422 the
    // request synchronously, not silently strand the matter in
    // `collecting` forever (there is no `failed` status in this entity's
    // `status` choice list, and `run_collect_job`'s own re-derive-current-
    // state check only ever no-ops on a status that's already moved past
    // `collecting` — it can't itself move a stuck matter back to `open`).
    let matter = load_matter(&state.base.db, id).await?;
    let registry = state.entities.load();
    let meta = registry.get(&matter.scope_entity).ok_or_else(|| {
        AppError::Validation(format!(
            "scope_entity {} is not a registered entity",
            matter.scope_entity
        ))
    })?;
    let attrs = meta.attrs.clone();
    drop(registry);
    let filters = parse_scope_filter(matter.scope_filter.as_deref())?;
    build_scope_predicate(&attrs, &filters)?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = sqlx::query(
        "UPDATE audit_legal_matter SET status = 'collecting', modified_at = NOW(), \
            row_version = row_version + 1 \
          WHERE id = $1 AND is_active = true AND status IN ('open', 'collected')",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if result.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "matter was not found, or is not in a state that can start a collection (open/collected)",
        ));
    }

    attome_jobs::enqueue_in_tx_dedup(
        &mut tx,
        EngineJob::LegalMatterCollect {
            matter_id: id,
            collected_by: ctx.user_id,
        },
        &format!("legal-matter-collect:{id}"),
    )
    .await
    .map_err(AppError::internal)?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok((
        StatusCode::ACCEPTED,
        Json(CollectTriggered {
            matter_id: id,
            status: "collecting".to_string(),
            enqueued: true,
        }),
    ))
}

#[derive(Serialize, ToSchema)]
struct ReleaseTriggered {
    matter_id: Uuid,
    status: String,
    enqueued: bool,
}

/// Release a legal matter
///
/// Moves a collected matter to releasing and queues the release job in the same transaction.
/// Compliance administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/legal/matters/{id}/release",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The legal matter")),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("EngineJob::LegalMatterRelease"),
        "the route only moves the matter to releasing and enqueues the job; the job writes security+update in the released-transition transaction",
    )))),
    responses(
        (status = 202, description = "Success", body = ReleaseTriggered),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Matter is not eligible to release", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn release(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<ReleaseTriggered>), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = sqlx::query(
        "UPDATE audit_legal_matter SET status = 'releasing', modified_at = NOW(), \
            row_version = row_version + 1 \
          WHERE id = $1 AND is_active = true AND status = 'collected'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if result.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "matter was not found, or is not in a state that can release (collected)",
        ));
    }

    attome_jobs::enqueue_in_tx_dedup(
        &mut tx,
        EngineJob::LegalMatterRelease {
            matter_id: id,
            released_by: ctx.user_id,
        },
        &format!("legal-matter-release:{id}"),
    )
    .await
    .map_err(AppError::internal)?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok((
        StatusCode::ACCEPTED,
        Json(ReleaseTriggered {
            matter_id: id,
            status: "releasing".to_string(),
            enqueued: true,
        }),
    ))
}

// ── Records posture report ─────────────────────────────────────────────

/// A single deployment-wide snapshot, not a list — same "aggregate summary,
/// not `PaginatedResponse<T>`" shape `attome_api::api_usage_admin`'s summary
/// endpoint already uses (guidelines §12 reserves the paginated envelope for
/// genuinely list-shaped access patterns).
#[derive(Serialize, ToSchema)]
struct RecordsPosture {
    /// `audit_retention_action` rows still `status = 'proposed'` — records past
    /// retention with no disposition decided yet.
    past_retention_awaiting_disposition: i64,
    /// `legal_hold` rows currently active (`released_at IS NULL`).
    active_legal_holds: i64,
    /// `archive_record` rows not yet restored.
    active_archives: i64,
    /// `audit_legal_matter` rows still `status IN ('open', 'collecting', 'collected', 'releasing')`.
    open_legal_matters: i64,
}

/// Read the records management posture
///
/// How many retention actions are proposed, legal holds active, records still archived and legal
/// matters in progress. Compliance administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/records/posture",
    tag = "admin",
    responses(
        (status = 200, description = "Success", body = RecordsPosture),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn records_posture(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Compliance>>,
) -> Result<Json<RecordsPosture>, AppError> {
    let db = &state.base.db;
    let past_retention_awaiting_disposition: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_retention_action WHERE status = 'proposed' AND is_deleted = false",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let active_legal_holds: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM legal_hold WHERE released_at IS NULL AND is_deleted = false",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let active_archives: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM archive_record WHERE restored_at IS NULL AND is_deleted = false",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let open_legal_matters: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_legal_matter \
          WHERE is_active = true AND status IN ('open', 'collecting', 'collected', 'releasing')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(RecordsPosture {
        past_retention_awaiting_disposition,
        active_legal_holds,
        active_archives,
        open_legal_matters,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/legal/matters/{id}/collect", post(collect))
        .route("/api/v1/admin/legal/matters/{id}/release", post(release))
        .route("/api/v1/admin/records/posture", get(records_posture))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(collect, release, records_posture))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(logicalname: &str, field_type_int: i32) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_string(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
            options: None,
        }
    }

    #[test]
    fn build_scope_predicate_rejects_an_unknown_field() {
        let attrs = vec![attr("name", 3)];
        let filters = vec![Filter {
            field: "ssn".to_string(),
            op: "eq".to_string(),
            value: Some(serde_json::json!("123")),
        }];
        assert!(build_scope_predicate(&attrs, &filters).is_err());
    }

    #[test]
    fn build_scope_predicate_always_includes_is_active() {
        let attrs = vec![attr("name", 3)];
        let (sql, params) = build_scope_predicate(&attrs, &[]).unwrap();
        assert!(sql.contains("t.is_active = true"));
        assert!(params.is_empty());
    }

    #[test]
    fn build_scope_predicate_casts_a_date_field() {
        let attrs = vec![attr("closed_on", 5)];
        let filters = vec![Filter {
            field: "closed_on".to_string(),
            op: "lt".to_string(),
            value: Some(serde_json::json!("2020-01-01T00:00:00Z")),
        }];
        let (sql, params) = build_scope_predicate(&attrs, &filters).unwrap();
        assert!(sql.contains("::timestamptz"));
        assert_eq!(params, vec!["2020-01-01T00:00:00Z".to_string()]);
    }

    #[test]
    fn parse_scope_filter_treats_missing_and_blank_as_no_filters() {
        assert!(parse_scope_filter(None).unwrap().is_empty());
        assert!(parse_scope_filter(Some("")).unwrap().is_empty());
        assert!(parse_scope_filter(Some("   ")).unwrap().is_empty());
    }

    #[test]
    fn parse_scope_filter_rejects_invalid_json() {
        assert!(parse_scope_filter(Some("not json")).is_err());
    }
}
