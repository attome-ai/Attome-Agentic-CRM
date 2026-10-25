//! M19 (Audit) gap list — read-only admin surfaces over the audit ledger:
//! a filtered search (`GET /api/v1/admin/audit/search`) and a streamed
//! SIEM/CSV export (`GET /api/v1/admin/audit/export`).
//!
//! **Read-only, by construction.** Every handler here binds runtime values
//! and enumerates columns (guidelines §4); nothing in this file writes to
//! `audit_header`/`audit_detail`/`audit_snapshot` or any of the
//! chain-batch/signing-key/ingest infrastructure `crate::service`/
//! `crate::chainer`/`crate::anchor`/`crate::verify` own — this module never
//! touches those files.
//!
//! **Pool.** Both handlers use `state.base.readonly_query_pool(...)`
//! (D-344's sticky-primary-aware readonly routing, the same pool
//! `query_exec.rs`'s stored-query path uses) rather than the primary `db`
//! pool — the task's "least-privileged read-only pool" requirement.
//! `audit_header`/`audit_detail` are registered XRM entities
//! (`seed.rs`), so D-126's per-entity `attome_readonly` grant already
//! covers them; no new GRANT is needed.
//!
//! **Never mind the whole table.** `search` is offset-paginated like every
//! other admin list (D-347), capped at `MAX_PAGE_SIZE`. `export` never
//! materializes its result: it streams formatted lines through a keyset
//! cursor over `audit_header.id` (uuidv7, monotonic within one
//! serialized-by-org writer — see the module doc on `EXPORT_SAFETY_MARGIN`
//! below for the one caveat that ordering carries), one bounded batch at a
//! time via `futures_util::stream::unfold`, so memory is bounded by
//! `EXPORT_BATCH_SIZE` regardless of how many rows match.
//!
//! **Ordering caveat, stated once here.** `audit_header.id` is a
//! `uuidv7()` generated at INSERT time. `AuditService::acquire_chain_lock`
//! serializes header writes *per organization* (one non-blocking
//! `pg_try_advisory_xact_lock` attempt, no retry — a loser's whole mutation
//! fails outright rather than queuing), so for a single organization,
//! `id` order and commit order coincide exactly — the same reasoning
//! `fetch_last_hash`'s doc comment already relies on. Across DIFFERENT
//! organizations writing concurrently, that guarantee does not hold (org A
//! can generate a smaller uuidv7 but commit later than org B's write) —
//! exactly the class of bug migration `0104` built `commit_xid`-based
//! cursoring to prevent for the entity change feed. Rather than duplicating
//! that (materially larger) machinery for a read-only export endpoint, this
//! module applies the simpler, honest mitigation: `export`'s upper bound is
//! always clamped to `NOW() - EXPORT_SAFETY_MARGIN`, giving any
//! still-in-flight transaction time to commit before its row is considered
//! part of a "closed" export window. A SIEM/M62 subscriber polling forward
//! in time will see every row eventually; what the margin buys is that a
//! row is never reported as "before the cursor" and then silently missed
//! by the next poll. A deployment with multiple root organizations writing
//! audit events at high concurrency and needing a stronger guarantee than
//! this margin should track that as a follow-up (a `commit_xid` column on
//! `audit_header`, mirroring `0104`), not assume this module already
//! provides it.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::{
    AppError, DEFAULT_PAGE_SIZE, ErrorResponse, PageBase, PageWindow, PaginatedResponse,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// How far behind "now" a streamed export's effective upper time bound is
/// clamped — see this module's doc comment for why. 30s comfortably covers
/// ordinary write-transaction duration (audit appends are small, synchronous
/// single-row/few-row inserts) without meaningfully delaying a SIEM
/// consumer polling on a minute-or-coarser cadence.
const EXPORT_SAFETY_MARGIN_SECS: i64 = 30;

/// Rows fetched per page inside `export`'s streaming cursor — bounds memory
/// to one batch regardless of the matched window's total size.
const EXPORT_BATCH_SIZE: i64 = 1000;

// ── Shared filter shape ─────────────────────────────────────────────────────

/// The search/export filter dimensions the task calls for: entity, record,
/// user, operation, date range, field. `field_name` matches against
/// `audit_detail.field_name` via an `EXISTS` correlated on `audit_ref`
/// (see this module's `EXPLAIN` evidence in `document/evidence/` for why
/// that shape, not a JOIN, is what stays index-backed).
///
/// Deliberately NOT `Deserialize`/`IntoParams` itself and NOT
/// `#[serde(flatten)]`ed into the query structs below — this codebase has
/// no existing use of `#[serde(flatten)]` on a utoipa `IntoParams` struct,
/// and risking that proc-macro interaction for a handful of fields isn't
/// worth it. `SearchQuery`/`ExportQuery` instead declare these fields
/// directly and build an `AuditFilterParams` from themselves.
#[derive(Debug, Default)]
struct AuditFilterParams {
    entity_name: Option<String>,
    record_id: Option<Uuid>,
    user_id: Option<Uuid>,
    /// Matches `audit_header.user_email` case-insensitively (no index —
    /// see the EXPLAIN evidence; prefer `user_id` for an index-backed
    /// lookup when it's known).
    user_email: Option<String>,
    /// `audit_header.operation` (see `AuditOperation` in `model.rs`) —
    /// the integer discriminant, not a name, to avoid a second name<->int
    /// table this admin surface would have to keep in sync.
    operation: Option<i32>,
    field_name: Option<String>,
    date_from: Option<DateTime<Utc>>,
    date_to: Option<DateTime<Utc>>,
    organization_ref: Option<Uuid>,
    /// Q17-T2: a unit auditor's units; only their events are read. Set by
    /// the handler from the caller, never from the query string.
    unit_scope: Option<Vec<Uuid>>,
}

/// Q17-T2: the privilege of an auditor scoped to their units.
pub const UNIT_AUDITOR: &str = "audit.read_unit";

/// Q17-T2: what one caller may read of the audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditScope {
    /// An administrator: every event.
    All,
    /// A unit auditor: the events of these organisations only (none when
    /// they reach no unit).
    Units(Vec<Uuid>),
}

/// Q17-T2: the scope of a caller who may be an administrator or a holder
/// of [`UNIT_AUDITOR`]; anyone else is refused. Pure.
pub fn auditor_scope(
    is_admin: bool,
    unit_auditor: bool,
    units: Vec<Uuid>,
) -> Result<AuditScope, AppError> {
    if is_admin {
        Ok(AuditScope::All)
    } else if unit_auditor {
        Ok(AuditScope::Units(units))
    } else {
        Err(AppError::Forbidden)
    }
}

/// Q17-T2: the organisations a unit auditor answers for: their own (home
/// and memberships) and every one below them in the organisation tree.
async fn units_of(db: &attome_db::DbPool, user: Uuid) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "WITH RECURSIVE tree AS ( \
           SELECT o.id FROM organization o \
            WHERE o.id IN (SELECT m.organization_ref FROM user_account_mm_organization m \
                            WHERE m.user_ref = $1 AND m.is_deleted = false \
                           UNION \
                           SELECT u.organization_ref FROM user_account u \
                            WHERE u.id = $1 AND u.organization_ref IS NOT NULL) \
           UNION \
           SELECT o.id FROM organization o JOIN tree t ON o.organization_ref = t.id) \
         SELECT id FROM tree",
    )
    .bind(user)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Q17-T2: refuses anyone who is neither an administrator nor a unit
/// auditor, and answers the scope of one who is.
async fn require_audit_reader(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
) -> Result<AuditScope, AppError> {
    let unit_auditor = ctx.privileges.contains(UNIT_AUDITOR);
    let units = if !ctx.is_admin && unit_auditor {
        units_of(&state.base.db, ctx.user_id).await?
    } else {
        Vec::new()
    };
    auditor_scope(ctx.is_admin, unit_auditor, units)
}

impl AuditFilterParams {
    fn scoped(mut self, scope: AuditScope) -> Self {
        self.unit_scope = match scope {
            AuditScope::All => None,
            AuditScope::Units(units) => Some(units),
        };
        self
    }
}

/// Binds `p`'s filters onto `qb`'s WHERE clause. Every predicate is an
/// explicit bind (guidelines §4 — never interpolate request data into SQL);
/// the only thing that varies textually between calls is which optional
/// clauses are present at all, and those are fixed strings this function
/// chooses, never request-supplied text.
fn push_filters<'a>(
    qb: &mut sqlx::QueryBuilder<'a, sqlx::Postgres>,
    p: &'a AuditFilterParams,
    date_to_ceiling: Option<DateTime<Utc>>,
) {
    if let Some(v) = &p.organization_ref {
        qb.push(" AND h.organization_ref = ").push_bind(*v);
    }
    if let Some(units) = &p.unit_scope {
        qb.push(" AND h.organization_ref = ANY(")
            .push_bind(units.as_slice())
            .push(")");
    }
    if let Some(v) = &p.entity_name {
        qb.push(" AND h.entity_name = ").push_bind(v.as_str());
    }
    if let Some(v) = &p.record_id {
        qb.push(" AND h.record_id = ").push_bind(*v);
    }
    if let Some(v) = &p.user_id {
        qb.push(" AND h.user_id = ").push_bind(*v);
    }
    if let Some(v) = &p.user_email {
        qb.push(" AND h.user_email ILIKE ").push_bind(v.as_str());
    }
    if let Some(v) = &p.operation {
        qb.push(" AND h.operation = ").push_bind(*v);
    }
    if let Some(v) = &p.date_from {
        qb.push(" AND h.created_at >= ").push_bind(*v);
    }
    match (&p.date_to, date_to_ceiling) {
        (Some(v), Some(ceiling)) => {
            qb.push(" AND h.created_at <= ")
                .push_bind((*v).min(ceiling));
        }
        (Some(v), None) => {
            qb.push(" AND h.created_at <= ").push_bind(*v);
        }
        (None, Some(ceiling)) => {
            qb.push(" AND h.created_at <= ").push_bind(ceiling);
        }
        (None, None) => {}
    }
    if let Some(v) = &p.field_name {
        qb.push(
            " AND EXISTS (SELECT 1 FROM audit_detail d \
                   WHERE d.audit_ref = h.id AND d.field_name = ",
        )
        .push_bind(v.as_str())
        .push(")");
    }
}

// ── search ───────────────────────────────────────────────────────────────────

#[derive(Deserialize, IntoParams, Debug)]
struct SearchQuery {
    entity_name: Option<String>,
    record_id: Option<Uuid>,
    user_id: Option<Uuid>,
    user_email: Option<String>,
    operation: Option<i32>,
    field_name: Option<String>,
    date_from: Option<DateTime<Utc>>,
    date_to: Option<DateTime<Utc>>,
    organization_ref: Option<Uuid>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

impl SearchQuery {
    fn filter(&self) -> AuditFilterParams {
        AuditFilterParams {
            entity_name: self.entity_name.clone(),
            record_id: self.record_id,
            user_id: self.user_id,
            user_email: self.user_email.clone(),
            operation: self.operation,
            field_name: self.field_name.clone(),
            date_from: self.date_from,
            date_to: self.date_to,
            organization_ref: self.organization_ref,
            unit_scope: None,
        }
    }
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
struct AuditSearchRow {
    id: Uuid,
    created_at: DateTime<Utc>,
    organization_ref: Uuid,
    category: i32,
    entity_name: Option<String>,
    record_id: Option<Uuid>,
    operation: i32,
    user_id: Uuid,
    user_name: String,
    user_email: String,
    changed_on: DateTime<Utc>,
    correlation_id: Option<Uuid>,
    event_name: Option<String>,
}

#[utoipa::path(
    get,
    operation_id = "audit_search",
    path = "/api/v1/admin/audit/search",
    tag = "admin-audit",
    params(SearchQuery),
    extensions(("x-audit" = json!(crate::security::x_audit(&[(crate::AuditCategory::Security, crate::AuditOperation::View)])))),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<AuditSearchRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn search(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(q): Query<SearchQuery>,
) -> Result<Json<PaginatedResponse<AuditSearchRow>>, AppError> {
    // Q17-T2: an administrator reads everything, a unit auditor their units.
    let scope = require_audit_reader(&state, &ctx).await?;
    let window = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    // D-541 rule 1: reading the audit trail is itself a mandatory `Security`
    // event. It is written before the read, and a failed write refuses the
    // read, so no search goes unrecorded.
    crate::security::SecurityAuditor::from_state(&state)
        .write(
            crate::security::SecurityEvent::new(
                crate::security::MandatoryCategory::Security,
                crate::AuditOperation::View,
                ctx.user_id,
                "audit_header",
                None,
            )
            .named("audit.search")
            .comment(format!(
                "page {}, page size {}",
                window.page, window.page_size
            )),
        )
        .await?;

    let pool = state.base.readonly_query_pool(ctx.user_id).await;
    let filter = q.filter().scoped(scope);

    let mut qb = sqlx::QueryBuilder::new(
        "SELECT h.id, h.created_at, h.organization_ref, h.category, h.entity_name, \
                h.record_id, h.operation, h.user_id, h.user_name, h.user_email, \
                h.changed_on, h.correlation_id, h.event_name \
         FROM audit_header h WHERE h.is_active = true",
    );
    push_filters(&mut qb, &filter, None);
    qb.push(" ORDER BY h.created_at DESC, h.id DESC LIMIT ")
        .push_bind(window.page_size)
        .push(" OFFSET ")
        .push_bind(window.offset);

    let items: Vec<AuditSearchRow> = qb
        .build_query_as()
        .fetch_all(pool)
        .await
        .map_err(AppError::internal)?;

    let mut count_qb =
        sqlx::QueryBuilder::new("SELECT COUNT(*) FROM audit_header h WHERE h.is_active = true");
    push_filters(&mut count_qb, &filter, None);
    let total: i64 = count_qb
        .build_query_scalar()
        .fetch_one(pool)
        .await
        .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

// ── export (SIEM / CSV, streamed) ───────────────────────────────────────────

#[derive(Deserialize, IntoParams, Debug)]
struct ExportQuery {
    entity_name: Option<String>,
    record_id: Option<Uuid>,
    user_id: Option<Uuid>,
    user_email: Option<String>,
    operation: Option<i32>,
    field_name: Option<String>,
    organization_ref: Option<Uuid>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    /// `jsonl` (default) | `cef` | `csv`.
    format: Option<String>,
}

impl ExportQuery {
    fn filter(&self) -> AuditFilterParams {
        AuditFilterParams {
            entity_name: self.entity_name.clone(),
            record_id: self.record_id,
            user_id: self.user_id,
            user_email: self.user_email.clone(),
            operation: self.operation,
            field_name: self.field_name.clone(),
            date_from: self.from,
            date_to: self.to,
            organization_ref: self.organization_ref,
            unit_scope: None,
        }
    }
}

/// One exported row's shape — a strict subset of `audit_header`'s
/// columns (the "header", per the task; field-level before/after detail is
/// what `/search` + the M12-style CSV button surface instead, not this
/// streamed export).
#[derive(sqlx::FromRow, Clone)]
struct ExportRow {
    id: Uuid,
    created_at: DateTime<Utc>,
    organization_ref: Uuid,
    category: i32,
    entity_name: Option<String>,
    record_id: Option<Uuid>,
    operation: i32,
    user_id: Uuid,
    user_name: String,
    user_email: String,
    changed_on: DateTime<Utc>,
    source: Option<i32>,
    ip_address: Option<String>,
    correlation_id: Option<Uuid>,
    batch_id: Option<Uuid>,
    event_name: Option<String>,
    event_hash: String,
    prev_hash: Option<String>,
    signing_key_id: Option<String>,
}

/// A local copy of `attome_report::render::csv_escape`, kept on purpose
/// (CLEANUP-REVIEW batch 2 follow-up 5): attome-report depends on attome-audit, so
/// importing it here would be a dependency cycle, and no base crate owns CSV.
/// Unlike that helper this one does not quote a field whose only special
/// character is a carriage return; the export format is left unchanged here.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

fn format_jsonl(row: &ExportRow) -> String {
    let v = serde_json::json!({
        "id": row.id,
        "created_at": row.created_at,
        "organization_ref": row.organization_ref,
        "category": row.category,
        "entity_name": row.entity_name,
        "record_id": row.record_id,
        "operation": row.operation,
        "user_id": row.user_id,
        "user_name": row.user_name,
        "user_email": row.user_email,
        "changed_on": row.changed_on,
        "source": row.source,
        "ip_address": row.ip_address,
        "correlation_id": row.correlation_id,
        "batch_id": row.batch_id,
        "event_name": row.event_name,
        "event_hash": row.event_hash,
        "prev_hash": row.prev_hash,
        "signing_key_id": row.signing_key_id,
    });
    format!("{v}\n")
}

/// RFC 5424-flavored Common Event Format (CEF:0), the wire shape most SIEMs
/// (ArcSight, Splunk's CEF input, Sentinel) parse without a custom
/// connector. Severity is fixed at 3 (low) — this endpoint carries fact-of-
/// change records, not alerts; a receiving SIEM's own correlation rules are
/// where severity judgment belongs.
fn format_cef(row: &ExportRow) -> String {
    let name = row
        .event_name
        .clone()
        .unwrap_or_else(|| format!("audit.operation.{}", row.operation));
    format!(
        "CEF:0|Attome|XRM|1|{op}|{name}|3|rt={rt} suid={uid} suser={email} \
         dvchost={entity} duid={record} cs1={hash} cs1Label=eventHash \
         cs2={prev} cs2Label=prevHash cs3={corr} cs3Label=correlationId\n",
        op = row.operation,
        name = name,
        rt = row.changed_on.timestamp_millis(),
        uid = row.user_id,
        email = row.user_email,
        entity = row.entity_name.as_deref().unwrap_or(""),
        record = row.record_id.map(|r| r.to_string()).unwrap_or_default(),
        hash = row.event_hash,
        prev = row.prev_hash.as_deref().unwrap_or(""),
        corr = row
            .correlation_id
            .map(|c| c.to_string())
            .unwrap_or_default(),
    )
}

fn format_csv_header() -> String {
    "id,created_at,organization_ref,category,entity_name,record_id,operation,user_id,\
     user_name,user_email,changed_on,source,ip_address,correlation_id,batch_id,\
     event_name,event_hash,prev_hash,signing_key_id\n"
        .to_owned()
}

fn format_csv_row(row: &ExportRow) -> String {
    format!(
        "{id},{created_at},{org},{cat},{entity},{record},{op},{uid},{uname},{email},{changed},\
         {source},{ip},{corr},{batch},{ename},{hash},{prev},{key}\n",
        id = row.id,
        created_at = row.created_at.to_rfc3339(),
        org = row.organization_ref,
        cat = row.category,
        entity = csv_escape(row.entity_name.as_deref().unwrap_or("")),
        record = row.record_id.map(|r| r.to_string()).unwrap_or_default(),
        op = row.operation,
        uid = row.user_id,
        uname = csv_escape(&row.user_name),
        email = csv_escape(&row.user_email),
        changed = row.changed_on.to_rfc3339(),
        source = row.source.map(|s| s.to_string()).unwrap_or_default(),
        ip = csv_escape(row.ip_address.as_deref().unwrap_or("")),
        corr = row
            .correlation_id
            .map(|c| c.to_string())
            .unwrap_or_default(),
        batch = row.batch_id.map(|b| b.to_string()).unwrap_or_default(),
        ename = csv_escape(row.event_name.as_deref().unwrap_or("")),
        hash = row.event_hash,
        prev = row.prev_hash.as_deref().unwrap_or(""),
        key = row.signing_key_id.as_deref().unwrap_or(""),
    )
}

#[utoipa::path(
    get,
    operation_id = "audit_export",
    path = "/api/v1/admin/audit/export",
    tag = "admin-audit",
    params(ExportQuery),
    extensions(("x-audit" = json!(crate::security::x_audit(&[(crate::AuditCategory::Security, crate::AuditOperation::Download)])))),
    responses(
        (status = 200, description = "Streamed export body (jsonl/cef/csv per `format`)"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn export(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(q): Query<ExportQuery>,
) -> Result<Response, AppError> {
    // Q17-T2: an administrator exports everything, a unit auditor their units.
    let scope = require_audit_reader(&state, &ctx).await?;
    let format = q.format.as_deref().unwrap_or("jsonl");
    let (content_type, header_line): (&str, Option<String>) = match format {
        "jsonl" => ("application/x-ndjson", None),
        "cef" => ("text/plain; charset=utf-8", None),
        "csv" => ("text/csv; charset=utf-8", Some(format_csv_header())),
        other => {
            return Err(AppError::Validation(format!(
                "format must be 'jsonl', 'cef', or 'csv' (got '{other}')"
            )));
        }
    };

    // D-541 rule 1: an audit export is a mandatory `Security` + `Download`
    // event, written (or the export refused) before the first byte streams.
    crate::security::SecurityAuditor::from_state(&state)
        .write(
            crate::security::SecurityEvent::new(
                crate::security::MandatoryCategory::Security,
                crate::AuditOperation::Download,
                ctx.user_id,
                "audit_header",
                None,
            )
            .named(format!("audit.export.{format}")),
        )
        .await?;

    let ceiling = Utc::now() - chrono::Duration::seconds(EXPORT_SAFETY_MARGIN_SECS);
    let pool = state.base.readonly_query_pool(ctx.user_id).await.clone();
    // Q17-T2: a unit auditor's export covers their units only, like search.
    let filter = q.filter().scoped(scope);

    struct CursorState {
        last_id: Option<Uuid>,
        exhausted: bool,
        wrote_header: bool,
    }

    let state0 = CursorState {
        last_id: None,
        exhausted: false,
        wrote_header: header_line.is_some(),
    };

    let stream = futures_util::stream::unfold(
        (
            state0,
            filter,
            pool,
            ceiling,
            header_line,
            format.to_owned(),
        ),
        move |(mut st, filter, pool, ceiling, header_line, format)| async move {
            if st.wrote_header {
                st.wrote_header = false;
                if let Some(h) = header_line.clone() {
                    return Some((
                        Ok::<_, std::io::Error>(bytes::Bytes::from(h)),
                        (st, filter, pool, ceiling, header_line, format),
                    ));
                }
            }
            if st.exhausted {
                return None;
            }

            let mut qb = sqlx::QueryBuilder::new(
                "SELECT h.id, h.created_at, h.organization_ref, h.category, h.entity_name, \
                        h.record_id, h.operation, h.user_id, h.user_name, h.user_email, \
                        h.changed_on, h.source, h.ip_address, h.correlation_id, h.batch_id, \
                        h.event_name, h.event_hash, h.prev_hash, h.signing_key_id \
                 FROM audit_header h WHERE h.is_active = true",
            );
            push_filters(&mut qb, &filter, Some(ceiling));
            if let Some(last) = st.last_id {
                qb.push(" AND h.id > ").push_bind(last);
            }
            qb.push(" ORDER BY h.id ASC LIMIT ")
                .push_bind(EXPORT_BATCH_SIZE);

            let rows: Vec<ExportRow> = match qb.build_query_as().fetch_all(&pool).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "audit export: batch read failed");
                    return Some((
                        Err(std::io::Error::other("audit export batch read failed")),
                        (
                            CursorState {
                                exhausted: true,
                                ..st
                            },
                            filter,
                            pool,
                            ceiling,
                            header_line,
                            format,
                        ),
                    ));
                }
            };

            if rows.is_empty() {
                return None;
            }

            st.last_id = rows.last().map(|r| r.id);
            if (rows.len() as i64) < EXPORT_BATCH_SIZE {
                st.exhausted = true;
            }

            let mut chunk = String::new();
            for row in &rows {
                match format.as_str() {
                    "cef" => chunk.push_str(&format_cef(row)),
                    "csv" => chunk.push_str(&format_csv_row(row)),
                    _ => chunk.push_str(&format_jsonl(row)),
                }
            }

            Some((
                Ok(bytes::Bytes::from(chunk)),
                (st, filter, pool, ceiling, header_line, format),
            ))
        },
    );

    let body = Body::from_stream(stream);
    let filename = format!(
        "audit-export-{}.{}",
        Utc::now().format("%Y%m%dT%H%M%SZ"),
        if format == "csv" { "csv" } else { format }
    );

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response())
}

// ── proofs and evidence packs (Q16-T3) ───────────────────────────────────────

/// An audit event's inclusion proof.
///
/// The Merkle path from the event's hash to its sealed batch's signed root,
/// with the signature, the signing key's public half and the anchor key, so
/// the event can be checked without the database (see `crate::proof`).
#[utoipa::path(
    get,
    operation_id = "audit_event_proof",
    path = "/api/v1/admin/audit/events/{id}/proof",
    tag = "admin-audit",
    params(("id" = Uuid, Path, description = "The audit event (audit_header) id")),
    responses(
        (status = 200, description = "The inclusion proof", body = crate::proof::InclusionProof),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such audit event", body = ErrorResponse),
        (status = 409, description = "The event is not sealed into a batch yet", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn event_proof(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::proof::InclusionProof>, AppError> {
    crate::proof::proof_for(&state.base.db, id).await.map(Json)
}

/// Builds an audit evidence pack.
///
/// Every sealed event in a time range or of one record (at most 2,000),
/// each with its inclusion proof, the public signing keys and the steps to
/// verify them offline. Building one is itself audited.
#[utoipa::path(
    post,
    operation_id = "audit_evidence_pack",
    path = "/api/v1/admin/audit/evidence-packs",
    tag = "admin-audit",
    request_body = crate::proof::EvidencePackRequest,
    extensions(("x-audit" = json!(crate::security::x_audit(&[(crate::AuditCategory::Security, crate::AuditOperation::Download)])))),
    responses(
        (status = 200, description = "The evidence pack", body = crate::proof::EvidencePack),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "No range or record, or more than 2,000 events", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn evidence_pack(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<crate::proof::EvidencePackRequest>,
) -> Result<Json<crate::proof::EvidencePack>, AppError> {
    // Like an export: the download is a mandatory event, written (or the
    // pack refused) before anything leaves.
    crate::security::SecurityAuditor::from_state(&state)
        .write(
            crate::security::SecurityEvent::new(
                crate::security::MandatoryCategory::Security,
                crate::AuditOperation::Download,
                ctx.user_id,
                "audit_header",
                None,
            )
            .named("audit.evidence_pack"),
        )
        .await?;
    crate::proof::evidence_pack(&state.base.db, &body)
        .await
        .map(Json)
}

// ── routes ───────────────────────────────────────────────────────────────────

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/audit/search", get(search))
        .route("/api/v1/admin/audit/export", get(export))
        .route("/api/v1/admin/audit/events/{id}/proof", get(event_proof))
        .route("/api/v1/admin/audit/evidence-packs", post(evidence_pack))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged upward via `attome_server::openapi::openapi_document`.
/// `export` is documented with no typed response body (its content type
/// varies by `format` and is streamed) — same convention `files.rs`'s
/// binary-download routes use.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(search, export, event_proof, evidence_pack),
    components(schemas(
        crate::proof::InclusionProof,
        crate::proof::ProofStep,
        crate::proof::ProofSide,
        crate::proof::EvidencePack,
        crate::proof::EvidencePackRequest,
        crate::proof::PackKey
    ))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auditor_scope_admin_unit_and_others() {
        let unit = Uuid::now_v7();
        assert_eq!(auditor_scope(true, false, vec![]).unwrap(), AuditScope::All);
        assert_eq!(
            auditor_scope(false, true, vec![unit]).unwrap(),
            AuditScope::Units(vec![unit])
        );
        assert!(matches!(
            auditor_scope(false, false, vec![unit]),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn auditor_scope_filters_by_unit() {
        let filter = AuditFilterParams::default().scoped(AuditScope::Units(vec![Uuid::nil()]));
        let mut qb = sqlx::QueryBuilder::new("SELECT 1 FROM audit_header h WHERE true");
        push_filters(&mut qb, &filter, None);
        assert!(
            qb.sql().contains("h.organization_ref = ANY("),
            "{}",
            qb.sql()
        );
        let all = AuditFilterParams::default().scoped(AuditScope::All);
        let mut qb = sqlx::QueryBuilder::new("SELECT 1 FROM audit_header h WHERE true");
        push_filters(&mut qb, &all, None);
        assert!(!qb.sql().contains("ANY("));
    }

    fn sample_row() -> ExportRow {
        ExportRow {
            id: Uuid::nil(),
            created_at: DateTime::parse_from_rfc3339("2026-08-28T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            organization_ref: Uuid::nil(),
            category: 0,
            entity_name: Some("service_ticket".to_owned()),
            record_id: Some(Uuid::nil()),
            operation: 1,
            user_id: Uuid::nil(),
            user_name: "Jane, \"Q\"".to_owned(),
            user_email: "jane@example.test".to_owned(),
            changed_on: DateTime::parse_from_rfc3339("2026-08-28T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            source: Some(1),
            ip_address: None,
            correlation_id: None,
            batch_id: None,
            event_name: None,
            event_hash: "deadbeef".to_owned(),
            prev_hash: Some("cafebabe".to_owned()),
            signing_key_id: Some("key-1".to_owned()),
        }
    }

    #[test]
    fn csv_escape_quotes_fields_that_need_it() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_escape("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn csv_row_escapes_a_comma_and_quote_bearing_user_name() {
        let line = format_csv_row(&sample_row());
        assert!(line.starts_with(&format!("{},", Uuid::nil())));
        assert!(line.contains("\"Jane, \"\"Q\"\"\""));
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn jsonl_row_is_one_valid_json_object_per_line() {
        let line = format_jsonl(&sample_row());
        assert!(line.ends_with('\n'));
        let parsed: serde_json::Value =
            serde_json::from_str(line.trim_end()).expect("format_jsonl must emit valid JSON");
        assert_eq!(parsed["entity_name"], "service_ticket");
        assert_eq!(parsed["event_hash"], "deadbeef");
    }

    #[test]
    fn cef_row_carries_the_hash_chain_fields_as_custom_strings() {
        let line = format_cef(&sample_row());
        assert!(line.starts_with("CEF:0|Attome|XRM|1|1|"));
        assert!(line.contains("cs1=deadbeef cs1Label=eventHash"));
        assert!(line.contains("cs2=cafebabe cs2Label=prevHash"));
        assert!(line.ends_with('\n'));
    }
}
