//! Solution 7 Phase 2 (D-788 Topic 14, D-791; `SOLUTION-7-PHASE-2-DESIGN.md`
//! §9.3, §10.4) — the release report's admin routes.
//!
//! | Method | Path | |
//! |---|---|---|
//! | GET | `/api/v1/admin/metadata/release-reports` | reports, newest first |
//! | GET | `/api/v1/admin/metadata/release-reports/summary` | open items by kind (the fleet view reads it) |
//! | GET | `/api/v1/admin/metadata/release-reports/{report_id}` | one report with counts |
//! | GET | `/api/v1/admin/metadata/release-reports/{report_id}/items` | its items; conflict values decrypted (audited) |
//! | POST | `/api/v1/admin/metadata/release-report-items/{item_id}/accept` | conflict: keep the customer's value |
//! | POST | `/api/v1/admin/metadata/release-report-items/{item_id}/use-mine` | conflict: write ours now |
//! | POST | `/api/v1/admin/metadata/release-report-items/{item_id}/dismiss` | any open/info item |
//! | POST | `/api/v1/admin/metadata/release-report-items/{item_id}/restore` | archive-backed item: restore its values |
//!
//! `Authorized<Privilege<MetadataRollout>>` (`system.admin`, or the fleet
//! console's rollout credential `metadata.rollout`, D-792: we decide
//! conflicts, owner Topic 9/17), under `/api/v1/admin/metadata/…`, the
//! prefix the production authoring gate admits (a customer admin, or our
//! console, works the report on a customer server). The rollout principal
//! decides through its own security context: the field gate still hides a
//! sensitive field's values from it (and Use mine on one is refused by the
//! engine's field-write gate) unless a field-security profile grants it. Lists are one-based (`OnePageQuery`,
//! D-731). No deadline (Topic 14, Topic 15 #4): nothing here gates an apply.
//!
//! **Decisions** (design §9.3). Accept, Use mine and Dismiss take
//! `If-Match: "<item row_version>"` (missing or malformed: 422; stale: 409
//! `version_conflict`; already decided: 409 `report_item_decided`) and write
//! their `Configuration`/`Update` security event in the decision's own
//! transaction (D-542).
//!
//! - **Use mine on a record conflict** writes our value through the generic
//!   engine's update (`entity_mutation::update_one`, the deciding admin's
//!   security context: validation, business rules and the record's audit
//!   apply like any edit), compare-first on the record's `row_version` the
//!   caller read (`record_row_version` in the body; 409 when the record
//!   changed since), in the same transaction as the item's `used_mine` and
//!   the baseline's stored form. On a deployment in `auto` mode the write is
//!   an ordinary customer edit; the item is the durable record of the choice.
//! - **Use mine on a rule conflict** replays our definition
//!   (`rule_admin::force_rule`, or `force_retire_rule` for a retire), then
//!   marks the item; the rule write commits first (it refreshes the rule
//!   cache after its own commit, and no transaction is held across that).
//! - **Restore** restores every unrestored, unexpired archived value linked
//!   to the item through the recovery archive's own restore (fills empty
//!   targets only, each value its own transaction and `Configuration` event);
//!   the item becomes `restored` when none is left. Not `If-Match`-guarded:
//!   restored values are skipped, so a retry is harmless.
//!
//! **Values** are decrypted only for a conflict item and only when the
//! caller may read the field (the interactive field gate, as a record read:
//! D-111); otherwise `values_hidden` is set. A read that returned values
//! writes one `Security`/`Export` event (ids and counts, never values), in
//! the read's own transaction, for every reader — the rollout principal's
//! reads included (its comment names the principal kind).

use std::collections::BTreeMap;

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::release_report::{
    self as rr, ITEM_COLUMNS, ItemKind, ItemStatus, REPORT_COLUMNS, ReleaseReport, ReportItem,
};
use attome_core::{EngineState, recovery_archive};
use attome_security::MetadataRollout;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, header::IF_MATCH},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::audit_service;
use super::recovery_archive::{RestoreCounts, restore_row, tally};

/// Most archived values one item Restore request writes.
const MAX_ITEM_RESTORE: i64 = 10_000;

/// Stable refusal: the item's values are not stored (no key ring when it
/// was written).
const VALUES_MISSING: &str = "report_values_missing: this conflict was stored without its values \
     (no recovery-archive key ring was configured); Use mine is unavailable";

/// Stable refusal: the action does not apply to this item's kind.
const WRONG_KIND: &str =
    "report_item_kind: this action does not apply to this kind of release-report item";

/// Stable refusal: the field a record conflict names no longer exists.
const FIELD_MISSING: &str =
    "record_field_missing: the field this conflict names no longer exists on the entity";

// ── Wire types ──────────────────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(super) struct ReportFilter {
    /// `building | ready`.
    status: Option<String>,
    /// `boot | admin | replay | change`.
    source: Option<String>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(super) struct ItemFilter {
    /// An item kind (`conflict`, `field_deleted`, ...).
    kind: Option<String>,
    /// An item status (`open`, `info`, `accepted`, ...).
    status: Option<String>,
    /// Entity logical name.
    entity: Option<String>,
}

/// What the fleet view reads (design §10.5).
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct ReleaseReportSummary {
    /// Open items across every report.
    open_items: i64,
    /// Open items by kind.
    by_kind: BTreeMap<String, i64>,
    /// When the newest report became ready.
    last_release_at: Option<DateTime<Utc>>,
    /// Reports still building (an apply running or stopped mid-run).
    building: i64,
}

/// One item, with a conflict's values when the caller may read them.
#[derive(Serialize, ToSchema)]
pub(super) struct ReportItemView {
    #[serde(flatten)]
    item: ReportItem,
    /// A conflict's `{theirs, ours, key}` (the customer's value, kept; ours;
    /// the record's business key).
    #[schema(value_type = Option<Object>)]
    values: Option<Value>,
    /// The values exist but the caller may not read the field.
    values_hidden: bool,
}

/// `POST .../use-mine`.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(super) struct UseMineBody {
    /// The record's `row_version` the caller saw (record conflicts; the write
    /// is refused with 409 when the record changed since).
    #[serde(default)]
    record_row_version: Option<i64>,
}

/// What an item Restore did.
#[derive(Serialize, ToSchema)]
pub(super) struct ItemRestoreResult {
    restore: RestoreCounts,
    /// Linked values still unrestored (repeat the request when above 0).
    remaining: i64,
    item: ReportItem,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// `If-Match: "<row_version>"` → the item's expected `row_version` (required).
fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers.get(IF_MATCH).ok_or_else(|| {
        AppError::Validation(
            "If-Match: \"<row_version>\" is required to decide a release-report item".into(),
        )
    })?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

fn parse_or_422<T>(
    value: Option<&str>,
    parse: fn(&str) -> Option<T>,
    what: &str,
) -> Result<(), AppError> {
    match value {
        Some(v) if parse(v).is_none() => Err(AppError::Validation(format!("unknown {what}: {v}"))),
        _ => Ok(()),
    }
}

/// The checks every decision makes on a locked item: open (or, for
/// Dismiss, info), the expected version, the kind (`kinds` empty: any).
fn check_decidable(
    item: &ReportItem,
    expected: i64,
    from: &[ItemStatus],
    kinds: &[ItemKind],
) -> Result<ItemKind, AppError> {
    let kind = ItemKind::parse(&item.kind).ok_or_else(|| {
        AppError::internal(format!(
            "release-report item {} has an unknown kind",
            item.id
        ))
    })?;
    if !kinds.is_empty() && !kinds.contains(&kind) {
        return Err(AppError::Conflict(WRONG_KIND));
    }
    let status = ItemStatus::parse(&item.status);
    if !status.is_some_and(|s| from.contains(&s)) {
        return Err(AppError::Conflict(rr::REPORT_ITEM_DECIDED));
    }
    if item.row_version != expected {
        return Err(AppError::VersionConflict);
    }
    Ok(kind)
}

fn decision_event(
    actor: Uuid,
    item_id: Uuid,
    name: &'static str,
    comment: String,
) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Update,
        actor,
        "release_report_item",
        Some(item_id),
    )
    .named(name)
    .comment(comment)
}

/// Who read conflict values, for the read's audit comment: an administrator
/// or the fleet console's rollout credential (D-792).
fn reader_kind(ctx: &attome_server::security::SecurityContext) -> &'static str {
    if ctx.is_admin {
        "an administrator"
    } else {
        "the rollout credential (metadata.rollout)"
    }
}

/// The item as it is now (the decision's response).
async fn read_item(state: &EngineState, item_id: Uuid) -> Result<ReportItem, AppError> {
    sqlx::query_as::<_, ReportItem>(&format!(
        "SELECT {ITEM_COLUMNS} FROM release_report_item WHERE id = $1"
    ))
    .bind(item_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Whether the field a record conflict names is sensitive now (unknown
/// field: not sensitive; the value was recorded from a non-sensitive one).
fn field_is_sensitive(state: &EngineState, entity: &str, field: &str) -> bool {
    state.entities.load().get(entity).is_some_and(|m| {
        m.attrs
            .iter()
            .any(|a| a.logicalname == field && a.is_sensitive)
    })
}

// ── Reads ───────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/release-reports",
    tag = "admin",
    params(ReportFilter, OnePageQuery),
    responses(
        (status = 200, description = "Release reports, newest first", body = PaginatedResponse<ReleaseReport>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 422, description = "Unknown status or source", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_reports(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<MetadataRollout>>,
    Query(filter): Query<ReportFilter>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ReleaseReport>>, AppError> {
    if let Some(s) = filter.status.as_deref()
        && !matches!(s, "building" | "ready")
    {
        return Err(AppError::Validation(format!("unknown status: {s}")));
    }
    parse_or_422(filter.source.as_deref(), rr::ReportSource::parse, "source")?;
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let predicate = "($1::text IS NULL OR status = $1) AND ($2::text IS NULL OR source = $2)";
    let rows: Vec<ReleaseReport> = sqlx::query_as(&format!(
        "SELECT {REPORT_COLUMNS} FROM release_report WHERE {predicate} \
         ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4"
    ))
    .bind(&filter.status)
    .bind(&filter.source)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM release_report WHERE {predicate}"
    ))
    .bind(&filter.status)
    .bind(&filter.source)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(rows, total, page, page_size)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/release-reports/summary",
    tag = "admin",
    responses(
        (status = 200, description = "Open items by kind and the last release", body = ReleaseReportSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn report_summary(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<MetadataRollout>>,
) -> Result<Json<ReleaseReportSummary>, AppError> {
    let by_kind: Vec<(String, i64)> = sqlx::query_as(
        "SELECT kind, COUNT(*) FROM release_report_item \
         WHERE status = 'open' GROUP BY kind ORDER BY kind",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (last_release_at, building): (Option<DateTime<Utc>>, i64) = sqlx::query_as(
        "SELECT MAX(ready_at), COUNT(*) FILTER (WHERE status = 'building') \
         FROM release_report WHERE source <> 'change'",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(ReleaseReportSummary {
        open_items: by_kind.iter().map(|(_, n)| n).sum(),
        by_kind: by_kind.into_iter().collect(),
        last_release_at,
        building,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/release-reports/{report_id}",
    operation_id = "get_release_report",
    tag = "admin",
    params(("report_id" = Uuid, Path)),
    responses(
        (status = 200, description = "The report with its counts", body = ReleaseReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 404, description = "No such report", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_report(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<MetadataRollout>>,
    Path(report_id): Path<Uuid>,
) -> Result<Json<ReleaseReport>, AppError> {
    let report: Option<ReleaseReport> = sqlx::query_as(&format!(
        "SELECT {REPORT_COLUMNS} FROM release_report WHERE id = $1"
    ))
    .bind(report_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    report.map(Json).ok_or(AppError::NotFound)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/release-reports/{report_id}/items",
    tag = "admin",
    params(("report_id" = Uuid, Path), ItemFilter, OnePageQuery),
    responses(
        (status = 200, description = "The report's items, oldest first; conflict values decrypted for a caller who may read the field", body = PaginatedResponse<ReportItemView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 404, description = "No such report", body = ErrorResponse),
        (status = 409, description = "report_values_unreadable", body = ErrorResponse),
        (status = 422, description = "Unknown kind or status", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_items(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetadataRollout>>,
    Path(report_id): Path<Uuid>,
    Query(filter): Query<ItemFilter>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ReportItemView>>, AppError> {
    parse_or_422(filter.kind.as_deref(), ItemKind::parse, "kind")?;
    parse_or_422(filter.status.as_deref(), ItemStatus::parse, "status")?;
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM release_report WHERE id = $1)")
            .bind(report_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    #[derive(sqlx::FromRow)]
    struct Row {
        #[sqlx(flatten)]
        item: ReportItem,
        values_enc: Option<Vec<u8>>,
    }
    let predicate = "report_ref = $1 AND ($2::text IS NULL OR kind = $2) \
         AND ($3::text IS NULL OR status = $3) AND ($4::text IS NULL OR entity_logicalname = $4)";
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {ITEM_COLUMNS}, values_enc FROM release_report_item WHERE {predicate} \
         ORDER BY created_at, id LIMIT $5 OFFSET $6"
    ))
    .bind(report_id)
    .bind(&filter.kind)
    .bind(&filter.status)
    .bind(&filter.entity)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM release_report_item WHERE {predicate}"
    ))
    .bind(report_id)
    .bind(&filter.kind)
    .bind(&filter.status)
    .bind(&filter.entity)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let ring = recovery_archive::ring(state.base.config.as_ref());
    let mut opened = 0usize;
    let mut items = Vec::with_capacity(rows.len());
    for Row { item, values_enc } in rows {
        let (values, values_hidden) = match (values_enc, ring) {
            (Some(enc), Some(ring)) => {
                let readable = match item.field_logicalname.as_deref() {
                    Some(field) => attome_security::field_gate::field_readable(
                        &ctx,
                        &item.entity_logicalname,
                        field,
                        field_is_sensitive(&state, &item.entity_logicalname, field),
                        None,
                        attome_security::field_gate::Surface::Interactive,
                    ),
                    None => true,
                };
                if readable {
                    let values = rr::open_values(ring, item.id, &enc)?;
                    opened += 1;
                    (
                        Some(serde_json::to_value(values).map_err(AppError::internal)?),
                        false,
                    )
                } else {
                    (None, true)
                }
            }
            // Stored but no ring now: the values cannot be shown.
            (Some(_), None) => (None, true),
            (None, _) => (None, false),
        };
        items.push(ReportItemView {
            item,
            values,
            values_hidden,
        });
    }
    if opened > 0 {
        write_security_event(
            &mut tx,
            &audit_service(&state),
            SecurityEvent::new(
                MandatoryCategory::Security,
                AuditOperation::Export,
                ctx.user_id,
                "release_report_item",
                None,
            )
            .named("release_report.values_read")
            .comment(format!(
                "release-report conflict values read by {}: report {report_id}, {opened} item(s)",
                reader_kind(&ctx)
            )),
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

// ── Decisions ───────────────────────────────────────────────────────────────

/// Accept (keep the customer's value): nothing is written but the decision;
/// the baseline already holds ours, so the next release does not raise it
/// again unless we change the field again.
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/release-report-items/{item_id}/accept",
    tag = "admin",
    params(("item_id" = Uuid, Path), ("If-Match" = String, Header, description = "The item's row_version, quoted")),
    responses(
        (status = 200, description = "Accepted", body = ReportItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 404, description = "No such item", body = ErrorResponse),
        (status = 409, description = "version_conflict, report_item_decided, or not a conflict item", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
pub(super) async fn accept_item(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetadataRollout>>,
    Path(item_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ReportItem>, AppError> {
    let expected = if_match(&headers)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (item, _) = rr::lock_item(&mut tx, item_id)
        .await?
        .ok_or(AppError::NotFound)?;
    check_decidable(&item, expected, &[ItemStatus::Open], &[ItemKind::Conflict])?;
    if !rr::set_status(
        &mut tx,
        item_id,
        &[ItemStatus::Open],
        ItemStatus::Accepted,
        Some(expected),
        Some(ctx.user_id),
    )
    .await?
    {
        return Err(AppError::VersionConflict);
    }
    write_security_event(
        &mut tx,
        &audit_service(&state),
        decision_event(
            ctx.user_id,
            item_id,
            "release_report.accept",
            format!(
                "release-report conflict accepted (customer value kept): {} {}",
                item.entity_logicalname,
                item.field_logicalname.as_deref().unwrap_or("-")
            ),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(read_item(&state, item_id).await?))
}

/// Dismiss: an item the admin has seen (any kind; open or info).
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/release-report-items/{item_id}/dismiss",
    tag = "admin",
    params(("item_id" = Uuid, Path), ("If-Match" = String, Header, description = "The item's row_version, quoted")),
    responses(
        (status = 200, description = "Dismissed", body = ReportItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 404, description = "No such item", body = ErrorResponse),
        (status = 409, description = "version_conflict or report_item_decided", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
pub(super) async fn dismiss_item(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetadataRollout>>,
    Path(item_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<ReportItem>, AppError> {
    let expected = if_match(&headers)?;
    let from = [ItemStatus::Open, ItemStatus::Info];
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (item, _) = rr::lock_item(&mut tx, item_id)
        .await?
        .ok_or(AppError::NotFound)?;
    check_decidable(&item, expected, &from, &[])?;
    if !rr::set_status(
        &mut tx,
        item_id,
        &from,
        ItemStatus::Dismissed,
        Some(expected),
        Some(ctx.user_id),
    )
    .await?
    {
        return Err(AppError::VersionConflict);
    }
    write_security_event(
        &mut tx,
        &audit_service(&state),
        decision_event(
            ctx.user_id,
            item_id,
            "release_report.dismiss",
            format!(
                "release-report item dismissed: {} {}",
                item.kind, item.entity_logicalname
            ),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(read_item(&state, item_id).await?))
}

/// Use mine: our value is written now (record: in the decision's
/// transaction; rule: our definition replayed, then the decision).
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/release-report-items/{item_id}/use-mine",
    tag = "admin",
    params(("item_id" = Uuid, Path), ("If-Match" = String, Header, description = "The item's row_version, quoted")),
    request_body = UseMineBody,
    responses(
        (status = 200, description = "Our value written; the item is used_mine", body = ReportItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 404, description = "No such item, or the record no longer exists", body = ErrorResponse),
        (status = 409, description = "version_conflict (item or record), report_item_decided, archive_key_missing, report_values_missing, record_field_missing, or not a conflict item", body = ErrorResponse),
        (status = 422, description = "If-Match or record_row_version missing or malformed, or our value fails validation now", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
pub(super) async fn use_mine_item(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetadataRollout>>,
    Path(item_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<UseMineBody>,
) -> Result<Json<ReportItem>, AppError> {
    let expected = if_match(&headers)?;
    let ring = recovery_archive::ring(state.base.config.as_ref())
        .ok_or(AppError::Conflict(recovery_archive::ARCHIVE_KEY_MISSING))?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (item, values_enc) = rr::lock_item(&mut tx, item_id)
        .await?
        .ok_or(AppError::NotFound)?;
    check_decidable(&item, expected, &[ItemStatus::Open], &[ItemKind::Conflict])?;
    let values_enc = values_enc.ok_or(AppError::Conflict(VALUES_MISSING))?;
    let values = rr::open_values(ring, item.id, &values_enc)?;

    match (item.record_id, item.field_logicalname.as_deref()) {
        (Some(record_id), Some(field)) => {
            // A record conflict: our value, in this transaction.
            let record_row_version = body.record_row_version.ok_or_else(|| {
                AppError::Validation(
                    "record_row_version (the record's row_version you saw) is required".into(),
                )
            })?;
            let entity = item.entity_logicalname.clone();
            let attrs = state
                .entities
                .load()
                .get(&entity)
                .map(|m| m.attrs.clone())
                .ok_or(AppError::Conflict(FIELD_MISSING))?;
            if !attrs.iter().any(|a| a.logicalname == field) {
                return Err(AppError::Conflict(FIELD_MISSING));
            }
            let entity_id: Uuid = sqlx::query_scalar(
                "SELECT id FROM entity_info \
                 WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
            )
            .bind(&entity)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::Conflict(FIELD_MISSING))?;
            let mut obj = serde_json::Map::new();
            obj.insert(field.to_owned(), values.ours.clone());
            let written = attome_records::entity_mutation::update_one(
                &mut tx,
                &state,
                &ctx,
                &entity,
                entity_id,
                record_id,
                &attrs,
                &obj,
                ctx.user_id,
                record_row_version,
                attome_records::entity_mutation::MutationMode::Strict,
            )
            .await?;
            if let Some(stored) = written.new_row.as_ref().and_then(|r| r.get(field)) {
                let stored_hash = crate::bundle::record_sets::value_hash(stored)?;
                rr::set_live_hash(&mut tx, &entity, record_id, field, &stored_hash).await?;
            }
            if !rr::set_status(
                &mut tx,
                item_id,
                &[ItemStatus::Open],
                ItemStatus::UsedMine,
                Some(expected),
                Some(ctx.user_id),
            )
            .await?
            {
                return Err(AppError::VersionConflict);
            }
            write_security_event(
                &mut tx,
                &audit_service(&state),
                decision_event(
                    ctx.user_id,
                    item_id,
                    "release_report.use_mine",
                    format!(
                        "release-report conflict: our value written to {entity}.{field} \
                         record {record_id}"
                    ),
                ),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
        }
        _ if item.object_kind.as_deref() == Some(crate::rule_admin::RULE_OBJECT_KIND) => {
            // A rule conflict: the rule write commits on its own (it
            // refreshes the rule cache after its commit; no transaction is
            // held across that), then the decision.
            drop(tx);
            let is_retire = values.ours.get("retire").and_then(Value::as_bool) == Some(true);
            if is_retire {
                let entity = values
                    .ours
                    .get("entity")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let rule = values
                    .ours
                    .get("rule")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                crate::rule_admin::force_retire_rule(&state, entity, rule).await?;
            } else {
                let def: crate::bundle::model::RuleDef = serde_json::from_value(values.ours)
                    .map_err(|_| AppError::Conflict(rr::REPORT_VALUES_UNREADABLE))?;
                crate::rule_admin::force_rule(&state, &def).await?;
            }
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let moved = rr::set_status(
                &mut tx,
                item_id,
                &[ItemStatus::Open],
                ItemStatus::UsedMine,
                Some(expected),
                Some(ctx.user_id),
            )
            .await?;
            if !moved {
                // Decided concurrently after our checks: our definition is
                // written either way (the admin asked for it); say so.
                tracing::warn!(%item_id,
                    "release report: Use mine wrote our rule, but the item was decided concurrently");
            }
            write_security_event(
                &mut tx,
                &audit_service(&state),
                decision_event(
                    ctx.user_id,
                    item_id,
                    "release_report.use_mine",
                    format!(
                        "release-report conflict: our rule definition written ({} {})",
                        item.entity_logicalname,
                        item.object_ref.map(|r| r.to_string()).unwrap_or_default()
                    ),
                ),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
        }
        _ => return Err(AppError::Conflict(WRONG_KIND)),
    }
    Ok(Json(read_item(&state, item_id).await?))
}

/// Restore: every unrestored, unexpired archived value of an archive-backed
/// item, through the recovery archive's restore (fills empty targets only).
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/release-report-items/{item_id}/restore",
    tag = "admin",
    params(("item_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Counts; `remaining > 0` means repeat the request", body = ItemRestoreResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 404, description = "No such item", body = ErrorResponse),
        (status = 409, description = "Not an archive-backed item, report_item_decided, restore_target_missing, archive_key_missing", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
pub(super) async fn restore_item(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetadataRollout>>,
    Path(item_id): Path<Uuid>,
) -> Result<Json<ItemRestoreResult>, AppError> {
    recovery_archive::ring(state.base.config.as_ref())
        .ok_or(AppError::Conflict(recovery_archive::ARCHIVE_KEY_MISSING))?;
    let item = read_item(&state, item_id).await?;
    let kind = ItemKind::parse(&item.kind).filter(|k| k.archive_backed());
    let Some(kind) = kind else {
        return Err(AppError::Conflict(WRONG_KIND));
    };
    if item.status != ItemStatus::Open.as_str() {
        return Err(AppError::Conflict(rr::REPORT_ITEM_DECIDED));
    }
    // A large run archives after the item was written: link those rows now.
    if let Some(field) = item.field_logicalname.as_deref() {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let op = item.changeset_id.zip(item.op_seq);
        rr::link_archive_rows(
            &mut tx,
            item_id,
            kind,
            &item.entity_logicalname,
            field,
            op,
            Some(item.created_at),
        )
        .await?;
        attome_db::tx::commit(tx).await?;
    }
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM recovery_archive \
         WHERE report_item_ref = $1 AND restored_at IS NULL AND expires_at > now() \
         ORDER BY id LIMIT $2",
    )
    .bind(item_id)
    .bind(MAX_ITEM_RESTORE)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut counts = RestoreCounts::default();
    for id in &ids {
        // Each value: its own transaction and Configuration event; the item
        // becomes `restored` with its last value.
        let one = restore_row(&state, &ctx, ctx.user_id, *id).await?;
        tally(&mut counts, one);
    }
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_archive \
         WHERE report_item_ref = $1 AND restored_at IS NULL AND expires_at > now()",
    )
    .bind(item_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    tracing::info!(%item_id, values = ids.len(), remaining,
        "release report: item restore request done (each value audited in its own restore)");
    Ok(Json(ItemRestoreResult {
        restore: counts,
        remaining,
        item: read_item(&state, item_id).await?,
    }))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/metadata/release-reports", get(list_reports))
        .route(
            "/api/v1/admin/metadata/release-reports/summary",
            get(report_summary),
        )
        .route(
            "/api/v1/admin/metadata/release-reports/{report_id}",
            get(get_report),
        )
        .route(
            "/api/v1/admin/metadata/release-reports/{report_id}/items",
            get(list_items),
        )
        .route(
            "/api/v1/admin/metadata/release-report-items/{item_id}/accept",
            post(accept_item),
        )
        .route(
            "/api/v1/admin/metadata/release-report-items/{item_id}/use-mine",
            post(use_mine_item),
        )
        .route(
            "/api/v1/admin/metadata/release-report-items/{item_id}/dismiss",
            post(dismiss_item),
        )
        .route(
            "/api/v1/admin/metadata/release-report-items/{item_id}/restore",
            post(restore_item),
        )
}

/// This file's slice of the OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_reports,
    report_summary,
    get_report,
    list_items,
    accept_item,
    use_mine_item,
    dismiss_item,
    restore_item
))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn item(kind: &str, status: &str, row_version: i64) -> ReportItem {
        ReportItem {
            id: Uuid::now_v7(),
            report_ref: Uuid::now_v7(),
            kind: kind.into(),
            actionable: true,
            status: status.into(),
            entity_logicalname: "country".into(),
            field_logicalname: Some("name".into()),
            record_id: Some(Uuid::now_v7()),
            object_kind: None,
            object_ref: None,
            detail: serde_json::json!({}),
            has_values: true,
            changeset_id: None,
            op_seq: None,
            decided_by: None,
            decided_at: None,
            superseded_by: None,
            created_at: Utc::now(),
            row_version,
        }
    }

    #[test]
    fn if_match_is_required_and_parsed() {
        let mut headers = HeaderMap::new();
        assert!(matches!(if_match(&headers), Err(AppError::Validation(_))));
        headers.insert(IF_MATCH, HeaderValue::from_static("\"4\""));
        assert_eq!(if_match(&headers).expect("parsed"), 4);
        headers.insert(IF_MATCH, HeaderValue::from_static("four"));
        assert!(matches!(if_match(&headers), Err(AppError::Validation(_))));
    }

    #[test]
    fn a_decision_checks_status_version_and_kind() {
        let open = item("conflict", "open", 2);
        assert_eq!(
            check_decidable(&open, 2, &[ItemStatus::Open], &[ItemKind::Conflict])
                .expect("decidable"),
            ItemKind::Conflict
        );
        assert!(matches!(
            check_decidable(&open, 1, &[ItemStatus::Open], &[]),
            Err(AppError::VersionConflict)
        ));
        let decided = item("conflict", "accepted", 3);
        assert!(matches!(
            check_decidable(&decided, 3, &[ItemStatus::Open], &[]),
            Err(AppError::Conflict(rr::REPORT_ITEM_DECIDED))
        ));
        let info = item("breaking_api_change", "info", 0);
        assert!(matches!(
            check_decidable(&info, 0, &[ItemStatus::Open], &[ItemKind::Conflict]),
            Err(AppError::Conflict(WRONG_KIND))
        ));
        assert!(check_decidable(&info, 0, &[ItemStatus::Open, ItemStatus::Info], &[]).is_ok());
    }

    #[test]
    fn unknown_filters_are_refused() {
        assert!(parse_or_422(Some("conflict"), ItemKind::parse, "kind").is_ok());
        assert!(parse_or_422(None, ItemKind::parse, "kind").is_ok());
        assert!(matches!(
            parse_or_422(Some("nope"), ItemStatus::parse, "status"),
            Err(AppError::Validation(_))
        ));
    }
}
