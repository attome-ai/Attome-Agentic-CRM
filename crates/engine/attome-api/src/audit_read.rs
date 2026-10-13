//! audit-10-10 Phase 6 items 6.1-6.3 — the caller's own activity feed over the
//! audit ledger. Per-record history is NOT here: it is the single
//! `GET /api/v1/{entity}/{id}/history` in `attome-records`'s
//! `entity_crud/history.rs` (R-2: one record-history API, not two).
//!
//! **Scope.** This file builds the read surface and its authorization only.
//! It deliberately does NOT decrypt values (`attome_audit::decrypt_field` gets
//! its first production caller in Phase 6.4) and does NOT define
//! `audit.view_sensitive` (Phase 6.6) — every `Restricted`-mode field reads
//! as hidden by default until that permission exists. Phase 6.4/6.5/6.6/6.7
//! (decryption, audited decryption, dedicated permissions, Angular UI) are
//! out of scope here.
//!
//! **Existence vs values are separate decisions** (the principle earlier
//! phases established for My Activity): Record History hard-gates on
//! `require_record_access` (D-147/D-133) — a caller who cannot currently
//! read the record gets `NotFound`, matching the rest of this codebase's
//! record-level-security convention (`entity_crud::access`'s doc comment on
//! why a narrowed grant reads as "doesn't exist," not `Forbidden`). My
//! Activity always lists the caller's own events regardless of current
//! record access, but every entry whose referenced record the caller can no
//! longer read shows the action/entity/record id with every value
//! `Restricted` — checked per row via the same `require_record_access`,
//! never assumed from the write-time relationship.
//!
//! **Field-level value authorization (I7, 6.3).** Within a readable record,
//! an individual field's value is additionally gated by
//! `SecurityContextExt::has_field_read_grant` — record-level and field-level
//! access are independent checks, matching `query_exec.rs`'s existing
//! `is_sensitive && !ctx.has_field_read_grant(..)` posture. Erased values
//! (`attome_audit::ERASED_MARKER`) are surfaced as their own explicit state
//! rather than silently treated as an ordinary value.
//!
//! **Pool.** Both handlers use `state.base.readonly_query_pool(...)`, the
//! least-privileged pool `attome_audit::admin`'s search/export handlers and
//! `query_exec.rs`'s stored-query path already use.

use attome_audit::ERASED_MARKER;
use attome_core::EngineState;
use attome_records::entity_crud::{require_record_access, resolve_entity};
use attome_security::RecordAction;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{
    AppError, DEFAULT_PAGE_SIZE, ErrorResponse, PageBase, PageWindow, PaginatedResponse,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Mirrors `attome_audit::value_mode::ValueMode`'s stored discriminants (that
/// enum is private to the write path's crate-internal classification; this
/// read path only needs to distinguish the two it can ever actually see —
/// `NotCaptured` fields never produce a detail row at all, so a row here is
/// always `Encrypted` or `Restricted`, or NULL for a pre-Phase-5 legacy row).
const VALUE_MODE_RESTRICTED: i16 = 1;

// ── response shapes ─────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
enum FieldValueView {
    /// The viewer is authorized to see this value, but this API does not
    /// decrypt it yet — see this module's doc comment.
    Encrypted,
    /// Hidden: the viewer cannot currently read this field (I7), the whole
    /// record's access has been revoked, or the value is `Restricted`-mode
    /// and `audit.view_sensitive` does not exist yet (Phase 6.6).
    Restricted,
    /// Erased via a DSR/retention erasure pass.
    Erased { value: String },
}

#[derive(Serialize, ToSchema)]
struct FieldChangeView {
    field_name: String,
    #[serde(flatten)]
    value: FieldValueView,
}

#[derive(Serialize, ToSchema)]
struct HistoryEntry {
    id: Uuid,
    changed_on: DateTime<Utc>,
    category: i32,
    entity_name: Option<String>,
    record_id: Option<Uuid>,
    operation: i32,
    user_id: Uuid,
    user_name: String,
    user_email: String,
    source: i32,
    outcome: Option<i32>,
    correlation_id: Option<Uuid>,
    event_name: Option<String>,
    changes: Vec<FieldChangeView>,
}

#[derive(sqlx::FromRow)]
struct HeaderRow {
    id: Uuid,
    changed_on: DateTime<Utc>,
    category: i32,
    entity_name: Option<String>,
    record_id: Option<Uuid>,
    operation: i32,
    user_id: Uuid,
    user_name: String,
    user_email: String,
    source: i32,
    outcome: Option<i32>,
    correlation_id: Option<Uuid>,
    event_name: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DetailRow {
    field_name: String,
    old_value: Option<String>,
    new_value: Option<String>,
    value_mode: Option<i16>,
    is_sensitive: bool,
}

/// Loads `header_id`'s changed fields and classifies each one's visibility.
/// `record_readable` gates the whole set at once (My Activity's per-row
/// check, or Record History's already-enforced record-level access) —
/// field names themselves are not revealed when the record is not
/// currently readable, the conservative reading of "values Restricted."
async fn fetch_field_changes(
    pool: &sqlx::PgPool,
    header_id: Uuid,
    ctx: &SecurityContext,
    entity_name: Option<&str>,
    record_readable: bool,
) -> Result<Vec<FieldChangeView>, AppError> {
    if !record_readable {
        return Ok(vec![]);
    }
    let rows: Vec<DetailRow> = sqlx::query_as(
        "SELECT field_name, old_value, new_value, value_mode, is_sensitive \
         FROM audit_detail WHERE audit_ref = $1 AND is_active = true ORDER BY field_name",
    )
    .bind(header_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::internal)?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let field_readable = entity_name
            .map(|e| ctx.has_field_read_grant(e, &row.field_name))
            .unwrap_or(true);
        let is_erased = row.new_value.as_deref() == Some(ERASED_MARKER)
            || row.old_value.as_deref() == Some(ERASED_MARKER);
        // D-540's read-time rule for a legacy (pre-migration-0474) row: NULL
        // value_mode reads as Restricted iff is_sensitive, else Encrypted.
        let restricted_mode = row.value_mode.unwrap_or(if row.is_sensitive {
            VALUE_MODE_RESTRICTED
        } else {
            0
        }) == VALUE_MODE_RESTRICTED;

        let value = if !field_readable {
            FieldValueView::Restricted
        } else if is_erased {
            FieldValueView::Erased {
                value: ERASED_MARKER.to_string(),
            }
        } else if restricted_mode {
            FieldValueView::Restricted
        } else {
            FieldValueView::Encrypted
        };
        out.push(FieldChangeView {
            field_name: row.field_name,
            value,
        });
    }
    Ok(out)
}

fn header_to_entry(h: HeaderRow, changes: Vec<FieldChangeView>) -> HistoryEntry {
    HistoryEntry {
        id: h.id,
        changed_on: h.changed_on,
        category: h.category,
        entity_name: h.entity_name,
        record_id: h.record_id,
        operation: h.operation,
        user_id: h.user_id,
        user_name: h.user_name,
        user_email: h.user_email,
        source: h.source,
        outcome: h.outcome,
        correlation_id: h.correlation_id,
        event_name: h.event_name,
        changes,
    }
}

/// The date/category/operation/source/outcome filters both endpoints share.
/// A separate, smaller shape than `attome_audit::admin`'s `AuditFilterParams`
/// (that one adds entity/record/user/field filters this self-service surface
/// doesn't need — Record History's entity+record come from the path, My
/// Activity's user is always the caller).
#[derive(Debug, Default)]
struct CommonFilters {
    date_from: Option<DateTime<Utc>>,
    date_to: Option<DateTime<Utc>>,
    category: Option<i32>,
    operation: Option<i32>,
    source: Option<i32>,
    outcome: Option<i32>,
}

fn push_common_filters<'a>(qb: &mut sqlx::QueryBuilder<'a, sqlx::Postgres>, f: &'a CommonFilters) {
    if let Some(v) = &f.date_from {
        qb.push(" AND changed_on >= ").push_bind(*v);
    }
    if let Some(v) = &f.date_to {
        qb.push(" AND changed_on <= ").push_bind(*v);
    }
    if let Some(v) = &f.category {
        qb.push(" AND category = ").push_bind(*v);
    }
    if let Some(v) = &f.operation {
        qb.push(" AND operation = ").push_bind(*v);
    }
    if let Some(v) = &f.source {
        qb.push(" AND source = ").push_bind(*v);
    }
    if let Some(v) = &f.outcome {
        qb.push(" AND outcome = ").push_bind(*v);
    }
}

// ── 6.1/6.2/6.3: my activity ─────────────────────────────────────────────────

#[derive(Deserialize, IntoParams, Debug)]
struct ActivityQuery {
    date_from: Option<DateTime<Utc>>,
    date_to: Option<DateTime<Utc>>,
    category: Option<i32>,
    operation: Option<i32>,
    entity_name: Option<String>,
    source: Option<i32>,
    outcome: Option<i32>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

impl ActivityQuery {
    fn filter(&self) -> CommonFilters {
        CommonFilters {
            date_from: self.date_from,
            date_to: self.date_to,
            category: self.category,
            operation: self.operation,
            source: self.source,
            outcome: self.outcome,
        }
    }
}

#[utoipa::path(
    get,
    operation_id = "audit_my_activity",
    path = "/api/v1/audit/me/activity",
    tag = "audit",
    params(ActivityQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<HistoryEntry>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn my_activity(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(q): Query<ActivityQuery>,
) -> Result<Json<PaginatedResponse<HistoryEntry>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);
    let pool = state.base.readonly_query_pool(ctx.user_id).await;
    let filter = q.filter();

    // Always the caller's own events (My Activity never gates on current
    // record access at the list level — only per-row value visibility does).
    let mut qb = sqlx::QueryBuilder::new(
        "SELECT id, changed_on, category, entity_name, record_id, operation, user_id, \
                user_name, user_email, source, outcome, correlation_id, event_name \
         FROM audit_header WHERE is_active = true AND user_id = ",
    );
    qb.push_bind(ctx.user_id);
    if let Some(v) = &q.entity_name {
        qb.push(" AND entity_name = ").push_bind(v.clone());
    }
    push_common_filters(&mut qb, &filter);
    qb.push(" ORDER BY changed_on DESC, id DESC LIMIT ")
        .push_bind(page_size)
        .push(" OFFSET ")
        .push_bind(offset);

    let headers: Vec<HeaderRow> = qb
        .build_query_as()
        .fetch_all(pool)
        .await
        .map_err(AppError::internal)?;

    let mut count_qb = sqlx::QueryBuilder::new(
        "SELECT COUNT(*) FROM audit_header WHERE is_active = true AND user_id = ",
    );
    count_qb.push_bind(ctx.user_id);
    if let Some(v) = &q.entity_name {
        count_qb.push(" AND entity_name = ").push_bind(v.clone());
    }
    push_common_filters(&mut count_qb, &filter);
    let total: i64 = count_qb
        .build_query_scalar()
        .fetch_one(pool)
        .await
        .map_err(AppError::internal)?;

    let mut items = Vec::with_capacity(headers.len());
    for h in headers {
        // Existence vs values: My Activity always lists this row (it's the
        // caller's own action), but a per-row require_record_access check
        // decides whether the referenced record's values are still visible
        // — access may have been revoked, or the entity itself renamed/
        // removed, since the action happened.
        let record_readable = match (h.entity_name.as_deref(), h.record_id) {
            (Some(en), Some(rid)) => match resolve_entity(&state, en).await {
                Ok((entity_id, resolved_name, _, _)) => require_record_access(
                    &state,
                    &ctx,
                    entity_id,
                    &resolved_name,
                    rid,
                    RecordAction::Read,
                )
                .await
                .is_ok(),
                Err(_) => false,
            },
            // A security/business event with no referenced record has
            // nothing to restrict.
            _ => true,
        };
        let changes =
            fetch_field_changes(pool, h.id, &ctx, h.entity_name.as_deref(), record_readable)
                .await?;
        items.push(header_to_entry(h, changes));
    }

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

// ── mounting ─────────────────────────────────────────────────────────────────

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/audit/me/activity", get(my_activity))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; the crate's `openapi_document` merges every fragment back into
/// one document (coding-guidelines §12).
#[derive(utoipa::OpenApi)]
#[openapi(paths(my_activity))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
