//! M89 Change Intelligence, item 1 (checklist item 1 only — see
//! `document/module-master-plans/M89-change-intelligence.md`) — `GET
//! /api/v1/admin/changes`, `system.admin` only. A **read-only aggregation**
//! over changes this deployment already records in several distinct places,
//! merged into one ordered feed. It writes nothing and adds no new source of
//! truth — every row it returns is re-derived, on each request, from tables
//! that already exist.
//!
//! **Sources, and how each one's "this changed" moment was actually found**
//! (the module plan names five kinds — metadata log, bundle ledger,
//! `_version` publishes, security/AI change tracking, settings — but the
//! *shape* each one takes on disk differs more than the plan's one-line
//! summary suggests; this is what verifying against the code, not the plan
//! prose, actually found, per coding-guidelines.md's instruction hierarchy
//! §6):
//!
//! - **metadata** — `metadata_change_log` (`attome_core::change_log`,
//!   D-025). Append-only, `id`/`entity_ref`/`logicalname`/`change_kind`/
//!   `created_at` only — no actor column exists on this table, so `actor` is
//!   always `None` here.
//! - **bundle** — `metadata_bundle_plan` (`crate::bundle::ledger`,
//!   P-environment-promotion §4), `succeeded` rows only: a `failed` or
//!   in-flight plan changed nothing on disk, so it is not a "change".
//! - **query** — `sql_query_version` (D-126): every row IS a publish
//!   (`query_admin.rs` writes one on every create/update that passes its
//!   publish-time lint), so no `status`/`published_at` filter is needed.
//! - **workflow** — `workflow_definition_version` (F094): rows exist in
//!   `draft`/`published`/`deprecated` states; only `status = 'published'`
//!   rows are a change to what's live.
//! - **dashboard** — `dashboard_version` (a *provisioned entity table*,
//!   `attome-dashboard`'s `owned_entities`, not a migration — see
//!   `attome-dashboard/src/lifecycle.rs::do_publish_dashboard`): every row is a
//!   publish, same shape as `query`.
//! - **content** — verified evidence contradicts the module plan's claim of a
//!   `_version` sibling table: `content_page` has none. A publish is
//!   `status = 'published' AND published_at IS NOT NULL` directly on the page
//!   row itself (`attome-content/src/admin.rs::publish_page`,
//!   `scheduling.rs`'s sweep). Read accordingly.
//! - **license** — likewise no `_version` table: `license` is itself
//!   append-only (`0006_core_license.sql`'s own header: "a new license
//!   'replaces' the active one simply by being the newest row"), so every row
//!   already IS the change event. No actor column exists here either
//!   (licenses are issued by `license-tool` outside the running app).
//! - **security** — the audit trail (`attome-audit`), filtered to
//!   `category = 1` (Security) AND `operation IN (12, 13, 14)`
//!   (PermissionChange/RoleChange/OwnerChange) — narrower than all of
//!   `AuditCategory::Security`, which also covers Login/Logout/FailedLogin
//!   (not grant changes). The table is `audit_header` (0092 renamed it
//!   from `audit_header`; this file read the old name until the
//!   keyset rework, so every unfiltered request failed).
//! - **ai** — the module plan states `prompt_registry`/`model_registry`
//!   "have their own change tracking already"; reading both found that is
//!   only true for one of them. `model_registry`'s approval gate reads
//!   `ai_model.approval_status` (D-491 removed the separate
//!   `ai_model_approval` entity), which is an ordinary provisioned
//!   entity (guidelines §9: ordinary admin CRUD, not a bespoke mechanism) —
//!   its changes are the standard generic-mutation audit trail,
//!   `entity_name = 'ai_model'`. `prompt_registry` is deliberately
//!   read-only, compiled-in Rust constants (D-360 ruling 4: "a prompt is
//!   code, reviewed like code") — it has no database row and no runtime
//!   timestamp at all, so there is nothing to feed a time-ordered feed with;
//!   surfacing it here would mean fabricating an `occurred_at` this module
//!   has no evidence for, which coding-guidelines.md's instruction hierarchy
//!   forbids ("never claim ... verified unless you actually verified it").
//!   `ai` therefore reports model-registry changes only.
//! - **settings** — M02/D-412's `write_setting` (`settings_admin.rs`) writes
//!   an audit event (`entity_name = 'setting'`, `event_name =
//!   "setting_changed"`) in the same transaction as the write, which is
//!   richer than `setting_change_log` (0169) — that table exists
//!   only as a cache watermark and carries no actor. Read the audit trail
//!   instead, same as `security`/`ai`.
//!
//! **Known limitation, inherited, not introduced here**: `security`/`ai`/
//! `settings` all read `audit_header`. Under
//! `audit.chainer_enabled` (D-316, default `true`, required in production),
//! `AuditService::write` durably captures an event into `audit_ingest`
//! immediately but the chainer process is what turns it into a queryable
//! `audit_header` row, asynchronously. A very recent security/AI/
//! settings change may not appear in this feed until the next chain batch
//! runs — an existing architectural property of the audit subsystem
//! (P1.13 stage 4), not something this endpoint can or should paper over.
//!
//! **Paging is keyset, exact and complete** (basic-units-10-10 §8, "P1
//! follow-ups"). The merged feed has one stable total order,
//! `(occurred_at DESC, kind rank ASC, source row id DESC)` — the kind rank is
//! [`ALL_KINDS`]'s position, and the source row id is that source's own
//! primary key, which is what makes the order total: two changes at the same
//! instant in the same source are still distinguished. `next_cursor` is an
//! opaque encoding of the last returned row's sort key (plus the window's
//! resolved lower bound, so a continuation page does not drift when `from`
//! was defaulted from "now"). For each active source the handler runs one
//! bounded query — `LIMIT page_size + 1`, newest first, restricted to rows
//! strictly after the cursor in the total order — then merges the per-source
//! heads in memory and cuts `page_size`. The top `n` of a merge is always
//! drawn from each source's own top `n`, so nothing is capped and nothing is
//! silently dropped, however deep the caller pages. `total` is an exact
//! per-source `COUNT(*)` over the window, computed only on a request without
//! a cursor (the first page). The old one-based `page` offset mode was
//! deleted outright (D-790); `cursor` is the only way past the first page.
//! The response is the shared `attome_types::CursorPage<ChangeFeedEntry>`
//! (`items`, `next_cursor`, first-page `total`; D-793).

use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, CursorPage, DEFAULT_PAGE_SIZE, ErrorResponse, MAX_PAGE_SIZE};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::postgres::PgRow;
use std::cmp::Ordering;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Default lookback when the caller omits `from` — generous enough for an
/// admin skimming "what changed lately" without an explicit range.
const DEFAULT_WINDOW_DAYS: i64 = 30;
/// Version tag of the cursor encoding, so a future change can reject an old
/// cursor explicitly instead of misreading it.
const CURSOR_VERSION: &str = "v1";

/// Security-category audit operations that represent a grant change, not
/// merely session activity — `attome_audit::model::AuditOperation` discriminants
/// (mirrored here because this file reads `audit_header` directly rather
/// than through `attome-audit`'s Rust API, same as every other raw read of that
/// table in this crate). Compile-time constants, formatted into the static
/// SQL below — no request value is ever interpolated.
const OP_PERMISSION_CHANGE: i32 = 12;
const OP_ROLE_CHANGE: i32 = 13;
const OP_OWNER_CHANGE: i32 = 14;
const CATEGORY_SECURITY: i32 = 1;

/// One source this feed aggregates. The wire value (`kind` filter and each
/// entry's own `kind` field) is this variant's snake_case name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Metadata,
    Bundle,
    Query,
    Workflow,
    Dashboard,
    Content,
    License,
    Security,
    Ai,
    Settings,
}

/// Also the feed's tie-break order: at one instant, kinds sort in this order
/// (a kind's rank is its index here). Append new kinds at the end — the rank
/// is part of every cursor already handed out.
const ALL_KINDS: [ChangeKind; 10] = [
    ChangeKind::Metadata,
    ChangeKind::Bundle,
    ChangeKind::Query,
    ChangeKind::Workflow,
    ChangeKind::Dashboard,
    ChangeKind::Content,
    ChangeKind::License,
    ChangeKind::Security,
    ChangeKind::Ai,
    ChangeKind::Settings,
];

impl ChangeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Bundle => "bundle",
            Self::Query => "query",
            Self::Workflow => "workflow",
            Self::Dashboard => "dashboard",
            Self::Content => "content",
            Self::License => "license",
            Self::Security => "security",
            Self::Ai => "ai",
            Self::Settings => "settings",
        }
    }

    fn rank(self) -> u8 {
        // ALL_KINDS holds every variant, so the search always succeeds.
        ALL_KINDS.iter().position(|k| *k == self).unwrap_or(0) as u8
    }

    /// `metadata_change_log.id` is a `BIGSERIAL`; every other
    /// source is keyed by a UUID.
    fn has_bigint_id(self) -> bool {
        matches!(self, Self::Metadata)
    }

    /// Client error naming the bad value, same posture as
    /// `prompt_registry::diff`'s unknown-version handling (guidelines §6:
    /// this is admin-only, nothing dark to protect by staying vague).
    fn parse(value: &str) -> Result<Self, AppError> {
        ALL_KINDS
            .iter()
            .copied()
            .find(|k| k.as_str() == value)
            .ok_or_else(|| AppError::Validation(format!("unknown change kind: {value}")))
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ChangeFeedQuery {
    /// Inclusive lower bound. Defaults to `to - 30 days` — on a continuation
    /// page, to the lower bound the first page resolved (carried in the
    /// cursor).
    from: Option<DateTime<Utc>>,
    /// Inclusive upper bound. Defaults to now.
    to: Option<DateTime<Utc>>,
    /// One of [`ChangeKind`]'s wire values. Omitted = every source.
    kind: Option<String>,
    /// The previous response's `next_cursor`, verbatim. Omit for the first
    /// page. A malformed cursor is a 422.
    cursor: Option<String>,
    /// Rows per page, 1..=200 (default 50).
    page_size: Option<i64>,
}

/// One row of the unified feed. `reference` is always the id of the actual
/// source record (not this feed's own bookkeeping), so a caller can follow up
/// against that source's own admin surface.
#[derive(Clone, Debug, Serialize, ToSchema)]
struct ChangeFeedEntry {
    kind: ChangeKind,
    occurred_at: DateTime<Utc>,
    /// Best-effort — `None` when the source records no actor at all (see the
    /// module doc's per-source notes), never fabricated.
    actor: Option<String>,
    description: String,
    reference: String,
}

// ── sort key and cursor ──────────────────────────────────────────────────

/// A source row's own primary key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RowId {
    Big(i64),
    Uuid(Uuid),
}

/// The feed's total order: `occurred_at DESC, rank ASC, id DESC`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SortKey {
    at: DateTime<Utc>,
    rank: u8,
    id: RowId,
}

impl SortKey {
    /// `Less` = earlier in the feed.
    fn feed_cmp(&self, other: &Self) -> Ordering {
        other
            .at
            .cmp(&self.at)
            .then_with(|| self.rank.cmp(&other.rank))
            .then_with(|| other.id.cmp(&self.id))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cursor {
    /// The window's resolved lower bound on the page that issued it.
    from: DateTime<Utc>,
    /// The last row returned; the next page starts strictly after it.
    after: SortKey,
}

impl Cursor {
    fn encode(&self) -> String {
        let id = match self.after.id {
            RowId::Big(v) => format!("b{v}"),
            RowId::Uuid(v) => format!("u{v}"),
        };
        let raw = format!(
            "{CURSOR_VERSION}:{}:{}:{}:{id}",
            self.from.timestamp_micros(),
            self.after.at.timestamp_micros(),
            self.after.rank
        );
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    }

    /// Every failure is the same client error: the cursor is opaque, so the
    /// caller can do nothing with a more specific reason than "start over".
    fn decode(token: &str) -> Result<Self, AppError> {
        Self::try_decode(token).ok_or_else(|| {
            AppError::Validation(
                "invalid cursor: pass back a next_cursor value unchanged, or omit it".to_string(),
            )
        })
    }

    fn try_decode(token: &str) -> Option<Self> {
        if token.len() > 256 {
            return None;
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .ok()?;
        let raw = String::from_utf8(bytes).ok()?;
        let mut parts = raw.split(':');
        if parts.next()? != CURSOR_VERSION {
            return None;
        }
        let from = DateTime::from_timestamp_micros(parts.next()?.parse().ok()?)?;
        let at = DateTime::from_timestamp_micros(parts.next()?.parse().ok()?)?;
        let rank: u8 = parts.next()?.parse().ok()?;
        let kind = *ALL_KINDS.get(usize::from(rank))?;
        let id_part = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let id = match (kind.has_bigint_id(), id_part.split_at_checked(1)?) {
            (true, ("b", v)) => RowId::Big(v.parse().ok()?),
            (false, ("u", v)) => RowId::Uuid(Uuid::parse_str(v).ok()?),
            _ => return None,
        };
        Some(Self {
            from,
            after: SortKey { at, rank, id },
        })
    }
}

// ── per-source SQL ───────────────────────────────────────────────────────

/// One source's static SQL pieces. Every string is a compile-time constant
/// (or formatted from one); request values are only ever bound.
struct SourceSql {
    columns: &'static str,
    /// `FROM <table> WHERE <the source's own "is a change" filter>`.
    from_where: String,
    /// The column that is the change's `occurred_at`.
    ts: &'static str,
}

const AUDIT_COLUMNS: &str = "id, operation, entity_name, record_id, user_id, user_display_name, \
     event_comment, changed_on";

fn source_sql(kind: ChangeKind) -> SourceSql {
    match kind {
        ChangeKind::Metadata => SourceSql {
            columns: "id, entity_ref, logicalname, change_kind, created_at",
            from_where: "FROM metadata_change_log WHERE TRUE".into(),
            ts: "created_at",
        },
        // `succeeded` only: a failed or in-flight plan changed nothing.
        ChangeKind::Bundle => SourceSql {
            columns: "id, requested_by, applied_count, finished_at",
            from_where: "FROM metadata_bundle_plan \
                         WHERE status = 'succeeded' AND finished_at IS NOT NULL"
                .into(),
            ts: "finished_at",
        },
        ChangeKind::Query => SourceSql {
            columns: "id, query_id, created_by, created_at",
            from_where: "FROM sql_query_version WHERE TRUE".into(),
            ts: "created_at",
        },
        ChangeKind::Workflow => SourceSql {
            columns: "id, definition_id, version_number, published_by, published_at",
            from_where: "FROM workflow_definition_version \
                         WHERE status = 'published' AND published_at IS NOT NULL"
                .into(),
            ts: "published_at",
        },
        // `version_number` is provisioned as a `"number"` (NUMERIC)
        // attribute, cast the way `attome-dashboard`'s own
        // `do_publish_dashboard` casts it.
        ChangeKind::Dashboard => SourceSql {
            columns: "id, dashboard_id, version_number::bigint AS version_number, \
                      published_by, published_at",
            from_where: "FROM dashboard_version WHERE published_at IS NOT NULL".into(),
            ts: "published_at",
        },
        // No `_version` sibling exists for `content_page` (module doc).
        ChangeKind::Content => SourceSql {
            columns: "id, title, updated_by, published_at",
            from_where: "FROM content_page \
                         WHERE status = 'published' AND is_deleted = FALSE \
                           AND published_at IS NOT NULL"
                .into(),
            ts: "published_at",
        },
        // Append-only (0006's header): every row already IS the change.
        ChangeKind::License => SourceSql {
            columns: "id, domain, tier, issued_at",
            from_where: "FROM license WHERE TRUE".into(),
            ts: "issued_at",
        },
        // Narrower than all of `AuditCategory::Security` — excludes
        // Login/Logout/FailedLogin (session activity, not a grant change).
        ChangeKind::Security => SourceSql {
            columns: AUDIT_COLUMNS,
            from_where: format!(
                "FROM audit_header WHERE category = {CATEGORY_SECURITY} \
                 AND operation IN ({OP_PERMISSION_CHANGE}, {OP_ROLE_CHANGE}, {OP_OWNER_CHANGE}) \
                 AND changed_on IS NOT NULL"
            ),
            ts: "changed_on",
        },
        ChangeKind::Ai => SourceSql {
            columns: AUDIT_COLUMNS,
            from_where: "FROM audit_header \
                         WHERE entity_name = 'ai_model' AND changed_on IS NOT NULL"
                .into(),
            ts: "changed_on",
        },
        ChangeKind::Settings => SourceSql {
            columns: AUDIT_COLUMNS,
            from_where: "FROM audit_header \
                         WHERE entity_name = 'setting' AND changed_on IS NOT NULL"
                .into(),
            ts: "changed_on",
        },
    }
}

/// The resolved read window for one request.
struct Window {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    after: Option<SortKey>,
    /// Per-source row limit: `page_size + 1`.
    limit: i64,
}

/// One source's head of the feed after `w.after`, newest first, in the
/// feed's total order. For a source of rank `r` and a cursor at
/// `(t, rank_c, id_c)`, "strictly after the cursor" is:
/// `r > rank_c` → `ts <= t`; `r < rank_c` → `ts < t`;
/// `r == rank_c` → `(ts, id) < (t, id_c)`. The SQL encodes all three with
/// one static predicate: `ts <= min(to, t)` as the index range, then
/// `ts < t OR <r > rank_c> OR id < <id_c if r == rank_c, else NULL>`.
async fn fetch_source<R>(db: &DbPool, kind: ChangeKind, w: &Window) -> Result<Vec<R>, AppError>
where
    R: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin,
{
    let SourceSql {
        columns,
        from_where,
        ts,
    } = source_sql(kind);
    let (id_type, rank) = (
        if kind.has_bigint_id() {
            "bigint"
        } else {
            "uuid"
        },
        kind.rank(),
    );
    let sql = format!(
        "SELECT {columns} {from_where} \
           AND {ts} >= $1 AND {ts} <= $2 \
           AND ($3::timestamptz IS NULL OR {ts} < $3 OR $4::boolean OR id < $5::{id_type}) \
         ORDER BY {ts} DESC, id DESC LIMIT $6"
    );
    let upper = match w.after {
        Some(after) => w.to.min(after.at),
        None => w.to,
    };
    let cursor_at = w.after.map(|a| a.at);
    let later_rank = w.after.is_some_and(|a| rank > a.rank);
    let same_rank_id = w.after.filter(|a| a.rank == rank).map(|a| a.id);

    let query = sqlx::query_as::<_, R>(&sql)
        .bind(w.from)
        .bind(upper)
        .bind(cursor_at)
        .bind(later_rank);
    let query = if kind.has_bigint_id() {
        query.bind(match same_rank_id {
            Some(RowId::Big(v)) => Some(v),
            _ => None,
        })
    } else {
        query.bind(match same_rank_id {
            Some(RowId::Uuid(v)) => Some(v),
            _ => None,
        })
    };
    query
        .bind(w.limit)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)
}

async fn count_source(
    db: &DbPool,
    kind: ChangeKind,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<i64, AppError> {
    let SourceSql { from_where, ts, .. } = source_sql(kind);
    let sql = format!("SELECT COUNT(*) {from_where} AND {ts} >= $1 AND {ts} <= $2");
    sqlx::query_scalar(&sql)
        .bind(from)
        .bind(to)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// `dashboard_version` is a provisioned entity table, present only once
/// `attome-dashboard` has provisioned it — an absent table is "no dashboard
/// publishes", not an error (same `to_regclass` probe as
/// `attome-ai::session_admin`).
async fn dashboard_provisioned(db: &DbPool) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass('dashboard_version') IS NOT NULL")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

// ── per-source rows ──────────────────────────────────────────────────────

struct FeedRow {
    key: SortKey,
    entry: ChangeFeedEntry,
}

fn feed_row(
    kind: ChangeKind,
    at: DateTime<Utc>,
    id: RowId,
    actor: Option<String>,
    description: String,
    reference: String,
) -> FeedRow {
    FeedRow {
        key: SortKey {
            at,
            rank: kind.rank(),
            id,
        },
        entry: ChangeFeedEntry {
            kind,
            occurred_at: at,
            actor,
            description,
            reference,
        },
    }
}

#[derive(sqlx::FromRow)]
struct MetadataRow {
    id: i64,
    entity_ref: Uuid,
    logicalname: String,
    change_kind: String,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct BundleRow {
    id: Uuid,
    requested_by: Option<Uuid>,
    applied_count: i32,
    finished_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct QueryVersionRow {
    id: Uuid,
    query_id: Uuid,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct WorkflowVersionRow {
    id: Uuid,
    definition_id: Uuid,
    version_number: i32,
    published_by: Option<Uuid>,
    published_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct DashboardVersionRow {
    id: Uuid,
    dashboard_id: Uuid,
    version_number: i64,
    published_by: Option<Uuid>,
    published_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct ContentPageRow {
    id: Uuid,
    title: String,
    updated_by: Uuid,
    published_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct LicenseRow {
    id: Uuid,
    domain: String,
    tier: String,
    issued_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: Uuid,
    operation: Option<i32>,
    entity_name: Option<String>,
    record_id: Option<Uuid>,
    user_id: Option<Uuid>,
    user_display_name: Option<String>,
    event_comment: Option<String>,
    changed_on: DateTime<Utc>,
}

impl AuditRow {
    fn actor(&self) -> Option<String> {
        self.user_display_name
            .clone()
            .or_else(|| self.user_id.map(|u| u.to_string()))
    }

    /// The audited record when there is one, else the audit row itself.
    fn reference(&self) -> String {
        self.record_id.unwrap_or(self.id).to_string()
    }

    fn into_feed_row(self, kind: ChangeKind, fallback: impl FnOnce(&Self) -> String) -> FeedRow {
        let description = self
            .event_comment
            .clone()
            .unwrap_or_else(|| fallback(&self));
        let (actor, reference) = (self.actor(), self.reference());
        feed_row(
            kind,
            self.changed_on,
            RowId::Uuid(self.id),
            actor,
            description,
            reference,
        )
    }
}

fn security_operation_label(operation: Option<i32>) -> &'static str {
    match operation {
        Some(OP_PERMISSION_CHANGE) => "permission change",
        Some(OP_ROLE_CHANGE) => "role change",
        Some(OP_OWNER_CHANGE) => "owner change",
        _ => "security grant change",
    }
}

fn opt_uuid(u: Option<Uuid>) -> Option<String> {
    u.map(|u| u.to_string())
}

async fn fetch_kind(db: &DbPool, kind: ChangeKind, w: &Window) -> Result<Vec<FeedRow>, AppError> {
    use ChangeKind as K;
    let rows = match kind {
        K::Metadata => fetch_source::<MetadataRow>(db, kind, w)
            .await?
            .into_iter()
            .map(|r| {
                feed_row(
                    kind,
                    r.created_at,
                    RowId::Big(r.id),
                    // No actor column exists on this table.
                    None,
                    format!("metadata {} on {}", r.change_kind, r.logicalname),
                    r.entity_ref.to_string(),
                )
            })
            .collect(),
        K::Bundle => fetch_source::<BundleRow>(db, kind, w)
            .await?
            .into_iter()
            .map(|r| {
                feed_row(
                    kind,
                    r.finished_at,
                    RowId::Uuid(r.id),
                    opt_uuid(r.requested_by),
                    format!("metadata bundle applied ({} objects)", r.applied_count),
                    r.id.to_string(),
                )
            })
            .collect(),
        K::Query => fetch_source::<QueryVersionRow>(db, kind, w)
            .await?
            .into_iter()
            .map(|r| {
                feed_row(
                    kind,
                    r.created_at,
                    RowId::Uuid(r.id),
                    opt_uuid(r.created_by),
                    "stored query published a new version".to_string(),
                    r.query_id.to_string(),
                )
            })
            .collect(),
        K::Workflow => fetch_source::<WorkflowVersionRow>(db, kind, w)
            .await?
            .into_iter()
            .map(|r| {
                feed_row(
                    kind,
                    r.published_at,
                    RowId::Uuid(r.id),
                    opt_uuid(r.published_by),
                    format!(
                        "workflow definition published as version {}",
                        r.version_number
                    ),
                    r.definition_id.to_string(),
                )
            })
            .collect(),
        K::Dashboard => fetch_source::<DashboardVersionRow>(db, kind, w)
            .await?
            .into_iter()
            .map(|r| {
                feed_row(
                    kind,
                    r.published_at,
                    RowId::Uuid(r.id),
                    opt_uuid(r.published_by),
                    format!("dashboard published as version {}", r.version_number),
                    r.dashboard_id.to_string(),
                )
            })
            .collect(),
        // `updated_by` is the closest available actor: the page has no
        // separate `published_by` column, so this is whoever last touched
        // the row — for the ordinary publish path, the publisher.
        K::Content => fetch_source::<ContentPageRow>(db, kind, w)
            .await?
            .into_iter()
            .map(|r| {
                feed_row(
                    kind,
                    r.published_at,
                    RowId::Uuid(r.id),
                    Some(r.updated_by.to_string()),
                    format!("content page \"{}\" published", r.title),
                    r.id.to_string(),
                )
            })
            .collect(),
        // Issued by `license-tool` outside the running app — no actor column.
        K::License => fetch_source::<LicenseRow>(db, kind, w)
            .await?
            .into_iter()
            .map(|r| {
                feed_row(
                    kind,
                    r.issued_at,
                    RowId::Uuid(r.id),
                    None,
                    format!("license issued for domain {} ({})", r.domain, r.tier),
                    r.id.to_string(),
                )
            })
            .collect(),
        K::Security => fetch_source::<AuditRow>(db, kind, w)
            .await?
            .into_iter()
            .map(|r| {
                r.into_feed_row(kind, |r| {
                    format!(
                        "{}{}",
                        security_operation_label(r.operation),
                        r.entity_name
                            .as_deref()
                            .map(|e| format!(" on {e}"))
                            .unwrap_or_default()
                    )
                })
            })
            .collect(),
        K::Ai => fetch_source::<AuditRow>(db, kind, w)
            .await?
            .into_iter()
            .map(|r| r.into_feed_row(kind, |_| "AI model catalog entry changed".to_string()))
            .collect(),
        K::Settings => fetch_source::<AuditRow>(db, kind, w)
            .await?
            .into_iter()
            .map(|r| r.into_feed_row(kind, |_| "runtime setting changed".to_string()))
            .collect(),
    };
    Ok(rows)
}

// ── HTTP surface ─────────────────────────────────────────────────────────

/// `GET /api/v1/admin/changes` — `system.admin` only. Unifies the metadata
/// change log, the bundle apply ledger, every `_version`/publish-style change
/// this deployment tracks, security grant changes, AI model-registry
/// changes, and runtime settings changes into one ordered, filterable feed,
/// paged by an opaque keyset cursor. See the module doc for exactly what each
/// `kind` reads, the total order, and why the envelope is the keyset
/// `CursorPage<T>`, not `PaginatedResponse<T>`.
#[utoipa::path(
    get,
    path = "/api/v1/admin/changes",
    tag = "admin",
    params(ChangeFeedQuery),
    responses(
        (status = 200, description = "One keyset page of the merged feed; `total` is set on the first page only", body = CursorPage<ChangeFeedEntry>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation (unknown kind, malformed cursor, or from after to)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_changes(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<ChangeFeedQuery>,
) -> Result<Json<CursorPage<ChangeFeedEntry>>, AppError> {
    let page_size = q
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);
    let cursor = q.cursor.as_deref().map(Cursor::decode).transpose()?;

    let to = q.to.unwrap_or_else(Utc::now);
    let from = q
        .from
        .or(cursor.map(|c| c.from))
        .unwrap_or_else(|| to - Duration::days(DEFAULT_WINDOW_DAYS));
    if from > to {
        return Err(AppError::Validation(
            "from must not be after to".to_string(),
        ));
    }

    let kind_filter = q.kind.as_deref().map(ChangeKind::parse).transpose()?;
    let db = &state.base.db;
    let mut active_kinds: Vec<ChangeKind> = match kind_filter {
        Some(k) => vec![k],
        None => ALL_KINDS.to_vec(),
    };
    if active_kinds.contains(&ChangeKind::Dashboard) && !dashboard_provisioned(db).await? {
        active_kinds.retain(|k| *k != ChangeKind::Dashboard);
    }

    let window = Window {
        from,
        to,
        after: cursor.map(|c| c.after),
        limit: page_size + 1,
    };
    let mut merged: Vec<FeedRow> = Vec::new();
    for kind in &active_kinds {
        merged.extend(fetch_kind(db, *kind, &window).await?);
    }
    merged.sort_by(|a, b| a.key.feed_cmp(&b.key));

    let end = page_size as usize;
    let has_more = merged.len() > end;
    merged.truncate(end);
    let rows: Vec<FeedRow> = merged;
    let next_cursor = if has_more {
        rows.last().map(|r| Cursor { from, after: r.key }.encode())
    } else {
        None
    };

    let total = if cursor.is_none() {
        let mut total = 0i64;
        for kind in &active_kinds {
            total += count_source(db, *kind, from, to).await?;
        }
        Some(total)
    } else {
        None
    };

    Ok(Json(
        CursorPage::new(rows.into_iter().map(|r| r.entry).collect(), next_cursor).with_total(total),
    ))
}

/// L7-T7: how every change-feed consumer is keeping up, the platform's own
/// and subscriptions alike.
#[utoipa::path(
    get,
    path = "/api/v1/admin/change-feed/consumers",
    tag = "admin",
    responses(
        (status = 200, description = "Every consumer with its lag", body = attome_types::PaginatedResponse<attome_core::change_feed::ConsumerHealth>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_consumers(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<attome_types::PaginatedResponse<attome_core::change_feed::ConsumerHealth>>, AppError>
{
    let consumers = attome_core::change_feed::consumer_health(&state.base.db).await?;
    let total = i64::try_from(consumers.len()).map_err(AppError::internal)?;
    Ok(Json(attome_types::PaginatedResponse::new(
        consumers,
        total,
        1,
        total.max(1),
    )))
}

/// Y7-T4: where to rewind a consumer to; exactly one of the two.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct RewindBody {
    /// The first event at or after this sequence number.
    pub to_seq: Option<i64>,
    /// The first event written at or after this time.
    pub to_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// Y7-T4: moves a consumer back so it reads the feed again from a sequence
/// number or a time, within what the feed still holds. A consumer applies
/// each event once, so what it already applied is skipped.
#[utoipa::path(
    post,
    path = "/api/v1/admin/change-feed/consumers/{name}/rewind",
    tag = "admin",
    params(("name" = String, Path, description = "The consumer's name")),
    request_body = RewindBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "The consumer reads again from that point"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such consumer", body = ErrorResponse),
        (status = 422, description = "Neither or both points given, or the feed no longer holds that point", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn rewind_consumer(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(body): Json<RewindBody>,
) -> Result<axum::http::StatusCode, AppError> {
    let to = match (body.to_seq, body.to_time) {
        (Some(seq), None) => attome_core::change_feed::RewindTo::Seq(seq),
        (None, Some(at)) => attome_core::change_feed::RewindTo::Time(at),
        _ => {
            return Err(AppError::Validation(
                "give exactly one of to_seq and to_time".into(),
            ));
        }
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_core::change_feed::rewind(&mut tx, &name, to).await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "change_consumer_cursor",
            None,
        )
        .named("change_feed.consumer_rewind"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(consumer = %name, ?to, "change feed: consumer rewound");
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/changes", get(list_changes))
        .route("/api/v1/admin/change-feed/consumers", get(list_consumers))
        .route(
            "/api/v1/admin/change-feed/consumers/{name}/rewind",
            axum::routing::post(rewind_consumer),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged in by `crate::openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_changes, list_consumers, rewind_consumer),
    components(schemas(RewindBody))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(at_us: i64, kind: ChangeKind, id: RowId) -> SortKey {
        SortKey {
            at: DateTime::from_timestamp_micros(at_us).unwrap(),
            rank: kind.rank(),
            id,
        }
    }

    #[test]
    fn cursor_round_trips_both_id_kinds() {
        let from = DateTime::from_timestamp_micros(1_000_000).unwrap();
        for after in [
            key(1_234_567, ChangeKind::Metadata, RowId::Big(42)),
            key(7, ChangeKind::Settings, RowId::Uuid(Uuid::now_v7())),
        ] {
            let c = Cursor { from, after };
            assert_eq!(Cursor::decode(&c.encode()).unwrap(), c);
        }
    }

    #[test]
    fn malformed_cursors_are_rejected() {
        let enc = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        let u = Uuid::nil();
        for bad in [
            "not base64 !!".to_string(),
            enc("garbage"),
            enc(&format!("v2:0:0:1:u{u}")),
            enc(&format!("v1:0:0:10:u{u}")), // rank out of range
            enc("v1:0:0:0:u00000000-0000-0000-0000-000000000000"), // metadata needs a bigint
            enc("v1:0:0:1:b5"),              // bundle needs a uuid
            enc(&format!("v1:0:0:1:u{u}:extra")),
            enc(&format!("v1:x:0:1:u{u}")),
            "A".repeat(300),
        ] {
            assert!(
                matches!(Cursor::decode(&bad), Err(AppError::Validation(_))),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn feed_order_is_newest_then_rank_then_id_desc() {
        let a = key(10, ChangeKind::License, RowId::Uuid(Uuid::nil()));
        let newer = key(11, ChangeKind::Settings, RowId::Uuid(Uuid::nil()));
        let lower_rank = key(10, ChangeKind::Metadata, RowId::Big(1));
        let bigger_id = key(
            10,
            ChangeKind::License,
            RowId::Uuid(Uuid::from_u128(u128::MAX)),
        );
        assert_eq!(newer.feed_cmp(&a), Ordering::Less);
        assert_eq!(lower_rank.feed_cmp(&a), Ordering::Less);
        assert_eq!(bigger_id.feed_cmp(&a), Ordering::Less);
        assert_eq!(a.feed_cmp(&a), Ordering::Equal);
    }

    #[test]
    fn kind_ranks_follow_all_kinds() {
        for (i, k) in ALL_KINDS.iter().enumerate() {
            assert_eq!(usize::from(k.rank()), i);
        }
    }
}
