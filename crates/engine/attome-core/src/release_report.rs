//! Solution 7 Phase 2 (D-788 Topic 14, D-791 rules 2 and 7;
//! `SOLUTION-7-PHASE-2-DESIGN.md` §9, §10) — the release report store and the
//! record baseline (`release_report`, `release_report_item`,
//! migration 0540; `record_baseline`, 0541).
//!
//! **Report.** One report per apply run (the changesets of one release),
//! created before the first operation (`building`), filled while the run
//! executes, and marked `ready` after it ([`mark_ready`]); the apply engine
//! owns that lifecycle (`attome_server::changeset::report`). A structure change
//! made on an admin route outside any apply writes its items into a
//! standalone report (`source = 'change'`, ready at once, no notification).
//!
//! **Where items go.** The apply job runs every operation inside [`scope`]
//! with its report id and the operation's `(changeset id, seq)`; executors
//! that produce items ([`record_drafts`], the record and rule conflict paths)
//! read [`current`]. Outside a scope they write a standalone report. Same
//! `tokio::task_local!` shape as `changeset::reference`.
//!
//! **No deadline** (Topic 14, Topic 15 #4): items stay until decided,
//! dismissed, superseded or (archive-backed) expired; nothing reads an
//! item's status to gate an apply. A new item on the same (kind, entity,
//! field, record/object) supersedes the open one ([`insert_item`]).
//!
//! **Values.** `detail` never carries record values. A conflict's values
//! (the customer's, ours) and the record's business key are sealed with the
//! recovery-archive key ring (design §9.3: "same ring as §8.2"), the
//! envelope's additional data bound to the item id ([`aad`]), and kept for
//! the item's lifetime (§15 Q6 default; conflict items never expire). With
//! no ring configured the item is still written, without values: the
//! customer's value stays either way, and "Use mine" answers
//! `archive_key_missing`.
//!
//! **Baseline** (§9.1, §9.2): per field of a reference record (and per
//! customer-layer rule, field `definition`), the hash of **our last intended
//! value** plus the hash of the value as stored after our write. [`decide`]
//! is the three-way rule.

use std::collections::HashMap;
use std::future::Future;

use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::changeset::field_hooks::{
    FieldReferenceHook, HookFuture, HookOutcome, RefScan, ReportItemDraft,
};

/// The envelope's `field_name` for sealed conflict values (error messages
/// only; never key material).
pub const ENVELOPE_FIELD: &str = "release_report";

/// Stable refusal: a decided item cannot be decided again.
pub const REPORT_ITEM_DECIDED: &str =
    "report_item_decided: this report item is no longer open (decided, superseded or expired)";

/// Stable refusal: the item's sealed values do not open for this item.
pub const REPORT_VALUES_UNREADABLE: &str = "report_values_unreadable: this item's stored values do \
     not open for it (moved between items or sealed in another format); nothing was read";

/// The baseline entity name of a business rule (its `definition` field).
pub const RULE_BASELINE_ENTITY: &str = "rule";
/// The baseline field name of a business rule.
pub const RULE_BASELINE_FIELD: &str = "definition";

// ── Kinds and statuses ──────────────────────────────────────────────────────

/// An item kind (the table's CHECK, design §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Conflict,
    ConversionNulled,
    FieldDeleted,
    CustomerObjectAdjusted,
    CustomerObjectRemoved,
    BreakingApiChange,
    ChoiceRemovedInUse,
    RequiredEmpty,
    /// Y11-T12: a customisation on an item the release retired, deleted or
    /// renamed (information; never moved automatically).
    CustomisationAffected,
}

impl ItemKind {
    pub const ALL: [ItemKind; 9] = [
        Self::Conflict,
        Self::ConversionNulled,
        Self::FieldDeleted,
        Self::CustomerObjectAdjusted,
        Self::CustomerObjectRemoved,
        Self::BreakingApiChange,
        Self::ChoiceRemovedInUse,
        Self::RequiredEmpty,
        Self::CustomisationAffected,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::ConversionNulled => "conversion_nulled",
            Self::FieldDeleted => "field_deleted",
            Self::CustomerObjectAdjusted => "customer_object_adjusted",
            Self::CustomerObjectRemoved => "customer_object_removed",
            Self::BreakingApiChange => "breaking_api_change",
            Self::ChoiceRemovedInUse => "choice_removed_in_use",
            Self::RequiredEmpty => "required_empty",
            Self::CustomisationAffected => "customisation_affected",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == value)
    }

    /// Conflicts and archive-backed items are decided by an action (Accept /
    /// Use mine / Restore); the rest are information (Dismiss only).
    pub fn actionable(self) -> bool {
        matches!(
            self,
            Self::Conflict | Self::ConversionNulled | Self::FieldDeleted
        )
    }

    /// Items whose Restore reads the recovery archive.
    pub fn archive_backed(self) -> bool {
        matches!(self, Self::ConversionNulled | Self::FieldDeleted)
    }
}

/// An item status (the table's CHECK).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    Open,
    Info,
    Accepted,
    UsedMine,
    Restored,
    Dismissed,
    Superseded,
    Expired,
}

impl ItemStatus {
    pub const ALL: [ItemStatus; 8] = [
        Self::Open,
        Self::Info,
        Self::Accepted,
        Self::UsedMine,
        Self::Restored,
        Self::Dismissed,
        Self::Superseded,
        Self::Expired,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Info => "info",
            Self::Accepted => "accepted",
            Self::UsedMine => "used_mine",
            Self::Restored => "restored",
            Self::Dismissed => "dismissed",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == value)
    }

    /// The status a new item of `kind` starts in.
    pub fn initial(kind: ItemKind) -> Self {
        if kind.actionable() {
            Self::Open
        } else {
            Self::Info
        }
    }
}

/// Who built a report (the table's CHECK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportSource {
    /// Platform changesets applied at boot.
    Boot,
    /// An admin apply request (`POST .../changesets/apply`).
    Admin,
    /// The replay tool.
    Replay,
    /// A structure change on an admin route outside an apply.
    Change,
}

impl ReportSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Admin => "admin",
            Self::Replay => "replay",
            Self::Change => "change",
        }
    }

    /// Whether a ready report of this source with items notifies the
    /// administrators (design §10.5): a release does; an admin's own
    /// structure change (answered in its response) does not.
    pub fn notifies(self) -> bool {
        !matches!(self, Self::Change)
    }

    pub fn parse(value: &str) -> Option<Self> {
        [Self::Boot, Self::Admin, Self::Replay, Self::Change]
            .into_iter()
            .find(|s| s.as_str() == value)
    }
}

// ── The ambient report of an apply run ──────────────────────────────────────

/// The report an apply run writes into, and the operation running now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportCtx {
    pub report_id: Uuid,
    /// `(changeset id, op seq)` of the operation being applied.
    pub op: Option<(Uuid, i32)>,
}

tokio::task_local! {
    static CURRENT_REPORT: ReportCtx;
}

/// Runs `f` with `ctx` as the ambient report (the apply job wraps its run,
/// and each operation, in this).
pub async fn scope<F: Future>(ctx: ReportCtx, f: F) -> F::Output {
    CURRENT_REPORT.scope(ctx, f).await
}

/// The ambient report, or `None` outside a [`scope`].
pub fn current() -> Option<ReportCtx> {
    CURRENT_REPORT.try_with(|c| *c).ok()
}

// ── Sealed conflict values ──────────────────────────────────────────────────

/// What a conflict item seals: the customer's value (kept), ours, and the
/// record's business key (record data too).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConflictValues {
    pub theirs: Value,
    pub ours: Value,
    #[serde(default)]
    pub key: Option<Value>,
}

/// The additional authenticated data binding sealed values to their item.
pub fn aad(item_id: Uuid) -> Vec<u8> {
    format!("{ENVELOPE_FIELD}/v1:{item_id}").into_bytes()
}

fn seal(ring: &KeyRing, item_id: Uuid, values: &ConflictValues) -> Result<Vec<u8>, AppError> {
    let text = serde_json::to_vec(values).map_err(AppError::internal)?;
    attome_auth::envelope::encrypt_bytes_with_aad(ENVELOPE_FIELD, ring, &text, &aad(item_id))
}

/// Opens an item's sealed values. A ciphertext that does not open for this
/// item is refused with [`REPORT_VALUES_UNREADABLE`] (logged at error).
pub fn open_values(
    ring: &KeyRing,
    item_id: Uuid,
    values_enc: &[u8],
) -> Result<ConflictValues, AppError> {
    let unreadable = |why: &str| {
        tracing::error!(%item_id, why,
            "release report: an item's sealed values do not open for it (moved, tampered or old format)");
        AppError::Conflict(REPORT_VALUES_UNREADABLE)
    };
    let bytes = attome_auth::envelope::decrypt_bytes_with_aad(
        ENVELOPE_FIELD,
        ring,
        values_enc,
        &aad(item_id),
    )
    .map_err(|_| unreadable("decrypt"))?;
    serde_json::from_slice(&bytes).map_err(|_| unreadable("payload"))
}

// ── Rows ────────────────────────────────────────────────────────────────────

/// One release report.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct ReleaseReport {
    pub id: Uuid,
    /// The ledger rows (`changeset_apply.id`) of this apply run.
    pub apply_ids: Vec<Uuid>,
    /// Platform version and the changesets of the release.
    pub release: String,
    /// `boot | admin | replay | change`.
    pub source: String,
    /// `building | ready`.
    pub status: String,
    pub items_total: i32,
    pub items_open: i32,
    pub backup_ref: Option<String>,
    /// Keep the pre-apply snapshot at least until then (design §7.2).
    pub backup_retain_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub ready_at: Option<DateTime<Utc>>,
    pub notified_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

/// The enumerated columns of [`ReleaseReport`].
pub const REPORT_COLUMNS: &str = "id, apply_ids, release, source, status, items_total, \
     items_open, backup_ref, backup_retain_until, created_at, ready_at, notified_at, row_version";

/// One report item, without its sealed values.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct ReportItem {
    pub id: Uuid,
    pub report_ref: Uuid,
    /// `conflict | conversion_nulled | field_deleted | customer_object_adjusted |
    /// customer_object_removed | breaking_api_change | choice_removed_in_use |
    /// required_empty`.
    pub kind: String,
    pub actionable: bool,
    /// `open | info | accepted | used_mine | restored | dismissed | superseded | expired`.
    pub status: String,
    pub entity_logicalname: String,
    pub field_logicalname: Option<String>,
    pub record_id: Option<Uuid>,
    pub object_kind: Option<String>,
    pub object_ref: Option<Uuid>,
    /// Counts, names and what changed; never record values.
    #[schema(value_type = Object)]
    pub detail: Value,
    /// The item carries sealed values (a conflict).
    pub has_values: bool,
    pub changeset_id: Option<Uuid>,
    pub op_seq: Option<i32>,
    pub decided_by: Option<Uuid>,
    pub decided_at: Option<DateTime<Utc>>,
    pub superseded_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub row_version: i64,
}

/// The enumerated columns of [`ReportItem`].
pub const ITEM_COLUMNS: &str = "id, report_ref, kind, actionable, status, entity_logicalname, \
     field_logicalname, record_id, object_kind, object_ref, detail, \
     (values_enc IS NOT NULL) AS has_values, changeset_id, op_seq, decided_by, decided_at, \
     superseded_by, created_at, row_version";

// ── Writing ─────────────────────────────────────────────────────────────────

/// A new item.
#[derive(Debug, Clone)]
pub struct NewItem {
    pub kind: ItemKind,
    pub entity: String,
    pub field: Option<String>,
    pub record_id: Option<Uuid>,
    pub object_kind: Option<String>,
    pub object_ref: Option<Uuid>,
    pub detail: Value,
    /// Conflict only; sealed before the insert.
    pub values: Option<ConflictValues>,
    pub op: Option<(Uuid, i32)>,
}

impl NewItem {
    /// An item from a hook's or executor's draft. `None` for a draft whose
    /// kind is not a report kind (logged by the caller).
    pub fn from_draft(draft: &ReportItemDraft, op: Option<(Uuid, i32)>) -> Option<Self> {
        Some(Self {
            kind: ItemKind::parse(draft.kind)?,
            entity: draft.entity.clone(),
            field: draft.field.clone(),
            record_id: None,
            object_kind: draft.object_kind.clone(),
            object_ref: draft.object_ref,
            detail: draft.detail.clone(),
            values: None,
            op,
        })
    }
}

/// Creates a report (`building`). `backup_retain_until` is the snapshot's
/// keep-until (apply time + 30 days when `backup_ref` is set).
pub async fn create_report(
    conn: &mut PgConnection,
    apply_ids: &[Uuid],
    release: &str,
    source: ReportSource,
    backup_ref: Option<&str>,
) -> Result<Uuid, AppError> {
    sqlx::query_scalar(
        "INSERT INTO release_report \
             (apply_ids, release, source, backup_ref, backup_retain_until) \
         VALUES ($1, $2, $3, $4, CASE WHEN $4::text IS NULL THEN NULL \
                                      ELSE now() + interval '30 days' END) \
         RETURNING id",
    )
    .bind(apply_ids)
    .bind(release)
    .bind(source.as_str())
    .bind(backup_ref)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// Recomputes a report's `items_total` / `items_open` (every transaction that
/// adds an item or changes a status calls it, so the counts are exact).
pub async fn refresh_counts(conn: &mut PgConnection, report_id: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE release_report r \
            SET items_total = c.total, items_open = c.open, row_version = r.row_version + 1 \
           FROM (SELECT COUNT(*)::int AS total, \
                        COUNT(*) FILTER (WHERE status = 'open')::int AS open \
                   FROM release_report_item WHERE report_ref = $1) c \
          WHERE r.id = $1",
    )
    .bind(report_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Inserts one item into `report_id`, in the caller's transaction. A
/// conflict's values are sealed first (no ring: stored without values, see
/// the module doc). An open item on the same (kind, entity, field,
/// record/object) is superseded by this one (design §9.3, §10.3). Returns
/// the new item's id.
pub async fn insert_item(
    conn: &mut PgConnection,
    ring: Option<&KeyRing>,
    report_id: Uuid,
    item: &NewItem,
) -> Result<Uuid, AppError> {
    let id = Uuid::now_v7();
    let values_enc = match (&item.values, ring) {
        (Some(values), Some(ring)) => Some(seal(ring, id, values)?),
        (Some(_), None) => {
            tracing::warn!(
                item_id = %id, entity = %item.entity, field = ?item.field,
                "release report: a conflict item is stored without its values \
                 (metadata.recovery_archive_key_encryption_key is not configured); \
                 the customer's value stays, Use mine is unavailable"
            );
            None
        }
        (None, _) => None,
    };
    let (changeset_id, op_seq) = match item.op {
        Some((c, s)) => (Some(c), Some(s)),
        None => (None, None),
    };
    sqlx::query(
        "INSERT INTO release_report_item \
             (id, report_ref, kind, actionable, status, entity_logicalname, field_logicalname, \
              record_id, object_kind, object_ref, detail, values_enc, changeset_id, op_seq) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(id)
    .bind(report_id)
    .bind(item.kind.as_str())
    .bind(item.kind.actionable())
    .bind(ItemStatus::initial(item.kind).as_str())
    .bind(&item.entity)
    .bind(&item.field)
    .bind(item.record_id)
    .bind(&item.object_kind)
    .bind(item.object_ref)
    .bind(&item.detail)
    .bind(values_enc)
    .bind(changeset_id)
    .bind(op_seq)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;

    // Replacement: a later release touching the same target supersedes the
    // open item (Topic 14 "a later release touching the same field replaces
    // the old item").
    let touched: Vec<Uuid> = sqlx::query_scalar(
        "WITH old AS ( \
             UPDATE release_report_item \
                SET status = 'superseded', superseded_by = $1, row_version = row_version + 1 \
              WHERE id <> $1 AND status = 'open' AND kind = $2 AND entity_logicalname = $3 \
                AND field_logicalname IS NOT DISTINCT FROM $4 \
                AND record_id IS NOT DISTINCT FROM $5 \
                AND object_ref IS NOT DISTINCT FROM $6 \
              RETURNING report_ref) \
         SELECT DISTINCT report_ref FROM old",
    )
    .bind(id)
    .bind(item.kind.as_str())
    .bind(&item.entity)
    .bind(&item.field)
    .bind(item.record_id)
    .bind(item.object_ref)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    for other in touched.iter().filter(|r| **r != report_id) {
        refresh_counts(conn, *other).await?;
    }
    refresh_counts(conn, report_id).await?;

    if item.kind.archive_backed()
        && let Some(field) = &item.field
    {
        link_archive_rows(conn, id, item.kind, &item.entity, field, item.op, None).await?;
    }
    Ok(id)
}

/// Points unlinked archive rows of the item's (entity, field, reason,
/// changeset op) at the item, so its Restore finds them. `since` limits it to
/// rows archived at or after a time (a large run archives after the item was
/// written; the Restore action links those lazily).
pub async fn link_archive_rows(
    conn: &mut PgConnection,
    item_id: Uuid,
    kind: ItemKind,
    entity: &str,
    field: &str,
    op: Option<(Uuid, i32)>,
    since: Option<DateTime<Utc>>,
) -> Result<u64, AppError> {
    let (changeset_id, op_seq) = match op {
        Some((c, s)) => (Some(c), Some(s)),
        None => (None, None),
    };
    let done = sqlx::query(
        "UPDATE recovery_archive SET report_item_ref = $1 \
          WHERE report_item_ref IS NULL AND reason = $2 AND entity_logicalname = $3 \
            AND field_logicalname = $4 AND changeset_id IS NOT DISTINCT FROM $5 \
            AND op_seq IS NOT DISTINCT FROM $6 AND restored_at IS NULL \
            AND ($7::timestamptz IS NULL OR archived_at >= $7)",
    )
    .bind(item_id)
    .bind(kind.as_str())
    .bind(entity)
    .bind(field)
    .bind(changeset_id)
    .bind(op_seq)
    .bind(since)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(done.rows_affected())
}

/// The report an executor writes into now: the ambient one, else a new
/// standalone `change` report (which the caller marks ready).
async fn target_report(
    conn: &mut PgConnection,
    release: &str,
) -> Result<(ReportCtx, bool), AppError> {
    match current() {
        Some(ctx) => Ok((ctx, false)),
        None => {
            let report_id = create_report(conn, &[], release, ReportSource::Change, None).await?;
            Ok((
                ReportCtx {
                    report_id,
                    op: None,
                },
                true,
            ))
        }
    }
}

/// Writes items into the ambient report (else a standalone `change` report,
/// marked ready at once) in the caller's transaction, so an item exists
/// exactly when the effect it reports committed. An item without an
/// operation takes the ambient one. Returns the report id, or `None` when
/// `items` is empty.
pub async fn insert_items(
    conn: &mut PgConnection,
    ring: Option<&KeyRing>,
    items: Vec<NewItem>,
    standalone_release: &str,
) -> Result<Option<Uuid>, AppError> {
    if items.is_empty() {
        return Ok(None);
    }
    let (ctx, standalone) = target_report(conn, standalone_release).await?;
    for mut item in items {
        if item.op.is_none() {
            item.op = ctx.op;
        }
        insert_item(conn, ring, ctx.report_id, &item).await?;
    }
    if standalone {
        mark_ready(conn, ctx.report_id).await?;
    }
    Ok(Some(ctx.report_id))
}

/// [`insert_items`] in a short transaction of its own (a caller whose effect
/// already committed).
pub async fn record_items(
    db: &DbPool,
    ring: Option<&KeyRing>,
    items: Vec<NewItem>,
    standalone_release: &str,
) -> Result<Option<Uuid>, AppError> {
    if items.is_empty() {
        return Ok(None);
    }
    let mut tx = attome_db::tx::begin(db).await?;
    let report = insert_items(&mut tx, ring, items, standalone_release).await?;
    attome_db::tx::commit(tx).await?;
    Ok(report)
}

/// [`record_items`] for hook and executor drafts (design §7.4 `HookOutcome`,
/// the structure-change executors). A draft of an unknown kind is logged and
/// skipped (never a failure of the change that produced it).
pub async fn record_drafts(
    db: &DbPool,
    ring: Option<&KeyRing>,
    drafts: &[ReportItemDraft],
    standalone_release: &str,
) -> Result<Option<Uuid>, AppError> {
    let mut items = Vec::with_capacity(drafts.len());
    for draft in drafts {
        match NewItem::from_draft(draft, None) {
            Some(item) => items.push(item),
            None => tracing::error!(
                kind = draft.kind, entity = %draft.entity,
                "release report: a draft of an unknown kind was not stored"
            ),
        }
    }
    record_items(db, ring, items, standalone_release).await
}

/// What [`mark_ready`] flipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyReport {
    pub id: Uuid,
    pub source: ReportSource,
    pub release: String,
    pub items_total: i32,
    pub items_open: i32,
}

/// `building -> ready` with exact counts, in the caller's transaction.
/// `None` when the report is not `building` (already ready: a retried
/// post-apply), so the caller notifies at most once.
pub async fn mark_ready(
    conn: &mut PgConnection,
    report_id: Uuid,
) -> Result<Option<ReadyReport>, AppError> {
    refresh_counts(conn, report_id).await?;
    let row: Option<(Uuid, String, String, i32, i32)> = sqlx::query_as(
        "UPDATE release_report \
            SET status = 'ready', ready_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND status = 'building' \
          RETURNING id, source, release, items_total, items_open",
    )
    .bind(report_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    row.map(|(id, source, release, items_total, items_open)| {
        let source = ReportSource::parse(&source).ok_or_else(|| {
            AppError::internal(format!(
                "release_report.source holds an unknown value {source:?}"
            ))
        })?;
        Ok(ReadyReport {
            id,
            source,
            release,
            items_total,
            items_open,
        })
    })
    .transpose()
}

/// Sets `notified_at` (in the ready transaction, with the dispatch).
pub async fn set_notified(conn: &mut PgConnection, report_id: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE release_report SET notified_at = now(), row_version = row_version + 1 \
         WHERE id = $1 AND notified_at IS NULL",
    )
    .bind(report_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Item counts by kind for one report (the notification text).
pub async fn counts_by_kind(
    conn: &mut PgConnection,
    report_id: Uuid,
) -> Result<Vec<(String, i64)>, AppError> {
    sqlx::query_as(
        "SELECT kind, COUNT(*) FROM release_report_item \
         WHERE report_ref = $1 GROUP BY kind ORDER BY kind",
    )
    .bind(report_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)
}

// ── Reading and deciding ────────────────────────────────────────────────────

/// One item with its sealed values, locked `FOR UPDATE` (the decide actions).
pub async fn lock_item(
    conn: &mut PgConnection,
    item_id: Uuid,
) -> Result<Option<(ReportItem, Option<Vec<u8>>)>, AppError> {
    #[derive(sqlx::FromRow)]
    struct Row {
        #[sqlx(flatten)]
        item: ReportItem,
        values_enc: Option<Vec<u8>>,
    }
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {ITEM_COLUMNS}, values_enc FROM release_report_item \
         WHERE id = $1 FOR UPDATE"
    ))
    .bind(item_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(|r| (r.item, r.values_enc)))
}

/// Moves an item from `from` to `to` under its `row_version` (`If-Match`),
/// recording who decided, and refreshes its report's counts. `Ok(false)`
/// when the item was not in `from` at that version (the caller answers 409).
pub async fn set_status(
    conn: &mut PgConnection,
    item_id: Uuid,
    from: &[ItemStatus],
    to: ItemStatus,
    expected_row_version: Option<i64>,
    actor: Option<Uuid>,
) -> Result<bool, AppError> {
    let from: Vec<&str> = from.iter().map(|s| s.as_str()).collect();
    let report: Option<Uuid> = sqlx::query_scalar(
        "UPDATE release_report_item \
            SET status = $3, decided_by = COALESCE($5, decided_by), \
                decided_at = CASE WHEN $5::uuid IS NULL THEN decided_at ELSE now() END, \
                row_version = row_version + 1 \
          WHERE id = $1 AND status = ANY($2) \
            AND ($4::bigint IS NULL OR row_version = $4) \
          RETURNING report_ref",
    )
    .bind(item_id)
    .bind(&from)
    .bind(to.as_str())
    .bind(expected_row_version)
    .bind(actor)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    match report {
        Some(report_id) => {
            refresh_counts(conn, report_id).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// After an archive row was restored (either Restore route): an
/// archive-backed item with no unrestored, unexpired row left becomes
/// `restored`. In the restore's transaction.
pub async fn on_archive_restored(
    conn: &mut PgConnection,
    item_id: Option<Uuid>,
    actor: Uuid,
) -> Result<(), AppError> {
    let Some(item_id) = item_id else {
        return Ok(());
    };
    let left: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM recovery_archive \
                        WHERE report_item_ref = $1 AND restored_at IS NULL \
                          AND expires_at > now())",
    )
    .bind(item_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if !left {
        set_status(
            conn,
            item_id,
            &[ItemStatus::Open],
            ItemStatus::Restored,
            None,
            Some(actor),
        )
        .await?;
    }
    Ok(())
}

/// The purge's follow-up (design §8.4): an open archive-backed item whose
/// archive rows are all gone (purged) or past their 30 days, none restored
/// since, is `expired`. Returns the items expired.
pub async fn expire_archive_items(db: &DbPool) -> Result<u64, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let reports: Vec<Uuid> = sqlx::query_scalar(
        "WITH gone AS ( \
             UPDATE release_report_item i \
                SET status = 'expired', row_version = i.row_version + 1 \
              WHERE i.status = 'open' AND i.kind IN ('conversion_nulled', 'field_deleted') \
                AND NOT EXISTS (SELECT 1 FROM recovery_archive a \
                                WHERE a.report_item_ref = i.id AND a.restored_at IS NULL \
                                  AND a.expires_at > now()) \
                AND i.created_at < now() - interval '30 days' \
              RETURNING i.report_ref) \
         SELECT DISTINCT report_ref FROM gone",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for report_id in &reports {
        refresh_counts(&mut tx, *report_id).await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(u64::try_from(reports.len()).unwrap_or(u64::MAX))
}

/// DSR erasure: a data subject's record's conflict items (they hold its
/// values) and its baseline rows. In the erasure's own transaction. Returns
/// the items deleted. The erasure path (`attome-compliance`) calls it next to
/// `recovery_archive::erase_record`.
pub async fn erase_record(
    conn: &mut PgConnection,
    entity: &str,
    record_id: Uuid,
) -> Result<u64, AppError> {
    let reports: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT report_ref FROM release_report_item \
         WHERE entity_logicalname = $1 AND record_id = $2",
    )
    .bind(entity)
    .bind(record_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    // An item a later one superseded is pointed at by it: unlink first.
    sqlx::query(
        "UPDATE release_report_item SET superseded_by = NULL \
         WHERE superseded_by IN (SELECT id FROM release_report_item \
                                 WHERE entity_logicalname = $1 AND record_id = $2)",
    )
    .bind(entity)
    .bind(record_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let done = sqlx::query(
        "DELETE FROM release_report_item WHERE entity_logicalname = $1 AND record_id = $2",
    )
    .bind(entity)
    .bind(record_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    sqlx::query("DELETE FROM record_baseline WHERE entity_logicalname = $1 AND record_id = $2")
        .bind(entity)
        .bind(record_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    for report_id in &reports {
        refresh_counts(conn, *report_id).await?;
    }
    Ok(done.rows_affected())
}

// ── Baseline and the three-way rule ─────────────────────────────────────────

/// `sha256:` + hex of a canonical JSON text (the caller canonicalises with
/// RFC 8785, `attome_server::changeset::jcs`).
pub fn hash_text(canonical: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    )
}

/// One baseline row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    /// Our last intended value.
    pub value_hash: String,
    /// The value as stored after our write; `None` when we did not write.
    pub live_hash: Option<String>,
}

/// The baselines of one record, by field.
pub async fn read_baselines(
    conn: &mut PgConnection,
    entity: &str,
    record_id: Uuid,
) -> Result<HashMap<String, Baseline>, AppError> {
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT field_logicalname, value_hash, live_hash FROM record_baseline \
         WHERE entity_logicalname = $1 AND record_id = $2",
    )
    .bind(entity)
    .bind(record_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(field, value_hash, live_hash)| {
            (
                field,
                Baseline {
                    value_hash,
                    live_hash,
                },
            )
        })
        .collect())
}

/// Sets one field's baseline (our intended value, and the stored value when
/// we wrote it), stamped with the operation.
pub async fn write_baseline(
    conn: &mut PgConnection,
    entity: &str,
    record_id: Uuid,
    field: &str,
    baseline: &Baseline,
    op: (Uuid, i32),
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO record_baseline \
             (entity_logicalname, record_id, field_logicalname, value_hash, live_hash, \
              changeset_id, op_seq) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (entity_logicalname, record_id, field_logicalname) DO UPDATE \
            SET value_hash = EXCLUDED.value_hash, live_hash = EXCLUDED.live_hash, \
                changeset_id = EXCLUDED.changeset_id, op_seq = EXCLUDED.op_seq, \
                written_at = now()",
    )
    .bind(entity)
    .bind(record_id)
    .bind(field)
    .bind(&baseline.value_hash)
    .bind(&baseline.live_hash)
    .bind(op.0)
    .bind(op.1)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// After "Use mine" wrote our value: the stored value's hash becomes the
/// baseline's `live_hash` (our intended value is already `value_hash`).
pub async fn set_live_hash(
    conn: &mut PgConnection,
    entity: &str,
    record_id: Uuid,
    field: &str,
    live_hash: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE record_baseline SET live_hash = $4, written_at = now() \
         WHERE entity_logicalname = $1 AND record_id = $2 AND field_logicalname = $3",
    )
    .bind(entity)
    .bind(record_id)
    .bind(field)
    .bind(live_hash)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The record-baseline store as a field reference hook (design §9.1): a
/// rename moves the field's baseline rows to the new name, a delete removes
/// them, in the change's own transaction. Never blocks; owned here with the
/// table's writer, registered in `attome_server::field_hooks`. Rows are hashes,
/// not objects, so `scan` lists none.
#[derive(Debug)]
pub struct RecordBaselineHook;

/// The registered hook name.
pub const RECORD_BASELINE_HOOK: &str = "record_baseline";

impl FieldReferenceHook for RecordBaselineHook {
    fn name(&self) -> &'static str {
        RECORD_BASELINE_HOOK
    }

    fn scan<'a>(
        &'a self,
        _conn: &'a mut PgConnection,
        _entity: &'a str,
        _field: &'a str,
        _renaming: bool,
    ) -> HookFuture<'a, RefScan> {
        Box::pin(async move { Ok(RefScan::default()) })
    }

    fn rename<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        old: &'a str,
        new: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            // A deleted field's name may be reused (Topic 14); its rows went
            // with the delete, but drop any stale row under the new name
            // first so the move cannot hit the primary key.
            sqlx::query(
                "DELETE FROM record_baseline \
                 WHERE entity_logicalname = $1 AND field_logicalname = $2",
            )
            .bind(entity)
            .bind(new)
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            let done = sqlx::query(
                "UPDATE record_baseline SET field_logicalname = $3 \
                 WHERE entity_logicalname = $1 AND field_logicalname = $2",
            )
            .bind(entity)
            .bind(old)
            .bind(new)
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            Ok(HookOutcome {
                touched: done.rows_affected(),
                ..HookOutcome::default()
            })
        })
    }

    fn remove<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            let done = sqlx::query(
                "DELETE FROM record_baseline \
                 WHERE entity_logicalname = $1 AND field_logicalname = $2",
            )
            .bind(entity)
            .bind(field)
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            Ok(HookOutcome {
                touched: done.rows_affected(),
                ..HookOutcome::default()
            })
        })
    }
}

/// What the three-way rule decides for one field (design §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The customer did not change it, we did: write ours; baseline := ours.
    Write,
    /// Nothing to write, but the baseline becomes ours (ours already equals
    /// the live value, or no baseline existed and they agree).
    Rebase,
    /// Nothing changed on either side.
    Noop,
    /// The customer changed it, we did not: keep theirs, nothing reported.
    KeepTheirs,
    /// Both changed it and differ: keep theirs; baseline := ours; report.
    Conflict,
}

/// The three-way rule for one field. `live_hash`/`ours_hash` are the
/// [`hash_text`] of the live and our value; `live_eq_ours` is their value
/// equality (the same comparison the write path makes); `baseline` is the
/// field's row, if any.
pub fn decide(
    live_hash: &str,
    ours_hash: &str,
    live_eq_ours: bool,
    baseline: Option<&Baseline>,
) -> Decision {
    let Some(b) = baseline else {
        // First apply on data that predates baselines: the customer is taken
        // to have changed it whenever it differs from ours (§9.2, last row).
        return if live_eq_ours {
            Decision::Rebase
        } else {
            Decision::Conflict
        };
    };
    let customer_changed = live_hash != b.live_hash.as_deref().unwrap_or(&b.value_hash);
    let we_changed = ours_hash != b.value_hash;
    match (customer_changed, we_changed) {
        (false, true) if live_eq_ours => Decision::Rebase,
        (false, true) => Decision::Write,
        (false, false) => Decision::Noop,
        (true, false) => Decision::KeepTheirs,
        (true, true) if live_eq_ours => Decision::Rebase,
        (true, true) => Decision::Conflict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn h(s: &str) -> String {
        hash_text(s)
    }

    fn base(value: &str, live: Option<&str>) -> Baseline {
        Baseline {
            value_hash: h(value),
            live_hash: live.map(h),
        }
    }

    #[test]
    fn the_three_way_rule_matches_the_design_table() {
        // §9.2 row 1: customer did not change it, we did.
        let b = base("\"a\"", Some("\"a\""));
        assert_eq!(
            decide(&h("\"a\""), &h("\"b\""), false, Some(&b)),
            Decision::Write
        );
        // Row 2: neither changed.
        assert_eq!(
            decide(&h("\"a\""), &h("\"a\""), true, Some(&b)),
            Decision::Noop
        );
        // Row 3: the customer changed it, we did not.
        assert_eq!(
            decide(&h("\"c\""), &h("\"a\""), false, Some(&b)),
            Decision::KeepTheirs
        );
        // Row 4: both changed it to the same value.
        assert_eq!(
            decide(&h("\"b\""), &h("\"b\""), true, Some(&b)),
            Decision::Rebase
        );
        // Row 5: both changed it, differently: the customer wins.
        assert_eq!(
            decide(&h("\"c\""), &h("\"b\""), false, Some(&b)),
            Decision::Conflict
        );
        // Row 6: no baseline (data predates baselines).
        assert_eq!(
            decide(&h("\"c\""), &h("\"b\""), false, None),
            Decision::Conflict
        );
        assert_eq!(
            decide(&h("\"b\""), &h("\"b\""), true, None),
            Decision::Rebase
        );
    }

    #[test]
    fn the_stored_form_decides_whether_the_customer_changed_it() {
        // We wrote 2 (intended `2`), the database reads it back as `2.0`:
        // reading `2.0` again is not a customer change.
        let b = base("2", Some("2.0"));
        assert_eq!(decide(&h("2.0"), &h("3"), false, Some(&b)), Decision::Write);
        // Without a stored form (we did not write: a kept conflict), our
        // intended value is compared instead.
        let kept = base("2", None);
        assert_eq!(
            decide(&h("5"), &h("2"), false, Some(&kept)),
            Decision::KeepTheirs
        );
        assert_eq!(
            decide(&h("5"), &h("3"), false, Some(&kept)),
            Decision::Conflict
        );
    }

    #[test]
    fn sealed_values_open_only_for_their_item() {
        let ring = KeyRing::single("cd".repeat(32));
        let id = Uuid::now_v7();
        let values = ConflictValues {
            theirs: json!("Kingdom of Bahrain"),
            ours: json!("Bahrain"),
            key: Some(json!({ "code": "BH" })),
        };
        let sealed = seal(&ring, id, &values).expect("seal");
        assert!(!sealed.windows(7).any(|w| w == b"Bahrain"), "not in clear");
        assert_eq!(open_values(&ring, id, &sealed).expect("open"), values);
        assert!(matches!(
            open_values(&ring, Uuid::now_v7(), &sealed),
            Err(AppError::Conflict(REPORT_VALUES_UNREADABLE))
        ));
    }

    #[test]
    fn kinds_and_statuses_round_trip() {
        for k in ItemKind::ALL {
            assert_eq!(ItemKind::parse(k.as_str()), Some(k));
        }
        for s in ItemStatus::ALL {
            assert_eq!(ItemStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(ItemStatus::initial(ItemKind::Conflict), ItemStatus::Open);
        assert_eq!(
            ItemStatus::initial(ItemKind::BreakingApiChange),
            ItemStatus::Info
        );
        assert!(ItemKind::FieldDeleted.archive_backed());
        assert!(!ItemKind::Conflict.archive_backed());
        assert!(ReportSource::Admin.notifies());
        assert!(!ReportSource::Change.notifies());
    }

    #[test]
    fn a_draft_becomes_an_item_and_an_unknown_kind_does_not() {
        let draft = ReportItemDraft {
            kind: "customer_object_adjusted",
            entity: "account".into(),
            field: Some("rating".into()),
            object_kind: Some("view".into()),
            object_ref: Some(Uuid::now_v7()),
            detail: json!({ "changed": "column removed" }),
        };
        let item = NewItem::from_draft(&draft, None).expect("a report kind");
        assert_eq!(item.kind, ItemKind::CustomerObjectAdjusted);
        assert_eq!(item.object_kind.as_deref(), Some("view"));
        let odd = ReportItemDraft {
            kind: "something_else",
            ..draft
        };
        assert!(NewItem::from_draft(&odd, None).is_none());
    }

    #[tokio::test]
    async fn the_scope_carries_the_report() {
        assert!(current().is_none());
        let ctx = ReportCtx {
            report_id: Uuid::now_v7(),
            op: Some((Uuid::now_v7(), 3)),
        };
        let seen = scope(ctx, async { current() }).await;
        assert_eq!(seen, Some(ctx));
        let inner = scope(ctx, async {
            scope(ReportCtx { op: None, ..ctx }, async { current() }).await
        })
        .await;
        assert_eq!(inner.map(|c| c.op), Some(None), "the inner scope wins");
    }
}
