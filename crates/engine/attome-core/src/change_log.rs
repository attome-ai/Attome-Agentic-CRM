//! Append-only `metadata_change_log` (Plan 1.14) — the source of truth
//! for *what* changed, so a subscriber can patch one entity's key in
//! `EntityMetaRegistry` instead of rebuilding the whole thing on every edit.
//! Redis `meta_version` pub/sub (Plan 1.2) stays wired up, but only as a
//! doorbell — see `attome-server/src/system.rs` for the catch-up loop that
//! actually reads this table. See DECISIONS.md D-025.

use attome_db::{DbPool, Tx};
use attome_types::AppError;
use uuid::Uuid;

/// Fixed, platform-wide advisory-lock key — never per-entity. Every
/// metadata-write transaction takes this lock first, serializing all
/// metadata writes so `metadata_change_log.id` order always matches
/// commit order. Without this, a subscriber watermarking by "highest id
/// seen" could permanently skip a row that commits late relative to a
/// higher-id row from a concurrent transaction. Cheap to serialize globally:
/// metadata writes are rare, admin-only operations.
///
/// Renamed from `..._NAMESPACE` when the two-argument advisory-lock form
/// landed (L-1 / TODO-027): "namespace" now means the `int4`
/// [`crate::ADVISORY_LOCK_NAMESPACE`] this key is hashed under, not the key
/// string itself.
const METADATA_WRITE_LOCK_KEY: &str = "attome-core/metadata-write";

#[derive(Clone, Copy, Debug)]
pub enum ChangeKind {
    /// Re-fetch `entity_ref`'s current row + active attributes and replace
    /// `registry[logicalname]`. Covers entity create/update and every
    /// attribute create/update/delete — the owning entity still exists.
    Upsert,
    /// Remove `registry[logicalname]` outright — entity soft- or
    /// hard-deleted. `logicalname` is carried on the row itself since a
    /// hard-deleted entity can no longer be re-queried.
    Delete,
}

impl ChangeKind {
    fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Upsert => "upsert",
            ChangeKind::Delete => "delete",
        }
    }
}

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct ChangeLogRow {
    pub id: i64,
    pub entity_ref: Uuid,
    pub logicalname: String,
    #[sqlx(rename = "change_kind")]
    pub kind: String,
}

/// Acquires the global metadata-write lock inside `tx`. Must be the first
/// statement of the transaction (Layer 2, guidelines §2) — call before any
/// metadata mutation. Non-blocking; returns `Conflict` rather than waiting,
/// matching `pg_try_advisory_xact_lock`'s semantics elsewhere in this
/// codebase (e.g. `s2s_admin.rs`).
///
/// C-18 — delegates to the crate-wide [`crate::try_xact_lock`] shared body;
/// this wrapper keeps its own fixed key and wording so no call site changes.
pub async fn acquire_metadata_write_lock(tx: &mut Tx<'_>) -> Result<(), AppError> {
    crate::try_xact_lock(
        tx,
        METADATA_WRITE_LOCK_KEY,
        "a metadata write is already in progress",
    )
    .await
}

/// Y8-T1: the Postgres channel every metadata change rings, with the new
/// change-log id as its payload.
pub const METADATA_CHANGE_CHANNEL: &str = "attome_metadata_change";

/// Appends one row to `metadata_change_log`. Call as the last statement
/// before `commit()` so the row and the metadata change it describes always
/// land in the same transaction. It also rings [`METADATA_CHANGE_CHANNEL`]
/// in that transaction (Y8-T1), so other nodes hear of it on commit, with or
/// without Redis.
pub async fn append_change_log(
    tx: &mut Tx<'_>,
    entity_ref: Uuid,
    logicalname: &str,
    kind: ChangeKind,
) -> Result<i64, AppError> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO metadata_change_log (entity_ref, logicalname, change_kind) \
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(entity_ref)
    .bind(logicalname)
    .bind(kind.as_str())
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(METADATA_CHANGE_CHANNEL)
        .bind(id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    Ok(id)
}

/// Highest committed id in `table` — the watermark shape every
/// `*_log_watermark` function in this crate shares (this module's own
/// [`log_watermark`], `setting_store::setting_log_watermark`,
/// `label_store::label_log_watermark`, C-18). `table` is always a
/// code-literal constant the caller hardcodes at its own call site, never
/// derived from request input — a plain Rust string literal, not the
/// "dynamic identifier" guidelines §4 gates behind validated metadata +
/// `quote_ident`.
pub(crate) async fn change_log_watermark(db: &DbPool, table: &str) -> Result<i64, AppError> {
    let sql = format!("SELECT COALESCE(MAX(id), 0) FROM {table}");
    sqlx::query_scalar(&sql)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// Highest committed log id right now. Callers building a full-rebuild
/// baseline MUST read this *before* reading `entity_info`/
/// `attribute_info` — see `attome-server::system::full_rebuild` for why
/// that order is the one that keeps the returned id a safe lower bound.
pub async fn log_watermark(db: &DbPool) -> Result<i64, AppError> {
    change_log_watermark(db, "metadata_change_log").await
}

/// Rows strictly after `after_id`, oldest first, capped at `limit`. Callers
/// loop (re-calling with the new max id as `after_id`) while a batch comes
/// back full, to bound a single query's cost during a large catch-up.
pub async fn changes_since(
    db: &DbPool,
    after_id: i64,
    limit: i64,
) -> Result<Vec<ChangeLogRow>, AppError> {
    sqlx::query_as(
        "SELECT id, entity_ref, logicalname, change_kind \
         FROM metadata_change_log WHERE id > $1 ORDER BY id LIMIT $2",
    )
    .bind(after_id)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}
