//! The applied-changeset ledger — `changeset_apply` (migration 0522,
//! Solution 7 design §2.4, §5).
//!
//! One row per (changeset, phase) applied to this deployment, whatever
//! applied it: boot (platform changesets), an admin apply, adopt, or the
//! replay tool. `UNIQUE (changeset_id, phase)` holds for a changeset's whole
//! life: a failed row is retried in place (`failed -> queued`), and a row
//! whose checksum differs from a document planned under the same id is the
//! checksum refusal (§5.4, D-785 rule 4).
//!
//! Lifecycle: `planned` (plan route or boot) -> `queued` (apply route, an
//! approved `metadata.changeset_apply`, or boot) -> `claimed` -> `applying`
//! (cursor advanced after each committed step) -> `succeeded` | `failed`.
//! `adopted` is terminal and written only by adopt (§5.6). The claim,
//! advance and mark statements are the bundle ledger's, shared through
//! [`crate::bundle::ledger::shared`] (§5.1).
//!
//! Every statement binds its values and enumerates its columns.

use attome_core::EngineState;
use attome_db::{DbPool, Tx};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::bundle::ledger::{LedgerTable, shared};

/// `changeset_checksum_mismatch`: a changeset id this deployment already has
/// a ledger row for arrived with a different checksum — the file changed
/// after it was applied (or planned). Refused for the whole plan; the fix is
/// a new changeset (D-710's rule, applied to changesets).
pub const CHANGESET_CHECKSUM_MISMATCH: &str = "changeset_checksum_mismatch: a changeset with this \
     id is already in this deployment's ledger with a different checksum; a changeset is \
     immutable once planned or applied — make the change in a new changeset";

/// `backup_ref_required`: the production profile applies only against a
/// verified backup the operator names (design §5.5).
pub const BACKUP_REF_REQUIRED: &str = "backup_ref_required: on the production profile an apply \
     must name the verified backup taken before it (backup_ref)";

/// The phase a ledger row covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplyPhase {
    Expand,
    Contract,
}

impl ApplyPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Expand => "expand",
            Self::Contract => "contract",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "expand" => Some(Self::Expand),
            "contract" => Some(Self::Contract),
            _ => None,
        }
    }
}

/// `changeset_apply.status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStatus {
    Planned,
    Queued,
    Claimed,
    Applying,
    Succeeded,
    Failed,
    Adopted,
}

impl ApplyStatus {
    pub const ALL: [Self; 7] = [
        Self::Planned,
        Self::Queued,
        Self::Claimed,
        Self::Applying,
        Self::Succeeded,
        Self::Failed,
        Self::Adopted,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Queued => "queued",
            Self::Claimed => "claimed",
            Self::Applying => "applying",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Adopted => "adopted",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == value)
    }

    /// The changeset's effects are in place (`already_applied`).
    pub const fn is_done(self) -> bool {
        matches!(self, Self::Succeeded | Self::Adopted)
    }
}

/// `changeset_apply.source`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplySource {
    Boot,
    Admin,
    Adopt,
    Replay,
}

impl ApplySource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Admin => "admin",
            Self::Adopt => "adopt",
            Self::Replay => "replay",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        [Self::Boot, Self::Admin, Self::Adopt, Self::Replay]
            .into_iter()
            .find(|s| s.as_str() == value)
    }
}

/// One ledger row with its document and plan.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct LedgerRow {
    pub id: Uuid,
    pub changeset_id: Uuid,
    /// `<layer>/<scope>/<NNNN>-<name>`.
    #[serde(rename = "ref")]
    pub changeset_ref: String,
    pub layer: String,
    pub scope: String,
    pub seq: i32,
    pub phase: ApplyPhase,
    pub checksum: String,
    #[schema(value_type = Object)]
    pub document: Value,
    #[schema(value_type = Object)]
    pub plan: Value,
    pub status: ApplyStatus,
    pub source: ApplySource,
    pub platform_version: String,
    pub backup_ref: Option<String>,
    pub requested_by: Option<Uuid>,
    pub approval_ref: Option<Uuid>,
    pub claimed_at: Option<DateTime<Utc>>,
    /// Index of the next operation to apply; a resumed run starts here.
    pub cursor: i32,
    pub applied_count: i32,
    pub error_message: Option<String>,
    pub finished_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
}

/// Enumerated, never `*`, in `RawRow`'s field order.
pub(crate) const APPLY_COLUMNS: &str = "id, changeset_id, ref AS changeset_ref, layer, scope, \
     seq, phase, checksum, document, plan, status, source, platform_version, backup_ref, \
     requested_by, approval_ref, claimed_at, cursor, applied_count, error_message, finished_at, \
     created_at, updated_at, row_version";

#[derive(sqlx::FromRow)]
pub(crate) struct RawRow {
    id: Uuid,
    changeset_id: Uuid,
    changeset_ref: String,
    layer: String,
    scope: String,
    seq: i32,
    phase: String,
    checksum: String,
    document: Value,
    plan: Value,
    status: String,
    source: String,
    platform_version: String,
    backup_ref: Option<String>,
    requested_by: Option<Uuid>,
    approval_ref: Option<Uuid>,
    claimed_at: Option<DateTime<Utc>>,
    cursor: i32,
    applied_count: i32,
    error_message: Option<String>,
    finished_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    row_version: i64,
}

impl TryFrom<RawRow> for LedgerRow {
    type Error = AppError;

    fn try_from(r: RawRow) -> Result<Self, AppError> {
        // The table's CHECK constraints make these unreachable; a failure
        // means the schema and this code disagree.
        let unknown = |column: &str, value: &str| {
            AppError::internal(format!(
                "changeset_apply.{column} holds an unknown value {value:?}"
            ))
        };
        Ok(Self {
            id: r.id,
            changeset_id: r.changeset_id,
            changeset_ref: r.changeset_ref,
            layer: r.layer,
            scope: r.scope,
            seq: r.seq,
            phase: ApplyPhase::parse(&r.phase).ok_or_else(|| unknown("phase", &r.phase))?,
            checksum: r.checksum,
            document: r.document,
            plan: r.plan,
            status: ApplyStatus::parse(&r.status).ok_or_else(|| unknown("status", &r.status))?,
            source: ApplySource::parse(&r.source).ok_or_else(|| unknown("source", &r.source))?,
            platform_version: r.platform_version,
            backup_ref: r.backup_ref,
            requested_by: r.requested_by,
            approval_ref: r.approval_ref,
            claimed_at: r.claimed_at,
            cursor: r.cursor,
            applied_count: r.applied_count,
            error_message: r.error_message,
            finished_at: r.finished_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
            row_version: r.row_version,
        })
    }
}

/// What a plan writes for one (changeset, phase).
#[derive(Debug, Clone)]
pub struct NewApplyRow<'a> {
    pub changeset_id: Uuid,
    pub changeset_ref: &'a str,
    pub layer: &'a str,
    pub scope: &'a str,
    pub seq: i32,
    pub phase: ApplyPhase,
    pub checksum: &'a str,
    pub document: &'a Value,
    pub plan: &'a Value,
    pub status: ApplyStatus,
    pub source: ApplySource,
    pub platform_version: &'a str,
    pub requested_by: Option<Uuid>,
}

/// The ledger row for `(changeset_id, phase)`, if any.
pub async fn find(
    conn: &mut PgConnection,
    changeset_id: Uuid,
    phase: ApplyPhase,
) -> Result<Option<LedgerRow>, AppError> {
    let raw: Option<RawRow> = sqlx::query_as(&format!(
        "SELECT {APPLY_COLUMNS} FROM changeset_apply \
         WHERE changeset_id = $1 AND phase = $2"
    ))
    .bind(changeset_id)
    .bind(phase.as_str())
    .fetch_optional(conn)
    .await
    .map_err(AppError::internal)?;
    raw.map(LedgerRow::try_from).transpose()
}

/// Every ledger row of `changeset_id` (both phases), `(phase, checksum,
/// status)` — the checksum refusal's lookup.
pub async fn checksums_of(
    conn: &mut PgConnection,
    changeset_id: Uuid,
) -> Result<Vec<(ApplyPhase, String, ApplyStatus)>, AppError> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT phase, checksum, status FROM changeset_apply WHERE changeset_id = $1",
    )
    .bind(changeset_id)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)?;
    rows.into_iter()
        .map(|(phase, checksum, status)| {
            let phase = ApplyPhase::parse(&phase)
                .ok_or_else(|| AppError::internal(format!("unknown ledger phase {phase:?}")))?;
            let status = ApplyStatus::parse(&status)
                .ok_or_else(|| AppError::internal(format!("unknown ledger status {status:?}")))?;
            Ok((phase, checksum, status))
        })
        .collect()
}

/// One row by id.
pub async fn get(db: &DbPool, id: Uuid) -> Result<Option<LedgerRow>, AppError> {
    let raw: Option<RawRow> = sqlx::query_as(&format!(
        "SELECT {APPLY_COLUMNS} FROM changeset_apply WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    raw.map(LedgerRow::try_from).transpose()
}

/// Inserts a new row, or — for a row that is still only `planned` or
/// `failed` under the same checksum — replaces its plan (a re-plan; a failed
/// row keeps its cursor so the retry resumes). Returns the row id and its
/// status after the write. The caller has already refused a different
/// checksum and reported a done row as `already_applied`.
pub async fn upsert_planned(tx: &mut Tx<'_>, new: &NewApplyRow<'_>) -> Result<Uuid, AppError> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO changeset_apply \
             (changeset_id, ref, layer, scope, seq, phase, checksum, document, plan, status, \
              source, platform_version, requested_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         ON CONFLICT (changeset_id, phase) DO UPDATE \
            SET plan = EXCLUDED.plan, source = EXCLUDED.source, \
                platform_version = EXCLUDED.platform_version, \
                requested_by = EXCLUDED.requested_by, \
                status = CASE WHEN changeset_apply.status = 'failed' \
                              THEN 'failed' ELSE EXCLUDED.status END, \
                row_version = changeset_apply.row_version + 1, updated_at = NOW() \
          WHERE changeset_apply.checksum = EXCLUDED.checksum \
            AND changeset_apply.status IN ('planned', 'failed') \
         RETURNING id",
    )
    .bind(new.changeset_id)
    .bind(new.changeset_ref)
    .bind(new.layer)
    .bind(new.scope)
    .bind(new.seq)
    .bind(new.phase.as_str())
    .bind(new.checksum)
    .bind(new.document)
    .bind(new.plan)
    .bind(new.status.as_str())
    .bind(new.source.as_str())
    .bind(new.platform_version)
    .bind(new.requested_by)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    // No row: an existing row with a different checksum, or one past
    // planning (queued, running, done). Both were meant to be caught first.
    id.ok_or(AppError::Conflict(
        "changeset apply row is already queued, running or finished; plan it again only after \
         it finishes",
    ))
}

/// Inserts an `adopted` row (design §5.6). `Ok(false)` when the
/// `(changeset_id, phase)` row exists already.
pub async fn insert_adopted(tx: &mut Tx<'_>, new: &NewApplyRow<'_>) -> Result<bool, AppError> {
    let inserted = sqlx::query(
        "INSERT INTO changeset_apply \
             (changeset_id, ref, layer, scope, seq, phase, checksum, document, plan, status, \
              source, platform_version, requested_by, finished_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'adopted', 'adopt', $10, $11, NOW()) \
         ON CONFLICT (changeset_id, phase) DO NOTHING",
    )
    .bind(new.changeset_id)
    .bind(new.changeset_ref)
    .bind(new.layer)
    .bind(new.scope)
    .bind(new.seq)
    .bind(new.phase.as_str())
    .bind(new.checksum)
    .bind(new.document)
    .bind(new.plan)
    .bind(new.platform_version)
    .bind(new.requested_by)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(inserted == 1)
}

/// `planned|failed -> queued` for every id, recording the authorizing
/// approval and the backup reference. Returns how many rows moved.
pub async fn mark_queued(
    conn: &mut PgConnection,
    ids: &[Uuid],
    approval_ref: Option<Uuid>,
    backup_ref: Option<&str>,
) -> Result<u64, AppError> {
    Ok(sqlx::query(
        "UPDATE changeset_apply \
            SET status = 'queued', approval_ref = COALESCE($2, approval_ref), \
                backup_ref = COALESCE($3, backup_ref), error_message = NULL, \
                finished_at = NULL, row_version = row_version + 1, updated_at = NOW() \
          WHERE id = ANY($1) AND status IN ('planned', 'failed')",
    )
    .bind(ids)
    .bind(approval_ref)
    .bind(backup_ref)
    .execute(conn)
    .await
    .map_err(AppError::internal)?
    .rows_affected())
}

/// The queue dedup key of one apply run: the ids, in order, hashed (two
/// enqueues of the same run — an approval executed then retried — collapse).
pub(crate) fn apply_dedup_key(ids: &[Uuid]) -> String {
    let mut h = Sha256::new();
    for id in ids {
        h.update(id.as_bytes());
    }
    format!("changeset-apply:{}", hex::encode(h.finalize()))
}

/// Queues `ids` (`planned|failed -> queued`) and enqueues
/// `EngineJob::ApplyChangesets` in ONE transaction. A row already
/// `queued` stays queued; any other status is a conflict (running or done).
pub async fn enqueue_apply(
    state: &EngineState,
    ids: &[Uuid],
    approval_ref: Option<Uuid>,
    backup_ref: Option<&str>,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    mark_queued(&mut tx, ids, approval_ref, backup_ref).await?;
    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM changeset_apply WHERE id = ANY($1) AND status = 'queued'",
    )
    .bind(ids)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if usize::try_from(queued).unwrap_or(0) != ids.len() {
        tx.rollback().await.map_err(AppError::internal)?;
        return Err(AppError::Conflict(
            "a changeset apply row is missing, still running or already finished",
        ));
    }
    attome_jobs::enqueue_in_tx_dedup(
        &mut tx,
        attome_core::jobs::EngineJob::ApplyChangesets {
            apply_ids: ids.to_vec(),
        },
        &apply_dedup_key(ids),
    )
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await
}

/// Row-CAS claim (the bundle ledger's scheme).
pub async fn claim(db: &DbPool, id: Uuid, worker: &str) -> Result<Option<LedgerRow>, AppError> {
    let raw: Option<RawRow> =
        shared::claim(db, LedgerTable::ChangesetApply, APPLY_COLUMNS, id, worker).await?;
    raw.map(LedgerRow::try_from).transpose()
}

/// Progress after one committed step.
pub async fn advance(
    db: &DbPool,
    id: Uuid,
    cursor: i32,
    applied_count: i32,
) -> Result<(), AppError> {
    shared::advance(db, LedgerTable::ChangesetApply, id, cursor, applied_count).await
}

pub async fn mark_succeeded(db: &DbPool, id: Uuid) -> Result<(), AppError> {
    shared::mark_succeeded(db, LedgerTable::ChangesetApply, id).await
}

pub async fn mark_failed(db: &DbPool, id: Uuid, error: &str) -> Result<(), AppError> {
    shared::mark_failed(db, LedgerTable::ChangesetApply, id, error).await
}

/// `GET …/ledger` filters.
#[derive(Debug, Default, Clone)]
pub struct LedgerFilter {
    pub layer: Option<String>,
    pub scope: Option<String>,
    pub status: Option<String>,
}

const LIST_FILTER: &str = "($1::text IS NULL OR layer = $1) AND ($2::text IS NULL OR scope = $2) \
     AND ($3::text IS NULL OR status = $3)";

/// One page of the ledger, newest first, and the total.
pub async fn list(
    db: &DbPool,
    filter: &LedgerFilter,
    limit: i64,
    offset: i64,
) -> Result<(Vec<LedgerRow>, i64), AppError> {
    let raw: Vec<RawRow> = sqlx::query_as(&format!(
        "SELECT {APPLY_COLUMNS} FROM changeset_apply WHERE {LIST_FILTER} \
         ORDER BY created_at DESC, id DESC LIMIT $4 OFFSET $5"
    ))
    .bind(&filter.layer)
    .bind(&filter.scope)
    .bind(&filter.status)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM changeset_apply WHERE {LIST_FILTER}"
    ))
    .bind(&filter.layer)
    .bind(&filter.scope)
    .bind(&filter.status)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let rows = raw
        .into_iter()
        .map(LedgerRow::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((rows, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_round_trip_through_their_column_values() {
        for status in ApplyStatus::ALL {
            assert_eq!(ApplyStatus::parse(status.as_str()), Some(status));
            assert_eq!(
                serde_json::to_value(status).ok(),
                Some(Value::String(status.as_str().to_owned()))
            );
        }
        assert!(ApplyStatus::Adopted.is_done());
        assert!(ApplyStatus::Succeeded.is_done());
        assert!(!ApplyStatus::Failed.is_done());
        for phase in [ApplyPhase::Expand, ApplyPhase::Contract] {
            assert_eq!(ApplyPhase::parse(phase.as_str()), Some(phase));
        }
        for source in [
            ApplySource::Boot,
            ApplySource::Admin,
            ApplySource::Adopt,
            ApplySource::Replay,
        ] {
            assert_eq!(ApplySource::parse(source.as_str()), Some(source));
        }
    }

    #[test]
    fn the_dedup_key_is_per_run_and_order_sensitive() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        assert_eq!(apply_dedup_key(&[a, b]), apply_dedup_key(&[a, b]));
        assert_ne!(apply_dedup_key(&[a, b]), apply_dedup_key(&[b, a]));
        assert!(apply_dedup_key(&[a]).starts_with("changeset-apply:"));
    }

    #[test]
    fn the_refusal_messages_start_with_their_stable_codes() {
        use attome_core::changeset::errors::code_of;
        assert_eq!(
            code_of(CHANGESET_CHECKSUM_MISMATCH),
            "changeset_checksum_mismatch"
        );
        assert_eq!(code_of(BACKUP_REF_REQUIRED), "backup_ref_required");
    }
}
