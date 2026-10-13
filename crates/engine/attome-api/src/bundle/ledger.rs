//! The plan/apply ledger — `metadata_bundle_plan` (migration 0134,
//! P-environment-promotion §4 "Durable job with a ledger, not one giant
//! transaction" / §5 step 11).
//!
//! One row per plan. `import?mode=plan` inserts it as `planned`; an apply
//! (directly on the development profile, or through an approved
//! `metadata.bundle_apply` request in production) moves it to `queued` and
//! enqueues [`attome_core::jobs::EngineJob::ApplyMetadataBundle`]; the worker
//! claims it (`claimed`), walks the plan's entries advancing `cursor` after
//! each object's own short transaction (`applying`), and closes it as
//! `succeeded` or `failed`. The set of `succeeded` rows IS the applied-bundle
//! history; the newest of them is "the last applied bundle"
//! ([`latest_succeeded`]).
//!
//! The claim is a row-CAS with a stale-claim timeout, the same shape
//! `attome_metadata::provision::schema_change`'s `claim_schema_change_plan` and
//! D-100's staged-import item ledger use — never a session advisory lock
//! (guidelines §2). A worker that loses the race simply returns; the one that
//! holds the claim is the one making progress, and a claim that has been
//! silent for [`CLAIM_TIMEOUT`] may be taken over by a later pass, which
//! resumes from `cursor` rather than restarting.
//!
//! Every statement here binds its values and enumerates its columns; this
//! file issues only row reads and writes against the ledger itself.

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// `attome_approval` action type for applying a bundle on a production
/// profile (`KNOWN_ACTION_TYPES` + `PRODUCTION_MANDATORY_ACTIONS`, plan §4
/// "Production change control"). The approval payload carries
/// `{ "plan_id": <uuid>, ... }` — `approval_admin::execute_approved` queues
/// that plan through `routes::do_apply_plan` ([`mark_queued`] then
/// [`enqueue_apply`]) once approved, the same path the ungated route takes.
pub const ACTION_BUNDLE_APPLY: &str = "metadata.bundle_apply";

/// How long a `claimed`/`applying` row may sit with no progress update
/// before a second worker pass may reclaim it. Same value and same
/// "generous relative to one object's DDL, short relative to a release
/// cycle" reasoning as `SCHEMA_CHANGE_CLAIM_TIMEOUT` in attome-metadata. The
/// predicate requires both `claimed_at` AND `updated_at` (touched by every
/// [`advance`]) to be older than this, so a long but live apply — one that
/// is still committing objects — is never falsely reclaimed mid-flight.
pub const CLAIM_TIMEOUT: &str = "30 minutes";

/// Dedup key for the apply job, so two enqueues for one plan (an approval
/// executed and then retried, two admin clicks) collapse to one queue row.
fn apply_dedup_key(plan_id: Uuid) -> String {
    format!("bundle-apply:{plan_id}")
}

/// `error_message` is bounded so a pathological reconcile error (one that
/// quotes a whole bundle object, say) cannot bloat the ledger row.
const MAX_ERROR_MESSAGE_CHARS: usize = 4_000;

/// Lifecycle of one plan row. The string form is the `status` column value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Planned,
    Queued,
    Claimed,
    Applying,
    Succeeded,
    Failed,
}

impl PlanStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Queued => "queued",
            Self::Claimed => "claimed",
            Self::Applying => "applying",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    /// Terminal rows are never claimed, advanced, or re-marked.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }

    fn parse(value: &str) -> Result<Self, AppError> {
        Ok(match value {
            "planned" => Self::Planned,
            "queued" => Self::Queued,
            "claimed" => Self::Claimed,
            "applying" => Self::Applying,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            other => {
                return Err(AppError::internal(format!(
                    "metadata_bundle_plan.status holds an unknown value {other:?}"
                )));
            }
        })
    }
}

impl std::fmt::Display for PlanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One ledger row as the routes and the apply job see it. `bundle` and
/// `plan` are the JSON snapshots frozen at plan time (see the migration's
/// header for why they are stored rather than re-fetched).
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct PlanRow {
    pub id: Uuid,
    pub status: PlanStatus,
    #[schema(value_type = Object)]
    pub bundle: serde_json::Value,
    #[schema(value_type = Object)]
    pub plan: serde_json::Value,
    pub bundle_hash: String,
    pub basis_hash: String,
    pub format_version: String,
    pub platform_version: String,
    pub allow_retire: bool,
    pub requested_by: Option<Uuid>,
    pub approval_ref: Option<Uuid>,
    /// Index of the next plan entry to apply; a resumed run starts here.
    pub cursor: i32,
    pub applied_count: i32,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// Enumerated, never `*` — every read below selects exactly this list, in
/// `RawPlanRow`'s field order.
const PLAN_COLUMNS: &str = "id, status, bundle, plan, bundle_hash, basis_hash, format_version, \
     platform_version, allow_retire, requested_by, approval_ref, cursor, applied_count, \
     error_message, created_at, claimed_at, finished_at";

/// The wire shape of a row straight from sqlx; `status` is decoded into
/// [`PlanStatus`] by `TryFrom` so an unexpected column value surfaces as an
/// `Internal` error instead of a decode panic.
#[derive(sqlx::FromRow)]
struct RawPlanRow {
    id: Uuid,
    status: String,
    bundle: serde_json::Value,
    plan: serde_json::Value,
    bundle_hash: String,
    basis_hash: String,
    format_version: String,
    platform_version: String,
    allow_retire: bool,
    requested_by: Option<Uuid>,
    approval_ref: Option<Uuid>,
    cursor: i32,
    applied_count: i32,
    error_message: Option<String>,
    created_at: DateTime<Utc>,
    claimed_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
}

impl TryFrom<RawPlanRow> for PlanRow {
    type Error = AppError;

    fn try_from(raw: RawPlanRow) -> Result<Self, AppError> {
        Ok(PlanRow {
            id: raw.id,
            status: PlanStatus::parse(&raw.status)?,
            bundle: raw.bundle,
            plan: raw.plan,
            bundle_hash: raw.bundle_hash,
            basis_hash: raw.basis_hash,
            format_version: raw.format_version,
            platform_version: raw.platform_version,
            allow_retire: raw.allow_retire,
            requested_by: raw.requested_by,
            approval_ref: raw.approval_ref,
            cursor: raw.cursor,
            applied_count: raw.applied_count,
            error_message: raw.error_message,
            created_at: raw.created_at,
            claimed_at: raw.claimed_at,
            finished_at: raw.finished_at,
        })
    }
}

/// Inserts a `planned` row and returns its id. `bundle`/`plan` are stored as
/// given — the caller (`import?mode=plan`) has already parsed, hashed, and
/// planned them; this function never re-derives either.
#[allow(clippy::too_many_arguments)]
pub async fn insert_plan(
    db: &DbPool,
    bundle: &serde_json::Value,
    plan: &serde_json::Value,
    bundle_hash: &str,
    basis_hash: &str,
    format_version: &str,
    platform_version: &str,
    allow_retire: bool,
    requested_by: Option<Uuid>,
) -> Result<Uuid, AppError> {
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO metadata_bundle_plan
               (status, bundle, plan, bundle_hash, basis_hash, format_version,
                platform_version, allow_retire, requested_by)
           VALUES ('planned', $1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id"#,
    )
    .bind(bundle)
    .bind(plan)
    .bind(bundle_hash)
    .bind(basis_hash)
    .bind(format_version)
    .bind(platform_version)
    .bind(allow_retire)
    .bind(requested_by)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(id)
}

/// One row by id, or `None` when there is no such plan.
pub async fn get_plan(db: &DbPool, id: Uuid) -> Result<Option<PlanRow>, AppError> {
    let raw: Option<RawPlanRow> = sqlx::query_as(&format!(
        "SELECT {PLAN_COLUMNS} FROM metadata_bundle_plan WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    raw.map(PlanRow::try_from).transpose()
}

/// Newest first, at most `limit` rows (clamped to `1..=MAX_LIST_LIMIT`),
/// optionally filtered to one `status` (M92 Phase 1 — the lifecycle UI's
/// "pending plans" view is `status = planned` or `queued`). This list,
/// unfiltered and restricted to `succeeded`, is the applied-bundle history.
pub async fn list_plans(
    db: &DbPool,
    limit: i64,
    status: Option<PlanStatus>,
) -> Result<Vec<PlanRow>, AppError> {
    let limit = limit.clamp(1, MAX_LIST_LIMIT);
    let raw: Vec<RawPlanRow> = match status {
        Some(s) => {
            sqlx::query_as(&format!(
                "SELECT {PLAN_COLUMNS} FROM metadata_bundle_plan \
                 WHERE status = $1 ORDER BY created_at DESC, id DESC LIMIT $2"
            ))
            .bind(s.as_str())
            .bind(limit)
            .fetch_all(db)
            .await
        }
        None => {
            sqlx::query_as(&format!(
                "SELECT {PLAN_COLUMNS} FROM metadata_bundle_plan \
                 ORDER BY created_at DESC, id DESC LIMIT $1"
            ))
            .bind(limit)
            .fetch_all(db)
            .await
        }
    }
    .map_err(AppError::internal)?;
    raw.into_iter().map(PlanRow::try_from).collect()
}

/// Upper bound on [`list_plans`]'s page — the same ceiling every paginated
/// admin list in this crate uses (`MAX_PAGE_SIZE`).
pub const MAX_LIST_LIMIT: i64 = 200;

/// The most recently finished `succeeded` row — "the last applied bundle",
/// which the drift route diffs live metadata against. `None` on a
/// deployment that has never applied a bundle.
pub async fn latest_succeeded(db: &DbPool) -> Result<Option<PlanRow>, AppError> {
    let raw: Option<RawPlanRow> = sqlx::query_as(&format!(
        "SELECT {PLAN_COLUMNS} FROM metadata_bundle_plan \
         WHERE status = 'succeeded' \
         ORDER BY finished_at DESC NULLS LAST, created_at DESC, id DESC LIMIT 1"
    ))
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    raw.map(PlanRow::try_from).transpose()
}

/// Every `succeeded` row whose stored bundle declares this [`super::model::
/// Bundle::name`], newest first (M92 Phase 1). Two callers: [`super::plan::
/// check_bundle_dependencies`] uses it to find the highest applied version
/// of a bundle dependency; the rollback route (`super::routes::rollback`)
/// uses it to find one exact version's prior snapshot. `bundle` is JSONB, so
/// this is an ordinary jsonb text-extraction predicate (`->>`), not a second
/// index — the ledger is small enough per deployment that a sequential scan
/// per name is fine; add an expression index if that stops being true.
pub async fn succeeded_bundles_by_name(db: &DbPool, name: &str) -> Result<Vec<PlanRow>, AppError> {
    let raw: Vec<RawPlanRow> = sqlx::query_as(&format!(
        "SELECT {PLAN_COLUMNS} FROM metadata_bundle_plan \
         WHERE status = 'succeeded' AND bundle ->> 'name' = $1 \
         ORDER BY finished_at DESC NULLS LAST, created_at DESC, id DESC"
    ))
    .bind(name)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    raw.into_iter().map(PlanRow::try_from).collect()
}

/// `planned -> queued`, recording the approval that authorized it (if any).
/// Returns `false` — and writes nothing — when the row is not `planned`
/// (already queued/running/finished, or missing): the transition is a CAS on
/// status, so two concurrent apply requests for one plan cannot both queue
/// it.
pub async fn mark_queued(
    db: &DbPool,
    id: Uuid,
    approval_ref: Option<Uuid>,
) -> Result<bool, AppError> {
    let rows_affected = sqlx::query(
        r#"UPDATE metadata_bundle_plan
           SET status = 'queued', approval_ref = COALESCE($2, approval_ref),
               row_version = row_version + 1, updated_at = NOW()
           WHERE id = $1 AND status = 'planned'"#,
    )
    .bind(id)
    .bind(approval_ref)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(rows_affected == 1)
}

/// Enqueues `EngineJob::ApplyMetadataBundle { plan_id }` for a plan that is
/// `planned` or already `queued`, in ONE transaction with the status write:
/// a `planned` row becomes `queued` here (without an approval reference —
/// call [`mark_queued`] first to record one), a `queued` row stays `queued`
/// (so a caller that already called `mark_queued` is not refused), and any
/// other status is a `Conflict` because the plan is either running or
/// finished. The queue row is dedup-keyed on the plan id, so calling this
/// twice for one plan (an approval executed, then retried via
/// `retry-execution`) yields one job, not two.
pub async fn enqueue_apply(state: &EngineState, plan_id: Uuid) -> Result<(), AppError> {
    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;
    let rows_affected = sqlx::query(
        r#"UPDATE metadata_bundle_plan
           SET status = 'queued', row_version = row_version + 1, updated_at = NOW()
           WHERE id = $1 AND status IN ('planned', 'queued')"#,
    )
    .bind(plan_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if rows_affected != 1 {
        // Distinguish "no such plan" from "plan is past the point of
        // queueing" — both stop the caller, but a client can act on the
        // difference (re-plan vs. poll the existing run).
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM metadata_bundle_plan WHERE id = $1)")
                .bind(plan_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        tx.rollback().await.map_err(AppError::internal)?;
        return Err(if exists {
            AppError::Conflict("metadata bundle plan is already running or finished")
        } else {
            AppError::NotFound
        });
    }
    attome_jobs::enqueue_in_tx_dedup(
        &mut tx,
        attome_core::jobs::EngineJob::ApplyMetadataBundle { plan_id },
        &apply_dedup_key(plan_id),
    )
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// Row-CAS claim. `Some(row)` iff this call won: the row was `queued`, or it
/// was `claimed`/`applying` under a claim that has made no progress for
/// [`CLAIM_TIMEOUT`] (a crashed worker). `None` means the row is missing,
/// terminal, still `planned`, or held by a live claim — the caller returns
/// without doing any work (apalis does not retry a job that returns `Ok`,
/// so a lost race is not itself a failure). The returned row carries the
/// `cursor` to resume from.
pub async fn claim(db: &DbPool, id: Uuid, worker: &str) -> Result<Option<PlanRow>, AppError> {
    let raw: Option<RawPlanRow> =
        shared::claim(db, LedgerTable::BundlePlan, PLAN_COLUMNS, id, worker).await?;
    raw.map(PlanRow::try_from).transpose()
}

/// Records progress: `status = applying`, the next entry index, and how many
/// objects have been applied so far. Called after each object's own
/// transaction commits — it is the resume point. `Conflict` when the row is
/// no longer `claimed`/`applying` (reclaimed by another worker and finished,
/// or otherwise moved on): the caller must stop, not keep writing.
pub async fn advance(
    db: &DbPool,
    id: Uuid,
    cursor: i32,
    applied_count: i32,
) -> Result<(), AppError> {
    shared::advance(db, LedgerTable::BundlePlan, id, cursor, applied_count).await
}

/// `claimed|applying -> succeeded`, stamping `finished_at` and clearing any
/// earlier error. `Conflict` if the row is not in a running state.
pub async fn mark_succeeded(db: &DbPool, id: Uuid) -> Result<(), AppError> {
    shared::mark_succeeded(db, LedgerTable::BundlePlan, id).await
}

/// `queued|claimed|applying -> failed` with the (bounded) error text and
/// `finished_at`. `queued` is included so an apply that is refused before it
/// is ever claimed (basis hash drifted, plan blocked) can still be closed
/// with its reason. `Conflict` if the row is already terminal or still only
/// `planned`.
pub async fn mark_failed(db: &DbPool, id: Uuid, error: &str) -> Result<(), AppError> {
    shared::mark_failed(db, LedgerTable::BundlePlan, id, error).await
}

/// The ledgers that share the claim / advance / mark scheme: the bundle plan
/// ledger (`metadata_bundle_plan`, migration 0134) and the applied-
/// changeset ledger (`changeset_apply`, migration 0522; Solution 7
/// design §5.1). The table name is a code literal chosen here, never input,
/// so formatting it into the statements interpolates no request data (the
/// `change_log_watermark` pattern).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LedgerTable {
    BundlePlan,
    ChangesetApply,
}

impl LedgerTable {
    const fn table(self) -> &'static str {
        match self {
            Self::BundlePlan => "metadata_bundle_plan",
            Self::ChangesetApply => "changeset_apply",
        }
    }

    const fn lost_claim(self) -> &'static str {
        match self {
            Self::BundlePlan => "metadata bundle plan is no longer claimed by this worker",
            Self::ChangesetApply => "changeset apply row is no longer claimed by this worker",
        }
    }

    const fn not_running(self) -> &'static str {
        match self {
            Self::BundlePlan => "metadata bundle plan is not in a running state",
            Self::ChangesetApply => "changeset apply row is not in a running state",
        }
    }

    const fn cannot_fail(self) -> &'static str {
        match self {
            Self::BundlePlan => "metadata bundle plan is not in a state that can fail",
            Self::ChangesetApply => "changeset apply row is not in a state that can fail",
        }
    }
}

/// The claim / advance / mark statements both ledgers run, parameterised by
/// [`LedgerTable`] (Solution 7 design §5.1: extracted from this file so the
/// changeset ledger shares one implementation of the scheme). Behaviour is
/// the bundle ledger's own: a row CAS on `status` with the [`CLAIM_TIMEOUT`]
/// takeover, never a session advisory lock.
pub(crate) mod shared {
    use super::{CLAIM_TIMEOUT, LedgerTable, MAX_ERROR_MESSAGE_CHARS};
    use attome_db::DbPool;
    use attome_types::AppError;
    use sqlx::postgres::PgRow;
    use uuid::Uuid;

    /// `queued`, or a stale `claimed`/`applying`, -> `claimed` by `worker`,
    /// returning `columns` of the claimed row (`None`: not claimable).
    pub(crate) async fn claim<T>(
        db: &DbPool,
        table: LedgerTable,
        columns: &str,
        id: Uuid,
        worker: &str,
    ) -> Result<Option<T>, AppError>
    where
        T: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin,
    {
        sqlx::query_as(&format!(
            r#"UPDATE {table}
               SET status = 'claimed', claimed_by = $1, claimed_at = NOW(),
                   row_version = row_version + 1, updated_at = NOW()
               WHERE id = $2
                 AND (status = 'queued'
                      OR (status IN ('claimed', 'applying')
                          AND claimed_at < NOW() - INTERVAL '{CLAIM_TIMEOUT}'
                          AND updated_at < NOW() - INTERVAL '{CLAIM_TIMEOUT}'))
               RETURNING {columns}"#,
            table = table.table(),
        ))
        .bind(worker)
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)
    }

    /// Progress after one committed step; `Conflict` once the claim is lost.
    pub(crate) async fn advance(
        db: &DbPool,
        table: LedgerTable,
        id: Uuid,
        cursor: i32,
        applied_count: i32,
    ) -> Result<(), AppError> {
        let rows_affected = sqlx::query(&format!(
            r#"UPDATE {table}
               SET status = 'applying', cursor = $2, applied_count = $3,
                   row_version = row_version + 1, updated_at = NOW()
               WHERE id = $1 AND status IN ('claimed', 'applying')"#,
            table = table.table(),
        ))
        .bind(id)
        .bind(cursor)
        .bind(applied_count)
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if rows_affected != 1 {
            return Err(AppError::Conflict(table.lost_claim()));
        }
        Ok(())
    }

    /// `claimed|applying -> succeeded`, clearing any earlier error.
    pub(crate) async fn mark_succeeded(
        db: &DbPool,
        table: LedgerTable,
        id: Uuid,
    ) -> Result<(), AppError> {
        let rows_affected = sqlx::query(&format!(
            r#"UPDATE {table}
               SET status = 'succeeded', error_message = NULL, finished_at = NOW(),
                   row_version = row_version + 1, updated_at = NOW()
               WHERE id = $1 AND status IN ('claimed', 'applying')"#,
            table = table.table(),
        ))
        .bind(id)
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if rows_affected != 1 {
            return Err(AppError::Conflict(table.not_running()));
        }
        Ok(())
    }

    /// `queued|claimed|applying -> failed`, the error text bounded.
    pub(crate) async fn mark_failed(
        db: &DbPool,
        table: LedgerTable,
        id: Uuid,
        error: &str,
    ) -> Result<(), AppError> {
        let error: String = error.chars().take(MAX_ERROR_MESSAGE_CHARS).collect();
        let rows_affected = sqlx::query(&format!(
            r#"UPDATE {table}
               SET status = 'failed', error_message = $2, finished_at = NOW(),
                   row_version = row_version + 1, updated_at = NOW()
               WHERE id = $1 AND status IN ('queued', 'claimed', 'applying')"#,
            table = table.table(),
        ))
        .bind(id)
        .bind(error)
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if rows_affected != 1 {
            return Err(AppError::Conflict(table.cannot_fail()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_through_its_column_value() {
        for status in [
            PlanStatus::Planned,
            PlanStatus::Queued,
            PlanStatus::Claimed,
            PlanStatus::Applying,
            PlanStatus::Succeeded,
            PlanStatus::Failed,
        ] {
            assert_eq!(PlanStatus::parse(status.as_str()).ok(), Some(status));
            // serde's snake_case name IS the column value — the API and the
            // ledger never disagree on the spelling.
            assert_eq!(
                serde_json::to_value(status).ok(),
                Some(serde_json::Value::String(status.as_str().to_string()))
            );
        }
        assert!(PlanStatus::parse("running").is_err());
        assert!(PlanStatus::Succeeded.is_terminal());
        assert!(PlanStatus::Failed.is_terminal());
        assert!(!PlanStatus::Applying.is_terminal());
    }

    #[test]
    fn dedup_key_is_per_plan() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        assert_ne!(apply_dedup_key(a), apply_dedup_key(b));
        assert!(apply_dedup_key(a).starts_with("bundle-apply:"));
    }
}
