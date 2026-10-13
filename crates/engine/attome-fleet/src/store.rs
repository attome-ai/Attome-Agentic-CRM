//! SQL over the `fleet_*` tables (migration 0543) in the developer's own
//! database. Columns are enumerated, every value is bound, and
//! `secret_enc` is read by exactly one function ([`load_credential`]) so no
//! listing ever carries it. Writes that race take the row's `row_version`
//! (guidelines §2) and report a lost race as `None` / `false` for the caller
//! to turn into `409 version_conflict`.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

use attome_db::DbPool;
use attome_types::AppError;

const DEPLOYMENT_COLUMNS: &str = "id, project_code, label, environment, ring, base_url, \
     s2s_client_id, s2s_key_id, secret_last4, secret_rotated_at, maintenance_window, is_active, \
     created_at, updated_at, row_version";

const OBSERVATION_COLUMNS: &str = "deployment_ref, application_version, git_revision, \
     schema_version, schema_dirty, configuration_version, ready, open_items, last_report_id, \
     last_release_at, ledger_head, pending_approvals, error_code, observed_at, notified_report_id";

const ROLLOUT_COLUMNS: &str =
    "id, title, changesets, plan, status, created_by, created_at, updated_at, row_version";

const TARGET_COLUMNS: &str = "id, rollout_ref, deployment_ref, wave, status, remote_apply_ids, \
     remote_approval_id, backup_ref, plan_summary, error_code, updated_at, row_version";

const ACTION_COLUMNS: &str = "id, actor_ref, deployment_ref, rollout_ref, action, remote_method, \
     remote_path, remote_status, outcome, detail, created_at";

/// One registered deployment, without its sealed secret.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeploymentRow {
    pub id: Uuid,
    pub project_code: String,
    pub label: String,
    pub environment: String,
    pub ring: String,
    pub base_url: String,
    pub s2s_client_id: Option<String>,
    pub s2s_key_id: Option<String>,
    pub secret_last4: Option<String>,
    pub secret_rotated_at: Option<DateTime<Utc>>,
    pub maintenance_window: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
}

impl DeploymentRow {
    pub fn has_credential(&self) -> bool {
        self.s2s_client_id.is_some()
    }
}

/// The editable columns of a deployment (register and PATCH write all of
/// them; PATCH reads the row first and overlays the request).
#[derive(Debug, Clone)]
pub struct DeploymentFields {
    pub project_code: String,
    pub label: String,
    pub environment: String,
    pub ring: String,
    pub base_url: String,
    pub maintenance_window: Option<String>,
    pub is_active: bool,
}

/// The latest probe of one deployment.
#[derive(Debug, Clone, Default, sqlx::FromRow)]
pub struct ObservationRow {
    pub deployment_ref: Uuid,
    pub application_version: Option<String>,
    pub git_revision: Option<String>,
    pub schema_version: Option<i64>,
    pub schema_dirty: Option<bool>,
    pub configuration_version: Option<String>,
    pub ready: Option<bool>,
    pub open_items: Option<i32>,
    pub last_report_id: Option<Uuid>,
    pub last_release_at: Option<DateTime<Utc>>,
    pub ledger_head: Option<Value>,
    pub pending_approvals: Option<i32>,
    pub error_code: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub notified_report_id: Option<Uuid>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RolloutRow {
    pub id: Uuid,
    pub title: String,
    pub changesets: Value,
    pub plan: Value,
    pub status: String,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TargetRow {
    pub id: Uuid,
    pub rollout_ref: Uuid,
    pub deployment_ref: Uuid,
    pub wave: i32,
    pub status: String,
    pub remote_apply_ids: Option<Vec<Uuid>>,
    pub remote_approval_id: Option<Uuid>,
    pub backup_ref: Option<String>,
    pub plan_summary: Option<Value>,
    pub error_code: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ActionRow {
    pub id: Uuid,
    pub actor_ref: Uuid,
    pub deployment_ref: Option<Uuid>,
    pub rollout_ref: Option<Uuid>,
    pub action: String,
    pub remote_method: Option<String>,
    pub remote_path: Option<String>,
    pub remote_status: Option<i32>,
    pub outcome: String,
    pub detail: Value,
    pub created_at: DateTime<Utc>,
}

/// One append-only action-log row (design §6.7).
#[derive(Debug, Clone)]
pub struct ActionWrite {
    /// Pre-allocated so it can travel as `x-correlation-id` before the row
    /// exists.
    pub id: Uuid,
    pub actor_ref: Uuid,
    pub deployment_ref: Option<Uuid>,
    pub rollout_ref: Option<Uuid>,
    pub action: &'static str,
    pub remote_method: Option<&'static str>,
    pub remote_path: Option<String>,
    pub remote_status: Option<u16>,
    /// `ok`, `refused` or `failed`.
    pub outcome: &'static str,
    /// Ids and counts only; never secrets or record values.
    pub detail: Value,
}

fn db_err(e: sqlx::Error) -> AppError {
    match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => AppError::Conflict(
            "fleet_deployment_exists: a deployment with this project code and environment is \
             already registered",
        ),
        _ => attome_db::classify(e),
    }
}

// ── Deployments ─────────────────────────────────────────────────────────────

pub async fn list_deployments(
    db: &DbPool,
    include_inactive: bool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<DeploymentRow>, i64), AppError> {
    let rows: Vec<DeploymentRow> = sqlx::query_as(&format!(
        "SELECT {DEPLOYMENT_COLUMNS} FROM fleet_deployment \
         WHERE ($1 OR is_active) ORDER BY project_code, environment LIMIT $2 OFFSET $3"
    ))
    .bind(include_inactive)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM fleet_deployment WHERE ($1 OR is_active)")
            .bind(include_inactive)
            .fetch_one(db)
            .await
            .map_err(attome_db::classify)?;
    Ok((rows, total))
}

/// Every active deployment (the poll's work list; the fleet is ~10).
pub async fn active_deployments(db: &DbPool) -> Result<Vec<DeploymentRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {DEPLOYMENT_COLUMNS} FROM fleet_deployment WHERE is_active \
         ORDER BY project_code, environment"
    ))
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)
}

pub async fn deployments_by_ids(db: &DbPool, ids: &[Uuid]) -> Result<Vec<DeploymentRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {DEPLOYMENT_COLUMNS} FROM fleet_deployment WHERE id = ANY($1)"
    ))
    .bind(ids)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)
}

pub async fn get_deployment(db: &DbPool, id: Uuid) -> Result<Option<DeploymentRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {DEPLOYMENT_COLUMNS} FROM fleet_deployment WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(attome_db::classify)
}

pub async fn insert_deployment(
    conn: &mut PgConnection,
    id: Uuid,
    fields: &DeploymentFields,
) -> Result<DeploymentRow, AppError> {
    sqlx::query_as(&format!(
        "INSERT INTO fleet_deployment \
           (id, project_code, label, environment, ring, base_url, maintenance_window, is_active) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {DEPLOYMENT_COLUMNS}"
    ))
    .bind(id)
    .bind(&fields.project_code)
    .bind(&fields.label)
    .bind(&fields.environment)
    .bind(&fields.ring)
    .bind(&fields.base_url)
    .bind(&fields.maintenance_window)
    .bind(fields.is_active)
    .fetch_one(conn)
    .await
    .map_err(db_err)
}

/// Writes every editable column if `row_version` still matches. `None`:
/// the row is gone or changed since it was read.
pub async fn update_deployment(
    conn: &mut PgConnection,
    id: Uuid,
    expected_row_version: i64,
    fields: &DeploymentFields,
) -> Result<Option<DeploymentRow>, AppError> {
    sqlx::query_as(&format!(
        "UPDATE fleet_deployment SET project_code = $3, label = $4, environment = $5, \
           ring = $6, base_url = $7, maintenance_window = $8, is_active = $9, \
           updated_at = now(), row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 RETURNING {DEPLOYMENT_COLUMNS}"
    ))
    .bind(id)
    .bind(expected_row_version)
    .bind(&fields.project_code)
    .bind(&fields.label)
    .bind(&fields.environment)
    .bind(&fields.ring)
    .bind(&fields.base_url)
    .bind(&fields.maintenance_window)
    .bind(fields.is_active)
    .fetch_optional(conn)
    .await
    .map_err(db_err)
}

/// Stores a new rollout credential (sealed) if `row_version` still matches.
#[allow(clippy::too_many_arguments)]
pub async fn set_credential(
    conn: &mut PgConnection,
    id: Uuid,
    expected_row_version: i64,
    client_id: &str,
    key_id: &str,
    sealed: &[u8],
    last4: &str,
) -> Result<Option<DeploymentRow>, AppError> {
    sqlx::query_as(&format!(
        "UPDATE fleet_deployment SET s2s_client_id = $3, s2s_key_id = $4, secret_enc = $5, \
           secret_last4 = $6, secret_rotated_at = now(), updated_at = now(), \
           row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 RETURNING {DEPLOYMENT_COLUMNS}"
    ))
    .bind(id)
    .bind(expected_row_version)
    .bind(client_id)
    .bind(key_id)
    .bind(sealed)
    .bind(last4)
    .fetch_optional(conn)
    .await
    .map_err(attome_db::classify)
}

/// The credential columns as stored: each may be NULL until a credential is set.
type CredentialColumns = (Option<String>, Option<String>, Option<Vec<u8>>);

/// The sealed credential of one deployment: `(client_id, key_id,
/// secret_enc)`. The only reader of `secret_enc`.
pub async fn load_credential(
    db: &DbPool,
    id: Uuid,
) -> Result<Option<(String, String, Vec<u8>)>, AppError> {
    let row: Option<CredentialColumns> = sqlx::query_as(
        "SELECT s2s_client_id, s2s_key_id, secret_enc FROM fleet_deployment WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(attome_db::classify)?;
    Ok(match row {
        Some((Some(client_id), Some(key_id), Some(sealed))) => Some((client_id, key_id, sealed)),
        _ => None,
    })
}

// ── Observations ────────────────────────────────────────────────────────────

pub async fn observations_for(db: &DbPool, ids: &[Uuid]) -> Result<Vec<ObservationRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {OBSERVATION_COLUMNS} FROM fleet_observation WHERE deployment_ref = ANY($1)"
    ))
    .bind(ids)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)
}

/// The previous observation, row-locked so two syncs of one deployment
/// decide notifications one after the other.
pub async fn observation_for_update(
    conn: &mut PgConnection,
    deployment_id: Uuid,
) -> Result<Option<ObservationRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {OBSERVATION_COLUMNS} FROM fleet_observation \
         WHERE deployment_ref = $1 FOR UPDATE"
    ))
    .bind(deployment_id)
    .fetch_optional(conn)
    .await
    .map_err(attome_db::classify)
}

/// Replaces the deployment's observation (`notified_report_id` included).
pub async fn upsert_observation(
    conn: &mut PgConnection,
    row: &ObservationRow,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO fleet_observation (deployment_ref, application_version, git_revision, \
           schema_version, schema_dirty, configuration_version, ready, open_items, \
           last_report_id, last_release_at, ledger_head, pending_approvals, error_code, \
           observed_at, notified_report_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
         ON CONFLICT (deployment_ref) DO UPDATE SET \
           application_version = EXCLUDED.application_version, \
           git_revision = EXCLUDED.git_revision, schema_version = EXCLUDED.schema_version, \
           schema_dirty = EXCLUDED.schema_dirty, \
           configuration_version = EXCLUDED.configuration_version, ready = EXCLUDED.ready, \
           open_items = EXCLUDED.open_items, last_report_id = EXCLUDED.last_report_id, \
           last_release_at = EXCLUDED.last_release_at, ledger_head = EXCLUDED.ledger_head, \
           pending_approvals = EXCLUDED.pending_approvals, error_code = EXCLUDED.error_code, \
           observed_at = EXCLUDED.observed_at, notified_report_id = EXCLUDED.notified_report_id",
    )
    .bind(row.deployment_ref)
    .bind(&row.application_version)
    .bind(&row.git_revision)
    .bind(row.schema_version)
    .bind(row.schema_dirty)
    .bind(&row.configuration_version)
    .bind(row.ready)
    .bind(row.open_items)
    .bind(row.last_report_id)
    .bind(row.last_release_at)
    .bind(&row.ledger_head)
    .bind(row.pending_approvals)
    .bind(&row.error_code)
    .bind(row.observed_at)
    .bind(row.notified_report_id)
    .execute(conn)
    .await
    .map_err(attome_db::classify)?;
    Ok(())
}

// ── Action log (append-only) ────────────────────────────────────────────────

pub async fn insert_action(conn: &mut PgConnection, action: &ActionWrite) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO fleet_action (id, actor_ref, deployment_ref, rollout_ref, action, \
           remote_method, remote_path, remote_status, outcome, detail) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(action.id)
    .bind(action.actor_ref)
    .bind(action.deployment_ref)
    .bind(action.rollout_ref)
    .bind(action.action)
    .bind(action.remote_method)
    .bind(&action.remote_path)
    .bind(action.remote_status.map(i32::from))
    .bind(action.outcome)
    .bind(&action.detail)
    .execute(conn)
    .await
    .map_err(attome_db::classify)?;
    Ok(())
}

pub async fn list_actions(
    db: &DbPool,
    deployment_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<(Vec<ActionRow>, i64), AppError> {
    let rows: Vec<ActionRow> = sqlx::query_as(&format!(
        "SELECT {ACTION_COLUMNS} FROM fleet_action WHERE deployment_ref = $1 \
         ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"
    ))
    .bind(deployment_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM fleet_action WHERE deployment_ref = $1")
            .bind(deployment_id)
            .fetch_one(db)
            .await
            .map_err(attome_db::classify)?;
    Ok((rows, total))
}

// ── Rollouts and targets ────────────────────────────────────────────────────

/// Rollouts that still drive work: `planned` or `in_progress`.
pub async fn count_active_rollouts(conn: &mut PgConnection) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT count(*) FROM fleet_rollout WHERE status IN ('planned', 'in_progress')",
    )
    .fetch_one(conn)
    .await
    .map_err(attome_db::classify)
}

pub async fn insert_rollout(
    conn: &mut PgConnection,
    id: Uuid,
    title: &str,
    changesets: &Value,
    plan: &Value,
    status: &str,
    created_by: Uuid,
) -> Result<RolloutRow, AppError> {
    sqlx::query_as(&format!(
        "INSERT INTO fleet_rollout (id, title, changesets, plan, status, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {ROLLOUT_COLUMNS}"
    ))
    .bind(id)
    .bind(title)
    .bind(changesets)
    .bind(plan)
    .bind(status)
    .bind(created_by)
    .fetch_one(conn)
    .await
    .map_err(attome_db::classify)
}

pub async fn get_rollout(db: &DbPool, id: Uuid) -> Result<Option<RolloutRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {ROLLOUT_COLUMNS} FROM fleet_rollout WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(attome_db::classify)
}

pub async fn get_rollout_for_update(
    conn: &mut PgConnection,
    id: Uuid,
) -> Result<Option<RolloutRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {ROLLOUT_COLUMNS} FROM fleet_rollout WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(conn)
    .await
    .map_err(attome_db::classify)
}

pub async fn list_rollouts(
    db: &DbPool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<RolloutRow>, i64), AppError> {
    let rows: Vec<RolloutRow> = sqlx::query_as(&format!(
        "SELECT {ROLLOUT_COLUMNS} FROM fleet_rollout \
         ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2"
    ))
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM fleet_rollout")
        .fetch_one(db)
        .await
        .map_err(attome_db::classify)?;
    Ok((rows, total))
}

/// Rollouts the poll re-evaluates: `in_progress`, plus `halted` ones that
/// may still have targets following an apply.
pub async fn live_rollout_ids(db: &DbPool) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM fleet_rollout WHERE status IN ('in_progress', 'halted') \
         ORDER BY created_at",
    )
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)
}

/// Writes the plan and status if `row_version` still matches.
pub async fn update_rollout(
    conn: &mut PgConnection,
    id: Uuid,
    expected_row_version: i64,
    plan: &Value,
    status: &str,
) -> Result<Option<RolloutRow>, AppError> {
    sqlx::query_as(&format!(
        "UPDATE fleet_rollout SET plan = $3, status = $4, updated_at = now(), \
           row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 RETURNING {ROLLOUT_COLUMNS}"
    ))
    .bind(id)
    .bind(expected_row_version)
    .bind(plan)
    .bind(status)
    .fetch_optional(conn)
    .await
    .map_err(attome_db::classify)
}

pub async fn insert_target(
    conn: &mut PgConnection,
    rollout_id: Uuid,
    deployment_id: Uuid,
    wave: i32,
    status: &str,
) -> Result<TargetRow, AppError> {
    sqlx::query_as(&format!(
        "INSERT INTO fleet_target (rollout_ref, deployment_ref, wave, status) \
         VALUES ($1, $2, $3, $4) RETURNING {TARGET_COLUMNS}"
    ))
    .bind(rollout_id)
    .bind(deployment_id)
    .bind(wave)
    .bind(status)
    .fetch_one(conn)
    .await
    .map_err(attome_db::classify)
}

pub async fn targets_of(db: &DbPool, rollout_id: Uuid) -> Result<Vec<TargetRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {TARGET_COLUMNS} FROM fleet_target WHERE rollout_ref = $1 \
         ORDER BY wave, id"
    ))
    .bind(rollout_id)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)
}

pub async fn targets_of_locked(
    conn: &mut PgConnection,
    rollout_id: Uuid,
) -> Result<Vec<TargetRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {TARGET_COLUMNS} FROM fleet_target WHERE rollout_ref = $1 \
         ORDER BY wave, id FOR UPDATE"
    ))
    .bind(rollout_id)
    .fetch_all(conn)
    .await
    .map_err(attome_db::classify)
}

pub async fn get_target(db: &DbPool, id: Uuid) -> Result<Option<TargetRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {TARGET_COLUMNS} FROM fleet_target WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(attome_db::classify)
}

/// The new state of one target after a step or a route.
#[derive(Debug, Clone)]
pub struct TargetUpdate {
    pub status: String,
    pub remote_apply_ids: Option<Vec<Uuid>>,
    pub remote_approval_id: Option<Uuid>,
    pub backup_ref: Option<String>,
    pub plan_summary: Option<Value>,
    pub error_code: Option<String>,
}

impl TargetUpdate {
    /// The row as it is, ready to change one field.
    pub fn from_row(row: &TargetRow) -> Self {
        Self {
            status: row.status.clone(),
            remote_apply_ids: row.remote_apply_ids.clone(),
            remote_approval_id: row.remote_approval_id,
            backup_ref: row.backup_ref.clone(),
            plan_summary: row.plan_summary.clone(),
            error_code: row.error_code.clone(),
        }
    }
}

/// Writes a target if `row_version` still matches. `None`: changed since read.
pub async fn update_target(
    conn: &mut PgConnection,
    id: Uuid,
    expected_row_version: i64,
    update: &TargetUpdate,
) -> Result<Option<TargetRow>, AppError> {
    sqlx::query_as(&format!(
        "UPDATE fleet_target SET status = $3, remote_apply_ids = $4, \
           remote_approval_id = $5, backup_ref = $6, plan_summary = $7, error_code = $8, \
           updated_at = now(), row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 RETURNING {TARGET_COLUMNS}"
    ))
    .bind(id)
    .bind(expected_row_version)
    .bind(&update.status)
    .bind(&update.remote_apply_ids)
    .bind(update.remote_approval_id)
    .bind(&update.backup_ref)
    .bind(&update.plan_summary)
    .bind(&update.error_code)
    .fetch_optional(conn)
    .await
    .map_err(attome_db::classify)
}

/// Targets of live rollouts that wait on the customer (an approval or an
/// apply in flight) — the poll re-arms a step for each.
pub async fn waiting_target_ids(db: &DbPool) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT t.id FROM fleet_target t \
         JOIN fleet_rollout r ON r.id = t.rollout_ref \
         WHERE r.status IN ('in_progress', 'halted') \
           AND t.status IN ('approval_pending', 'applying') \
         ORDER BY t.updated_at",
    )
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)
}
