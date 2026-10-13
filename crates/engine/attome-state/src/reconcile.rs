//! Declarative "make this state model match this description" primitive —
//! one implementation of the insert/update path, shared by `admin.rs`'s
//! interactive CRUD and the bundle engine's apply step
//! (`attome-api/src/bundle/apply.rs`), mirroring
//! `attome_security::reconcile::reconcile_field_security_profile`'s shape:
//! **transitions are set semantics inside their parent** — this call takes
//! the whole desired model, upserts/deletes its transition rows to match,
//! in one transaction.
//!
//! There is no `is_customized` column on either table (state models are
//! always admin-authored, never boot-seeded), so unlike the entity/security
//! reconcile primitives this one ignores `ReconcilePolicy`'s marker — every
//! call always applies the desired state. The parameter is kept so the
//! bundle engine's call site reads the same as every other component's.

use attome_types::AppError;
// Glob import matches `attome_core::state`'s own import for the identical
// `.next().publish(...)` call in `invalidate` below.
use attome_core::{EngineState, reconcile::ReconcileOutcome, reconcile::ReconcilePolicy};
use fred::prelude::*;
use uuid::Uuid;

pub struct TransitionDesc {
    pub from_state: String,
    pub to_state: String,
    pub name: String,
    pub required_privilege: Option<String>,
    pub guard_expression: Option<String>,
    pub entry_actions: Vec<String>,
    pub exit_actions: Vec<String>,
    pub display_order: i32,
    /// M07 Phase F (D-770) — see `attome_core::TransitionDef`. Validated
    /// by `validate` below exactly as the admin API validates it.
    pub approval_plan: Option<attome_approval::ApprovalPlan>,
    pub pending_state: Option<String>,
    pub on_reject_state: Option<String>,
}

impl std::fmt::Debug for TransitionDesc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitionDesc").finish_non_exhaustive()
    }
}

pub struct StateModelDesc {
    pub entity_logicalname: String,
    pub name: String,
    pub state_field: String,
    pub initial_state: String,
    pub is_active: bool,
    pub transitions: Vec<TransitionDesc>,
}

impl std::fmt::Debug for StateModelDesc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateModelDesc").finish_non_exhaustive()
    }
}

#[derive(sqlx::FromRow)]
struct ModelRow {
    id: Uuid,
    name: String,
    state_field: String,
    initial_state: String,
    is_active: bool,
    is_deleted: bool,
}

#[derive(sqlx::FromRow, Clone, PartialEq)]
struct TransitionRow {
    id: Uuid,
    from_state: String,
    to_state: String,
    name: String,
    required_privilege: Option<String>,
    guard_expression: Option<String>,
    entry_actions: Vec<String>,
    exit_actions: Vec<String>,
    display_order: i32,
    approval_plan: Option<serde_json::Value>,
    pending_state: Option<String>,
    on_reject_state: Option<String>,
}

fn validate(desc: &StateModelDesc) -> Result<(), AppError> {
    if desc.entity_logicalname.trim().is_empty() {
        return Err(AppError::Validation(
            "state model: entity_logicalname is required".into(),
        ));
    }
    if desc.state_field.trim().is_empty() || desc.initial_state.trim().is_empty() {
        return Err(AppError::Validation(format!(
            "{}: state_field and initial_state are required",
            desc.entity_logicalname
        )));
    }
    for t in &desc.transitions {
        if t.from_state.trim().is_empty() || t.to_state.trim().is_empty() {
            return Err(AppError::Validation(format!(
                "{}: every transition needs a from_state and to_state",
                desc.entity_logicalname
            )));
        }
        crate::approval::validate_transition_approval(
            &t.from_state,
            &t.to_state,
            t.approval_plan.as_ref(),
            t.pending_state.as_deref(),
            t.on_reject_state.as_deref(),
            Some(desc.initial_state.as_str()),
        )
        .map_err(|e| match e {
            AppError::Validation(msg) => AppError::Validation(format!(
                "{} transition {} -> {}: {msg}",
                desc.entity_logicalname, t.from_state, t.to_state
            )),
            other => other,
        })?;
    }
    Ok(())
}

/// Upserts `desc`'s model row and reconciles its transitions to exactly the
/// desired set (create missing, update changed, delete removed). Takes the
/// `attome-state/` advisory lock for `entity_logicalname` first — same
/// two-argument form as every other subsystem (guidelines §2).
pub async fn reconcile_state_model(
    state: &EngineState,
    desc: &StateModelDesc,
    policy: ReconcilePolicy,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    validate(desc)?;
    let db = &state.base.db;
    // Solution 7 (D-785, design §2.2 step 3): a row this primitive inserts is
    // stamped `platform` under the Seed policy and `project` otherwise (bundle
    // apply, design §1.4). An existing row keeps its owner.
    let owner_layer = match policy {
        ReconcilePolicy::Seed => attome_core::changeset::Layer::Platform,
        _ => attome_core::changeset::Layer::Project,
    }
    .as_str();

    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-state/model:{}", desc.entity_logicalname))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a state-model write for this entity is already in progress",
        ));
    }

    let current: Option<ModelRow> = sqlx::query_as(
        "SELECT id, name, state_field, initial_state, is_active, is_deleted \
         FROM state_model WHERE entity_logicalname = $1 \
         ORDER BY is_deleted ASC, created_at DESC LIMIT 1",
    )
    .bind(&desc.entity_logicalname)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let unchanged_model = current.as_ref().is_some_and(|r| {
        !r.is_deleted
            && r.name == desc.name
            && r.state_field == desc.state_field
            && r.initial_state == desc.initial_state
            && r.is_active == desc.is_active
    });

    let model_id = match &current {
        Some(row) if !unchanged_model || row.is_deleted => {
            let n = sqlx::query(
                "UPDATE state_model \
                 SET name = $2, state_field = $3, initial_state = $4, is_active = $5, \
                     is_deleted = false, updated_at = NOW(), row_version = row_version + 1 \
                 WHERE id = $1",
            )
            .bind(row.id)
            .bind(&desc.name)
            .bind(&desc.state_field)
            .bind(&desc.initial_state)
            .bind(desc.is_active)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            if n != 1 {
                return Err(AppError::Conflict(
                    "state model row vanished during reconcile",
                ));
            }
            row.id
        }
        Some(row) => row.id,
        None => sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO state_model \
                 (entity_logicalname, name, state_field, initial_state, is_active, owner_layer) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(&desc.entity_logicalname)
        .bind(&desc.name)
        .bind(&desc.state_field)
        .bind(&desc.initial_state)
        .bind(desc.is_active)
        .bind(owner_layer)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_unique_violation)?,
    };

    let live_transitions: Vec<TransitionRow> = sqlx::query_as(
        "SELECT id, from_state, to_state, name, required_privilege, guard_expression, \
                entry_actions, exit_actions, display_order, approval_plan, pending_state, \
                on_reject_state \
         FROM state_transition WHERE model_ref = $1 AND is_deleted = false",
    )
    .bind(model_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let mut transitions_changed = false;
    for t in &desc.transitions {
        let plan_json = t
            .approval_plan
            .as_ref()
            .map(|p| serde_json::to_value(p).map_err(AppError::internal))
            .transpose()?;
        let existing = live_transitions
            .iter()
            .find(|r| r.from_state == t.from_state && r.to_state == t.to_state);
        let matches = existing.is_some_and(|r| {
            r.name == t.name
                && r.required_privilege == t.required_privilege
                && r.guard_expression == t.guard_expression
                && r.entry_actions == t.entry_actions
                && r.exit_actions == t.exit_actions
                && r.display_order == t.display_order
                && r.approval_plan == plan_json
                && r.pending_state == t.pending_state
                && r.on_reject_state == t.on_reject_state
        });
        if matches {
            continue;
        }
        transitions_changed = true;
        sqlx::query(
            "INSERT INTO state_transition \
                 (model_ref, from_state, to_state, name, required_privilege, \
                  guard_expression, entry_actions, exit_actions, display_order, \
                  approval_plan, pending_state, on_reject_state, owner_layer) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             ON CONFLICT (model_ref, from_state, to_state) WHERE is_deleted = false \
             DO UPDATE SET name = EXCLUDED.name, \
                 required_privilege = EXCLUDED.required_privilege, \
                 guard_expression = EXCLUDED.guard_expression, \
                 entry_actions = EXCLUDED.entry_actions, \
                 exit_actions = EXCLUDED.exit_actions, \
                 display_order = EXCLUDED.display_order, \
                 approval_plan = EXCLUDED.approval_plan, \
                 pending_state = EXCLUDED.pending_state, \
                 on_reject_state = EXCLUDED.on_reject_state, \
                 updated_at = NOW(), row_version = state_transition.row_version + 1",
        )
        .bind(model_id)
        .bind(&t.from_state)
        .bind(&t.to_state)
        .bind(&t.name)
        .bind(&t.required_privilege)
        .bind(&t.guard_expression)
        .bind(&t.entry_actions)
        .bind(&t.exit_actions)
        .bind(t.display_order)
        .bind(&plan_json)
        .bind(&t.pending_state)
        .bind(&t.on_reject_state)
        .bind(owner_layer)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    for r in &live_transitions {
        if !desc
            .transitions
            .iter()
            .any(|t| t.from_state == r.from_state && t.to_state == r.to_state)
        {
            transitions_changed = true;
            sqlx::query(
                "UPDATE state_transition \
                 SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1 \
                 WHERE id = $1",
            )
            .bind(r.id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
    }

    tx.commit().await.map_err(AppError::internal)?;

    let outcome = match &current {
        None => ReconcileOutcome::Created,
        Some(row) if !unchanged_model || row.is_deleted || transitions_changed => {
            ReconcileOutcome::Updated
        }
        Some(_) => ReconcileOutcome::Unchanged,
    };
    if wrote(outcome) {
        invalidate(state).await;
    }
    tracing::info!(
        entity = %desc.entity_logicalname,
        ?outcome,
        "attome-state reconcile: reconciled state model"
    );
    Ok((model_id, outcome))
}

/// Soft-retires the live model for `entity_logicalname`, if any. Transition
/// rows are left alone (`ON DELETE CASCADE` only fires on a hard delete,
/// which this never does) so reactivation is lossless, same posture as
/// `attome_security::reconcile::retire_field_security_profile`.
pub async fn retire_state_model(
    state: &EngineState,
    entity_logicalname: &str,
) -> Result<ReconcileOutcome, AppError> {
    let db = &state.base.db;
    let n = sqlx::query(
        "UPDATE state_model \
         SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1 \
         WHERE entity_logicalname = $1 AND is_deleted = false",
    )
    .bind(entity_logicalname)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Ok(ReconcileOutcome::Unchanged);
    }
    invalidate(state).await;
    Ok(ReconcileOutcome::Updated)
}

pub(crate) fn wrote(outcome: ReconcileOutcome) -> bool {
    matches!(
        outcome,
        ReconcileOutcome::Created | ReconcileOutcome::Updated
    )
}

/// Reloads this node's own `state_models` snapshot and best-effort publishes
/// on `STATE_MODEL_VERSION_CHANNEL` so every other node reloads too — call
/// after a write has committed, never inside its transaction (guidelines
/// §4/§5: no Redis I/O across a DB transaction). A failed publish only
/// widens the staleness window other nodes see until their own next
/// reconnect/state-model edit; it never fails the write that triggered it.
pub(crate) async fn invalidate(state: &EngineState) {
    match attome_core::state_registry::load(&state.base.db).await {
        Ok(fresh) => state.state_models.swap(fresh),
        Err(e) => {
            tracing::warn!(error = %e, "attome-state: local registry reload failed after write")
        }
    }

    let publish_result = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        state
            .base
            .redis
            .next()
            .publish::<i64, _, _>(attome_core::STATE_MODEL_VERSION_CHANNEL, "1"),
    )
    .await;
    match publish_result {
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "attome-state: failed to publish invalidation doorbell")
        }
        Err(_) => tracing::warn!("attome-state: publishing invalidation doorbell timed out"),
        Ok(Ok(_)) => {}
    }
}

fn map_unique_violation(error: sqlx::Error) -> AppError {
    if attome_db::is_unique_violation(&error) {
        AppError::Conflict("a concurrent write created this state model first; retry")
    } else {
        AppError::internal(error)
    }
}
