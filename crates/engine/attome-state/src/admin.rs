//! `state_model`/`state_transition` admin CRUD —
//! `/api/v1/admin/state-models*`.
//!
//! Mounted through `StateModel::routes()` (`lib.rs`), so every route here is
//! already license-gated by `ModelRegistry` before this module ever sees a
//! request (D-010) — handlers only need `Authorized<Admin>`, the same
//! posture `attome-workflow`'s admin CRUD uses.
//!
//! Targeted per-row writes, not `reconcile::reconcile_state_model` (that
//! primitive replaces a model's *whole* transition set, which is exactly
//! right for a bundle apply and exactly wrong for "add one transition" from
//! an admin screen) — each handler here takes its own
//! `attome-state/{model,transition}:...` advisory lock and calls
//! `reconcile::invalidate` after a write commits.
//!
//! Solution 7 Phase 1 (D-785, design §1.1): every write here is recorded as
//! one changeset operation as the last statement before commit —
//! `upsert_state_model` / `retire_state_model` (target `{ entity }`, one live
//! model per entity) and `upsert_state_transition` /
//! `retire_state_transition` (target `{ entity, transition }`, where
//! `transition` is the edge key `"<from_state>-><to_state>"`, unique per
//! model). A new model or transition is stamped with the recording
//! changeset's layer (a transition's model may belong to a lower layer); an
//! update or delete is refused with 409 `layer_mismatch` unless the row's own
//! `owner_layer` is that layer.

use attome_core::EngineState;
use attome_core::changeset::{Layer, Op, RecordedOp, RecordingCtx};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use uuid::Uuid;

use crate::model::{
    CreateStateModelBody, CreateTransitionBody, StateModelDetail, StateModelListItem,
    TransitionListItem, UpdateStateModelBody, UpdateTransitionBody,
};

/// A state-model row, enumerated columns. `Serialize` is the changeset
/// operation's post-write snapshot.
#[derive(sqlx::FromRow, serde::Serialize)]
struct ModelRow {
    id: Uuid,
    entity_logicalname: String,
    name: String,
    state_field: String,
    initial_state: String,
    is_active: bool,
    row_version: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    owner_layer: String,
    // M8-T2: left out of the snapshot when empty, so a changeset's fold
    // reads it as the bundle shape's defaults.
    #[serde(skip_serializing_if = "Option::is_none")]
    record_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locked_states: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasons: Option<serde_json::Value>,
}

impl ModelRow {
    fn locked_states(&self) -> Vec<attome_core::LockedState> {
        self.locked_states
            .clone()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default()
    }

    fn reasons(&self) -> Vec<attome_core::StateReasons> {
        self.reasons
            .clone()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default()
    }
}

/// Every column `ModelRow` reads.
const MODEL_COLUMNS: &str = "id, entity_logicalname, name, state_field, initial_state, is_active, \
     row_version, created_at, updated_at, owner_layer, record_type, locked_states, reason_field, \
     reasons";

/// M8-T2: a model's checked rules, as the columns store them.
struct CheckedRules {
    locked_states: Option<serde_json::Value>,
    reason_field: Option<String>,
    reasons: Option<serde_json::Value>,
}

/// M8-T2: checks a model's locked states and reasons: every state named
/// once, reasons not empty, and the reason field an attribute of the entity.
fn check_rules(
    state: &EngineState,
    entity_logicalname: &str,
    locked_states: &[attome_core::LockedState],
    reason_field: Option<&str>,
    reasons: &[attome_core::StateReasons],
) -> Result<CheckedRules, AppError> {
    let mut seen = std::collections::HashSet::new();
    let mut locked = Vec::with_capacity(locked_states.len());
    for l in locked_states {
        let state_name = l.state.trim();
        if state_name.is_empty() || !seen.insert(state_name.to_owned()) {
            return Err(AppError::Validation(
                "locked_states: each state is named once".into(),
            ));
        }
        locked.push(attome_core::LockedState {
            state: state_name.to_owned(),
            editable: l
                .editable
                .iter()
                .map(|f| f.trim().to_owned())
                .filter(|f| !f.is_empty())
                .collect(),
        });
    }
    let mut seen = std::collections::HashSet::new();
    let mut listed = Vec::with_capacity(reasons.len());
    for r in reasons {
        let state_name = r.state.trim();
        let codes: Vec<String> = r
            .reasons
            .iter()
            .map(|c| c.trim().to_owned())
            .filter(|c| !c.is_empty())
            .collect();
        if state_name.is_empty() || codes.is_empty() || !seen.insert(state_name.to_owned()) {
            return Err(AppError::Validation(
                "reasons: each state is named once, with at least one reason".into(),
            ));
        }
        listed.push(attome_core::StateReasons {
            state: state_name.to_owned(),
            reasons: codes,
        });
    }
    let reason_field = reason_field
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(str::to_owned);
    if let Some(field) = &reason_field {
        let known = state
            .entities
            .load()
            .get(entity_logicalname)
            .is_some_and(|m| m.attrs.iter().any(|a| &a.logicalname == field));
        if !known {
            return Err(AppError::Validation(format!(
                "reason_field: {entity_logicalname} has no field named '{field}'"
            )));
        }
    }
    if !listed.is_empty() && reason_field.is_none() {
        return Err(AppError::Validation("reasons need a reason_field".into()));
    }
    let json = |empty: bool, v: serde_json::Value| (!empty).then_some(v);
    Ok(CheckedRules {
        locked_states: json(
            locked.is_empty(),
            serde_json::to_value(&locked).map_err(AppError::internal)?,
        ),
        reason_field,
        reasons: json(
            listed.is_empty(),
            serde_json::to_value(&listed).map_err(AppError::internal)?,
        ),
    })
}

/// M8-T2: whether the model governs one record type. A typed model is kept
/// out of changesets: they identify a model by its entity alone.
async fn model_is_typed(tx: &mut attome_db::Tx<'_>, model_id: Uuid) -> Result<bool, AppError> {
    let record_type: Option<Option<String>> =
        sqlx::query_scalar("SELECT record_type FROM state_model WHERE id = $1")
            .bind(model_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    Ok(record_type.flatten().is_some())
}

impl From<ModelRow> for StateModelListItem {
    fn from(r: ModelRow) -> Self {
        let (locked_states, reasons) = (r.locked_states(), r.reasons());
        StateModelListItem {
            id: r.id,
            entity_logicalname: r.entity_logicalname,
            name: r.name,
            state_field: r.state_field,
            initial_state: r.initial_state,
            is_active: r.is_active,
            row_version: r.row_version,
            locked_states,
            reasons,
            record_type: r.record_type,
            reason_field: r.reason_field,
            owner_layer: r.owner_layer,
        }
    }
}

/// A transition row, enumerated columns. `Serialize` is the changeset
/// operation's post-write snapshot.
#[derive(sqlx::FromRow, serde::Serialize)]
struct TransitionRow {
    id: Uuid,
    model_ref: Uuid,
    from_state: String,
    to_state: String,
    name: String,
    required_privilege: Option<String>,
    guard_expression: Option<String>,
    entry_actions: Vec<String>,
    exit_actions: Vec<String>,
    display_order: i32,
    row_version: i64,
    approval_plan: Option<serde_json::Value>,
    pending_state: Option<String>,
    on_reject_state: Option<String>,
    auto_condition: Option<String>,
    owner_layer: String,
}

/// Every column `TransitionRow` reads, for the SELECT/RETURNING lists below.
const TRANSITION_COLUMNS: &str = "id, model_ref, from_state, to_state, name, required_privilege, \
     guard_expression, entry_actions, exit_actions, display_order, row_version, approval_plan, \
     pending_state, on_reject_state, auto_condition, owner_layer";

impl From<TransitionRow> for TransitionListItem {
    fn from(r: TransitionRow) -> Self {
        TransitionListItem {
            id: r.id,
            model_ref: r.model_ref,
            from_state: r.from_state,
            to_state: r.to_state,
            name: r.name,
            required_privilege: r.required_privilege,
            guard_expression: r.guard_expression,
            entry_actions: r.entry_actions,
            exit_actions: r.exit_actions,
            display_order: r.display_order,
            row_version: r.row_version,
            // Written only after `validate_transition_approval`, so a parse
            // failure means a hand-edited row; shown as absent rather than
            // failing the whole model read (the registry refuses the edge).
            approval_plan: r.approval_plan.and_then(|v| serde_json::from_value(v).ok()),
            pending_state: r.pending_state,
            on_reject_state: r.on_reject_state,
            auto_condition: r.auto_condition,
            owner_layer: r.owner_layer,
        }
    }
}

// ── Changeset recording (D-785) ─────────────────────────────────────────────

/// A stored `owner_layer`, parsed. The column's CHECK admits only the four
/// layers, so an unknown value is a defect, not client input.
fn parse_owner_layer(value: &str) -> Result<Layer, AppError> {
    Layer::parse(value).ok_or_else(|| AppError::internal(format!("unknown owner_layer {value:?}")))
}

/// A transition's logical key inside its model: the `(from_state, to_state)`
/// edge, which the table keeps unique per model.
fn transition_key(from_state: &str, to_state: &str) -> String {
    format!("{from_state}->{to_state}")
}

/// The changeset operation for a state model just written.
fn model_op(op: Op, row: &ModelRow) -> Result<RecordedOp, AppError> {
    Ok(RecordedOp {
        op,
        object_kind: "state_model",
        object_ref: Some(row.id),
        target: serde_json::json!({ "entity": row.entity_logicalname }),
        snapshot: serde_json::to_value(row).map_err(AppError::internal)?,
        changed: Vec::new(),
    })
}

/// The changeset operation for a transition just written, on the model of
/// `entity_logicalname`.
fn transition_op(
    op: Op,
    entity_logicalname: &str,
    row: &TransitionRow,
) -> Result<RecordedOp, AppError> {
    Ok(RecordedOp {
        op,
        object_kind: "state_transition",
        object_ref: Some(row.id),
        target: serde_json::json!({
            "entity": entity_logicalname,
            "transition": transition_key(&row.from_state, &row.to_state),
        }),
        snapshot: serde_json::to_value(row).map_err(AppError::internal)?,
        changed: Vec::new(),
    })
}

/// The model row inside the write's transaction (live or just
/// soft-deleted), for the snapshot.
async fn fetch_model_in_tx(tx: &mut attome_db::Tx<'_>, id: Uuid) -> Result<ModelRow, AppError> {
    sqlx::query_as(&format!(
        "SELECT {MODEL_COLUMNS} FROM state_model WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Checks the live model's owner layer against the recording (409
/// `layer_mismatch`); `NotFound` when there is no live model.
async fn check_live_model_owner(
    tx: &mut attome_db::Tx<'_>,
    recording: &RecordingCtx,
    id: Uuid,
) -> Result<(), AppError> {
    let layer: Option<String> = sqlx::query_scalar(
        "SELECT owner_layer FROM state_model WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let layer = layer.ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&layer)?)
}

/// The entity a model belongs to (live or soft-deleted): a transition's
/// logical key is scoped by it.
/// M8-T3: a transition's automatic condition, trimmed (blank is none),
/// refused unless it compiles to a yes-or-no over the model entity's fields.
async fn checked_auto_condition(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    model_id: Uuid,
    raw: Option<&str>,
) -> Result<Option<String>, AppError> {
    let Some(source) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let entity = model_entity_in_tx(tx, model_id).await?;
    let attrs = state
        .entities
        .load()
        .get(entity.as_str())
        .map(|m| m.attrs.clone())
        .unwrap_or_default();
    match crate::auto_transitions::check_condition(&attrs, source) {
        None => Ok(Some(source.to_owned())),
        Some(problem) => Err(AppError::Validation(format!("auto_condition: {problem}"))),
    }
}

async fn model_entity_in_tx(
    tx: &mut attome_db::Tx<'_>,
    model_id: Uuid,
) -> Result<String, AppError> {
    sqlx::query_scalar("SELECT entity_logicalname FROM state_model WHERE id = $1")
        .bind(model_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

/// A transition's approval settings after trimming, with an empty
/// `pending_state`/`on_reject_state` read as absent.
struct ApprovalSettings {
    plan: Option<attome_approval::ApprovalPlan>,
    pending_state: Option<String>,
    on_reject_state: Option<String>,
}

impl ApprovalSettings {
    fn new(
        plan: Option<attome_approval::ApprovalPlan>,
        pending_state: Option<&str>,
        on_reject_state: Option<&str>,
    ) -> Self {
        let clean = |v: Option<&str>| {
            v.map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        };
        Self {
            plan,
            pending_state: clean(pending_state),
            on_reject_state: clean(on_reject_state),
        }
    }

    /// The plan as the JSONB value to store.
    fn plan_json(&self) -> Result<Option<serde_json::Value>, AppError> {
        self.plan
            .as_ref()
            .map(|p| serde_json::to_value(p).map_err(AppError::internal))
            .transpose()
    }

    /// Every state the settings name, for the state-field option check.
    fn states(&self) -> Vec<&str> {
        self.pending_state
            .iter()
            .chain(self.on_reject_state.iter())
            .map(String::as_str)
            .collect()
    }

    fn validate(&self, from: &str, to: &str, initial_state: &str) -> Result<(), AppError> {
        crate::approval::validate_transition_approval(
            from,
            to,
            self.plan.as_ref(),
            self.pending_state.as_deref(),
            self.on_reject_state.as_deref(),
            Some(initial_state),
        )
    }
}

/// `state_field` must name an existing `Choice` attribute (`field_type_int`
/// 7, or its legacy alias 8 — `attome-core/src/field_type.rs`) on a
/// registered entity.
///
/// Queries `entity_info`/`attribute_info` directly rather
/// than `state.entities` (`EntityMetaRegistry`) — that snapshot is a cache
/// (`cache.metadata_registry_enabled = false` disables it outright, the same
/// config every DB-backed test in this workspace runs with, matching
/// `entity_crud::resolve::resolve_entity`'s own fallback for that case) and
/// even when enabled it is refreshed asynchronously, so a create/update
/// requested immediately after the entity or field itself was created is not
/// guaranteed to see it yet. This is an admin-only, low-traffic surface, so a
/// direct read is the simple, always-correct choice — same reasoning
/// `resolve_entity_from_db` documents for its own fallback.
async fn validate_state_field(
    state: &EngineState,
    entity_logicalname: &str,
    state_field: &str,
) -> Result<(), AppError> {
    let entity_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_logicalname)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(entity_id) = entity_id else {
        return Err(AppError::Validation(format!(
            "entity '{entity_logicalname}' does not exist"
        )));
    };

    let field_type: Option<i32> = sqlx::query_scalar(
        "SELECT COALESCE(\"type\", 3) FROM attribute_info \
         WHERE entity_ref = $1 AND logicalname = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_id)
    .bind(state_field)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(field_type) = field_type else {
        return Err(AppError::Validation(format!(
            "{entity_logicalname}: no field named '{state_field}'"
        )));
    };
    if !matches!(field_type, 7 | 8) {
        return Err(AppError::Validation(format!(
            "{entity_logicalname}.{state_field}: must be a Choice field to back a state model"
        )));
    }
    Ok(())
}

/// A transition's `from_state`/`to_state` must each be an option of the
/// model's state field (its Choice attribute's `options.choices`). A field
/// with no configured choices constrains nothing — the same "no options set
/// is a no-op" rule `attome-field`'s own value validation applies. Returns
/// `NotFound` when the model itself is gone.
///
/// Runs inside the caller's transaction so the model row it reads is the
/// one the write that follows is about to reference. Returns the model's
/// `initial_state` (M07 Phase F: a pending state may not be it).
async fn validate_transition_states(
    tx: &mut attome_db::Tx<'_>,
    model_id: Uuid,
    states: &[&str],
) -> Result<String, AppError> {
    let model: Option<(String, String, String)> = sqlx::query_as(
        "SELECT entity_logicalname, state_field, initial_state FROM state_model \
         WHERE id = $1 AND is_deleted = false",
    )
    .bind(model_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some((entity_logicalname, state_field, initial_state)) = model else {
        return Err(AppError::NotFound);
    };

    let choices: Option<Vec<String>> = sqlx::query_scalar(
        "SELECT ARRAY(SELECT jsonb_array_elements_text(a.options -> 'choices')) \
         FROM attribute_info a \
         JOIN entity_info e ON e.id = a.entity_ref \
         WHERE e.logicalname = $1 AND (e.is_active IS NULL OR e.is_active = true) \
           AND a.logicalname = $2 AND (a.is_active IS NULL OR a.is_active = true) \
           AND jsonb_typeof(a.options -> 'choices') = 'array'",
    )
    .bind(&entity_logicalname)
    .bind(&state_field)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let choices = choices.unwrap_or_default();
    if choices.is_empty() {
        return Ok(initial_state);
    }
    for state_value in states {
        if !choices.iter().any(|c| c == state_value) {
            return Err(AppError::Validation(format!(
                "'{state_value}' is not an option of {entity_logicalname}.{state_field}"
            )));
        }
    }
    Ok(initial_state)
}

// ── Handlers: state models ──────────────────────────────────────────────────

/// List state models
///
/// Every state model: its entity, state field, initial state and record type. Automation
/// administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/state-models",
    tag = "state",
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<StateModelListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_state_models(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Automation>>,
) -> Result<Json<PaginatedResponse<StateModelListItem>>, AppError> {
    let rows: Vec<ModelRow> = sqlx::query_as(&format!(
        "SELECT {MODEL_COLUMNS} \
         FROM state_model WHERE is_deleted = false ORDER BY entity_logicalname"
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = rows.len() as i64;
    let items: Vec<StateModelListItem> = rows.into_iter().map(Into::into).collect();
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

async fn fetch_detail(state: &EngineState, id: Uuid) -> Result<StateModelDetail, AppError> {
    let row: ModelRow = sqlx::query_as(&format!(
        "SELECT {MODEL_COLUMNS} \
         FROM state_model WHERE id = $1 AND is_deleted = false"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;

    let transitions: Vec<TransitionRow> = sqlx::query_as(&format!(
        "SELECT {TRANSITION_COLUMNS} \
         FROM state_transition WHERE model_ref = $1 AND is_deleted = false \
         ORDER BY display_order, from_state, to_state"
    ))
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let (locked_states, reasons) = (row.locked_states(), row.reasons());
    Ok(StateModelDetail {
        id: row.id,
        entity_logicalname: row.entity_logicalname,
        name: row.name,
        state_field: row.state_field,
        initial_state: row.initial_state,
        is_active: row.is_active,
        row_version: row.row_version,
        created_at: row.created_at,
        updated_at: row.updated_at,
        locked_states,
        reasons,
        record_type: row.record_type,
        reason_field: row.reason_field,
        owner_layer: row.owner_layer,
        transitions: transitions.into_iter().map(Into::into).collect(),
    })
}

/// Get a state model
///
/// One state model: its entity, state field, initial state, whether it is active, its transitions and
/// `row_version`. Automation administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/state-models/{id}",
    tag = "state",
    params(("id" = Uuid, Path, description = "State model id")),
    responses(
        (status = 200, description = "Success", body = StateModelDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_state_model(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Automation>>,
    Path(id): Path<Uuid>,
) -> Result<Json<StateModelDetail>, AppError> {
    Ok(Json(fetch_detail(&state, id).await?))
}

/// Create a state model
///
/// A state model on an entity's choice field with its initial state, optionally for one record type
/// (fixed once created; a typed model is not recorded in changesets). Recorded in the open changeset
/// otherwise. Automation administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/state-models",
    tag = "state",
    request_body = CreateStateModelBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = StateModelDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "This entity already has an active state model, or no open changeset to record into", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_state_model(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    recording: RecordingCtx,
    Json(body): Json<CreateStateModelBody>,
) -> Result<(StatusCode, Json<StateModelDetail>), AppError> {
    let entity_logicalname = body.entity_logicalname.trim().to_owned();
    let name = body.name.trim().to_owned();
    let state_field = body.state_field.trim().to_owned();
    let initial_state = body.initial_state.trim().to_owned();
    if entity_logicalname.is_empty() || name.is_empty() || initial_state.is_empty() {
        return Err(AppError::Validation(
            "entity_logicalname, name, and initial_state are required".into(),
        ));
    }
    validate_state_field(&state, &entity_logicalname, &state_field).await?;
    let record_type = body
        .record_type
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned);
    let rules = check_rules(
        &state,
        &entity_logicalname,
        &body.locked_states,
        body.reason_field.as_deref(),
        &body.reasons,
    )?;
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-state/model:{entity_logicalname}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a state-model write for this entity is already in progress",
        ));
    }

    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM state_model \
         WHERE entity_logicalname = $1 AND is_deleted = false AND is_active = true \
           AND COALESCE(record_type, '') = COALESCE($2, '')",
    )
    .bind(&entity_logicalname)
    .bind(&record_type)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if existing.is_some() {
        return Err(AppError::Conflict(
            "this entity (or record type) already has an active state model",
        ));
    }

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO state_model \
             (entity_logicalname, name, state_field, initial_state, is_active, owner_layer, \
              record_type, locked_states, reason_field, reasons) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
    )
    .bind(&entity_logicalname)
    .bind(&name)
    .bind(&state_field)
    .bind(&initial_state)
    .bind(body.is_active)
    .bind(layer.as_str())
    .bind(&record_type)
    .bind(&rules.locked_states)
    .bind(&rules.reason_field)
    .bind(&rules.reasons)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "state_model",
            Some(id),
        )
        .named("state_model.create"),
    )
    .await?;
    let row = fetch_model_in_tx(&mut tx, id).await?;
    if row.record_type.is_none() {
        recording
            .record(&mut tx, model_op(Op::UpsertStateModel, &row)?)
            .await?;
    }

    tx.commit().await.map_err(AppError::internal)?;
    crate::reconcile::invalidate(&state).await;

    Ok((StatusCode::CREATED, Json(fetch_detail(&state, id).await?)))
}

/// Change a state model
///
/// Changes the fields given. Recorded in the open changeset. Automation administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/state-models/{id}",
    tag = "state",
    params(("id" = Uuid, Path, description = "State model id")),
    request_body = UpdateStateModelBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = StateModelDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "row_version mismatch, no open changeset to record into, or the model is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_state_model(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateStateModelBody>,
) -> Result<Json<StateModelDetail>, AppError> {
    let name = body.name.trim().to_owned();
    let state_field = body.state_field.trim().to_owned();
    let initial_state = body.initial_state.trim().to_owned();
    if name.is_empty() || initial_state.is_empty() {
        return Err(AppError::Validation(
            "name and initial_state are required".into(),
        ));
    }
    let entity_logicalname: String = sqlx::query_scalar(
        "SELECT entity_logicalname FROM state_model WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    validate_state_field(&state, &entity_logicalname, &state_field).await?;
    let rules = check_rules(
        &state,
        &entity_logicalname,
        &body.locked_states,
        body.reason_field.as_deref(),
        &body.reasons,
    )?;
    recording.preflight(&state.base.db).await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-state/model:{entity_logicalname}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a state-model write for this entity is already in progress",
        ));
    }
    check_live_model_owner(&mut tx, &recording, id).await?;
    let n = sqlx::query(
        "UPDATE state_model \
         SET name = $2, state_field = $3, initial_state = $4, is_active = $5, \
             locked_states = $7, reason_field = $8, reasons = $9, \
             updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND is_deleted = false AND row_version = $6",
    )
    .bind(id)
    .bind(&name)
    .bind(&state_field)
    .bind(&initial_state)
    .bind(body.is_active)
    .bind(body.row_version)
    .bind(&rules.locked_states)
    .bind(&rules.reason_field)
    .bind(&rules.reasons)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Err(AppError::VersionConflict);
    }

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "state_model",
            Some(id),
        )
        .named("state_model.update"),
    )
    .await?;
    let row = fetch_model_in_tx(&mut tx, id).await?;
    if row.record_type.is_none() {
        recording
            .record(&mut tx, model_op(Op::UpsertStateModel, &row)?)
            .await?;
    }

    tx.commit().await.map_err(AppError::internal)?;
    crate::reconcile::invalidate(&state).await;

    Ok(Json(fetch_detail(&state, id).await?))
}

/// Delete a state model
///
/// Retires the model. Recorded in the open changeset. Automation administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/state-models/{id}",
    tag = "state",
    params(("id" = Uuid, Path, description = "State model id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the row is owned by another layer", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_state_model(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    check_live_model_owner(&mut tx, &recording, id).await?;
    let n = sqlx::query(
        "UPDATE state_model \
         SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::SoftDelete,
            ctx.user_id,
            "state_model",
            Some(id),
        )
        .named("state_model.delete"),
    )
    .await?;
    let row = fetch_model_in_tx(&mut tx, id).await?;
    if row.record_type.is_none() {
        recording
            .record(&mut tx, model_op(Op::RetireStateModel, &row)?)
            .await?;
    }

    tx.commit().await.map_err(AppError::internal)?;
    crate::reconcile::invalidate(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Handlers: transitions ────────────────────────────────────────────────────

/// Add a transition to a state model
///
/// A named move from one state to another, with an optional privilege, guard expression, and entry
/// and exit actions. Recorded in the open changeset. Automation administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/state-models/{id}/transitions",
    tag = "state",
    params(("id" = Uuid, Path, description = "State model id")),
    request_body = CreateTransitionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = TransitionListItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "State model not found", body = ErrorResponse),
        (status = 409, description = "This edge already exists, or no open changeset to record into", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_transition(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateTransitionBody>,
) -> Result<(StatusCode, Json<TransitionListItem>), AppError> {
    let from_state = body.from_state.trim().to_owned();
    let to_state = body.to_state.trim().to_owned();
    let name = body.name.trim().to_owned();
    if from_state.is_empty() || to_state.is_empty() || name.is_empty() {
        return Err(AppError::Validation(
            "from_state, to_state, and name are required".into(),
        ));
    }

    let approval = ApprovalSettings::new(
        body.approval_plan,
        body.pending_state.as_deref(),
        body.on_reject_state.as_deref(),
    );
    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-state/transition:{id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a transition write for this model is already in progress",
        ));
    }
    let mut named_states = vec![from_state.as_str(), to_state.as_str()];
    named_states.extend(approval.states());
    let initial_state = validate_transition_states(&mut tx, id, &named_states).await?;
    approval.validate(&from_state, &to_state, &initial_state)?;
    let auto_condition =
        checked_auto_condition(&state, &mut tx, id, body.auto_condition.as_deref()).await?;

    let row: TransitionRow = sqlx::query_as(&format!(
        "INSERT INTO state_transition \
             (model_ref, from_state, to_state, name, required_privilege, guard_expression, \
              entry_actions, exit_actions, display_order, approval_plan, pending_state, \
              on_reject_state, owner_layer, auto_condition) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
         RETURNING {TRANSITION_COLUMNS}"
    ))
    .bind(id)
    .bind(&from_state)
    .bind(&to_state)
    .bind(&name)
    .bind(&body.required_privilege)
    .bind(&body.guard_expression)
    .bind(&body.entry_actions)
    .bind(&body.exit_actions)
    .bind(body.display_order)
    .bind(approval.plan_json()?)
    .bind(&approval.pending_state)
    .bind(&approval.on_reject_state)
    .bind(layer.as_str())
    .bind(&auto_condition)
    .fetch_one(&mut *tx)
    .await
    .map_err(map_unique_violation)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "state_transition",
            Some(row.id),
        )
        .named("state_transition.create"),
    )
    .await?;
    let entity_logicalname = model_entity_in_tx(&mut tx, id).await?;
    if !model_is_typed(&mut tx, id).await? {
        recording
            .record(
                &mut tx,
                transition_op(Op::UpsertStateTransition, &entity_logicalname, &row)?,
            )
            .await?;
    }

    tx.commit().await.map_err(AppError::internal)?;
    crate::reconcile::invalidate(&state).await;

    Ok((StatusCode::CREATED, Json(row.into())))
}

/// Change a transition
///
/// Changes the fields given. Recorded in the open changeset. Automation administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/state-models/{id}/transitions/{transition_id}",
    tag = "state",
    params(
        ("id" = Uuid, Path, description = "State model id"),
        ("transition_id" = Uuid, Path, description = "Transition id"),
    ),
    request_body = UpdateTransitionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = TransitionListItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "row_version mismatch, the new (from_state, to_state) edge already exists, no open changeset to record into, or the transition is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_transition(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    recording: RecordingCtx,
    Path((id, transition_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateTransitionBody>,
) -> Result<Json<TransitionListItem>, AppError> {
    let name = body.name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    // Omitted keeps the current end; present must be non-blank, same as
    // create's own required-field check.
    let new_from = trimmed_edge_end(body.from_state.as_deref(), "from_state")?;
    let new_to = trimmed_edge_end(body.to_state.as_deref(), "to_state")?;
    recording.preflight(&state.base.db).await?;

    // The same lock create takes: two writes that move edges on one model
    // are serialized, so the (model, from, to) uniqueness is never decided
    // by a race between them.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-state/transition:{id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a transition write for this model is already in progress",
        ));
    }

    let current: Option<(String, String, i64, String)> = sqlx::query_as(
        "SELECT from_state, to_state, row_version, owner_layer FROM state_transition \
         WHERE id = $1 AND model_ref = $2 AND is_deleted = false",
    )
    .bind(transition_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((current_from, current_to, current_row_version, current_layer)) = current else {
        return Err(AppError::NotFound);
    };
    recording.check_owner(parse_owner_layer(&current_layer)?)?;
    if current_row_version != body.row_version {
        return Err(AppError::VersionConflict);
    }
    let from_state = new_from.unwrap_or(current_from);
    let to_state = new_to.unwrap_or(current_to);
    let approval = ApprovalSettings::new(
        body.approval_plan,
        body.pending_state.as_deref(),
        body.on_reject_state.as_deref(),
    );
    let mut named_states = vec![from_state.as_str(), to_state.as_str()];
    named_states.extend(approval.states());
    let initial_state = validate_transition_states(&mut tx, id, &named_states).await?;
    approval.validate(&from_state, &to_state, &initial_state)?;
    let auto_condition =
        checked_auto_condition(&state, &mut tx, id, body.auto_condition.as_deref()).await?;

    let row: Option<TransitionRow> = sqlx::query_as(&format!(
        "UPDATE state_transition \
         SET from_state = $3, to_state = $4, name = $5, required_privilege = $6, \
             guard_expression = $7, entry_actions = $8, exit_actions = $9, display_order = $10, \
             approval_plan = $12, pending_state = $13, on_reject_state = $14, \
             auto_condition = $15, \
             updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND model_ref = $2 AND is_deleted = false AND row_version = $11 \
         RETURNING {TRANSITION_COLUMNS}"
    ))
    .bind(transition_id)
    .bind(id)
    .bind(&from_state)
    .bind(&to_state)
    .bind(&name)
    .bind(&body.required_privilege)
    .bind(&body.guard_expression)
    .bind(&body.entry_actions)
    .bind(&body.exit_actions)
    .bind(body.display_order)
    .bind(body.row_version)
    .bind(approval.plan_json()?)
    .bind(&approval.pending_state)
    .bind(&approval.on_reject_state)
    .bind(&auto_condition)
    .fetch_optional(&mut *tx)
    .await
    .map_err(map_unique_violation)?;
    // The version was checked above under the model's transition lock; a
    // miss here means a writer that does not take that lock (a bundle
    // reconcile) moved the row in between.
    let Some(row) = row else {
        return Err(AppError::VersionConflict);
    };

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "state_transition",
            Some(row.id),
        )
        .named("state_transition.update"),
    )
    .await?;
    let entity_logicalname = model_entity_in_tx(&mut tx, id).await?;
    if !model_is_typed(&mut tx, id).await? {
        recording
            .record(
                &mut tx,
                transition_op(Op::UpsertStateTransition, &entity_logicalname, &row)?,
            )
            .await?;
    }

    tx.commit().await.map_err(AppError::internal)?;
    crate::reconcile::invalidate(&state).await;
    Ok(Json(row.into()))
}

/// Remove a transition
///
/// Records can no longer take it. Recorded in the open changeset. Automation administrators only.
/// Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/state-models/{id}/transitions/{transition_id}",
    tag = "state",
    params(
        ("id" = Uuid, Path, description = "State model id"),
        ("transition_id" = Uuid, Path, description = "Transition id"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the row is owned by another layer", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_transition(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    recording: RecordingCtx,
    Path((id, transition_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let current_layer: Option<String> = sqlx::query_scalar(
        "SELECT owner_layer FROM state_transition \
         WHERE id = $1 AND model_ref = $2 AND is_deleted = false",
    )
    .bind(transition_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let current_layer = current_layer.ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&current_layer)?)?;

    let row: Option<TransitionRow> = sqlx::query_as(&format!(
        "UPDATE state_transition \
         SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND model_ref = $2 AND is_deleted = false \
         RETURNING {TRANSITION_COLUMNS}"
    ))
    .bind(transition_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return Err(AppError::NotFound);
    };

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::SoftDelete,
            ctx.user_id,
            "state_transition",
            Some(transition_id),
        )
        .named("state_transition.delete"),
    )
    .await?;
    let entity_logicalname = model_entity_in_tx(&mut tx, id).await?;
    if !model_is_typed(&mut tx, id).await? {
        recording
            .record(
                &mut tx,
                transition_op(Op::RetireStateTransition, &entity_logicalname, &row)?,
            )
            .await?;
    }

    tx.commit().await.map_err(AppError::internal)?;
    crate::reconcile::invalidate(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `None` for an omitted edge end; the trimmed value for a present one; a
/// blank one is `422`.
fn trimmed_edge_end(value: Option<&str>, field: &str) -> Result<Option<String>, AppError> {
    match value.map(str::trim) {
        None => Ok(None),
        Some("") => Err(AppError::Validation(format!("{field} must not be blank"))),
        Some(v) => Ok(Some(v.to_owned())),
    }
}

fn map_unique_violation(error: sqlx::Error) -> AppError {
    if attome_db::is_unique_violation(&error) {
        AppError::Conflict("this (from_state, to_state) edge already exists on this model")
    } else {
        AppError::internal(error)
    }
}

// ── Routes ───────────────────────────────────────────────────────────────────

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/state-models",
            get(list_state_models).post(create_state_model),
        )
        .route(
            "/api/v1/admin/state-models/{id}",
            get(get_state_model)
                .patch(update_state_model)
                .delete(delete_state_model),
        )
        .route(
            "/api/v1/admin/state-models/{id}/transitions",
            axum::routing::post(create_transition),
        )
        .route(
            "/api/v1/admin/state-models/{id}/transitions/{transition_id}",
            axum::routing::patch(update_transition).delete(delete_transition),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document. Separate per file because `#[utoipa::path]` generates a
/// `__path_*` type with the handler's own visibility, and these handlers are
/// module-private — the crate's `openapi()` merges every fragment back into
/// one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_state_models,
    get_state_model,
    create_state_model,
    update_state_model,
    delete_state_model,
    create_transition,
    update_transition,
    delete_transition,
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_row() -> ModelRow {
        let now = chrono::Utc::now();
        ModelRow {
            id: Uuid::now_v7(),
            entity_logicalname: "incident".into(),
            name: "Incident lifecycle".into(),
            state_field: "status".into(),
            initial_state: "new".into(),
            is_active: true,
            row_version: 2,
            created_at: now,
            updated_at: now,
            owner_layer: "project".into(),
            record_type: None,
            locked_states: None,
            reason_field: None,
            reasons: None,
        }
    }

    fn transition_row() -> TransitionRow {
        TransitionRow {
            id: Uuid::now_v7(),
            model_ref: Uuid::now_v7(),
            from_state: "new".into(),
            to_state: "in_progress".into(),
            name: "Start".into(),
            required_privilege: None,
            guard_expression: None,
            entry_actions: vec![],
            exit_actions: vec![],
            display_order: 0,
            row_version: 0,
            approval_plan: None,
            pending_state: None,
            on_reject_state: None,
            auto_condition: None,
            owner_layer: "project".into(),
        }
    }

    #[test]
    fn state_model_ops_are_keyed_by_entity() {
        for op in [Op::UpsertStateModel, Op::RetireStateModel] {
            let recorded = model_op(op, &model_row()).expect("op");
            recorded.check().expect("well-formed op");
            assert_eq!(recorded.target, serde_json::json!({ "entity": "incident" }));
            assert_eq!(recorded.snapshot["owner_layer"], "project");
        }
    }

    #[test]
    fn transition_ops_are_keyed_by_entity_and_edge() {
        for op in [Op::UpsertStateTransition, Op::RetireStateTransition] {
            let recorded = transition_op(op, "incident", &transition_row()).expect("op");
            recorded.check().expect("well-formed op");
            assert_eq!(
                recorded.target,
                serde_json::json!({ "entity": "incident", "transition": "new->in_progress" })
            );
            assert_eq!(recorded.snapshot["from_state"], "new");
        }
    }

    #[test]
    fn an_unknown_stored_layer_is_an_internal_error() {
        assert_eq!(parse_owner_layer("product").ok(), Some(Layer::Product));
        assert!(matches!(parse_owner_layer("x"), Err(AppError::Internal(_))));
    }
}
