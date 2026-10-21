//! AH1-T2: everything one agent session wrote, the input to undoing a run.
//!
//! - [`collect_session_changes`]: the record changes, from the audit headers
//!   tagged with the session (`audit_header.agent_session_id`, written for
//!   every agent-initiated change) and their field details, newest first.
//! - [`collect_external_effects`]: what reached outside the deployment or a
//!   person, from the invocation ledger (`action_invocation`): every
//!   completed call of an action whose effect is external or that sends a
//!   message (the same rule the agent limits count by,
//!   [`crate::descriptor::is_message_send`]). These cannot be undone, only
//!   reported.
//!
//! **Planning** (AH1-T3, [`plan_undo`]) turns the changes into steps without
//! writing anything. Changes are grouped per record, newest record first; a
//! record changed several times is judged from the oldest change's old values
//! against the newest change's new values:
//!
//! - created by the run: soft-deleted, unless someone else changed it since
//!   (then skipped) or it is already gone;
//! - updated: each attribute whose current value is still the agent's is set
//!   back; one a person has changed since is skipped and named, so a
//!   person's later edit is never overwritten;
//! - soft-deleted: restored; restored by the agent: soft-deleted again;
//! - hard-deleted, merged, cloned, imported or exported: not undoable;
//! - every external effect: not undoable, with what it was.
//!
//! **Running** (AH1-T4): [`start_undo`] plans as the person asking and, in
//! one transaction, writes the `ai_undo_run`, one `ai_undo_item` per step
//! (newest first, the step kept in `step`) and the job [`UNDO_JOB`]. Skips
//! and not-undoable steps are final at once; the rest are `pending`.
//! [`run_undo`] applies each pending item in order as that person, with the
//! planned `row_version` as If-Match, and commits each outcome on its own:
//! `restored`, `skipped_changed` when the record moved on meanwhile (a
//! person's edit always wins), or `failed` with a short reason. An item is
//! only ever moved out of `pending` once, so a restarted job resumes at the
//! next pending item and applies nothing twice. The run ends `done`, or
//! `failed` when any item failed, with its counts in `summary`.
//!
//! **Values.** A field's old and new values are restorable only when the
//! audit kept them readably: with crypto-shredding off they are plain text;
//! with it on they are opened with the record's key
//! ([`attome_audit::erasure::read_dek`]), and a record whose key was
//! destroyed has none. A sensitive field (`value_mode` Restricted) or a
//! credential column (NotCaptured) is never read here: it is marked not
//! restorable, and its values are left out.

use std::collections::HashMap;
use std::future::Future;

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::descriptor::{Effect, is_message_send};

/// The registered job that applies an undo run.
pub const UNDO_JOB: &str = "ai_undo_run";

/// The undo job's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoRunJob {
    pub undo_run_id: Uuid,
}

/// Most headers one collection reads.
pub const MAX_CHANGES: i64 = 5_000;

/// `audit_detail.value_mode` as stored (`attome_audit::value_mode`).
const MODE_ENCRYPTED: i16 = 0;

/// One field of one change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldChange {
    pub field: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    /// False when the audit did not keep the value readably.
    pub restorable: bool,
}

/// One record change the session made.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RunChange {
    pub entity: String,
    pub record_id: Uuid,
    pub audit_header_id: Uuid,
    /// `None` for an operation that is not an entity change.
    #[serde(skip)]
    pub operation: Option<AuditOperation>,
    pub operation_code: i32,
    pub changed_on: DateTime<Utc>,
    pub version_after: Option<i64>,
    pub fields: Vec<FieldChange>,
}

/// One call that reached outside the deployment or a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExternalEffect {
    pub invocation_id: Uuid,
    pub action_id: String,
    pub outcome: String,
    pub at: DateTime<Utc>,
}

/// The entity operation a stored code names. Pure.
pub fn operation_of(code: i32) -> Option<AuditOperation> {
    Some(match code {
        0 => AuditOperation::Create,
        1 => AuditOperation::Update,
        2 => AuditOperation::SoftDelete,
        3 => AuditOperation::HardDelete,
        4 => AuditOperation::Restore,
        5 => AuditOperation::Merge,
        6 => AuditOperation::Clone,
        7 => AuditOperation::Import,
        8 => AuditOperation::Export,
        _ => return None,
    })
}

/// Whether a detail's values may be read for a restore: only those kept
/// in the default mode (or before modes existed). Pure.
pub fn readable_mode(value_mode: Option<i16>, is_sensitive: bool) -> bool {
    match value_mode {
        Some(mode) => mode == MODE_ENCRYPTED,
        None => !is_sensitive,
    }
}

type HeaderRow = (
    Uuid,
    Option<String>,
    Option<Uuid>,
    Option<i32>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
    Option<i64>,
);

type DetailRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i16>,
    bool,
);

/// Opens one stored value with the record's key, or returns it as stored
/// when the audit keeps plain text.
fn open_value(
    key: Option<&[u8; 32]>,
    encrypted: bool,
    stored: Option<String>,
) -> Result<Option<String>, ()> {
    match (stored, encrypted, key) {
        (None, _, _) => Ok(None),
        (Some(v), false, _) => Ok(Some(v)),
        (Some(v), true, Some(k)) => attome_audit::erasure::decrypt_field(k, &v)
            .map(Some)
            .map_err(|_| ()),
        (Some(_), true, None) => Err(()),
    }
}

/// The record changes `session` made, newest first.
pub async fn collect_session_changes(
    state: &EngineState,
    session: Uuid,
) -> Result<Vec<RunChange>, AppError> {
    let db = &state.base.db;
    let headers: Vec<HeaderRow> = sqlx::query_as(
        "SELECT id, entity_name, record_id, operation, changed_on, created_at, version_after \
           FROM audit_header \
          WHERE agent_session_id = $1 AND initiator = 1 AND record_id IS NOT NULL \
            AND entity_name IS NOT NULL AND operation BETWEEN 0 AND 8 \
          ORDER BY COALESCE(changed_on, created_at) DESC, id DESC LIMIT $2",
    )
    .bind(session)
    .bind(MAX_CHANGES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let ids: Vec<Uuid> = headers.iter().map(|h| h.0).collect();
    let details: Vec<DetailRow> = sqlx::query_as(
        "SELECT audit_ref, field_name, old_value, new_value, value_mode, is_sensitive \
           FROM audit_detail WHERE audit_ref = ANY($1) ORDER BY audit_ref, id",
    )
    .bind(&ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut by_header: HashMap<Uuid, Vec<&DetailRow>> = HashMap::new();
    for detail in &details {
        by_header.entry(detail.0).or_default().push(detail);
    }
    let master = state.audit_erasure_key.as_ref();
    let mut keys: HashMap<Uuid, Option<[u8; 32]>> = HashMap::new();
    let mut out = Vec::with_capacity(headers.len());
    for (id, entity, record, operation, changed_on, created_at, version_after) in headers {
        let (Some(entity), Some(record)) = (entity, record) else {
            continue;
        };
        let key = match master {
            Some(ring) => match keys.get(&record) {
                Some(known) => *known,
                None => {
                    let dek = attome_audit::erasure::read_dek(db, ring, record).await?;
                    keys.insert(record, dek);
                    dek
                }
            },
            None => None,
        };
        let fields = by_header
            .get(&id)
            .into_iter()
            .flatten()
            .filter_map(|(_, field, old, new, mode, sensitive)| {
                let field = field.clone()?;
                if !readable_mode(*mode, *sensitive) {
                    return Some(FieldChange {
                        field,
                        old_value: None,
                        new_value: None,
                        restorable: false,
                    });
                }
                let encrypted = master.is_some();
                let old = open_value(key.as_ref(), encrypted, old.clone());
                let new = open_value(key.as_ref(), encrypted, new.clone());
                Some(match (old, new) {
                    (Ok(old_value), Ok(new_value)) => FieldChange {
                        field,
                        old_value,
                        new_value,
                        restorable: true,
                    },
                    _ => FieldChange {
                        field,
                        old_value: None,
                        new_value: None,
                        restorable: false,
                    },
                })
            })
            .collect();
        let code = operation.unwrap_or(-1);
        out.push(RunChange {
            entity,
            record_id: record,
            audit_header_id: id,
            operation: operation_of(code),
            operation_code: code,
            changed_on: changed_on.unwrap_or(created_at),
            version_after,
            fields,
        });
    }
    Ok(out)
}

/// The calls `session` made that reached outside the deployment or a
/// person, newest first.
pub async fn collect_external_effects(
    state: &EngineState,
    session: Uuid,
) -> Result<Vec<ExternalEffect>, AppError> {
    let rows: Vec<(Uuid, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, action_id, outcome, created_at FROM action_invocation \
          WHERE agent_session_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2",
    )
    .bind(session)
    .bind(MAX_CHANGES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter(|(_, action, outcome, _)| {
            outcome == "completed"
                && crate::engine::REGISTRY
                    .resolve(action)
                    .is_some_and(|d| d.effect == Effect::External || is_message_send(action))
        })
        .map(|(id, action_id, outcome, at)| ExternalEffect {
            invocation_id: id,
            action_id,
            outcome,
            at,
        })
        .collect())
}

/// One planned undo step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum UndoStep {
    RevertFields {
        entity: String,
        record_id: Uuid,
        expected_row_version: i64,
        #[schema(value_type = Object)]
        set: Map<String, Value>,
    },
    SoftDelete {
        entity: String,
        record_id: Uuid,
        expected_row_version: i64,
    },
    Restore {
        entity: String,
        record_id: Uuid,
    },
    Skip {
        entity: String,
        record_id: Uuid,
        reason: String,
        changed_attributes: Vec<String>,
    },
    NotUndoable {
        entity: Option<String>,
        record_id: Option<Uuid>,
        action_id: Option<String>,
        reason: String,
    },
}

/// A record as it is now.
#[derive(Debug, Clone, PartialEq)]
pub struct CurrentRecord {
    pub row_version: i64,
    pub values: Map<String, Value>,
}

/// What the planner reads. The database one is [`RecordsReader`]; tests
/// pass a stub.
pub trait UndoReader {
    /// The live record, or `None` when it is gone or the caller cannot read
    /// it.
    fn current(
        &self,
        entity: &str,
        record_id: Uuid,
    ) -> impl Future<Output = Result<Option<CurrentRecord>, AppError>> + Send;

    /// Whether anything outside `run_headers` changed the record after
    /// `since`.
    fn changed_outside(
        &self,
        entity: &str,
        record_id: Uuid,
        since: DateTime<Utc>,
        run_headers: &[Uuid],
    ) -> impl Future<Output = Result<bool, AppError>> + Send;
}

/// The planner's reader over the record engine, as the person asking.
#[derive(Debug, Clone, Copy)]
pub struct RecordsReader<'a> {
    pub state: &'a EngineState,
    pub ctx: &'a attome_server::security::SecurityContext,
}

impl UndoReader for RecordsReader<'_> {
    async fn current(
        &self,
        entity: &str,
        record_id: Uuid,
    ) -> Result<Option<CurrentRecord>, AppError> {
        match attome_records::entity_crud::read_record_bulk(self.state, self.ctx, entity, record_id)
            .await
        {
            Ok(row) => Ok(Some(CurrentRecord {
                row_version: row.row_version(),
                values: row.data().as_object().cloned().unwrap_or_default(),
            })),
            Err(AppError::NotFound | AppError::Forbidden) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn changed_outside(
        &self,
        entity: &str,
        record_id: Uuid,
        since: DateTime<Utc>,
        run_headers: &[Uuid],
    ) -> Result<bool, AppError> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM audit_header \
              WHERE entity_name = $1 AND record_id = $2 \
                AND COALESCE(changed_on, created_at) > $3 AND NOT (id = ANY($4)) \
                AND operation BETWEEN 0 AND 8)",
        )
        .bind(entity)
        .bind(record_id)
        .bind(since)
        .bind(run_headers)
        .fetch_one(&self.state.base.db)
        .await
        .map_err(AppError::internal)
    }
}

/// Whether a current JSON value is the value the audit recorded as text.
/// Numbers compare by value, so "12.50" and 12.5 agree. Pure.
pub fn same_value(current: Option<&Value>, recorded: Option<&str>) -> bool {
    match (current, recorded) {
        (None | Some(Value::Null), None) => true,
        (None | Some(Value::Null), Some(_)) | (Some(_), None) => false,
        (Some(Value::String(s)), Some(r)) => s == r,
        (Some(Value::Bool(b)), Some(r)) => r.trim().parse::<bool>().is_ok_and(|v| v == *b),
        (Some(Value::Number(n)), Some(r)) => match (n.as_f64(), r.trim().parse::<f64>()) {
            (Some(a), Ok(b)) => (a - b).abs() < 1e-9,
            _ => false,
        },
        (Some(other), Some(r)) => other.to_string() == r,
    }
}

/// The recorded old text as a JSON value shaped like the current one. Pure.
pub fn restore_value(recorded: Option<&str>, shape: Option<&Value>) -> Value {
    let Some(text) = recorded else {
        return Value::Null;
    };
    match shape {
        Some(Value::Number(_)) => serde_json::from_str::<serde_json::Number>(text.trim())
            .map(Value::Number)
            .unwrap_or_else(|_| Value::String(text.to_owned())),
        Some(Value::Bool(_)) => text
            .trim()
            .parse::<bool>()
            .map(Value::Bool)
            .unwrap_or_else(|_| Value::String(text.to_owned())),
        Some(Value::Array(_) | Value::Object(_)) => {
            serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned()))
        }
        _ => Value::String(text.to_owned()),
    }
}

/// One attribute across a record's changes: the oldest old value, the
/// newest new value, and whether every change kept them readably.
#[derive(Debug, Clone, PartialEq)]
struct Span {
    old: Option<String>,
    new: Option<String>,
    restorable: bool,
}

/// The record's attributes across its changes, which come newest first.
/// Pure.
fn spans(changes: &[&RunChange]) -> Vec<(String, Span)> {
    let mut out: Vec<(String, Span)> = Vec::new();
    for change in changes {
        for f in &change.fields {
            match out.iter_mut().find(|(name, _)| *name == f.field) {
                // An older change: its old value is the earlier one.
                Some((_, span)) => {
                    span.old.clone_from(&f.old_value);
                    span.restorable &= f.restorable;
                }
                None => out.push((
                    f.field.clone(),
                    Span {
                        old: f.old_value.clone(),
                        new: f.new_value.clone(),
                        restorable: f.restorable,
                    },
                )),
            }
        }
    }
    out
}

/// The steps that undo `changes` (newest first, as collected) and report
/// `externals`. Writes nothing.
pub async fn plan_undo<R: UndoReader>(
    reader: &R,
    changes: &[RunChange],
    externals: &[ExternalEffect],
) -> Result<Vec<UndoStep>, AppError> {
    let run_headers: Vec<Uuid> = changes.iter().map(|c| c.audit_header_id).collect();
    let mut order: Vec<(String, Uuid)> = Vec::new();
    for c in changes {
        let key = (c.entity.clone(), c.record_id);
        if !order.contains(&key) {
            order.push(key);
        }
    }
    let mut steps = Vec::new();
    for (entity, record_id) in order {
        let mine: Vec<&RunChange> = changes
            .iter()
            .filter(|c| c.entity == entity && c.record_id == record_id)
            .collect();
        let Some(newest) = mine.first() else {
            continue;
        };
        let created = mine
            .iter()
            .find(|c| c.operation == Some(AuditOperation::Create));
        let gone = |reason: &str| UndoStep::NotUndoable {
            entity: Some(entity.clone()),
            record_id: Some(record_id),
            action_id: None,
            reason: reason.to_owned(),
        };
        if let Some(created) = created {
            if reader
                .changed_outside(&entity, record_id, created.changed_on, &run_headers)
                .await?
            {
                steps.push(UndoStep::Skip {
                    entity: entity.clone(),
                    record_id,
                    reason: "edited after the agent created it".into(),
                    changed_attributes: Vec::new(),
                });
            } else {
                match reader.current(&entity, record_id).await? {
                    Some(now) => steps.push(UndoStep::SoftDelete {
                        entity: entity.clone(),
                        record_id,
                        expected_row_version: now.row_version,
                    }),
                    None => steps.push(gone("the record the agent created is already gone")),
                }
            }
            continue;
        }
        match newest.operation {
            Some(AuditOperation::SoftDelete) => steps.push(UndoStep::Restore {
                entity: entity.clone(),
                record_id,
            }),
            Some(AuditOperation::Restore) => match reader.current(&entity, record_id).await? {
                Some(now) => steps.push(UndoStep::SoftDelete {
                    entity: entity.clone(),
                    record_id,
                    expected_row_version: now.row_version,
                }),
                None => steps.push(gone("the record is already gone")),
            },
            Some(AuditOperation::Update) => {
                let Some(now) = reader.current(&entity, record_id).await? else {
                    steps.push(gone("the record is gone or not readable"));
                    continue;
                };
                let mut set = Map::new();
                let mut changed = Vec::new();
                let mut unreadable = Vec::new();
                for (field, span) in spans(&mine) {
                    if !span.restorable {
                        unreadable.push(field);
                        continue;
                    }
                    let current = now.values.get(&field);
                    if same_value(current, span.new.as_deref()) {
                        set.insert(field, restore_value(span.old.as_deref(), current));
                    } else {
                        changed.push(field);
                    }
                }
                if !set.is_empty() {
                    steps.push(UndoStep::RevertFields {
                        entity: entity.clone(),
                        record_id,
                        expected_row_version: now.row_version,
                        set,
                    });
                }
                if !changed.is_empty() {
                    steps.push(UndoStep::Skip {
                        entity: entity.clone(),
                        record_id,
                        reason: "a person changed these attributes since".into(),
                        changed_attributes: changed,
                    });
                }
                if !unreadable.is_empty() {
                    steps.push(gone(&format!(
                        "the audit did not keep these values: {}",
                        unreadable.join(", ")
                    )));
                }
            }
            Some(AuditOperation::HardDelete) => {
                steps.push(gone("a hard delete cannot be undone"));
            }
            _ => steps.push(gone(&format!(
                "operation {} cannot be undone",
                newest.operation_code
            ))),
        }
    }
    for e in externals {
        let reason = if is_message_send(&e.action_id) {
            "the message was already sent"
        } else {
            "it reached a system outside this deployment"
        };
        steps.push(UndoStep::NotUndoable {
            entity: Some("action_invocation".into()),
            record_id: Some(e.invocation_id),
            action_id: Some(e.action_id.clone()),
            reason: reason.into(),
        });
    }
    Ok(steps)
}

/// How a step is stored: entity, record, operation, first outcome, the
/// attributes it names and its detail. Pure.
pub fn item_parts(
    step: &UndoStep,
) -> (String, Uuid, &'static str, &'static str, Vec<String>, Option<String>) {
    match step {
        UndoStep::RevertFields {
            entity, record_id, set, ..
        } => (
            entity.clone(),
            *record_id,
            "revert_fields",
            "pending",
            set.keys().cloned().collect(),
            None,
        ),
        UndoStep::SoftDelete {
            entity, record_id, ..
        } => (
            entity.clone(),
            *record_id,
            "soft_delete",
            "pending",
            Vec::new(),
            None,
        ),
        UndoStep::Restore { entity, record_id } => (
            entity.clone(),
            *record_id,
            "restore",
            "pending",
            Vec::new(),
            None,
        ),
        UndoStep::Skip {
            entity,
            record_id,
            reason,
            changed_attributes,
        } => (
            entity.clone(),
            *record_id,
            "skip",
            "skipped_changed",
            changed_attributes.clone(),
            Some(reason.clone()),
        ),
        UndoStep::NotUndoable {
            entity,
            record_id,
            action_id,
            reason,
        } => (
            entity.clone().unwrap_or_else(|| "unknown".into()),
            record_id.unwrap_or(Uuid::nil()),
            "not_undoable",
            "not_undoable",
            Vec::new(),
            Some(match action_id {
                Some(action) => format!("{action}: {reason}"),
                None => reason.clone(),
            }),
        ),
    }
}

/// Plans undoing `sessions` as `ctx` and stores the run, its items and the
/// job in one transaction. Returns the run's id.
pub async fn start_undo(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    sessions: &[Uuid],
) -> Result<Uuid, AppError> {
    let mut changes = Vec::new();
    let mut externals = Vec::new();
    for session in sessions {
        changes.extend(collect_session_changes(state, *session).await?);
        externals.extend(collect_external_effects(state, *session).await?);
    }
    changes.sort_by_key(|c| std::cmp::Reverse((c.changed_on, c.audit_header_id)));
    let reader = RecordsReader { state, ctx };
    let steps = plan_undo(&reader, &changes, &externals).await?;
    let run = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO ai_undo_run (id, scope, agent_session_ids, requested_by, status) \
         VALUES ($1, 'session', $2, $3, 'planned')",
    )
    .bind(run)
    .bind(sessions)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for (seq, step) in steps.iter().enumerate() {
        let (entity, record, operation, outcome, attributes, detail) = item_parts(step);
        sqlx::query(
            "INSERT INTO ai_undo_item \
                 (undo_run_id, entity, record_id, operation, outcome, changed_attributes, \
                  detail, seq, step) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(run)
        .bind(entity)
        .bind(record)
        .bind(operation)
        .bind(outcome)
        .bind(attributes)
        .bind(detail)
        .bind(i32::try_from(seq).map_err(AppError::internal)?)
        .bind(serde_json::to_value(step).map_err(AppError::internal)?)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    let job = attome_jobs::RegisteredJob {
        name: UNDO_JOB.to_owned(),
        version: 1,
        payload: serde_json::to_value(UndoRunJob { undo_run_id: run })
            .map_err(AppError::internal)?,
        next: None,
    };
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    // AH1-T5: an undo changes what an agent did, so it is an Ai event,
    // written with the run it starts.
    let note = format!("{} step(s) for {} session(s)", steps.len(), sessions.len());
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Ai,
            AuditOperation::Create,
            ctx.user_id,
            "ai_undo_run",
            Some(run),
        )
        .named("ai.undo.start")
        .comment(note),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    tracing::info!(%run, steps = steps.len(), "undo run planned");
    Ok(run)
}

/// The outcome of applying one step, and its detail. Pure.
pub fn outcome_of(result: &Result<(), AppError>) -> (&'static str, Option<String>) {
    match result {
        Ok(()) => ("restored", None),
        Err(
            AppError::VersionConflict | AppError::VersionConflictAt { .. } | AppError::Conflict(_),
        ) => (
            "skipped_changed",
            Some("the record changed after the undo was planned".into()),
        ),
        Err(AppError::NotFound) => ("failed", Some("the record is no longer there".into())),
        Err(AppError::Forbidden) => ("failed", Some("the change is not allowed".into())),
        Err(AppError::Validation(message)) => ("failed", Some(message.clone())),
        Err(_) => ("failed", Some("the change was refused".into())),
    }
}

/// Applies one stored step as `ctx`.
async fn apply(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    run: Uuid,
    step: &UndoStep,
) -> Result<(), AppError> {
    let user = ctx.user_id;
    match step {
        UndoStep::RevertFields {
            entity,
            record_id,
            expected_row_version,
            set,
        } => attome_records::entity_crud::update_record_for(
            state,
            ctx,
            user,
            entity,
            *record_id,
            *expected_row_version,
            Value::Object(set.clone()),
        )
        .await
        .map(|_| ()),
        UndoStep::SoftDelete {
            entity,
            record_id,
            expected_row_version,
        } => {
            let origin = attome_records::entity_mutation::DeleteOrigin::with_id(
                attome_records::entity_mutation::DeleteKind::Request,
                format!("undo:{run}"),
            );
            attome_records::entity_crud::delete_record_for(
                state,
                ctx,
                user,
                entity,
                *record_id,
                Some(*expected_row_version),
                &origin,
            )
            .await
        }
        UndoStep::Restore { entity, record_id } => {
            attome_records::entity_crud::restore_record_for(
                state,
                ctx,
                user,
                entity,
                *record_id,
                None,
            )
            .await
            .map(|_| ())
        }
        UndoStep::Skip { .. } | UndoStep::NotUndoable { .. } => Ok(()),
    }
}

type ItemRow = (Uuid, Option<Value>);

/// Applies an undo run's pending items in order. Safe to run again.
pub async fn run_undo(state: &EngineState, run: Uuid) -> Result<(), AppError> {
    let db = &state.base.db;
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT requested_by, status FROM ai_undo_run WHERE id = $1")
            .bind(run)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let Some((requested_by, status)) = row else {
        return Err(AppError::NotFound);
    };
    if status == "done" || status == "failed" {
        return Ok(());
    }
    let ctx = state.base.security.resolve(requested_by).await?;
    sqlx::query("UPDATE ai_undo_run SET status = 'running' WHERE id = $1 AND status = 'planned'")
        .bind(run)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    let items: Vec<ItemRow> = sqlx::query_as(
        "SELECT id, step FROM ai_undo_item \
          WHERE undo_run_id = $1 AND outcome = 'pending' ORDER BY seq",
    )
    .bind(run)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (item, step) in items {
        let result = match step.map(serde_json::from_value::<UndoStep>) {
            Some(Ok(step)) => apply(state, &ctx, run, &step).await,
            _ => Err(AppError::Validation("the planned step could not be read".into())),
        };
        let (outcome, detail) = outcome_of(&result);
        sqlx::query(
            "UPDATE ai_undo_item SET outcome = $2, detail = $3 \
              WHERE id = $1 AND outcome = 'pending'",
        )
        .bind(item)
        .bind(outcome)
        .bind(detail)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    }
    let counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT outcome, count(*) FROM ai_undo_item WHERE undo_run_id = $1 GROUP BY outcome",
    )
    .bind(run)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let summary: Map<String, Value> = counts
        .iter()
        .map(|(outcome, n)| (outcome.clone(), json!(n)))
        .collect();
    let failed = counts.iter().any(|(o, n)| o == "failed" && *n > 0);
    sqlx::query(
        "UPDATE ai_undo_run SET status = $2, finished_at = now(), summary = $3 \
          WHERE id = $1 AND status IN ('planned', 'running')",
    )
    .bind(run)
    .bind(if failed { "failed" } else { "done" })
    .bind(Value::Object(summary))
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    tracing::info!(%run, failed, "undo run finished");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn undo_reads_only_values_kept_readably() {
        assert!(readable_mode(Some(0), false));
        assert!(
            !readable_mode(Some(1), true),
            "a sensitive field is restricted"
        );
        assert!(
            !readable_mode(Some(2), false),
            "a credential column is not captured"
        );
        assert!(readable_mode(None, false), "before modes, a plain field");
        assert!(
            !readable_mode(None, true),
            "before modes, a sensitive field"
        );
    }

    #[test]
    fn undo_opens_plain_values_and_refuses_ciphertext_without_a_key() {
        assert_eq!(
            open_value(None, false, Some("a".into())),
            Ok(Some("a".into()))
        );
        assert_eq!(open_value(None, false, None), Ok(None));
        assert_eq!(open_value(None, true, Some("c2VjcmV0".into())), Err(()));
        assert_eq!(open_value(None, true, None), Ok(None));
    }

    #[test]
    fn undo_maps_entity_operations() {
        assert_eq!(operation_of(0), Some(AuditOperation::Create));
        assert_eq!(operation_of(2), Some(AuditOperation::SoftDelete));
        assert_eq!(operation_of(8), Some(AuditOperation::Export));
        assert_eq!(operation_of(9), None, "a login is not an entity change");
        assert_eq!(operation_of(-1), None);
    }

    /// A reader over fixed records, for the planner's branches.
    struct Stub {
        records: HashMap<Uuid, CurrentRecord>,
        edited: Vec<Uuid>,
    }

    impl UndoReader for Stub {
        async fn current(
            &self,
            _entity: &str,
            record_id: Uuid,
        ) -> Result<Option<CurrentRecord>, AppError> {
            Ok(self.records.get(&record_id).cloned())
        }

        async fn changed_outside(
            &self,
            _entity: &str,
            record_id: Uuid,
            _since: DateTime<Utc>,
            _run_headers: &[Uuid],
        ) -> Result<bool, AppError> {
            Ok(self.edited.contains(&record_id))
        }
    }

    fn stub(id: Uuid, version: i64, values: Value) -> Stub {
        let values = values.as_object().cloned().unwrap_or_default();
        let current = CurrentRecord {
            row_version: version,
            values,
        };
        Stub {
            records: HashMap::from([(id, current)]),
            edited: Vec::new(),
        }
    }

    fn field(name: &str, old: Option<&str>, new: Option<&str>) -> FieldChange {
        FieldChange {
            field: name.into(),
            old_value: old.map(str::to_owned),
            new_value: new.map(str::to_owned),
            restorable: true,
        }
    }

    fn change(record: Uuid, op: AuditOperation, fields: Vec<FieldChange>) -> RunChange {
        RunChange {
            entity: "deal".into(),
            record_id: record,
            audit_header_id: Uuid::now_v7(),
            operation: Some(op),
            operation_code: op as i32,
            changed_on: Utc::now(),
            version_after: Some(2),
            fields,
        }
    }

    fn reverted(steps: &[UndoStep]) -> Option<(i64, &Map<String, Value>)> {
        steps.iter().find_map(|s| match s {
            UndoStep::RevertFields {
                expected_row_version, set, ..
            } => Some((*expected_row_version, set)),
            _ => None,
        })
    }

    fn skipped(steps: &[UndoStep]) -> Option<&Vec<String>> {
        steps.iter().find_map(|s| match s {
            UndoStep::Skip {
                changed_attributes, ..
            } => Some(changed_attributes),
            _ => None,
        })
    }

    #[tokio::test]
    async fn undo_plan_reverts_an_update_still_as_the_agent_left_it() {
        let id = Uuid::now_v7();
        let reader = stub(id, 5, json!({ "stage": "won", "amount": 12.5 }));
        let fields = vec![
            field("stage", Some("open"), Some("won")),
            field("amount", Some("10"), Some("12.50")),
        ];
        let changes = [change(id, AuditOperation::Update, fields)];
        let steps = plan_undo(&reader, &changes, &[]).await.unwrap();
        assert_eq!(steps.len(), 1);
        let (version, set) = reverted(&steps).unwrap();
        assert_eq!(version, 5);
        assert_eq!(set["stage"], json!("open"));
        assert_eq!(set["amount"], json!(10));
    }

    #[tokio::test]
    async fn undo_plan_skips_an_attribute_a_person_changed() {
        let id = Uuid::now_v7();
        let reader = stub(id, 7, json!({ "stage": "lost", "note": "x" }));
        let fields = vec![
            field("stage", Some("open"), Some("won")),
            field("note", None, Some("x")),
        ];
        let changes = [change(id, AuditOperation::Update, fields)];
        let steps = plan_undo(&reader, &changes, &[]).await.unwrap();
        let (_, set) = reverted(&steps).unwrap();
        assert!(set.contains_key("note") && !set.contains_key("stage"));
        assert_eq!(skipped(&steps), Some(&vec!["stage".to_owned()]));
    }

    #[tokio::test]
    async fn undo_plan_soft_deletes_a_created_record_unless_edited() {
        let id = Uuid::now_v7();
        let mut reader = stub(id, 3, json!({}));
        let changes = [change(id, AuditOperation::Create, Vec::new())];
        let steps = plan_undo(&reader, &changes, &[]).await.unwrap();
        assert!(matches!(
            steps[0],
            UndoStep::SoftDelete {
                expected_row_version: 3,
                ..
            }
        ));
        reader.edited.push(id);
        let steps = plan_undo(&reader, &changes, &[]).await.unwrap();
        assert!(matches!(steps[0], UndoStep::Skip { .. }));
    }

    #[tokio::test]
    async fn undo_plan_restores_deletes_and_lists_sends() {
        let soft = Uuid::now_v7();
        let hard = Uuid::now_v7();
        let reader = Stub {
            records: HashMap::new(),
            edited: Vec::new(),
        };
        let changes = [
            change(soft, AuditOperation::SoftDelete, Vec::new()),
            change(hard, AuditOperation::HardDelete, Vec::new()),
        ];
        let sent = ExternalEffect {
            invocation_id: Uuid::now_v7(),
            action_id: "email.send".into(),
            outcome: "completed".into(),
            at: Utc::now(),
        };
        let steps = plan_undo(&reader, &changes, &[sent]).await.unwrap();
        assert!(matches!(steps[0], UndoStep::Restore { .. }));
        let reasons: Vec<&str> = steps
            .iter()
            .filter_map(|s| match s {
                UndoStep::NotUndoable { reason, .. } => Some(reason.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            reasons,
            ["a hard delete cannot be undone", "the message was already sent"]
        );
    }

    #[tokio::test]
    async fn undo_plan_judges_a_record_from_its_oldest_old_and_newest_new_values() {
        let id = Uuid::now_v7();
        let reader = stub(id, 9, json!({ "stage": "won" }));
        // Newest first: open -> qualified, then qualified -> won.
        let newer = vec![field("stage", Some("qualified"), Some("won"))];
        let older = vec![field("stage", Some("open"), Some("qualified"))];
        let changes = [
            change(id, AuditOperation::Update, newer),
            change(id, AuditOperation::Update, older),
        ];
        let steps = plan_undo(&reader, &changes, &[]).await.unwrap();
        assert_eq!(steps.len(), 1);
        let (_, set) = reverted(&steps).unwrap();
        assert_eq!(set["stage"], json!("open"));
    }

    #[test]
    fn undo_run_items_start_pending_or_final() {
        let id = Uuid::now_v7();
        let revert = UndoStep::RevertFields {
            entity: "deal".into(),
            record_id: id,
            expected_row_version: 4,
            set: Map::from_iter([("stage".to_owned(), json!("open"))]),
        };
        let (_, _, op, outcome, attrs, _) = item_parts(&revert);
        assert_eq!((op, outcome), ("revert_fields", "pending"));
        assert_eq!(attrs, vec!["stage".to_owned()]);
        let skip = UndoStep::Skip {
            entity: "deal".into(),
            record_id: id,
            reason: "changed".into(),
            changed_attributes: vec!["amount".into()],
        };
        assert_eq!(item_parts(&skip).3, "skipped_changed");
        let sent = UndoStep::NotUndoable {
            entity: Some("action_invocation".into()),
            record_id: Some(id),
            action_id: Some("email.send".into()),
            reason: "the message was already sent".into(),
        };
        let parts = item_parts(&sent);
        assert_eq!(parts.3, "not_undoable");
        assert_eq!(
            parts.5.as_deref(),
            Some("email.send: the message was already sent")
        );
    }

    #[test]
    fn undo_run_a_conflict_is_a_skip_not_a_failure() {
        assert_eq!(outcome_of(&Ok(())).0, "restored");
        assert_eq!(
            outcome_of(&Err(AppError::VersionConflict)).0,
            "skipped_changed"
        );
        assert_eq!(outcome_of(&Err(AppError::NotFound)).0, "failed");
        let refused = outcome_of(&Err(AppError::internal("db down")));
        assert_eq!(
            refused.1.as_deref(),
            Some("the change was refused"),
            "masked"
        );
    }

    #[test]
    fn undo_run_steps_round_trip_as_stored() {
        let step = UndoStep::SoftDelete {
            entity: "deal".into(),
            record_id: Uuid::now_v7(),
            expected_row_version: 2,
        };
        let stored = serde_json::to_value(&step).unwrap();
        assert_eq!(stored["step"], json!("soft_delete"));
        assert_eq!(serde_json::from_value::<UndoStep>(stored).unwrap(), step);
    }

    #[test]
    fn undo_compares_values_by_kind() {
        assert!(same_value(Some(&json!(12.5)), Some("12.50")));
        assert!(same_value(Some(&json!(true)), Some("true")));
        assert!(same_value(None, None));
        assert!(!same_value(Some(&json!("a")), Some("b")));
        assert_eq!(restore_value(Some("3"), Some(&json!(1))), json!(3));
        assert_eq!(restore_value(None, Some(&json!(1))), Value::Null);
    }

    #[test]
    fn undo_reports_message_sends_as_external() {
        assert!(is_message_send("email.send"));
        assert!(is_message_send("lead.send_message"));
        assert!(!is_message_send("record.update"));
    }
}
