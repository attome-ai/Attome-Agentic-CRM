//! M7-T1: the record write path's stage process check.
//!
//! An entity with a published `stage_process` (`attome_model::kinds::
//! stage_process`) holds each record's stage in its `stage` attribute. A
//! create that names no stage starts in the first one; any create or update
//! that names a stage is checked against the process
//! (`stage_process::check_move`) on the record as the write leaves it:
//! the stage must exist, an update may move only to a stage the current one
//! lists in `next`, and the stage's required attributes must be filled.
//! Every refused required attribute is reported at once
//! (`AppError::FieldValidation`, code `required_for_stage`). Each move an
//! update makes is recorded in `stage_move` (migration 0215) in the write's
//! own transaction: record, from, to, who, when, and the reason the request
//! gave in its `Attome-Stage-Reason` header.
//!
//! Only entities whose attributes include `stage` pay the process lookup,
//! and on update only writes that name it.

use attome_core::{AttrInfo, EngineState};
use attome_model::kinds::stage_process::{self, MoveRefusal, STAGE_ATTRIBUTE};
use attome_types::AppError;
use attome_types::types::FieldError;
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::entity_mutation::MutationMode;

tokio::task_local! {
    /// The reason the request gave for a stage move.
    static STAGE_REASON: Option<String>;
}

/// Runs `f` with the reason the request gave for a stage move (its
/// `Attome-Stage-Reason` header).
pub async fn with_reason<F: std::future::Future>(reason: Option<String>, f: F) -> F::Output {
    STAGE_REASON.scope(reason, f).await
}

fn reason() -> Option<String> {
    STAGE_REASON
        .try_with(Clone::clone)
        .ok()
        .flatten()
        .filter(|r| !r.trim().is_empty())
}

/// The header a stage move's reason travels in, trimmed to 500 characters.
pub fn reason_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("attome-stage-reason")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().chars().take(500).collect::<String>())
        .filter(|v| !v.is_empty())
}

/// The write modes the process binds: people, their agents and the
/// engines writing for them; not legacy imports or bundle record sets.
fn enforced(mode: MutationMode) -> bool {
    matches!(
        mode,
        MutationMode::Strict
            | MutationMode::ClientId(_)
            | MutationMode::HeldChange(_)
            | MutationMode::EngineManaged
    )
}

/// The newest published stage process of `entity_id`, if any.
async fn process_of(
    tx: &mut Transaction<'_, Postgres>,
    entity_id: Uuid,
) -> Result<Option<Value>, AppError> {
    sqlx::query_scalar(
        "SELECT v.doc FROM metadata_object o \
           JOIN metadata_object_version v ON v.object_id = o.id \
          WHERE o.kind = 'stage_process' AND o.is_active AND v.state = 'published' \
            AND v.doc->>'entity' = $1 \
          ORDER BY o.created_at, o.id, v.version_no DESC LIMIT 1",
    )
    .bind(entity_id.to_string())
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)
}

fn refusal(refused: MoveRefusal) -> AppError {
    match refused {
        MoveRefusal::UnknownStage(stage) => AppError::FieldValidation(vec![FieldError {
            field: STAGE_ATTRIBUTE.to_owned(),
            code: "unknown_stage".into(),
            message: format!("`{stage}` is not a stage of this record's process"),
        }]),
        MoveRefusal::NotAllowed { from, to } => AppError::TransitionNotAllowed(format!(
            "a record in stage `{from}` cannot move to `{to}`"
        )),
        MoveRefusal::MissingRequired { stage, attributes } => AppError::FieldValidation(
            attributes
                .into_iter()
                .map(|attribute| FieldError {
                    message: format!("{attribute} is required to move to stage `{stage}`"),
                    field: attribute,
                    code: "required_for_stage".into(),
                })
                .collect(),
        ),
    }
}

fn stage_of(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// The create body, with the first stage when it names none; `None` when it
/// needs no change. Refuses a stage the record does not qualify for.
pub async fn guard_create(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    entity_name: &str,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    mode: MutationMode,
) -> Result<Option<serde_json::Map<String, Value>>, AppError> {
    if !enforced(mode) || !attrs.iter().any(|a| a.logicalname == STAGE_ATTRIBUTE) {
        return Ok(None);
    }
    let Some(entity_id) = state.entities.load().get(entity_name).map(|m| m.entity_id) else {
        return Ok(None);
    };
    let Some(process) = process_of(tx, entity_id).await? else {
        return Ok(None);
    };
    let mut body = None;
    let to = match stage_of(obj.get(STAGE_ATTRIBUTE)) {
        Some(to) => to.to_owned(),
        None => {
            let Some(first) = stage_process::initial_stage(&process) else {
                return Ok(None);
            };
            let mut filled = obj.clone();
            filled.insert(STAGE_ATTRIBUTE.into(), Value::String(first.to_owned()));
            body = Some(filled);
            first.to_owned()
        }
    };
    stage_process::check_move(&process, None, &to, body.as_ref().unwrap_or(obj))
        .map_err(refusal)?;
    Ok(body)
}

/// Checks an update that names the stage, and records the move.
#[allow(clippy::too_many_arguments)]
pub async fn guard_update(
    tx: &mut Transaction<'_, Postgres>,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    actor: Option<Uuid>,
    mode: MutationMode,
) -> Result<(), AppError> {
    if !enforced(mode) || !obj.contains_key(STAGE_ATTRIBUTE) {
        return Ok(());
    }
    let Some(process) = process_of(tx, entity_id).await? else {
        return Ok(());
    };
    let Some(to) = stage_of(obj.get(STAGE_ATTRIBUTE)) else {
        return Err(AppError::FieldValidation(vec![FieldError {
            field: STAGE_ATTRIBUTE.to_owned(),
            code: "required".into(),
            message: "a record in a stage process always has a stage".into(),
        }]));
    };
    let Some(stored) =
        crate::entity_mutation::fetch_stored_record(tx, entity_name, record_id, attrs).await?
    else {
        // No live row: the update itself answers NotFound.
        return Ok(());
    };
    let from = stage_of(stored.get(STAGE_ATTRIBUTE)).map(str::to_owned);
    if from.as_deref() == Some(to) {
        return Ok(());
    }
    let mut effective = stored;
    for (k, v) in obj {
        effective.insert(k.clone(), v.clone());
    }
    stage_process::check_move(&process, from.as_deref(), to, &effective).map_err(refusal)?;
    sqlx::query(
        "INSERT INTO stage_move (entity_logicalname, record_id, from_stage, to_stage, moved_by, reason) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(entity_name)
    .bind(record_id)
    .bind(from)
    .bind(to)
    .bind(actor)
    .bind(reason())
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}
