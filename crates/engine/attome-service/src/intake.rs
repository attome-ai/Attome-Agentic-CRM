//! M70 Phase 1 (`document/xrm/module/M70-work-intake/master-plan.md` §4
//! item 1): the pieces every intake write shares now that it goes through the
//! entity engine (`entity_mutation::create_one_as`/`update_one_as`) instead
//! of a raw `INSERT`/`UPDATE`.
//!
//! The engine owns the row itself: validation, field-write grants, the state
//! model, autovalues, default/calculation/formula rules (D-604), lookup
//! liveness, and the change-feed row. Two things a caller of the bare
//! primitive still owns stay here, because an intake route writes two
//! records in one transaction and so cannot hand the tail to
//! `MutationRing::commit_mutation` (that helper commits after one record):
//! the D-133 creator share, and the `Entity` audit event per record, written
//! in the same transaction as the write it describes.

use attome_audit::policy_resolver::AuditPolicy;
use attome_audit::{AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource};
use attome_core::{AttrInfo, EngineState};
use attome_records::entity_mutation::MutationResult;
use attome_records::mutation_ring::MutationActor;
use attome_types::AppError;
use serde_json::{Map, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// One resolved entity an intake route writes to, with the audit policy that
/// governs its ordinary `Entity` events. Both are read before the write's
/// transaction opens, so the transaction does no Redis or pool I/O of its
/// own (guidelines §4).
pub(crate) struct IntakeEntity {
    pub id: Uuid,
    pub name: String,
    pub attrs: Vec<AttrInfo>,
    pub policy: AuditPolicy,
}

impl IntakeEntity {
    /// Resolves `logicalname` through the engine's own resolver — the same
    /// licence gate and metadata source generic CRUD uses.
    pub async fn resolve(state: &EngineState, logicalname: &str) -> Result<Self, AppError> {
        let (id, name, attrs, _) =
            attome_records::entity_crud::resolve_entity(state, logicalname).await?;
        let policy = attome_audit::policy_resolver::resolve(state, &name).await;
        Ok(Self {
            id,
            name,
            attrs,
            policy,
        })
    }
}

/// Inserts `value` into `obj` only when it is present — an absent optional
/// stays absent rather than becoming an explicit `null` the engine would
/// then have to judge.
pub(crate) fn put_opt(obj: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        obj.insert(key.to_owned(), Value::String(v));
    }
}

/// Writes the ordinary `Entity` audit event for one engine mutation, inside
/// `tx`, gated by the entity's audit policy exactly as
/// `MutationRing::commit_mutation` gates its own. `body` is what the caller
/// asked to write (the audit diff is computed from it and the old row, the
/// same inputs the generic create/update handlers use).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn audit_entity_write(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    actor: &MutationActor,
    entity: &IntakeEntity,
    result: &MutationResult,
    operation: AuditOperation,
    body: &Map<String, Value>,
    event_name: &str,
) -> Result<(), AppError> {
    if !entity.policy.permits(operation) {
        return Ok(());
    }
    let changed_fields = attome_records::entity_crud::field_changes_from_obj(
        tx,
        state,
        &entity.attrs,
        body,
        result.old_row.as_ref(),
    )
    .await
    .into_iter()
    .filter(|f| !entity.policy.field_excluded(&f.field_name))
    .collect();
    let event = AuditEvent {
        organization_ref: actor.org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity.name.clone()),
        record_id: Some(result.record_id),
        operation,
        version_before: None,
        version_after: None,
        user_context: actor.user_context.clone(),
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(event_name.to_owned()),
        event_comment: None,
        changed_fields,
        snapshot_json: None,
    };
    attome_audit::audit_service(state)
        .write_in_tx(tx, event)
        .await?;
    Ok(())
}

/// A string field of an engine-returned row (`row_to_json` output).
pub(crate) fn row_str(result: &MutationResult, field: &str) -> Option<String> {
    result
        .new_row
        .as_ref()
        .and_then(|row| row.get(field))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// A short, visibly-placeholder record number (`TKT-…`, `PRJ-…`) for
/// entities that have no numbering scheme configured yet. Taken from the
/// random tail of a UUIDv7, not its head: the head is the millisecond
/// timestamp, so two numbers minted within the same ~minute shared a prefix
/// under the old `&id[..8]` scheme. Supplied explicitly because both fields
/// are required attributes, which the engine checks before any Auto Value
/// rule (`attome_metadata::autovalue`) could fill them.
pub(crate) fn placeholder_number(prefix: &str) -> String {
    let simple = Uuid::now_v7().simple().to_string();
    format!("{prefix}-{}", simple[24..].to_uppercase())
}
