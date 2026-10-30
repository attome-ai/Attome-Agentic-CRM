//! S1-T8: record writes staged in one shared transaction, for a composite
//! request with `all_or_none`.
//!
//! Each operation runs the same steps its single route does, in the same
//! order, with three differences that keeping every write in one
//! uncommitted transaction forces:
//!
//! - The record-level access inputs (`resolve_record_access_inputs`) and a
//!   delete's cascade access are resolved on the pool before the transaction
//!   opens ([`prepare`]); the per-record probe runs inside it
//!   (`require_record_access_in_tx`), so a record created earlier in the same
//!   request is found through the creator share its create staged.
//! - The read-time lookup preflight is skipped: the writer's own lock of the
//!   lookup targets (`lock_lookup_targets`, inside `create_one`/`update_one`)
//!   is the decisive check, and it sees records created earlier in the
//!   request where the pool cannot.
//! - A record created earlier in the request is not looked up on the pool
//!   (its declaration, its parent): it does not exist there yet. Moving such
//!   a record to another parent in the same request is refused.
//!
//! Nothing here commits: [`stage_create`], [`stage_update`] and
//! [`stage_delete`] stage the mutation ring's creator share, file mirror and
//! audit in the transaction, and the caller commits them all with
//! `MutationRing::commit_many`.

use std::collections::HashSet;

use attome_audit::AuditOperation;
use attome_core::{AttrInfo, EngineState, OnTargetDelete};
use attome_security::RecordAction;
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::AppError;
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::entity_mutation::{DeleteKind, DeleteOrigin, MutationMode, validate_body};
use crate::mutation_ring::{
    MutationActor, MutationAudit, MutationRing, MutationSideEffects, StagedMutation,
};

use super::access::{
    guard_cascade_dependent_access, require_child_parent_access,
    require_child_parent_access_for_write, require_record_access_in_tx,
    resolve_record_access_inputs,
};
use super::mutations::{audit_duplicate_skip, field_changes_from_obj, update_audit};
use super::resolve::resolve_entity;

/// What one operation needs from the pool before the transaction opens.
pub struct Prepared {
    pub entity_id: Uuid,
    pub entity_name: String,
    pub attrs: Vec<AttrInfo>,
    /// The caller's depth and owner visibility for the operation's action;
    /// `None` for a create, which has no record to probe.
    access: Option<(AccessLevel, bool)>,
    /// A delete's dependents and the caller's access to each.
    cascade: Option<Cascade>,
}

struct Cascade {
    dependents: Vec<(String, String, OnTargetDelete)>,
    access: Vec<(Option<AccessLevel>, bool)>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("entity_name", &self.entity_name)
            .finish_non_exhaustive()
    }
}

/// One staged write: the ring's staged item, and what the caller needs
/// after the commit to answer as the single route would.
pub struct StagedWrite {
    pub record_id: Uuid,
    /// The row as written; `None` for a delete.
    pub row: Option<Value>,
    /// The fields the write sent, for the duplicate match keys written
    /// after the commit; `None` for a delete.
    pub sent: Option<serde_json::Map<String, Value>>,
    pub staged: StagedMutation,
}

impl std::fmt::Debug for StagedWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedWrite")
            .field("record_id", &self.record_id)
            .finish_non_exhaustive()
    }
}

/// Resolves the entity and the caller's access inputs for `action`, on the
/// pool. The caller has checked the entity privilege for the action.
pub async fn prepare(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    action: RecordAction,
) -> Result<Prepared, AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        resolve_entity(state, entity_input).await?;
    if matches!(action, RecordAction::Create) {
        if super::LEDGER_ENTITIES.contains(&entity_name.as_str()) {
            return Err(AppError::Forbidden);
        }
        return Ok(Prepared {
            entity_id,
            entity_name,
            attrs,
            access: None,
            cascade: None,
        });
    }
    if is_append_only {
        return Err(AppError::Forbidden);
    }
    let cascade = if matches!(action, RecordAction::Delete) {
        crate::entity_mutation::require_metadata_table_unlocked(state, ctx, &entity_name).await?;
        let dependents = state.entities.load().dependents_of(entity_id);
        let access =
            super::access::resolve_cascade_dependent_access(state, ctx, &dependents).await?;
        Some(Cascade { dependents, access })
    } else {
        None
    };
    let access = resolve_record_access_inputs(state, ctx, entity_id, &entity_name, action).await?;
    Ok(Prepared {
        entity_id,
        entity_name,
        attrs,
        access: Some(access),
        cascade,
    })
}

/// The parent record a polymorphic child's body names, when it parses.
fn named_parent(body: &serde_json::Map<String, Value>) -> Option<Uuid> {
    body.get("record_id")
        .and_then(Value::as_str)
        .and_then(|id| Uuid::parse_str(id.trim()).ok())
}

/// Stages a create: the single create route's validation, duplicate rule,
/// write and audit, in `tx`. `in_request` holds the records created earlier
/// in the same request.
#[allow(clippy::too_many_arguments)]
pub async fn stage_create(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    ctx: &SecurityContext,
    actor: &MutationActor,
    prepared: &Prepared,
    body: Value,
    in_request: &HashSet<Uuid>,
) -> Result<StagedWrite, AppError> {
    let Prepared {
        entity_id,
        entity_name,
        attrs,
        ..
    } = prepared;
    let mut body = body;
    if let Some(fields) = body.as_object_mut() {
        super::upsert::resolve_lookups_by_external_id(state, attrs, fields).await?;
        if attrs
            .iter()
            .any(|a| a.logicalname == attome_metadata::provision::record_type::ATTRIBUTE)
        {
            attome_metadata::provision::record_type::apply_on_create(
                &state.base.db,
                *entity_id,
                ctx.role_ids.as_deref(),
                fields,
            )
            .await?;
        }
    }
    let obj = body
        .as_object()
        .ok_or_else(|| AppError::Validation("request body must be a JSON object".into()))?;
    let with_initial =
        crate::entity_mutation::apply_engine_managed_initial_values(state, entity_name, obj)?;
    validate_body(attrs, with_initial.as_ref().unwrap_or(obj), true)?;
    // A child of a record created earlier in this request: its create
    // already passed the access check, and the pool cannot see it yet.
    if !named_parent(obj).is_some_and(|parent| in_request.contains(&parent)) {
        require_child_parent_access_for_write(state, ctx, entity_name, None, obj).await?;
    }
    let duplicate_reason = attome_core::match_rule::duplicate_reason();
    let (duplicates, hidden) = crate::duplicate_check::enforce(
        crate::duplicate_check::check(state, ctx, *entity_id, entity_name, None, obj).await?,
        duplicate_reason.as_deref(),
    )?;

    let mutation = crate::entity_mutation::create_one(
        tx,
        state,
        ctx,
        entity_name,
        attrs,
        obj,
        actor.acting_user_id,
        actor.org_ref,
        MutationMode::Strict,
    )
    .await?;
    let row = mutation
        .new_row
        .clone()
        .ok_or_else(|| AppError::internal("create mutation returned no row"))?;
    audit_duplicate_skip(
        tx,
        state,
        actor.acting_user_id,
        entity_name,
        mutation.record_id,
    )
    .await?;
    let mut audit = MutationAudit::new();
    audit.changed_fields = field_changes_from_obj(tx, state, attrs, obj, None).await;
    if !duplicates.is_empty() || hidden > 0 {
        audit.event_comment = duplicate_reason
            .as_deref()
            .map(|reason| format!("saved as a likely duplicate: {reason}"));
    }
    let audit_header_id = MutationRing::new(state)
        .stage(
            tx,
            ctx,
            *entity_id,
            entity_name,
            attrs,
            actor,
            AuditOperation::Create,
            MutationSideEffects {
                grant_creator_share: true,
                mirror_file_fields: true,
            },
            audit,
            &mutation,
        )
        .await?;
    Ok(StagedWrite {
        record_id: mutation.record_id,
        row: Some(row),
        sent: Some(obj.clone()),
        staged: StagedMutation {
            entity_name: entity_name.clone(),
            result: mutation,
            audit_header_id,
            grant_by_row: true,
        },
    })
}

/// Stages an update of `record_id` at `expected_row_version`.
#[allow(clippy::too_many_arguments)]
pub async fn stage_update(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    ctx: &SecurityContext,
    actor: &MutationActor,
    prepared: &Prepared,
    record_id: Uuid,
    expected_row_version: i64,
    body: Value,
    in_request: &HashSet<Uuid>,
) -> Result<StagedWrite, AppError> {
    let Prepared {
        entity_id,
        entity_name,
        attrs,
        access,
        ..
    } = prepared;
    let created_here = in_request.contains(&record_id);
    if !created_here {
        super::declared::refuse_if_declared(&state.base.db, entity_name, record_id).await?;
    }
    let (access_level, owner_visible) =
        access.ok_or_else(|| AppError::internal("update prepared without access inputs"))?;
    require_record_access_in_tx(
        tx,
        state,
        ctx,
        *entity_id,
        entity_name,
        record_id,
        RecordAction::Update,
        access_level,
        owner_visible,
        attrs,
    )
    .await?;
    let mut body = body;
    if let Some(fields) = body.as_object_mut() {
        super::upsert::resolve_lookups_by_external_id(state, attrs, fields).await?;
    }
    let obj = body
        .as_object()
        .ok_or_else(|| AppError::Validation("request body must be a JSON object".into()))?;
    validate_body(attrs, obj, false)?;
    if created_here {
        if obj.contains_key("entity_name") || obj.contains_key("record_id") {
            return Err(AppError::Validation(
                "a record created in an all_or_none request cannot be moved to another \
                 parent in the same request"
                    .into(),
            ));
        }
    } else {
        require_child_parent_access(state, ctx, entity_name, record_id).await?;
        require_child_parent_access_for_write(state, ctx, entity_name, Some(record_id), obj)
            .await?;
    }
    let duplicate_reason = attome_core::match_rule::duplicate_reason();
    let (duplicates, hidden) = crate::duplicate_check::enforce(
        crate::duplicate_check::check(state, ctx, *entity_id, entity_name, Some(record_id), obj)
            .await?,
        duplicate_reason.as_deref(),
    )?;
    let event_comment = match (&duplicate_reason, duplicates.is_empty() && hidden == 0) {
        (Some(reason), false) => Some(format!("saved as a likely duplicate: {reason}")),
        _ => None,
    };

    let mutation = crate::entity_mutation::update_one(
        tx,
        state,
        ctx,
        entity_name,
        *entity_id,
        record_id,
        attrs,
        obj,
        actor.acting_user_id,
        expected_row_version,
        MutationMode::Strict,
    )
    .await?;
    let row = mutation
        .new_row
        .clone()
        .ok_or_else(|| AppError::internal("update mutation returned no row"))?;
    audit_duplicate_skip(tx, state, actor.acting_user_id, entity_name, record_id).await?;
    let audit = update_audit(
        tx,
        state,
        attrs,
        obj,
        &mutation,
        &row,
        event_comment.as_deref(),
    )
    .await;
    let audit_header_id = MutationRing::new(state)
        .stage(
            tx,
            ctx,
            *entity_id,
            entity_name,
            attrs,
            actor,
            AuditOperation::Update,
            MutationSideEffects {
                grant_creator_share: false,
                mirror_file_fields: true,
            },
            audit,
            &mutation,
        )
        .await?;
    Ok(StagedWrite {
        record_id,
        row: Some(row),
        sent: Some(obj.clone()),
        staged: StagedMutation {
            entity_name: entity_name.clone(),
            result: mutation,
            audit_header_id,
            grant_by_row: true,
        },
    })
}

/// Stages a soft delete of `record_id`, following the entity's delete
/// rules as the single delete route does.
#[allow(clippy::too_many_arguments)]
pub async fn stage_delete(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    ctx: &SecurityContext,
    actor: &MutationActor,
    prepared: &Prepared,
    record_id: Uuid,
    expected_row_version: Option<i64>,
    in_request: &HashSet<Uuid>,
) -> Result<StagedWrite, AppError> {
    let Prepared {
        entity_id,
        entity_name,
        attrs,
        access,
        cascade,
    } = prepared;
    let created_here = in_request.contains(&record_id);
    if !created_here {
        super::declared::refuse_if_declared(&state.base.db, entity_name, record_id).await?;
    }
    let (access_level, owner_visible) =
        access.ok_or_else(|| AppError::internal("delete prepared without access inputs"))?;
    require_record_access_in_tx(
        tx,
        state,
        ctx,
        *entity_id,
        entity_name,
        record_id,
        RecordAction::Delete,
        access_level,
        owner_visible,
        attrs,
    )
    .await?;
    if !created_here {
        require_child_parent_access(state, ctx, entity_name, record_id).await?;
    }
    let cascade = cascade
        .as_ref()
        .ok_or_else(|| AppError::internal("delete prepared without its dependents"))?;
    guard_cascade_dependent_access(
        tx,
        state,
        ctx,
        &cascade.dependents,
        record_id,
        &cascade.access,
    )
    .await?;
    let mutation = crate::entity_mutation::delete_one(
        tx,
        entity_name,
        &cascade.dependents,
        record_id,
        actor.acting_user_id,
        expected_row_version,
        &DeleteOrigin::new(DeleteKind::Request),
    )
    .await?;
    let mut audit = MutationAudit::new();
    if !mutation.cascade_summary.is_empty() {
        audit.event_comment = Some(format!(
            "cascade-deactivated dependents: {}",
            mutation.cascade_summary.join(", ")
        ));
    }
    let audit_header_id = MutationRing::new(state)
        .stage(
            tx,
            ctx,
            *entity_id,
            entity_name,
            attrs,
            actor,
            AuditOperation::SoftDelete,
            MutationSideEffects {
                grant_creator_share: false,
                mirror_file_fields: false,
            },
            audit,
            &mutation,
        )
        .await?;
    Ok(StagedWrite {
        record_id,
        row: None,
        sent: None,
        staged: StagedMutation {
            entity_name: entity_name.clone(),
            result: mutation,
            audit_header_id,
            grant_by_row: false,
        },
    })
}

/// The answer a staged create or update gives once committed: the same
/// record response the single route builds.
pub async fn committed_response(
    state: &EngineState,
    ctx: &SecurityContext,
    prepared: &Prepared,
    record_id: Uuid,
    row: Value,
    sent: Option<&serde_json::Map<String, Value>>,
) -> Result<Value, AppError> {
    if let Some(sent) = sent {
        crate::duplicate_check::write_match_keys(state, &prepared.entity_name, record_id, sent)
            .await;
    }
    let lookups = super::response::resolve_lookup_meta(state, ctx, &row, &prepared.attrs).await;
    let response = super::response::build_response(
        prepared.entity_id,
        row,
        &prepared.attrs,
        lookups,
        ctx,
        &prepared.entity_name,
    );
    serde_json::to_value(response).map_err(AppError::internal)
}
