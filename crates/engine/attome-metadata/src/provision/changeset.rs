//! Solution 7 Phase 1 (D-785, design `document/general/SOLUTION-7-PHASE-1-DESIGN.md`
//! §1.1, §1.4, §4.4) — how the entity, attribute and relationship primitives
//! stamp owner layers and record their writes as changeset operations.
//!
//! The primitives that commit DDL before their metadata transaction
//! (`reconcile_entity`, `reconcile_attribute`, relationship create) gain
//! `_recorded` siblings taking `Option<RecordAs>` (the D-494 `_with_id`
//! precedent: the existing signatures and their callers are unchanged and
//! behave as before, stamping by policy and recording nothing).
//!
//! - **Stamp.** A new row gets the recording's layer; without a recording the
//!   policy decides: [`ReconcilePolicy::Seed`] stamps `platform` (a boot seed
//!   is a platform definition), `Admin`/`Bundle` stamp `project` (the old
//!   bundle promotion path, §1.4).
//! - **Owner check.** With a recording, a write that touches an existing row
//!   (update, reactivate, retire) is refused with `409 layer_mismatch` unless
//!   the row belongs to the recording's layer. It runs before any DDL.
//! - **Record.** The operation is appended as the last statement of the
//!   primitive's own lock + change-log transaction, with the post-write row as
//!   its snapshot. A write that changes nothing records nothing.

use attome_core::changeset::{Layer, Op, RecordedOp, Recording};
use attome_core::reconcile::ReconcilePolicy;
use attome_db::Tx;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

/// How a `_recorded` primitive treats its write.
#[derive(Debug, Clone, Copy)]
pub struct RecordAs<'a> {
    pub recording: &'a Recording,
    /// The operation to record. `None` stamps new rows and checks the owner
    /// but records nothing: a later write of the same request records the one
    /// operation (the size-gated attribute path records when the contract
    /// change is queued, design §4.5).
    pub op: Option<Op>,
}

impl<'a> RecordAs<'a> {
    pub fn op(recording: &'a Recording, op: Op) -> Self {
        Self {
            recording,
            op: Some(op),
        }
    }

    pub fn stamp_only(recording: &'a Recording) -> Self {
        Self {
            recording,
            op: None,
        }
    }
}

/// The layer a new row is stamped with.
pub(super) fn layer_for(
    policy: ReconcilePolicy,
    rec: Option<RecordAs<'_>>,
) -> Result<Layer, AppError> {
    match rec {
        Some(rec) => rec.recording.stamp(),
        None => Ok(default_layer(policy)),
    }
}

/// Without a recording: a boot seed owns the platform definitions; the admin
/// and bundle paths write `project` rows (§1.4).
pub(super) fn default_layer(policy: ReconcilePolicy) -> Layer {
    match policy {
        ReconcilePolicy::Seed => Layer::Platform,
        _ => Layer::Project,
    }
}

/// `409 layer_mismatch` unless the recording may change a row owned by
/// `row_layer`. No recording: no check (the unrecorded callers keep today's
/// behaviour).
pub(super) fn check_owner(rec: Option<RecordAs<'_>>, row_layer: &str) -> Result<(), AppError> {
    let Some(rec) = rec else {
        return Ok(());
    };
    let layer = Layer::parse(row_layer).ok_or_else(|| {
        AppError::internal(format!(
            "metadata row carries an unknown owner_layer {row_layer:?}"
        ))
    })?;
    rec.recording.check_owner(layer)
}

/// Resolves the changeset before any work, so a refusal happens before DDL.
pub(super) async fn preflight(
    db: &attome_db::DbPool,
    rec: Option<RecordAs<'_>>,
) -> Result<(), AppError> {
    if let Some(rec) = rec {
        rec.recording.preflight(db).await?;
    }
    Ok(())
}

/// Appends `op` built from the row `id` when `rec` asks for one. MUST be the
/// last statement before commit.
pub(super) async fn record(
    tx: &mut Tx<'_>,
    rec: Option<RecordAs<'_>>,
    kind: ObjectKind,
    id: Uuid,
    target: Value,
    changed: Vec<&'static str>,
) -> Result<(), AppError> {
    let Some(RecordAs {
        recording,
        op: Some(op),
    }) = rec
    else {
        return Ok(());
    };
    let snapshot = snapshot(tx, kind, id).await?;
    recording
        .record(
            tx,
            RecordedOp {
                op,
                object_kind: kind.as_str(),
                object_ref: Some(id),
                target,
                snapshot,
                changed,
            },
        )
        .await
}

/// The recorded object kinds of this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Entity,
    Attribute,
    Relationship,
}

impl ObjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Entity => "entity",
            Self::Attribute => "attribute",
            Self::Relationship => "relationship",
        }
    }
}

pub fn entity_target(entity: &str) -> Value {
    json!({ "entity": entity })
}

pub fn field_target(entity: &str, field: &str) -> Value {
    json!({ "entity": entity, "field": field })
}

pub fn relationship_target(name: &str) -> Value {
    json!({ "relationship": name })
}

/// The post-write row, enumerated columns, with the logical names a UUID
/// reference resolves to alongside it (close translates from these).
pub async fn snapshot(tx: &mut Tx<'_>, kind: ObjectKind, id: Uuid) -> Result<Value, AppError> {
    let sql = match kind {
        ObjectKind::Entity => {
            "SELECT jsonb_build_object( \
                 'id', e.id, 'logicalname', e.logicalname, 'name', e.name, \
                 'primary_name_attribute', e.primary_name_attribute, \
                 'is_active', (e.is_active IS NULL OR e.is_active = true), \
                 'is_append_only', COALESCE(e.is_append_only, false), \
                 'is_audited', COALESCE(e.is_audited, false), \
                 'category', e.category, 'domain_ref', e.domain_ref, 'domain', d.name, \
                 'is_customized', e.is_customized, 'owner_layer', e.owner_layer) \
             FROM entity_info e \
             LEFT JOIN data_domain d ON d.id = e.domain_ref \
             WHERE e.id = $1"
        }
        ObjectKind::Attribute => {
            "SELECT jsonb_build_object( \
                 'id', a.id, 'entity_ref', a.entity_ref, 'entity', e.logicalname, \
                 'logicalname', a.logicalname, 'name', a.name, 'type', a.\"type\", \
                 'required', COALESCE(a.required, false), \
                 'is_sensitive', COALESCE(a.is_sensitive, false), \
                 'is_write_restricted', COALESCE(a.is_write_restricted, false), \
                 'is_sortable', COALESCE(a.is_sortable, false), \
                 'is_filterable', COALESCE(a.is_filterable, false), \
                 'max_length', a.max_length, 'lookup_entity_ref', a.lookup_entity_ref, \
                 'lookup_entity', le.logicalname, 'options', a.options, \
                 'on_target_delete', a.on_target_delete, \
                 'data_classification', a.data_classification, 'purpose', a.purpose, \
                 'sort_order', a.sort_order, \
                 'is_active', (a.is_active IS NULL OR a.is_active = true), \
                 'is_customized', a.is_customized, 'owner_layer', a.owner_layer) \
             FROM attribute_info a \
             JOIN entity_info e ON e.id = a.entity_ref \
             LEFT JOIN entity_info le ON le.id = a.lookup_entity_ref \
             WHERE a.id = $1"
        }
        ObjectKind::Relationship => {
            "SELECT jsonb_build_object( \
                 'id', id, 'name', name, 'entity_a', entity_a, 'entity_b', entity_b, \
                 'role_a', role_a, 'role_b', role_b, 'join_table', join_table, \
                 'cascade', cascade, 'is_active', is_active, 'is_deleted', is_deleted, \
                 'is_customized', is_customized, 'row_version', row_version, \
                 'owner_layer', owner_layer) \
             FROM relationship_info WHERE id = $1"
        }
    };
    sqlx::query_scalar::<_, Value>(sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| {
            AppError::internal(format!(
                "changeset snapshot: the {} row {id} it just wrote is missing",
                kind.as_str()
            ))
        })
}

/// Pushes `name` onto `changed` when `before != after`.
pub(super) fn diff<T: PartialEq + ?Sized>(
    changed: &mut Vec<&'static str>,
    name: &'static str,
    before: &T,
    after: &T,
) {
    if before != after {
        changed.push(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::changeset::RequestContext;
    use attome_core::changeset::{RecordingMode, errors};

    #[test]
    fn unrecorded_writes_stamp_by_policy() {
        assert_eq!(
            layer_for(ReconcilePolicy::Seed, None).ok(),
            Some(Layer::Platform)
        );
        assert_eq!(
            layer_for(ReconcilePolicy::Admin, None).ok(),
            Some(Layer::Project)
        );
        assert_eq!(
            layer_for(
                ReconcilePolicy::Bundle {
                    is_customized: false
                },
                None
            )
            .ok(),
            Some(Layer::Project)
        );
    }

    #[test]
    fn recorded_writes_stamp_the_recording_layer() {
        let applying = Recording::Applying {
            layer: Layer::Product,
        };
        assert_eq!(
            layer_for(
                ReconcilePolicy::Admin,
                Some(RecordAs::stamp_only(&applying))
            )
            .ok(),
            Some(Layer::Product)
        );
        // An unresolved request cannot guess its layer.
        let request = Recording::for_request(RequestContext {
            header: None,
            actor: Some(Uuid::now_v7()),
            actor_label: "user:test".into(),
            request_id: None,
            route: "POST /api/v1/admin/entities".into(),
            mode: RecordingMode::Required,
            auto_layer: Layer::Project,
            break_glass: false,
        });
        assert!(layer_for(ReconcilePolicy::Admin, Some(RecordAs::stamp_only(&request))).is_err());
    }

    #[test]
    fn the_owner_check_needs_the_same_layer() {
        assert!(check_owner(None, "platform").is_ok());
        let applying = Recording::Applying {
            layer: Layer::Project,
        };
        let rec = Some(RecordAs::op(&applying, Op::UpdateEntity));
        assert!(check_owner(rec, "project").is_ok());
        let Err(AppError::Conflict(message)) = check_owner(rec, "platform") else {
            panic!("a platform row must be refused to a project recording");
        };
        assert_eq!(errors::code_of(message), "layer_mismatch");
        assert!(matches!(
            check_owner(rec, "nonsense"),
            Err(AppError::Internal(_))
        ));
    }

    #[test]
    fn targets_carry_exactly_the_catalogue_keys() {
        for (op, target) in [
            (Op::CreateEntity, entity_target("account")),
            (Op::AddField, field_target("account", "name")),
            (
                Op::UpsertRelationship,
                relationship_target("account_contact"),
            ),
        ] {
            let recorded = RecordedOp {
                op,
                object_kind: "entity",
                object_ref: None,
                target,
                snapshot: json!({}),
                changed: vec![],
            };
            assert!(recorded.check().is_ok(), "{op:?}");
        }
    }

    #[test]
    fn diff_names_only_what_changed() {
        let mut changed = Vec::new();
        diff(&mut changed, "name", "a", "a");
        diff(&mut changed, "category", &Some(1), &None);
        assert_eq!(changed, vec!["category"]);
    }
}
