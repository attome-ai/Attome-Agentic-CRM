//! Solution 7 Phase 2 (D-787 rule 7, D-791 rule 7; `SOLUTION-7-PHASE-2-DESIGN.md`
//! §3.8, §3.9, §5.2) — business keys in the changeset planner and applier.
//!
//! - A `create_entity`/`update_entity` whose `definition` carries
//!   `business_key` / `is_reference_data` declares them on apply (the
//!   recorder puts them there, `translate.rs`); with `args.changed`, only the
//!   properties it names are written (§3.9). The plan blocks a key live rows
//!   duplicate (`business_key_duplicates`) and an invalid one.
//! - An `upsert_record` must name exactly the entity's declared key
//!   (`business_key_mismatch`); an entity without one is blocked
//!   (`business_key_missing`) except in a platform changeset, whose committed
//!   files predate declarations and keep the Phase 1 rule (match on the op's
//!   own key fields). A declaration earlier in the same plan counts.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_core::changeset::{Layer, Op, errors};
use attome_db::DbPool;
use attome_metadata::provision::{self, BusinessKey};
use attome_types::AppError;
use serde_json::{Map, Value};
use uuid::Uuid;

use super::plan::DocOp;

/// What an entity operation sets of an entity's business key; `None` in a
/// member: not managed by this operation (leave the live value).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyPatch {
    /// `Some(None)` clears the key.
    pub fields: Option<Option<Vec<String>>>,
    pub is_reference_data: Option<bool>,
}

impl KeyPatch {
    pub fn is_empty(&self) -> bool {
        self.fields.is_none() && self.is_reference_data.is_none()
    }

    /// `current` with this patch laid over it.
    pub fn apply_to(&self, current: &BusinessKey) -> BusinessKey {
        BusinessKey {
            fields: self
                .fields
                .clone()
                .unwrap_or_else(|| current.fields.clone()),
            is_reference_data: self.is_reference_data.unwrap_or(current.is_reference_data),
        }
    }
}

/// The `args.changed` list of an op, when it carries one.
fn changed_list(op: &DocOp) -> Option<Vec<&str>> {
    op.arg("changed")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
}

/// The business-key part of an entity op (`create_entity`, `update_entity`):
/// `Ok(None)` for any other op or one that does not carry it. With
/// `args.changed`, a property it does not name is not managed (§3.9).
pub fn declared_by(op: &DocOp) -> Result<Option<KeyPatch>, String> {
    if !matches!(op.op, Op::CreateEntity | Op::UpdateEntity) {
        return Ok(None);
    }
    let Some(definition) = op.arg("definition").and_then(Value::as_object) else {
        return Ok(None);
    };
    let changed = changed_list(op);
    let managed = |name: &str| changed.as_ref().is_none_or(|list| list.contains(&name));
    let mut patch = KeyPatch::default();
    if managed("business_key")
        && let Some(value) = definition.get("business_key")
    {
        patch.fields = Some(match value {
            Value::Null => None,
            Value::Array(items) => Some(
                items
                    .iter()
                    .map(|v| v.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| {
                        format!(
                            "operation {}: definition.business_key must list field names",
                            op.seq
                        )
                    })?,
            ),
            _ => {
                return Err(format!(
                    "operation {}: definition.business_key must be a list or null",
                    op.seq
                ));
            }
        });
    }
    if managed("is_reference_data")
        && let Some(value) = definition.get("is_reference_data")
    {
        patch.is_reference_data = Some(value.as_bool().ok_or_else(|| {
            format!(
                "operation {}: definition.is_reference_data must be a boolean",
                op.seq
            )
        })?);
    }
    Ok((!patch.is_empty()).then_some(patch))
}

/// The key an `upsert_record` is matched by (design §3.8). `declared` is the
/// entity's key (this plan's declaration, else the live one).
///
/// - declared: `target.key` must name exactly its fields → `Some(declared)`;
/// - none, platform changeset: `None` (Phase 1: the op's own key fields);
/// - none, any other layer: `business_key_missing`.
pub fn match_key(
    declared: Option<&[String]>,
    target_key: &Map<String, Value>,
    layer: Layer,
) -> Result<Option<Vec<String>>, &'static str> {
    match declared {
        Some(fields) => {
            let exact = fields.len() == target_key.len()
                && fields.iter().all(|f| target_key.contains_key(f));
            if exact {
                Ok(Some(fields.to_vec()))
            } else {
                Err(errors::BUSINESS_KEY_MISMATCH)
            }
        }
        None if layer == Layer::Platform => Ok(None),
        None => Err(errors::BUSINESS_KEY_MISSING),
    }
}

/// `target.key` of an `upsert_record`.
pub fn target_key(op: &DocOp) -> Map<String, Value> {
    op.target
        .get("key")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// `args.changed` of an `upsert_record` as owned names.
pub fn record_changed(op: &DocOp) -> Option<Vec<String>> {
    changed_list(op).map(|list| list.into_iter().map(str::to_owned).collect())
}

/// The plan's view of declared keys: declarations made by earlier operations
/// of this plan, over the live ones (read once per entity).
#[derive(Debug, Default)]
pub struct PlanKeys {
    known: HashMap<String, BusinessKey>,
}

impl PlanKeys {
    async fn current(&mut self, db: &DbPool, entity: &str) -> Result<BusinessKey, AppError> {
        if let Some(key) = self.known.get(entity) {
            return Ok(key.clone());
        }
        let live = provision::read_business_key(db, entity)
            .await?
            .unwrap_or_default();
        self.known.insert(entity.to_owned(), live.clone());
        Ok(live)
    }

    /// The business-key refusal of one operation, or `None`. Every entity
    /// declaration is noted for the operations after it, blocked or not.
    pub async fn check(
        &mut self,
        db: &DbPool,
        layer: Layer,
        op: &DocOp,
    ) -> Result<Option<String>, AppError> {
        match op.op {
            Op::CreateEntity | Op::UpdateEntity => {
                let patch = match declared_by(op) {
                    Ok(Some(patch)) => patch,
                    Ok(None) => return Ok(None),
                    Err(e) => return Ok(Some(format!("invalid_operation: {e}"))),
                };
                let entity = op.t("entity");
                let current = self.current(db, entity).await?;
                let desired = patch.apply_to(&current);
                self.known.insert(entity.to_owned(), desired.clone());
                if desired.is_reference_data && desired.fields.is_none() {
                    return Ok(Some(
                        errors::BUSINESS_KEY_REQUIRED_FOR_REFERENCE_DATA.to_owned(),
                    ));
                }
                let Some(fields) = desired
                    .fields
                    .filter(|f| current.fields.as_ref() != Some(f))
                else {
                    return Ok(None);
                };
                match provision::business_key::normalize_key(&fields) {
                    Ok(_) => {}
                    Err(AppError::Validation(message)) => return Ok(Some(message)),
                    Err(e) => return Err(e),
                }
                // §5.2 `business_key_duplicates`: only a live table can hold
                // duplicates; an entity this plan creates is empty.
                let append_only: Option<bool> = sqlx::query_scalar(
                    "SELECT COALESCE(is_append_only, false) FROM entity_info \
                     WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
                )
                .bind(entity)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?;
                if let Some(is_append_only) = append_only
                    && provision::business_key::count_duplicate_keys(
                        db,
                        entity,
                        &fields,
                        is_append_only,
                    )
                    .await?
                    .is_some_and(|n| n > 0)
                {
                    return Ok(Some(errors::BUSINESS_KEY_DUPLICATES.to_owned()));
                }
                Ok(None)
            }
            Op::UpsertRecord => {
                let current = self.current(db, op.t("entity")).await?;
                Ok(match_key(current.fields.as_deref(), &target_key(op), layer)
                    .err()
                    .map(str::to_owned))
            }
            _ => Ok(None),
        }
    }
}

/// Applies the business-key part of an applied entity operation (§3.8):
/// declares it (unrecorded: the apply ledger is the record) and brings the
/// unique index in line. `true` when something was written.
pub async fn apply_declaration(
    state: &EngineState,
    entity_id: Uuid,
    op: &DocOp,
) -> Result<bool, AppError> {
    let Some(patch) = declared_by(op).map_err(AppError::Validation)? else {
        return Ok(false);
    };
    let db = &state.base.db_migrator;
    let entity = op.t("entity");
    let current = provision::read_business_key(db, entity)
        .await?
        .ok_or(AppError::NotFound)?;
    let outcome =
        provision::declare_business_key_recorded(db, entity_id, &patch.apply_to(&current), None)
            .await?;
    if outcome.key_changed() {
        provision::ensure_business_key_index(db, state.base.config.as_ref(), entity).await?;
    }
    Ok(!outcome.changed.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changeset::ledger::ApplyPhase;
    use serde_json::json;

    fn op(op: Op, target: Value, args: Value) -> DocOp {
        DocOp {
            seq: 1,
            op,
            phase: ApplyPhase::Expand,
            target: target.as_object().cloned().unwrap_or_default(),
            args: Some(args),
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn an_entity_op_declares_only_what_it_manages() {
        let full = op(
            Op::UpdateEntity,
            json!({ "entity": "country" }),
            json!({ "definition": { "logicalname": "country", "display_name": "Country",
                    "business_key": ["code"], "is_reference_data": true } }),
        );
        assert_eq!(
            declared_by(&full),
            Ok(Some(KeyPatch {
                fields: Some(Some(names(&["code"]))),
                is_reference_data: Some(true),
            }))
        );

        // `changed` names only the flag: the key is not ours to write.
        let flag_only = op(
            Op::UpdateEntity,
            json!({ "entity": "country" }),
            json!({ "definition": { "business_key": ["code"], "is_reference_data": false },
                    "changed": ["is_reference_data"] }),
        );
        assert_eq!(
            declared_by(&flag_only),
            Ok(Some(KeyPatch {
                fields: None,
                is_reference_data: Some(false),
            }))
        );

        // A rename-only update (no key members) declares nothing.
        let rename = op(
            Op::UpdateEntity,
            json!({ "entity": "country" }),
            json!({ "definition": { "display_name": "Countries" }, "changed": ["display_name"] }),
        );
        assert_eq!(declared_by(&rename), Ok(None));

        // null clears.
        let clear = op(
            Op::UpdateEntity,
            json!({ "entity": "country" }),
            json!({ "definition": { "business_key": null } }),
        );
        assert_eq!(
            declared_by(&clear).ok().flatten().and_then(|p| p.fields),
            Some(None)
        );

        let bad = op(
            Op::UpdateEntity,
            json!({ "entity": "country" }),
            json!({ "definition": { "business_key": "code" } }),
        );
        assert!(declared_by(&bad).is_err());
    }

    #[test]
    fn a_patch_keeps_what_it_does_not_manage() {
        let current = BusinessKey {
            fields: Some(names(&["code"])),
            is_reference_data: true,
        };
        let patch = KeyPatch {
            fields: None,
            is_reference_data: Some(false),
        };
        assert_eq!(
            patch.apply_to(&current),
            BusinessKey {
                fields: Some(names(&["code"])),
                is_reference_data: false,
            }
        );
    }

    #[test]
    fn upsert_record_matches_the_declared_key_exactly() {
        let declared = names(&["code", "region"]);
        let exact = json!({ "region": "gcc", "code": "BH" });
        let exact = exact.as_object().expect("object");
        assert_eq!(
            match_key(Some(declared.as_slice()), exact, Layer::Product),
            Ok(Some(declared.clone()))
        );

        for wrong in [
            json!({ "code": "BH" }),
            json!({ "code": "BH", "region": "gcc", "name": "Bahrain" }),
            json!({ "name": "Bahrain", "region": "gcc" }),
        ] {
            let wrong = wrong.as_object().expect("object");
            assert_eq!(
                match_key(Some(declared.as_slice()), wrong, Layer::Platform)
                    .map_err(errors::code_of),
                Err("business_key_mismatch"),
                "{wrong:?}"
            );
        }
    }

    #[test]
    fn an_entity_without_a_key_is_refused_outside_the_platform_layer() {
        let key = json!({ "code": "BH" });
        let key = key.as_object().expect("object");
        assert_eq!(match_key(None, key, Layer::Platform), Ok(None));
        for layer in [Layer::Product, Layer::Project, Layer::Customer] {
            assert_eq!(
                match_key(None, key, layer).map_err(errors::code_of),
                Err("business_key_missing")
            );
        }
    }

    #[test]
    fn record_changed_reads_the_args_list() {
        let with = op(
            Op::UpsertRecord,
            json!({ "entity": "country", "key": { "code": "BH" } }),
            json!({ "values": { "name": "Bahrain" }, "changed": ["name"] }),
        );
        assert_eq!(record_changed(&with), Some(names(&["name"])));
        let without = op(
            Op::UpsertRecord,
            json!({ "entity": "country", "key": { "code": "BH" } }),
            json!({ "values": { "name": "Bahrain" } }),
        );
        assert_eq!(record_changed(&without), None);
        assert_eq!(target_key(&without).len(), 1);
    }
}
