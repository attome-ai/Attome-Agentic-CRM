//! A8-T1: polymorphic lookups. A "regarding" field points at a record of
//! one of several entities, so it is stored as two attributes: the target
//! entity's logical name (`<name>_entity`, text) and the target record's id
//! (`<name>_id`, text holding a UUID). The id attribute's options mark the
//! pair and say what it may point at:
//!
//! ```json
//! { "polymorphic": { "pair": "regarding_entity", "targets": ["account", "contact"] } }
//! { "polymorphic": { "pair": "regarding_entity", "extends": "party" } }
//! ```
//!
//! `targets` lists the entities; `extends` admits every entity built on that
//! base (A1-T4); `"any": true` admits every entity (V7-T1's queue item, which
//! may hold a record of any kind). On every write that sets either attribute
//! ([`check_writes`]), both are set together, the entity is an allowed
//! target, and the record exists, is live and is readable by the writer
//! (person or agent); otherwise the write is refused, with one message for a
//! missing and an unreadable record so the refusal reveals nothing.

use attome_core::{AttrInfo, EngineState};
use attome_security::RecordAction;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::entity_mutation::Principal;

/// `options.polymorphic` of a polymorphic id attribute.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PolymorphicOptions {
    /// The attribute holding the target entity's logical name.
    pub pair: String,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub extends: Option<String>,
    /// Every entity is a target.
    #[serde(default)]
    pub any: bool,
    /// A8-T2: what deleting a target does to the records pointing at it, per
    /// target entity (`"*"` for every other): `restrict`, `orphan` (the
    /// default) or `cascade-deactivate`.
    #[serde(default)]
    pub on_delete: std::collections::BTreeMap<String, String>,
}

impl PolymorphicOptions {
    /// A8-T2: the delete rule for a target of `entity`: its own, else the
    /// `"*"` rule, else orphan. Pure.
    pub fn delete_rule(&self, entity: &str) -> attome_core::OnTargetDelete {
        self.on_delete
            .get(entity)
            .or_else(|| self.on_delete.get("*"))
            .map(|mode| attome_core::OnTargetDelete::from_db_str(mode))
            .unwrap_or(attome_core::OnTargetDelete::Orphan)
    }
}

/// The polymorphic options of `attr`, if it is a polymorphic id attribute.
pub fn options_of(attr: &AttrInfo) -> Option<PolymorphicOptions> {
    let raw = attr.options.as_ref()?.get("polymorphic")?;
    serde_json::from_value(raw.clone()).ok()
}

/// What one write sets on a polymorphic pair. Pure.
#[derive(Debug, Clone, PartialEq)]
pub enum PairWrite {
    /// Neither attribute is written.
    Untouched,
    /// Both cleared.
    Cleared,
    /// A target: (entity, record id).
    Target(String, Uuid),
}

/// What `obj` writes on the pair `(id_attr, entity_attr)`. Pure.
pub fn pair_write(
    obj: &Map<String, Value>,
    id_attr: &str,
    entity_attr: &str,
) -> Result<PairWrite, AppError> {
    let id = obj.get(id_attr);
    let entity = obj.get(entity_attr);
    let empty = |v: Option<&Value>| {
        v.is_none_or(|v| v.is_null() || v.as_str().is_some_and(|s| s.trim().is_empty()))
    };
    match (id, entity) {
        (None, None) => Ok(PairWrite::Untouched),
        (Some(_), None) | (None, Some(_)) => Err(AppError::Validation(format!(
            "{id_attr} and {entity_attr} are written together"
        ))),
        (Some(_), Some(_)) if empty(id) && empty(entity) => Ok(PairWrite::Cleared),
        (Some(_), Some(_)) if empty(id) || empty(entity) => Err(AppError::Validation(format!(
            "{id_attr} and {entity_attr} are both set or both cleared"
        ))),
        (Some(id), Some(entity)) => {
            let record = id
                .as_str()
                .and_then(|s| Uuid::parse_str(s.trim()).ok())
                .ok_or_else(|| AppError::Validation(format!("{id_attr}: invalid UUID")))?;
            let name = entity
                .as_str()
                .map(str::trim)
                .unwrap_or_default()
                .to_owned();
            Ok(PairWrite::Target(name, record))
        }
    }
}

/// Whether `entity` is a target the options allow: listed, or built on the
/// `extends` base (`base_of` answers an entity's base). Pure.
pub fn allowed(options: &PolymorphicOptions, entity: &str, base_of: Option<&str>) -> bool {
    options.any
        || options.targets.iter().any(|t| t == entity)
        || options
            .extends
            .as_deref()
            .is_some_and(|base| base == entity || base_of == Some(base))
}

/// Refuses a write whose polymorphic pairs point anywhere but a live,
/// allowed, readable record.
pub(crate) async fn check_writes(
    state: &EngineState,
    principal: Principal<'_>,
    attrs: &[AttrInfo],
    obj: &Map<String, Value>,
) -> Result<(), AppError> {
    for attr in attrs {
        let Some(options) = options_of(attr) else {
            continue;
        };
        let (entity, record) = match pair_write(obj, &attr.logicalname, &options.pair)? {
            PairWrite::Untouched | PairWrite::Cleared => continue,
            PairWrite::Target(entity, record) => (entity, record),
        };
        let refused = || {
            AppError::Validation(format!(
                "{}: the record does not exist or cannot be read",
                attr.logicalname
            ))
        };
        let target: Option<(Uuid, String, Option<String>)> = sqlx::query_as(
            "SELECT e.id, e.logicalname, b.logicalname FROM entity_info e \
               LEFT JOIN entity_info b ON b.id = e.extends_entity_id \
              WHERE e.logicalname = $1 AND (e.is_active IS NULL OR e.is_active = true)",
        )
        .bind(&entity)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let Some((entity_id, entity_name, base)) = target else {
            return Err(AppError::Validation(format!(
                "{}: {entity} is not an entity it may point at",
                attr.logicalname
            )));
        };
        if !allowed(&options, &entity_name, base.as_deref()) {
            return Err(AppError::Validation(format!(
                "{}: {entity} is not an entity it may point at",
                attr.logicalname
            )));
        }
        let live: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {} WHERE id = $1 AND is_active = TRUE)",
            attome_core::quote_ident(&entity_name)
        ))
        .bind(record)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if !live {
            return Err(refused());
        }
        match principal {
            Principal::Staff(ctx) => {
                crate::entity_crud::require_record_access(
                    state,
                    ctx,
                    entity_id,
                    &entity_name,
                    record,
                    RecordAction::Read,
                )
                .await
                .map_err(|_| refused())?;
            }
            // A portal user names no staff record.
            Principal::Portal(_) => return Err(AppError::Forbidden),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn polymorphic_lookup_pairs_are_written_together() {
        let id = "019a0000-0000-7000-8000-000000000001";
        assert_eq!(
            pair_write(&obj(json!({})), "r_id", "r_entity").unwrap(),
            PairWrite::Untouched
        );
        assert_eq!(
            pair_write(
                &obj(json!({ "r_id": null, "r_entity": "" })),
                "r_id",
                "r_entity"
            )
            .unwrap(),
            PairWrite::Cleared
        );
        assert_eq!(
            pair_write(
                &obj(json!({ "r_id": id, "r_entity": "account" })),
                "r_id",
                "r_entity"
            )
            .unwrap(),
            PairWrite::Target("account".into(), Uuid::parse_str(id).unwrap())
        );
        assert!(pair_write(&obj(json!({ "r_id": id })), "r_id", "r_entity").is_err());
        assert!(
            pair_write(
                &obj(json!({ "r_id": id, "r_entity": null })),
                "r_id",
                "r_entity"
            )
            .is_err()
        );
        assert!(
            pair_write(
                &obj(json!({ "r_id": "nope", "r_entity": "account" })),
                "r_id",
                "r_entity"
            )
            .is_err()
        );
    }

    #[test]
    fn polymorphic_lookup_targets_by_list_or_base() {
        let listed = PolymorphicOptions {
            pair: "r_entity".into(),
            targets: vec!["account".into()],
            extends: None,
            any: false,
        };
        assert!(allowed(&listed, "account", None));
        assert!(!allowed(&listed, "contact", None));
        let based = PolymorphicOptions {
            pair: "r_entity".into(),
            targets: vec![],
            extends: Some("party".into()),
            any: false,
        };
        assert!(allowed(&based, "person", Some("party")));
        assert!(allowed(&based, "party", None));
        assert!(!allowed(&based, "invoice", None));
        let any: PolymorphicOptions =
            serde_json::from_value(serde_json::json!({ "pair": "r_entity", "any": true })).unwrap();
        assert!(allowed(&any, "invoice", None));
        assert!(allowed(&any, "service_ticket", None));
    }
}
