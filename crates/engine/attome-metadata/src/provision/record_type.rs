//! A27-T1/T2: the `record_type` attribute an entity gets with its first record
//! type (`attome_model::kinds::record_type`), and the type a new record gets.
//!
//! The column is nullable text, so adding it is a catalogue change on any
//! table size, and existing rows are not rewritten: a record whose
//! `record_type` is empty is of the entity's default type. Registering it
//! goes through the same reconcile path as every engine's seeded attribute,
//! so a second call changes nothing and the metadata change log tells every
//! node.
//!
//! A27-T2: a type may name the roles allowed to create it (`roles`; none
//! named means every role) and the roles it is the default for
//! (`default_for_roles`). A create that names no type gets its role's
//! default, else the entity's default; a type the caller's roles may not use
//! is refused with 403. A system writer (no roles on its context) may use
//! any type. The chosen type's `defaults` fill fields the request left out.

use attome_db::DbPool;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Map, Value};
use uuid::Uuid;

/// The record attribute that holds a record's type code.
pub const ATTRIBUTE: &str = attome_model::kinds::record_type::RECORD_TYPE_ATTRIBUTE;

/// The most record types one entity's write path reads.
const MAX_TYPES: i64 = 1_000;

/// Gives `entity_id` its `record_type` attribute and column, when it has
/// neither.
pub async fn ensure_column(db: &DbPool, entity_id: Uuid) -> Result<(), AppError> {
    super::attribute::ensure_attribute(
        db,
        entity_id,
        ATTRIBUTE,
        "Record type",
        "text",
        false,
        false,
        true,
        true,
        None,
        None,
    )
    .await
    .map(|_| ())
}

/// One published record type, as the write path reads it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RecordType {
    pub code: String,
    #[serde(default)]
    pub is_default: bool,
    /// The roles that may create records of this type; empty is every role.
    #[serde(default)]
    pub roles: Vec<Uuid>,
    /// The roles whose new records get this type when none is named.
    #[serde(default)]
    pub default_for_roles: Vec<Uuid>,
    #[serde(default)]
    pub defaults: Map<String, Value>,
}

/// The newest published version of every record type of `entity_id`.
pub async fn published_types(db: &DbPool, entity_id: Uuid) -> Result<Vec<RecordType>, AppError> {
    let docs: Vec<Value> = sqlx::query_scalar(
        "SELECT doc FROM ( \
             SELECT DISTINCT ON (o.id) v.doc \
             FROM metadata_object o \
             JOIN metadata_object_version v ON v.object_id = o.id \
             WHERE o.kind = 'record_type' AND o.is_active AND v.state = 'published' \
               AND v.doc->>'entity' = $1 \
             ORDER BY o.id, v.version_no DESC \
         ) t LIMIT $2",
    )
    .bind(entity_id.to_string())
    .bind(MAX_TYPES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(docs
        .into_iter()
        .filter_map(|doc| serde_json::from_value(doc).ok())
        .collect())
}

/// The type a new record gets: the one it names, else its role's default,
/// else the entity's default; `None` when the entity has no types or no
/// default applies. A named type that does not exist is a validation error;
/// a type the caller's roles may not use is forbidden. `roles` is `None` for
/// a system writer, which may use any type.
pub fn decide_create<'a>(
    types: &'a [RecordType],
    requested: Option<&str>,
    roles: Option<&[Uuid]>,
) -> Result<Option<&'a RecordType>, AppError> {
    if types.is_empty() {
        return Ok(None);
    }
    let chosen = match requested {
        Some(code) => types
            .iter()
            .find(|t| t.code == code)
            .ok_or_else(|| AppError::Validation(format!("unknown record type `{code}`")))?,
        None => {
            let role_default = roles.and_then(|held| {
                types
                    .iter()
                    .find(|t| t.default_for_roles.iter().any(|r| held.contains(r)))
            });
            match role_default.or_else(|| types.iter().find(|t| t.is_default)) {
                Some(t) => t,
                None => return Ok(None),
            }
        }
    };
    let allowed = match roles {
        None => true,
        Some(held) => chosen.roles.is_empty() || chosen.roles.iter().any(|r| held.contains(r)),
    };
    if !allowed {
        return Err(AppError::Forbidden);
    }
    Ok(Some(chosen))
}

/// Applies [`decide_create`] to a create request's fields: writes the chosen
/// type's code when the request named none, and fills the type's defaults
/// into fields left out.
pub async fn apply_on_create(
    db: &DbPool,
    entity_id: Uuid,
    roles: Option<&[Uuid]>,
    fields: &mut Map<String, Value>,
) -> Result<(), AppError> {
    let types = published_types(db, entity_id).await?;
    let requested = match fields.get(ATTRIBUTE) {
        None | Some(Value::Null) => None,
        Some(Value::String(code)) if code.trim().is_empty() => None,
        Some(Value::String(code)) => Some(code.clone()),
        Some(_) => {
            return Err(AppError::Validation(
                "record_type is a type code (text)".into(),
            ));
        }
    };
    let Some(chosen) = decide_create(&types, requested.as_deref(), roles)? else {
        return Ok(());
    };
    fill(chosen, fields);
    Ok(())
}

fn fill(chosen: &RecordType, fields: &mut Map<String, Value>) {
    fields
        .entry(ATTRIBUTE)
        .and_modify(|value| {
            if value.is_null() || value.as_str().is_some_and(|s| s.trim().is_empty()) {
                *value = Value::String(chosen.code.clone());
            }
        })
        .or_insert_with(|| Value::String(chosen.code.clone()));
    for (name, value) in &chosen.defaults {
        if name != ATTRIBUTE && !fields.contains_key(name) {
            fields.insert(name.clone(), value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn types(sales: Uuid, support: Uuid) -> Vec<RecordType> {
        vec![
            RecordType {
                code: "service".into(),
                is_default: true,
                ..RecordType::default()
            },
            RecordType {
                code: "complaint".into(),
                roles: vec![support],
                default_for_roles: vec![support],
                defaults: json!({ "priority": "high" }).as_object().cloned().unwrap(),
                ..RecordType::default()
            },
            RecordType {
                code: "quote".into(),
                roles: vec![sales],
                ..RecordType::default()
            },
        ]
    }

    #[test]
    fn record_type_role_may_not_create_a_type_it_is_not_allowed() {
        let (sales, support) = (Uuid::now_v7(), Uuid::now_v7());
        let all = types(sales, support);
        assert!(matches!(
            decide_create(&all, Some("complaint"), Some(&[sales])),
            Err(AppError::Forbidden)
        ));
        assert_eq!(
            decide_create(&all, Some("quote"), Some(&[sales]))
                .unwrap()
                .map(|t| t.code.as_str()),
            Some("quote")
        );
        // A type naming no roles is open to every role.
        assert!(decide_create(&all, Some("service"), Some(&[sales])).is_ok());
        // A system writer may use any type.
        assert!(decide_create(&all, Some("complaint"), None).is_ok());
        assert!(matches!(
            decide_create(&all, Some("nope"), Some(&[sales])),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn record_type_role_default_comes_before_the_entity_default() {
        let (sales, support) = (Uuid::now_v7(), Uuid::now_v7());
        let all = types(sales, support);
        let pick = |roles: &[Uuid]| {
            decide_create(&all, None, Some(roles))
                .unwrap()
                .map(|t| t.code.clone())
        };
        assert_eq!(pick(&[support]).as_deref(), Some("complaint"));
        assert_eq!(pick(&[sales]).as_deref(), Some("service"));
        assert!(
            decide_create(&[], Some("anything"), Some(&[sales]))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn record_type_role_defaults_fill_only_missing_fields() {
        let (sales, support) = (Uuid::now_v7(), Uuid::now_v7());
        let all = types(sales, support);
        let complaint = &all[1];
        let mut fields = json!({ "title": "late", "record_type": null })
            .as_object()
            .cloned()
            .unwrap();
        fill(complaint, &mut fields);
        assert_eq!(fields["record_type"], "complaint");
        assert_eq!(fields["priority"], "high");
        let mut kept = json!({ "priority": "low" }).as_object().cloned().unwrap();
        fill(complaint, &mut kept);
        assert_eq!(kept["priority"], "low");
    }
}
