//! Y11-T12: the customisations a platform or app release affects. When a
//! release retires, deletes or renames an entity or a field, the customer's
//! (or an app's) layer rows on it no longer reach anything: they stay keyed
//! by the old item. [`deprecation_impact`] lists them, with the new name as
//! the suggested move for a rename; [`report_drafts`] turns them into
//! `customisation_affected` release-report items. Nothing is moved: a
//! builder decides.

use std::collections::BTreeMap;

use attome_core::changeset::field_hooks::ReportItemDraft;
use attome_db::DbPool;
use attome_types::AppError;
use serde_json::{Value, json};

/// A layered item: `(object_kind, object_key)`, as `metadata_property_layer`
/// keys it (`entity` and its logical name, `attribute` and
/// `<entity>.<field>`).
pub type ObjectKey = (String, String);

/// One customisation on a removed or renamed item.
#[derive(Debug, Clone, PartialEq)]
pub struct Impact {
    pub object_kind: String,
    pub object_key: String,
    pub property: String,
    /// `customer` or `app`.
    pub layer: String,
    pub app: String,
    /// Where it would apply now: the renamed item's key; `None` for a
    /// removal.
    pub suggested_key: Option<String>,
}

/// The items a changeset's operations remove and rename. Pure.
pub fn affected_items(ops: &[Value]) -> (Vec<ObjectKey>, Vec<(ObjectKey, ObjectKey)>) {
    let mut removed = Vec::new();
    let mut renamed = Vec::new();
    for op in ops {
        let name = op.get("op").and_then(Value::as_str).unwrap_or_default();
        let target = |k: &str| {
            op.get("target")
                .and_then(|t| t.get(k))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let (entity, field) = (target("entity"), target("field"));
        match name {
            "retire_entity" if !entity.is_empty() => {
                removed.push(("entity".to_owned(), entity));
            }
            "retire_field" | "delete_field" if !entity.is_empty() && !field.is_empty() => {
                removed.push(("attribute".to_owned(), format!("{entity}.{field}")));
            }
            "rename_field" if !entity.is_empty() && !field.is_empty() => {
                let new_name = op
                    .get("args")
                    .and_then(|a| a.get("new_name"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !new_name.is_empty() {
                    renamed.push((
                        ("attribute".to_owned(), format!("{entity}.{field}")),
                        ("attribute".to_owned(), format!("{entity}.{new_name}")),
                    ));
                }
            }
            _ => {}
        }
    }
    (removed, renamed)
}

/// The customer and app rows on `removed` items (an entity's fields
/// included) and on `renamed` ones, the latter with the new key suggested.
pub async fn deprecation_impact(
    db: &DbPool,
    removed: &[ObjectKey],
    renamed: &[(ObjectKey, ObjectKey)],
) -> Result<Vec<Impact>, AppError> {
    let mut impacts = Vec::new();
    let targets = removed
        .iter()
        .map(|item| (item, None))
        .chain(renamed.iter().map(|(from, to)| (from, Some(to.1.clone()))));
    for ((kind, key), suggested) in targets {
        // An entity's removal reaches its fields' customisations too. The
        // prefix is compared, not matched: `_` is a LIKE wildcard and logical
        // names use it.
        let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
            "SELECT object_kind, object_key, property, layer, app FROM metadata_property_layer \
              WHERE layer <> 'platform' \
                AND ((object_kind = $1 AND object_key = $2) \
                  OR ($1 = 'entity' AND object_kind = 'attribute' \
                      AND left(object_key, length($2) + 1) = $2 || '.')) \
              ORDER BY object_kind, object_key, property",
        )
        .bind(kind)
        .bind(key)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        for (object_kind, object_key, property, layer, app) in rows {
            impacts.push(Impact {
                object_kind,
                object_key,
                property,
                layer,
                app,
                suggested_key: suggested.clone(),
            });
        }
    }
    Ok(impacts)
}

/// One `customisation_affected` draft per affected item, naming its
/// customised properties and, for a rename, the new name. Pure.
pub fn report_drafts(impacts: &[Impact]) -> Vec<ReportItemDraft> {
    let mut by_item: BTreeMap<(String, String), (Vec<String>, Option<String>)> = BTreeMap::new();
    for impact in impacts {
        let entry = by_item
            .entry((impact.object_kind.clone(), impact.object_key.clone()))
            .or_insert_with(|| (Vec::new(), impact.suggested_key.clone()));
        if !entry.0.contains(&impact.property) {
            entry.0.push(impact.property.clone());
        }
    }
    by_item
        .into_iter()
        .map(|((kind, key), (properties, suggested))| {
            let (entity, field) = match key.split_once('.') {
                Some((entity, field)) if kind == "attribute" => {
                    (entity.to_owned(), Some(field.to_owned()))
                }
                _ => (key.clone(), None),
            };
            let to = suggested
                .as_deref()
                .and_then(|k| k.split_once('.'))
                .map(|(_, field)| field.to_owned());
            ReportItemDraft {
                kind: "customisation_affected",
                entity,
                field,
                object_kind: Some(kind),
                object_ref: None,
                detail: json!({
                    "change": if to.is_some() { "renamed" } else { "removed" },
                    "properties": properties,
                    "to": to,
                }),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changeset_names_what_it_removes_and_renames() {
        let ops = vec![
            json!({"op": "retire_entity", "target": {"entity": "legacy"}}),
            json!({"op": "delete_field", "target": {"entity": "account", "field": "fax"}}),
            json!({"op": "rename_field", "target": {"entity": "account", "field": "phone"},
                   "args": {"new_name": "phone_main"}}),
            json!({"op": "update_field", "target": {"entity": "account", "field": "name"}}),
        ];
        let (removed, renamed) = affected_items(&ops);
        assert_eq!(
            removed,
            vec![
                ("entity".to_owned(), "legacy".to_owned()),
                ("attribute".to_owned(), "account.fax".to_owned()),
            ]
        );
        assert_eq!(
            renamed,
            vec![(
                ("attribute".to_owned(), "account.phone".to_owned()),
                ("attribute".to_owned(), "account.phone_main".to_owned()),
            )]
        );
    }

    #[test]
    fn a_draft_groups_an_items_properties_and_names_the_new_field() {
        let impact = |property: &str| Impact {
            object_kind: "attribute".into(),
            object_key: "account.phone".into(),
            property: property.into(),
            layer: "customer".into(),
            app: String::new(),
            suggested_key: Some("account.phone_main".into()),
        };
        let drafts = report_drafts(&[impact("name"), impact("max_length")]);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].entity, "account");
        assert_eq!(drafts[0].field.as_deref(), Some("phone"));
        assert_eq!(drafts[0].detail["change"], "renamed");
        assert_eq!(drafts[0].detail["to"], "phone_main");
        assert_eq!(
            drafts[0].detail["properties"],
            json!(["name", "max_length"])
        );
    }
}
