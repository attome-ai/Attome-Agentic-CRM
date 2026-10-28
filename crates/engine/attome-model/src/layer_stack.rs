//! The layer-stack merge (roadmap Y11-T3), pure: an object's effective value
//! for each property is the platform's, then each installed app's in
//! install order, then the customer's, the last one that set the property
//! winning. Each property merges on its own, so a customer label change
//! leaves every other property following the platform, including a later
//! platform fix to the same object.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::Layer;

/// One layer's value for one property.
#[derive(Debug, Clone, PartialEq)]
pub struct PropertyValue {
    pub layer: Layer,
    /// The app (pack) that set it; empty for the platform and the customer.
    pub app: String,
    pub value: Value,
}

fn layer_rank(layer: Layer) -> u8 {
    match layer {
        Layer::Platform => 0,
        Layer::App => 1,
        Layer::Customer => 2,
    }
}

/// The effective properties and the layer each one came from.
///
/// `base` is the object as the platform defines it; `rows` are property
/// values per layer, keyed by property name; `app_order` is the order the
/// apps were installed in (an app missing from it sorts after the listed
/// ones, by name). The result does not depend on the order of `rows`.
pub fn effective(
    base: &Map<String, Value>,
    rows: &[(String, PropertyValue)],
    app_order: &[String],
) -> (Map<String, Value>, BTreeMap<String, Layer>) {
    let app_position = |app: &str| {
        app_order
            .iter()
            .position(|a| a == app)
            .unwrap_or(app_order.len())
    };
    let mut sorted: Vec<&(String, PropertyValue)> = rows.iter().collect();
    sorted.sort_by(|(pa, a), (pb, b)| {
        pa.cmp(pb)
            .then(layer_rank(a.layer).cmp(&layer_rank(b.layer)))
            .then(app_position(&a.app).cmp(&app_position(&b.app)))
            .then(a.app.cmp(&b.app))
    });

    let mut values = base.clone();
    let mut winners: BTreeMap<String, Layer> =
        base.keys().map(|k| (k.clone(), Layer::Platform)).collect();
    for (property, row) in sorted {
        values.insert(property.clone(), row.value.clone());
        winners.insert(property.clone(), row.layer);
    }
    (values, winners)
}

/// Y11-T5: one property across the layers: each layer's value, in merge
/// order (platform, apps in install order, customer), and the winner.
#[derive(Debug, Clone, PartialEq)]
pub struct PropertyStack {
    pub property: String,
    pub winner: Layer,
    pub values: Vec<PropertyValue>,
}

/// Each property's stack, by property name. Pure.
pub fn stacks(rows: &[(String, PropertyValue)], app_order: &[String]) -> Vec<PropertyStack> {
    let (_, winners) = effective(&Map::new(), rows, app_order);
    let app_position = |app: &str| {
        app_order
            .iter()
            .position(|a| a == app)
            .unwrap_or(app_order.len())
    };
    let mut by_property: BTreeMap<&str, Vec<PropertyValue>> = BTreeMap::new();
    for (property, value) in rows {
        by_property
            .entry(property.as_str())
            .or_default()
            .push(value.clone());
    }
    by_property
        .into_iter()
        .map(|(property, mut values)| {
            values.sort_by(|a, b| {
                layer_rank(a.layer)
                    .cmp(&layer_rank(b.layer))
                    .then(app_position(&a.app).cmp(&app_position(&b.app)))
                    .then(a.app.cmp(&b.app))
            });
            PropertyStack {
                property: property.to_owned(),
                winner: winners.get(property).copied().unwrap_or(Layer::Platform),
                values,
            }
        })
        .collect()
}

/// A property whose value differs between two layers.
#[derive(Debug, Clone, PartialEq)]
pub struct LayerDifference {
    pub property: String,
    /// `None` when the layer does not set the property.
    pub from: Option<Value>,
    pub to: Option<Value>,
}

/// The properties whose value in layer `from` differs from layer `to`'s
/// (among several apps, the last installed one's). Pure.
pub fn diff(stacks: &[PropertyStack], from: Layer, to: Layer) -> Vec<LayerDifference> {
    let at = |stack: &PropertyStack, layer: Layer| {
        stack
            .values
            .iter()
            .rev()
            .find(|v| v.layer == layer)
            .map(|v| v.value.clone())
    };
    stacks
        .iter()
        .filter_map(|stack| {
            let (a, b) = (at(stack, from), at(stack, to));
            (a != b).then(|| LayerDifference {
                property: stack.property.clone(),
                from: a,
                to: b,
            })
        })
        .collect()
}

/// Y11-T5: the stacks of one object (`metadata_property_layer`'s `kind` and
/// `key`, e.g. `attribute` and `account.phone`), merged in the installed
/// apps' order.
pub async fn stack(
    db: &attome_db::DbPool,
    kind: &str,
    key: &str,
) -> Result<Vec<PropertyStack>, attome_types::AppError> {
    let rows: Vec<(String, String, String, Option<Value>)> = sqlx::query_as(
        "SELECT property, layer, app, value FROM metadata_property_layer           WHERE object_kind = $1 AND object_key = $2",
    )
    .bind(kind)
    .bind(key)
    .fetch_all(db)
    .await
    .map_err(attome_types::AppError::internal)?;
    let app_order: Vec<String> = sqlx::query_scalar("SELECT app FROM app_layer ORDER BY position")
        .fetch_all(db)
        .await
        .map_err(attome_types::AppError::internal)?;
    let rows: Vec<(String, PropertyValue)> = rows
        .into_iter()
        .filter_map(|(property, layer, app, value)| {
            Some((
                property,
                PropertyValue {
                    layer: Layer::from_stored(&layer)?,
                    app,
                    value: value.unwrap_or(Value::Null),
                },
            ))
        })
        .collect();
    Ok(stacks(&rows, &app_order))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(property: &str, layer: Layer, app: &str, value: Value) -> (String, PropertyValue) {
        (
            property.to_owned(),
            PropertyValue {
                layer,
                app: app.to_owned(),
                value,
            },
        )
    }

    fn map(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn customer_label_keeps_platform_validation_fix() {
        // The platform fixed the validation after the customer relabelled
        // the field: the label stays the customer's, the fix applies.
        let base = map(json!({ "label": "Phone", "max_length": 20 }));
        let rows = [
            row("label", Layer::Customer, "", json!("Mobile")),
            row("max_length", Layer::Platform, "", json!(32)),
        ];
        let (values, winners) = effective(&base, &rows, &[]);
        assert_eq!(values["label"], json!("Mobile"));
        assert_eq!(values["max_length"], json!(32));
        assert_eq!(winners["label"], Layer::Customer);
        assert_eq!(winners["max_length"], Layer::Platform);
    }

    #[test]
    fn app_order_decides_clash() {
        let base = map(json!({ "label": "Account" }));
        let rows = [
            row("label", Layer::App, "sales", json!("Customer")),
            row("label", Layer::App, "crm", json!("Company")),
        ];
        let order = ["crm".to_owned(), "sales".to_owned()];
        let (values, winners) = effective(&base, &rows, &order);
        assert_eq!(values["label"], json!("Customer"), "the later app wins");
        assert_eq!(winners["label"], Layer::App);
        let reversed = ["sales".to_owned(), "crm".to_owned()];
        assert_eq!(
            effective(&base, &rows, &reversed).0["label"],
            json!("Company")
        );
    }

    #[test]
    fn a_stack_lists_every_layer_in_merge_order_with_the_winner() {
        let rows = [
            row("label", Layer::Customer, "", json!("Mobile")),
            row("label", Layer::Platform, "", json!("Phone")),
            row("max_length", Layer::Platform, "", json!(20)),
        ];
        let stacks = stacks(&rows, &[]);
        assert_eq!(stacks.len(), 2);
        assert_eq!(stacks[0].property, "label");
        assert_eq!(stacks[0].winner, Layer::Customer);
        assert_eq!(
            stacks[0].values.iter().map(|v| v.layer).collect::<Vec<_>>(),
            vec![Layer::Platform, Layer::Customer]
        );
        assert_eq!(stacks[1].winner, Layer::Platform);
        let differences = diff(&stacks, Layer::Platform, Layer::Customer);
        assert_eq!(
            differences,
            vec![
                LayerDifference {
                    property: "label".into(),
                    from: Some(json!("Phone")),
                    to: Some(json!("Mobile")),
                },
                LayerDifference {
                    property: "max_length".into(),
                    from: Some(json!(20)),
                    to: None,
                },
            ]
        );
    }

    #[test]
    fn customer_beats_every_app_and_order_of_rows_does_not_matter() {
        let base = Map::new();
        let mut rows = vec![
            row("label", Layer::Customer, "", json!("Mine")),
            row("label", Layer::App, "crm", json!("Theirs")),
            row("label", Layer::Platform, "", json!("Base")),
        ];
        let first = effective(&base, &rows, &["crm".to_owned()]);
        rows.reverse();
        let second = effective(&base, &rows, &["crm".to_owned()]);
        assert_eq!(first, second);
        assert_eq!(first.0["label"], json!("Mine"));
        assert_eq!(first.1["label"], Layer::Customer);
    }
}
