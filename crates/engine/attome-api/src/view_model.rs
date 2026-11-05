//! V2-D1815, the expand step's mirror: every system view (`view`, scope
//! `system`) published as a `view` model object under its own id, so the
//! model holds the same views the lists read from the table, ready for the
//! switch (the lists reading the cooked view, then AA4-T8's cooked plan).
//!
//! The table stays the source of truth: [`mirror_views`] reads it and never
//! writes it, each view in its own transaction, and a view the model refuses
//! (a column naming an attribute that is gone) is logged and skipped, so a
//! mirror never stands in the way of a view save, a pack install or a boot.
//! A view whose published document already matches is left as it is.

use attome_core::EngineState;
use attome_model::store::{self, ObjectSpec};
use attome_model::{Layer, ObjectId};
use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

/// One system view as the table holds it.
#[derive(sqlx::FromRow)]
struct ViewRow {
    id: Uuid,
    name: String,
    entity_id: Uuid,
    entity: String,
    query_id: Uuid,
    is_default: bool,
    table_definition: Value,
    icon: String,
    kind: String,
    view_metadata: Value,
    owner_layer: String,
}

/// The model layer and app a view's owner layer maps to.
fn layer_of(owner_layer: &str) -> (Layer, &'static str) {
    match Layer::from_stored(owner_layer).unwrap_or(Layer::Customer) {
        Layer::Platform => (Layer::Platform, "platform"),
        Layer::App => (Layer::App, "views"),
        Layer::Customer => (Layer::Customer, "customer"),
    }
}

/// The view document for `row`, its columns resolved to attribute ids
/// through `attributes` (logical name to id); a column whose attribute is
/// gone is left out. Pure.
fn document(row: &ViewRow, attributes: &std::collections::HashMap<String, Uuid>) -> Value {
    let columns: Vec<Value> = row
        .table_definition
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|column| {
            let name = column
                .get("name")
                .or_else(|| column.get("field"))
                .and_then(Value::as_str)?;
            let id = attributes.get(name)?;
            let mut out = Map::new();
            out.insert("attribute".into(), json!(id.to_string()));
            if let Some(label) = column
                .get("display_name")
                .or_else(|| column.get("label"))
                .and_then(Value::as_str)
                .filter(|l| !l.is_empty())
            {
                out.insert("label".into(), json!(label));
            }
            if let Some(width) = column
                .get("width")
                .and_then(Value::as_u64)
                .filter(|w| *w > 0)
            {
                out.insert("width".into(), json!(width.min(2000)));
            }
            Some(Value::Object(out))
        })
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    let columns: Vec<Value> = columns
        .into_iter()
        .filter(|c| seen.insert(c["attribute"].as_str().unwrap_or_default().to_owned()))
        .collect();
    json!({
        "entity": row.entity_id.to_string(),
        "query": row.query_id.to_string(),
        "view_kind": row.kind,
        "columns": columns,
        "is_default": row.is_default,
        "icon": row.icon,
        "settings": if row.view_metadata.is_object() { row.view_metadata.clone() } else { json!({}) },
    })
}

/// Mirrors every active system view into the model; answers how many it
/// published. Logs and skips a view the model refuses.
pub async fn mirror_views(state: &EngineState) -> Result<usize, AppError> {
    let kinds = crate::model_admin::kinds();
    let Some(kind) = kinds.get(attome_model::kinds::VIEW.as_str()) else {
        return Ok(0);
    };
    let rows: Vec<ViewRow> = sqlx::query_as(
        "SELECT v.id, v.name::text AS name, v.entity_logical_name AS entity_id, \
                ei.logicalname::text AS entity, v.sql_query_ref AS query_id, v.is_default, \
                v.table_definition, v.icon, v.kind::text AS kind, v.view_metadata, v.owner_layer \
           FROM view v JOIN entity_info ei ON ei.id = v.entity_logical_name \
          WHERE v.is_active AND v.scope = 'system' AND ei.is_active IS NOT FALSE",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut published = 0;
    for row in rows {
        let attributes: std::collections::HashMap<String, Uuid> =
            sqlx::query_as::<_, (String, Uuid)>(
                "SELECT logicalname::text, id FROM attribute_info \
              WHERE entity_ref = $1 AND logicalname IS NOT NULL AND is_active IS NOT FALSE",
            )
            .bind(row.entity_id)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .collect();
        let doc = document(&row, &attributes);
        if let Ok(current) = store::read_published(&state.base.db, row.id).await
            && current.doc == doc
        {
            continue;
        }
        let (layer, app) = layer_of(&row.owner_layer);
        let spec = ObjectSpec {
            id: ObjectId(row.id),
            name: format!("{}.{}", row.entity, row.name),
            app: app.to_owned(),
            layer,
        };
        let outcome = async {
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            store::save_draft(&mut tx, kinds, kind.as_ref(), &spec, &doc, None).await?;
            attome_model::publish::publish(
                &mut tx,
                kinds,
                &attome_model::validate::CrossChecks::default(),
                kind.as_ref(),
                row.id,
            )
            .await?;
            attome_db::tx::commit(tx).await
        }
        .await;
        match outcome {
            Ok(()) => published += 1,
            Err(e) => tracing::warn!(
                view_id = %row.id,
                entity = %row.entity,
                error = %e,
                "views: a system view was not mirrored into the model"
            ),
        }
    }
    // The published views join the cooked snapshot, where AA4-T8 reads them.
    if published > 0
        && let Err(e) = crate::model_admin::refresh_cooked(state).await
    {
        tracing::warn!(error = %e, "views: the mirrored views were not cooked yet");
    }
    Ok(published)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(table_definition: Value) -> ViewRow {
        ViewRow {
            id: Uuid::now_v7(),
            name: "Open deals".into(),
            entity_id: Uuid::from_u128(1),
            entity: "opportunity".into(),
            query_id: Uuid::from_u128(2),
            is_default: true,
            table_definition,
            icon: "las la-table".into(),
            kind: "kanban".into(),
            view_metadata: json!({ "lane": "stage" }),
            owner_layer: "product".into(),
        }
    }

    #[test]
    fn a_view_row_becomes_a_view_document_the_kind_accepts() {
        let attributes = std::collections::HashMap::from([
            ("name".to_owned(), Uuid::from_u128(10)),
            ("amount".to_owned(), Uuid::from_u128(11)),
        ]);
        let doc = document(
            &row(json!([
                { "name": "name", "display_name": "Deal", "width": 240 },
                { "name": "gone" },
                { "field": "amount" },
                { "name": "name" }
            ])),
            &attributes,
        );
        use attome_model::Kind as _;
        assert!(
            attome_model::kinds::ViewKind.validate_shape(&doc).is_ok(),
            "{doc}"
        );
        assert_eq!(
            attome_model::kinds::view::column_attributes(&doc),
            vec![
                Uuid::from_u128(10).to_string(),
                Uuid::from_u128(11).to_string()
            ]
        );
        assert_eq!(doc["columns"][0]["label"], "Deal");
        assert_eq!(doc["view_kind"], "kanban");
        assert_eq!(layer_of("product"), (Layer::App, "views"));
    }
}
