//! L4-T2: the data catalog's asset index (`catalog_asset`, migration 0060)
//! filled from the metadata itself.
//!
//! [`rebuild_assets`] reads every asset kind and upserts one row per asset,
//! keyed by `(kind, ref)`, then deletes rows whose asset is gone:
//!
//! - `entity` (`entity_info`, ref = logical name) and `attribute`
//!   (`attribute_info`, ref = `entity.field`, parent = the entity); a choice
//!   attribute is also an `option_set` (same ref);
//! - `view` (`view`), `saved_query` and `report` (`sql_query`, a report when
//!   `is_report`; and `attome_report` records), `dashboard`
//!   (`attome_dashboard`), `metric` (`dashboard_metric_definition`) and
//!   `flow` (`workflow_definition`), ref = id;
//! - `agent_tool`: every action of the AI registry, ref = action id.
//!
//! Rows are read whole (`row_to_json`) and named from the first of their
//! name columns that is set, so a table's column set may differ; a table a
//! deployment lacks is skipped; a row marked inactive or deleted is left
//! out. Names and descriptions in English and Arabic make the search vector
//! (`simple` configuration, Arabic normalised: alef forms, taa marbuta,
//! diacritics). A description someone has written (`description_status`
//! not `missing`) is kept; a new one from the metadata only fills an empty
//! one.
//!
//! It runs after every model publish and from the `catalog_asset_rebuild`
//! job (every 15 minutes, first at boot), so changes made through the entity,
//! view and query admin routes are picked up too.

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_core::quote_ident;
use attome_types::AppError;
use serde_json::{Map, Value};

/// The registered job.
pub const JOB: &str = "catalog_asset_rebuild";

/// One asset to index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub kind: &'static str,
    pub reference: String,
    pub parent: Option<String>,
    pub name_en: Option<String>,
    pub name_ar: Option<String>,
    pub description_en: Option<String>,
    pub description_ar: Option<String>,
}

/// What a rebuild did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RebuildCounts {
    pub upserted: usize,
    pub removed: u64,
}

const NAME_EN: [&str; 5] = ["display_name", "label_en", "name_en", "name", "title"];
const NAME_AR: [&str; 4] = ["display_name_ar", "label_ar", "name_ar", "title_ar"];
const DESC_EN: [&str; 2] = ["description_en", "description"];
const DESC_AR: [&str; 1] = ["description_ar"];

/// The first non-blank text among `keys`. Pure.
pub fn pick(row: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|k| row.get(*k).and_then(Value::as_str))
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Whether a row is live: not `is_active = false`, not `is_deleted = true`.
/// Pure.
pub fn live(row: &Map<String, Value>) -> bool {
    row.get("is_active").and_then(Value::as_bool) != Some(false)
        && row.get("is_deleted").and_then(Value::as_bool) != Some(true)
}

/// An asset from a whole row. Pure.
pub fn asset_from(
    kind: &'static str,
    reference: String,
    parent: Option<String>,
    row: &Map<String, Value>,
) -> Asset {
    Asset {
        kind,
        reference,
        parent,
        name_en: pick(row, &NAME_EN),
        name_ar: pick(row, &NAME_AR),
        description_en: pick(row, &DESC_EN),
        description_ar: pick(row, &DESC_AR),
    }
}

/// The text the search vector is built from, Arabic normalised. Pure.
pub fn search_text(asset: &Asset) -> String {
    let ar = |s: &Option<String>| {
        s.as_deref()
            .map(attome_core::match_normalize::normalize_ar)
            .unwrap_or_default()
    };
    [
        asset.reference.clone(),
        asset.name_en.clone().unwrap_or_default(),
        ar(&asset.name_ar),
        asset.description_en.clone().unwrap_or_default(),
        ar(&asset.description_ar),
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join(" ")
}

/// Every live row of `table` (skipped when the table does not exist).
async fn rows(state: &EngineState, table: &str) -> Result<Vec<Map<String, Value>>, AppError> {
    let exists: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
        .bind(table)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    if exists.is_none() {
        return Ok(Vec::new());
    }
    let found: Vec<Value> = sqlx::query_scalar(&format!(
        "SELECT row_to_json(t) FROM {} t",
        quote_ident(table)
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(found
        .into_iter()
        .filter_map(|v| match v {
            Value::Object(map) if live(&map) => Some(map),
            _ => None,
        })
        .collect())
}

fn id_of(row: &Map<String, Value>) -> Option<String> {
    row.get("id").and_then(Value::as_str).map(str::to_owned)
}

/// Every asset of every kind, read from the metadata.
pub async fn collect(state: &EngineState) -> Result<Vec<Asset>, AppError> {
    let mut assets = Vec::new();
    let entities = rows(state, "entity_info").await?;
    let mut entity_names: BTreeMap<String, String> = BTreeMap::new();
    for row in &entities {
        let (Some(id), Some(name)) = (id_of(row), row.get("logicalname").and_then(Value::as_str))
        else {
            continue;
        };
        entity_names.insert(id, name.to_owned());
        assets.push(asset_from("entity", name.to_owned(), None, row));
    }
    for row in rows(state, "attribute_info").await? {
        let Some(entity) = row
            .get("entity_ref")
            .and_then(Value::as_str)
            .and_then(|e| entity_names.get(e))
        else {
            continue;
        };
        let Some(field) = row.get("logicalname").and_then(Value::as_str) else {
            continue;
        };
        let reference = format!("{entity}.{field}");
        let has_choices = row
            .get("options")
            .and_then(|o| o.get("choices"))
            .and_then(Value::as_array)
            .is_some_and(|c| !c.is_empty());
        if has_choices {
            assets.push(asset_from(
                "option_set",
                reference.clone(),
                Some(entity.clone()),
                &row,
            ));
        }
        assets.push(asset_from(
            "attribute",
            reference,
            Some(entity.clone()),
            &row,
        ));
    }
    for row in rows(state, "sql_query").await? {
        let Some(id) = id_of(&row) else { continue };
        let kind = if row.get("is_report").and_then(Value::as_bool) == Some(true) {
            "report"
        } else {
            "saved_query"
        };
        assets.push(asset_from(kind, id, None, &row));
    }
    for (kind, table) in [
        ("view", "view"),
        ("report", "attome_report"),
        ("dashboard", "attome_dashboard"),
        ("metric", "dashboard_metric_definition"),
        ("flow", "workflow_definition"),
    ] {
        for row in rows(state, table).await? {
            let Some(id) = id_of(&row) else { continue };
            assets.push(asset_from(kind, id, None, &row));
        }
    }
    for action in attome_ai::actions::all() {
        assets.push(Asset {
            kind: "agent_tool",
            reference: action.id.0.to_owned(),
            parent: None,
            name_en: Some(action.id.0.to_owned()),
            name_ar: None,
            description_en: Some(action.description.to_owned()),
            description_ar: None,
        });
    }
    // One row per (kind, ref): the first wins.
    let mut seen = std::collections::BTreeSet::new();
    assets.retain(|a| seen.insert((a.kind, a.reference.clone())));
    Ok(assets)
}

/// Rebuilds the index: upserts every asset and removes the ones gone.
pub async fn rebuild_assets(state: &EngineState) -> Result<RebuildCounts, AppError> {
    let assets = collect(state).await?;
    let col = |f: fn(&Asset) -> Option<String>| assets.iter().map(f).collect::<Vec<_>>();
    let kinds: Vec<String> = assets.iter().map(|a| a.kind.to_owned()).collect();
    let refs: Vec<String> = assets.iter().map(|a| a.reference.clone()).collect();
    let parents = col(|a| a.parent.clone());
    let names_en = col(|a| a.name_en.clone());
    let names_ar = col(|a| a.name_ar.clone());
    let descs_en = col(|a| a.description_en.clone());
    let descs_ar = col(|a| a.description_ar.clone());
    let search: Vec<String> = assets.iter().map(search_text).collect();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO catalog_asset (id, kind, ref, parent_ref, name_en, name_ar, description_en, \
                description_ar, description_status, search, updated_at) \
         SELECT uuidv7(), u.kind, u.ref, u.parent, u.name_en, u.name_ar, u.desc_en, u.desc_ar, \
                CASE WHEN COALESCE(u.desc_en, u.desc_ar) IS NULL THEN 'missing' ELSE 'draft' END, \
                to_tsvector('simple', u.search), now() \
           FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], \
                       $7::text[], $8::text[]) \
                AS u(kind, ref, parent, name_en, name_ar, desc_en, desc_ar, search) \
         ON CONFLICT (kind, ref) DO UPDATE SET \
                parent_ref = EXCLUDED.parent_ref, \
                name_en = EXCLUDED.name_en, \
                name_ar = EXCLUDED.name_ar, \
                description_en = CASE WHEN catalog_asset.description_status = 'missing' \
                                      THEN EXCLUDED.description_en ELSE catalog_asset.description_en END, \
                description_ar = CASE WHEN catalog_asset.description_status = 'missing' \
                                      THEN EXCLUDED.description_ar ELSE catalog_asset.description_ar END, \
                description_status = CASE WHEN catalog_asset.description_status = 'missing' \
                                          THEN EXCLUDED.description_status \
                                          ELSE catalog_asset.description_status END, \
                search = EXCLUDED.search, \
                updated_at = now()",
    )
    .bind(&kinds)
    .bind(&refs)
    .bind(&parents)
    .bind(&names_en)
    .bind(&names_ar)
    .bind(&descs_en)
    .bind(&descs_ar)
    .bind(&search)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let removed = sqlx::query(
        "DELETE FROM catalog_asset c \
          WHERE NOT EXISTS (SELECT 1 FROM unnest($1::text[], $2::text[]) AS u(kind, ref) \
                             WHERE u.kind = c.kind AND u.ref = c.ref)",
    )
    .bind(&kinds)
    .bind(&refs)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    attome_db::tx::commit(tx).await?;
    Ok(RebuildCounts {
        upserted: assets.len(),
        removed,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn row(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn names_come_from_the_first_set_column() {
        let r = row(
            json!({ "name": "contact", "display_name": "Contact", "display_name_ar": "جهة اتصال", "description": " " }),
        );
        let a = asset_from("entity", "contact".into(), None, &r);
        assert_eq!(a.name_en.as_deref(), Some("Contact"));
        assert_eq!(a.name_ar.as_deref(), Some("جهة اتصال"));
        assert_eq!(a.description_en, None, "a blank description is none");
    }

    #[test]
    fn inactive_and_deleted_rows_are_left_out() {
        assert!(live(&row(json!({ "id": "a" }))));
        assert!(live(&row(
            json!({ "is_active": true, "is_deleted": false })
        )));
        assert!(!live(&row(json!({ "is_active": false }))));
        assert!(!live(&row(json!({ "is_deleted": true }))));
    }

    #[test]
    fn arabic_is_normalised_in_the_search_text() {
        let a = Asset {
            kind: "entity",
            reference: "invoice".into(),
            parent: None,
            name_en: Some("Invoice".into()),
            name_ar: Some("فاتورة".into()),
            description_en: None,
            description_ar: Some("إصدار الفواتير".into()),
        };
        let text = search_text(&a);
        assert!(text.starts_with("invoice Invoice"));
        assert!(!text.contains('إ'), "alef forms are folded: {text}");
    }
}
