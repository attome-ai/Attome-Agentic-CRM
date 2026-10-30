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

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_core::quote_ident;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

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

// ── L4-T4: search, the asset page, descriptions and access ─────────────────

/// What a caller may see of the index (L4-T3's rule over every asset): an
/// entity they may read, an attribute or option set of such an entity
/// unless it is sensitive without their field grant, and every other kind
/// (views, queries, reports, dashboards, metrics, flows, agent tools) to any
/// holder of `metadata.read`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetScope {
    /// `None` for an administrator: every asset.
    pub entities: Option<Vec<String>>,
    /// `entity.field` of each sensitive attribute the caller holds no grant for.
    pub hidden_attributes: Vec<String>,
}

/// The scope of `ctx`.
pub fn asset_scope(state: &EngineState, ctx: &SecurityContext) -> AssetScope {
    if ctx.is_admin {
        return AssetScope::default();
    }
    let registry = state.entities.load();
    let mut entities = Vec::new();
    let mut hidden_attributes = Vec::new();
    for meta in registry.iter() {
        if ctx.require(&meta.logicalname, "read").is_err() {
            continue;
        }
        for a in &meta.attrs {
            if a.is_sensitive && !ctx.has_field_read_grant(&meta.logicalname, &a.logicalname) {
                hidden_attributes.push(format!("{}.{}", meta.logicalname, a.logicalname));
            }
        }
        entities.push(meta.logicalname.clone());
    }
    AssetScope {
        entities: Some(entities),
        hidden_attributes,
    }
}

/// The visibility predicate over `catalog_asset a`, binding `$1` (the
/// readable entities, or NULL for all) and `$2` (the hidden attributes).
const VISIBLE: &str = "($1::text[] IS NULL \
     OR (a.kind = 'entity' AND a.ref = ANY($1)) \
     OR (a.kind IN ('attribute', 'option_set') AND a.parent_ref = ANY($1) \
         AND NOT (a.ref = ANY($2))) \
     OR a.kind NOT IN ('entity', 'attribute', 'option_set'))";

const ASSET_COLUMNS: &str = "a.id, a.kind, a.ref AS asset_ref, a.parent_ref, a.name_en, a.name_ar, \
     a.description_en, a.description_ar, a.description_status, a.domain_ref, a.label, \
     a.row_version, a.updated_at";

/// One asset as the catalogue lists it.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct CatalogAssetSummary {
    pub id: Uuid,
    /// `entity`, `attribute`, `option_set`, `view`, `saved_query`, `report`,
    /// `dashboard`, `metric`, `flow` or `agent_tool`.
    pub kind: String,
    /// The asset's own reference: a logical name, `entity.field` or an id.
    #[serde(rename = "ref")]
    pub asset_ref: String,
    pub parent_ref: Option<String>,
    pub name_en: Option<String>,
    pub name_ar: Option<String>,
    pub description_en: Option<String>,
    pub description_ar: Option<String>,
    /// `missing`, `draft` (proposed, by a person or an agent) or `reviewed`
    /// (approved by a builder).
    pub description_status: String,
    pub domain_ref: Option<Uuid>,
    pub label: Option<String>,
    pub row_version: i64,
    pub updated_at: DateTime<Utc>,
}

/// One facet value and its count.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct CatalogFacet {
    pub value: String,
    pub count: i64,
}

/// Counts by kind, domain and label over the visible assets the query matches.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct CatalogFacets {
    pub kind: Vec<CatalogFacet>,
    pub domain: Vec<CatalogFacet>,
    pub label: Vec<CatalogFacet>,
}

/// What a catalogue search narrows to.
#[derive(Debug, Clone, Default)]
pub struct AssetFilter {
    pub q: Option<String>,
    pub kind: Option<String>,
    pub domain: Option<Uuid>,
    pub label: Option<String>,
}

fn normalized_query(q: Option<&str>) -> Option<String> {
    q.map(str::trim)
        .filter(|q| !q.is_empty())
        .map(attome_core::match_normalize::normalize_ar)
}

/// A page of the visible assets `filter` selects, best match first, their
/// total and the facet counts (over the visible assets the words match,
/// before the kind, domain and label filters, so each facet shows what
/// choosing it would give).
pub async fn search_assets(
    state: &EngineState,
    scope: &AssetScope,
    filter: &AssetFilter,
    page_size: i64,
    offset: i64,
) -> Result<(Vec<CatalogAssetSummary>, i64, CatalogFacets), AppError> {
    let db = &state.base.db;
    let q = normalized_query(filter.q.as_deref());
    let matched =
        format!("{VISIBLE} AND ($3::text IS NULL OR a.search @@ plainto_tsquery('simple', $3))");
    let selected = format!(
        "{matched} AND ($4::text IS NULL OR a.kind = $4) \
         AND ($5::uuid IS NULL OR a.domain_ref = $5) \
         AND ($6::text IS NULL OR a.label = $6)"
    );
    let items: Vec<CatalogAssetSummary> = sqlx::query_as(&format!(
        "SELECT {ASSET_COLUMNS} FROM catalog_asset a WHERE {selected} \
          ORDER BY ts_rank(a.search, plainto_tsquery('simple', COALESCE($3, ''))) DESC, \
                   a.kind, a.ref \
          LIMIT $7 OFFSET $8"
    ))
    .bind(scope.entities.as_deref())
    .bind(&scope.hidden_attributes)
    .bind(q.as_deref())
    .bind(filter.kind.as_deref())
    .bind(filter.domain)
    .bind(filter.label.as_deref())
    .bind(page_size)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM catalog_asset a WHERE {selected}"
    ))
    .bind(scope.entities.as_deref())
    .bind(&scope.hidden_attributes)
    .bind(q.as_deref())
    .bind(filter.kind.as_deref())
    .bind(filter.domain)
    .bind(filter.label.as_deref())
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let mut facets = CatalogFacets::default();
    for (column, out) in [
        ("a.kind", &mut facets.kind),
        ("a.domain_ref::text", &mut facets.domain),
        ("a.label", &mut facets.label),
    ] {
        *out = sqlx::query_as(&format!(
            "SELECT {column} AS value, count(*) AS count FROM catalog_asset a \
              WHERE {matched} AND {column} IS NOT NULL \
              GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 50"
        ))
        .bind(scope.entities.as_deref())
        .bind(&scope.hidden_attributes)
        .bind(q.as_deref())
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    }
    Ok((items, total, facets))
}

/// The asset `id`, when `scope` sees it.
pub async fn visible_asset(
    state: &EngineState,
    scope: &AssetScope,
    id: Uuid,
) -> Result<CatalogAssetSummary, AppError> {
    sqlx::query_as(&format!(
        "SELECT {ASSET_COLUMNS} FROM catalog_asset a WHERE a.id = $3 AND {VISIBLE}"
    ))
    .bind(scope.entities.as_deref())
    .bind(&scope.hidden_attributes)
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Everything known about one asset, each fact from the feature that owns
/// it; a fact whose feature this deployment lacks (its table is absent) is
/// `null`, not an error.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CatalogAssetPage {
    pub asset: CatalogAssetSummary,
    /// The data domain (M15): id, name, description, steward.
    #[schema(value_type = Option<Object>)]
    pub domain: Option<Value>,
    pub label: Option<String>,
    /// Glossary terms of the asset's entity.
    #[schema(value_type = Option<Vec<Object>>)]
    pub terms: Option<Vec<Value>>,
    /// The latest quality score per dimension of the asset's entity.
    #[schema(value_type = Option<Vec<Object>>)]
    pub quality: Option<Vec<Value>>,
    /// The latest completed profile of the entity (an attribute's own
    /// column only, for an attribute).
    #[schema(value_type = Option<Object>)]
    pub profile: Option<Value>,
    /// What reads the entity (or the attribute): queries, flows, dashboards, rules.
    #[schema(value_type = Option<Vec<Object>>)]
    pub lineage: Option<Vec<Value>>,
    /// The entity's nightly usage numbers.
    #[schema(value_type = Option<Object>)]
    pub usage: Option<Value>,
    /// Its certification, when certified.
    #[schema(value_type = Option<Object>)]
    pub certification: Option<Value>,
    /// The entity's latest metadata changes.
    #[schema(value_type = Option<Vec<Object>>)]
    pub history: Option<Vec<Value>>,
}

async fn table_exists(db: &attome_db::DbPool, table: &str) -> Result<bool, AppError> {
    let found: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
        .bind(table)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    Ok(found.is_some())
}

/// One JSON value from `sql` binding `arg`, or `None` when `table` is absent.
async fn fact(
    db: &attome_db::DbPool,
    table: &str,
    sql: &str,
    args: &[&str],
) -> Result<Option<Value>, AppError> {
    if !table_exists(db, table).await? {
        return Ok(None);
    }
    let mut query = sqlx::query_scalar::<_, Option<Value>>(sql);
    for arg in args {
        query = query.bind(*arg);
    }
    let found = query.fetch_optional(db).await.map_err(AppError::internal)?;
    Ok(Some(found.flatten().unwrap_or(Value::Null)))
}

fn as_list(value: Option<Value>) -> Option<Vec<Value>> {
    value.map(|v| match v {
        Value::Array(items) => items,
        _ => Vec::new(),
    })
}

/// The entity an asset belongs to, and its attribute when it is one.
fn asset_entity(asset: &CatalogAssetSummary) -> (Option<String>, Option<String>) {
    match asset.kind.as_str() {
        "entity" => (Some(asset.asset_ref.clone()), None),
        "attribute" | "option_set" => {
            let field = asset.asset_ref.split_once('.').map(|(_, f)| f.to_owned());
            (asset.parent_ref.clone(), field)
        }
        _ => (None, None),
    }
}

/// The asset page for `id` as `scope` sees it.
pub async fn asset_page(
    state: &EngineState,
    scope: &AssetScope,
    id: Uuid,
) -> Result<CatalogAssetPage, AppError> {
    let asset = visible_asset(state, scope, id).await?;
    let db = &state.base.db;
    let (entity, field) = asset_entity(&asset);
    let domain_id = match asset.domain_ref {
        Some(d) => Some(d),
        None => match &entity {
            Some(e) => sqlx::query_scalar::<_, Option<Uuid>>(
                "SELECT domain_ref FROM entity_info WHERE logicalname = $1",
            )
            .bind(e)
            .fetch_optional(&state.base.db_migrator)
            .await
            .map_err(AppError::internal)?
            .flatten(),
            None => None,
        },
    };
    let domain = match domain_id {
        Some(d) => fact(
            db,
            "data_domain",
            "SELECT row_to_json(d) FROM (SELECT id, name, description, steward_ref FROM data_domain \
              WHERE id = $1::uuid AND is_deleted = false) d",
            &[&d.to_string()],
        )
        .await?
        .filter(|v| !v.is_null()),
        None => None,
    };
    let (mut terms, mut quality, mut profile, mut lineage, mut usage, mut history) =
        (None, None, None, None, None, None);
    if let Some(entity) = &entity {
        terms = as_list(
            fact(
                db,
                "glossary_term",
                "SELECT COALESCE(json_agg(t), '[]'::json) FROM (SELECT id, term, definition, status \
                   FROM glossary_term WHERE primary_entity_logicalname = $1 \
                    AND is_active IS NOT FALSE ORDER BY term LIMIT 50) t",
                &[entity],
            )
            .await?,
        );
        quality = as_list(
            fact(
                db,
                "quality_score",
                "SELECT COALESCE(json_agg(q), '[]'::json) FROM (SELECT DISTINCT ON (dimension) \
                        dimension, score, period, computed_at FROM quality_score \
                  WHERE entity_logicalname = $1 ORDER BY dimension, computed_at DESC) q",
                &[entity],
            )
            .await?,
        );
        profile = fact(
            db,
            "data_profile",
            "SELECT row_to_json(p) FROM (SELECT row_count, completed_at, fields FROM data_profile \
              WHERE entity_logicalname = $1 AND status = 'completed' AND is_deleted = false \
              ORDER BY completed_at DESC NULLS LAST LIMIT 1) p",
            &[entity],
        )
        .await?
        .map(|p| profile_of(p, field.as_deref()));
        usage = fact(
            db,
            "catalog_usage_rollup",
            "SELECT row_to_json(u) FROM (SELECT record_count, last_write_at, search_impressions_30d, \
                    readers, unused, computed_at FROM catalog_usage_rollup \
              WHERE entity_logicalname = $1) u",
            &[entity],
        )
        .await?;
        history = as_list(
            fact(
                db,
                "metadata_change_log",
                "SELECT COALESCE(json_agg(h), '[]'::json) FROM (SELECT change_kind, created_at \
                   FROM metadata_change_log WHERE logicalname = $1 \
                  ORDER BY created_at DESC LIMIT 20) h",
                &[entity],
            )
            .await?,
        );
        let references = attome_core::references_to_entity(db, entity, 200).await?;
        lineage = Some(
            references
                .into_iter()
                .filter(|r| field.as_deref().is_none_or(|f| r.to_attribute == f))
                .filter(|r| {
                    r.to_attribute.is_empty()
                        || !scope
                            .hidden_attributes
                            .contains(&format!("{entity}.{}", r.to_attribute))
                })
                .map(|r| {
                    serde_json::json!({
                        "from_kind": r.from_kind,
                        "from_ref": r.from_ref,
                        "from_label": r.from_label,
                        "to_attribute": (!r.to_attribute.is_empty()).then_some(r.to_attribute),
                        "created_at": r.created_at,
                    })
                })
                .collect(),
        );
    }
    let certification = fact(
        db,
        "governance_certification",
        "SELECT row_to_json(c) FROM (SELECT status, certified_by, certified_at \
           FROM governance_certification WHERE asset_kind = $1 AND asset_ref = $2) c",
        &[&asset.kind, &asset.asset_ref],
    )
    .await?
    .filter(|v| !v.is_null());
    Ok(CatalogAssetPage {
        label: asset.label.clone(),
        asset,
        domain,
        terms,
        quality,
        profile: profile.filter(|v| !v.is_null()),
        lineage,
        usage: usage.filter(|v| !v.is_null()),
        certification,
        history,
    })
}

/// A profile narrowed to `field`'s own entry when there is one. Pure.
fn profile_of(profile: Value, field: Option<&str>) -> Value {
    let Some(field) = field else {
        return profile;
    };
    let mut profile = profile;
    if let Some(fields) = profile.get_mut("fields").and_then(Value::as_array_mut) {
        fields.retain(|f| {
            f.get("field")
                .or_else(|| f.get("name"))
                .and_then(Value::as_str)
                == Some(field)
        });
    }
    profile
}

/// A description edit.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CatalogDescriptionBody {
    #[serde(default)]
    pub description_en: Option<String>,
    #[serde(default)]
    pub description_ar: Option<String>,
}

const MAX_DESCRIPTION_CHARS: usize = 4_000;

fn clean_description(text: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(text) = text.map(str::trim) else {
        return Ok(None);
    };
    if text.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(AppError::Validation(format!(
            "a description is at most {MAX_DESCRIPTION_CHARS} characters"
        )));
    }
    Ok(Some(text.to_owned()))
}

/// Proposes a description for a visible asset at `expected` row version: it
/// becomes a `draft` until a builder approves it. Audited as a
/// configuration change.
pub async fn set_description(
    state: &EngineState,
    ctx: &SecurityContext,
    scope: &AssetScope,
    id: Uuid,
    expected: i64,
    body: &CatalogDescriptionBody,
) -> Result<CatalogAssetSummary, AppError> {
    visible_asset(state, scope, id).await?;
    let en = clean_description(body.description_en.as_deref())?;
    let ar = clean_description(body.description_ar.as_deref())?;
    if en.is_none() && ar.is_none() {
        return Err(AppError::Validation(
            "give description_en, description_ar or both".into(),
        ));
    }
    let mut tx = SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "catalog_asset",
            Some(id),
        )
        .comment("catalog description drafted"),
    )
    .await?;
    let updated: Option<CatalogAssetSummary> = sqlx::query_as(&format!(
        "UPDATE catalog_asset a SET description_en = COALESCE($3, a.description_en), \
                description_ar = COALESCE($4, a.description_ar), description_status = 'draft', \
                description_by = $5, description_reviewed_by = NULL, \
                row_version = a.row_version + 1, updated_at = now() \
          WHERE a.id = $1 AND a.row_version = $2 RETURNING {ASSET_COLUMNS}"
    ))
    .bind(id)
    .bind(expected)
    .bind(&en)
    .bind(&ar)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(updated) = updated else {
        return Err(AppError::VersionConflict);
    };
    tx.commit().await?;
    Ok(updated)
}

/// Approves a drafted description at `expected` row version (a builder:
/// the caller is an administrator). Audited as a configuration change.
pub async fn approve_description(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    expected: i64,
) -> Result<CatalogAssetSummary, AppError> {
    ctx.require_admin()?;
    let mut tx = SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "catalog_asset",
            Some(id),
        )
        .comment("catalog description approved"),
    )
    .await?;
    let current: Option<(i64, String)> = sqlx::query_as(
        "SELECT row_version, description_status FROM catalog_asset WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (version, status) = current.ok_or(AppError::NotFound)?;
    if version != expected {
        return Err(AppError::VersionConflict);
    }
    if status != "draft" {
        return Err(AppError::Conflict("only a drafted description is approved"));
    }
    let updated: CatalogAssetSummary = sqlx::query_as(&format!(
        "UPDATE catalog_asset a SET description_status = 'reviewed', description_reviewed_by = $2, \
                row_version = a.row_version + 1, updated_at = now() \
          WHERE a.id = $1 RETURNING {ASSET_COLUMNS}"
    ))
    .bind(id)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok(updated)
}

/// A request for access to an asset.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct CatalogAccessRequest {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub requester_id: Uuid,
    pub reason: String,
    /// `pending`, `granted`, `refused` or `withdrawn`.
    pub status: String,
    /// The role asked for or granted.
    pub role_ref: Option<Uuid>,
    pub decided_by: Option<Uuid>,
    pub decided_at: Option<DateTime<Utc>>,
    /// When the grant waits for a second administrator (D-195).
    pub approval_request_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

const REQUEST_COLUMNS: &str = "id, asset_id, requester_id, reason, status, role_ref, decided_by, \
     decided_at, approval_request_id, created_at";

/// Asks for access.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CatalogAccessRequestBody {
    pub reason: String,
    /// The role that would give the access, when the requester knows it.
    #[serde(default)]
    pub role_id: Option<Uuid>,
}

/// Records `ctx`'s request for access to an asset they can see in the
/// catalogue (a hidden attribute shows by name when the deployment says so,
/// L4-T3). One pending request per person and asset.
pub async fn request_access(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    body: &CatalogAccessRequestBody,
) -> Result<CatalogAccessRequest, AppError> {
    let reason = body.reason.trim();
    if reason.is_empty() || reason.chars().count() > 1_000 {
        return Err(AppError::Validation(
            "give a reason of 1 to 1,000 characters".into(),
        ));
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM catalog_asset WHERE id = $1)")
            .bind(id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM catalog_access_request \
           WHERE asset_id = $1 AND requester_id = $2 AND status = 'pending')",
    )
    .bind(id)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if pending {
        return Err(AppError::Conflict(
            "you already asked for access to this asset",
        ));
    }
    let request: CatalogAccessRequest = sqlx::query_as(&format!(
        "INSERT INTO catalog_access_request (asset_id, requester_id, reason, role_ref) \
         VALUES ($1, $2, $3, $4) RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(id)
    .bind(ctx.user_id)
    .bind(reason)
    .bind(body.role_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "catalog_access_request",
            request.id,
            AuditOperation::Submitted,
            "catalog.access_requested",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(request)
}

/// Whether `ctx` owns `asset` for access decisions: an administrator, or
/// the steward or deputy of the asset's data domain (its entity's, for an
/// entity or attribute asset).
pub async fn owns_asset(
    state: &EngineState,
    ctx: &SecurityContext,
    asset: &CatalogAssetSummary,
) -> Result<bool, AppError> {
    if ctx.is_admin {
        return Ok(true);
    }
    let (entity, _) = asset_entity(asset);
    let domain: Option<Uuid> = match (asset.domain_ref, entity) {
        (Some(d), _) => Some(d),
        (None, Some(e)) => sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT domain_ref FROM entity_info WHERE logicalname = $1",
        )
        .bind(e)
        .fetch_optional(&state.base.db_migrator)
        .await
        .map_err(AppError::internal)?
        .flatten(),
        (None, None) => None,
    };
    let Some(domain) = domain else {
        return Ok(false);
    };
    if !table_exists(&state.base.db, "data_domain").await? {
        return Ok(false);
    }
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM data_domain WHERE id = $1 AND is_deleted = false \
           AND (steward_ref = $2 OR deputy_ref = $2))",
    )
    .bind(domain)
    .bind(ctx.user_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Decides an access request.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CatalogAccessDecisionBody {
    /// `true` grants the role; `false` refuses.
    pub grant: bool,
    /// The role to grant; the one asked for when omitted.
    #[serde(default)]
    pub role_id: Option<Uuid>,
    /// When the granted role ends (Q10).
    #[serde(default)]
    pub valid_until: Option<DateTime<Utc>>,
}

/// Decides a pending request as the asset's owner. A grant goes through
/// `attome_security::admin::grant_role_as`, the admin route's own path:
/// step-up, the grant ceiling and the D-195 approval gate, so a gated grant
/// waits (`approval_request_id`) and nothing is skipped. The request is
/// claimed first, so two decisions cannot both act; a grant that is then
/// refused leaves it pending again.
pub async fn decide_access(
    state: &EngineState,
    caller: attome_auth::step_up::Caller,
    ctx: &SecurityContext,
    request_id: Uuid,
    body: &CatalogAccessDecisionBody,
) -> Result<CatalogAccessRequest, AppError> {
    let request: CatalogAccessRequest = sqlx::query_as(&format!(
        "SELECT {REQUEST_COLUMNS} FROM catalog_access_request WHERE id = $1"
    ))
    .bind(request_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let asset: CatalogAssetSummary = sqlx::query_as(&format!(
        "SELECT {ASSET_COLUMNS} FROM catalog_asset a WHERE a.id = $1"
    ))
    .bind(request.asset_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    if !owns_asset(state, ctx, &asset).await? {
        return Err(AppError::NotFound);
    }
    let role = body.role_id.or(request.role_ref);
    if body.grant && role.is_none() {
        return Err(AppError::Validation(
            "a grant names role_id (the request asked for none)".into(),
        ));
    }
    let claimed: Option<CatalogAccessRequest> = sqlx::query_as(&format!(
        "UPDATE catalog_access_request SET status = $2, decided_by = $3, decided_at = now(), \
                role_ref = COALESCE($4, role_ref), row_version = row_version + 1 \
          WHERE id = $1 AND status = 'pending' RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(request_id)
    .bind(if body.grant { "granted" } else { "refused" })
    .bind(ctx.user_id)
    .bind(role)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(claimed) = claimed else {
        return Err(AppError::Conflict("the request is already decided"));
    };
    if !body.grant {
        attome_audit::write_business_event(
            state,
            "catalog_access_request",
            request_id,
            AuditOperation::Rejected,
            "catalog.access_refused",
            ctx.user_id,
            None,
            None,
            String::new(),
        )
        .await;
        return Ok(claimed);
    }
    let reason = format!("catalog access: {}", request.reason);
    let outcome = attome_security::admin::grant_role_as(
        state,
        caller,
        ctx,
        request.requester_id,
        role.unwrap_or_default(),
        body.valid_until,
        Some(&reason),
    )
    .await;
    match outcome {
        Ok(attome_security::admin::RoleGrantOutcome::Assigned(_)) => Ok(claimed),
        Ok(attome_security::admin::RoleGrantOutcome::Pending(approval)) => {
            sqlx::query_as(&format!(
                "UPDATE catalog_access_request SET approval_request_id = $2 \
              WHERE id = $1 RETURNING {REQUEST_COLUMNS}"
            ))
            .bind(request_id)
            .bind(approval)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)
        }
        Err(error) => {
            // Back to pending: the grant was refused, nothing was given.
            let _ = sqlx::query(
                "UPDATE catalog_access_request SET status = 'pending', decided_by = NULL, \
                        decided_at = NULL WHERE id = $1",
            )
            .bind(request_id)
            .execute(&state.base.db)
            .await
            .inspect_err(
                |e| tracing::warn!(error = %e, "catalog access: could not reopen a request"),
            );
            Err(error)
        }
    }
}

/// One reader of a labelled attribute.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PersonalDataReader {
    /// `query` (a stored query or report), `workflow`, `dashboard` or `rule`.
    pub kind: String,
    #[serde(rename = "ref")]
    pub reader_ref: Uuid,
    pub label: String,
    /// It reads the whole entity, not only this attribute.
    pub whole_entity: bool,
}

/// An attribute labelled personal, financial or health, and what reads it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PersonalDataItem {
    pub entity: String,
    pub attribute: String,
    /// `personal`, `financial` or `health` (A1-T1).
    pub sensitivity: String,
    pub readers: Vec<PersonalDataReader>,
}

/// The attributes labelled personal, financial or health of live entities
/// `scope` may see (`$1` the entities, `$2` the hidden attributes).
const LABELLED: &str = "FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
    WHERE a.sensitivity IN ('personal', 'financial', 'health') \
      AND (a.is_active IS NULL OR a.is_active = true) \
      AND (e.is_active IS NULL OR e.is_active = true) \
      AND ($1::text[] IS NULL OR e.logicalname = ANY($1)) \
      AND NOT ((e.logicalname || '.' || a.logicalname) = ANY($2))";

/// L4-T5: a page of the labelled attributes `scope` may see, by entity and
/// attribute, each with its readers from the metadata references.
pub async fn personal_data_map(
    state: &EngineState,
    scope: &AssetScope,
    page_size: i64,
    offset: i64,
) -> Result<(Vec<PersonalDataItem>, i64), AppError> {
    // The metadata tables are the migrator pool's (`schema.rs`'s convention).
    let meta = &state.base.db_migrator;
    let rows: Vec<(String, String, String)> = sqlx::query_as(&format!(
        "SELECT e.logicalname, a.logicalname, a.sensitivity {LABELLED} \
          ORDER BY e.logicalname, a.logicalname LIMIT $3 OFFSET $4"
    ))
    .bind(scope.entities.as_deref())
    .bind(&scope.hidden_attributes)
    .bind(page_size)
    .bind(offset)
    .fetch_all(meta)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) {LABELLED}"))
        .bind(scope.entities.as_deref())
        .bind(&scope.hidden_attributes)
        .fetch_one(meta)
        .await
        .map_err(AppError::internal)?;
    let entities: Vec<String> = rows
        .iter()
        .map(|(e, _, _)| e.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let references: Vec<(String, String, String, Uuid, String)> = sqlx::query_as(
        "SELECT to_entity, to_attribute, from_kind, from_ref, from_label FROM metadata_reference \
          WHERE to_entity = ANY($1) ORDER BY from_kind, from_label",
    )
    .bind(&entities)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items = rows
        .into_iter()
        .map(|(entity, attribute, sensitivity)| {
            let readers = references
                .iter()
                .filter(|(to_entity, to_attribute, ..)| {
                    *to_entity == entity && (to_attribute.is_empty() || *to_attribute == attribute)
                })
                .map(
                    |(_, to_attribute, kind, reader, label)| PersonalDataReader {
                        kind: kind.clone(),
                        reader_ref: *reader,
                        label: label.clone(),
                        whole_entity: to_attribute.is_empty(),
                    },
                )
                .collect();
            PersonalDataItem {
                entity,
                attribute,
                sensitivity,
                readers,
            }
        })
        .collect();
    Ok((items, total))
}

/// One asset as the export lists it: metadata only, never record values.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct CatalogExportAsset {
    pub kind: String,
    #[serde(rename = "ref")]
    pub asset_ref: String,
    pub parent_ref: Option<String>,
    pub name_en: Option<String>,
    pub name_ar: Option<String>,
    pub description_en: Option<String>,
    pub description_ar: Option<String>,
    pub description_status: String,
    pub domain: Option<String>,
    pub label: Option<String>,
    pub certified: bool,
    pub updated_at: DateTime<Utc>,
}

/// The setting the export answers behind.
pub const EXPORT_SETTING: &str = "catalog.export_enabled";

/// A page of the whole catalogue for a harvester, when the deployment turned
/// the export on (`catalog.export_enabled`); `NotFound` otherwise.
pub async fn export_assets(
    state: &EngineState,
    page_size: i64,
    offset: i64,
) -> Result<(Vec<CatalogExportAsset>, i64), AppError> {
    let on = attome_core::setting_registry()
        .get(EXPORT_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !on {
        return Err(AppError::NotFound);
    }
    let certified = if table_exists(&state.base.db, "governance_certification").await? {
        "EXISTS (SELECT 1 FROM governance_certification c WHERE c.asset_kind = a.kind \
            AND c.asset_ref = a.ref AND c.status = 'certified')"
    } else {
        "false"
    };
    let domain = if table_exists(&state.base.db, "data_domain").await? {
        "(SELECT d.name FROM data_domain d WHERE d.id = a.domain_ref)"
    } else {
        "NULL::text"
    };
    let items: Vec<CatalogExportAsset> = sqlx::query_as(&format!(
        "SELECT a.kind, a.ref AS asset_ref, a.parent_ref, a.name_en, a.name_ar, a.description_en, \
                a.description_ar, a.description_status, {domain} AS domain, a.label, \
                {certified} AS certified, a.updated_at \
           FROM catalog_asset a ORDER BY a.kind, a.ref LIMIT $1 OFFSET $2"
    ))
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM catalog_asset")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok((items, total))
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
