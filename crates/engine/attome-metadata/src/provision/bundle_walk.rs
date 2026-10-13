//! Test-fixture walker for a platform bundle's static metadata.
//!
//! D-478 moved platform-owned entity/attribute/query/view provisioning out
//! of imperative `*_seed.rs` code and into `platform-bundles/*.json`,
//! applied at boot by `attome_server::bundle::apply_platform_bundle`. That
//! function needs a full `EngineState` (license, registry, pub/sub) and lives
//! in `attome-server`, which every engine crate sits *below* — so an engine's
//! own DB-backed tests, which historically called `seed(db)` against a bare
//! `DbPool`, have no way to reach the real apply path without a dependency
//! cycle.
//!
//! [`seed_bundle_for_tests`] is the shared answer: it walks a bundle's
//! `entities` / `attribute_patches` / `queries` / `views` arrays and drives the exact same
//! `ensure_entity` / `ensure_attribute` / `ensure_default_query` /
//! `ensure_secondary_view` primitives the old imperative seeds called, so
//! the JSON file stays the single source of truth for content and the test
//! fixture cannot drift from what boot provisions. It deliberately covers
//! only what a bare-pool fixture can do — no privileges, sidebar, state
//! models, roles or record sets; those need the real apply path.
//!
//! Two entity passes: every entity is created first so a same-bundle
//! forward reference or self-reference (`lookup_entity` naming an entity
//! declared later in the same file) resolves; a `lookup_entity` naming an
//! entity outside the bundle is resolved by logicalname against the live
//! `entity_info`, which the caller must therefore have seeded
//! first (typically via `attome_security::seed::seed_for_tests`).
//!
//! Earlier per-crate copies of this walk (`attome_project::seed::
//! seed_for_tests`, `attome_service::seed::seed_for_tests`, `attome_dashboard::
//! seed::seed_for_tests`, `attome_security::seed::seed_for_tests`) predate
//! this helper and still carry their own; new conversions use this one.

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

use super::{ensure_attribute, ensure_default_query, ensure_entity, ensure_secondary_view};

async fn entity_id_by_logicalname(db: &DbPool, logicalname: &str) -> Result<Uuid, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| {
        AppError::internal(format!(
            "bundle lookup target '{logicalname}' is not a live entity; seed its bundle first"
        ))
    })
}

/// Provisions the static metadata declared in `bundle_json` (the raw
/// `include_str!`'d content of one `platform-bundles/*.json` file) through
/// the ordinary provisioning primitives. Idempotent — safe to call on every
/// test fixture setup. `label` names the bundle in error messages only.
pub async fn seed_bundle_for_tests(
    db: &DbPool,
    label: &str,
    bundle_json: &str,
) -> Result<(), AppError> {
    let bundle: serde_json::Value = serde_json::from_str(bundle_json)
        .map_err(|e| AppError::internal(format!("platform-bundles/{label}.json: {e}")))?;
    let empty = Vec::new();
    let entities = match bundle.get("entities") {
        None => &empty,
        Some(v) => v.as_array().ok_or_else(|| {
            AppError::internal(format!(
                "platform-bundles/{label}.json: \"entities\" is not an array"
            ))
        })?,
    };

    let mut entity_ids = std::collections::HashMap::new();
    for entity in entities {
        let logicalname = entity["logicalname"].as_str().unwrap_or_default();
        let id = ensure_entity(
            db,
            logicalname,
            entity["display_name"].as_str().unwrap_or_default(),
            entity["primary_name_attribute"].as_str(),
            entity["is_append_only"].as_bool().unwrap_or(false),
        )
        .await?;
        entity_ids.insert(logicalname.to_string(), id);
    }

    for entity in entities {
        let entity_id = entity_ids[entity["logicalname"].as_str().unwrap_or_default()];
        let Some(attributes) = entity["attributes"].as_array() else {
            continue;
        };
        for attr in attributes {
            let lookup_entity_ref = match attr["lookup_entity"].as_str() {
                Some(target) if entity_ids.contains_key(target) => Some(entity_ids[target]),
                Some(target) => Some(entity_id_by_logicalname(db, target).await?),
                None => None,
            };
            ensure_attribute(
                db,
                entity_id,
                attr["logicalname"].as_str().unwrap_or_default(),
                attr["display_name"].as_str().unwrap_or_default(),
                attr["field_type"].as_str().unwrap_or_default(),
                attr["is_required"].as_bool().unwrap_or(false),
                attr["is_sensitive"].as_bool().unwrap_or(false),
                attr["is_sortable"].as_bool().unwrap_or(false),
                attr["is_filterable"].as_bool().unwrap_or(false),
                lookup_entity_ref,
                attr.get("options").cloned(),
            )
            .await?;
        }
    }

    // `attribute_patches`: one attribute onto an entity another bundle owns
    // (e.g. attome-grc's `risk_ref` on `project_issue`). The target entity
    // must already be live, the same precondition as an outside lookup.
    for patch in bundle["attribute_patches"].as_array().into_iter().flatten() {
        let target = patch["entity"].as_str().unwrap_or_default();
        let entity_id = match entity_ids.get(target) {
            Some(&id) => id,
            None => entity_id_by_logicalname(db, target).await?,
        };
        let attr = &patch["attribute"];
        let lookup_entity_ref = match attr["lookup_entity"].as_str() {
            Some(t) if entity_ids.contains_key(t) => Some(entity_ids[t]),
            Some(t) => Some(entity_id_by_logicalname(db, t).await?),
            None => None,
        };
        ensure_attribute(
            db,
            entity_id,
            attr["logicalname"].as_str().unwrap_or_default(),
            attr["display_name"].as_str().unwrap_or_default(),
            attr["field_type"].as_str().unwrap_or_default(),
            attr["is_required"].as_bool().unwrap_or(false),
            attr["is_sensitive"].as_bool().unwrap_or(false),
            attr["is_sortable"].as_bool().unwrap_or(false),
            attr["is_filterable"].as_bool().unwrap_or(false),
            lookup_entity_ref,
            attr.get("options").cloned(),
        )
        .await?;
    }

    let queries = bundle["queries"].as_array().cloned().unwrap_or_default();
    let views = bundle["views"].as_array().cloned().unwrap_or_default();
    let sql_for = |entity: &str, name: &str| -> Option<String> {
        queries
            .iter()
            .find(|q| {
                q["entity"].as_str().unwrap_or_default() == entity
                    && q["name"].as_str().unwrap_or_default() == name
            })
            .and_then(|q| q["sql"].as_str())
            .map(str::to_owned)
    };

    // Default views first: `ensure_default_query` is what mints the
    // entity's default `view`, and `ensure_secondary_view` refuses
    // to become the default itself.
    for v in views
        .iter()
        .filter(|v| v["is_default"].as_bool().unwrap_or(false))
    {
        let entity_name = v["entity"].as_str().unwrap_or_default();
        let Some(&entity_id) = entity_ids.get(entity_name) else {
            continue;
        };
        let Some(sql) = sql_for(entity_name, v["query"]["name"].as_str().unwrap_or_default())
        else {
            continue;
        };
        ensure_default_query(db, entity_id, v["name"].as_str().unwrap_or_default(), &sql).await?;
    }
    for v in views
        .iter()
        .filter(|v| !v["is_default"].as_bool().unwrap_or(false))
    {
        let entity_name = v["entity"].as_str().unwrap_or_default();
        let Some(&entity_id) = entity_ids.get(entity_name) else {
            continue;
        };
        let Some(sql) = sql_for(entity_name, v["query"]["name"].as_str().unwrap_or_default())
        else {
            continue;
        };
        ensure_secondary_view(
            db,
            entity_id,
            entity_name,
            v["name"].as_str().unwrap_or_default(),
            &sql,
        )
        .await?;
    }
    Ok(())
}
