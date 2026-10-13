//! REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478) — this file used to
//! provision every `project_*` entity imperatively (`ensure_entity`/
//! `ensure_attribute`/`ensure_entity_list_views`, one call per field, ~2,100
//! lines). That content now lives in `platform-bundles/attome-project.json`,
//! applied at boot by `attome-api/src/system.rs` via `bundle::
//! apply_platform_bundle` — proven a pure no-op against the old imperative
//! seed's live output by `attome-api/tests/platform_bundle_apply.rs`
//! (`project_platform_bundle_is_a_pure_noop_against_the_old_seed`)
//! before the swap-over.
//!
//! What's left here is the one piece of the old `seed_body` that is NOT
//! static metadata: `crate::utilization`'s code-seeded report query needs
//! `resource_allocation`'s live entity id, which the old code held as an
//! in-memory `Uuid` returned from `ensure_entity` — a value the bundle path
//! has no equivalent for, since bundle apply resolves everything by
//! logicalname internally and returns nothing to the caller. [`seed_utilization`]
//! re-resolves that id by logicalname instead (the same lookup the old code
//! used for entities it didn't create in this file, e.g.
//! `user_account`), so `crate::utilization::seed`'s call shape is
//! unchanged. Called from `system.rs` right after the platform bundle
//! applies — see that call site for why the ordering matters.
//!
//! `seed_utilization` also stays for a second reason, found when D-478's
//! second pass tried to move it: the KPI's SQL carries a scalar subquery
//! (`(SELECT COUNT(*) FROM user_account ...)`), and a bundled query
//! goes through `attome_metadata::provision::reject_unsafe_default_query_sql`'s
//! single-`FROM`-clause rule, which structurally cannot admit it — the same
//! reason `attome-dashboard`'s "Team Members Breakdown" stayed out of its
//! bundle. The code-seeded path is the sanctioned home for such a query.
//!
//! The built-in `project_work_item` state model that used to be
//! reconciled here by `seed_state_models` (REVIEW-2026-09-02 finding #7)
//! is now `platform-bundles/attome-project.json`'s `state_models[]` entry,
//! applied through the same `attome_state::reconcile::reconcile_state_model`
//! (D-478 second pass; proven a pure no-op against the old call by
//! `platform_bundle_apply.rs` first).
use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

async fn entity_id_by_logicalname(db: &DbPool, logicalname: &str) -> Result<Uuid, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Resolves `resource_allocation`'s live entity id (created by the
/// platform bundle `system.rs` applies right before calling this) and hands
/// it to `crate::utilization::seed`, which needs it to code-seed its report
/// query. See this module's doc comment for why this one call survives as
/// code instead of moving into the bundle.
pub async fn seed_utilization(db: &DbPool) -> Result<(), AppError> {
    let resource_allocation_id = entity_id_by_logicalname(db, "resource_allocation").await?;
    crate::utilization::seed(db, resource_allocation_id).await
}

/// Test-only equivalent of the old `seed(db)` — this crate's own
/// `tests/{capacity,portfolio_program,rollup,seed}.rs` call it directly
/// against a bare `DbPool`, without the full `EngineState`/license ceremony
/// `bundle::apply_platform_bundle` needs (that function lives in
/// `attome-api`, which would be a heavier dev-dependency than these
/// lightweight tests currently carry, and a different config shape than
/// their existing `minimal_config()` helpers build). This walks
/// `platform-bundles/attome-project.json`'s `entities` array directly via
/// `attome_metadata::provision::{ensure_entity, ensure_attribute}` — the exact
/// primitives the old imperative seed called, just driven by the bundle's
/// JSON instead of hand-written Rust, so the bundle stays the single source
/// of truth for content. Deliberately skips `queries`/`views`: none of the
/// four test files above assert on `view`/`sql_query`
/// rows, only on entity/attribute existence and hand-inserted record data.
///
/// Two passes, not one: every entity is created first (so every lookup
/// target — including a same-bundle forward reference and the self-
/// referencing `project_work_item.parent_work_item_id`) already exists
/// in `entity_info` by the time attributes are added and lookups
/// are resolved by logicalname.
pub async fn seed_for_tests(db: &DbPool) -> Result<(), AppError> {
    // Skipped when this bundle's content is stamped and its entities, attribute
    // rows and tables are all still live (see `attome_metadata::provision::fixture_gate`).
    attome_metadata::provision::run_bundle_fixture(
        db,
        "tests:attome-project",
        include_str!("../../../../platform-bundles/attome-project.json"),
        || seed_for_tests_walk(db),
    )
    .await
}

async fn seed_for_tests_walk(db: &DbPool) -> Result<(), AppError> {
    let bundle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../platform-bundles/attome-project.json"
    ))
    .map_err(|e| AppError::internal(format!("platform-bundles/attome-project.json: {e}")))?;
    let entities = bundle["entities"].as_array().ok_or_else(|| {
        AppError::internal("platform-bundles/attome-project.json: \"entities\" is not an array")
    })?;

    let mut entity_ids = std::collections::HashMap::new();
    for entity in entities {
        let logicalname = entity["logicalname"].as_str().unwrap_or_default();
        let display_name = entity["display_name"].as_str().unwrap_or_default();
        let primary_name_attribute = entity["primary_name_attribute"].as_str();
        let is_append_only = entity["is_append_only"].as_bool().unwrap_or(false);
        let id = attome_metadata::provision::ensure_entity(
            db,
            logicalname,
            display_name,
            primary_name_attribute,
            is_append_only,
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
            let field_type = attr["field_type"].as_str().unwrap_or_default();
            let lookup_entity_ref = match attr["lookup_entity"].as_str() {
                Some(target) if entity_ids.contains_key(target) => Some(entity_ids[target]),
                Some(target) => Some(entity_id_by_logicalname(db, target).await?),
                None => None,
            };
            attome_metadata::provision::ensure_attribute(
                db,
                entity_id,
                attr["logicalname"].as_str().unwrap_or_default(),
                attr["display_name"].as_str().unwrap_or_default(),
                field_type,
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
    Ok(())
}
