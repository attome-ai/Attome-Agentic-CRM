//! Entity/attribute provisioning for `service_work_request`/`service_ticket`/
//! `service_sla_policy`/`service_offering`/`service_sla_clock`/`service_work_queue`/
//! `service_work_queue_member` (the Phase 8 "Work Intake & Service Management"
//! backlog's storage layer) has moved to `platform-bundles/attome-service.json`
//! — REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478). The imperative
//! `ensure_entity`/`ensure_attribute`/`ensure_entity_list_views` calls this
//! file used to make are gone; `crates/engine/attome-api/src/system.rs` now
//! applies that bundle directly (`bundle::apply_platform_bundle`) instead of
//! calling a `seed()` function here, since `attome-service` (a lower-layer
//! engine, T3-2/D-477) must not gain a dependency on `attome-api` just to
//! call the bundle-apply mechanism — the same reason the old imperative
//! seed lived in this crate but its replacement's call site lives in
//! `system.rs`. Proven a pure no-op against the old seed's output by
//! `attome-api/tests/platform_bundle_apply.rs` before the swap.
//!
//! `analytics_seed::seed` (SLA KPIs) and, in D-478's second pass,
//! `queue_analytics_seed::seed` (queue depth / average wait / claim-to-
//! resolve) are gone too: every `Uuid` they took was only ever "which
//! entity does this report query belong to", which is `QueryDef.entity`
//! along with `is_report`/`required_privilege` in the bundle's `queries[]`. The
//! built-in `service_ticket` lifecycle (M07, REVIEW-2026-09-02
//! finding #7) that `seed_state_models` used to reconcile is the bundle's
//! `state_models[]` entry, applied through the same
//! `attome_state::reconcile::reconcile_state_model`.
//!
//! [`seed_for_tests`] is the test-only equivalent of the old `seed(db)` —
//! this crate's own `tests/{clock,convert,offering,portal,queue,seed,
//! sla_severity,timeline}.rs` call it directly against a bare `DbPool`,
//! without the full `EngineState`/license ceremony `bundle::
//! apply_platform_bundle` needs. Same shape `attome_project::seed::
//! seed_for_tests` already established for its own bundle.
//!
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

/// See this module's doc comment. Two passes, not one — every entity exists
/// in `entity_info` before any attribute's lookup is resolved,
/// including same-bundle forward references and the self-referencing
/// `service_ticket.parent_ticket_id`. Deliberately skips `queries`/`views`: no
/// test in this crate asserts on `view`/`sql_query` rows.
pub async fn seed_for_tests(db: &DbPool) -> Result<(), AppError> {
    // Skipped when this bundle's content is stamped and its entities, attribute
    // rows and tables are all still live (see `attome_metadata::provision::fixture_gate`).
    attome_metadata::provision::run_bundle_fixture(
        db,
        "tests:attome-service",
        include_str!("../../../../platform-bundles/attome-service.json"),
        || seed_for_tests_walk(db),
    )
    .await
}

async fn seed_for_tests_walk(db: &DbPool) -> Result<(), AppError> {
    let bundle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../platform-bundles/attome-service.json"
    ))
    .map_err(|e| AppError::internal(format!("platform-bundles/attome-service.json: {e}")))?;
    let entities = bundle["entities"].as_array().ok_or_else(|| {
        AppError::internal("platform-bundles/attome-service.json: \"entities\" is not an array")
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
