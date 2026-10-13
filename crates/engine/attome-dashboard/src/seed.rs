//! Registers every `attome_dashboard*` entity as a browsable XRM entity —
//! Phases 1-4 (partial) of `document/XRM-Dashboard-Module.md`.
//!
//! REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478): the 8 entities this
//! file used to provision imperatively (dashboard, dashboard_version, page,
//! section, section_breakpoint, widget, variable, parameter) now live in
//! `platform-bundles/attome-dashboard.json`, applied by `attome-api`'s
//! `system.rs` via `bundle::apply_platform_bundle` before this crate's
//! `seed()` runs. Proven a pure no-op against the old imperative code (save
//! `widget_type`'s deliberately-excluded choice list, see below) by
//! `attome-api/tests/platform_bundle_apply.rs`'s
//! `dashboard_platform_bundle_is_a_pure_noop_against_the_old_seed_except_widget_type`.
//!
//! Second pass (D-478): the three sibling seeds this file used to
//! orchestrate after the bundle — `attome_metric::metric::seed` (now
//! `platform-bundles/attome-metric.json`, applied by `system.rs` right before
//! this crate's bundle) and `decision_seed`/`scenario_seed` (their seven
//! entities now live in `platform-bundles/attome-dashboard.json` itself) —
//! are gone. Every `Uuid` they took (`systemuser_id`,
//! `metric_definition_id`, and the ids they threaded between their own
//! entities) was only ever a lookup *target*, which is `AttributeDef.
//! lookup_entity` by logicalname in a bundle. Proven a pure no-op against
//! the old code by `platform_bundle_apply.rs` before the swap.
//!
//! What stays here, and why it could not become static bundle content:
//! [`seed`] re-syncs `dashboard_widget.widget_type`'s choice list from
//! `widget_registry::registry().type_ids()` — a genuinely dynamic source
//! of truth (new widget types register themselves in Rust), not data a
//! static bundle can own. [`entity_id_by_logicalname`] resolves the
//! `user_account`/`organization`/`team` ids
//! `attome-security`'s own bundle provisions for [`seed_for_tests`].
//!
//! `general_seed.rs` — the fourth sibling this file used to orchestrate — is
//! gone (M26 R-05): it raw-`INSERT`ed a built-in "General [System & Team]
//! Overview" dashboard tree, a `general` tag category/item, and 8
//! `sql_query` rows directly
//! against `attome_dashboard`/`dashboard_page`/`dashboard_section`/
//! `dashboard_widget`/`tag_category`/`tag_item`/
//! `sql_query`, bypassing the admin API (guidelines §4 hard
//! constraint) and never writing an `dashboard_version` row for a
//! `lifecycle_status = 'published'` dashboard (`lifecycle.rs`'s invariant) or
//! an `sql_query_version` row for any of its 8 queries (so
//! `run_query_metric`/`execute_stored_query` rejected them outright). 7 of
//! its 8 report queries (all but "Team Members Breakdown", which needs a
//! `JOIN` across `team`/`user_account_mm_team`/
//! `user_account` — structurally incompatible with a platform
//! bundle's query containment check, `attome_metadata::provision::
//! reject_unsafe_default_query_sql`'s single-`FROM`-clause rule; see that
//! function's doc comment) now live in `platform-bundles/attome-dashboard.json`
//! `queries[]`, applied through the same `reconcile_query` path every other
//! bundled query uses — which does write a version row on create/update, so
//! they are immediately executable. Their own inline `ORDER BY` clauses were
//! dropped in the move (D-350: a stored query's caller supplies `order_by`/
//! `order_dir` to `query/execute` instead), not merely to satisfy the
//! containment check. The seeded dashboard/page/section/widget/tag tree
//! itself is not replaced by anything — `bundle/record_sets.rs` keys rows by
//! business key, not id, so a four-level tree of id-based parent references
//! cannot be expressed as bundle content; a real "no dashboards yet" empty
//! state is a separate, later spec (R-10). Existing deployments keep
//! whatever built-in overview dashboard row `general_seed.rs` already wrote;
//! nothing here cleans it up.
use attome_db::DbPool;
use attome_metadata::provision::ensure_attribute;
use attome_types::AppError;
use uuid::Uuid;

/// Resolves an entity another bundle provisioned (`user_account`/
/// `organization`/`team` from `attome-security`'s,
/// `dashboard_metric_definition` from `attome-metric`'s) for
/// [`seed_for_tests`]'s lookup attributes and for the widget_type resync.
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

fn choice(choices: &[&str]) -> serde_json::Value {
    serde_json::json!({ "choices": choices, "multi": false })
}

/// Test-only equivalent of applying `platform-bundles/attome-dashboard.json` —
/// this crate's own `tests/seed.rs` calls it (before `seed(db)`) against a
/// bare `DbPool`, without the full `EngineState`/license ceremony
/// `bundle::apply_platform_bundle` needs (that function lives in
/// `attome-api`, a heavier dev-dependency than this crate's existing
/// lightweight fixtures carry — same reasoning as `attome_project::seed::
/// seed_for_tests`'s own doc comment). Walks the bundle's `entities`/
/// `queries`/`views` arrays directly via `attome_metadata::provision::*` —
/// unlike `attome_project::seed::seed_for_tests` (which skips `queries`/
/// `views` because nothing in that crate's tests asserts on them), this one
/// includes them: `tests/seed.rs`'s `has_view` check needs every
/// `attome_dashboard*` entity's default view to exist. Two entity passes, same
/// reason as every other `seed_for_tests`: every entity exists before any
/// attribute's lookup is resolved by logicalname.
pub async fn seed_for_tests(db: &DbPool) -> Result<(), AppError> {
    // Skipped when this bundle's content is stamped and its entities, attribute
    // rows and tables are all still live (see `attome_metadata::provision::fixture_gate`).
    attome_metadata::provision::run_bundle_fixture(
        db,
        "tests:attome-dashboard",
        include_str!("../../../../platform-bundles/attome-dashboard.json"),
        || seed_for_tests_walk(db),
    )
    .await
}

async fn seed_for_tests_walk(db: &DbPool) -> Result<(), AppError> {
    use attome_metadata::provision::{ensure_default_query, ensure_entity, ensure_secondary_view};

    let bundle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../platform-bundles/attome-dashboard.json"
    ))
    .map_err(|e| AppError::internal(format!("platform-bundles/attome-dashboard.json: {e}")))?;
    let entities = bundle["entities"].as_array().ok_or_else(|| {
        AppError::internal("platform-bundles/attome-dashboard.json: \"entities\" is not an array")
    })?;

    let mut entity_ids = std::collections::HashMap::new();
    for entity in entities {
        let logicalname = entity["logicalname"].as_str().unwrap_or_default();
        let display_name = entity["display_name"].as_str().unwrap_or_default();
        let primary_name_attribute = entity["primary_name_attribute"].as_str();
        let is_append_only = entity["is_append_only"].as_bool().unwrap_or(false);
        let id = ensure_entity(
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
            // `widget_type`'s bundle-shipped choice list is a placeholder
            // (`resync_widget_type_choices` overwrites it from the live
            // widget registry once `seed(db)` runs right after this) — no
            // special-casing needed here either way, `ensure_attribute`
            // just writes whatever the bundle says first.
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

    if let Some(queries) = bundle["queries"].as_array() {
        for q in queries {
            let entity_name = q["entity"].as_str().unwrap_or_default();
            if let Some(&entity_id) = entity_ids.get(entity_name) {
                ensure_default_query(
                    db,
                    entity_id,
                    q["name"].as_str().unwrap_or_default(),
                    q["sql"].as_str().unwrap_or_default(),
                )
                .await?;
            }
        }
    }

    if let Some(views) = bundle["views"].as_array() {
        for v in views {
            if v["is_default"].as_bool().unwrap_or(false) {
                // The default view for each entity is created by
                // `ensure_default_query` above (one default query/view pair
                // per entity in this bundle) — only secondary (non-default)
                // views need a separate call here.
                continue;
            }
            let entity_name = v["entity"].as_str().unwrap_or_default();
            let Some(&entity_id) = entity_ids.get(entity_name) else {
                continue;
            };
            let Some(sql) = v["query"]["name"].as_str().and_then(|qname| {
                bundle["queries"].as_array().and_then(|qs| {
                    qs.iter()
                        .find(|q| {
                            q["entity"].as_str().unwrap_or_default() == entity_name
                                && q["name"].as_str().unwrap_or_default() == qname
                        })
                        .and_then(|q| q["sql"].as_str())
                })
            }) else {
                continue;
            };
            ensure_secondary_view(
                db,
                entity_id,
                entity_name,
                v["name"].as_str().unwrap_or_default(),
                sql,
            )
            .await?;
        }
    }

    Ok(())
}

/// `dashboard_widget.widget_type`'s choice list, re-synced from the live
/// widget registry every boot (cheap: one `ensure_attribute` call, itself a
/// no-op UPDATE when the choice list hasn't changed) — the one field
/// `platform-bundles/attome-dashboard.json` cannot own, since new widget types
/// register themselves in `widget_registry.rs`, not in the bundle.
async fn resync_widget_type_choices(db: &DbPool) -> Result<(), AppError> {
    let widget_id = entity_id_by_logicalname(db, "dashboard_widget").await?;
    let widget_type_choices: Vec<&str> = crate::widget_registry::registry().type_ids();
    ensure_attribute(
        db,
        widget_id,
        "widget_type",
        "Type",
        "choice",
        true,
        false,
        true,
        true,
        None,
        Some(choice(&widget_type_choices)),
    )
    .await?;
    Ok(())
}

/// Bump whenever `seed_body` changes. Distinct from the `"attome-dashboard"`
/// watermark key `bundle::apply_platform_bundle` now owns for this crate's
/// entity provisioning (`system.rs`'s call site) — this key covers only
/// what's still imperative here: the widget_type resync. Reusing the bundle's own key would silently share one
/// watermark row between two unrelated gates.
///
/// `pub` (`#[doc(hidden)]`) — exposed only so `tests/seed.rs` can assert the
/// stored `seed_watermark.version` starts with this and is longer
/// than it, proving `residual_seed_version`'s hash suffix is actually in
/// play rather than the bare human version.
#[doc(hidden)]
pub const SEED_VERSION: &str = "4";

/// The actual seed-gate watermark: `SEED_VERSION` plus a hash of every
/// registered widget `type_id`. `resync_widget_type_choices` re-syncs
/// `widget_type`'s choice list from the live widget registry, but the outer
/// `run_if_stale` gate only re-runs `seed_body` when this string changes —
/// so a plain `SEED_VERSION` bump was the only thing that made a
/// newly-registered widget type actually reach the database. Hashing the
/// registry's `type_id`s into the watermark means registering a new widget
/// type changes the watermark by itself, no human bump required (the same
/// "hash the input" idea `apply_platform_bundle` uses for its own content
/// hash). `SEED_VERSION` is still hashed in first so a deliberate human bump
/// (e.g. a change to `seed_body`'s non-widget-registry logic) keeps working.
fn residual_seed_version() -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(SEED_VERSION.as_bytes());
    for d in crate::widget_registry::registry().all() {
        h.update(d.type_id.as_bytes());
        h.update(b"\0");
    }
    format!("{SEED_VERSION}-{:x}", h.finalize())
}

pub async fn seed(db: &DbPool) -> Result<(), AppError> {
    attome_core::seed_gate::run_if_stale(
        db,
        "attome-dashboard-residual",
        &residual_seed_version(),
        || seed_body(db),
    )
    .await
}

/// `#[doc(hidden)]` — exposed for the idempotency test only. `seed()` above
/// is the real entry point; it wraps this in the seed-gate watermark check.
/// `tests/seed.rs` calls this directly (twice) so it actually exercises
/// `seed_body`'s idempotency rather than the watermark short-circuit that
/// calling `seed()` twice would prove instead.
#[doc(hidden)]
pub async fn seed_body(db: &DbPool) -> Result<(), AppError> {
    resync_widget_type_choices(db).await?;
    tracing::info!("attome-dashboard: entity seed complete");
    Ok(())
}
