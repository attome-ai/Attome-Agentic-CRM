//! Test-only seeding for this crate's metadata; production provisioning is
//! `platform-bundles/attome-security.json`, applied from `attome-server`'s
//! `system.rs`.
//!
//! This module used to also carry `seed(db, config)`, which granted
//! `system.admin` to `security.bootstrap_admin_email` on every boot. That is
//! gone: creating the first administrator is an operator action, not
//! provisioning, and `server --bootstrap-admin <email>` (D-128) already did it
//! in one step — creating the account or granting to an existing one — without
//! a config key, a per-boot lookup, or a boot that fails when the address
//! resolves to nobody. The two privileges it also ensured (`system.admin`,
//! `sidebar.manage`) were pure duplication: the bundle applied immediately
//! before it already declares both.
//!
//! `user_account_mm_privilege` is pre-existing
//! legacy infrastructure (`0000_core_bootstrap.sql`), but — unlike this
//! comment's previous claim — IS now registered as an entity, the same as
//! `user_account_mm_team`: `provision_table`'s self-healing backfill
//! (row_version, modified_at/modified_by — see its own doc comment, which
//! names this exact table shape) makes registering a legacy core_* table
//! safe, so the User form's Privileges tab can be an ordinary
//! `xrm-related-grid` m2m subgrid instead of a bespoke panel. See the
//! registration below, right after `privilege`'s own.
//! `privilege` and `role` ARE also registered, by
//! `register_readonly_entities` below (alongside
//! `user_account`/`organization`/`team`). `privilege`'s
//! `is_active` column already matched the convention `attome_metadata::provision`
//! and every real authz read (`db.rs`, `entity_privileges.rs`) both use, so
//! its self-healing backfill was a safe no-op. `role` did NOT match
//! — it used `is_deleted`, not `is_active`, for liveness (`admin/roles.rs`,
//! resolver.rs), and there was no delete endpoint anyway (every row's
//! `is_deleted` was always false). Migration 0131 (D-372) added `is_active`
//! to `role`, backfilled to agree with `is_deleted`, plus a trigger
//! keeping the two in sync (whichever a writer sets — `is_deleted` wins on
//! conflict) — closes the gap before this registration, so a future
//! generic-CRUD delete now correctly revokes the role too.

use attome_db::DbPool;
use attome_types::AppError;

use crate::db::ensure_privilege;

/// REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478) — this used to be a
/// ~600-line imperative registration of `organization`/`_team`/
/// `_systemuser`/`_systemuser_mm_team`/`_privilege`/`_systemuser_mm_privilege`/
/// `_role`, closing the gap that `user_account` (and its siblings)
/// were never registered in `entity_info`, so `attome_readonly` had
/// no access to them (`attome_metadata::provision::backfill_readonly_grants`
/// discovers entities by reading that table). That content now lives in
/// `platform-bundles/attome-security.json`, applied at boot by
/// `attome_server::bundle::apply_platform_bundle` — **not called from this
/// crate**, since `attome-security` sits below `attome-server` in the dependency
/// graph and calling up would be a cycle; the production call site is
/// `attome-server/src/system.rs`, immediately before this file's `seed()`.
///
/// [`seed_for_tests`] below is what a bare-`DbPool` test fixture (this
/// crate's own conversion had ~20 across five crates) now calls instead of
/// the old `seed()` + `register_readonly_entities()` pair.
///
/// Bare-`DbPool` fixture setup for tests across `attome-ai`, `attome-dashboard`,
/// `attome-grc`, `attome-project`, and `attome-service` that used to call `seed()` +
/// `register_readonly_entities()` back to back (with a `minimal_config()`/
/// `test_config()` that never sets `security.bootstrap_admin_email`, so
/// `seed()`'s only observable effect for them was ever the two privilege
/// rows, never a grant). One call now does both: applies
/// `platform-bundles/attome-security.json`'s full content (privileges, entities,
/// attributes, queries, views) directly via `attome_metadata::provision::*`
/// primitives — the same "read the bundle JSON at runtime, walk it" pattern
/// `attome_project::seed::seed_for_tests` and `attome_service::seed::seed_for_tests`
/// already established, extended here to cover privileges and queries/views
/// too since production `seed()` and the bundle both provide them.
pub async fn seed_for_tests(db: &DbPool) -> Result<(), AppError> {
    use attome_metadata::provision::{
        ensure_attribute, ensure_default_query, ensure_entity, ensure_secondary_view,
    };

    let bundle: serde_json::Value = serde_json::from_str(include_str!("../seed/security.json"))
        .map_err(|e| AppError::internal(format!("platform-bundles/attome-security.json: {e}")))?;

    if let Some(privileges) = bundle["privileges"].as_array() {
        for p in privileges {
            ensure_privilege(
                db,
                p["key"].as_str().unwrap_or_default(),
                p["name"].as_str().unwrap_or_default(),
                p["description"].as_str().unwrap_or_default(),
                attome_core::changeset::Layer::Platform,
            )
            .await?;
        }
    }

    let entities = bundle["entities"].as_array().ok_or_else(|| {
        AppError::internal("platform-bundles/attome-security.json: \"entities\" is not an array")
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
        let logicalname = entity["logicalname"].as_str().unwrap_or_default();
        let entity_id = entity_ids[logicalname];
        let Some(attributes) = entity["attributes"].as_array() else {
            continue;
        };
        for attr in attributes {
            let lookup_entity_ref = match attr["lookup_entity"].as_str() {
                Some(target) => entity_ids.get(target).copied(),
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
                attr["options"].as_object().map(|_| attr["options"].clone()),
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
            let Some(sql) = v["query"]["name"]
                .as_str()
                .and_then(|qname| {
                    bundle["queries"].as_array().and_then(|qs| {
                        qs.iter().find(|q| {
                            q["entity"].as_str().unwrap_or_default() == entity_name
                                && q["name"].as_str().unwrap_or_default() == qname
                        })
                    })
                })
                .and_then(|q| q["sql"].as_str())
            else {
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
