use attome_core::meta_registry::OPTIONS_SQL;
use attome_core::{AttrInfo, DataClassification, EngineState, EntityModuleMap, OnTargetDelete};
use attome_modules::ModuleSet;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

// â”€â”€ Entity + attribute lookup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The direct-Postgres resolver, used when `cache.metadata_registry_enabled`
/// is off and by callers that hold only a `DbPool`.
///
/// `pub(crate)` (not module-private) so `bundle::record_sets` (P-environment-
/// promotion §5 step 24) can resolve an entity's live attributes from a bare
/// `DbPool` — the bundle plan path (`plan_bundle`) has no `EngineState`, only
/// `db`/`db_migrator`, so the registry-cached `resolve_entity` below is not
/// reachable there; this DB-direct query is exactly what a background/plan-
/// time reader needs instead, and reusing it (rather than a second copy)
/// keeps the `AttrInfo`-from-`attribute_info` mapping in one place.
pub async fn resolve_entity_from_db(
    db: &attome_db::DbPool,
    input_name: &str,
) -> Result<(Uuid, String, Vec<AttrInfo>, bool), AppError> {
    #[derive(sqlx::FromRow)]
    struct AttrRow {
        logicalname: String,
        field_type_int: i32,
        is_required: bool,
        max_length: Option<i32>,
        is_sensitive: bool,
        is_write_restricted: bool,
        is_sortable: bool,
        is_filterable: bool,
        lookup_entity_ref: Option<Uuid>,
        on_target_delete: String,
        data_classification: String,
        options: Option<Value>,
    }

    // Fetch entity by logicalname; the returned logicalname is DB-trusted.
    let entity_row: Option<(Uuid, String, Option<bool>)> = sqlx::query_as(attome_db::tagged_sql!(
        "entity.resolve",
        "SELECT id, COALESCE(logicalname, '') AS logicalname, is_append_only
         FROM entity_info
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)"
    ))
    .bind(input_name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let (entity_id, entity_name, is_append_only) = entity_row.ok_or(AppError::NotFound)?;

    // A5-T1: a choice field that names an option set gets the set's
    // published, not retired codes, as the registry gives them.
    let sql = attome_db::tag_dynamic(
        "entity.resolve",
        &format!(
            r#"SELECT COALESCE(logicalname, '')        AS logicalname,
                  COALESCE("type", 3)              AS field_type_int,
                  COALESCE(required, false)         AS is_required,
                  max_length,
                  COALESCE(is_sensitive, false)    AS is_sensitive,
                  COALESCE(is_write_restricted, false) AS is_write_restricted,
                  COALESCE(is_sortable, false)     AS is_sortable,
                  COALESCE(is_filterable, false)   AS is_filterable,
                  lookup_entity_ref,
                  COALESCE(on_target_delete, 'orphan') AS on_target_delete,
                  COALESCE(data_classification, 'general') AS data_classification,
                  {OPTIONS_SQL} AS options
           FROM attribute_info
           WHERE entity_ref = $1 AND (is_active IS NULL OR is_active = true)
             AND logicalname IS NOT NULL AND logicalname <> ''"#
        ),
    );
    let attrs: Vec<AttrRow> = sqlx::query_as(&sql)
        .bind(entity_id)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;

    let attrs = attrs
        .into_iter()
        .map(|r| AttrInfo {
            logicalname: r.logicalname,
            field_type_int: r.field_type_int,
            is_required: r.is_required,
            max_length: r.max_length,
            is_sensitive: r.is_sensitive,
            is_write_restricted: r.is_write_restricted,
            is_sortable: r.is_sortable,
            is_filterable: r.is_filterable,
            lookup_entity_ref: r.lookup_entity_ref,
            on_target_delete: OnTargetDelete::from_db_str(&r.on_target_delete),
            data_classification: DataClassification::from_db_str(&r.data_classification),
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
            options: r.options,
        })
        .collect();

    Ok((
        entity_id,
        entity_name,
        attrs,
        is_append_only.unwrap_or(false),
    ))
}

/// D-383 â€” refuses an entity owned by an engine whose module this licence
/// does not include.
///
/// Entity provisioning (`seed()`) runs unconditionally at boot regardless of
/// licence, and `entity_crud::routes()` is gated on `MODULE_CORE` alone, so
/// before this check a licence holding only core could read and write a paid
/// engine's raw records through `/api/v1/{entity}` even though that engine's
/// own routes were correctly hidden. The condition here is exactly the one
/// `ModelRegistry::mounted_routes` applies to those routes (same bit, same
/// `FeatureHidden` response; the paid-tier rule is gone, CLEANUP-REVIEW 1.1),
/// so the generic path
/// and the bespoke path cannot drift apart.
///
/// An entity with no registered owner passes: core platform tables and
/// customer-created entities, both already covered by the `MODULE_CORE` gate.
fn require_entity_licensed(state: &EngineState, entity_name: &str) -> Result<(), AppError> {
    check_entity_license(&state.entity_modules, &state.modules.load(), entity_name)
}

/// The predicate itself, split out from [`require_entity_licensed`] so it can
/// be tested against a real `EntityModuleMap` and `ModuleSet` without
/// standing up an `EngineState` (which needs a live pool and Redis). Keeping the
/// logic here rather than in the caller means the tests exercise the shipping
/// code path, not a re-implementation of it.
fn check_entity_license(
    entity_modules: &EntityModuleMap,
    active: &ModuleSet,
    entity_name: &str,
) -> Result<(), AppError> {
    let Some(owner) = entity_modules.owner(entity_name) else {
        return Ok(());
    };
    if active.require(owner.module_id).is_ok() {
        Ok(())
    } else {
        Err(AppError::FeatureHidden(owner.model_name.to_string()))
    }
}

/// Resolves an entity + its attributes by logicalname. Serves from the
/// arc-swap metadata registry (Plan 1.2) â€” one atomic read, no per-request
/// Postgres query â€” unless the `cache.metadata_registry_enabled` rollback
/// flag is off, in which case it falls back to the pre-1.2 direct query.
///
/// Every generic entity path funnels through here â€” `entity_crud`'s reads,
/// mutations, hierarchy and merge, plus `bulk`/`bulk_graph` â€” which is why
/// D-383's licence gate lives at this single choke point rather than being
/// repeated per handler. A new generic path inherits the gate by construction.
pub async fn resolve_entity(
    state: &EngineState,
    input_name: &str,
) -> Result<(Uuid, String, Vec<AttrInfo>, bool), AppError> {
    // Resolve first, so a name that does not exist stays a 404 and the
    // licence answer only ever describes an entity that is really there.
    let resolved = if !state.base.config.cache.metadata_registry_enabled {
        resolve_entity_from_db(&state.base.db, input_name).await?
    } else {
        let registry = state.entities.load();
        let meta = registry.get(input_name).ok_or(AppError::NotFound)?;
        (
            meta.entity_id,
            meta.logicalname.clone(),
            meta.attrs.clone(),
            meta.is_append_only,
        )
    };

    // Check against the DB-trusted logical name, never the caller's spelling.
    require_entity_licensed(state, &resolved.1)?;
    Ok(resolved)
}

#[cfg(test)]
mod license_gate_tests {
    //! D-383 — exercises the shipping predicate (`check_entity_license`)
    //! directly. `tests/entity_module_gate.rs` covers the declaration side
    //! (which engine owns what, and the seed drift guards); this covers the
    //! decision side.
    use super::*;
    use attome_core::EntityModuleOwner;
    use attome_modules::{MODULE_CORE, MODULE_REPORT, ModuleId};

    fn map_with(entity: &'static str, module: ModuleId) -> EntityModuleMap {
        let mut m = EntityModuleMap::new();
        m.claim(
            entity,
            EntityModuleOwner {
                model_name: "attome-report",
                module_id: module,
            },
        );
        m
    }

    fn license(bits_for: &[ModuleId]) -> ModuleSet {
        let mut bits = [0u64; 4];
        for m in bits_for {
            bits[m.word] |= m.mask;
        }
        ModuleSet::from_bits(bits)
    }

    #[test]
    fn an_unowned_entity_is_never_gated() {
        let map = map_with("dashboard", MODULE_REPORT);
        assert!(check_entity_license(&map, &license(&[MODULE_CORE]), "note").is_ok());
    }

    #[test]
    fn a_core_only_license_is_refused_with_feature_hidden() {
        let map = map_with("dashboard", MODULE_REPORT);
        let err = check_entity_license(&map, &license(&[MODULE_CORE]), "dashboard")
            .expect_err("core-only must not reach a report entity");
        assert!(
            matches!(&err, AppError::FeatureHidden(m) if m == "attome-report"),
            "expected FeatureHidden(attome-report), got {err:?}"
        );
    }

    #[test]
    fn the_owning_module_bit_opens_it() {
        let map = map_with("dashboard", MODULE_REPORT);
        assert!(
            check_entity_license(&map, &license(&[MODULE_CORE, MODULE_REPORT]), "dashboard")
                .is_ok()
        );
    }

    #[test]
    fn an_engine_needs_only_its_module_bit() {
        let map = map_with("dashboard", MODULE_REPORT);
        assert!(check_entity_license(&map, &license(&[MODULE_REPORT]), "dashboard").is_ok());
    }

    #[test]
    fn the_core_only_set_reaches_nothing_owned() {
        let map = map_with("dashboard", MODULE_REPORT);
        assert!(check_entity_license(&map, &ModuleSet::core_only(), "dashboard").is_err());
    }

    #[test]
    fn an_empty_map_gates_nothing_preserving_pre_d383_behaviour() {
        let map = EntityModuleMap::new();
        assert!(check_entity_license(&map, &ModuleSet::core_only(), "workflow_definition").is_ok());
    }
}
