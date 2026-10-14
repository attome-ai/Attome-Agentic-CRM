use std::collections::HashMap;

use attome_modules::ModuleId;
use axum::Router;

use crate::state::EngineState;

/// A model's write-time check of one record body (dashboard 10/10 Phase 2.1):
/// the submitted fields (a full body on create, a partial patch on update) and
/// the live entity metadata. `Err` carries an actionable client message and
/// refuses the write with a 422 on every mutation mode.
pub type RecordValidator = fn(
    &serde_json::Map<String, serde_json::Value>,
    &crate::meta_registry::EntityMetaRegistry,
) -> Result<(), String>;

/// Every XRM engine/model implements this trait.
/// Return a `Router<EngineState>` — handlers use `State<EngineState>` (or `State<AppState>`
/// via FromRef) as extractors. `.with_state()` is applied once by EngineSystem::core_routes.
pub trait EngineModel: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn module_id(&self) -> ModuleId;
    fn routes(&self) -> Router<EngineState>;

    /// The entity logical names this model's `seed()` provisions — the
    /// records that belong to *this* engine rather than to the core platform.
    ///
    /// Declaring them is what lets generic entity CRUD (`/api/v1/{entity}`)
    /// apply the same licence check `routes()` already gets from
    /// `ModelRegistry::mounted_routes`. Without it an engine's bespoke routes
    /// are gated by its module bit while its raw records stay readable and
    /// writable through the generic path on any licence holding
    /// `MODULE_CORE` — see D-383.
    ///
    /// Return `&[]` (the default) only when the model provisions no entities,
    /// or when its entities are core platform tables that `MODULE_CORE`
    /// already covers. A model that seeds an entity and does not list it here
    /// is a licence hole; `entity_module_gate.rs` is the test that says so.
    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    /// `(entity_logicalname, attribute_logicalname)` pairs whose value this
    /// model's own bespoke routes own the transition of — a PATCH/POST
    /// through generic entity CRUD (`/api/v1/{entity}`) must not be allowed
    /// to set them directly, because doing so skips the concurrency/lock,
    /// approval-gate, ledger-row and audit work the model's bespoke route
    /// performs around the same write (R-03,
    /// `document/module-master-plans/M26-dashboard-remediation.md`).
    /// Mirrors `owned_entities`'s declare/collect/enforce shape (D-383): a
    /// model declares the pairs, `ModelRegistry` collects them into
    /// `EngineState::engine_managed_fields`, and
    /// `attome_records::entity_mutation` enforces them.
    ///
    /// Return `&[]` (the default) when the model has no such field — the
    /// common case, since most models have no bespoke state machine at all.
    fn engine_managed_fields(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    /// D-524 — `(entity_logicalname, attribute_logicalname, initial_value)`
    /// for an engine-managed field a new record may be created with.
    /// `attome_records::entity_mutation::create_one` enforces it on every
    /// mutation mode: the field must be absent or null (the initial value is
    /// then written explicitly) or equal to `initial_value`. An engine-managed
    /// field with no entry here must be absent or null on create — no record
    /// can be born in a state only the owning engine's lifecycle routes may
    /// produce.
    ///
    /// Every pair must also appear in [`EngineModel::engine_managed_fields`]; this
    /// only adds the create-time allowance, it does not make a field
    /// engine-managed on its own.
    fn engine_managed_initial_values(
        &self,
    ) -> &'static [(&'static str, &'static str, &'static str)] {
        &[]
    }

    /// Entity logical names whose records only this model's own routes may
    /// create, change or restore (D-535). The generic engine refuses those
    /// writes for every caller and every mutation mode, admins and system
    /// contexts included; generic reads and deletes stay allowed. Same
    /// declare/collect/enforce shape as `engine_managed_fields` (D-383):
    /// `ModelRegistry` collects the names into `EngineState::engine_owned_entities`
    /// and `attome_records::entity_mutation` enforces them.
    ///
    /// Return `&[]` (the default) unless a record of the entity is a credential
    /// or similar that must never be minted around the owning route.
    fn engine_owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    /// `(entity_logicalname, validator)` pairs this model enforces on every
    /// generic create and update of that entity — for structured content the
    /// field layer cannot express, such as a dashboard widget's `config.data`
    /// (D-528). Same declare/collect/enforce shape as `engine_managed_fields`:
    /// `ModelRegistry` collects them into `EngineState::record_validators` and
    /// `attome_records::entity_mutation` runs them after field validation.
    fn record_validators(&self) -> &'static [(&'static str, RecordValidator)] {
        &[]
    }
}

#[cfg(test)]
mod engine_managed_fields_tests {
    use super::*;
    use attome_modules::MODULE_CORE;

    struct PlainModel;

    impl EngineModel for PlainModel {
        fn name(&self) -> &'static str {
            "plain-model"
        }
        fn module_id(&self) -> ModuleId {
            MODULE_CORE
        }
        fn routes(&self) -> Router<EngineState> {
            Router::new()
        }
    }

    #[test]
    fn a_model_with_no_override_declares_no_engine_managed_fields() {
        assert!(PlainModel.engine_managed_fields().is_empty());
        assert!(PlainModel.engine_managed_initial_values().is_empty());
    }
}

/// Which engine owns an entity — mirrors exactly the module check
/// `ModelRegistry::mounted_routes` applies to that engine's own routes, so the
/// generic path and the bespoke path can never disagree about whether a module
/// is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntityModuleOwner {
    /// The owning model's `name()`, used verbatim in `AppError::FeatureHidden`
    /// so the message a caller sees is the same one that engine's own routes
    /// produce.
    pub model_name: &'static str,
    pub module_id: ModuleId,
}

/// Entity logical name -> owning engine, built once at boot from the
/// registered models and then read-only. An entity that is absent is not
/// owned by any engine: core platform tables and customer-created entities,
/// both already covered by the `MODULE_CORE` gate on `entity_crud::routes()`.
///
/// Empty by default (`EngineState::new`) so a test or tool that builds bare
/// state keeps today's behaviour; `EngineSystemBuilder::build` populates it.
#[derive(Debug, Default, Clone)]
pub struct EntityModuleMap {
    owners: HashMap<&'static str, EntityModuleOwner>,
}

impl EntityModuleMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `entity` as owned by `owner`. Panics on a second, conflicting
    /// claim: two engines seeding the same entity is a wiring bug that must
    /// not reach traffic, and boot is the only moment it can be caught
    /// cheaply. A repeated *identical* claim is idempotent, so re-registering
    /// the same model is harmless.
    pub fn claim(&mut self, entity: &'static str, owner: EntityModuleOwner) {
        if let Some(existing) = self.owners.get(entity)
            && *existing != owner
        {
            panic!(
                "entity '{entity}' is claimed by both '{}' and '{}' — an entity has exactly one owning engine (see EngineModel::owned_entities)",
                existing.model_name, owner.model_name
            );
        }
        self.owners.insert(entity, owner);
    }

    pub fn owner(&self, entity: &str) -> Option<&EntityModuleOwner> {
        self.owners.get(entity)
    }

    pub fn len(&self) -> usize {
        self.owners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    /// Every claimed entity, for tests and diagnostics. Unordered.
    pub fn entities(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.owners.keys().copied()
    }
}
