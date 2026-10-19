use std::collections::HashSet;
use std::sync::Arc;

use arc_swap::ArcSwap;
use attome_core::{EngineModel, EngineState, EntityModuleMap, EntityModuleOwner};
use attome_modules::ModuleSet;
use attome_types::AppError;
use axum::{
    Router,
    extract::Request,
    middleware::{self, Next},
    response::IntoResponse,
};

/// Runtime registry of XRM models/engines.
/// Call EngineSystem::builder().register(model) to add models.
/// Every model is mounted at startup; each model's routes check the live license
/// before dispatching a request.
pub struct ModelRegistry {
    models: Vec<Box<dyn EngineModel>>,
}

impl std::fmt::Debug for ModelRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelRegistry").finish_non_exhaustive()
    }
}

impl Default for ModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelRegistry {
    pub fn new() -> Self {
        Self { models: Vec::new() }
    }

    pub fn register(mut self, model: impl EngineModel + 'static) -> Self {
        self.models.push(Box::new(model));
        self
    }

    /// D-383 — the entity-ownership map, built from the same `module_id()`
    /// `mounted_routes` gates each model's own routes with, so
    /// generic entity CRUD (`/api/v1/{entity}`) cannot disagree with the
    /// bespoke routes about whether a module is licensed. Call once at boot;
    /// the result is read-only.
    pub fn entity_modules(&self) -> EntityModuleMap {
        let mut map = EntityModuleMap::new();
        for model in &self.models {
            let owner = EntityModuleOwner {
                model_name: model.name(),
                module_id: model.module_id(),
            };
            for entity in model.owned_entities() {
                map.claim(entity, owner);
            }
        }
        map
    }

    /// R-03 (`document/module-master-plans/M26-dashboard-remediation.md`) —
    /// every `(entity_logicalname, attribute_logicalname)` pair a registered
    /// model declared via `EngineModel::engine_managed_fields`, folded into one
    /// set the same way `entity_modules` folds `owned_entities`. Call once at
    /// boot; the result is read-only.
    pub fn engine_managed_fields(&self) -> HashSet<(String, String)> {
        let mut fields = HashSet::new();
        for model in &self.models {
            for (entity, attribute) in model.engine_managed_fields() {
                fields.insert(((*entity).to_owned(), (*attribute).to_owned()));
            }
        }
        fields
    }

    /// D-524 — every `(entity, attribute) -> initial_value` a registered model
    /// declared via `EngineModel::engine_managed_initial_values`. Call once at
    /// boot next to [`Self::engine_managed_fields`]; the result is read-only.
    pub fn engine_managed_initial_values(
        &self,
    ) -> std::collections::HashMap<(String, String), String> {
        let mut values = std::collections::HashMap::new();
        for model in &self.models {
            for (entity, attribute, initial) in model.engine_managed_initial_values() {
                values.insert(
                    ((*entity).to_owned(), (*attribute).to_owned()),
                    (*initial).to_owned(),
                );
            }
        }
        values
    }

    /// Dashboard 10/10 Phase 2.1 — every `EngineModel::record_validators` pair,
    /// grouped by entity. Call once at boot; the result is read-only.
    pub fn record_validators(
        &self,
    ) -> std::collections::HashMap<String, Vec<attome_core::model::RecordValidator>> {
        let mut validators: std::collections::HashMap<
            String,
            Vec<attome_core::model::RecordValidator>,
        > = std::collections::HashMap::new();
        for model in &self.models {
            for (entity, validator) in model.record_validators() {
                validators
                    .entry((*entity).to_owned())
                    .or_default()
                    .push(*validator);
            }
        }
        validators
    }

    /// D-535 — every entity a registered model declared through
    /// `EngineModel::engine_owned_entities`, folded into one set. Call once at
    /// boot; the result is read-only.
    pub fn engine_owned_entities(&self) -> HashSet<String> {
        self.models
            .iter()
            .flat_map(|model| model.engine_owned_entities())
            .map(|entity| (*entity).to_owned())
            .collect()
    }

    /// Returns a Router<EngineState> with every model mounted and each model
    /// protected by a per-request lookup of the live license: the module bit
    /// gates the route (Module Management switches it, D-778). There is no
    /// paid tier any more (CLEANUP-REVIEW 1.1): every licence D-778 loads was
    /// paid, and the pre-load `degraded()` licence holds no module bit, so
    /// the module check alone refuses exactly what the old paid check did.
    /// The single `.with_state()` in `core_routes()` completes wiring.
    pub fn mounted_routes(&self, license: Arc<ArcSwap<ModuleSet>>) -> Router<EngineState> {
        self.models.iter().fold(Router::new(), |router, model| {
            let model_routes = model.routes();
            // `route_layer` panics ("adding a route_layer before any routes
            // is a no-op") on a router with zero routes — a real case here,
            // not a hypothetical: SecurityModel deliberately returns
            // `Router::new()` (its routes are mounted unconditionally
            // elsewhere, never license-gated). Nothing to wrap, so nothing
            // to license-check; merge it as-is.
            if !model_routes.has_routes() {
                return router.merge(model_routes);
            }

            let module_id = model.module_id();
            let model_name = model.name().to_string();
            let license = Arc::clone(&license);

            router.merge(model_routes.route_layer(middleware::from_fn(
                move |req: Request, next: Next| {
                    let license = Arc::clone(&license);
                    let model_name = model_name.clone();
                    async move {
                        let active = license.load();
                        if active.require(module_id).is_ok() {
                            next.run(req).await
                        } else {
                            AppError::FeatureHidden(model_name).into_response()
                        }
                    }
                },
            )))
        })
    }
}

#[cfg(test)]
mod entity_module_tests {
    //! D-383 — proves the *production* builder wires the real engines into the
    //! map. `tests/entity_module_gate.rs` pins what each engine declares;
    //! this pins that `ModelRegistry::entity_modules()` actually folds those
    //! declarations together with the right module bit.
    use super::*;
    use attome_modules::{
        MODULE_NOTIFICATION, MODULE_PROJECT, MODULE_REPORT, MODULE_SERVICE, MODULE_WORKFLOW,
    };

    fn production_registry() -> ModelRegistry {
        ModelRegistry::new()
            .register(attome_workflow::WorkflowModel)
            .register(attome_notification::NotificationModel)
            .register(attome_report::ReportModel)
            .register(attome_project::ProjectModel)
            .register(attome_service::ServiceModel)
    }

    #[test]
    fn the_real_registry_claims_every_engine_entity() {
        let map = production_registry().entity_modules();

        for (entity, module, model) in [
            ("workflow_definition", MODULE_WORKFLOW, "attome-workflow"),
            (
                "notification_template",
                MODULE_NOTIFICATION,
                "attome-notification",
            ),
            // D-479 (M26 R-09) — the legacy `dashboard` entity this row used
            // to pin was retired; `attome_report` (the still-live Reporting
            // Engine entity, unaffected by that sunset) is the representative
            // MODULE_REPORT-owned entity now.
            ("attome_report", MODULE_REPORT, "attome-report"),
            ("attome_project", MODULE_PROJECT, "attome-project"),
            ("project_issue", MODULE_PROJECT, "attome-project"),
            ("service_work_request", MODULE_SERVICE, "attome-service"),
            ("service_ticket", MODULE_SERVICE, "attome-service"),
            ("service_sla_policy", MODULE_SERVICE, "attome-service"),
            ("service_offering", MODULE_SERVICE, "attome-service"),
            ("service_sla_clock", MODULE_SERVICE, "attome-service"),
            ("service_sla_calculation", MODULE_SERVICE, "attome-service"),
        ] {
            let owner = map
                .owner(entity)
                .unwrap_or_else(|| panic!("{entity} is not claimed by any engine"));
            assert_eq!(owner.module_id, module, "{entity} module bit");
            assert_eq!(owner.model_name, model, "{entity} owner");
        }

        // 1 workflow + 1 notification + 2 report + 18 project + 11 service
        // (G9-T3 added `supplier_sla_clock`, G8-T1 `service_escalation_rule`,
        // G2-T3 `service_conversion_map`)
        // (M70 added `service_offering`, D-423; M73 added
        // `service_sla_clock`, D-422; D-517 added `service_sla_calculation`; M25 added `attome_report`/`report_schedule`,
        // D-440; M72 added `resource_allocation`; M84 added
        // `service_work_queue`/`service_work_queue_member`, D-464; D-479 (M26 R-09)
        // retired the legacy `dashboard` entity's claim under MODULE_REPORT,
        // dropping that category from 3 to 2). Not hardcoded further than
        // this count on purpose — see
        // `attome_project::engine::ProjectModel::owned_entities` and
        // `attome_service::model::ServiceModel::owned_entities` for the actual
        // lists; `entity_module_gate.rs`'s
        // `the_real_engines_declare_exactly_these_entities` is what pins
        // those against each engine's own seed.
        assert_eq!(map.len(), 33, "unexpected claimed-entity count");
    }

    #[test]
    fn a_registry_with_no_models_claims_nothing() {
        assert!(ModelRegistry::new().entity_modules().is_empty());
    }

    #[test]
    fn a_model_that_declares_no_entities_contributes_nothing() {
        // SecurityModel seeds the core tables but deliberately declares none,
        // because MODULE_CORE already gates entity_crud::routes().
        let map = ModelRegistry::new()
            .register(attome_security::model::SecurityModel)
            .entity_modules();
        assert!(map.is_empty(), "core entities must not be double-gated");
    }
}
