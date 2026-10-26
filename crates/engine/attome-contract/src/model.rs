//! `EngineModel` registration: mounted only when the `contract` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_CONTRACT, ModuleId};
use axum::{Router, routing::post};

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct ContractModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for ContractModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-contract"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_CONTRACT
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        // `platform-bundles/attome-contract.json`.
        &[
            "contract_version",
            "contract_comparison",
            "contract_import",
            "contract_playbook_rule",
            // `platform-bundles/attome-contract-counterparty.json`.
            "counterparty_match_proposal",
        ]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
            .route(
                "/api/v1/contract/counterparty-proposals/{id}/decide",
                post(crate::counterparty::post_decide),
            )
            .route(
                "/api/v1/contract/counterparty-match/run",
                post(crate::counterparty::post_run),
            )
            .route(
                "/api/v1/contract/contracts/{id}/draft",
                post(crate::draft::post_draft),
            )
            .route(
                "/api/v1/contract/contracts/{id}/compare",
                post(crate::compare::post_compare),
            )
    }
}
