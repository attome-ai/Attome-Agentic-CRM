//! `EngineModel` registration for the Reporting Engine (`attome_report`/
//! `report_schedule`), the CSV/XLSX scheduled-report feature — distinct
//! from `attome-dashboard`'s `attome_dashboard` model (its own `MODULE_DASHBOARD`
//! bit; see that crate's `model.rs`), the platform's one dashboard product.
//!
//! D-479 (M26 R-09) removed the legacy `dashboard` entity from
//! [`owned_entities`](ReportModel::owned_entities) and its widget-type
//! catalog route — see this crate's `lib.rs` doc comment.

use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_REPORT, ModuleId};
use axum::Router;

#[derive(Debug)]
pub struct ReportModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for ReportModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-report"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_REPORT
    }

    /// M25 Phase 1 (D-440) — `attome_report`/`report_schedule`, provisioned
    /// by `crate::seed::seed_reports`. `report_run` is NOT here — it is
    /// a migration-owned infra table (`0240_xrm_report_run.sql`), not a
    /// provisioned entity, so it has no `entity_info` row for this
    /// list to name. D-479 (M26 R-09) removed the legacy `dashboard` entity
    /// that used to be listed here — see this crate's `lib.rs` doc comment.
    fn owned_entities(&self) -> &'static [&'static str] {
        &["attome_report", "report_schedule"]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::report_admin::routes()
            .merge(crate::run::routes())
            .merge(crate::schedule_admin::routes())
            .merge(crate::secured_sql::routes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins that this model claims `MODULE_REPORT` and not another bit — a
    /// copy-paste from a sibling engine would silently make scheduled
    /// reports share a licence with, say, search.
    #[test]
    fn the_model_claims_the_report_module_bit() {
        let model = ReportModel;
        assert_eq!(
            (model.module_id().word, model.module_id().mask),
            (MODULE_REPORT.word, MODULE_REPORT.mask)
        );
        assert_eq!(model.name(), "attome-report");
    }
}
