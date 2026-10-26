//! `EngineModel` registration for the search engine (TODO-007).
//!
//! **The license gate mounts the QUERY surface only. Indexing runs
//! regardless.**
//!
//! That asymmetry is the whole point of this file and it is not an oversight.
//! `EngineModel::routes` is gated by `MODULE_SEARCH` through `ModelRegistry`, so
//! an unlicensed deployment 404s every route here — but the drain and the
//! backfill are jobs, not routes, and they keep running. If indexing were
//! gated too, then licensing search *later* would require a full backfill of
//! every record the deployment has ever held: hours to days on a large
//! customer, at exactly the moment they have just paid and expect it to work.
//!
//! The cost of the asymmetry is a table of derived text on a deployment that
//! cannot query it. That is a disk cost, and a bounded one; the alternative is
//! a first impression measured in hours.

use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_SEARCH, ModuleId};
use axum::Router;

#[derive(Debug)]
pub struct SearchModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for SearchModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-search"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_SEARCH
    }

    /// The query surface, gated by `MODULE_SEARCH` through `ModelRegistry` —
    /// an unlicensed deployment 404s every route here while the drain and the
    /// backfill keep running. `aggregate::routes()` merged in alongside the
    /// full-text search route — same license gate, same reasoning (a
    /// dashboard aggregation widget is a query, not indexing/drain work).
    /// `graph::routes()` (M38 Phase 1) is the same shape again: a traversal
    /// is retrieval, gated the same way the text and aggregation routes are.
    /// `saved_search::routes()` (the "run" action) and `suggest::routes()`
    /// (M11 gap list) are retrieval too, by the same reasoning — entity
    /// registration for `saved_search` itself happens in `saved_search::
    /// seed`, called from `attome-api/src/system.rs`, not here (D-366:
    /// indexing/seeding must not be gated, or licensing search later would
    /// need a full re-seed).
    fn routes(&self) -> Router<EngineState> {
        crate::routes::routes()
            .merge(crate::aggregate::routes())
            .merge(crate::graph::routes())
            .merge(crate::saved_search::routes())
            .merge(crate::suggest::routes())
            .merge(crate::quality::routes())
    }
}

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document, merged in by `server::openapi::document`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = <crate::routes::ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(crate::aggregate::openapi_fragment());
    doc.merge(crate::graph::openapi_fragment());
    doc.merge(<crate::saved_search::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<crate::suggest::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc.merge(<crate::quality::ApiDocFragment as utoipa::OpenApi>::openapi());
    doc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `MODULE_SEARCH` (bit 8) has been allocated and gating nothing since it
    /// was reserved. This pins that the model claims that bit and not another
    /// — a copy-paste from a sibling engine would silently make search share a
    /// licence with, say, reporting.
    #[test]
    fn the_model_claims_the_search_module_bit() {
        let model = SearchModel;
        assert_eq!(
            (model.module_id().word, model.module_id().mask),
            (MODULE_SEARCH.word, MODULE_SEARCH.mask)
        );
        assert_eq!(model.name(), "attome-search");
    }
}
