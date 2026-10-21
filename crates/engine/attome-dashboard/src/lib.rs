pub(crate) mod access;
pub mod auth;
pub mod context;
pub mod decision;
/// O10-T1: decisions measured before and after.
pub mod decision_outcome;
pub mod declarative_widget;
pub mod drill;
pub mod execution;
pub mod health;
pub mod layout;
pub mod lifecycle;
pub mod model;
pub mod pages;
pub mod publish_gate;
pub mod scenario;
pub mod seed;
pub mod widget_actions;
/// D-543 — published widgets execute from their snapshot, not from a
/// client-supplied query/view reference.
pub mod widget_data;
pub mod widget_registry;

pub use model::DashboardModel;

/// D-351 — this crate's advisory-lock namespace (`"attome-dashboard/…"` keys),
/// registered in `crates/server/tests/advisory_lock_namespaces.rs`. M27's
/// metric-snapshot lock moved to `attome_metric::ADVISORY_LOCK_NAMESPACE` (D-480,
/// M26 R-14); `scenario.rs`'s own `scenario-evaluate` lock still uses this
/// namespace, unchanged.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 15;

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document. Merged in by `attome_api::openapi_document()`, same composition
/// point as `attome_project::openapi()`/`attome_service::openapi()`. M27's metrics
/// routes moved to `attome_metric::openapi()` (D-480), merged in next to this
/// one at that call site rather than from here.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = lifecycle::openapi_fragment();
    doc.merge(layout::openapi_fragment());
    doc.merge(pages::openapi_fragment());
    doc.merge(widget_data::openapi_fragment());
    doc.merge(drill::openapi_fragment());
    doc.merge(widget_registry::openapi_fragment());
    doc.merge(widget_actions::openapi_fragment());
    doc.merge(declarative_widget::openapi_fragment());
    doc.merge(context::openapi_fragment());
    doc.merge(health::openapi_fragment());
    doc.merge(decision::openapi_fragment());
    doc.merge(scenario::openapi_fragment());
    doc
}

#[cfg(test)]
mod openapi_tests {
    /// **Regression: a recursive schema must not expand inline forever.**
    ///
    /// `SnapshotSection.children: Vec<SnapshotSection>` shipped without
    /// utoipa's `#[schema(no_recursion)]`, so building this crate's fragment
    /// recursed until the stack ran out. The visible symptom was two removes
    /// away from the cause: `server --print-openapi` aborted with 0xC00000FD,
    /// which took down `npm run generate:api` and, with it, the ability to
    /// regenerate `openapi.json`/`api-types.ts` at all.
    ///
    /// This is the second time the defect has landed — `attome_api::sidebar::
    /// SidebarItem::child` carries the same annotation, added after the same
    /// crash — so it gets a test this time rather than a third rediscovery.
    /// A test thread's stack is far smaller than the 64 MB `main.rs` spawns
    /// for schema generation, which makes this a *stricter* check than the
    /// binary it protects.
    #[test]
    fn building_the_fragment_terminates() {
        let doc = super::openapi();
        assert!(
            !doc.paths.paths.is_empty(),
            "the fragment must carry this crate's routes"
        );
    }
}
