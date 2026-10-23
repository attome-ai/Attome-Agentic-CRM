//! P-api-contract Phase 1 — the engine layer's composition point for the
//! workspace OpenAPI document.
//!
//! Mirrors `system::EngineSystem::core_routes`: every route bundle merged into the
//! router there has its annotated counterpart merged here. Keeping the two
//! lists in step is a review rule: nothing diffs them since D-768 removed the
//! coverage script (and there is no CI).
//!
//! What this deliberately does NOT include: `crates/server`'s auth routes and
//! any engine mounted through `ModelRegistry` from outside this crate
//! (`attome-workflow` today). Those live above this layer — `crates/server`'s own
//! `openapi.rs` merges them onto this document and serves the result.

/// The engine layer's document: `attome-server`'s root identity and health
/// probes, this crate's own handlers, and the `xrm-*` crates it depends on.
pub fn openapi_document() -> utoipa::openapi::OpenApi {
    let mut doc = attome_server::openapi::tag_module(attome_server::openapi::openapi(), "core");

    // S2-T9: each fragment with the module whose licence gates its routes in
    // `system.rs` (`core` for ungated and core-gated routes); a fragment its
    // crate already tagged keeps its tags.
    for (fragment, module) in [
        // Engine crates this one already depends on directly.
        (attome_security::openapi(), "core"),
        (attome_notification::openapi(), "notification"),
        (attome_project::openapi(), "project"),
        (attome_service::openapi(), "service"),
        (attome_grc::openapi(), "grc"),
        (attome_dashboard::openapi(), "dashboard"),
        // D-480 (M26 R-14) — M27 (KPI & Metrics), split out of attome-dashboard.
        (attome_metric::openapi(), "dashboard"),
        (attome_state::openapi(), "state"),
        // This crate's own route bundles, in `core_routes()` order.
        (attome_records::query_exec::openapi_fragment(), "core"),
        (attome_records::query_admin::openapi_fragment(), "core"),
        (attome_records::composite::openapi_fragment(), "core"),
        (crate::view_admin::openapi_fragment(), "core"),
        (crate::model_admin::openapi_fragment(), "core"),
        (crate::model_health::openapi_fragment(), "core"),
        (crate::table_health::openapi_fragment(), "core"),
        (crate::deployment_openapi::openapi_fragment(), "core"),
        (crate::live::openapi_fragment(), "core"),
        (crate::calendar_admin::openapi_fragment(), "core"),
        (crate::app_admin::openapi_fragment(), "core"),
        (crate::slo_admin::openapi_fragment(), "core"),
        (crate::limits_admin::openapi_fragment(), "core"),
        (crate::model_admin::cooked::openapi_fragment(), "core"),
        (crate::mentions::openapi_fragment(), "core"),
        (crate::ratelimit_admin::openapi_fragment(), "core"),
        (crate::sbom_admin::openapi_fragment(), "core"),
        (crate::env_variable_admin::openapi_fragment(), "core"),
        (crate::customer_test_admin::openapi_fragment(), "core"),
        (crate::metadata_label_admin::openapi_fragment(), "core"),
        (crate::bundle::routes::openapi_fragment(), "core"),
        (crate::bundle::break_glass::openapi_fragment(), "core"),
        // Solution 7 Phase 1 (D-785) — changeset authoring.
        (crate::changeset::routes::openapi_fragment(), "core"),
        (crate::changeset::apply_routes::openapi_fragment(), "core"),
        (crate::admin::openapi(), "core"),
        (crate::settings_admin::openapi_fragment(), "core"),
        (crate::features_admin::openapi_fragment(), "core"),
        (crate::schema::openapi_fragment(), "core"),
        (crate::catalog_admin::openapi_fragment(), "core"),
        (crate::sidebar::openapi_fragment(), "core"),
        (crate::my_work::openapi_fragment(), "core"),
        (attome_records::entity_crud::openapi(), "core"),
        (attome_records::bulk::openapi_fragment(), "core"),
        (attome_records::bulk_edit::openapi_fragment(), "core"),
        (crate::data_export::openapi_fragment(), "core"),
        (crate::data_mapping_admin::openapi_fragment(), "core"),
        (crate::data_profile_admin::openapi_fragment(), "core"),
        (crate::migration::openapi_fragment(), "core"),
        (crate::duplicates_admin::openapi_fragment(), "core"),
        (crate::bulk_transform::openapi_fragment(), "core"),
        // D-486 — M55 moved to `attome-document`. Both fragments (the generic
        // file-field path and the document tree) merge from there; this crate
        // has a real dependency on it, so the list in `crates/server` does
        // not have to grow the way it does for attome-search/attome-process/
        // attome-docgen.
        (attome_document::openapi(), "core"),
        (crate::communication::openapi_fragment(), "core"),
        (attome_notification::admin::openapi_fragment(), "core"),
        (crate::webcrawl_admin::openapi_fragment(), "core"),
        (attome_content::admin::openapi_fragment(), "content"),
        (crate::content_public::openapi_fragment(), "core"),
        (crate::storage_local::openapi_fragment(), "core"),
        (crate::service_public::openapi_fragment(), "core"),
        (attome_content::space_admin::openapi_fragment(), "content"),
        (
            attome_content::template_admin::openapi_fragment(),
            "content",
        ),
        (attome_s2s::admin::openapi_fragment(), "core"),
        (attome_s2s::oauth_clients::openapi_fragment(), "core"),
        (attome_events::admin::openapi_fragment(), "integration"),
        (attome_audit::admin::openapi_fragment(), "audit"),
        (crate::audit_read::openapi_fragment(), "audit"),
        (attome_compliance::erasure_admin::openapi_fragment(), "core"),
        (
            attome_compliance::retention_admin::openapi_fragment(),
            "core",
        ),
        (attome_compliance::dsr_admin::openapi_fragment(), "core"),
        (
            attome_compliance::legal_hold_admin::openapi_fragment(),
            "core",
        ),
        (
            attome_compliance::governance_admin::openapi_fragment(),
            "core",
        ),
        (attome_compliance::rewrap_admin::openapi_fragment(), "core"),
        (attome_compliance::config_admin::openapi_fragment(), "core"),
        (attome_compliance::consent_admin::openapi_fragment(), "core"),
        (attome_compliance::archive_admin::openapi_fragment(), "core"),
        (
            attome_compliance::legal_matter_admin::openapi_fragment(),
            "core",
        ),
        (crate::jobs_admin::openapi_fragment(), "core"),
        (crate::dead_letter_inbox::openapi_fragment(), "core"),
        (crate::email_admin::openapi_fragment(), "core"),
        (crate::license_admin::openapi_fragment(), "core"),
        (crate::approval_admin::openapi_fragment(), "core"),
        (crate::approval_metrics::openapi_fragment(), "core"),
        (crate::approval_policy_admin::openapi_fragment(), "core"),
        (crate::signoff::openapi_fragment(), "core"),
        (crate::profiler_admin::openapi_fragment(), "core"),
        (crate::system_health::openapi_fragment(), "core"),
        (crate::autonumber_admin::openapi_fragment(), "core"),
        (crate::api_usage_admin::openapi_fragment(), "core"),
        (crate::changes_admin::openapi_fragment(), "core"),
        (crate::relationship_admin::openapi_fragment(), "core"),
        (crate::quality_admin::openapi_fragment(), "core"),
        (crate::business_rule_admin::openapi_fragment(), "core"),
        (
            crate::omnichannel_metrics::openapi_fragment(),
            "omnichannel",
        ),
    ] {
        doc.merge(attome_server::openapi::tag_module(fragment, module));
    }
    doc
}
