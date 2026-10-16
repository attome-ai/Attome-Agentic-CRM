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
    let mut doc = attome_server::openapi::openapi();

    for fragment in [
        // Engine crates this one already depends on directly.
        attome_security::openapi(),
        attome_notification::openapi(),
        attome_project::openapi(),
        attome_service::openapi(),
        attome_grc::openapi(),
        attome_dashboard::openapi(),
        // D-480 (M26 R-14) — M27 (KPI & Metrics), split out of attome-dashboard.
        attome_metric::openapi(),
        attome_state::openapi(),
        // This crate's own route bundles, in `core_routes()` order.
        attome_records::query_exec::openapi_fragment(),
        attome_records::query_admin::openapi_fragment(),
        attome_records::composite::openapi_fragment(),
        crate::view_admin::openapi_fragment(),
        crate::model_admin::openapi_fragment(),
        crate::model_health::openapi_fragment(),
        crate::live::openapi_fragment(),
        crate::calendar_admin::openapi_fragment(),
        crate::app_admin::openapi_fragment(),
        crate::slo_admin::openapi_fragment(),
        crate::mentions::openapi_fragment(),
        crate::sbom_admin::openapi_fragment(),
        crate::env_variable_admin::openapi_fragment(),
        crate::metadata_label_admin::openapi_fragment(),
        crate::bundle::routes::openapi_fragment(),
        crate::bundle::break_glass::openapi_fragment(),
        // Solution 7 Phase 1 (D-785) — changeset authoring.
        crate::changeset::routes::openapi_fragment(),
        crate::changeset::apply_routes::openapi_fragment(),
        crate::admin::openapi(),
        crate::settings_admin::openapi_fragment(),
        crate::features_admin::openapi_fragment(),
        crate::schema::openapi_fragment(),
        crate::catalog_admin::openapi_fragment(),
        crate::sidebar::openapi_fragment(),
        crate::my_work::openapi_fragment(),
        attome_records::entity_crud::openapi(),
        attome_records::bulk::openapi_fragment(),
        attome_records::bulk_edit::openapi_fragment(),
        crate::data_export::openapi_fragment(),
        crate::data_mapping_admin::openapi_fragment(),
        crate::data_profile_admin::openapi_fragment(),
        crate::migration::openapi_fragment(),
        crate::duplicates_admin::openapi_fragment(),
        crate::bulk_transform::openapi_fragment(),
        // D-486 — M55 moved to `attome-document`. Both fragments (the generic
        // file-field path and the document tree) merge from there; this crate
        // has a real dependency on it, so the list in `crates/server` does
        // not have to grow the way it does for attome-search/attome-process/
        // attome-docgen.
        attome_document::openapi(),
        crate::communication::openapi_fragment(),
        attome_notification::admin::openapi_fragment(),
        crate::webcrawl_admin::openapi_fragment(),
        attome_content::admin::openapi_fragment(),
        crate::content_public::openapi_fragment(),
        crate::service_public::openapi_fragment(),
        attome_content::space_admin::openapi_fragment(),
        attome_content::template_admin::openapi_fragment(),
        attome_s2s::admin::openapi_fragment(),
        attome_events::admin::openapi_fragment(),
        attome_audit::admin::openapi_fragment(),
        crate::audit_read::openapi_fragment(),
        attome_compliance::erasure_admin::openapi_fragment(),
        attome_compliance::retention_admin::openapi_fragment(),
        attome_compliance::dsr_admin::openapi_fragment(),
        attome_compliance::legal_hold_admin::openapi_fragment(),
        attome_compliance::governance_admin::openapi_fragment(),
        attome_compliance::rewrap_admin::openapi_fragment(),
        attome_compliance::consent_admin::openapi_fragment(),
        attome_compliance::archive_admin::openapi_fragment(),
        attome_compliance::legal_matter_admin::openapi_fragment(),
        crate::jobs_admin::openapi_fragment(),
        crate::email_admin::openapi_fragment(),
        crate::license_admin::openapi_fragment(),
        crate::approval_admin::openapi_fragment(),
        crate::approval_metrics::openapi_fragment(),
        crate::approval_policy_admin::openapi_fragment(),
        crate::signoff::openapi_fragment(),
        crate::profiler_admin::openapi_fragment(),
        crate::system_health::openapi_fragment(),
        crate::autonumber_admin::openapi_fragment(),
        crate::api_usage_admin::openapi_fragment(),
        crate::changes_admin::openapi_fragment(),
        crate::relationship_admin::openapi_fragment(),
        crate::quality_admin::openapi_fragment(),
        crate::business_rule_admin::openapi_fragment(),
        crate::omnichannel_metrics::openapi_fragment(),
    ] {
        doc.merge(fragment);
    }
    doc
}
