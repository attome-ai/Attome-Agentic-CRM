//! D-383 — every entity a licensed engine provisions must be declared in that
//! engine's `EngineModel::owned_entities`, so generic entity CRUD
//! (`/api/v1/{entity}`) applies the same module/tier licence check the
//! engine's own routes already get from `ModelRegistry::mounted_routes`.
//!
//! The hole this closes (review §2.2 / SEC-5): entity provisioning runs
//! unconditionally at boot regardless of licence, while `entity_crud::routes()`
//! is gated on `MODULE_CORE` alone. A paid engine's raw records were therefore
//! readable and writable through the generic path on a licence that never
//! included that module, even though the engine's bespoke routes were
//! correctly hidden.
//!
//! `seeds_without_a_declared_owner_are_either_gated_or_listed_here` is the
//! part that keeps it closed: it reads every seed-shaped source file in the
//! workspace, extracts the entities each one provisions, and fails on any
//! entity that is neither claimed by an engine nor explicitly recorded below
//! as core/ungated. A new engine that seeds an entity and forgets to declare
//! it fails this test rather than shipping a silent licence hole.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use attome_core::{EngineModel, EntityModuleMap, EntityModuleOwner};
use attome_modules::{
    MODULE_AI, MODULE_AUDIT, MODULE_CORE, MODULE_DASHBOARD, MODULE_DOCGEN, MODULE_DOCUMENT,
    MODULE_GRC, MODULE_INTEGRATION, MODULE_NOTIFICATION, MODULE_PROJECT, MODULE_REPORT,
    MODULE_SERVICE, MODULE_WORKFLOW, ModuleId, ModuleSet,
};

/// Entities provisioned by a seed that has **no** owning `EngineModel`, and whose
/// routes are correspondingly **not** licence-gated anywhere today.
///
/// Gating these would not be closing SEC-5, it would be inventing new
/// licensing policy — a product decision, not a security fix. They are listed
/// (not silently skipped) so the next person sees the choice was made rather
/// than missed. If any of these features ever gains a licence gate on its own
/// routes, its entities belong in an engine's `owned_entities` at the same
/// time.
const UNGATED_BY_DESIGN: &[(&str, &str)] = &[
    // Core platform tables — already covered by the MODULE_CORE gate on
    // `entity_crud::routes()`, so a second check would be redundant.
    ("organization", "core platform (attome-security seed)"),
    ("team", "core platform (attome-security seed)"),
    ("user_account", "core platform (attome-security seed)"),
    (
        "user_account_mm_team",
        "core platform (attome-security seed)",
    ),
    ("privilege", "core platform (attome-security seed)"),
    (
        "user_account_mm_privilege",
        "core platform (attome-security seed)",
    ),
    ("role", "core platform (attome-security seed)"),
    ("api_key", "core platform (server apikey_seed)"),
    ("license", "core platform (attome-api license_seed)"),
    ("note", "core platform (attome-api note_seed)"),
    ("activity", "core platform (attome-api activity bundle)"),
    ("autovalue", "core platform (attome-metadata autovalue)"),
    ("saved_search", "core platform (saved searches)"),
    (
        "webportal",
        "attome-portal claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "webportal_user",
        "attome-portal claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "profiler_finding",
        "attome-profiler has no EngineModel/licence gate (attome-api profiler_finding_seed) — \
         PROFILER-2026-09-09.md group G",
    ),
    (
        "communication",
        "core platform (attome-api communication_seed)",
    ),
    (
        "communication_event",
        "core platform (attome-api communication_event_seed) — child of communication above",
    ),
    (
        "glossary_term",
        "core platform (attome-api glossary_seed) — reachable under MODULE_CORE, no separate gate",
    ),
    (
        "record_relationship",
        "core platform (attome-api relationship_seed)",
    ),
    ("follow", "core platform (attome-api follow_seed)"),
    ("resource_skill", "core platform (attome-api resource_seed)"),
    (
        "resource_availability",
        "core platform (attome-api resource_seed)",
    ),
    ("tag_category", "core platform (attome-api tag_seed)"),
    ("tag_item", "core platform (attome-api tag_seed)"),
    (
        "reminder",
        "core platform (platform-bundles/xrm-reminder.json, D-602)",
    ),
    (
        "scan_action",
        "core platform (platform-bundles/attome-scan.json, B16-T7)",
    ),
    // Engines with no EngineModel impl and no licence gate on their routes.
    (
        "audit_header",
        "attome-audit has no EngineModel; audit routes are not gated",
    ),
    (
        "audit_detail",
        "attome-audit has no EngineModel; audit routes are not gated",
    ),
    (
        "audit_snapshot",
        "attome-audit has no EngineModel; audit routes are not gated",
    ),
    (
        "audit_config",
        "attome-audit has no EngineModel; audit routes are not gated",
    ),
    (
        "s2s_client",
        "s2s_admin.rs is admin-gated, not licence-gated",
    ),
    (
        "s2s_permission",
        "s2s_admin.rs is admin-gated, not licence-gated",
    ),
    (
        "s2s_access_log",
        "s2s_admin.rs is admin-gated, not licence-gated",
    ),
    (
        "knowledge_data_source",
        "D-365: webcrawl deliberately has no module bit",
    ),
    (
        "knowledge_data_item",
        "D-365: webcrawl deliberately has no module bit",
    ),
    (
        "authentication_type",
        "core reference data (Master List) — a reusable Value/Purpose lookup \
         not owned by any single engine, same posture as tag_category/ \
         glossary_term above",
    ),
    (
        "contract_version",
        "attome-contract claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "contract_comparison",
        "attome-contract claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "contract_import",
        "attome-contract claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "contract_playbook_rule",
        "attome-contract claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "call_analysis",
        "attome-callintel claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "call_tracker",
        "attome-callintel claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "call_finding",
        "attome-callintel claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "call_scorecard",
        "attome-callintel claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "call_scorecard_answer",
        "attome-callintel claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "call_comment",
        "attome-callintel claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "call_library",
        "attome-callintel claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "call_library_item",
        "attome-callintel claims it through EngineModel::owned_entities at runtime",
    ),
    (
        "call_daily_aggregate",
        "attome-callintel claims it through EngineModel::owned_entities at runtime",
    ),
];

fn owner(model_name: &'static str, module_id: ModuleId) -> EntityModuleOwner {
    EntityModuleOwner {
        model_name,
        module_id,
    }
}

/// Mirrors what `ModelRegistry::entity_modules()` produces at boot. Kept in
/// this test rather than reaching into `attome-api`'s private registry, and
/// pinned against the real engines by
/// `the_real_engines_declare_exactly_these_entities` below.
fn production_map() -> EntityModuleMap {
    let mut map = EntityModuleMap::new();
    map.claim(
        "workflow_definition",
        owner("attome-workflow", MODULE_WORKFLOW),
    );
    map.claim(
        "notification_template",
        owner("attome-notification", MODULE_NOTIFICATION),
    );
    // M25 Phase 1 (Report, D-440) — attome_report/report_schedule. D-479
    // (M26 R-09) removed the legacy `dashboard` entity this map used to also
    // claim under the same module — it is no longer bundled/owned by any
    // engine.
    for entity in ["attome_report", "report_schedule"] {
        map.claim(entity, owner("attome-report", MODULE_REPORT));
    }
    for entity in [
        "attome_project",
        "project_team",
        "project_work_item",
        "project_work_item_dependency",
        "project_baseline",
        "project_baseline_item",
        "project_resource_rate",
        "project_timesheet",
        "project_time_entry",
        "project_deliverable",
        "project_issue",
        "project_change_request",
        "project_meeting",
        "project_lesson",
        "project_template",
        "project_portfolio",
        "project_program",
        // M72 Resource Management — capacity heat grid.
        "resource_allocation",
    ] {
        map.claim(entity, owner("attome-project", MODULE_PROJECT));
    }
    // M73/D-422 adds `service_sla_clock` alongside the rest of attome-service's
    // owned entities.
    for entity in [
        "service_work_request",
        "service_ticket",
        "service_sla_policy",
        "service_offering",
        "service_sla_clock",
        // D-517 — append-only SLA calculation evidence.
        "service_sla_calculation",
        // M84 Phase 1 (Queue Management, D-464) — already in attome-service's
        // real `owned_entities()` since that shipped; this fixture was
        // never updated to match (found by REVIEW-2026-09-02 follow-up
        // verification — a stale-fixture gap, not a live license-gate leak,
        // confirmed by reproducing the same failure against the pre-batch
        // baseline commit in an isolated worktree).
        "service_work_queue",
        "service_work_queue_member",
    ] {
        map.claim(entity, owner("attome-service", MODULE_SERVICE));
    }
    for entity in [
        "attome_dashboard",
        "dashboard_version",
        "dashboard_page",
        "dashboard_section",
        "dashboard_section_breakpoint",
        "dashboard_widget",
        "dashboard_variable",
        "dashboard_parameter",
        // M28 Phase 1 (Decision Intelligence, D-420) — `attome_ai::decision`'s
        // own `DecisionExecutionModel` owns no entities of its own; these stay
        // claimed by `attome-dashboard` (see that crate's `model.rs` comment).
        "dashboard_decision",
        "dashboard_decision_option",
        "dashboard_decision_dependency",
        // M48 Phase 1 (Scenario & Simulation scaffolding, D-453) —
        // metadata-seeded alongside the rest of attome-dashboard's owned
        // entities; see attome_dashboard::model's own comment.
        "dashboard_scenario",
        "dashboard_scenario_assumption",
        "dashboard_scenario_metric",
        "dashboard_scenario_result",
    ] {
        map.claim(entity, owner("attome-dashboard", MODULE_DASHBOARD));
    }
    // M27 Phase 1 (KPI & Metrics, D-407) — split out of attome-dashboard into
    // its own `attome-metric` crate/`MetricModel` (D-480, M26 R-14); still
    // gated on `MODULE_DASHBOARD`, same bit as attome-dashboard itself.
    for entity in [
        "dashboard_metric_definition",
        "dashboard_metric_target",
        "metric_scorecard",
        "metric_scorecard_item",
        "metric_comment",
    ] {
        map.claim(entity, owner("attome-metric", MODULE_DASHBOARD));
    }
    // M59 Phase 1 — shares MODULE_INTEGRATION with attome-events' admin
    // surface (D-403's precedent for that bit covering more than one
    // engine; attome-events has no EngineModel of its own).
    for entity in ["integration_system", "integration_event"] {
        map.claim(entity, owner("attome-integration", MODULE_INTEGRATION));
    }
    // M20 Phase 1 (D-427) — attome-grc's owned entities. Deliberately does NOT
    // include `project_issue`: attome-grc only adds an additive `risk_ref`
    // attribute to that already attome-project-owned entity (see
    // `attome_grc::model::GrcModel::owned_entities`'s own doc comment).
    for entity in [
        "grc_regulation",
        "grc_requirement",
        "grc_control",
        "grc_control_requirement",
        "grc_assessment",
        "grc_assessment_item",
        "grc_finding",
        "grc_evidence",
        "grc_risk",
        "grc_risk_dependency",
        "grc_policy",
        "grc_policy_ack",
        "grc_regulatory_change",
        "grc_regulatory_change_link",
    ] {
        map.claim(entity, owner("attome-grc", MODULE_GRC));
    }
    // D-435, simplified by D-491 (M34 AI Governance) — `ai_model` (the
    // AI Model catalog, carrying its own `approval_status`; the separate
    // `ai_model_approval` registry entity this comment used to describe
    // is removed) is metadata-seeded by
    // `platform-bundles/attome-ai-model-catalog.json` (no Rust seed), applied
    // from `boot.rs` after `attome-ai-provider`. See `model_registry.rs`'s
    // module doc.
    map.claim("ai_model", owner("attome-ai", MODULE_AI));
    // M32 Phase 1 (AI Agent Platform, D-450) — `ai_agent` is metadata-seeded
    // by `platform-bundles/attome-ai-agent.json`, applied from `crates/server/
    // src/boot.rs` for the same reason as `ai_model` above.
    map.claim("ai_agent", owner("attome-ai", MODULE_AI));
    // D-505 — `ai_agent_policy`, the reusable governance policy an
    // agent references through `policy_ref`, seeded by the same bundle.
    map.claim("ai_agent_policy", owner("attome-ai", MODULE_AI));
    // C6 (D-556) — `ai_capability_pack`, a named, versioned set of action
    // ids a policy references, metadata-seeded by
    // `platform-bundles/attome-ai-capability-pack.json` (applied from
    // `crates/server/src/boot.rs`). Same reason as the policy above: its raw
    // records must not stay readable/writable through the generic path on a
    // licence holding only MODULE_CORE.
    map.claim("ai_capability_pack", owner("attome-ai", MODULE_AI));
    // `ai_provider` — provider connection catalog (name, type, endpoint,
    // status/health, capabilities), metadata-seeded
    // by `platform-bundles/attome-ai-provider.json`, applied from `boot.rs`
    // alongside the other attome-ai bundles for the same reason given above.
    map.claim("ai_provider", owner("attome-ai", MODULE_AI));
    // `ai_personality`/`ai_tone` — reusable persona/tone vocabulary
    // for `ai_agent`'s many-to-many relationships, metadata-seeded by
    // `platform-bundles/attome-ai-personality.json`/`attome-ai-tone.json`, applied
    // from `boot.rs` alongside the other attome-ai bundles for the same reason
    // given above.
    map.claim("ai_personality", owner("attome-ai", MODULE_AI));
    map.claim("ai_tone", owner("attome-ai", MODULE_AI));
    // The AI agents' records (platform-bundles/attome-ai-followup.json,
    // -collections, -meeting and -work-share).
    for entity in [
        "ai_followup_rule",
        "ai_collection_rule",
        "ai_payment_promise",
        "ai_meeting_brief",
        "ai_meeting_notes",
        "ai_work_measure",
    ] {
        map.claim(entity, owner("attome-ai", MODULE_AI));
    }
    // D-383 fix (this test's own discovery) — audit_consent/audit_consent_purpose
    // (M24, D-428) and audit_legal_matter (M23, D-456) are ordinary
    // generic-CRUD entities `attome-compliance` provisions directly
    // (`consent_seed`/`legal_matter_seed`), previously reachable through
    // `/api/v1/{entity}` on any licence holding only MODULE_CORE. This
    // matches the module-bit-only `license_gate(...,
    // MODULE_AUDIT, "audit")` attome-api/system.rs already applies to
    // attome_audit::admin::routes()/M58's signoff::routes() — the generic and
    // bespoke paths must never disagree about whether a module is licensed.
    for entity in [
        "audit_consent",
        "audit_consent_purpose",
        "audit_legal_matter",
    ] {
        map.claim(entity, owner("attome-compliance", MODULE_AUDIT));
    }
    // M57 Phase 1 (Document Generation, D-463) — `docgen_template` is
    // metadata-seeded by the `attome-docgen` platform bundle, applied from
    // `crates/server/src/boot.rs` for the same reason `ai_model`/
    // `ai_agent` above are (a real, non-dev dependency on `attome-api`).
    map.claim("docgen_template", owner("attome-docgen", MODULE_DOCGEN));
    // D-486 (M55 Document Management) — extracted out of attome-api, and the
    // first thing in the workspace to gate on MODULE_DOCUMENT, which was
    // allocated and enforcing nothing before. Provisioned by
    // `platform-bundles/attome-document.json`, not a `*_seed.rs`.
    map.claim("attome_document", owner("attome-document", MODULE_DOCUMENT));
    map
}

fn licensed_for(module: ModuleId) -> ModuleSet {
    let mut bits = [0u64; 4];
    bits[module.word] |= module.mask;
    bits[MODULE_CORE.word] |= MODULE_CORE.mask;
    ModuleSet::from_bits(bits)
}

/// The exact licence the hole was reachable on: core only, nothing else.
fn core_only_license() -> ModuleSet {
    let mut bits = [0u64; 4];
    bits[MODULE_CORE.word] |= MODULE_CORE.mask;
    ModuleSet::from_bits(bits)
}

/// The same predicate `resolve.rs::require_entity_licensed` applies.
fn is_licensed(map: &EntityModuleMap, entity: &str, license: &ModuleSet) -> bool {
    match map.owner(entity) {
        None => true,
        Some(o) => license.require(o.module_id).is_ok(),
    }
}

#[test]
fn a_core_only_license_cannot_reach_any_paid_engines_entities() {
    let map = production_map();
    let license = core_only_license();

    let reachable: Vec<_> = map
        .entities()
        .filter(|e| is_licensed(&map, e, &license))
        .collect();

    assert!(
        reachable.is_empty(),
        "SEC-5 regression — a core-only licence still reaches: {reachable:?}"
    );
}

#[test]
fn core_and_customer_entities_are_unaffected_by_the_gate() {
    let map = production_map();
    let license = core_only_license();
    for entity in ["user_account", "note", "some_customer_created_entity"] {
        assert!(
            is_licensed(&map, entity, &license),
            "{entity} must stay reachable — it is not owned by any engine"
        );
    }
}

#[test]
fn the_owning_module_bit_alone_opens_exactly_its_own_entities() {
    let map = production_map();
    let license = licensed_for(MODULE_WORKFLOW);

    assert!(is_licensed(&map, "workflow_definition", &license));
    for other in ["attome_report", "attome_project", "notification_template"] {
        assert!(
            !is_licensed(&map, other, &license),
            "a workflow licence must not open {other}"
        );
    }
}

#[test]
fn an_expired_or_degraded_license_reaches_nothing() {
    let map = production_map();
    let license = ModuleSet::core_only();
    for entity in map.entities() {
        assert!(!is_licensed(&map, entity, &license), "{entity} on degraded");
    }
}

#[test]
fn two_engines_cannot_claim_the_same_entity() {
    let clash = std::panic::catch_unwind(|| {
        let mut map = EntityModuleMap::new();
        map.claim("shared", owner("engine-a", MODULE_WORKFLOW));
        map.claim("shared", owner("engine-b", MODULE_REPORT));
    });
    assert!(clash.is_err(), "a conflicting claim must panic at boot");
}

#[test]
fn re_claiming_the_same_entity_identically_is_idempotent() {
    let mut map = EntityModuleMap::new();
    map.claim("dashboard", owner("attome-report", MODULE_REPORT));
    map.claim("dashboard", owner("attome-report", MODULE_REPORT));
    assert_eq!(map.len(), 1);
}

fn repo_root() -> PathBuf {
    // crates/engine/attome-api -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root")
        .to_path_buf()
}

fn seed_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            seed_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs")
            && path
                .file_stem()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "seed" || n.ends_with("_seed"))
        {
            out.push(path);
        }
    }
}

/// Every entity name passed to `ensure_entity` in the workspace's seed files.
fn provisioned_entities() -> BTreeSet<String> {
    let mut files = Vec::new();
    seed_files(&repo_root().join("crates"), &mut files);
    assert!(
        files.len() >= 10,
        "expected to find the workspace's seed files, found {}",
        files.len()
    );

    let mut found = BTreeSet::new();
    for file in files {
        let src = std::fs::read_to_string(&file).expect("read seed file");
        let mut rest = src.as_str();
        while let Some(at) = rest.find("ensure_entity(") {
            rest = &rest[at + "ensure_entity(".len()..];
            // Skip the pool argument, then take the first string literal —
            // but only if that literal is the SECOND positional argument
            // directly (`db, "logicalname", ...`), not some later quoted
            // string reached by skipping over a bare identifier argument
            // (`db, logicalname, ...` — D-478's `seed_for_tests` helpers
            // call `ensure_entity` with a variable here, and the first
            // quote `.find('"')` would otherwise reach later in the same
            // function is unrelated content like a JSON map key literal).
            let Some(open) = rest.find('"') else { break };
            let between = &rest[..open];
            let looks_like_a_literal_call = between
                .trim()
                .trim_end_matches(',')
                .trim_end()
                .ends_with("db");
            if !looks_like_a_literal_call {
                continue;
            }
            let after = &rest[open + 1..];
            let Some(close) = after.find('"') else { break };
            let name = &after[..close];
            let looks_like_logical_name = !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit());
            assert!(
                looks_like_logical_name,
                "the first string argument to ensure_entity in {} is {name:?}, which is not a \
                 logical name — the call shape changed and this extractor needs revisiting",
                file.display()
            );
            found.insert(name.to_string());
            rest = after;
        }
    }

    // D-478 (seeds-to-bundles): entity provisioning for a growing set of
    // modules has moved from an `ensure_entity(db, "logicalname", ...)` call
    // in a `*_seed.rs` file (scanned above) to a static
    // `platform-bundles/<module>.json` bundle's `entities[].logicalname`
    // field, applied at boot via `bundle::apply_platform_bundle` instead of
    // the old imperative call. Scan those too, or every entity a converted
    // module owns falsely reads as "declared but no seed provisions it" —
    // the exact failure mode this extractor exists to prevent, now against
    // the wrong source of truth.
    let bundles_dir = repo_root().join("platform-bundles");
    if let Ok(entries) = std::fs::read_dir(&bundles_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json") {
                let src = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                let bundle: serde_json::Value = serde_json::from_str(&src)
                    .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
                if let Some(entities) = bundle["entities"].as_array() {
                    for entity in entities {
                        if let Some(name) = entity["logicalname"].as_str() {
                            found.insert(name.to_string());
                        }
                    }
                }
            }
        }
    }
    found
}

#[test]
fn seeds_without_a_declared_owner_are_either_gated_or_listed_here() {
    let map = production_map();
    let gated: BTreeSet<String> = map.entities().map(str::to_string).collect();
    let allowed: BTreeSet<String> = UNGATED_BY_DESIGN
        .iter()
        .map(|(e, _)| (*e).to_string())
        .collect();

    let unaccounted: Vec<String> = provisioned_entities()
        .into_iter()
        .filter(|e| !gated.contains(e) && !allowed.contains(e))
        .collect();

    assert!(
        unaccounted.is_empty(),
        "these entities are provisioned by a seed but are neither licence-gated nor recorded as \
         ungated-by-design: {unaccounted:?}. If the entity belongs to a licensed engine, add it \
         to that engine's EngineModel::owned_entities (D-383). If it is core, or its feature has no \
         licence gate at all, add it to UNGATED_BY_DESIGN with the reason."
    );
}

#[test]
fn every_gated_entity_is_actually_provisioned_by_a_seed() {
    let provisioned = provisioned_entities();
    let stale: Vec<String> = production_map()
        .entities()
        .filter(|e| !provisioned.contains(*e))
        .map(str::to_string)
        .collect();
    assert!(
        stale.is_empty(),
        "declared in owned_entities but no seed provisions them — stale entries: {stale:?}"
    );
}

#[test]
fn ungated_by_design_has_no_stale_or_duplicate_entries() {
    let provisioned = provisioned_entities();
    let mut seen = BTreeSet::new();
    for (entity, reason) in UNGATED_BY_DESIGN {
        assert!(
            seen.insert(*entity),
            "duplicate UNGATED_BY_DESIGN entry: {entity}"
        );
        assert!(!reason.trim().is_empty(), "{entity} needs a reason");
        assert!(
            provisioned.contains(*entity),
            "UNGATED_BY_DESIGN lists {entity}, but no seed provisions it any more — remove it"
        );
    }
}

/// Pins `production_map()` against the real engines, so the fixture above
/// cannot quietly drift from what `ModelRegistry::entity_modules()` builds.
#[test]
fn the_real_engines_declare_exactly_these_entities() {
    let models: Vec<Box<dyn EngineModel>> = vec![
        Box::new(attome_workflow::WorkflowModel),
        Box::new(attome_notification::NotificationModel),
        Box::new(attome_report::ReportModel),
        Box::new(attome_project::ProjectModel),
        Box::new(attome_service::ServiceModel),
        Box::new(attome_dashboard::DashboardModel),
        // D-480 (M26 R-14) — M27 (KPI & Metrics), split out of attome-dashboard.
        Box::new(attome_metric::MetricModel),
        Box::new(attome_integration::IntegrationModel),
        Box::new(attome_grc::GrcModel),
        // D-435 — dev-dependency only (attome-ai has a real dependency on
        // this crate, so this edge only exists in tests; see attome-api's
        // Cargo.toml dev-dependency comment).
        Box::new(attome_ai::ActionModel),
        Box::new(attome_compliance::model::ComplianceModel),
        // D-463 — dev-dependency only (attome-docgen has a real dependency on
        // this crate, so this edge only exists in tests; see attome-api's
        // Cargo.toml dev-dependency comment).
        Box::new(attome_docgen::DocgenModel),
        // D-486 — a real (non-dev) dependency of this crate, unlike the two
        // above: attome-api mounts `attome_document::files::routes()` itself.
        Box::new(attome_document::DocumentModel),
    ];

    let mut real = EntityModuleMap::new();
    for model in &models {
        let o = owner(model.name(), model.module_id());
        for entity in model.owned_entities() {
            real.claim(entity, o);
        }
    }

    let expected = production_map();
    let expected_names: BTreeSet<&str> = expected.entities().collect();
    let actual_names: BTreeSet<&str> = real.entities().collect();
    assert_eq!(
        expected_names, actual_names,
        "the engines' owned_entities no longer match this test's fixture"
    );

    for entity in actual_names {
        assert_eq!(
            expected.owner(entity),
            real.owner(entity),
            "owner mismatch for {entity}"
        );
    }
}
