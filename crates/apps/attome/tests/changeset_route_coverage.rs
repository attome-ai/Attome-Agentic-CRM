//! Solution 7 Phase 1 (D-785, design `document/general/SOLUTION-7-PHASE-1-DESIGN.md`
//! §1, §8 lane L7) — every metadata-authoring route is either recorded into a
//! changeset or a named exclusion, and the classification matches the code.
//!
//! The routes come from the committed `openapi.json` (every mounted route
//! carries a `#[utoipa::path]`, guidelines §12). In scope: every mutating
//! route under `METADATA_AUTHORING_PREFIXES` (the production authoring gate)
//! plus the §1.1 routes that live elsewhere ([`EXTRA_PREFIXES`]). Each one
//! must be in exactly one of:
//!
//! - [`RECORDED`] — with the catalogue op(s) it records (design §1.1, §3);
//! - [`EXCLUDED`] — with the reason it records nothing (design §1.3).
//!
//! Then, against the handler source found through its `#[utoipa::path]`
//! annotation:
//!
//! - a recorded route's handler takes the `RecordingCtx` extractor, and its
//!   crate names each listed op (`Op::<Variant>`);
//! - an excluded route's handler does not take it;
//! - every handler anywhere that takes `RecordingCtx` is a recorded route (so
//!   a hook added outside the prefixes is classified too).
//!
//! A new mutating route under a metadata prefix fails this test until someone
//! decides which list it belongs to. That the hooks write exactly one op per
//! change, and refuse without an open changeset in `required` mode, is proved
//! over HTTP by `crates/engine/attome-api/tests/changeset_hooks_{schema,ui,engines}.rs`
//! and `changeset_recording_order.rs`. No services needed:
//! `cargo test -p server --test changeset_route_coverage`.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use attome_core::changeset::Op;
use attome_server::middleware::authoring_gate::is_metadata_authoring_path;
use serde_json::Value;

/// §1.1 routes outside `METADATA_AUTHORING_PREFIXES`.
const EXTRA_PREFIXES: &[&str] = &[
    "/api/v1/admin/governance/domains",
    "/api/v1/process/case-defs",
    "/api/v1/admin/security/entity-default-shares",
];

/// Solution 7 Phase 2 (D-787 rule 7): the generic entity routes, in scope
/// by exact path (their siblings — bulk, restore, related, ... — are not
/// metadata authoring). A write to a reference-data entity records
/// `upsert_record` when a changeset is in play.
const EXTRA_ROUTES: &[&str] = &[
    "/api/v1/{entity}",
    "/api/v1/{entity}/{id}",
    "/api/v1/{entity}/upsert",
    // S1-T6: the same update, addressed by business key.
    "/api/v1/{entity}/key/{keyspec}",
    // B13 UI text overrides: labels are metadata a changeset carries
    // (`set_label` / `clear_label`), though the path is not an authoring
    // prefix the production gate guards.
    "/api/v1/admin/i18n/overrides",
];

/// Recorded routes and the op(s) each records (design §1.1).
const RECORDED: &[(&str, &[&str])] = &[
    // Reference data through the generic entity API (D-787 rule 7, design §1).
    ("POST /api/v1/{entity}", &["upsert_record"]),
    ("PATCH /api/v1/{entity}/{id}", &["upsert_record"]),
    ("POST /api/v1/{entity}/upsert", &["upsert_record"]),
    ("PATCH /api/v1/{entity}/key/{keyspec}", &["upsert_record"]),
    // Entities and fields (lane L3).
    ("POST /api/v1/admin/entities", &["create_entity"]),
    (
        "PATCH /api/v1/admin/entities/{entity_id}",
        &["update_entity"],
    ),
    (
        "DELETE /api/v1/admin/entities/{entity_id}",
        &["retire_entity"],
    ),
    (
        "POST /api/v1/admin/entities/{entity_id}/fields",
        &["add_field"],
    ),
    (
        "PATCH /api/v1/admin/entities/{entity_id}/fields/{field_id}",
        &["update_field", "rename_field"],
    ),
    // Solution 7 Phase 2 (D-788): the field DELETE is a real delete.
    (
        "DELETE /api/v1/admin/entities/{entity_id}/fields/{field_id}",
        &["delete_field"],
    ),
    (
        "POST /api/v1/admin/entities/{entity_id}/fields/{field_id}/rename",
        &["rename_field"],
    ),
    (
        "POST /api/v1/admin/entities/{entity_id}/fields/{field_id}/change-type",
        &["change_field_type"],
    ),
    (
        "POST /api/v1/admin/entities/{entity_id}/fields/{field_id}/choices",
        &["add_choice_value"],
    ),
    (
        "DELETE /api/v1/admin/entities/{entity_id}/fields/{field_id}/choices/{value}",
        &["remove_choice_value"],
    ),
    (
        "POST /api/v1/admin/entities/{entity_id}/labels",
        &["set_label"],
    ),
    (
        "PATCH /api/v1/admin/entities/{entity_id}/labels/{label_id}",
        &["set_label"],
    ),
    (
        "DELETE /api/v1/admin/entities/{entity_id}/labels/{label_id}",
        &["clear_label"],
    ),
    ("POST /api/v1/admin/entities/labels/xliff", &["set_label"]),
    ("PUT /api/v1/admin/i18n/overrides", &["set_label"]),
    ("DELETE /api/v1/admin/i18n/overrides", &["clear_label"]),
    (
        "POST /api/v1/admin/governance/domains",
        &["upsert_data_domain"],
    ),
    (
        "PATCH /api/v1/admin/governance/domains/{id}",
        &["upsert_data_domain"],
    ),
    (
        "POST /api/v1/admin/governance/domains/{id}/entities",
        &["set_entity_domain"],
    ),
    (
        "DELETE /api/v1/admin/governance/domains/{id}/entities/{entity_logicalname}",
        &["set_entity_domain"],
    ),
    ("POST /api/v1/admin/relationships", &["upsert_relationship"]),
    (
        "PATCH /api/v1/admin/relationships/{id}",
        &["upsert_relationship"],
    ),
    (
        "DELETE /api/v1/admin/relationships/{id}",
        &["retire_relationship"],
    ),
    // UI metadata (lane L4).
    ("POST /api/v1/admin/views", &["upsert_view"]),
    ("PATCH /api/v1/admin/views/{id}", &["upsert_view"]),
    ("DELETE /api/v1/admin/views/{id}", &["retire_view"]),
    ("POST /api/v1/admin/business-rules", &["upsert_rule"]),
    ("PATCH /api/v1/admin/business-rules/{id}", &["upsert_rule"]),
    ("DELETE /api/v1/admin/business-rules/{id}", &["retire_rule"]),
    (
        "POST /api/v1/admin/business-rules/{id}/publish",
        &["publish_rule"],
    ),
    ("POST /api/v1/sidebar/admin", &["upsert_sidebar_item"]),
    ("PATCH /api/v1/sidebar/admin/{id}", &["upsert_sidebar_item"]),
    (
        "DELETE /api/v1/sidebar/admin/{id}",
        &["retire_sidebar_item"],
    ),
    ("POST /api/v1/admin/apps", &["upsert_app"]),
    ("PATCH /api/v1/admin/apps/{id}", &["upsert_app"]),
    ("DELETE /api/v1/admin/apps/{id}", &["retire_app"]),
    ("POST /api/v1/admin/calendars", &["upsert_calendar"]),
    ("PATCH /api/v1/admin/calendars/{id}", &["upsert_calendar"]),
    ("DELETE /api/v1/admin/calendars/{id}", &["retire_calendar"]),
    (
        "POST /api/v1/admin/calendars/{id}/holidays",
        &["add_calendar_holiday"],
    ),
    (
        "DELETE /api/v1/admin/calendars/{id}/holidays/{holiday_id}",
        &["remove_calendar_holiday"],
    ),
    (
        "POST /api/v1/admin/calendars/{id}/holidays/hijri-recurring",
        &["add_calendar_holiday"],
    ),
    (
        "POST /api/v1/admin/calendars/{id}/exceptions",
        &["add_calendar_exception"],
    ),
    (
        "DELETE /api/v1/admin/calendars/{id}/exceptions/{exception_id}",
        &["remove_calendar_exception"],
    ),
    // Engines (lane L5).
    ("POST /api/v1/admin/queries", &["upsert_query"]),
    ("PATCH /api/v1/admin/queries/{id}", &["upsert_query"]),
    ("DELETE /api/v1/admin/queries/{id}", &["retire_query"]),
    ("POST /api/v1/admin/state-models", &["upsert_state_model"]),
    (
        "PATCH /api/v1/admin/state-models/{id}",
        &["upsert_state_model"],
    ),
    (
        "DELETE /api/v1/admin/state-models/{id}",
        &["retire_state_model"],
    ),
    (
        "POST /api/v1/admin/state-models/{id}/transitions",
        &["upsert_state_transition"],
    ),
    (
        "PATCH /api/v1/admin/state-models/{id}/transitions/{transition_id}",
        &["upsert_state_transition"],
    ),
    (
        "DELETE /api/v1/admin/state-models/{id}/transitions/{transition_id}",
        &["retire_state_transition"],
    ),
    ("POST /api/v1/workflow/definitions", &["upsert_workflow"]),
    (
        "PATCH /api/v1/workflow/definitions/{id}",
        &["upsert_workflow"],
    ),
    (
        "DELETE /api/v1/workflow/definitions/{id}",
        &["retire_workflow"],
    ),
    (
        "POST /api/v1/workflow/definitions/{id}/versions",
        &["set_workflow_draft"],
    ),
    (
        "PATCH /api/v1/workflow/definitions/{id}/versions/{version_id}",
        &["set_workflow_draft"],
    ),
    (
        "POST /api/v1/workflow/definitions/{id}/versions/{version_id}/publish",
        &["publish_workflow"],
    ),
    ("POST /api/v1/process/case-defs", &["upsert_case_def"]),
    ("PATCH /api/v1/process/case-defs/{id}", &["upsert_case_def"]),
    (
        "DELETE /api/v1/process/case-defs/{id}",
        &["retire_case_def"],
    ),
    ("POST /api/v1/admin/security/roles", &["upsert_role"]),
    ("PATCH /api/v1/admin/security/roles/{id}", &["upsert_role"]),
    (
        "PUT /api/v1/admin/security/roles/{id}/position-hierarchy",
        &["upsert_role"],
    ),
    (
        "PUT /api/v1/admin/security/roles/{id}/bulk-fields",
        &["set_role_bulk_fields"],
    ),
    (
        "POST /api/v1/admin/security/role-grants",
        &["ensure_privilege", "grant_role_privilege"],
    ),
    (
        "DELETE /api/v1/admin/security/role-grants/{id}",
        &["revoke_role_privilege"],
    ),
    (
        "POST /api/v1/admin/security/role-grants/{grant_id}/conditions",
        &["add_role_grant_condition"],
    ),
    (
        "DELETE /api/v1/admin/security/role-grants/{grant_id}/conditions/{condition_id}",
        &["remove_role_grant_condition"],
    ),
    (
        "POST /api/v1/admin/security/role-entity-access",
        &["set_role_entity_access"],
    ),
    (
        "DELETE /api/v1/admin/security/role-entity-access/{id}",
        &["clear_role_entity_access"],
    ),
    (
        "POST /api/v1/admin/security/entity-default-shares",
        &["set_entity_default_share"],
    ),
    (
        "DELETE /api/v1/admin/security/entity-default-shares/{id}",
        &["remove_entity_default_share"],
    ),
    (
        "POST /api/v1/admin/security/field-profiles",
        &["upsert_field_profile"],
    ),
    (
        "POST /api/v1/admin/security/field-profiles/{id}/fields",
        &["set_field_profile_field"],
    ),
    (
        "POST /api/v1/admin/security/field-profiles/{id}/assignments",
        &["assign_field_profile"],
    ),
    (
        "DELETE /api/v1/admin/security/field-profiles/{id}/assignments/{role_id}",
        &["unassign_field_profile"],
    ),
];

/// In-scope mutating routes that record nothing, with the reason (design
/// §1.3 and §7).
const EXCLUDED: &[(&str, &str)] = &[
    (
        "DELETE /api/v1/{entity}/{id}",
        "a generic record delete: the reference-data recorder records creates and updates \
         (upsert_record, D-787 rule 7); a delete of a reference record is not a changeset op",
    ),
    (
        "POST /api/v1/admin/changesets",
        "opens a changeset: the recording's own lifecycle, not metadata (audited as a \
         Configuration event)",
    ),
    (
        "POST /api/v1/admin/changesets/{id}/close",
        "closes a changeset: the recording's own lifecycle",
    ),
    (
        "POST /api/v1/admin/changesets/{id}/abandon",
        "abandons an empty changeset: the recording's own lifecycle",
    ),
    (
        "POST /api/v1/admin/entities/{entity_id}/fields/{field_id}/runs/{run_id}/abandon",
        "abandons a failed data-step run: undoes the run's partial state (shadow column, \
         archive copies); the change itself was recorded when it started, and no catalogue \
         op undoes a run",
    ),
    (
        "POST /api/v1/admin/entities/{entity_id}/scaffold-ui",
        "writes Angular files in a debug build; no metadata (§1.3)",
    ),
    (
        "POST /api/v1/admin/entities/{entity_id}/orphans/scan",
        "queues a read-only orphan scan (Y2-T4); no metadata changes",
    ),
    (
        "POST /api/v1/admin/queries/describe",
        "describes a draft query's columns; reads only",
    ),
    (
        "POST /api/v1/admin/business-rules/{id}/test",
        "dry-runs a rule against a sample record; writes nothing",
    ),
    (
        "POST /api/v1/admin/business-rules/validate",
        "validates a rule body; writes nothing",
    ),
    (
        "POST /api/v1/workflow/definitions/{id}/versions/{version_id}/simulate",
        "simulates a workflow version; writes nothing",
    ),
];

const MUTATING: &[&str] = &["post", "put", "patch", "delete"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn in_scope(path: &str) -> bool {
    EXTRA_ROUTES.contains(&path)
        || is_metadata_authoring_path(path)
        || EXTRA_PREFIXES
            .iter()
            .any(|p| path == *p || path.starts_with(&format!("{p}/")))
}

/// Every mutating operation in the committed `openapi.json`, as
/// `"METHOD /path"`.
fn mutating_routes() -> BTreeSet<String> {
    let path = workspace_root().join("openapi.json");
    let doc: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}")),
    )
    .expect("openapi.json parses");
    let mut out = BTreeSet::new();
    for (route, item) in doc["paths"].as_object().expect("paths") {
        for method in item.as_object().expect("path item").keys() {
            if MUTATING.contains(&method.as_str()) {
                out.insert(format!("{} {route}", method.to_uppercase()));
            }
        }
    }
    out
}

/// One `#[utoipa::path]`-annotated handler found in the sources.
struct Handler {
    route: String,
    file: PathBuf,
    name: String,
    signature: String,
}

fn rust_sources(dir: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != "tests" && name != "node_modules" {
                rust_sources(&path, into);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            into.push(path);
        }
    }
}

/// The attribute's HTTP method and path, from `#[utoipa::path(<method>, …,
/// path = "…", …)]`.
fn method_and_path(attr: &str) -> Option<(String, String)> {
    let body = attr.strip_prefix("#[utoipa::path(")?;
    let method: String = body
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    let at = attr.find("path = \"")? + "path = \"".len();
    let path: String = attr[at..].chars().take_while(|c| *c != '"').collect();
    (!method.is_empty()).then(|| (method.to_uppercase(), path))
}

/// Whether a trimmed source line starts a function item.
fn fn_name(line: &str) -> Option<String> {
    let mut rest = line;
    for prefix in ["pub(crate) ", "pub(super) ", "pub ", "async ", "fn "] {
        if let Some(r) = rest.strip_prefix(prefix) {
            rest = r;
            if prefix == "fn " {
                return Some(
                    rest.chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect(),
                );
            }
        }
    }
    None
}

fn handlers() -> Vec<Handler> {
    let mut files = Vec::new();
    rust_sources(&workspace_root().join("crates"), &mut files);
    let mut out = Vec::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            if !lines[i].trim_start().starts_with("#[utoipa::path(") {
                i += 1;
                continue;
            }
            // The attribute runs until the function it annotates.
            let mut attr = String::new();
            let mut j = i;
            let mut name = None;
            while j < lines.len() {
                if let Some(n) = fn_name(lines[j].trim_start()) {
                    name = Some(n);
                    break;
                }
                attr.push_str(lines[j].trim());
                attr.push(' ');
                j += 1;
            }
            let (Some(name), Some((method, path))) = (name, method_and_path(&attr)) else {
                i = j.max(i + 1);
                continue;
            };
            let mut signature = String::new();
            while j < lines.len() {
                signature.push_str(lines[j].trim());
                signature.push(' ');
                if lines[j].trim_end().ends_with('{') {
                    break;
                }
                j += 1;
            }
            out.push(Handler {
                route: format!("{method} {path}"),
                file: file.clone(),
                name,
                signature,
            });
            i = j + 1;
        }
    }
    out
}

fn takes_recording(h: &Handler) -> bool {
    h.signature.contains("RecordingCtx")
}

/// `upsert_state_transition` -> `UpsertStateTransition`.
fn variant(op: &str) -> String {
    op.split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}

/// The `src` directory of the crate `file` belongs to.
fn crate_src(file: &Path) -> PathBuf {
    let mut dir = file.parent().map(Path::to_path_buf).unwrap_or_default();
    while dir.file_name().is_some_and(|n| n != "src") {
        match dir.parent() {
            Some(p) => dir = p.to_path_buf(),
            None => break,
        }
    }
    dir
}

fn crate_text(src: &Path) -> String {
    let mut files = Vec::new();
    rust_sources(src, &mut files);
    files
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_lists_name_real_distinct_catalogue_ops() {
    let mut seen = BTreeSet::new();
    for (route, ops) in RECORDED {
        assert!(seen.insert(*route), "{route} is listed twice");
        assert!(!ops.is_empty(), "{route} records no op");
        for op in *ops {
            let parsed = Op::parse(op).unwrap_or_else(|| panic!("{route}: {op} is not a v1 op"));
            assert!(
                parsed.stage() <= attome_core::changeset::model::SUPPORTED_STAGE,
                "{route}: {op} is of a stage this release does not record"
            );
        }
    }
    for (route, reason) in EXCLUDED {
        assert!(seen.insert(*route), "{route} is listed twice");
        assert!(!reason.trim().is_empty(), "{route}: give the reason");
    }
}

#[test]
fn every_in_scope_mutating_route_is_recorded_or_a_named_exclusion() {
    let routes = mutating_routes();
    let scoped: Vec<&String> = routes
        .iter()
        .filter(|r| r.split_once(' ').is_some_and(|(_, path)| in_scope(path)))
        .collect();
    assert!(
        scoped.len() > 50,
        "found only {} in-scope routes in openapi.json; the scope filter is broken",
        scoped.len()
    );
    let mut problems = Vec::new();
    for route in &scoped {
        let recorded = RECORDED.iter().any(|(r, _)| r == route);
        let excluded = EXCLUDED.iter().any(|(r, _)| r == route);
        if recorded == excluded {
            problems.push(format!(
                "{route}: must be in exactly one of RECORDED or EXCLUDED (design §1.1 / §1.3)"
            ));
        }
    }
    for route in RECORDED
        .iter()
        .map(|(r, _)| *r)
        .chain(EXCLUDED.iter().map(|(r, _)| *r))
    {
        if !routes.contains(route) {
            problems.push(format!(
                "{route}: listed here but not a mutating route in openapi.json"
            ));
        } else if !route.split_once(' ').is_some_and(|(_, p)| in_scope(p)) {
            problems.push(format!(
                "{route}: listed here but outside the metadata-authoring scope"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn recorded_handlers_take_the_recorder_and_excluded_ones_do_not() {
    let handlers = handlers();
    assert!(
        handlers.len() > 200,
        "found only {} annotated handlers; the source scan is broken",
        handlers.len()
    );
    let mut problems = Vec::new();

    for (route, ops) in RECORDED {
        let found: Vec<&Handler> = handlers.iter().filter(|h| h.route == *route).collect();
        if found.is_empty() {
            problems.push(format!(
                "{route}: no #[utoipa::path] handler found in crates/"
            ));
            continue;
        }
        let Some(hooked) = found.iter().find(|h| takes_recording(h)) else {
            problems.push(format!(
                "{route}: handler `{}` ({}) does not take RecordingCtx, so it records nothing",
                found[0].name,
                found[0].file.display()
            ));
            continue;
        };
        let text = crate_text(&crate_src(&hooked.file));
        for op in *ops {
            let needle = format!("Op::{}", variant(op));
            if !text.contains(&needle) {
                problems.push(format!(
                    "{route}: its crate ({}) never names {needle}",
                    crate_src(&hooked.file).display()
                ));
            }
        }
    }

    for (route, _) in EXCLUDED {
        for h in handlers.iter().filter(|h| h.route == *route) {
            if takes_recording(h) {
                problems.push(format!(
                    "{route}: listed as EXCLUDED but `{}` takes RecordingCtx; move it to RECORDED",
                    h.name
                ));
            }
        }
    }

    for h in handlers.iter().filter(|h| takes_recording(h)) {
        if !RECORDED.iter().any(|(r, _)| *r == h.route) {
            problems.push(format!(
                "{}: `{}` ({}) takes RecordingCtx but is not in RECORDED",
                h.route,
                h.name,
                h.file.display()
            ));
        }
    }

    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
