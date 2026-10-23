//! `attome-api` must not regrow: a ratchet over its top-level module list.
//!
//! # Why this guard exists
//!
//! PLATFORM-REVIEW-2026-08-24 ARCH-9. `crates/engine/attome-api` is meant to be
//! *composition* — the `ModelRegistry`, the router assembly in `system.rs`,
//! the OpenAPI merge, the metrics/probe supervisors — with every engine's
//! handlers living in the crate that owns the concept. In practice it had
//! become the path of least resistance: a new admin surface landed as one
//! more `mod foo_admin;` here, because nothing said no. The extraction
//! programme (ARCH-2 content, ARCH-3 s2s, ARCH-4 notification, ARCH-5
//! compliance) is spending real effort moving those back out, and each
//! move edits the same three mount points (`lib.rs`, `system.rs`,
//! `openapi.rs`), so a module that regrows in the meantime is not a small
//! cost: it re-serialises the whole programme.
//!
//! ARCH-9 was first written as "extend `layer-guard`". It cannot be:
//! `layer-guard` (a CI job, now retired) parsed `Cargo.toml` *dependencies*
//! and had no view of modules at all. This repo's established idiom for an inventory
//! ratchet is a Rust test beside the other drift guards
//! (`orphan_source_files.rs`, `crate_list_drift.rs`, `doc_freshness.rs`),
//! which is what DOC-1 chose over a workflow job, and what this is.
//!
//! # What this test proves
//!
//! The set of top-level `mod` declarations in `attome-api/src/lib.rs` is
//! exactly [`BASELINE`]. Two failure modes, deliberately asymmetric:
//!
//! - **A module not in the baseline** is the regrowth this exists to stop.
//!   The fix is almost never "add it to the list": it is to put the handlers
//!   in their owning engine crate and mount the bundle from `system.rs` the
//!   way `attome_compliance::*::routes()` / `attome_notification::admin::routes()`
//!   are. Only genuine composition — wiring that must see every engine —
//!   belongs here, and adding one to the baseline should come with a
//!   one-line justification in the same commit.
//! - **A baseline module that no longer exists** means an extraction landed.
//!   Shrink the baseline in the same commit. The list only ever gets
//!   shorter; that is what makes it a ratchet rather than an inventory.
//!
//! # Baseline
//!
//! Frozen 2026-08-25, immediately after ARCH-5, at 33 modules. It is a
//! snapshot of what exists, not an endorsement: several entries are the
//! subject of open review items (ARCH-1's entity CRUD/query set, ARCH-6's
//! files pair, ARCH-4's `webcrawl_admin`) and are expected to leave. The
//! review's own sequencing note was right that a regrowth ratchet is most
//! valuable *during* the extraction window, which is why the baseline is
//! taken now rather than after ARCH-1 — re-baseline downward as each move
//! lands.
//!
//! `api_usage_admin` added 2026-08-28 (M61 Phase 1, D-438) — one small
//! self-contained read-only admin surface (`GET
//! /api/v1/admin/api-usage/summary`), same shape as the already-baselined
//! `jobs_admin`/`email_admin`/`license_admin`/`profiler_admin`: no existing
//! engine crate owns "API usage analytics" as a concept, and adding a
//! fifth single-purpose `*_admin` module to a baseline that already
//! contains four is a materially smaller cost than standing up a new engine
//! crate for one endpoint.
//!
//! # v2 re-baseline (2026-10-14)
//!
//! v1's `xrm-server` crate is `attome-api` in v2 and it absorbed the handler
//! modules of several v1 engine crates when the workspace was laid out in
//! three layers, so the module list is longer than the 33 frozen above. The
//! baseline below is the v2 snapshot, taken as the new starting point for the
//! same ratchet: it only ever shrinks as handlers move to their owning engine
//! crate.
//!
//! # Scope and limits
//!
//! Reads `lib.rs` only, literally: `mod name;` with any visibility prefix,
//! attributes stripped, `//` comments skipped. Inline `mod name { … }` blocks
//! and nested modules inside `admin/`, `bundle/`, `entity_crud/` are out of
//! scope — growth *inside* an existing directory module is a different
//! (smaller) problem, and `orphan_source_files.rs` already guarantees every
//! file is at least compiled. Nothing here needs a database.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Every top-level module `attome-api/src/lib.rs` is allowed to declare.
/// Keep sorted; the assertion below is set-based, but a sorted list makes the
/// diff of a re-baseline reviewable.
const BASELINE: &[&str] = &[
    "admin",
    "admin_hooks",
    "api_usage_admin",
    "app_admin",
    "approval_admin",
    "approval_metrics",
    "approval_policy_admin",
    // M9-T1: approval processes sit on attome-approval like the policies
    // beside them, with the record engine's lock; no one engine owns both.
    // M9-T3: emailed approval links over attome-approval's requests.
    "approval_email",
    "approval_process",
    "audit_read",
    // A4-T5: the gap report reads the autonumber sequence tables directly;
    // attome-metadata has no route or admin-guard dependency to host it.
    "autonumber_admin",
    "bootstrap_admin",
    "bulk_transform",
    "bundle",
    "business_rule_admin",
    "business_rule_hooks",
    "calendar_admin",
    "capability_probe",
    "catalog_admin",
    "changes_admin",
    "changeset",
    "communication",
    "content_public",
    // Z15-T13: the customer test admin routes; the store and runner live in
    // attome-records, which has no admin-guard routes to host them.
    "customer_test_admin",
    "data_export",
    "data_mapping_admin",
    "data_profile_admin",
    // M5-T2: the dead-letter inbox composes the sources of attome-jobs (in
    // jobs_admin), attome-workflow and attome-events; no one engine owns them.
    "dead_letter_inbox",
    // Y9-T2: the deployment's OpenAPI document reads every engine's live
    // registry at once, which is composition.
    "deployment_openapi",
    "duplicates_admin",
    "duplicates_match",
    "email_admin",
    // A30-T1: values of the `environment_variable` model kind, which the
    // changeset and model admin here define; no engine crate owns kinds.
    "env_variable_admin",
    "features_admin",
    "field_changes",
    "field_hooks",
    "jobs_admin",
    "license_admin",
    "limits_admin",
    "live",
    // C4-T1: belongs in attome-notification; kept here until that crate
    // takes a record-access (attome-security) dependency.
    "mentions",
    "metadata_label_admin",
    "metrics",
    "migration",
    "model_admin",
    "model_health",
    "my_work",
    "my_work_approvals",
    "my_work_decisions",
    "my_work_project",
    "my_work_service",
    "my_work_workflow",
    "omnichannel_metrics",
    "openapi",
    "profiler_admin",
    "quality_admin",
    // L2-T5/L2-T6: Arabic checks and fix transforms beside quality_admin and
    // quality_score, which they extend; the three move out together.
    "quality_arabic",
    "quality_fixes",
    "quality_score",
    // Q20-T5: the bans live in attome-server's rate limiter; belongs in
    // attome-security's admin routes, kept here until it moves.
    "ratelimit_admin",
    "registry",
    "relationship_admin",
    "reminder_access",
    "rule_admin",
    // AC7-T11: the bill of materials embedded by this crate's build.rs and
    // the packs in this crate's changeset ledger.
    "sbom_admin",
    "schema",
    // M12-T3: one list over flow, report and platform schedules.
    "schedules_admin",
    // M14-T1: builder-defined inbound endpoints.
    "inbound_hooks",
    "seed_support",
    // M7-T2/T3: stage processes read for forms and measured from stage_move.
    "stage_process_api",
    "service_public",
    "settings_admin",
    // AA9-T6: the limits registry spans every engine (rate classes, bulk,
    // query time), so its read surface sits where they are composed.
    "sidebar",
    "sidebar_seed",
    "signoff",
    // AA13-T8: the SLO store is attome-server's; an ops surface beside
    // `metrics` and `system_health`, which no engine owns.
    "slo_admin",
    "system",
    "system_health",
    // Y2-T8: reads the statistics views for every entity table, which needs
    // the registry this crate composes; no engine crate owns table storage.
    "table_health",
    "tag_seed",
    "view_admin",
    "webcrawl_admin",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root is three levels above crates/apps/attome")
        .to_path_buf()
}

/// Drops any leading `#[...]` attributes (nesting-aware) so `#[cfg(test)] mod
/// tests;` on one line is seen the same as on two.
fn strip_attributes(line: &str) -> &str {
    let mut rest = line.trim();
    while rest.starts_with("#[") {
        let mut depth = 0usize;
        let mut end = None;
        for (i, ch) in rest.char_indices() {
            match ch {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { break };
        rest = rest[end + 1..].trim();
    }
    rest
}

/// The `mod name;` declarations of one source file, in file order.
fn top_level_mods(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in source.lines() {
        let line = strip_attributes(raw);
        if line.starts_with("//") {
            continue;
        }
        // `pub mod x;`, `pub(crate) mod x;`, `mod x;` — anything else
        // (`use`, `const`, an inline `mod x {`) is not a file module.
        let Some(after_vis) = line
            .strip_prefix("pub(crate) ")
            .or_else(|| line.strip_prefix("pub(super) "))
            .or_else(|| line.strip_prefix("pub "))
            .or(Some(line))
        else {
            continue;
        };
        if let Some(decl) = after_vis.strip_prefix("mod ")
            && let Some(name) = decl.strip_suffix(';')
        {
            out.push(name.trim().to_string());
        }
    }
    out
}

#[test]
fn server_top_level_modules_match_the_arch9_baseline() {
    let lib = workspace_root().join("crates/engine/attome-api/src/lib.rs");
    let source =
        fs::read_to_string(&lib).unwrap_or_else(|e| panic!("cannot read {}: {e}", lib.display()));

    let declared: BTreeSet<String> = top_level_mods(&source).into_iter().collect();
    let baseline: BTreeSet<String> = BASELINE.iter().map(|s| s.to_string()).collect();

    let grown: Vec<&String> = declared.difference(&baseline).collect();
    let gone: Vec<&String> = baseline.difference(&declared).collect();

    assert!(
        grown.is_empty(),
        "attome-api/src/lib.rs declares top-level module(s) not in ARCH-9's baseline: {grown:?}.\n\
         attome-api is composition, not a home for handlers. Put the new surface in the \
         engine crate that owns its concept (content -> attome-content, s2s -> attome-s2s, \
         notification -> attome-notification, retention/DSR/legal hold/erasure/rewrap -> \
         attome-compliance, security -> attome-security, ...) and mount its `routes()` / \
         `openapi_fragment()` from system.rs and openapi.rs like the existing \
         `attome_compliance::*` bundles. If it is genuinely composition — wiring that must \
         see every engine at once — add it to BASELINE in this test with a one-line \
         justification in the same commit."
    );
    assert!(
        gone.is_empty(),
        "ARCH-9's baseline lists module(s) attome-api/src/lib.rs no longer declares: {gone:?}.\n\
         An extraction landed — good. Remove the entry from BASELINE in the same commit so \
         the ratchet stays truthful; the list only shrinks."
    );
}

#[test]
fn baseline_is_sorted_and_unique() {
    let mut sorted = BASELINE.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        BASELINE,
        sorted.as_slice(),
        "keep BASELINE sorted and free of duplicates so a re-baseline diffs cleanly"
    );
}

#[test]
fn parser_reads_every_declaration_shape() {
    let src = "\
mod plain;
pub mod public;
pub(crate) mod crate_vis;
#[cfg(test)] mod inline_attr;
#[cfg(all(test, feature = \"x\"))]
mod attr_above;
// mod commented_out;
/// doc mentioning `mod not_a_decl;`
mod inline_block {
    pub fn f() {}
}
pub use something::Else;
";
    assert_eq!(
        top_level_mods(src),
        ["plain", "public", "crate_vis", "inline_attr", "attr_above"]
    );
}
