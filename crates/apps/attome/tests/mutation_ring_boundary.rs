//! M01 Core C-10 ("One `commit_mutation` ring helper") — the source-scan grep
//! gate its own plan text calls for, same shape as
//! `advisory_lock_namespaces.rs` next door: a compile-time-cheap structural
//! check that needs no database, so it runs in every `cargo test -p server`.
//!
//! # What this checks, and why it is scoped the way it is
//!
//! C-10's "Problem" enumerated an exact, closed set of sites that duplicated
//! the 4-line `AuditService::new(..).with_ingest_capture(..)
//! .with_chainer_enabled(..).with_erasure_key(..)` builder as part of the
//! mutation-commit orchestration (creator share → file mirror → audit →
//! commit → cache invalidation → rw-pin): 10 call sites inside
//! `attome-records` (`entity_crud/mutations.rs` ×6, `upsert.rs`,
//! `related.rs` ×2, `merge.rs`), plus one each in
//! `attome-api/src/communication.rs` and `attome-workflow/src/scheduler.rs`. All
//! twelve now go through `attome_records::mutation_ring::MutationRing`
//! (the common one-row-one-audit-event shape, `commit_mutation`) or its
//! batch sibling `commit_events` (`merge.rs`'s two-event case) — both of
//! which build the audit service exactly once, via the already-existing
//! canonical `attome_audit::audit_service()` helper (M26 R-15), rather than each
//! call site hand-rolling its own copy.
//!
//! This guard is deliberately scoped to those exact files, not to
//! `AuditService::new(` everywhere under `crates/xrm`. A wider scan would
//! also flag `attome-compliance`, `attome-docgen`, `attome-report`, `attome-security`,
//! `attome-state`, `attome-audit`'s own tests, and several other `attome-api`
//! surfaces (`bulk_transform.rs`, `files.rs`, `files_scan.rs`, `migration.rs`,
//! `view_admin.rs`, `data_export.rs`, `webcrawl_admin.rs`) that write a
//! standalone audit event for an action with no `MutationResult` at all
//! (MFA reset, account-state change, a compliance job, a scan outcome, …) —
//! none of those were named in C-10's "Problem" section, forcing them onto
//! a ring built for entity-mutation orchestration would not fit their
//! shape, and `bulk.rs`'s two occurrences are C-11's job ("Collapse the bulk
//! rings"), which lands after this item and depends on it, not before.
//! Widening this guard to cover them is out of this item's scope; if that
//! duplication is worth closing it is a separate, explicitly scoped item.
//!
//! `attome-workflow/src/scheduler.rs::commit_checkpoint` is inside the scanned
//! file but is NOT expected to route through the ring itself — see its own
//! updated doc comment: its shape (a loop writing one audit event per dirty
//! workflow node run, plus a conditional rollback on a lost row_version CAS)
//! has no single `MutationResult`, so it now calls
//! `attome_audit::audit_service()` directly, the same canonical builder the
//! ring uses internally. This guard only requires that the literal
//! `AuditService::new(` construction is gone from the file — it does not
//! require every audit write in the file to go through `MutationRing`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::{Path, PathBuf};

/// The exact set of files C-10's "Problem" section named. Repo-relative,
/// forward-slash, so this test's own file-reading logic matches regardless
/// of platform path separators.
const SCANNED_FILES: &[&str] = &[
    "crates/engine/attome-records/src/entity_crud/mutations.rs",
    "crates/engine/attome-records/src/entity_crud/upsert.rs",
    "crates/engine/attome-records/src/entity_crud/related.rs",
    "crates/engine/attome-records/src/entity_crud/merge.rs",
    "crates/engine/attome-api/src/communication.rs",
    "crates/engine/attome-workflow/src/scheduler.rs",
];

/// The ring module itself is exempt — it is where the one remaining
/// `AuditService::new(` (via `attome_audit::audit_service`, not this literal
/// spelling — see that module) legitimately lives, and it is not in
/// `SCANNED_FILES` above so this constant is documentation, not logic. Kept
/// as a named constant anyway so a reviewer sees the exemption stated
/// rather than inferred from what the list happens to omit.
const RING_MODULE: &str = "crates/engine/attome-records/src/mutation_ring.rs";

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/server; the workspace root is two up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above crates/server")
        .to_path_buf()
}

#[test]
fn no_scanned_file_hand_rolls_the_audit_service_builder() {
    let root = workspace_root();
    let mut offenders = Vec::new();

    for rel in SCANNED_FILES {
        let path: &Path = rel.as_ref();
        let full = root.join(path);
        let source = std::fs::read_to_string(&full)
            .unwrap_or_else(|e| panic!("read {rel}: {e} — did this file move?"));
        for (idx, line) in source.lines().enumerate() {
            if line.contains("AuditService::new(") {
                offenders.push(format!("  {rel}:{}", idx + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these lines still hand-roll `AuditService::new(..).with_ingest_capture(..)\n\
         .with_chainer_enabled(..).with_erasure_key(..)` instead of going through\n\
         `attome_records::mutation_ring::MutationRing` (or, for a shape that \n\
         genuinely has no single MutationResult, `attome_audit::audit_service()` \n\
         directly — see {RING_MODULE}'s doc comment):\n{}",
        offenders.join("\n")
    );
}

/// The ring module is where the canonical builder is *used* (through
/// `attome_audit::audit_service`, not the raw `AuditService::new(` spelling),
/// so it is correct for it to contain neither spelling of the other. This
/// pins that rather than leaving it an unstated assumption of the test
/// above.
#[test]
fn the_ring_module_itself_never_hand_rolls_the_builder_either() {
    let root = workspace_root();
    let path: &Path = RING_MODULE.as_ref();
    let full = root.join(path);
    let source = std::fs::read_to_string(&full)
        .unwrap_or_else(|e| panic!("read {RING_MODULE}: {e} — did this file move?"));
    assert!(
        !source.contains("AuditService::new("),
        "{RING_MODULE} hand-rolls `AuditService::new(` directly instead of calling \
         the canonical `attome_audit::audit_service()` helper — the one thing this \
         module exists to centralize"
    );
}

/// Guards the guard: every path in `SCANNED_FILES` must resolve, or a rename
/// would make the first test above pass for the wrong reason (nothing found
/// to scan).
#[test]
fn every_scanned_file_exists() {
    let root = workspace_root();
    for rel in SCANNED_FILES {
        let path: &Path = rel.as_ref();
        assert!(
            root.join(path).is_file(),
            "{rel} is listed in SCANNED_FILES but does not exist — update the list"
        );
    }
}
