//! The workspace's advisory-lock namespace registry, and the only place that
//! proves the ids stay distinct.
//!
//! # Why namespaces exist
//!
//! Every advisory lock in this workspace used to call
//! `pg_try_advisory_xact_lock` with a single `hashtext($1)` argument.
//! `hashtext` returns `int4`, so
//! *every* namespace string and *every* per-record key — approval request ids,
//! normalized emails, entity record ids, upload-session `(record, field)`
//! pairs — shared one 32-bit space. Two unrelated keys that collide while both
//! are held produce a spurious `Conflict`/`Forbidden`: a registration rejected
//! because an unrelated approval decision happens to hold the colliding slot.
//! Birthday maths puts that near one expected collision per 100k distinct
//! keys, and it only bites under concurrency, which is exactly when it is
//! hardest to diagnose (FINAL-ENTERPRISE-REVIEW-2026-08-12 L-1 / TODO-027).
//!
//! Every acquisition now uses PostgreSQL's two-argument form,
//! `pg_try_advisory_xact_lock($1, hashtext($2))`, with `$1` a stable
//! per-subsystem `int4`. A `hashtext` collision can then only occur *within*
//! one subsystem, and the highest-cardinality key spaces (entity records,
//! upload sessions) are walled off from the low-cardinality control keys
//! (role seeding, chainer leader election) they used to share a space with.
//!
//! # The registry
//!
//! Namespace ids are assigned here but *declared* by the crate that owns the
//! key prefix, so no base-layer crate has to name an `xrm-*` subsystem
//! (guidelines §1). `crates/server` is the only crate that depends on all of
//! them, which is why the collision test lives here.
//!
//! | id | key prefix           | declared as                                   |
//! |----|----------------------|-----------------------------------------------|
//! |  1 | `attome-approval/`     | `attome_approval::ADVISORY_LOCK_NAMESPACE`      |
//! |  2 | `attome-auth/`         | `attome_auth::ADVISORY_LOCK_NAMESPACE`          |
//! |  3 | `attome-core/`    | `attome_core::ADVISORY_LOCK_NAMESPACE`     |
//! |  4 | `attome-metadata/`        | `attome_metadata::ADVISORY_LOCK_NAMESPACE`         |
//! |  5 | `attome-audit/`         | `attome_audit::ADVISORY_LOCK_NAMESPACE`          |
//! |  6 | `attome-notification/`  | `attome_notification::ADVISORY_LOCK_NAMESPACE`   |
//! |  7 | `attome-workflow/`      | `attome_workflow::ADVISORY_LOCK_NAMESPACE`       |
//! |  8 | `attome-api/`        | `attome_api::ADVISORY_LOCK_NAMESPACE`         |
//! |  9 | `xrm-files/`         | `attome_records::FILES_ADVISORY_LOCK_NAMESPACE`   |
//! | 10 | `server/`            | `attome::role_seed_lock::ADVISORY_LOCK_NAMESPACE` |
//! | 11 | `attome-search/`        | `attome_search::ADVISORY_LOCK_NAMESPACE`         |
//! | 12 | `webcrawl/`          | `attome_webcrawl::ADVISORY_LOCK_NAMESPACE`       |
//! | 13 | `attome-content/`       | `attome_content::ADVISORY_LOCK_NAMESPACE`        |
//! | 14 | `attome-service/`       | `attome_service::ADVISORY_LOCK_NAMESPACE`        |
//! | 15 | `attome-dashboard/`     | `attome_dashboard::ADVISORY_LOCK_NAMESPACE`      |
//! | 16 | `attome-state/`         | `attome_state::ADVISORY_LOCK_NAMESPACE`          |
//! | 17 | `attome-integration/`   | `attome_integration::ADVISORY_LOCK_NAMESPACE`    |
//! | 18 | `attome-grc/`           | `attome_grc::ADVISORY_LOCK_NAMESPACE`            |
//! | 19 | `attome-compliance/`    | `attome_compliance::ADVISORY_LOCK_NAMESPACE`     |
//! | 20 | `attome-process/`       | `attome_process::ADVISORY_LOCK_NAMESPACE`        |
//! | 21 | `attome-predict/`       | `attome_predict::ADVISORY_LOCK_NAMESPACE`        |
//! | 22 | `attome-metric/`        | `attome_metric::ADVISORY_LOCK_NAMESPACE`         |
//! | 23 | `attome-security/`      | `attome_security::ADVISORY_LOCK_NAMESPACE`       |
//! | 24 | `attome-project/`       | `attome_project::ADVISORY_LOCK_NAMESPACE`        |
//! | 25 | `attome-ai/`            | `attome_ai::ADVISORY_LOCK_NAMESPACE`             |
//! | 26 | `attome-portal/`        | `attome_portal::ADVISORY_LOCK_NAMESPACE`         |
//! | 27 | `attome-modules/`       | `attome_modules::ADVISORY_LOCK_NAMESPACE`        |
//! | 28 | `attome-fleet/`         | `attome_fleet::ADVISORY_LOCK_NAMESPACE`          |
//! | 29 | `attome-s2s/`           | `attome_s2s::ADVISORY_LOCK_NAMESPACE`            |
//! | 30 | `attome-model/`         | `attome_model::ADVISORY_LOCK_NAMESPACE`          |
//! | 31 | `attome-records/`       | `attome_records::ADVISORY_LOCK_NAMESPACE`        |
//! | 32 | `attome-sales/`         | `attome_sales::ADVISORY_LOCK_NAMESPACE`          |
//! | 33 | `attome-callintel/`  | `attome_callintel::ADVISORY_LOCK_NAMESPACE` |
//! | 34 | `attome-marketing/`  | `attome_marketing::ADVISORY_LOCK_NAMESPACE` |
//! | 35 | `attome-billing/`    | `attome_billing::ADVISORY_LOCK_NAMESPACE` |
//! | 36 | `attome-commission/` | `attome_commission::ADVISORY_LOCK_NAMESPACE` |
//! | 37 | `attome-partner/`    | `attome_partner::ADVISORY_LOCK_NAMESPACE` |
//! | 38 | `attome-fulfilment/` | `attome_fulfilment::ADVISORY_LOCK_NAMESPACE` |
//! | 39 | `attome-workforce/`  | `attome_workforce::ADVISORY_LOCK_NAMESPACE` |
//! | 40 | `attome-contract/`   | `attome_contract::ADVISORY_LOCK_NAMESPACE` |
//! | 41 | `attome-offline/`    | `attome_offline::ADVISORY_LOCK_NAMESPACE` |
//! | 42 | `attome-procurement/` | `attome_procurement::ADVISORY_LOCK_NAMESPACE` |
//!
//! A key's prefix decides its namespace, not the crate the SQL is written in:
//! `attome-api`'s rewrap handler locks `"attome-auth/rewrap:{domain}"` under
//! namespace 2 because `crates/server`'s rewrap job holds the same key on its
//! own session, and two locks that must conflict have to agree on both
//! arguments. The same applies to `"attome-audit/erasure:…"` and
//! `"attome-metadata/hierarchy:…"`, both taken from `attome-api`.
//!
//! # Adding one
//!
//! Take the next free id, add a row above, declare the constant in the crate
//! that owns the prefix, and add it to `NAMESPACES` below. Never reuse or
//! renumber an id: doing so silently merges two key spaces (reuse) or splits
//! one across a rolling upgrade so old and new nodes stop conflicting
//! (renumber).
//!
//! These are compile-time constants, so this file needs no database and runs
//! in every `cargo test -p server`.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

/// Every namespace the workspace declares, as `(id, key prefix)`.
const NAMESPACES: &[(i32, &str)] = &[
    (attome_approval::ADVISORY_LOCK_NAMESPACE, "attome-approval/"),
    (attome_auth::ADVISORY_LOCK_NAMESPACE, "attome-auth/"),
    (attome_core::ADVISORY_LOCK_NAMESPACE, "attome-core/"),
    (attome_metadata::ADVISORY_LOCK_NAMESPACE, "attome-metadata/"),
    (attome_audit::ADVISORY_LOCK_NAMESPACE, "attome-audit/"),
    (
        attome_notification::ADVISORY_LOCK_NAMESPACE,
        "attome-notification/",
    ),
    (attome_workflow::ADVISORY_LOCK_NAMESPACE, "attome-workflow/"),
    (attome_api::ADVISORY_LOCK_NAMESPACE, "attome-api/"),
    (attome_records::FILES_ADVISORY_LOCK_NAMESPACE, "xrm-files/"),
    (attome::role_seed_lock::ADVISORY_LOCK_NAMESPACE, "server/"),
    (attome_search::ADVISORY_LOCK_NAMESPACE, "attome-search/"),
    (attome_webcrawl::ADVISORY_LOCK_NAMESPACE, "webcrawl/"),
    (attome_content::ADVISORY_LOCK_NAMESPACE, "attome-content/"),
    (attome_service::ADVISORY_LOCK_NAMESPACE, "attome-service/"),
    (
        attome_dashboard::ADVISORY_LOCK_NAMESPACE,
        "attome-dashboard/",
    ),
    (attome_state::ADVISORY_LOCK_NAMESPACE, "attome-state/"),
    (
        attome_integration::ADVISORY_LOCK_NAMESPACE,
        "attome-integration/",
    ),
    (attome_grc::ADVISORY_LOCK_NAMESPACE, "attome-grc/"),
    (
        attome_compliance::ADVISORY_LOCK_NAMESPACE,
        "attome-compliance/",
    ),
    (attome_process::ADVISORY_LOCK_NAMESPACE, "attome-process/"),
    (attome_predict::ADVISORY_LOCK_NAMESPACE, "attome-predict/"),
    (attome_metric::ADVISORY_LOCK_NAMESPACE, "attome-metric/"),
    (attome_security::ADVISORY_LOCK_NAMESPACE, "attome-security/"),
    (attome_project::ADVISORY_LOCK_NAMESPACE, "attome-project/"),
    (attome_ai::ADVISORY_LOCK_NAMESPACE, "attome-ai/"),
    (attome_portal::ADVISORY_LOCK_NAMESPACE, "attome-portal/"),
    (attome_modules::ADVISORY_LOCK_NAMESPACE, "attome-modules/"),
    // D-792 — the fleet console (`attome-fleet/rollout:active`, `attome-fleet/sync:…`).
    // A dev-dependency here, so the registry covers it in every test build.
    (attome_fleet::ADVISORY_LOCK_NAMESPACE, "attome-fleet/"),
    (attome_s2s::ADVISORY_LOCK_NAMESPACE, "attome-s2s/"),
    (attome_model::ADVISORY_LOCK_NAMESPACE, "attome-model/"),
    (attome_records::ADVISORY_LOCK_NAMESPACE, "attome-records/"),
    (attome_sales::ADVISORY_LOCK_NAMESPACE, "attome-sales/"),
    (
        attome_callintel::ADVISORY_LOCK_NAMESPACE,
        "attome-callintel/",
    ),
    (
        attome_marketing::ADVISORY_LOCK_NAMESPACE,
        "attome-marketing/",
    ),
    (attome_billing::ADVISORY_LOCK_NAMESPACE, "attome-billing/"),
    (
        attome_commission::ADVISORY_LOCK_NAMESPACE,
        "attome-commission/",
    ),
    (attome_partner::ADVISORY_LOCK_NAMESPACE, "attome-partner/"),
    (
        attome_fulfilment::ADVISORY_LOCK_NAMESPACE,
        "attome-fulfilment/",
    ),
    (
        attome_workforce::ADVISORY_LOCK_NAMESPACE,
        "attome-workforce/",
    ),
    (attome_contract::ADVISORY_LOCK_NAMESPACE, "attome-contract/"),
    (attome_offline::ADVISORY_LOCK_NAMESPACE, "attome-offline/"),
    (
        attome_procurement::ADVISORY_LOCK_NAMESPACE,
        "attome-procurement/",
    ),
];

/// The whole point of the registry: two subsystems sharing an id would put
/// their key spaces back into one `hashtext` space, reintroducing L-1 for that
/// pair while looking, at every call site, as if it had been fixed.
#[test]
fn every_namespace_id_is_distinct() {
    for (i, (id, prefix)) in NAMESPACES.iter().enumerate() {
        for (other_id, other_prefix) in &NAMESPACES[i + 1..] {
            assert_ne!(
                id, other_id,
                "advisory-lock namespace {id} is claimed by both \"{prefix}\" and \
                 \"{other_prefix}\" — two subsystems sharing a namespace share one \
                 hashtext space again (L-1). Take the next free id from the registry \
                 table in this file's header instead of reusing one."
            );
        }
    }
}

/// Guards against a stale registry: the table in the header, the constants,
/// and this list are only useful together, and a new namespace declared
/// without being added here would never be collision-checked.
#[test]
fn registry_covers_every_declared_namespace() {
    assert_eq!(
        NAMESPACES.len(),
        42,
        "NAMESPACES no longer lists 41 entries — update the registry table in this \
         file's header and this count together, so the documented table and the \
         collision-checked list cannot drift apart."
    );
}

/// Ids are an ordinary sequence starting at 1, not arbitrary magic numbers.
/// A gap or a zero usually means an id was removed (making reuse likely) or a
/// constant was left at its default.
#[test]
fn ids_are_a_dense_sequence_from_one() {
    let mut ids: Vec<i32> = NAMESPACES.iter().map(|(id, _)| *id).collect();
    ids.sort_unstable();
    let expected: Vec<i32> = (1..=NAMESPACES.len() as i32).collect();
    assert_eq!(
        ids, expected,
        "advisory-lock namespace ids must be 1..=N with no gaps; a gap means an id \
         was retired, and retired ids must never be handed out again"
    );
}
