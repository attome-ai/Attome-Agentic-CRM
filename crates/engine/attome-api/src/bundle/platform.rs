//! Boot-time application of platform-owned metadata bundles — the
//! replacement for the ~30 imperative `*::seed::seed(db)` functions
//! (REVIEW-2026-09-02 item 11; D-478 records the decision).
//!
//! A platform bundle is compiled into the binary (`include_str!`, same trust
//! level as the binary itself — never fetched or signature-checked, unlike
//! [`super::pull::sync`]'s remote `deployment.bundle_ref` bundle) and
//! reconciled through the exact same `plan_bundle` -> [`super::ledger`] ->
//! [`super::run_apply_job`] path every other bundle in this engine uses —
//! proven correct against a fresh database by
//! `attome-api/tests/verticals_bundle_apply.rs`.
//!
//! Two differences from `pull::sync`, both because a platform bundle is
//! code-shipped and trusted rather than an external, human-reviewed
//! artifact:
//!
//! - **No approval gate.** `pull::sync` reports a blocked plan as
//!   `approval_pending` and waits for a human. A platform bundle has no
//!   human in the loop — a blocked plan here is a boot-time programming
//!   error (the bundle's content disagrees with what a prior boot already
//!   established) and fails the boot outright, the same fail-closed posture
//!   `boot.rs` already documents for its other hard errors.
//! - **Watermark-gated fast path.** `pull::sync` always runs `plan_bundle`
//!   (a real diff against live metadata) to detect "nothing changed".
//!   That's the exact per-boot cost `seed_watermark` (D-a1e9f0c2)
//!   was built to avoid for the old seed functions — reused here via
//!   [`attome_core::seed_gate::run_if_stale`], keyed by the same
//!   `module` string the seed function it replaces used, so a module's
//!   watermark history carries over. An unchanged boot costs one row read,
//!   not a full plan.
//!
//! - **Seed reconcile contract.** The apply steps run under
//!   `ReconcilePolicy::Seed`, not `Bundle` (`apply.rs::policy`, keyed on
//!   `additive_only`): a platform bundle is the declarative form of the
//!   boot seed it replaced, so an `Option` it leaves out is "not managed
//!   here" (never "set to NULL") and an admin-customized row is skipped
//!   (D-375), exactly as the old `seed()` behaved. The planner mirrors
//!   that (`plan.rs::unmanaged`), so the no-op proof in
//!   `tests/platform_bundle_apply.rs` describes what apply really does.
//!
//! `allow_retire` is always `false` — a platform bundle only ever adds or
//! updates; nothing in the current conversion set needs to retire a
//! platform-owned object, and permitting it silently would be the same
//! "delete something nobody reviewed" risk `pull::sync` already refuses.
//!
//! `PlanOptions::additive_only` is always `true` for the same reason, one
//! level earlier: [`super::export::export_bundle`] (reused unchanged here)
//! always snapshots the *entire* live deployment, but a platform bundle only
//! ever declares one module's own slice of it. Without `additive_only`,
//! every other module's already-provisioned entities/sidebar items/etc. read
//! as "live, not in this bundle" and block the plan on a false-positive
//! "would retire" — not a real disagreement, just this bundle legitimately
//! not mentioning objects it was never meant to own.

use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

use super::{
    BUNDLE_FORMAT, Bundle, PLATFORM_VERSION, PlanOptions, canonical_json, ledger, plan_bundle,
    run_apply_job,
};

/// Applies one compiled-in platform bundle, gated by `module`'s watermark.
/// `bundle_json` is the raw `include_str!`'d file content; `module` is the
/// stable key `seed_watermark` stores it under (reuse the old seed
/// function's own module string so history carries over — never rename
/// after ship, same rule the watermark table's own doc comment states).
pub async fn apply_platform_bundle(
    state: &EngineState,
    module: &str,
    bundle_json: &str,
) -> Result<(), AppError> {
    // The watermark version is a hash of the raw file content: any edit to
    // the bundle changes this and forces reapplication, with no separate
    // "bump SEED_VERSION" step for a human to forget (unlike the old
    // `*::seed::seed` convention this replaces).
    let version = super::hash_bytes(bundle_json.as_bytes());

    attome_core::seed_gate::run_if_stale(&state.base.db, module, &version, || {
        apply_body(state, module, bundle_json)
    })
    .await
}

async fn apply_body(state: &EngineState, module: &str, bundle_json: &str) -> Result<(), AppError> {
    let bundle: Bundle = serde_json::from_str(bundle_json).map_err(|e| {
        AppError::internal(format!("platform bundle '{module}' is not valid JSON: {e}"))
    })?;

    // A compiled-in platform bundle is the product's own schema, provisioned
    // whatever the licence says — D-383: entity provisioning runs
    // unconditionally at boot, and the licence gates *access* (routes and
    // `resolve_entity`), never whether the tables exist. So its
    // `requires.modules` is planned against every module. Without this, a
    // core-only deployment (no signed licence yet, D-635) would refuse to
    // boot on `trd-governance`/`attome-service`, and a licence imported later
    // would find those engines' tables missing. Customer bundles promoted
    // through the admin API keep the real licence check (`bundle::apply`).
    let platform_license = attome_modules::ModuleSet {
        module_bits: [u64::MAX; 4],
        ..(*state.license.load_full()).clone()
    };
    let plan = plan_bundle(
        &state.base.db,
        &platform_license,
        &bundle,
        PlanOptions {
            allow_retire: false,
            additive_only: true,
        },
    )
    .await?;

    if !plan.blocked.is_empty() {
        return Err(AppError::internal(format!(
            "platform bundle '{module}' cannot apply: {} blocked entr{} — {:#?}. This means the \
             bundle's content disagrees with what a prior boot already established (e.g. a \
             field type change this engine cannot auto-reconcile). Fix the bundle content or \
             clear the offending object by hand through the admin API, then restart.",
            plan.blocked.len(),
            if plan.blocked.len() == 1 { "y" } else { "ies" },
            plan.blocked
        )));
    }

    // A plan with nothing to do still needs the watermark write below (the
    // caller only reaches `apply_body` because the watermark was stale), but
    // skipping the ledger/apply round trip when there is genuinely nothing
    // to reconcile keeps a first-time-stale-but-actually-unchanged boot
    // (e.g. after a binary upgrade that only touched an unrelated bundle)
    // as cheap as the common case.
    let all_noop = plan.retires.is_empty()
        && plan.blocked.is_empty()
        && plan
            .entries
            .iter()
            .all(|e| e.action == super::plan::PlanAction::Noop);
    if all_noop {
        return Ok(());
    }

    let bundle_value: serde_json::Value = serde_json::from_slice(&canonical_json(&bundle))
        .map_err(|e| AppError::internal(format!("canonical bundle is not JSON: {e}")))?;
    let plan_json = serde_json::to_value(&plan).map_err(AppError::internal)?;

    let plan_id: Uuid = ledger::insert_plan(
        &state.base.db,
        &bundle_value,
        &plan_json,
        &plan.bundle_hash,
        &plan.basis_hash,
        BUNDLE_FORMAT,
        PLATFORM_VERSION,
        false,
        None,
    )
    .await?;

    ledger::mark_queued(&state.base.db, plan_id, None).await?;
    run_apply_job(state, plan_id).await
}
