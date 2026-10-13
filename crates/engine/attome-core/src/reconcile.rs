//! Reconcile policy and outcome — the shared vocabulary for "how does a write
//! treat a row that already exists".
//!
//! ARCH-1a-i. These two enums lived in `attome-metadata::provision`, which forced
//! `attome-security` to depend on `attome-metadata` purely to name them
//! (`attome-security/src/reconcile.rs` re-exported them). That is one of the
//! edges making ARCH-1 a dependency cycle, and it was never a real dependency
//! — two field-less enums and a three-arm match carry no provisioning logic.
//!
//! `attome-metadata::provision` re-exports both, so every existing
//! `attome_metadata::provision::Reconcile*` path keeps resolving.

/// How a reconcile call treats an existing row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcilePolicy {
    /// Boot seed: update only if is_customized = false; never sets is_customized.
    Seed,
    /// Admin API write: always applies; sets is_customized = true.
    Admin,
    /// Bundle apply: always applies; sets is_customized to the given value (carried in the bundle).
    Bundle { is_customized: bool },
}

impl ReconcilePolicy {
    /// The `is_customized` value this policy writes, or `None` when it leaves
    /// the column alone (`Seed`).
    ///
    /// `pub`, where the `attome-metadata` original was private, because this exact
    /// three-arm match used to be written out three times — here, as a free
    /// `customized_marker` in `attome-security/src/reconcile.rs`, and again in
    /// `attome-records/src/query_admin.rs` (moved there from `attome-server`
    /// by D-477/T3-2 after ARCH-1a-i shipped). C-19 is the collapse ARCH-1a-i
    /// deliberately deferred: both other copies now call this method instead
    /// of restating the match, and `decide_step`/`WriteStep`/`RowStatus`
    /// (below) got the same treatment.
    pub fn customized_marker(self) -> Option<bool> {
        match self {
            ReconcilePolicy::Seed => None,
            ReconcilePolicy::Admin => Some(true),
            ReconcilePolicy::Bundle { is_customized } => Some(is_customized),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileOutcome {
    Created,
    Updated,
    Unchanged,
    /// Policy::Seed and the row is customized — nothing written.
    SkippedCustomized,
}

// ── C-19 collapse: the one `decide_step` ────────────────────────────────────
//
// This exact policy matrix used to be written out three times — as
// `attome_metadata::provision::reconcile::{WriteStep, RowStatus, decide_step}`
// (private to that module), as a duplicate `WriteStep`/`RowStatus`/
// `decide_step` in `attome-security/src/reconcile.rs`, and a third time as
// `ReconcileStep`/`reconcile_step`/`customized_marker` in
// `attome-records/src/query_admin.rs` (that one `pub`, so six more
// `attome-server` admin files — `app_admin.rs`, `calendar_admin.rs`,
// `rule_admin.rs`, `sidebar.rs`, `view_admin.rs` (`form_admin.rs` until
// D-790) — import it
// directly). `ReconcilePolicy::customized_marker` above was made `pub` for
// exactly this collapse (see its doc comment) but two of the three copies
// kept their own restatement instead of calling it. All three now delegate
// here; `query_admin.rs` and `attome-metadata`'s `reconcile.rs` keep their original
// type/function names as thin re-exports/wrappers so no external caller
// (including the six `attome-server` files above) has to change an import.

/// What the probe found for an existing row, independent of which table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowStatus {
    pub is_customized: bool,
    pub is_live: bool,
}

/// The step a reconcile call takes once the current row (if any) and the
/// desired state are known. Pure — no I/O — so the policy matrix is
/// unit-testable without a database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteStep {
    Create,
    Update,
    Unchanged,
    SkippedCustomized,
}

impl WriteStep {
    /// The `ReconcileOutcome` this step reports to the caller once the write
    /// (if any) has happened — a pure mapping, unlike `decide_step` itself
    /// (which decides *whether* to write).
    pub fn outcome(self) -> ReconcileOutcome {
        match self {
            WriteStep::Create => ReconcileOutcome::Created,
            WriteStep::Update => ReconcileOutcome::Updated,
            WriteStep::Unchanged => ReconcileOutcome::Unchanged,
            WriteStep::SkippedCustomized => ReconcileOutcome::SkippedCustomized,
        }
    }
}

/// Decides the step. `state_differs` is the caller's comparison of the
/// managed columns (current vs desired) for an existing row. Order matters:
/// the customized-skip is evaluated before anything else under `Seed`, so a
/// customized row never reaches the type/state check (which would otherwise
/// fail a boot over a field the customer deliberately changed).
pub fn decide_step(
    policy: ReconcilePolicy,
    current: Option<RowStatus>,
    state_differs: bool,
) -> WriteStep {
    let Some(row) = current else {
        return WriteStep::Create;
    };
    if policy == ReconcilePolicy::Seed && row.is_customized {
        return WriteStep::SkippedCustomized;
    }
    let marker_differs = policy
        .customized_marker()
        .is_some_and(|wanted| wanted != row.is_customized);
    if !row.is_live || state_differs || marker_differs {
        WriteStep::Update
    } else {
        WriteStep::Unchanged
    }
}
