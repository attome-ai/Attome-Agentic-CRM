//! Writes that start no automation (B5-T3).
//!
//! A bulk edit run with `quiet` (the [`QUIET_PRIVILEGE`] privilege) changes
//! its records through the ordinary engine path, but the change events it
//! writes are marked `quiet`: the workflow entry triggers start no flow (and
//! so no agent a flow runs), and followers get no notification. Everything
//! that keeps derived data right (search, caches, rollups, the audit trail,
//! external subscriptions) still reads every event as before.
//!
//! The bulk worker runs a quiet operation's items inside [`quiet`]; the
//! change feed reads [`is_quiet`]. Like [`crate::agent_scope`], a task
//! spawned from inside the scope does not inherit it.

use std::future::Future;

/// The privilege a caller needs to run a bulk edit without automation.
pub const QUIET_PRIVILEGE: &str = "records.bulk_quiet";

tokio::task_local! {
    static QUIET: ();
}

/// Runs `work` with its change events marked quiet.
pub async fn quiet<F: Future>(work: F) -> F::Output {
    QUIET.scope((), work).await
}

/// Whether the current task's writes start no automation.
pub fn is_quiet() -> bool {
    QUIET.try_with(|_| ()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quiet_scope_marks_only_the_work_inside() {
        assert!(!is_quiet());
        assert!(quiet(async { is_quiet() }).await);
        assert!(!is_quiet(), "the scope ends with the work");
    }
}
