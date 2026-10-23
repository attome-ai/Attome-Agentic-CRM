//! Where an engine write came from, for its change event (L7-T2).
//!
//! The change feed already records who drove a write (a person, or an agent
//! and its session, from [`crate::agent_scope`]) and what it changed
//! (Y7-T1). This scope adds the channel the write arrived through and, for a
//! write a flow made, the flow run, so a subscriber can tell a flow's own
//! update from a person's and skip the echo.
//!
//! The workflow scheduler runs each pass of an instance inside [`scope`]
//! with [`FLOW_CHANNEL`] and the instance id; the change-feed writers read
//! [`columns`]. Outside a scope both columns stay NULL, which a reader takes
//! as an ordinary request. Like [`crate::agent_scope`], a task spawned from
//! inside the scope does not inherit it.

use std::future::Future;

use uuid::Uuid;

/// The channel of a write a workflow run made.
pub const FLOW_CHANNEL: &str = "flow";
/// The channel of a write a bulk or import job made.
pub const JOB_CHANNEL: &str = "job";

/// Where the current task's writes come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub channel: &'static str,
    /// The workflow instance, for a flow's write.
    pub run_id: Option<Uuid>,
}

tokio::task_local! {
    static PROVENANCE: Provenance;
}

/// Runs `work` with its writes attributed to `provenance`.
pub async fn scope<F: Future>(provenance: Provenance, work: F) -> F::Output {
    PROVENANCE.scope(provenance, work).await
}

/// The provenance of the current task, if any.
pub fn current() -> Option<Provenance> {
    PROVENANCE.try_with(Clone::clone).ok()
}

/// The `(channel, flow_run_id)` a change event written now carries.
pub fn columns() -> (Option<&'static str>, Option<Uuid>) {
    match current() {
        Some(p) => (Some(p.channel), p.run_id),
        None => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_event_has_no_provenance_outside_a_scope() {
        assert_eq!(columns(), (None, None));
    }

    #[tokio::test]
    async fn flow_scope_names_the_run_inside_only() {
        let run = Uuid::now_v7();
        let inside = scope(
            Provenance {
                channel: FLOW_CHANNEL,
                run_id: Some(run),
            },
            async { columns() },
        )
        .await;
        assert_eq!(inside, (Some(FLOW_CHANNEL), Some(run)));
        assert_eq!(columns(), (None, None), "the scope ends with the work");
    }
}
