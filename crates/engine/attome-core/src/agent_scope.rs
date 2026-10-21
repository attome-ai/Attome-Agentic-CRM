//! The agent an engine write is made for (AK3-T1, AH1).
//!
//! An agent's action runs through ordinary engine code (the record engine,
//! a billing call), which writes its own audit header and change event with
//! no idea an agent is behind it. `attome-ai` runs every agent action's
//! executor inside [`scope`], and the two writers read [`current`]: the audit
//! service attributes the header to the agent acting for the person
//! (`initiator` 1, the session and the action), and the change feed records
//! the same initiator and session on the event. Outside a scope (a person's
//! request, a job) both stay as they were: a person, no session.
//!
//! A task spawned from inside the scope does not inherit it, the
//! `tokio::task_local!` rule, so work handed to a job is attributed by that
//! job, not by the agent that queued it.

use std::future::Future;

use uuid::Uuid;

/// The agent acting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentScope {
    pub session_id: Uuid,
    /// The action being run, e.g. `record.update`.
    pub action_id: String,
}

tokio::task_local! {
    static AGENT: AgentScope;
}

/// Runs `work` as done by `agent`.
pub async fn scope<F: Future>(agent: AgentScope, work: F) -> F::Output {
    AGENT.scope(agent, work).await
}

/// The agent the current task acts for, if any.
pub fn current() -> Option<AgentScope> {
    AGENT.try_with(Clone::clone).ok()
}

/// The `(initiator, agent_session_id)` an event written now carries: `(1,
/// session)` inside an agent's scope, `(0, None)` otherwise.
pub fn columns() -> (i16, Option<Uuid>) {
    match current() {
        Some(agent) => (1, Some(agent.session_id)),
        None => (0, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_event_defaults_to_user_initiator() {
        assert_eq!(columns(), (0, None));
        assert!(current().is_none());
    }

    #[tokio::test]
    async fn agent_scope_names_the_session_inside_only() {
        let session = Uuid::now_v7();
        let agent = AgentScope {
            session_id: session,
            action_id: "record.update".into(),
        };
        let inside = scope(agent, async { columns() }).await;
        assert_eq!(inside, (1, Some(session)));
        assert_eq!(columns(), (0, None), "the scope ends with the work");
    }
}
