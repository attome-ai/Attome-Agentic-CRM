//! Dual attribution: who acted, and on whose behalf (TODO-042, I-3).
//!
//! **"Who changed this" must never resolve to the AI alone — and never to the
//! human alone either.** Those are two different wrong answers. Attributing an
//! agent's write to the model loses the accountable human, which is the entire
//! point of running as the caller. Attributing it to the human hides that a
//! model was in the loop, and "did a person actually decide this" is the first
//! question any incident involving an automated write asks.
//!
//! So attribution is a pair — an acting user, always, plus an initiator saying
//! whether a human or an agent drove it. [`Attribution`] is the type; there is
//! no way to construct one that names an agent without also naming the human it
//! acts for, because [`Attribution::agent`] requires both.
//!
//! ## Strictly additive
//!
//! [`Initiator::User`] is the default, so every existing audit row and every
//! existing test keeps its current meaning. That is the acceptance criterion for
//! this change rather than a nice property of it: a migration that altered what
//! historical audit rows mean would be worse than no migration.
//!
//! ## In the hash from version 2 on (D-539)
//!
//! Hash version 1 (`compute_hash_raw`) covers `prev_hash | operation |
//! entity_name | record_id | user_id | changed_on` and nothing else, and it
//! can never change: adding a field would change the computed hash of every
//! historical row. So on **v1 rows** `initiator`, `agent_session_id` and
//! `agent_action_id` are unhashed, and direct database write access could flip
//! them without breaking the chain (`action_invocation` records the
//! same fact independently, which bounds that).
//!
//! Hash version 2 adds a new formula instead of changing the old one: its
//! canonical event (`crate::canonical`) hashes all three as fields 10–12, so
//! on **v2 rows** changing the initiator fails verification. Every writer
//! produces v2, including the chainer path, which now carries the
//! [`Attribution`] in the ingest payload rather than dropping it.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// What drove a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Initiator {
    /// A human acting directly. The default, so existing rows are unchanged.
    #[default]
    User = 0,
    /// An agent acting **for** a human. Never instead of one.
    Agent = 1,
    /// Deterministic automated execution attributed to the system/job itself
    /// — never to a human, and never to an LLM acting for a human. The
    /// motivating case is a LIVE trading strategy's order pipeline
    /// (`document/TRADING-PLATFORM-PLAN.md` §6 rule 5): once a strategy is
    /// promoted to LIVE it places orders with no human and no agent in the
    /// loop, so neither [`Initiator::User`] nor [`Initiator::Agent`] would be
    /// an honest attribution — both imply a person is accountable for the
    /// individual action, and here nobody approved the individual order, only
    /// the strategy's promotion. `System` exists so that fact is representable
    /// instead of being papered over as one of the other two.
    System = 2,
    /// An external web portal user (D-576 item 6). `acting_user_id` is then an
    /// `webportal_user` id, **never** an `user_account` id: a
    /// reader must check the initiator before resolving the id to a staff
    /// user. Hashed like the other initiators (v2 field 10), so it cannot be
    /// flipped without failing verification.
    PortalUser = 3,
    /// Q13-T1: an administrator acting as `acting_user_id` in a view-as or
    /// act-as session. `agent_session_id` is the impersonation session and
    /// `agent_action_id` is `impersonator:{administrator id}`, so both
    /// identities are hashed (v2 fields 10-12).
    Impersonation = 4,
}

impl Initiator {
    pub fn as_i16(self) -> i16 {
        self as i16
    }

    /// Reads a stored value.
    ///
    /// An unrecognised value reads as `User`. That is the conservative
    /// direction for *this* field, and it is worth being explicit about why,
    /// because it is the opposite of the rule elsewhere: a risk ceiling narrows
    /// on an unknown because widening it grants power, whereas an unknown
    /// initiator resolving to `Agent` would libel a human as having automated
    /// something they typed. Neither default is "safe" in the abstract — each is
    /// chosen against a specific harm.
    pub fn from_i16(v: i16) -> Self {
        match v {
            1 => Initiator::Agent,
            2 => Initiator::System,
            3 => Initiator::PortalUser,
            4 => Initiator::Impersonation,
            _ => Initiator::User,
        }
    }
}

/// Who acted, and on whose behalf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribution {
    /// **Always present.** The human accountable for the change, whether they
    /// typed it or an agent did it for them.
    pub acting_user_id: Uuid,
    pub initiator: Initiator,
    /// The session, when an agent drove it. `None` for a user.
    pub agent_session_id: Option<Uuid>,
    /// Which action the agent invoked, so an auditor can go from "an agent did
    /// this" to "by calling record.create" without joining a table that may
    /// have been pruned.
    pub agent_action_id: Option<String>,
}

impl Attribution {
    /// A human acting directly.
    pub fn user(acting_user_id: Uuid) -> Self {
        Self {
            acting_user_id,
            initiator: Initiator::User,
            agent_session_id: None,
            agent_action_id: None,
        }
    }

    /// An agent acting for a human.
    ///
    /// Both are required by the signature. There is deliberately no constructor
    /// that produces an agent attribution without a human — I-3 says an action
    /// always runs as the human, and a type that could express otherwise is one
    /// somebody eventually uses.
    /// A web portal user acting on their own behalf (D-576 item 6).
    pub fn portal_user(webportal_user_id: Uuid) -> Self {
        Self {
            acting_user_id: webportal_user_id,
            initiator: Initiator::PortalUser,
            agent_session_id: None,
            agent_action_id: None,
        }
    }

    pub fn agent(acting_user_id: Uuid, session_id: Uuid, action_id: impl Into<String>) -> Self {
        Self {
            acting_user_id,
            initiator: Initiator::Agent,
            agent_session_id: Some(session_id),
            agent_action_id: Some(action_id.into()),
        }
    }

    /// Q13-T1: `subject_id`'s access, used by administrator `actor_id` in
    /// impersonation session `session_id`. Both people are named.
    pub fn impersonated(subject_id: Uuid, session_id: Uuid, actor_id: Uuid) -> Self {
        Self {
            acting_user_id: subject_id,
            initiator: Initiator::Impersonation,
            agent_session_id: Some(session_id),
            agent_action_id: Some(format!("impersonator:{actor_id}")),
        }
    }

    /// The attribution a write in the current task carries when its caller
    /// names none: an agent's (AK3-T1), an impersonation session's (Q13-T1),
    /// or `user_id`'s own.
    pub fn ambient(user_id: Uuid) -> Self {
        if let Some(agent) = attome_core::agent_scope::current() {
            return Self::agent(user_id, agent.session_id, agent.action_id);
        }
        match attome_server::impersonation::current() {
            Some(session) => Self::impersonated(user_id, session.session_id, session.actor_id),
            None => Self::user(user_id),
        }
    }

    pub fn is_agent(&self) -> bool {
        self.initiator == Initiator::Agent
    }

    /// How an audit UI should describe this, in one line.
    ///
    /// Both parties named, always. A UI that showed only one of them would be
    /// making exactly the mistake this module exists to prevent, and leaving the
    /// phrasing to each call site guarantees that at least one of them will.
    pub fn describe(&self, user_display_name: &str) -> String {
        match self.initiator {
            Initiator::User => user_display_name.to_owned(),
            Initiator::Agent => match &self.agent_action_id {
                Some(action) => format!("AI agent on behalf of {user_display_name} ({action})"),
                None => format!("AI agent on behalf of {user_display_name}"),
            },
            // No human is accountable for the individual action here (see the
            // variant doc), so unlike the `Agent` arm this deliberately does
            // not name `user_display_name` — that would misattribute a
            // strategy's automated order to whichever person happens to be on
            // the `acting_user_id` this row carries.
            Initiator::System => match &self.agent_action_id {
                Some(action) => format!("Automated system job ({action})"),
                None => "Automated system job".to_owned(),
            },
            // Said outright, so a portal user is never read as staff.
            Initiator::PortalUser => format!("Web portal user {user_display_name}"),
            // Both people: the one whose access was used, and who used it.
            Initiator::Impersonation => match &self.agent_action_id {
                Some(actor) => format!(
                    "{user_display_name}, impersonated by {}",
                    actor.trim_start_matches("impersonator:")
                ),
                None => format!("{user_display_name}, impersonated"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default is `User`, so every existing row and test keeps its meaning.
    #[test]
    fn the_default_is_user_so_existing_rows_are_unchanged() {
        assert_eq!(Initiator::default(), Initiator::User);
        assert_eq!(Initiator::User.as_i16(), 0);
        assert_eq!(Initiator::from_i16(0), Initiator::User);
    }

    /// An unrecognised stored value reads as `User` — resolving it to `Agent`
    /// would libel a human as having automated something they typed.
    #[test]
    fn an_unknown_stored_initiator_reads_as_user() {
        assert_eq!(Initiator::from_i16(7), Initiator::User);
        assert_eq!(Initiator::from_i16(-1), Initiator::User);
    }

    /// `System` round-trips through the same `i16` encoding as `User` and
    /// `Agent`.
    #[test]
    fn system_round_trips_through_i16() {
        assert_eq!(Initiator::System.as_i16(), 2);
        assert_eq!(Initiator::from_i16(2), Initiator::System);
    }

    /// **The I-3 assertion.** An agent attribution always names the human.
    #[test]
    fn an_agent_attribution_always_names_a_human() {
        let human = Uuid::now_v7();
        let a = Attribution::agent(human, Uuid::now_v7(), "record.create");
        assert_eq!(a.acting_user_id, human);
        assert!(a.agent_session_id.is_some());
        assert!(a.is_agent());
    }

    /// A user attribution carries no session, so the database CHECK and the
    /// type agree about what a well-formed row looks like.
    #[test]
    fn a_user_attribution_carries_no_session() {
        let a = Attribution::user(Uuid::now_v7());
        assert!(a.agent_session_id.is_none());
        assert!(a.agent_action_id.is_none());
        assert!(!a.is_agent());
    }

    /// **Both parties are named in what a user reads.** Not one or the other.
    #[test]
    fn the_description_names_both_the_agent_and_the_human() {
        let d = Attribution::agent(Uuid::now_v7(), Uuid::now_v7(), "record.create")
            .describe("Sara Haddad");
        assert!(d.contains("Sara Haddad"), "the accountable human: {d}");
        assert!(d.contains("agent"), "and that a model was in the loop: {d}");
        assert!(d.contains("record.create"), "and what it did: {d}");
    }

    /// A human-initiated change reads as just the person. Adding "acting
    /// directly" to every ordinary row would train readers to skim the
    /// attribution line, which is the line that matters on the rare agent row.
    #[test]
    fn a_user_change_reads_as_just_the_person() {
        assert_eq!(
            Attribution::user(Uuid::now_v7()).describe("Sara Haddad"),
            "Sara Haddad"
        );
    }

    /// The two are distinguishable in a list — the property TODO-042 verifies.
    #[test]
    fn agent_and_user_changes_are_distinguishable() {
        let user = Attribution::user(Uuid::now_v7());
        let agent = Attribution::agent(Uuid::now_v7(), Uuid::now_v7(), "record.update");
        assert_ne!(user.initiator, agent.initiator);
        assert_ne!(user.describe("A"), agent.describe("A"));
    }
}
