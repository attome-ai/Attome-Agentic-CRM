//! Publish-time escalation validation (TODO-047).
//!
//! ## The hole this closes
//!
//! `gate.rs` refuses a `Consequential` action for an agent initiator. A
//! workflow is not an agent — it is a graph a human authored and published, so
//! its nodes run with the publisher's authority. That is correct on its own and
//! becomes a hole the moment AI nodes exist: **an agent that may only invoke
//! `Read` actions can still start a workflow, and that workflow can do anything
//! its author could.**
//!
//! The escalation is not exotic. A graph reaches a `SubWorkflow` node, which
//! reaches another, which contains a `Consequential` node. Nobody wrote a
//! malicious graph; three people wrote three reasonable ones and composition
//! did the rest.
//!
//! ## Why publish time, not run time
//!
//! Both would work, and run time is worse for two reasons that matter more than
//! they sound.
//!
//! A run-time refusal happens **to a user**, mid-process, on a graph that has
//! already done half its work — leaving a partially-executed workflow that
//! someone has to reason about. A publish-time refusal happens to the author,
//! who is the person who can actually fix it, at the moment they have the graph
//! in front of them.
//!
//! And a run-time check is reached only when execution takes that path. A graph
//! with an escalating branch nobody has triggered yet is a graph that passes
//! every test and fails in production the first time a condition goes the other
//! way. Publish time examines every path whether or not it has ever run.
//!
//! ## The rule
//!
//! A path from an entry node to a `Consequential` node must pass through an
//! `Approval` node. Not "the graph contains an approval somewhere" — an
//! approval on a *sibling* branch protects nothing, and that is the check a
//! hurried implementation writes.

use std::collections::{HashMap, HashSet};

use crate::node_types::NodeType;
use attome_ai::descriptor::RiskTier;

/// One node, as the validator sees it.
#[derive(Debug, Clone)]
pub struct GraphNode {
    pub id: String,
    pub node_type: NodeType,
    /// For a node that invokes an action, its risk. `None` for the ten shipped
    /// node types, whose risk comes from `NodeType::capability()`.
    pub action_risk: Option<RiskTier>,
}

impl GraphNode {
    /// The risk this node actually carries.
    ///
    /// An action node's own risk wins over its node type's — the node type is
    /// the container, and a "call an action" node is `Consequential` when the
    /// action it calls is, whatever the container says.
    pub fn risk(&self) -> RiskTier {
        self.action_risk
            .unwrap_or_else(|| self.node_type.capability().risk)
    }

    fn is_approval(&self) -> bool {
        matches!(self.node_type, NodeType::Approval)
    }
}

/// A graph reduced to what escalation validation needs.
pub struct GraphView<'a> {
    pub nodes: &'a [GraphNode],
    /// Directed edges, `(from, to)`.
    pub edges: &'a [(String, String)],
}

impl std::fmt::Debug for GraphView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphView").finish_non_exhaustive()
    }
}

/// Why a graph was refused at publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalationError {
    /// A `Consequential` node is reachable from an entry without passing an
    /// `Approval`. Names the path, because "your graph escalates" is not
    /// actionable and the author cannot see it by looking.
    UnapprovedConsequentialPath { path: Vec<String> },
}

/// Validates a graph at publish time.
///
/// Walks every path from every entry node, tracking whether an `Approval` has
/// been passed. Cycles cannot occur — `graph.rs` rejects them before this runs
/// — but the visited set is keyed on `(node, approved)` anyway, because a node
/// legitimately appears on both an approved and an unapproved path and
/// deduplicating on the node alone would let the first visit mask the second.
/// That is the subtle way this check silently stops working.
pub fn validate(graph: &GraphView<'_>) -> Result<(), EscalationError> {
    let by_id: HashMap<&str, &GraphNode> = graph.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut out: HashMap<&str, Vec<&str>> = HashMap::new();
    for (from, to) in graph.edges {
        out.entry(from.as_str()).or_default().push(to.as_str());
    }

    let mut visited: HashSet<(&str, bool)> = HashSet::new();

    for entry in graph.nodes.iter().filter(|n| n.node_type.is_entry()) {
        let mut stack: Vec<(&str, bool, Vec<String>)> =
            vec![(entry.id.as_str(), false, vec![entry.id.clone()])];

        while let Some((id, approved, path)) = stack.pop() {
            let Some(node) = by_id.get(id) else { continue };

            if node.risk() == RiskTier::Consequential && !approved {
                return Err(EscalationError::UnapprovedConsequentialPath { path });
            }

            // An approval node approves what is downstream of it, not itself.
            let approved_onward = approved || node.is_approval();

            if !visited.insert((id, approved_onward)) {
                continue;
            }

            for next in out.get(id).into_iter().flatten() {
                let mut next_path = path.clone();
                next_path.push((*next).to_string());
                stack.push((next, approved_onward, next_path));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, node_type: NodeType, risk: Option<RiskTier>) -> GraphNode {
        GraphNode {
            id: id.into(),
            node_type,
            action_risk: risk,
        }
    }

    fn edge(from: &str, to: &str) -> (String, String) {
        (from.into(), to.into())
    }

    /// **The deliberately-escalating graph is rejected at publish.**
    #[test]
    fn an_escalating_graph_is_rejected() {
        let nodes = vec![
            node("t", NodeType::Trigger, None),
            node(
                "delete",
                NodeType::SubWorkflow,
                Some(RiskTier::Consequential),
            ),
        ];
        let edges = vec![edge("t", "delete")];
        let err = validate(&GraphView {
            nodes: &nodes,
            edges: &edges,
        })
        .expect_err("must be refused");

        match err {
            EscalationError::UnapprovedConsequentialPath { path } => {
                assert_eq!(
                    path,
                    vec!["t".to_string(), "delete".to_string()],
                    "the error must name the path — 'your graph escalates' is \
                     not actionable and the author cannot see it by looking"
                );
            }
        }
    }

    /// An `Approval` on the path makes it legal.
    #[test]
    fn an_approval_on_the_path_permits_the_consequential_node() {
        let nodes = vec![
            node("t", NodeType::Trigger, None),
            node("appr", NodeType::Approval, None),
            node(
                "delete",
                NodeType::SubWorkflow,
                Some(RiskTier::Consequential),
            ),
        ];
        let edges = vec![edge("t", "appr"), edge("appr", "delete")];
        assert!(
            validate(&GraphView {
                nodes: &nodes,
                edges: &edges
            })
            .is_ok()
        );
    }

    /// **The check a hurried implementation writes, and why it is wrong.**
    ///
    /// An approval on a *sibling* branch protects nothing — execution can reach
    /// the consequential node without ever passing it. "The graph contains an
    /// approval" is not the rule.
    #[test]
    fn an_approval_on_a_sibling_branch_does_not_protect_anything() {
        let nodes = vec![
            node("t", NodeType::Trigger, None),
            node("cond", NodeType::Condition, None),
            node("appr", NodeType::Approval, None),
            node("safe", NodeType::SendNotification, None),
            node(
                "delete",
                NodeType::SubWorkflow,
                Some(RiskTier::Consequential),
            ),
        ];
        let edges = vec![
            edge("t", "cond"),
            // The approved branch.
            edge("cond", "appr"),
            edge("appr", "safe"),
            // The other one, which reaches the consequential node directly.
            edge("cond", "delete"),
        ];
        assert!(
            validate(&GraphView {
                nodes: &nodes,
                edges: &edges
            })
            .is_err(),
            "an approval elsewhere in the graph must not launder an unapproved \
             path"
        );
    }

    /// Escalation through composition — nobody wrote a malicious graph.
    #[test]
    fn escalation_through_a_chain_of_subworkflows_is_caught() {
        let nodes = vec![
            node("t", NodeType::Trigger, None),
            node("sub1", NodeType::SubWorkflow, None),
            node("sub2", NodeType::SubWorkflow, None),
            node("boom", NodeType::SubWorkflow, Some(RiskTier::Consequential)),
        ];
        let edges = vec![
            edge("t", "sub1"),
            edge("sub1", "sub2"),
            edge("sub2", "boom"),
        ];
        assert!(
            validate(&GraphView {
                nodes: &nodes,
                edges: &edges
            })
            .is_err()
        );
    }

    /// **The subtle failure**: a node reachable by both an approved and an
    /// unapproved path must still be caught.
    ///
    /// Deduplicating the walk on the node alone would let the approved visit
    /// arrive first and mark it seen, silently masking the unapproved one. This
    /// is how the check stops working without anyone noticing.
    #[test]
    fn a_node_reachable_both_ways_is_still_caught_on_the_unapproved_path() {
        let nodes = vec![
            node("t", NodeType::Trigger, None),
            node("cond", NodeType::Condition, None),
            node("appr", NodeType::Approval, None),
            node("join", NodeType::Condition, None),
            node(
                "delete",
                NodeType::SubWorkflow,
                Some(RiskTier::Consequential),
            ),
        ];
        let edges = vec![
            edge("t", "cond"),
            edge("cond", "appr"),
            edge("appr", "join"),
            // The unapproved way in to the same join node.
            edge("cond", "join"),
            edge("join", "delete"),
        ];
        assert!(
            validate(&GraphView {
                nodes: &nodes,
                edges: &edges
            })
            .is_err(),
            "the approved path must not launder the unapproved one through a \
             shared downstream node"
        );
    }

    /// A graph with no consequential node publishes, and the ten shipped node
    /// types alone never escalate — `SendNotification` and `Webhook` are
    /// `Consequential` in the capability vocabulary, so this pins the one thing
    /// that would make every existing graph unpublishable.
    #[test]
    fn ordinary_graphs_still_publish() {
        let nodes = vec![
            node("t", NodeType::Trigger, None),
            node("c", NodeType::Condition, None),
            node("u", NodeType::UpdateRecord, None),
        ];
        let edges = vec![edge("t", "c"), edge("c", "u")];
        assert!(
            validate(&GraphView {
                nodes: &nodes,
                edges: &edges
            })
            .is_ok()
        );
    }

    /// An action node's own risk wins over its container node type's.
    ///
    /// The node type is the container; a "call an action" node is
    /// `Consequential` when the action it calls is, whatever the container says.
    #[test]
    fn the_actions_own_risk_wins_over_the_node_types() {
        let n = node("x", NodeType::Condition, Some(RiskTier::Consequential));
        assert_eq!(n.risk(), RiskTier::Consequential);
        assert_eq!(
            node("y", NodeType::Condition, None).risk(),
            RiskTier::Read,
            "without an action, the node type decides"
        );
    }
}
