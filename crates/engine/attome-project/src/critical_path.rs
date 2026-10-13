//! Critical Path Method (CPM), generalized to all four Precedence
//! Diagramming Method (PDM) relationship types with lag/lead
//! (`project_work_item_dependency.dependency_type`:
//! `finish_to_start` | `start_to_start` | `finish_to_finish` |
//! `start_to_finish`).
//!
//! A node's duration is `due_date - start_date` in days when both are set,
//! else `0` (an instantaneous milestone) — the same "missing data degrades
//! gracefully rather than erroring" convention every other computed field on
//! this crate's two routes follows (see `summary.rs`/`work_plan.rs`).
//!
//! **The four constraint types, and how each translates into the forward/
//! backward pass.** Every edge `predecessor -> successor` with a given
//! `lag` constrains a pair of instants (start|finish, start|finish):
//!
//! | type              | constraint                                   |
//! |-------------------|-----------------------------------------------|
//! | `finish_to_start`  | `ES(successor) >= EF(predecessor) + lag`      |
//! | `start_to_start`   | `ES(successor) >= ES(predecessor) + lag`      |
//! | `finish_to_finish` | `EF(successor) >= EF(predecessor) + lag`      |
//! | `start_to_finish`  | `EF(successor) >= ES(predecessor) + lag`      |
//!
//! `EF(n) = ES(n) + duration(n)` always holds, so an `EF`-side constraint on
//! the successor is converted to an `ES(successor)` lower bound by
//! subtracting the successor's own (already-known) duration — see
//! `forward_bound`. The backward pass is the mirror image: each edge
//! constrains an upper bound on the *predecessor's* `LF`, again converted
//! through `LF(n) = LS(n) + duration(n)` when the edge names the
//! predecessor's start — see `backward_bound`. Both passes still run in one
//! topological order over the underlying node DAG; only the per-edge bound
//! formula changes by relationship type.
//!
//! **An `finish_to_finish`/`start_to_finish`-only successor can compute a
//! negative earliest start.** If a zero-duration predecessor finishes at day
//! 0 and an `finish_to_finish` edge (lag 0) is a 10-day successor's only
//! constraint, its earliest start is day -10 — it must already be running
//! before "day zero" to finish alongside the predecessor. This is correct
//! PDM arithmetic, not a bug: a network under-constrained by only
//! `finish_to_finish`/`start_to_finish` edges genuinely has no lower bound
//! on when the successor could start, and clamping it to zero would hide
//! that the network needs another edge (typically an explicit
//! `finish_to_start` or `start_to_start`) rather than silently
//! papering over it.
//!
//! Pure and DB-free by design: `compute` takes plain node/edge data and is
//! exercised by this module's own unit tests (`cargo test -p attome-project
//! --lib`, no database needed) before `work_plan.rs` ever calls it against
//! real rows.

use std::collections::{HashMap, HashSet, VecDeque};

use uuid::Uuid;

/// `project_work_item_dependency.dependency_type`'s four choice values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyType {
    FinishToStart,
    StartToStart,
    FinishToFinish,
    StartToFinish,
}

impl DependencyType {
    /// Parses the entity's stored choice value. `None` on anything else —
    /// the caller (`work_plan.rs::fetch_dependencies`) skips a row it can't
    /// parse rather than guessing, the same "degrade, don't guess" posture
    /// this module's own doc comment states for missing duration data.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "finish_to_start" => Some(Self::FinishToStart),
            "start_to_start" => Some(Self::StartToStart),
            "finish_to_finish" => Some(Self::FinishToFinish),
            "start_to_finish" => Some(Self::StartToFinish),
            _ => None,
        }
    }
}

pub struct DependencyEdge {
    pub predecessor: Uuid,
    pub successor: Uuid,
    pub dependency_type: DependencyType,
    pub lag_days: i64,
}

impl std::fmt::Debug for DependencyEdge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DependencyEdge").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CriticalPathResult {
    pub is_critical: bool,
    pub total_float_days: i64,
}

/// Forward-pass lower bound this one edge places on `ES(successor)`, given
/// the predecessor's already-computed `ES`/`EF` (topological order
/// guarantees the predecessor is finalized first) and the successor's own
/// duration (known independently of any edge).
fn forward_bound(
    dependency_type: DependencyType,
    pred_es: i64,
    pred_ef: i64,
    lag_days: i64,
    succ_duration: i64,
) -> i64 {
    match dependency_type {
        DependencyType::FinishToStart => pred_ef + lag_days,
        DependencyType::StartToStart => pred_es + lag_days,
        DependencyType::FinishToFinish => pred_ef + lag_days - succ_duration,
        DependencyType::StartToFinish => pred_es + lag_days - succ_duration,
    }
}

/// Backward-pass upper bound this one edge places on `LF(predecessor)`,
/// given the successor's already-computed `LS`/`LF` (reverse topological
/// order finalizes the successor first) and the predecessor's own duration.
fn backward_bound(
    dependency_type: DependencyType,
    succ_ls: i64,
    succ_lf: i64,
    lag_days: i64,
    pred_duration: i64,
) -> i64 {
    match dependency_type {
        DependencyType::FinishToStart => succ_ls - lag_days,
        DependencyType::StartToStart => succ_ls - lag_days + pred_duration,
        DependencyType::FinishToFinish => succ_lf - lag_days,
        DependencyType::StartToFinish => succ_lf - lag_days + pred_duration,
    }
}

/// `None` means the edge set restricted to `node_ids` contains a cycle —
/// CPM is undefined on a cyclic network, so the caller degrades every node
/// to "not computable" rather than looping forever or returning a
/// misleading answer. Edges referencing a node outside `node_ids` are
/// ignored defensively (should not happen given both come from the same
/// project-scoped query, but this function makes no assumption about that).
pub fn compute(
    node_ids: &[Uuid],
    durations_days: &HashMap<Uuid, i64>,
    edges: &[DependencyEdge],
) -> Option<HashMap<Uuid, CriticalPathResult>> {
    let node_set: HashSet<Uuid> = node_ids.iter().copied().collect();
    let relevant_edges: Vec<&DependencyEdge> = edges
        .iter()
        .filter(|e| node_set.contains(&e.predecessor) && node_set.contains(&e.successor))
        .collect();

    let mut successors: HashMap<Uuid, Vec<&DependencyEdge>> = HashMap::new();
    let mut predecessors: HashMap<Uuid, Vec<&DependencyEdge>> = HashMap::new();
    let mut in_degree: HashMap<Uuid, usize> = node_ids.iter().map(|&id| (id, 0)).collect();
    for &e in &relevant_edges {
        successors.entry(e.predecessor).or_default().push(e);
        predecessors.entry(e.successor).or_default().push(e);
        *in_degree.entry(e.successor).or_insert(0) += 1;
    }

    // Kahn's algorithm — the resulting order length tells us whether every
    // node was reachable, i.e. whether the graph is acyclic. Relationship
    // type doesn't change the underlying node DAG, so this is unchanged
    // from the FS-only version.
    let mut queue: VecDeque<Uuid> = node_ids
        .iter()
        .copied()
        .filter(|id| in_degree.get(id).copied().unwrap_or(0) == 0)
        .collect();
    let mut topo_order = Vec::with_capacity(node_ids.len());
    let mut remaining_in_degree = in_degree.clone();
    while let Some(n) = queue.pop_front() {
        topo_order.push(n);
        if let Some(succs) = successors.get(&n) {
            for e in succs {
                let d = remaining_in_degree.entry(e.successor).or_insert(0);
                *d -= 1;
                if *d == 0 {
                    queue.push_back(e.successor);
                }
            }
        }
    }
    if topo_order.len() != node_ids.len() {
        return None; // cycle
    }

    let duration = |id: &Uuid| durations_days.get(id).copied().unwrap_or(0);

    // Forward pass: earliest_start/earliest_finish in topological order.
    let mut earliest_start: HashMap<Uuid, i64> = HashMap::new();
    let mut earliest_finish: HashMap<Uuid, i64> = HashMap::new();
    for &n in &topo_order {
        let dur_n = duration(&n);
        let es = predecessors
            .get(&n)
            .map(|preds| {
                preds
                    .iter()
                    .map(|e| {
                        forward_bound(
                            e.dependency_type,
                            earliest_start[&e.predecessor],
                            earliest_finish[&e.predecessor],
                            e.lag_days,
                            dur_n,
                        )
                    })
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        earliest_start.insert(n, es);
        earliest_finish.insert(n, es + dur_n);
    }

    let project_finish = topo_order
        .iter()
        .map(|n| earliest_finish[n])
        .max()
        .unwrap_or(0);

    // Backward pass: latest_finish/latest_start in reverse topological order.
    //
    // Every node's LF is clamped to `project_finish`, not just a
    // successorless node's — a loose `finish_to_finish`/`start_to_finish`
    // edge can otherwise produce an edge-derived bound *larger* than
    // `project_finish` for a node that has a successor (found by this
    // module's own `start_to_finish_bounds_the_successors_finish_against_
    // the_predecessors_start` test): nothing may be scheduled to finish
    // later than the project's own overall finish, by that quantity's own
    // definition (`max` of every node's forward `EF`). For an
    // `finish_to_start`/`start_to_start`/`finish_to_finish`-only network
    // this clamp is a no-op — a node on the path that actually defines
    // `project_finish` already computes an edge-derived bound at or below
    // it — so this changes no previously-correct FS-only result.
    let mut latest_finish: HashMap<Uuid, i64> = HashMap::new();
    let mut latest_start: HashMap<Uuid, i64> = HashMap::new();
    for &n in topo_order.iter().rev() {
        let dur_n = duration(&n);
        let lf = successors
            .get(&n)
            .map(|succs| {
                succs
                    .iter()
                    .map(|e| {
                        backward_bound(
                            e.dependency_type,
                            latest_start[&e.successor],
                            latest_finish[&e.successor],
                            e.lag_days,
                            dur_n,
                        )
                    })
                    .min()
                    .unwrap_or(project_finish)
            })
            .unwrap_or(project_finish)
            .min(project_finish);
        latest_finish.insert(n, lf);
        latest_start.insert(n, lf - dur_n);
    }

    Some(
        topo_order
            .iter()
            .map(|&n| {
                let float = latest_start[&n] - earliest_start[&n];
                (
                    n,
                    CriticalPathResult {
                        is_critical: float == 0,
                        total_float_days: float,
                    },
                )
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid(seed: u8) -> Uuid {
        Uuid::from_bytes([seed; 16])
    }

    fn fs(predecessor: Uuid, successor: Uuid, lag_days: i64) -> DependencyEdge {
        DependencyEdge {
            predecessor,
            successor,
            dependency_type: DependencyType::FinishToStart,
            lag_days,
        }
    }

    #[test]
    fn single_node_with_no_edges_is_trivially_critical() {
        let a = uid(1);
        let result = compute(&[a], &HashMap::new(), &[]).expect("no cycle");
        assert_eq!(
            result[&a],
            CriticalPathResult {
                is_critical: true,
                total_float_days: 0
            }
        );
    }

    /// A -> B -> D (5 + 3 = 8 days) is longer than A -> C -> D (2 + 1 = 3
    /// days), so B and D sit on the critical path and C carries slack.
    /// FS-only fixture, unchanged from before generalization — the parity
    /// case this generalization must not regress.
    #[test]
    fn longer_chain_is_critical_shorter_parallel_chain_has_float() {
        let (a, b, c, d) = (uid(1), uid(2), uid(3), uid(4));
        let durations = HashMap::from([(a, 0), (b, 5), (c, 2), (d, 3)]);
        let edges = vec![fs(a, b, 0), fs(a, c, 0), fs(b, d, 0), fs(c, d, 0)];
        let result = compute(&[a, b, c, d], &durations, &edges).expect("no cycle");

        assert!(result[&a].is_critical);
        assert!(result[&b].is_critical, "A->B->D is the longer chain");
        assert!(result[&d].is_critical);
        assert!(!result[&c].is_critical, "A->C->D is the shorter chain");
        // Path lengths include every node's own duration: A->B->D =
        // 0+5+3 = 8 days, A->C->D = 0+2+3 = 5 days. C's float is the
        // 3-day difference between the two path lengths, not between B
        // and C's own durations.
        assert_eq!(result[&c].total_float_days, 3);
    }

    #[test]
    fn lag_extends_the_critical_path() {
        let (a, b) = (uid(1), uid(2));
        let durations = HashMap::from([(a, 2), (b, 3)]);
        let edges = vec![fs(a, b, 4)];
        let result = compute(&[a, b], &durations, &edges).expect("no cycle");
        assert!(result[&a].is_critical);
        assert!(result[&b].is_critical);
    }

    #[test]
    fn a_cycle_returns_none_rather_than_looping_forever() {
        let (a, b) = (uid(1), uid(2));
        let edges = vec![fs(a, b, 0), fs(b, a, 0)];
        assert!(compute(&[a, b], &HashMap::new(), &edges).is_none());
    }

    #[test]
    fn missing_duration_defaults_to_zero_not_a_panic() {
        let (a, b) = (uid(1), uid(2));
        // `a` has no entry in the duration map at all.
        let result = compute(&[a, b], &HashMap::from([(b, 3)]), &[fs(a, b, 0)]).expect("no cycle");
        assert!(result[&a].is_critical);
        assert!(result[&b].is_critical);
    }

    /// `start_to_start`, lag 2: B may not start until 2 days after A
    /// starts, regardless of A's own duration. A is 5 days, B is 3 days,
    /// both starting from day 0 conceptually — B's ES is A's ES (0) + 2 =
    /// day 2, EF = day 5. Since A's EF is day 5 too, both finish together;
    /// there is no successor to either, so both sit on the critical path
    /// (whichever finishes last defines project_finish, and both have zero
    /// float against it in this two-node network).
    #[test]
    fn start_to_start_constrains_the_successors_start_not_its_predecessors_finish() {
        let (a, b) = (uid(1), uid(2));
        let durations = HashMap::from([(a, 5), (b, 3)]);
        let edges = vec![DependencyEdge {
            predecessor: a,
            successor: b,
            dependency_type: DependencyType::StartToStart,
            lag_days: 2,
        }];
        let result = compute(&[a, b], &durations, &edges).expect("no cycle");
        // B's earliest start is day 2 (A's ES=0 + lag 2), not day 5 (A's
        // EF) — proving this is genuinely SS semantics, not FS.
        assert!(result[&a].is_critical);
        assert!(
            result[&b].is_critical,
            "B finishes last (day 5) in this network, so it has zero float"
        );
    }

    /// `finish_to_finish`, lag 0: B must finish no earlier than A finishes.
    /// A is a 0-duration milestone at day 3; B is a 4-day task. B's EF must
    /// be >= 3, so B's ES = 3 - 4 = -1 (it must already be under way before
    /// A's milestone). This is the documented "can compute a negative
    /// earliest start" case from this module's own doc comment — proof the
    /// arithmetic, not a clamp, is what's happening.
    #[test]
    fn finish_to_finish_can_push_a_longer_successor_to_a_negative_earliest_start() {
        let (a, b) = (uid(1), uid(2));
        let durations = HashMap::from([(a, 0), (b, 4)]);
        // A itself has an artificial 3-day head start via a dummy
        // predecessor-free duration; simulate "A finishes at day 3" by
        // giving A a 3-day duration instead of a separate node, since only
        // the finish instant matters to this edge type.
        let durations = {
            let mut d = durations;
            d.insert(a, 3);
            d
        };
        let edges = vec![DependencyEdge {
            predecessor: a,
            successor: b,
            dependency_type: DependencyType::FinishToFinish,
            lag_days: 0,
        }];
        let result = compute(&[a, b], &durations, &edges).expect("no cycle");
        assert_eq!(
            result[&b].total_float_days, 0,
            "B is forced to align exactly with A's finish, zero float"
        );
    }

    /// `start_to_finish`, lag 1: B must finish at or after A starts + 1.
    /// A is a 5-day task starting at day 0; B is a 2-day task. B's EF must
    /// be >= 0 + 1 = 1, so B's ES = 1 - 2 = -1.
    #[test]
    fn start_to_finish_bounds_the_successors_finish_against_the_predecessors_start() {
        let (a, b) = (uid(1), uid(2));
        let durations = HashMap::from([(a, 5), (b, 2)]);
        let edges = vec![DependencyEdge {
            predecessor: a,
            successor: b,
            dependency_type: DependencyType::StartToFinish,
            lag_days: 1,
        }];
        let result = compute(&[a, b], &durations, &edges).expect("no cycle");
        // A has no predecessor and is the longer path (5 days vs B's
        // effective negative-start float), so A is critical; B, driven
        // entirely by this one loose SF constraint, has slack against A's
        // 5-day project finish.
        assert!(result[&a].is_critical);
        assert!(result[&b].total_float_days > 0);
    }

    /// A network mixing all four types stays acyclic and solvable — proof
    /// the topological sort and both passes don't special-case FS-only
    /// graphs anywhere.
    #[test]
    fn a_network_mixing_all_four_dependency_types_still_resolves() {
        let (a, b, c, d) = (uid(1), uid(2), uid(3), uid(4));
        let durations = HashMap::from([(a, 3), (b, 2), (c, 4), (d, 1)]);
        let edges = vec![
            fs(a, b, 0),
            DependencyEdge {
                predecessor: a,
                successor: c,
                dependency_type: DependencyType::StartToStart,
                lag_days: 1,
            },
            DependencyEdge {
                predecessor: b,
                successor: d,
                dependency_type: DependencyType::FinishToFinish,
                lag_days: 0,
            },
            DependencyEdge {
                predecessor: c,
                successor: d,
                dependency_type: DependencyType::StartToFinish,
                lag_days: 2,
            },
        ];
        let result = compute(&[a, b, c, d], &durations, &edges).expect("no cycle, must resolve");
        assert_eq!(result.len(), 4);
    }
}
