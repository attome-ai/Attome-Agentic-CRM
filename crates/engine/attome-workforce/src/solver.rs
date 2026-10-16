//! The schedule solver (roadmap G17-T5), pure, behind [`ScheduleSolver`] so
//! a better one can replace it. The day is a run of intervals with a
//! requirement each (from [`crate::staffing`]); shift templates cover a run
//! of intervals; each agent may work one of the templates they are allowed.
//!
//! [`GreedySolver`] builds a schedule by repeatedly giving the free agent the
//! template that covers the most unmet requirement, then improves it by
//! local search: move one agent to another allowed template (or off) when
//! that lowers the cost. Cost is under-staffing weighted above
//! over-staffing, since a short interval misses the service level while an
//! extra agent only costs money. The rules check
//! ([`crate::rules::check`]) runs on the result afterwards.

use uuid::Uuid;

/// A shift template over interval indices `[start, end)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub id: Uuid,
    pub start: usize,
    pub end: usize,
}

/// An agent and the templates they may work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    pub id: Uuid,
    pub allowed: Vec<Uuid>,
}

/// One agent's shift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub agent: Uuid,
    pub template: Uuid,
}

/// A solved day.
#[derive(Debug, Clone, PartialEq)]
pub struct Solution {
    pub assignments: Vec<Assignment>,
    /// Agents on the floor per interval.
    pub coverage: Vec<u32>,
    pub under: u32,
    pub over: u32,
}

/// What the solver is asked.
#[derive(Debug, Clone, PartialEq)]
pub struct Problem {
    pub requirement: Vec<u32>,
    pub templates: Vec<Template>,
    pub agents: Vec<Agent>,
    /// Cost of one missing agent-interval against one extra (default 3).
    pub under_weight: f64,
}

/// A schedule solver.
pub trait ScheduleSolver {
    fn solve(&self, problem: &Problem) -> Solution;
}

/// Greedy construction plus local search.
#[derive(Debug, Clone, Copy)]
pub struct GreedySolver {
    /// Rounds of local search (each tries every agent once).
    pub improvement_rounds: usize,
}

impl Default for GreedySolver {
    fn default() -> Self {
        Self {
            improvement_rounds: 10,
        }
    }
}

fn coverage_of(problem: &Problem, chosen: &[Option<usize>]) -> Vec<u32> {
    let mut coverage = vec![0u32; problem.requirement.len()];
    for t in chosen.iter().flatten() {
        let template = &problem.templates[*t];
        for slot in coverage.iter_mut().take(template.end).skip(template.start) {
            *slot += 1;
        }
    }
    coverage
}

fn cost(problem: &Problem, coverage: &[u32]) -> f64 {
    problem
        .requirement
        .iter()
        .zip(coverage)
        .map(|(need, have)| {
            if have < need {
                f64::from(need - have) * problem.under_weight
            } else {
                f64::from(have - need)
            }
        })
        .sum()
}

/// The template indices an agent may work.
fn allowed_indices(problem: &Problem, agent: &Agent) -> Vec<usize> {
    problem
        .templates
        .iter()
        .enumerate()
        .filter(|(_, t)| {
            agent.allowed.contains(&t.id) && t.start < t.end && t.end <= problem.requirement.len()
        })
        .map(|(i, _)| i)
        .collect()
}

impl ScheduleSolver for GreedySolver {
    fn solve(&self, problem: &Problem) -> Solution {
        let mut chosen: Vec<Option<usize>> = vec![None; problem.agents.len()];
        let allowed: Vec<Vec<usize>> = problem
            .agents
            .iter()
            .map(|a| allowed_indices(problem, a))
            .collect();

        // Greedy: while some agent's best template still lowers the cost,
        // place the agent and template that lower it most.
        loop {
            let coverage = coverage_of(problem, &chosen);
            let current = cost(problem, &coverage);
            let mut best: Option<(usize, usize, f64)> = None;
            for (a, options) in allowed.iter().enumerate() {
                if chosen[a].is_some() {
                    continue;
                }
                for &t in options {
                    chosen[a] = Some(t);
                    let c = cost(problem, &coverage_of(problem, &chosen));
                    chosen[a] = None;
                    if c < current - 1e-9 && best.is_none_or(|(_, _, bc)| c < bc) {
                        best = Some((a, t, c));
                    }
                }
            }
            match best {
                Some((a, t, _)) => chosen[a] = Some(t),
                None => break,
            }
        }

        // Local search: move one agent at a time to its best option.
        for _ in 0..self.improvement_rounds {
            let mut improved = false;
            for a in 0..chosen.len() {
                let start = cost(problem, &coverage_of(problem, &chosen));
                let original = chosen[a];
                let mut best = (original, start);
                for candidate in std::iter::once(None).chain(allowed[a].iter().map(|t| Some(*t))) {
                    chosen[a] = candidate;
                    let c = cost(problem, &coverage_of(problem, &chosen));
                    if c < best.1 - 1e-9 {
                        best = (candidate, c);
                    }
                }
                chosen[a] = best.0;
                improved |= best.0 != original;
            }
            if !improved {
                break;
            }
        }

        let coverage = coverage_of(problem, &chosen);
        let (mut under, mut over) = (0, 0);
        for (need, have) in problem.requirement.iter().zip(&coverage) {
            if have < need {
                under += need - have;
            } else {
                over += have - need;
            }
        }
        Solution {
            assignments: chosen
                .iter()
                .zip(&problem.agents)
                .filter_map(|(t, agent)| {
                    t.map(|t| Assignment {
                        agent: agent.id,
                        template: problem.templates[t].id,
                    })
                })
                .collect(),
            coverage,
            under,
            over,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn template(n: u128, start: usize, end: usize) -> Template {
        Template {
            id: u(n),
            start,
            end,
        }
    }

    fn agents(count: u128, allowed: &[u128]) -> Vec<Agent> {
        (0..count)
            .map(|i| Agent {
                id: u(1000 + i),
                allowed: allowed.iter().map(|t| u(*t)).collect(),
            })
            .collect()
    }

    #[test]
    fn covers_a_two_peak_day_exactly() {
        // Morning needs 2, afternoon 1; templates for each half.
        let problem = Problem {
            requirement: vec![2, 2, 1, 1],
            templates: vec![template(1, 0, 2), template(2, 2, 4), template(3, 0, 4)],
            agents: agents(4, &[1, 2, 3]),
            under_weight: 3.0,
        };
        let s = GreedySolver::default().solve(&problem);
        assert_eq!(s.under, 0);
        assert_eq!(s.over, 0);
        assert_eq!(s.coverage, vec![2, 2, 1, 1]);
    }

    #[test]
    fn short_staff_leaves_the_least_under_coverage() {
        let problem = Problem {
            requirement: vec![3, 3, 3, 3],
            templates: vec![template(1, 0, 4)],
            agents: agents(2, &[1]),
            under_weight: 3.0,
        };
        let s = GreedySolver::default().solve(&problem);
        assert_eq!(s.assignments.len(), 2);
        assert_eq!(s.under, 4);
    }

    #[test]
    fn agents_only_work_allowed_templates_and_idle_when_not_needed() {
        let mut team = agents(1, &[2]);
        team.extend(agents(1, &[1]).into_iter().map(|mut a| {
            a.id = u(2000);
            a
        }));
        let problem = Problem {
            requirement: vec![1, 1, 0, 0],
            templates: vec![template(1, 0, 2), template(2, 2, 4)],
            agents: team,
            under_weight: 3.0,
        };
        let s = GreedySolver::default().solve(&problem);
        assert_eq!(
            s.assignments,
            vec![Assignment {
                agent: u(2000),
                template: u(1)
            }]
        );
        assert_eq!(s.over, 0);
    }
}
