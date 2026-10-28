//! On-call (roadmap H7-T1), pure: who is on call at a moment, and who an
//! unacknowledged alert goes to next.
//!
//! A schedule is a stack of rotation layers. Each layer hands over every
//! `shift` from its `handover` start, cycling through its members, and may
//! be limited to a daily window (business hours). The highest layer that
//! has someone at the moment wins, so a weekend layer placed above the
//! weekly one covers its hours. An override (a person swapping in for a
//! period) beats every layer.
//!
//! An escalation policy is a list of steps, each naming schedules or people
//! and how long to wait for an acknowledgement before the next step;
//! [`escalation_target`] says which step is current after a given time
//! without acknowledgement. The timers themselves run on the platform's
//! timer sweep; this module only answers the questions, so tests use a
//! fixed clock.

use chrono::{DateTime, Duration, NaiveTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// H7-T2: the on-call calendar route over stored schedules.
pub mod calendar;

/// One rotation layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    /// In rotation order.
    pub members: Vec<Uuid>,
    /// The first handover: `members[0]` starts here.
    pub handover: DateTime<Utc>,
    /// How long each turn lasts.
    pub shift: Duration,
    /// A daily window (UTC) the layer covers; `None` is all day. A window
    /// whose end is before its start runs past midnight.
    pub daily_window: Option<(NaiveTime, NaiveTime)>,
    /// When the layer stops applying.
    pub until: Option<DateTime<Utc>>,
}

/// A person on call in place of the rotation for a period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Override {
    pub user: Uuid,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Schedule {
    /// Lowest first; a higher layer wins where it has someone.
    pub layers: Vec<Layer>,
    pub overrides: Vec<Override>,
}

/// Why someone is on call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "via", rename_all = "snake_case")]
pub enum OnCall {
    Override { user: Uuid },
    Layer { user: Uuid, layer: usize },
}

impl OnCall {
    pub fn user(self) -> Uuid {
        match self {
            Self::Override { user } | Self::Layer { user, .. } => user,
        }
    }
}

fn in_window(window: Option<(NaiveTime, NaiveTime)>, at: DateTime<Utc>) -> bool {
    let Some((from, to)) = window else {
        return true;
    };
    let t = at.time();
    if from <= to {
        from <= t && t < to
    } else {
        t >= from || t < to
    }
}

/// The member of `layer` on call at `at`.
pub fn layer_member(layer: &Layer, at: DateTime<Utc>) -> Option<Uuid> {
    if layer.members.is_empty()
        || at < layer.handover
        || layer.until.is_some_and(|u| at >= u)
        || !in_window(layer.daily_window, at)
    {
        return None;
    }
    let shift = layer.shift.num_seconds();
    if shift <= 0 {
        return None;
    }
    let turns = (at - layer.handover).num_seconds() / shift;
    let len = i64::try_from(layer.members.len()).ok()?;
    let index = usize::try_from(turns.rem_euclid(len)).ok()?;
    layer.members.get(index).copied()
}

/// Who is on call at `at`: the latest-starting override covering it, else
/// the highest layer with someone.
pub fn on_call(schedule: &Schedule, at: DateTime<Utc>) -> Option<OnCall> {
    if let Some(o) = schedule
        .overrides
        .iter()
        .filter(|o| o.start <= at && at < o.end)
        .max_by_key(|o| o.start)
    {
        return Some(OnCall::Override { user: o.user });
    }
    schedule
        .layers
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, layer)| layer_member(layer, at).map(|user| OnCall::Layer { user, layer: i }))
}

/// H7-T2: the most change points [`timeline`] walks; a schedule whose shifts
/// are so short that a range holds more is refused.
pub const MAX_TIMELINE_POINTS: usize = 20_000;

/// One stretch of a schedule with one person on call: `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stretch {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub on_call: OnCall,
}

/// H7-T2: who is on call over `[from, to)`, as stretches in time order;
/// gaps with nobody on call are left out. The answer can only change at a
/// handover, a daily window's edge, a layer's end or an override's edge, so
/// [`on_call`] is asked once per stretch between those points. `None` when
/// the range holds more than [`MAX_TIMELINE_POINTS`] of them. Pure.
pub fn timeline(
    schedule: &Schedule,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Option<Vec<Stretch>> {
    if to <= from {
        return Some(Vec::new());
    }
    let mut points = vec![from];
    for layer in &schedule.layers {
        let shift = layer.shift.num_seconds();
        if shift > 0 {
            let mut turn = if from <= layer.handover {
                0
            } else {
                (from - layer.handover).num_seconds() / shift
            };
            loop {
                let at = layer.handover + Duration::seconds(turn.checked_mul(shift)?);
                if at >= to {
                    break;
                }
                points.push(at);
                if points.len() > MAX_TIMELINE_POINTS {
                    return None;
                }
                turn += 1;
            }
        }
        if let Some(until) = layer.until {
            points.push(until);
        }
        if let Some((open, close)) = layer.daily_window {
            let mut day = from.date_naive().pred_opt()?;
            while day <= to.date_naive() {
                points.push(day.and_time(open).and_utc());
                points.push(day.and_time(close).and_utc());
                if points.len() > MAX_TIMELINE_POINTS {
                    return None;
                }
                day = day.succ_opt()?;
            }
        }
    }
    for o in &schedule.overrides {
        points.push(o.start);
        points.push(o.end);
    }
    points.retain(|at| *at >= from && *at < to);
    points.sort_unstable();
    points.dedup();
    let mut out: Vec<Stretch> = Vec::new();
    for (i, start) in points.iter().enumerate() {
        let end = points.get(i + 1).copied().unwrap_or(to);
        let Some(on_call) = on_call(schedule, *start) else {
            continue;
        };
        match out.last_mut() {
            Some(last) if last.end == *start && last.on_call == on_call => last.end = end,
            _ => out.push(Stretch {
                start: *start,
                end,
                on_call,
            }),
        }
    }
    Some(out)
}

/// Who a step notifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Schedule(Uuid),
    User(Uuid),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub targets: Vec<Target>,
    /// How long to wait for an acknowledgement before the next step.
    pub wait: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub steps: Vec<Step>,
    /// Times to run the whole list again after the last step (0: once).
    pub repeat: u32,
}

/// The step that is current `elapsed` after an alert opened without an
/// acknowledgement, and when the next step starts; `None` when the policy
/// is exhausted.
pub fn escalation_target(policy: &Policy, elapsed: Duration) -> Option<(usize, Duration)> {
    let round: i64 = policy
        .steps
        .iter()
        .map(|s| s.wait.num_seconds().max(1))
        .sum();
    if round <= 0 || elapsed < Duration::zero() {
        return policy.steps.first().map(|s| (0, s.wait));
    }
    let rounds = i64::from(policy.repeat) + 1;
    let total = elapsed.num_seconds();
    if total >= round * rounds {
        return None;
    }
    let mut into = total % round;
    let base = total - into;
    for (i, step) in policy.steps.iter().enumerate() {
        let wait = step.wait.num_seconds().max(1);
        if into < wait {
            let next = base + (total % round - into) + wait;
            return Some((i, Duration::seconds(next)));
        }
        into -= wait;
    }
    None
}

/// The people a step notifies at `at`, without repeats.
pub fn step_recipients(
    step: &Step,
    schedules: &[(Uuid, Schedule)],
    at: DateTime<Utc>,
) -> Vec<Uuid> {
    let mut out = Vec::new();
    for target in &step.targets {
        let user = match target {
            Target::User(u) => Some(*u),
            Target::Schedule(id) => schedules
                .iter()
                .find(|(s, _)| s == id)
                .and_then(|(_, schedule)| on_call(schedule, at))
                .map(OnCall::user),
        };
        if let Some(user) = user
            && !out.contains(&user)
        {
            out.push(user);
        }
    }
    out
}

#[cfg(test)]
mod oncall_resolution {
    use super::*;
    use chrono::TimeZone;

    fn at(day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, day, hour, 0, 0)
            .single()
            .unwrap_or_default()
    }

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn weekly() -> Layer {
        Layer {
            members: vec![u(1), u(2), u(3)],
            // Monday 2 November 2026, 09:00.
            handover: at(2, 9),
            shift: Duration::weeks(1),
            daily_window: None,
            until: None,
        }
    }

    #[test]
    fn the_timeline_lists_who_is_on_call_between_two_moments() {
        let schedule = Schedule {
            layers: vec![weekly()],
            overrides: vec![Override {
                user: u(9),
                start: at(10, 12),
                end: at(11, 12),
            }],
        };
        let stretches = timeline(&schedule, at(1, 0), at(17, 0)).expect("a bounded range");
        let shown: Vec<(DateTime<Utc>, DateTime<Utc>, Uuid)> = stretches
            .iter()
            .map(|s| (s.start, s.end, s.on_call.user()))
            .collect();
        assert_eq!(
            shown,
            vec![
                (at(2, 9), at(9, 9), u(1)),
                (at(9, 9), at(10, 12), u(2)),
                (at(10, 12), at(11, 12), u(9)),
                (at(11, 12), at(16, 9), u(2)),
                (at(16, 9), at(17, 0), u(3)),
            ],
            "nobody before the first handover; the override splits the week"
        );
        assert!(timeline(&schedule, at(5, 0), at(5, 0)).is_some_and(|s| s.is_empty()));
        let minutely = Schedule {
            layers: vec![Layer {
                shift: Duration::minutes(1),
                ..weekly()
            }],
            overrides: vec![],
        };
        assert!(
            timeline(&minutely, at(2, 9), at(30, 0)).is_none(),
            "too many points"
        );
    }

    #[test]
    fn the_timeline_follows_a_daily_window() {
        let nights = Layer {
            members: vec![u(7)],
            handover: at(1, 0),
            shift: Duration::days(7),
            daily_window: NaiveTime::from_hms_opt(20, 0, 0).zip(NaiveTime::from_hms_opt(6, 0, 0)),
            until: None,
        };
        let schedule = Schedule {
            layers: vec![nights],
            overrides: vec![],
        };
        let stretches = timeline(&schedule, at(3, 0), at(5, 0)).expect("a bounded range");
        let shown: Vec<(DateTime<Utc>, DateTime<Utc>)> =
            stretches.iter().map(|s| (s.start, s.end)).collect();
        assert_eq!(
            shown,
            vec![
                (at(3, 0), at(3, 6)),
                (at(3, 20), at(4, 6)),
                (at(4, 20), at(5, 0))
            ]
        );
    }

    #[test]
    fn the_rotation_hands_over_weekly() {
        let schedule = Schedule {
            layers: vec![weekly()],
            overrides: vec![],
        };
        let who = |day, hour| on_call(&schedule, at(day, hour)).map(OnCall::user);
        assert_eq!(who(2, 9), Some(u(1)));
        assert_eq!(who(9, 8), Some(u(1)), "until the handover hour");
        assert_eq!(who(9, 9), Some(u(2)));
        assert_eq!(who(23, 9), Some(u(1)), "the rotation cycles");
        assert_eq!(who(1, 12), None, "nobody before the first handover");
    }

    #[test]
    fn a_higher_layer_and_an_override_win() {
        let nights = Layer {
            members: vec![u(7)],
            handover: at(1, 0),
            shift: Duration::days(1),
            daily_window: NaiveTime::from_hms_opt(20, 0, 0).zip(NaiveTime::from_hms_opt(6, 0, 0)),
            until: None,
        };
        let schedule = Schedule {
            layers: vec![weekly(), nights],
            overrides: vec![Override {
                user: u(9),
                start: at(4, 12),
                end: at(4, 18),
            }],
        };
        assert_eq!(
            on_call(&schedule, at(3, 22)),
            Some(OnCall::Layer {
                user: u(7),
                layer: 1
            }),
            "the night layer covers 20:00 to 06:00"
        );
        assert_eq!(on_call(&schedule, at(3, 10)).map(OnCall::user), Some(u(1)));
        assert_eq!(
            on_call(&schedule, at(4, 13)),
            Some(OnCall::Override { user: u(9) })
        );
        assert_eq!(on_call(&schedule, at(4, 18)).map(OnCall::user), Some(u(1)));
    }

    #[test]
    fn escalation_moves_on_without_acknowledgement() {
        let policy = Policy {
            steps: vec![
                Step {
                    targets: vec![Target::Schedule(u(100))],
                    wait: Duration::minutes(5),
                },
                Step {
                    targets: vec![Target::User(u(50)), Target::Schedule(u(100))],
                    wait: Duration::minutes(10),
                },
            ],
            repeat: 1,
        };
        assert_eq!(
            escalation_target(&policy, Duration::minutes(0)),
            Some((0, Duration::minutes(5)))
        );
        assert_eq!(
            escalation_target(&policy, Duration::minutes(7)),
            Some((1, Duration::minutes(15)))
        );
        assert_eq!(
            escalation_target(&policy, Duration::minutes(16)),
            Some((0, Duration::minutes(20))),
            "the policy runs again once"
        );
        assert_eq!(escalation_target(&policy, Duration::minutes(30)), None);

        let schedules = [(
            u(100),
            Schedule {
                layers: vec![weekly()],
                overrides: vec![],
            },
        )];
        assert_eq!(
            step_recipients(&policy.steps[1], &schedules, at(3, 10)),
            vec![u(50), u(1)]
        );
    }
}
