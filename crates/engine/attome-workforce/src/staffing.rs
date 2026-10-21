//! Staffing requirement (roadmap G17-T3), pure: how many agents each
//! interval needs. Live channels (voice, chat) use Erlang C against a
//! service-level target; deferred work (email, cases) uses its workload over
//! the backlog target. Shrinkage (breaks, training, absence) is added on top.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The most agents the Erlang C search tries before giving up.
const MAX_AGENTS: u32 = 5_000;

/// Erlang C: the probability a contact waits, for `agents` serving
/// `traffic` erlangs. Computed through the Erlang B recurrence, so it stays
/// finite for hundreds of agents where factorials would overflow.
fn erlang_c(agents: u32, traffic: f64) -> f64 {
    if f64::from(agents) <= traffic {
        return 1.0;
    }
    let mut b = 1.0;
    for k in 1..=agents {
        b = traffic * b / (f64::from(k) + traffic * b);
    }
    let n = f64::from(agents);
    n * b / (n - traffic * (1.0 - b))
}

/// The share of contacts answered within `target_secs` with `agents`.
pub fn service_level(agents: u32, traffic: f64, aht_secs: f64, target_secs: f64) -> f64 {
    let n = f64::from(agents);
    if n <= traffic {
        return 0.0;
    }
    1.0 - erlang_c(agents, traffic) * (-(n - traffic) * target_secs / aht_secs).exp()
}

/// The fewest agents that answer `target_pct` (0-100) of contacts within
/// `target_secs`. `concurrency` is how many contacts one agent handles at
/// once (1 for voice, more for chat).
pub fn erlang_c_agents(
    calls_per_interval: f64,
    aht_secs: f64,
    interval_secs: f64,
    target_pct: f64,
    target_secs: f64,
    concurrency: f64,
) -> u32 {
    if calls_per_interval <= 0.0 || aht_secs <= 0.0 || interval_secs <= 0.0 {
        return 0;
    }
    let effective_aht = aht_secs / concurrency.max(1.0);
    let traffic = calls_per_interval * effective_aht / interval_secs;
    let target = (target_pct / 100.0).clamp(0.0, 1.0);
    // Start just above the traffic: fewer agents than erlangs never keep up.
    let mut agents = (traffic.floor() as u32).saturating_add(1);
    while agents < MAX_AGENTS && service_level(agents, traffic, effective_aht, target_secs) < target
    {
        agents += 1;
    }
    agents
}

/// Agents to clear `items` of deferred work arriving in an interval within
/// the backlog target: the work spreads over the longer of the interval and
/// the target.
pub fn workload_agents(items: f64, aht_secs: f64, interval_secs: f64, backlog_hours: f64) -> u32 {
    if items <= 0.0 || aht_secs <= 0.0 {
        return 0;
    }
    let window = interval_secs.max(backlog_hours * 3600.0);
    if window <= 0.0 {
        return 0;
    }
    (items * aht_secs / window).ceil() as u32
}

/// Agents to schedule so `agents` are available after shrinkage
/// (`shrinkage_pct`, 0-100), rounded up.
pub fn apply_shrinkage(agents: u32, shrinkage_pct: f64) -> u32 {
    let shrinkage = (shrinkage_pct / 100.0).clamp(0.0, 0.95);
    (f64::from(agents) / (1.0 - shrinkage)).ceil() as u32
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Voice,
    Chat,
    Email,
    Case,
}

/// A planning group's staffing rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanningGroup {
    pub id: Uuid,
    pub channel: ChannelKind,
    pub aht_secs: f64,
    /// Service-level target for live channels: `target_pct` within
    /// `target_secs`.
    pub target_pct: f64,
    pub target_secs: f64,
    /// Contacts one agent handles at once (chat).
    pub concurrency: f64,
    /// How long deferred work may wait (email, cases).
    pub backlog_hours: f64,
    pub shrinkage_pct: f64,
}

/// One interval of the volume forecast (G16).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntervalForecast {
    pub start: DateTime<Utc>,
    pub interval_secs: f64,
    pub volume: f64,
    /// The share (0-1) digital workers (agents in software) handle.
    pub digital_share: f64,
}

/// Where the forecast comes from; G16 implements it.
pub trait ForecastSource {
    fn intervals(
        &self,
        group_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Vec<IntervalForecast>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntervalRequirement {
    pub start: DateTime<Utc>,
    /// Agents needed on the floor.
    pub agents: u32,
    /// Agents to schedule, with shrinkage.
    pub scheduled: u32,
}

/// The requirement per forecast interval for `group`, after taking out the
/// share digital workers handle.
pub fn requirement_for_group(
    group: &PlanningGroup,
    forecast: &[IntervalForecast],
) -> Vec<IntervalRequirement> {
    forecast
        .iter()
        .map(|f| {
            let human = f.volume * (1.0 - f.digital_share.clamp(0.0, 1.0));
            let agents = match group.channel {
                ChannelKind::Voice => erlang_c_agents(
                    human,
                    group.aht_secs,
                    f.interval_secs,
                    group.target_pct,
                    group.target_secs,
                    1.0,
                ),
                ChannelKind::Chat => erlang_c_agents(
                    human,
                    group.aht_secs,
                    f.interval_secs,
                    group.target_pct,
                    group.target_secs,
                    group.concurrency,
                ),
                ChannelKind::Email | ChannelKind::Case => {
                    workload_agents(human, group.aht_secs, f.interval_secs, group.backlog_hours)
                }
            };
            IntervalRequirement {
                start: f.start,
                agents,
                scheduled: apply_shrinkage(agents, group.shrinkage_pct),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(channel: ChannelKind) -> PlanningGroup {
        PlanningGroup {
            id: Uuid::now_v7(),
            channel,
            aht_secs: 180.0,
            target_pct: 80.0,
            target_secs: 20.0,
            concurrency: 2.0,
            backlog_hours: 4.0,
            shrinkage_pct: 30.0,
        }
    }

    fn interval(volume: f64, digital_share: f64) -> IntervalForecast {
        IntervalForecast {
            start: Utc::now(),
            interval_secs: 1800.0,
            volume,
            digital_share,
        }
    }

    #[test]
    fn erlang_c_reference_100_calls_gives_14() {
        assert_eq!(erlang_c_agents(100.0, 180.0, 1800.0, 80.0, 20.0, 1.0), 14);
        // Hundreds of agents stay finite.
        let big = erlang_c_agents(5000.0, 180.0, 1800.0, 80.0, 20.0, 1.0);
        assert!((500..600).contains(&big), "{big}");
    }

    #[test]
    fn workload_agents_email_backlog() {
        // 240 emails of 5 minutes over a 4-hour target: 20 agent-hours / 4 h.
        assert_eq!(workload_agents(240.0, 300.0, 1800.0, 4.0), 5);
        // A target shorter than the interval spreads over the interval.
        assert_eq!(workload_agents(12.0, 300.0, 1800.0, 0.0), 2);
        assert_eq!(apply_shrinkage(14, 30.0), 20);
        assert_eq!(apply_shrinkage(10, 0.0), 10);
    }

    #[test]
    fn requirement_picks_the_model_per_channel() {
        let voice = requirement_for_group(&group(ChannelKind::Voice), &[interval(100.0, 0.0)]);
        assert_eq!(voice[0].agents, 14);
        assert_eq!(voice[0].scheduled, 20);
        let chat = requirement_for_group(&group(ChannelKind::Chat), &[interval(100.0, 0.0)]);
        assert!(chat[0].agents < 14, "two chats at once need fewer agents");
        let email = requirement_for_group(&group(ChannelKind::Email), &[interval(240.0, 0.5)]);
        assert_eq!(
            email[0].agents, 2,
            "half the volume goes to digital workers"
        );
        let case = requirement_for_group(&group(ChannelKind::Case), &[interval(0.0, 0.0)]);
        assert_eq!(case[0].agents, 0);
    }

    #[test]
    fn more_volume_never_lowers_requirement() {
        let mut last = 0;
        for calls in 0..400 {
            let agents = erlang_c_agents(f64::from(calls), 180.0, 1800.0, 80.0, 20.0, 1.0);
            assert!(
                agents >= last,
                "{calls} calls need {agents}, fewer than {last}"
            );
            last = agents;
        }
        let mut last = 0;
        for items in 0..400 {
            let agents = workload_agents(f64::from(items), 300.0, 1800.0, 4.0);
            assert!(agents >= last);
            last = agents;
        }
    }
}
