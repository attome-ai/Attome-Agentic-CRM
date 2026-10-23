//! AB6-T8: every outbound service's breaker, by service name, so the
//! capability probe can count an open breaker as a failed probe and the
//! breaker state can be published as a gauge.
//!
//! Services register themselves when they are made ([`crate::Service::new`]).
//! The registry holds only weak references, so an endpoint service dropped
//! from its map ([`crate::EndpointServices`]) is forgotten here too. Several
//! services can share a name (one per endpoint); a name's state is the worst
//! of them: open over half open over closed.

use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use crate::breaker::{Breaker, BreakerState};

/// AB6-T9: how long the call counts cover.
pub const STATS_WINDOW: Duration = Duration::from_secs(3600);

/// One service's calls, failures and retries in the current window. The
/// window restarts once it is older than [`STATS_WINDOW`], so the numbers
/// cover between the last hour and the last two.
#[derive(Debug)]
pub struct CallStats {
    inner: Mutex<Counts>,
}

#[derive(Debug, Clone, Copy)]
struct Counts {
    since: Instant,
    calls: u64,
    failures: u64,
    retries: u64,
}

impl Default for CallStats {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Counts {
                since: Instant::now(),
                calls: 0,
                failures: 0,
                retries: 0,
            }),
        }
    }
}

impl CallStats {
    fn with<R>(&self, f: impl FnOnce(&mut Counts) -> R) -> R {
        let mut counts = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if counts.since.elapsed() > STATS_WINDOW {
            *counts = Counts {
                since: Instant::now(),
                calls: 0,
                failures: 0,
                retries: 0,
            };
        }
        f(&mut counts)
    }

    pub(crate) fn call(&self, failed: bool) {
        self.with(|c| {
            c.calls += 1;
            if failed {
                c.failures += 1;
            }
        });
    }

    pub(crate) fn retry(&self) {
        self.with(|c| c.retries += 1);
    }

    fn snapshot(&self) -> (u64, u64, u64) {
        self.with(|c| (c.calls, c.failures, c.retries))
    }
}

/// One registered service: its name, breaker and call counts.
type Entry = (&'static str, Weak<Breaker>, Weak<CallStats>);

static SERVICES: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

pub(crate) fn register(name: &'static str, breaker: &Arc<Breaker>, stats: &Arc<CallStats>) {
    let mut services = SERVICES.lock().unwrap_or_else(PoisonError::into_inner);
    services.retain(|(_, weak, _)| weak.strong_count() > 0);
    services.push((name, Arc::downgrade(breaker), Arc::downgrade(stats)));
}

fn rank(state: BreakerState) -> u8 {
    match state {
        BreakerState::Closed => 0,
        BreakerState::HalfOpen => 1,
        BreakerState::Open => 2,
    }
}

/// One service name's breaker state now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceState {
    pub name: &'static str,
    pub state: BreakerState,
    /// Live services under this name (endpoints, for an endpoint map).
    pub count: usize,
    /// Calls, failed calls and retries in the last hour, over all of them.
    pub calls: u64,
    pub failures: u64,
    pub retries: u64,
}

impl ServiceState {
    /// Failed calls over all calls, or `None` before the first call.
    pub fn error_rate(&self) -> Option<f64> {
        (self.calls > 0).then(|| self.failures as f64 / self.calls as f64)
    }
}

/// Every service name's worst breaker state, sorted by name.
pub fn states() -> Vec<ServiceState> {
    let services = SERVICES.lock().unwrap_or_else(PoisonError::into_inner);
    let mut out: Vec<ServiceState> = Vec::new();
    for (name, weak, stats) in services.iter() {
        let Some(breaker) = weak.upgrade() else {
            continue;
        };
        let state = breaker.state();
        let (calls, failures, retries) = stats.upgrade().map_or((0, 0, 0), |s| s.snapshot());
        match out.iter_mut().find(|s| s.name == *name) {
            Some(entry) => {
                entry.count += 1;
                entry.calls += calls;
                entry.failures += failures;
                entry.retries += retries;
                if rank(state) > rank(entry.state) {
                    entry.state = state;
                }
            }
            None => out.push(ServiceState {
                name,
                state,
                count: 1,
                calls,
                failures,
                retries,
            }),
        }
    }
    out.sort_by_key(|s| s.name);
    out
}

/// The worst state of the services named `name`; `None` when there is none.
pub fn state_of(name: &str) -> Option<BreakerState> {
    states()
        .into_iter()
        .find(|s| s.name == name)
        .map(|s| s.state)
}

/// Publishes `outbound_breaker_state{service}` (0 closed, 1 half open,
/// 2 open) for every service name. The capability probe calls it each round.
pub fn publish() -> Vec<ServiceState> {
    let states = states();
    for s in &states {
        metrics::gauge!("outbound_breaker_state", "service" => s.name)
            .set(f64::from(rank(s.state)));
    }
    states
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Policy, Service};

    #[test]
    fn a_name_reports_its_worst_breaker() {
        let a = Service::new("registry_test_svc", Policy::default());
        let b = Service::new("registry_test_svc", Policy::default());
        assert_eq!(state_of("registry_test_svc"), Some(BreakerState::Closed));
        for _ in 0..30 {
            b.breaker.record(false);
        }
        assert_eq!(state_of("registry_test_svc"), Some(BreakerState::Open));
        let entry = states()
            .into_iter()
            .find(|s| s.name == "registry_test_svc")
            .expect("registered");
        assert_eq!(entry.count, 2);
        a.stats.call(false);
        b.stats.call(true);
        b.stats.retry();
        let entry = states()
            .into_iter()
            .find(|s| s.name == "registry_test_svc")
            .expect("registered");
        assert_eq!((entry.calls, entry.failures, entry.retries), (2, 1, 1));
        assert_eq!(entry.error_rate(), Some(0.5));
        drop(b);
        assert_eq!(
            state_of("registry_test_svc"),
            Some(BreakerState::Closed),
            "a dropped service is forgotten"
        );
        drop(a);
        assert_eq!(state_of("registry_test_svc"), None);
    }
}
