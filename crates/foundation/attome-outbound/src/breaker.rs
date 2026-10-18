//! A circuit breaker per outside service. It watches the last calls' outcomes
//! and, when too many fail, refuses calls for a while instead of letting
//! every request wait on a service that is down. After the pause it lets a
//! few probe calls through; if they succeed it closes again.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// When a breaker opens and how it recovers.
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// How many recent outcomes it remembers.
    pub window: usize,
    /// The fewest calls in the window before it may open.
    pub min_calls: usize,
    /// The failure share, 0 to 1, that opens it.
    pub failure_rate: f64,
    /// How long it stays open.
    pub open_for: Duration,
    /// How many probe calls it lets through, half open; all must succeed.
    pub probes: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            window: 50,
            min_calls: 20,
            failure_rate: 0.5,
            open_for: Duration::from_secs(30),
            probes: 3,
        }
    }
}

/// Where a breaker stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
struct Inner {
    state: BreakerState,
    outcomes: VecDeque<bool>,
    open_until: Option<Instant>,
    probes_left: u32,
    probes_passed: u32,
}

/// One service's breaker.
#[derive(Debug)]
pub struct Breaker {
    config: BreakerConfig,
    inner: Mutex<Inner>,
}

impl Breaker {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(Inner {
                state: BreakerState::Closed,
                outcomes: VecDeque::with_capacity(config.window),
                open_until: None,
                probes_left: 0,
                probes_passed: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn state(&self) -> BreakerState {
        self.lock().state
    }

    /// Whether a call may go now; when not, how long until it may.
    pub fn allow(&self) -> Result<(), Duration> {
        self.allow_at(Instant::now())
    }

    /// [`allow`](Self::allow) at `now`.
    pub fn allow_at(&self, now: Instant) -> Result<(), Duration> {
        let mut inner = self.lock();
        match inner.state {
            BreakerState::Closed => Ok(()),
            BreakerState::Open => {
                let until = inner.open_until.unwrap_or(now);
                if now < until {
                    return Err(until - now);
                }
                inner.state = BreakerState::HalfOpen;
                inner.probes_left = self.config.probes.saturating_sub(1);
                inner.probes_passed = 0;
                Ok(())
            }
            BreakerState::HalfOpen if inner.probes_left > 0 => {
                inner.probes_left -= 1;
                Ok(())
            }
            // Every probe is out; wait for their answers.
            BreakerState::HalfOpen => Err(Duration::from_secs(1)),
        }
    }

    /// Records a call's outcome: `false` for a failure of the service (a
    /// timeout, a 5xx), never for a refusal of the request itself.
    pub fn record(&self, success: bool) {
        self.record_at(success, Instant::now());
    }

    /// [`record`](Self::record) at `now`.
    pub fn record_at(&self, success: bool, now: Instant) {
        let mut inner = self.lock();
        match inner.state {
            BreakerState::Closed => {
                if inner.outcomes.len() == self.config.window {
                    inner.outcomes.pop_front();
                }
                inner.outcomes.push_back(success);
                let calls = inner.outcomes.len();
                let failures = inner.outcomes.iter().filter(|ok| !**ok).count();
                if calls >= self.config.min_calls
                    && failures as f64 / calls as f64 >= self.config.failure_rate
                {
                    tracing::warn!(failures, calls, "outbound: breaker opened");
                    inner.state = BreakerState::Open;
                    inner.open_until = Some(now + self.config.open_for);
                    inner.outcomes.clear();
                }
            }
            BreakerState::HalfOpen if !success => {
                inner.state = BreakerState::Open;
                inner.open_until = Some(now + self.config.open_for);
            }
            BreakerState::HalfOpen => {
                inner.probes_passed += 1;
                if inner.probes_passed >= self.config.probes {
                    tracing::info!("outbound: breaker closed");
                    inner.state = BreakerState::Closed;
                    inner.outcomes.clear();
                }
            }
            BreakerState::Open => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breaker_opens_on_errors() {
        let breaker = Breaker::new(BreakerConfig::default());
        let now = Instant::now();
        for _ in 0..19 {
            breaker.record_at(false, now);
        }
        assert_eq!(
            breaker.state(),
            BreakerState::Closed,
            "too few calls to judge"
        );
        breaker.record_at(false, now);
        assert_eq!(breaker.state(), BreakerState::Open);
        let wait = breaker.allow_at(now).unwrap_err();
        assert_eq!(wait, Duration::from_secs(30));
    }

    #[test]
    fn breaker_half_open_recovers() {
        let breaker = Breaker::new(BreakerConfig::default());
        let now = Instant::now();
        for _ in 0..20 {
            breaker.record_at(false, now);
        }
        let later = now + Duration::from_secs(31);
        for _ in 0..3 {
            assert!(breaker.allow_at(later).is_ok(), "three probes go through");
        }
        assert!(breaker.allow_at(later).is_err(), "no fourth while they run");
        for _ in 0..3 {
            breaker.record_at(true, later);
        }
        assert_eq!(breaker.state(), BreakerState::Closed);
        assert!(breaker.allow_at(later).is_ok());
    }

    #[test]
    fn a_failed_probe_opens_it_again() {
        let breaker = Breaker::new(BreakerConfig::default());
        let now = Instant::now();
        for _ in 0..20 {
            breaker.record_at(false, now);
        }
        let later = now + Duration::from_secs(31);
        assert!(breaker.allow_at(later).is_ok());
        breaker.record_at(false, later);
        assert_eq!(breaker.state(), BreakerState::Open);
    }

    #[test]
    fn mostly_good_calls_keep_it_closed() {
        let breaker = Breaker::new(BreakerConfig::default());
        let now = Instant::now();
        for i in 0..100 {
            breaker.record_at(i % 3 != 0, now);
        }
        assert_eq!(breaker.state(), BreakerState::Closed);
    }
}
