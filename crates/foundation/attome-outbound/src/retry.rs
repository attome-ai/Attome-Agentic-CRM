//! When a failed outside call is tried again: a few times, further apart each
//! time with full jitter, and only while the service's retry budget lasts.
//! The budget keeps retries to a share of all calls, so a service that is
//! struggling is not hit with a retry storm on top of its normal load.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How a call is retried.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Attempts in all, the first included.
    pub max_attempts: u32,
    /// The ceiling of the first retry's wait.
    pub base: Duration,
    /// The largest wait.
    pub cap: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base: Duration::from_millis(100),
            cap: Duration::from_secs(5),
        }
    }
}

impl RetryPolicy {
    /// The wait before retry `retry` (1 for the first): a random point in
    /// `[0, min(cap, base * 2^(retry - 1))]`, from `seed`.
    pub fn backoff(&self, retry: u32, seed: u64) -> Duration {
        let exponent = retry.saturating_sub(1).min(20);
        let ceiling = self.base.saturating_mul(1u32 << exponent).min(self.cap);
        let millis = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
        if millis == 0 {
            return Duration::ZERO;
        }
        Duration::from_millis(seed % (millis + 1))
    }
}

/// A seed for [`RetryPolicy::backoff`] from the clock.
pub fn jitter_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::from(elapsed.subsec_nanos()))
}

#[derive(Debug)]
struct Window {
    started: Instant,
    calls: u64,
    retries: u64,
}

/// A service's allowance of retries: `ratio` of the calls in each `window`,
/// and never fewer than `min_retries`.
#[derive(Debug)]
pub struct RetryBudget {
    ratio: f64,
    window: Duration,
    min_retries: u64,
    current: Mutex<Window>,
}

impl Default for RetryBudget {
    fn default() -> Self {
        Self::new(0.1, Duration::from_secs(10), 3)
    }
}

impl RetryBudget {
    pub fn new(ratio: f64, window: Duration, min_retries: u64) -> Self {
        Self {
            ratio,
            window,
            min_retries,
            current: Mutex::new(Window {
                started: Instant::now(),
                calls: 0,
                retries: 0,
            }),
        }
    }

    fn at(&self, now: Instant) -> std::sync::MutexGuard<'_, Window> {
        let mut window = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if now.duration_since(window.started) >= self.window {
            *window = Window {
                started: now,
                calls: 0,
                retries: 0,
            };
        }
        window
    }

    /// Counts one call.
    pub fn record_call(&self) {
        self.record_call_at(Instant::now());
    }

    pub fn record_call_at(&self, now: Instant) {
        self.at(now).calls += 1;
    }

    /// Takes one retry from the budget, if any is left.
    pub fn try_retry(&self) -> bool {
        self.try_retry_at(Instant::now())
    }

    pub fn try_retry_at(&self, now: Instant) -> bool {
        let mut window = self.at(now);
        let allowed = ((window.calls as f64 * self.ratio) as u64).max(self.min_retries);
        if window.retries < allowed {
            window.retries += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_stays_under_its_cap() {
        let policy = RetryPolicy::default();
        for seed in [0, 7, 99, 12_345, u64::MAX] {
            assert!(policy.backoff(1, seed) <= Duration::from_millis(100));
            assert!(policy.backoff(2, seed) <= Duration::from_millis(200));
            assert!(policy.backoff(30, seed) <= Duration::from_secs(5));
        }
    }

    #[test]
    fn retry_budget_caps_retries() {
        let budget = RetryBudget::default();
        let now = Instant::now();
        for _ in 0..100 {
            budget.record_call_at(now);
        }
        let granted = (0..50).filter(|_| budget.try_retry_at(now)).count();
        assert_eq!(granted, 10, "10% of 100 calls");
        let next_window = now + Duration::from_secs(11);
        assert!(
            budget.try_retry_at(next_window),
            "a new window has its minimum"
        );
    }
}
