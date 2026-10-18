//! Z15-T5: the time a decision reads, so a test can move it. Production
//! passes [`SystemClock`]; a test passes a [`FakeClock`] and advances it
//! instead of sleeping.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};

/// Where "now" comes from.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> DateTime<Utc>;
}

/// The system's own clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A clock that stands still until told to move. Clones share one time.
#[derive(Debug, Clone)]
pub struct FakeClock(Arc<Mutex<DateTime<Utc>>>);

impl FakeClock {
    pub fn new(at: DateTime<Utc>) -> Self {
        Self(Arc::new(Mutex::new(at)))
    }

    /// Moves the clock on by `by`.
    pub fn advance(&self, by: Duration) {
        let mut at = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *at += by;
    }

    /// Sets the clock to `at`.
    pub fn set(&self, at: DateTime<Utc>) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = at;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> DateTime<Utc> {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_close_to_utc_now() {
        let gap = (SystemClock.now() - Utc::now()).num_milliseconds().abs();
        assert!(gap < 1_000, "{gap} ms");
    }

    #[test]
    fn fake_clock_moves_only_when_told() {
        let start = Utc::now();
        let clock = FakeClock::new(start);
        let shared = clock.clone();
        assert_eq!(clock.now(), start);
        shared.advance(Duration::hours(2));
        assert_eq!(clock.now(), start + Duration::hours(2));
        clock.set(start);
        assert_eq!(shared.now(), start);
    }
}
