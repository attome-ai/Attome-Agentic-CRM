//! Y12-T6: a backfill's batch size follows the load. Each batch is sized
//! from what the last one saw: under pressure (the last batch took over two
//! seconds, the replica lags over ten, or most connections are busy) the
//! batch halves and the run pauses before it; in the deployment's quiet
//! hours with no pressure it doubles; otherwise it keeps its size. Bounded
//! by a floor and `metadata.backfill_batch_max`.
//!
//! Request latency is not a signal: there is no per-request latency feed to
//! read without a new metric pipeline, so the last batch's own time and the
//! database's signals stand for it.

use std::time::Duration;

/// The batch a run starts with.
pub const BASE_BATCH: i64 = 2_000;
/// The smallest batch pressure shrinks to.
pub const MIN_BATCH: i64 = 200;
/// `metadata.backfill_batch_max` when unset.
pub const DEFAULT_MAX_BATCH: i64 = 50_000;
/// `metadata.quiet_hours` when unset: 01:00 to 05:00 local time.
pub const DEFAULT_QUIET_HOURS: (u32, u32) = (1, 5);

/// The pause before a batch under pressure.
const PRESSURE_PAUSE: Duration = Duration::from_millis(500);
const SLOW_BATCH_MS: u64 = 2_000;
const LAGGING_REPLICA_SECS: f64 = 10.0;
const BUSY_CONNECTIONS: f64 = 0.7;

/// What the run can see of the load.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct LoadSignals {
    /// Active connections over `max_connections`, 0 to 1.
    pub db_active_ratio: f64,
    /// The read replica's lag, when there is one.
    pub replica_lag_secs: Option<f64>,
    /// How long the last batch took; 0 before the first.
    pub last_batch_ms: u64,
}

impl LoadSignals {
    /// Whether any signal says the database is under pressure.
    pub fn under_pressure(&self) -> bool {
        self.last_batch_ms > SLOW_BATCH_MS
            || self
                .replica_lag_secs
                .is_some_and(|lag| lag > LAGGING_REPLICA_SECS)
            || self.db_active_ratio > BUSY_CONNECTIONS
    }
}

/// One run's batch sizing.
#[derive(Debug, Clone)]
pub struct Pacer {
    current: i64,
    min_batch: i64,
    max_batch: i64,
    quiet_hours: (u32, u32),
}

impl Pacer {
    pub fn new(base_batch: i64, min_batch: i64, max_batch: i64, quiet_hours: (u32, u32)) -> Self {
        let min_batch = min_batch.max(1);
        let max_batch = max_batch.max(min_batch);
        Self {
            current: base_batch.clamp(min_batch, max_batch),
            min_batch,
            max_batch,
            quiet_hours,
        }
    }

    /// The pacer a deployment's settings ask for: `backfill_batch_max` and
    /// `quiet_hours` (`"01-05"`), the defaults where unset or malformed.
    pub fn from_settings(backfill_batch_max: Option<i64>, quiet_hours: Option<&str>) -> Self {
        Self::new(
            BASE_BATCH,
            MIN_BATCH,
            backfill_batch_max
                .filter(|max| *max > 0)
                .unwrap_or(DEFAULT_MAX_BATCH),
            quiet_hours
                .and_then(parse_quiet_hours)
                .unwrap_or(DEFAULT_QUIET_HOURS),
        )
    }

    /// The next batch's size and the pause before it, at local hour
    /// `local_hour` (0 to 23).
    pub fn next_batch(&mut self, signals: &LoadSignals, local_hour: u32) -> (i64, Duration) {
        if signals.under_pressure() {
            self.current = (self.current / 2).max(self.min_batch);
            return (self.current, PRESSURE_PAUSE);
        }
        if in_quiet_hours(local_hour, self.quiet_hours) {
            self.current = self.current.saturating_mul(2).min(self.max_batch);
        }
        (self.current, Duration::ZERO)
    }
}

/// `"01-05"` (start hour, end hour; the end is not included) as hours.
pub fn parse_quiet_hours(text: &str) -> Option<(u32, u32)> {
    let (start, end) = text.trim().split_once('-')?;
    let start: u32 = start.trim().parse().ok()?;
    let end: u32 = end.trim().parse().ok()?;
    (start < 24 && end <= 24 && start != end).then_some((start, end))
}

/// Whether `hour` is in `[start, end)`, which may run past midnight.
pub fn in_quiet_hours(hour: u32, (start, end): (u32, u32)) -> bool {
    if start < end {
        hour >= start && hour < end
    } else {
        hour >= start || hour < end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calm(last_batch_ms: u64) -> LoadSignals {
        LoadSignals {
            db_active_ratio: 0.1,
            replica_lag_secs: Some(0.5),
            last_batch_ms,
        }
    }

    #[test]
    fn pressure_halves_batch() {
        let mut pacer = Pacer::new(2_000, 200, 50_000, (1, 5));
        let (size, pause) = pacer.next_batch(&calm(2_500), 12);
        assert_eq!((size, pause), (1_000, PRESSURE_PAUSE));
        let lagging = LoadSignals {
            replica_lag_secs: Some(30.0),
            ..calm(10)
        };
        assert_eq!(pacer.next_batch(&lagging, 12).0, 500);
        let busy = LoadSignals {
            db_active_ratio: 0.9,
            ..calm(10)
        };
        for _ in 0..10 {
            pacer.next_batch(&busy, 12);
        }
        assert_eq!(pacer.next_batch(&busy, 12).0, 200, "never below the floor");
        // No pressure outside quiet hours: the size holds.
        assert_eq!(pacer.next_batch(&calm(10), 12), (200, Duration::ZERO));
    }

    #[test]
    fn quiet_hours_doubles_batch() {
        let mut pacer = Pacer::new(2_000, 200, 10_000, (1, 5));
        assert_eq!(pacer.next_batch(&calm(10), 2).0, 4_000);
        assert_eq!(pacer.next_batch(&calm(10), 3).0, 8_000);
        assert_eq!(
            pacer.next_batch(&calm(10), 4).0,
            10_000,
            "capped at the maximum"
        );
        assert_eq!(
            pacer.next_batch(&calm(10), 5).0,
            10_000,
            "05:00 is outside, size holds"
        );
        assert!(in_quiet_hours(23, (22, 4)) && in_quiet_hours(1, (22, 4)));
        assert!(!in_quiet_hours(12, (22, 4)));
        assert_eq!(parse_quiet_hours("01-05"), Some((1, 5)));
        assert_eq!(parse_quiet_hours("bad"), None);
        let p = Pacer::from_settings(None, Some("nope"));
        assert_eq!(p.quiet_hours, DEFAULT_QUIET_HOURS);
        assert_eq!(p.max_batch, DEFAULT_MAX_BATCH);
    }
}
