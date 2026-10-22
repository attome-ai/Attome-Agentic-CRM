//! AA10-T6: one shared speed controller for background chunks.
//!
//! Background work that runs in chunks (every [`crate::batch`] job) waits
//! [`SpeedController::pace`] before each chunk. The wait follows how busy the
//! node is: nothing while requests are fast and the read replica keeps up,
//! longer as request latency climbs or the replica falls behind, so a bulk job
//! never makes people wait.
//!
//! | p95 request latency | replica lag | delay between chunks |
//! |---|---|---|
//! | under 100 ms | under 5 s | none |
//! | 100–300 ms | up to 30 s | 200 ms |
//! | over 300 ms | or over 30 s | 1 s |
//!
//! State: one process-local atomic, rebuilt from fresh readings every five
//! seconds (guidelines §5: observational, safe to lose). This crate sits
//! below the server, so it cannot read the server's metrics itself; the server
//! hands readings in through [`LoadSource`] (the task's stop condition).

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// How often the delay is recomputed.
pub const REFRESH: Duration = Duration::from_secs(5);

/// One look at how busy this node is. `None` is "not known", which slows
/// nothing down.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LoadReading {
    /// p95 request latency over the last window, in milliseconds.
    pub p95_ms: Option<f64>,
    /// How far the read replica is behind, in seconds.
    pub replica_lag_secs: Option<f64>,
}

/// Where readings come from (the server's request histogram and replica lag
/// gauge).
pub trait LoadSource: Send + Sync {
    fn reading(&self) -> LoadReading;
}

/// The delay a reading calls for.
pub fn delay_for(reading: LoadReading) -> Duration {
    let p95 = reading.p95_ms.unwrap_or(0.0);
    let lag = reading.replica_lag_secs.unwrap_or(0.0);
    if p95 > 300.0 || lag > 30.0 {
        Duration::from_millis(1_000)
    } else if p95 >= 100.0 || lag >= 5.0 {
        Duration::from_millis(200)
    } else {
        Duration::ZERO
    }
}

/// The delay between background chunks on this node.
#[derive(Debug, Default)]
pub struct SpeedController {
    delay_ms: AtomicU64,
}

impl SpeedController {
    pub const fn new() -> Self {
        Self {
            delay_ms: AtomicU64::new(0),
        }
    }

    /// Sets the delay from a fresh reading.
    pub fn update(&self, reading: LoadReading) {
        let ms = u64::try_from(delay_for(reading).as_millis()).unwrap_or(u64::MAX);
        let before = self.delay_ms.swap(ms, Ordering::Relaxed);
        if before != ms {
            metrics::gauge!("background_chunk_delay_ms").set(ms as f64);
        }
    }

    /// The current delay.
    pub fn delay(&self) -> Duration {
        Duration::from_millis(self.delay_ms.load(Ordering::Relaxed))
    }

    /// Waits the current delay; returns at once on an idle node.
    pub async fn pace(&self) {
        let delay = self.delay();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

/// This process's controller.
pub fn global() -> &'static SpeedController {
    static CONTROLLER: SpeedController = SpeedController::new();
    &CONTROLLER
}

/// Starts the five-second refresh of [`global`] from `source`, once per
/// process. A bare spawn is right here (guidelines §10): it is
/// process-lifetime supervision whose loss only stops the slowing down.
pub fn spawn(source: Arc<dyn LoadSource>) {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REFRESH);
        loop {
            tick.tick().await;
            global().update(source.reading());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(p95_ms: f64, lag: f64) -> LoadReading {
        LoadReading {
            p95_ms: Some(p95_ms),
            replica_lag_secs: Some(lag),
        }
    }

    #[test]
    fn delay_zero_when_idle() {
        let controller = SpeedController::new();
        controller.update(reading(40.0, 0.5));
        assert_eq!(controller.delay(), Duration::ZERO);
        controller.update(LoadReading::default());
        assert_eq!(controller.delay(), Duration::ZERO, "unknown slows nothing");
    }

    #[test]
    fn delay_high_when_busy() {
        let controller = SpeedController::new();
        controller.update(reading(150.0, 0.0));
        assert_eq!(controller.delay(), Duration::from_millis(200));
        controller.update(reading(20.0, 10.0));
        assert_eq!(
            controller.delay(),
            Duration::from_millis(200),
            "replica behind"
        );
        controller.update(reading(450.0, 0.0));
        assert_eq!(controller.delay(), Duration::from_secs(1));
        controller.update(reading(20.0, 45.0));
        assert_eq!(
            controller.delay(),
            Duration::from_secs(1),
            "replica far behind"
        );
        controller.update(reading(20.0, 0.0));
        assert_eq!(controller.delay(), Duration::ZERO, "back to idle");
    }
}
