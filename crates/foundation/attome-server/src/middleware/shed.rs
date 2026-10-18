//! AB5-T7: priority load shedding. Every request has a class from its path:
//! interactive (the default), report, export, AI or background. The
//! non-interactive classes each hold a fixed number of slots
//! (`shed.permits.*`); while more than `shed.interactive_high_water`
//! interactive requests are in flight, each of them runs one request at a
//! time. A request that cannot get a slot within two seconds is refused
//! with 503 `overloaded` and `Retry-After: 5`. Interactive requests are
//! never shed here.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use attome_config::ShedSection;
use attome_types::AppError;
use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::state::AppState;

/// How long a request waits for a slot.
pub const SLOT_WAIT: Duration = Duration::from_secs(2);

/// What kind of work a request is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestClass {
    Interactive,
    Report,
    Export,
    Ai,
    Background,
}

/// The class of a request to `path`.
pub fn classify(path: &str) -> RequestClass {
    if path.starts_with("/api/v1/ai/") || path.starts_with("/api/v1/mcp") {
        return RequestClass::Ai;
    }
    if path.contains("/export") {
        return RequestClass::Export;
    }
    if path.starts_with("/api/v1/reports") || path.starts_with("/api/v1/report/") {
        return RequestClass::Report;
    }
    if path.starts_with("/api/v1/admin/jobs") {
        return RequestClass::Background;
    }
    RequestClass::Interactive
}

#[derive(Debug)]
struct Pool {
    slots: Arc<Semaphore>,
    running: Arc<AtomicUsize>,
}

/// The process's shedding state.
#[derive(Debug)]
pub struct Shedder {
    report: Pool,
    export: Pool,
    ai: Pool,
    background: Pool,
    interactive: Arc<AtomicUsize>,
    high_water: usize,
}

/// A held admission; releases its slot when dropped.
#[derive(Debug)]
pub struct Admission {
    _slot: Option<OwnedSemaphorePermit>,
    running: Arc<AtomicUsize>,
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.running.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Shedder {
    pub fn new(config: &ShedSection) -> Self {
        let pool = |n: usize| Pool {
            slots: Arc::new(Semaphore::new(n.max(1))),
            running: Arc::new(AtomicUsize::new(0)),
        };
        Self {
            report: pool(config.permits.report),
            export: pool(config.permits.export),
            ai: pool(config.permits.ai),
            background: pool(config.permits.background),
            interactive: Arc::new(AtomicUsize::new(0)),
            high_water: config.interactive_high_water.max(1),
        }
    }

    fn pool(&self, class: RequestClass) -> Option<&Pool> {
        match class {
            RequestClass::Interactive => None,
            RequestClass::Report => Some(&self.report),
            RequestClass::Export => Some(&self.export),
            RequestClass::Ai => Some(&self.ai),
            RequestClass::Background => Some(&self.background),
        }
    }

    fn under_pressure(&self) -> bool {
        self.interactive.load(Ordering::Acquire) > self.high_water
    }

    /// Admits a request of `class`, waiting up to `wait`; `None` when shed.
    pub async fn admit(&self, class: RequestClass, wait: Duration) -> Option<Admission> {
        let Some(pool) = self.pool(class) else {
            self.interactive.fetch_add(1, Ordering::AcqRel);
            return Some(Admission {
                _slot: None,
                running: Arc::clone(&self.interactive),
            });
        };
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let slot = tokio::time::timeout(left, Arc::clone(&pool.slots).acquire_owned())
                .await
                .ok()?
                .ok()?;
            // Under pressure a class runs one request at a time.
            if !self.under_pressure() || pool.running.load(Ordering::Acquire) == 0 {
                pool.running.fetch_add(1, Ordering::AcqRel);
                return Some(Admission {
                    _slot: Some(slot),
                    running: Arc::clone(&pool.running),
                });
            }
            drop(slot);
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

/// The layer itself; see the module doc.
pub async fn shed(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let class = classify(req.uri().path());
    let Some(admission) = state.shedder.admit(class, SLOT_WAIT).await else {
        metrics::counter!("requests_shed_total").increment(1);
        let mut response = AppError::Overloaded("shed").into_response();
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            HeaderValue::from_static("5"),
        );
        return response;
    };
    let response = next.run(req).await;
    drop(admission);
    response
}

#[cfg(test)]
mod tests {
    use attome_config::ShedPermits;

    use super::*;

    fn shedder(high_water: usize) -> Shedder {
        Shedder::new(&ShedSection {
            permits: ShedPermits {
                report: 2,
                export: 1,
                ai: 2,
                background: 1,
            },
            interactive_high_water: high_water,
        })
    }

    #[test]
    fn requests_are_classified_by_path() {
        assert_eq!(classify("/api/v1/deal/123"), RequestClass::Interactive);
        assert_eq!(classify("/api/v1/ai/chat"), RequestClass::Ai);
        assert_eq!(classify("/api/v1/deal/export"), RequestClass::Export);
        assert_eq!(classify("/api/v1/reports/9/run"), RequestClass::Report);
    }

    #[tokio::test]
    async fn interactive_never_shed() {
        let shedder = shedder(1);
        let mut held = Vec::new();
        for _ in 0..50 {
            held.push(
                shedder
                    .admit(RequestClass::Interactive, Duration::from_millis(10))
                    .await
                    .expect("interactive always goes"),
            );
        }
    }

    #[tokio::test]
    async fn report_shed_when_high_water() {
        let shedder = shedder(2);
        // Calm: both report slots go.
        let first = shedder
            .admit(RequestClass::Report, Duration::from_millis(50))
            .await
            .unwrap();
        let second = shedder
            .admit(RequestClass::Report, Duration::from_millis(50))
            .await
            .unwrap();
        drop(second);
        // Interactive load past the high water: reports go one at a time.
        let mut busy = Vec::new();
        for _ in 0..3 {
            busy.push(
                shedder
                    .admit(RequestClass::Interactive, Duration::from_millis(10))
                    .await
                    .unwrap(),
            );
        }
        assert!(
            shedder
                .admit(RequestClass::Report, Duration::from_millis(100))
                .await
                .is_none(),
            "a second report waits, then is shed"
        );
        drop(first);
        assert!(
            shedder
                .admit(RequestClass::Report, Duration::from_millis(100))
                .await
                .is_some(),
            "one report at a time still runs"
        );
        drop(busy);
    }
}
