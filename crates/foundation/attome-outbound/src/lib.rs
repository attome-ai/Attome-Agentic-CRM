//! Calls to outside services (roadmap AB6-T1): a model provider, the object
//! store, an SMTP relay, a customer's API. Each service is a [`Service`]
//! with a [`Policy`], and every call goes through [`call`], which in order:
//!
//! 1. refuses at once while the service's [`breaker::Breaker`] is open
//!    ([`OutboundError::Open`], with how long until it may try again);
//! 2. takes a slot in the caller's bulkhead ([`bulkhead::CallClass`]),
//!    waiting at most a second ([`OutboundError::Busy`]);
//! 3. bounds the call by the policy's timeout and the request's remaining
//!    [`deadline`], whichever is shorter ([`OutboundError::Timeout`]);
//! 4. retries only an idempotent call whose error is retryable, while the
//!    attempts and the service's [`retry::RetryBudget`] last, waiting the
//!    backoff or the service's own `Retry-After` hint, never past the
//!    deadline.
//!
//! A non-idempotent call (a payment, a message sent without an outbox id)
//! is never retried here: a duplicate is worse than a visible failure.

pub mod breaker;
pub mod bulkhead;
pub mod deadline;
/// AB6-T5: one service per endpoint of an outside system.
pub mod endpoints;
/// Q21-T1: the one way to build an HTTP client for a call out, behind the SSRF guard.
pub mod http;
pub mod retry;

use std::future::Future;
use std::time::Duration;

pub use breaker::{Breaker, BreakerConfig, BreakerState};
pub use bulkhead::{Bulkheads, CallClass};
pub use endpoints::EndpointServices;
pub use retry::{RetryBudget, RetryPolicy};

/// How long a call waits for a bulkhead slot.
pub const BULKHEAD_WAIT: Duration = Duration::from_secs(1);

/// One service's limits.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// The longest one attempt may take.
    pub timeout: Duration,
    pub interactive_slots: usize,
    pub background_slots: usize,
    pub retry: RetryPolicy,
    pub breaker: BreakerConfig,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            interactive_slots: 32,
            background_slots: 8,
            retry: RetryPolicy::default(),
            breaker: BreakerConfig::default(),
        }
    }
}

/// An outside service and its state.
#[derive(Debug)]
pub struct Service {
    pub name: &'static str,
    pub policy: Policy,
    pub breaker: Breaker,
    pub budget: RetryBudget,
    pub bulkheads: Bulkheads,
}

impl Service {
    pub fn new(name: &'static str, policy: Policy) -> Self {
        Self {
            name,
            breaker: Breaker::new(policy.breaker),
            budget: RetryBudget::default(),
            bulkheads: Bulkheads::new(policy.interactive_slots, policy.background_slots),
            policy,
        }
    }
}

/// What a failed attempt tells the caller about retrying it.
pub trait Retryable {
    /// Whether the same call may succeed later: a timeout, a refused
    /// connection, a 429 or a 5xx. A refusal of the request (a 4xx) is not,
    /// and does not count against the service's breaker.
    fn retryable(&self) -> bool;
    /// The service's own `Retry-After`, when it sent one.
    fn retry_after(&self) -> Option<Duration> {
        None
    }
    /// Whether this failure counts against the service's breaker. The same as
    /// [`Retryable::retryable`] unless a service says otherwise: a model
    /// server's plain 500 is not worth replaying, yet still says the server is
    /// unwell (AB6-T3).
    fn counts_as_failure(&self) -> bool {
        self.retryable()
    }
}

/// Why a call failed.
#[derive(Debug)]
pub enum OutboundError<E> {
    /// The breaker is open; try again after this long.
    Open { retry_after: Duration },
    /// No slot freed in time.
    Busy,
    /// The attempt ran past its timeout or the request's deadline.
    Timeout,
    /// The service answered with an error.
    Failed(E),
}

impl<E: std::fmt::Display> std::fmt::Display for OutboundError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { retry_after } => {
                write!(
                    f,
                    "the service is unavailable; retry in {}s",
                    retry_after.as_secs()
                )
            }
            Self::Busy => f.write_str("the service is busy"),
            Self::Timeout => f.write_str("the service did not answer in time"),
            Self::Failed(error) => error.fmt(f),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for OutboundError<E> {}

/// AB6-T7: what a caller's client sees. The service's name and address stay
/// in the log, never in the answer: an open breaker is
/// `capability_unavailable` naming the dependency's kind with a
/// `Retry-After` of the time until it may try again, a full bulkhead is
/// `overloaded`, a timeout is `server_timeout`, and the service's own error
/// is masked as internal.
impl<E: std::fmt::Display> From<OutboundError<E>> for attome_types::AppError {
    fn from(error: OutboundError<E>) -> Self {
        use attome_types::AppError;
        match error {
            OutboundError::Open { retry_after } => {
                tracing::warn!(
                    retry_after_secs = retry_after.as_secs(),
                    "outbound: refused by an open breaker"
                );
                AppError::CapabilityUnavailable("dependency")
            }
            OutboundError::Busy => AppError::Overloaded("dependency"),
            OutboundError::Timeout => AppError::ServerTimeout,
            OutboundError::Failed(error) => AppError::internal(error),
        }
    }
}

/// One call to `svc`; see the crate doc.
pub async fn call<T, E, F, Fut>(
    svc: &Service,
    class: CallClass,
    idempotent: bool,
    mut attempt: F,
) -> Result<T, OutboundError<E>>
where
    E: Retryable,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut tries: u32 = 0;
    loop {
        tries += 1;
        svc.breaker
            .allow()
            .map_err(|retry_after| OutboundError::Open { retry_after })?;
        let permit = svc
            .bulkheads
            .acquire(class, BULKHEAD_WAIT)
            .await
            .ok_or(OutboundError::Busy)?;
        let timeout = match deadline::remaining() {
            Some(left) => left.min(svc.policy.timeout),
            None => svc.policy.timeout,
        };
        if timeout.is_zero() {
            return Err(OutboundError::Timeout);
        }
        svc.budget.record_call();
        // AA1-T5: the attempt's time is the request's `ext` phase.
        let outcome = attome_types::server_timing::timed(
            attome_types::server_timing::Phase::Ext,
            tokio::time::timeout(timeout, attempt()),
        )
        .await;
        drop(permit);
        let (error, hint) = match outcome {
            Ok(Ok(value)) => {
                svc.breaker.record(true);
                return Ok(value);
            }
            Ok(Err(error)) => {
                let retryable = error.retryable();
                // A refused request says nothing about the service's health.
                svc.breaker.record(!error.counts_as_failure());
                if !retryable {
                    return Err(OutboundError::Failed(error));
                }
                let hint = error.retry_after();
                (OutboundError::Failed(error), hint)
            }
            Err(_elapsed) => {
                svc.breaker.record(false);
                (OutboundError::Timeout, None)
            }
        };
        if !idempotent || tries >= svc.policy.retry.max_attempts || !svc.budget.try_retry() {
            return Err(error);
        }
        let wait = hint.unwrap_or_else(|| svc.policy.retry.backoff(tries, retry::jitter_seed()));
        if deadline::remaining().is_some_and(|left| left <= wait) {
            return Err(error);
        }
        tracing::debug!(
            service = svc.name,
            retry = tries,
            wait_ms = wait.as_millis() as u64,
            "outbound: retrying"
        );
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[derive(Debug)]
    struct Flaky(bool);

    impl Retryable for Flaky {
        fn retryable(&self) -> bool {
            self.0
        }
    }

    fn quick_service() -> Service {
        Service::new(
            "test",
            Policy {
                retry: RetryPolicy {
                    max_attempts: 3,
                    base: Duration::from_millis(1),
                    cap: Duration::from_millis(5),
                },
                ..Policy::default()
            },
        )
    }

    async fn attempts(svc: &Service, idempotent: bool, error: Flaky) -> u32 {
        let count = Arc::new(AtomicU32::new(0));
        let retryable = error.0;
        let result: Result<(), _> = call(svc, CallClass::Interactive, idempotent, || {
            let count = Arc::clone(&count);
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Err(Flaky(retryable))
            }
        })
        .await;
        assert!(result.is_err());
        count.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn no_retry_when_not_idempotent() {
        let svc = quick_service();
        assert_eq!(attempts(&svc, false, Flaky(true)).await, 1);
        assert_eq!(
            attempts(&svc, true, Flaky(true)).await,
            3,
            "idempotent: all attempts"
        );
        assert_eq!(
            attempts(&svc, true, Flaky(false)).await,
            1,
            "a refused request is not retried"
        );
    }

    #[tokio::test]
    async fn an_open_breaker_refuses_without_calling() {
        let svc = quick_service();
        for _ in 0..20 {
            svc.breaker.record(false);
        }
        let called = Arc::new(AtomicU32::new(0));
        let result: Result<(), OutboundError<Flaky>> =
            call(&svc, CallClass::Background, true, || {
                let called = Arc::clone(&called);
                async move {
                    called.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })
            .await;
        assert!(matches!(result, Err(OutboundError::Open { .. })));
        assert_eq!(called.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn outbound_errors_map_to_stable_codes() {
        use attome_types::AppError;
        let open: AppError = OutboundError::<String>::Open {
            retry_after: Duration::from_secs(12),
        }
        .into();
        assert!(matches!(
            open,
            AppError::CapabilityUnavailable("dependency")
        ));
        let busy: AppError = OutboundError::<String>::Busy.into();
        assert!(matches!(busy, AppError::Overloaded("dependency")));
        let timeout: AppError = OutboundError::<String>::Timeout.into();
        assert!(matches!(timeout, AppError::ServerTimeout));
        let failed: AppError = OutboundError::Failed("smtp.example.com refused".to_string()).into();
        assert!(matches!(failed, AppError::Internal(_)));
    }

    #[tokio::test]
    async fn deadline_shortens_timeout() {
        let svc = quick_service();
        let started = tokio::time::Instant::now();
        let result: Result<(), OutboundError<Flaky>> = deadline::with_deadline(
            started + Duration::from_millis(50),
            call(&svc, CallClass::Interactive, true, || async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            }),
        )
        .await;
        assert!(matches!(result, Err(OutboundError::Timeout)));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }
}
