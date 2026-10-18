//! AB6-T2: every request carries a deadline to the outside calls it makes
//! (`attome_outbound::deadline`). It is the request timeout less half a
//! second, so an outside call gives up, and the handler can still answer,
//! before the outer timeout cuts the request off.

use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

/// How much earlier than the request timeout outside calls must finish.
pub const DEADLINE_MARGIN: Duration = Duration::from_millis(500);

/// The deadline budget for a request timeout of `timeout`.
pub fn budget(timeout: Duration) -> Duration {
    timeout.saturating_sub(DEADLINE_MARGIN)
}

/// Runs the rest of the request under the deadline, as an axum `from_fn`
/// body (tests use it; the server mounts [`DeadlineLayer`]).
pub async fn with_request_deadline(timeout: Duration, req: Request, next: Next) -> Response {
    let deadline = tokio::time::Instant::now() + budget(timeout);
    attome_outbound::deadline::with_deadline(deadline, next.run(req)).await
}

/// The deadline as a plain tower layer, for the server's `ServiceBuilder`:
/// it wraps any inner service and leaves its types alone.
#[derive(Debug, Clone, Copy)]
pub struct DeadlineLayer {
    budget: Duration,
}

impl DeadlineLayer {
    /// A layer for requests that time out after `timeout`.
    pub fn new(timeout: Duration) -> Self {
        Self {
            budget: budget(timeout),
        }
    }
}

impl<S> tower::Layer<S> for DeadlineLayer {
    type Service = Deadline<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Deadline {
            inner,
            budget: self.budget,
        }
    }
}

/// [`DeadlineLayer`]'s service.
#[derive(Debug, Clone)]
pub struct Deadline<S> {
    inner: S,
    budget: Duration,
}

impl<S, R> tower::Service<R> for Deadline<S>
where
    S: tower::Service<R>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = tokio::task::futures::TaskLocalFuture<tokio::time::Instant, S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: R) -> Self::Future {
        let deadline = tokio::time::Instant::now() + self.budget;
        attome_outbound::deadline::scope(deadline, self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_leaves_half_a_second() {
        assert_eq!(
            budget(Duration::from_secs(30)),
            Duration::from_millis(29_500)
        );
        assert_eq!(budget(Duration::from_millis(100)), Duration::ZERO);
    }

    #[tokio::test]
    async fn inner_call_sees_remaining_deadline() {
        use axum::Router;
        use axum::body::Body;
        use axum::routing::get;
        use tower::ServiceExt;

        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    let left = attome_outbound::deadline::remaining().unwrap_or_default();
                    left.as_millis().to_string()
                }),
            )
            .layer(axum::middleware::from_fn(|req, next| {
                with_request_deadline(Duration::from_secs(5), req, next)
            }));
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let left: u128 = std::str::from_utf8(&bytes).unwrap().parse().unwrap();
        assert!(left > 4_000 && left <= 4_500, "{left} ms left");
    }
}
