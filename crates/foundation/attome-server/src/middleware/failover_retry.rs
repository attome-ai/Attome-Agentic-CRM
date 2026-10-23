//! AB2-T3: the in-server retry window across a database failover.
//!
//! While the primary is being replaced, a request whose statement lost its
//! connection answers 503 `overloaded` with the
//! [`RetryableDbUnavailable`](attome_types::RetryableDbUnavailable) marker in
//! its response extensions (`AppError::Overloaded("db_unavailable")`). This
//! layer runs such a request again inside the server, for up to
//! `app.failover_retry_max_secs` (default 10, 0 turns it off), so a failover
//! of a few seconds is a slow answer rather than an error. It retries only
//! what is safe to run twice: a `GET` or `HEAD`, or a request carrying an
//! `Idempotency-Key` (the idempotency layer, directly inside this one,
//! answers a replay of a write that did complete with its stored result).
//!
//! The body is read once (the body-limit layer outside has already capped
//! its size) and each attempt gets a copy of the method, URI, headers,
//! extensions (the caller's identity is resolved by then) and body. Backoff
//! is 200 ms doubling to 2 s with ±20% jitter; when the window is spent the
//! last response goes back unchanged. `http_failover_retries_total{outcome}`
//! counts the requests that recovered and those that gave up.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use attome_types::RetryableDbUnavailable;
use axum::body::Body;
use axum::extract::Request;
use axum::http::Method;
use axum::response::{IntoResponse, Response};
use tower::{Layer, Service, ServiceExt};

/// The header that makes a write safe to retry.
const IDEMPOTENCY_KEY: &str = "idempotency-key";
const FIRST_DELAY: Duration = Duration::from_millis(200);
const MAX_DELAY: Duration = Duration::from_secs(2);

/// Wraps a service with the retry window.
#[derive(Debug, Clone, Copy)]
pub struct FailoverRetryLayer {
    max_wait: Duration,
}

impl FailoverRetryLayer {
    /// `max_wait` zero turns the retry off.
    pub fn new(max_wait: Duration) -> Self {
        Self { max_wait }
    }
}

impl<S> Layer<S> for FailoverRetryLayer {
    type Service = FailoverRetry<S>;

    fn layer(&self, inner: S) -> Self::Service {
        FailoverRetry {
            inner,
            max_wait: self.max_wait,
        }
    }
}

/// The service [`FailoverRetryLayer`] builds.
#[derive(Debug, Clone)]
pub struct FailoverRetry<S> {
    inner: S,
    max_wait: Duration,
}

/// Whether a request may run twice.
fn retry_safe(method: &Method, headers: &axum::http::HeaderMap) -> bool {
    *method == Method::GET || *method == Method::HEAD || headers.contains_key(IDEMPOTENCY_KEY)
}

/// The wait before the next attempt: `delay` ±20%.
fn jittered(delay: Duration) -> Duration {
    let factor = 0.8 + rand::random::<f64>() * 0.4;
    delay.mul_f64(factor)
}

fn is_retryable(response: &Response) -> bool {
    response
        .extensions()
        .get::<RetryableDbUnavailable>()
        .is_some()
}

impl<S> Service<Request> for FailoverRetry<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        // The clone that was polled ready serves this call (tower's usual
        // pattern); the fresh clone stays for the next.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let max_wait = self.max_wait;
        Box::pin(async move {
            if max_wait.is_zero() || !retry_safe(request.method(), request.headers()) {
                return inner.call(request).await;
            }
            let (parts, body) = request.into_parts();
            let bytes = match axum::body::to_bytes(body, usize::MAX).await {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(attome_types::AppError::Validation(
                        "the request body could not be read".into(),
                    )
                    .into_response());
                }
            };
            let started = Instant::now();
            let mut delay = FIRST_DELAY;
            let mut retried = false;
            loop {
                let mut attempt = Request::new(Body::from(bytes.clone()));
                *attempt.method_mut() = parts.method.clone();
                *attempt.uri_mut() = parts.uri.clone();
                *attempt.version_mut() = parts.version;
                *attempt.headers_mut() = parts.headers.clone();
                *attempt.extensions_mut() = parts.extensions.clone();
                let response = inner.ready().await?.call(attempt).await?;
                if !is_retryable(&response) {
                    if retried {
                        crate::metrics::record_failover_retry("recovered");
                    }
                    return Ok(response);
                }
                let wait = jittered(delay);
                if started.elapsed() + wait > max_wait {
                    if retried {
                        crate::metrics::record_failover_retry("gave_up");
                    }
                    return Ok(response);
                }
                retried = true;
                tokio::time::sleep(wait).await;
                delay = (delay * 2).min(MAX_DELAY);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Sends one request through the layer over an inner service that
    /// answers the marked 503 twice, then 200 echoing the body: the status,
    /// how many times the inner service ran, and the body.
    async fn run(method: Method, key: bool) -> (StatusCode, usize, Vec<u8>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let inner = tower::service_fn(move |req: Request| {
            let calls = Arc::clone(&seen);
            async move {
                let body = axum::body::to_bytes(req.into_body(), usize::MAX)
                    .await
                    .unwrap_or_default();
                if calls.fetch_add(1, Ordering::SeqCst) < 2 {
                    Ok::<_, Infallible>(
                        attome_types::AppError::Overloaded("db_unavailable").into_response(),
                    )
                } else {
                    Ok(Response::new(Body::from(body)))
                }
            }
        });
        let mut svc = FailoverRetryLayer::new(Duration::from_secs(10)).layer(inner);
        let mut builder = Request::builder().method(method).uri("/api/v1/x");
        if key {
            builder = builder.header(IDEMPOTENCY_KEY, "k-1");
        }
        let request = builder.body(Body::from("payload")).unwrap();
        let response = svc.ready().await.unwrap().call(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, calls.load(Ordering::SeqCst), body)
    }

    #[tokio::test]
    async fn get_is_retried_until_ok() {
        let (status, calls, _) = run(Method::GET, false).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls, 3, "two marked 503s, then the answer");
    }

    #[tokio::test]
    async fn post_without_key_is_not_retried() {
        let (status, calls, _) = run(Method::POST, false).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(calls, 1);
    }

    #[tokio::test]
    async fn post_with_key_is_retried() {
        let (status, calls, body) = run(Method::POST, true).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls, 3);
        assert_eq!(body, b"payload", "each attempt carried the body");
    }
}
