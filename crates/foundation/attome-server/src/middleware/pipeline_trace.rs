//! Z5-T1: a debug-only trace of the layers a request passes.
//!
//! [`mark`] sits in front of each security-relevant layer in the assembly
//! (`app.rs`, `builder.rs`). With `app.debug_pipeline_trace` on in a debug
//! build, each mark appends its name as the request passes it, and the
//! outermost one writes the list, outermost first, into the
//! [`HEADER`] response header. `middleware_pipeline.rs` compares it with
//! [`crate::app::PIPELINE_ORDER`], so moving a layer without updating the
//! constant (or the other way round) fails a test.
//!
//! Off (the default, and always in a release build) a mark is
//! [`tower::layer::util::Identity`]: nothing is added to the stack.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use attome_config::AppConfig;
use axum::http::{HeaderValue, Request, Response};
use tower::layer::util::Identity;
use tower::util::Either;
use tower::{Layer, Service};

/// The response header the trace is written to.
pub const HEADER: &str = "x-attome-layers";

/// Whether this build and configuration trace the pipeline.
pub fn enabled(config: &AppConfig) -> bool {
    cfg!(debug_assertions) && config.app.debug_pipeline_trace
}

/// The mark for the layer called `name`: a [`MarkLayer`] when tracing is
/// on, otherwise nothing.
pub fn mark(config: &AppConfig, name: &'static str) -> Either<MarkLayer, Identity> {
    tower::util::option_layer(enabled(config).then_some(MarkLayer(name)))
}

/// The names recorded so far for one request.
#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Vec<&'static str>>>);

/// Records one layer's name.
#[derive(Debug, Clone, Copy)]
pub struct MarkLayer(&'static str);

impl<S> Layer<S> for MarkLayer {
    type Service = Mark<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Mark {
            name: self.0,
            inner,
        }
    }
}

/// The service [`MarkLayer`] wraps around the next layer.
#[derive(Debug, Clone)]
pub struct Mark<S> {
    name: &'static str,
    inner: S,
}

impl<S, ReqB, ResB> Service<Request<ReqB>> for Mark<S>
where
    S: Service<Request<ReqB>, Response = Response<ResB>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResB: Send + 'static,
{
    type Response = Response<ResB>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ResB>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<ReqB>) -> Self::Future {
        let (trace, outermost) = match request.extensions().get::<Trace>() {
            Some(trace) => (trace.clone(), false),
            None => {
                let trace = Trace::default();
                request.extensions_mut().insert(trace.clone());
                (trace, true)
            }
        };
        if let Ok(mut names) = trace.0.lock() {
            names.push(self.name);
        }
        let future = self.inner.call(request);
        Box::pin(async move {
            let mut response = future.await?;
            if outermost {
                let joined = trace
                    .0
                    .lock()
                    .map(|names| names.join(","))
                    .unwrap_or_default();
                if let Ok(value) = HeaderValue::from_str(&joined) {
                    response.headers_mut().insert(HEADER, value);
                }
            }
            Ok(response)
        })
    }
}
