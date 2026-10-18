//! AA1-T5: the `Server-Timing` response header.
//!
//! ```text
//! Server-Timing: mw;dur=0.412, auth;dur=1.020, perm;dur=0.611, db;dur=3.150, app;dur=4.877, ext;dur=0.000
//! ```
//!
//! [`server_timing`] (in `apply_outer_layers`, just inside the request id)
//! opens an `attome_types::server_timing` scope per request; the phase
//! layers in `apply_inner_layers` mark authentication (`auth`), permission
//! resolution (`perm`) and the handler (`app`, its response serialization
//! included); [`DbTimingLayer`] adds each SQL statement's time (`db`) and
//! `attome_outbound::call` each outside call's (`ext`). `mw` is the rest of
//! the total. `db` and `ext` are counted wherever they ran, so they overlap
//! the other phases.
//!
//! Who gets it is `observability.server_timing`: `dev` (every response, in a
//! debug environment only), `admins` (responses to an administrator, as
//! `authz` resolved the caller) or `off`. The value carries phase names and
//! durations only: never a statement, an entity or a user.
//!
//! State is request-scoped (guidelines §5): nothing outlives the request.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Instant;

use attome_config::AppConfig;
use attome_types::server_timing;
pub use attome_types::server_timing::Phase;
use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use tower::layer::util::Identity;
use tower::util::Either;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// The response header.
pub const HEADER: &str = "server-timing";

/// Who gets the header on this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Nobody: the layer is not mounted.
    Off,
    /// Every response.
    Everyone,
    /// Responses to an administrator.
    Admins,
}

impl Mode {
    /// The mode `config` asks for. `dev` is [`Mode::Everyone`] in a debug
    /// environment and [`Mode::Off`] anywhere else.
    pub fn from_config(config: &AppConfig) -> Self {
        Self::from_setting(
            &config.observability.server_timing,
            attome_config::is_debug_env(),
        )
    }

    /// The mode for a setting value, given whether this is a debug
    /// environment.
    pub fn from_setting(setting: &str, debug_env: bool) -> Self {
        match setting {
            "dev" if debug_env => Mode::Everyone,
            "admins" => Mode::Admins,
            _ => Mode::Off,
        }
    }
}

/// The outer layer: times the request and, when `mode` says so, writes the
/// header.
pub async fn server_timing(mode: Mode, req: Request, next: Next) -> Response {
    if mode == Mode::Off {
        return next.run(req).await;
    }
    let start = Instant::now();
    let (mut response, mut timings) = server_timing::scope(next.run(req)).await;
    let now = Instant::now();
    timings.close_all(now);
    let send = match mode {
        Mode::Everyone => true,
        Mode::Admins => timings.admin(),
        Mode::Off => false,
    };
    if send
        && let Ok(value) =
            HeaderValue::from_str(&timings.header_value(now.saturating_duration_since(start)))
    {
        response.headers_mut().insert(HEADER, value);
    }
    response
}

/// What a [`PhaseLayer`] does to its phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// Starts the phase as the request passes; the matching `End` (or the
    /// outer layer, when a layer in between answers) ends it.
    Start,
    /// Ends the phase as the request passes on into the next layer.
    End,
    /// Times everything inside it (the handler).
    Around,
}

/// A phase marker, or nothing when the header is off on this node.
pub fn phase(mode: Mode, phase: Phase, mark: Mark) -> Either<PhaseLayer, Identity> {
    tower::util::option_layer((mode != Mode::Off).then_some(PhaseLayer { phase, mark }))
}

/// Marks one phase; see [`phase`].
#[derive(Debug, Clone, Copy)]
pub struct PhaseLayer {
    phase: Phase,
    mark: Mark,
}

impl<S> tower::Layer<S> for PhaseLayer {
    type Service = PhaseService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PhaseService {
            phase: self.phase,
            mark: self.mark,
            inner,
        }
    }
}

/// The service [`PhaseLayer`] wraps around the next layer.
#[derive(Debug, Clone)]
pub struct PhaseService<S> {
    phase: Phase,
    mark: Mark,
    inner: S,
}

impl<S, ReqB, ResB> tower::Service<axum::http::Request<ReqB>> for PhaseService<S>
where
    S: tower::Service<axum::http::Request<ReqB>, Response = axum::http::Response<ResB>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResB: Send + 'static,
{
    type Response = axum::http::Response<ResB>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: axum::http::Request<ReqB>) -> Self::Future {
        let phase = self.phase;
        match self.mark {
            Mark::Start => server_timing::open(phase),
            Mark::End => server_timing::close(phase),
            Mark::Around => {}
        }
        let around = self.mark == Mark::Around;
        let start = Instant::now();
        let future = self.inner.call(request);
        Box::pin(async move {
            let response = future.await;
            if around {
                server_timing::add(phase, start.elapsed());
            }
            response
        })
    }
}

/// Adds each `sqlx::query` event's `elapsed_secs` to the current request's
/// `db` phase. Installed by the binary's tracing setup (with a per-layer
/// filter enabling `sqlx::query` at debug) when the header can be sent; sqlx
/// emits the event in the task that awaited the statement.
#[derive(Debug, Clone, Copy, Default)]
pub struct DbTimingLayer;

struct ElapsedSecs(Option<f64>);

impl tracing::field::Visit for ElapsedSecs {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        if field.name() == "elapsed_secs" {
            self.0 = Some(value);
        }
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}
}

impl<S: tracing::Subscriber> Layer<S> for DbTimingLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "sqlx::query" || !server_timing::active() {
            return;
        }
        let mut elapsed = ElapsedSecs(None);
        event.record(&mut elapsed);
        if let Some(secs) = elapsed.0.filter(|s| s.is_finite() && *s >= 0.0) {
            server_timing::add(Phase::Db, std::time::Duration::from_secs_f64(secs));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::middleware;
    use axum::routing::get;
    use tower::ServiceExt;

    /// The real phase layers around a handler, as `app.rs` stacks them; the
    /// `admin` flag stands in for what `authz` notes.
    fn app(mode: Mode, admin: bool) -> Router {
        Router::new()
            .route(
                "/api/v1/account/{id}",
                get(|| async {
                    server_timing::add(Phase::Db, std::time::Duration::from_micros(250));
                    "ok"
                }),
            )
            .layer(phase(mode, Phase::App, Mark::Around))
            .layer(phase(mode, Phase::Perm, Mark::End))
            .layer(middleware::from_fn(move |req, next: Next| async move {
                server_timing::note_admin(admin);
                next.run(req).await
            }))
            .layer(phase(mode, Phase::Perm, Mark::Start))
            .layer(phase(mode, Phase::Auth, Mark::End))
            .layer(phase(mode, Phase::Auth, Mark::Start))
            .layer(middleware::from_fn(move |req, next| {
                server_timing(mode, req, next)
            }))
    }

    async fn get_header(mode: Mode, admin: bool) -> Option<String> {
        let response = app(mode, admin)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/account/0199f0a0-0000-7000-8000-000000000001")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        response
            .headers()
            .get(HEADER)
            .map(|v| v.to_str().expect("ascii").to_owned())
    }

    #[test]
    fn dev_mode_is_on_only_in_a_debug_environment() {
        assert_eq!(Mode::from_setting("dev", true), Mode::Everyone);
        assert_eq!(Mode::from_setting("dev", false), Mode::Off);
        assert_eq!(Mode::from_setting("admins", false), Mode::Admins);
        assert_eq!(Mode::from_setting("off", true), Mode::Off);
    }

    #[tokio::test]
    async fn header_present_in_dev_mode() {
        let header = get_header(Mode::from_setting("dev", true), false)
            .await
            .expect("a dev-mode response carries the header");
        let phases: Vec<&str> = header.split(", ").collect();
        assert_eq!(phases.len(), 6, "{header}");
        for phase in phases {
            let (_, dur) = phase.split_once(";dur=").expect("name;dur=");
            let millis: f64 = dur.parse().expect("a number");
            assert!(millis >= 0.0, "{header}");
        }
        assert!(header.contains("db;dur=0.250"), "{header}");
    }

    #[tokio::test]
    async fn header_absent_for_non_admin_in_admins_mode() {
        assert_eq!(get_header(Mode::Admins, false).await, None);
        assert!(get_header(Mode::Admins, true).await.is_some());
        assert_eq!(get_header(Mode::Off, true).await, None);
    }

    #[tokio::test]
    async fn header_has_only_phase_names() {
        let header = get_header(Mode::Everyone, true).await.expect("header");
        let names: Vec<&str> = header
            .split(", ")
            .map(|phase| phase.split(';').next().unwrap_or_default())
            .collect();
        assert_eq!(names, ["mw", "auth", "perm", "db", "app", "ext"]);
        // Nothing from the request (its path, its id) reaches the value.
        assert!(!header.contains("account"), "{header}");
        assert!(!header.contains("0199f0a0"), "{header}");
        let allowed = |c: char| c.is_ascii_alphanumeric() || ";=., ".contains(c);
        assert!(header.chars().all(allowed), "{header}");
    }
}
