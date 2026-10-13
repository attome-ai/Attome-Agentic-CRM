//! P-observability-completion — tracing/OTel bootstrap for the `server`
//! binary. Replaces `main.rs`'s previous bare
//! `tracing_subscriber::fmt()....init()` call with a `registry()` carrying
//! the same `fmt` layer plus a conditional `tracing-opentelemetry` layer,
//! gated on `observability.enable_distributed_tracing`.
//!
//! `enable_distributed_tracing = false` (every shipped config file's value
//! today) takes the early-return path in [`init_tracing`] below and installs
//! exactly the same single `fmt` layer `main.rs` installed directly — no
//! OTel dependency is touched at runtime, byte-identical logging output to
//! before this module existed.
//!
//! Compiled and clippy-clean against the `opentelemetry 0.32`/`opentelemetry_sdk
//! 0.32`/`opentelemetry-otlp 0.32`/`tracing-opentelemetry 0.33` versions pinned
//! in the root `Cargo.toml`. Three API shapes moved between 0.27 and 0.32 and are
//! the spots to re-check on the next bump: the provider type is
//! `SdkTracerProvider` (0.27's `trace::TracerProvider` name now belongs to the
//! API trait alone), resources are built with `Resource::builder()` (0.27's
//! `Resource::new(vec![...])` is gone), and `with_batch_exporter` no longer takes
//! an async-runtime argument. `WithExportConfig` still needs its explicit `use`
//! for `SpanExporterBuilder::with_endpoint` to resolve. Not yet verified against
//! a live OTel collector — see `document/DECISIONS.md`'s
//! P-observability-completion entry.

// NOT unit-tested in this pass: `init_tracing` calls `tracing_subscriber`'s
// `.init()`, which installs the process-wide global default subscriber
// exactly once — a second call from a second `#[test]` in the same test
// binary panics ("SetGlobalDefaultError"), so this function can't be
// exercised directly by ordinary in-process unit tests the way
// `attome_types::w3c_trace`'s pure format/parse functions are (see that
// module's round-trip tests). Proving the `false` vs. `true` branches here
// actually behave as documented needs either a subprocess-per-case test
// harness or the live-collector verification this plan's own testing
// section (§6) already calls for separately ("prove one request trace
// crosses API, database and worker boundaries") — tracked as a live-
// environment TODO, not skipped by oversight.
use attome_config::ObservabilitySection;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Held by `main.rs` for the process's lifetime; `shutdown()` flushes and
/// tears down the exporter during graceful shutdown ("flush spans during
/// shutdown"). `None` when tracing is disabled (or the exporter failed to
/// construct) — either way `shutdown()` is a harmless no-op.
pub struct TracingGuard {
    tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl std::fmt::Debug for TracingGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TracingGuard").finish_non_exhaustive()
    }
}

impl TracingGuard {
    /// Flushes any buffered spans and shuts the exporter down. Call exactly
    /// once, right before `main.rs` returns — never on the request/job hot
    /// path. Errors are logged, not propagated: a stalled/unreachable
    /// collector must never fail process shutdown (guidelines §10's
    /// degrade-and-recover posture — same failure-mode class D-027 already
    /// applies to every cache/exporter dependency in this codebase).
    pub fn shutdown(self) {
        if let Some(provider) = self.tracer_provider
            && let Err(err) = provider.shutdown()
        {
            tracing::warn!(error = %err, "otel tracer provider shutdown/flush failed");
        }
    }
}

/// Resource attributes are static, set once at boot — no per-request or
/// per-tenant label anywhere (D-002 already means there is no tenant
/// dimension to add; guidelines §14's cardinality discipline for metrics
/// applies identically to span resource attributes).
fn resource(service_version: &str) -> opentelemetry_sdk::Resource {
    // Reuses the same `APP_ENV` signal `AppConfig::from_file` already keys
    // its own config-file selection on (attome-config/src/config.rs) rather
    // than inventing a new `observability.environment` field for one
    // resource attribute — the empty string (production's `config.json`
    // path) reads as "production" here, "debug" as "debug".
    let environment = if attome_config::is_debug_env() {
        "debug"
    } else {
        "production"
    };
    opentelemetry_sdk::Resource::builder()
        .with_service_name("attome-server")
        .with_attributes([
            opentelemetry::KeyValue::new("service.version", service_version.to_string()),
            opentelemetry::KeyValue::new("deployment.environment", environment),
        ])
        .build()
}

/// Installs the process-wide `tracing_subscriber` registry and returns the
/// guard `main.rs` holds until shutdown. `service_version` should be
/// `env!("CARGO_PKG_VERSION")`, passed in rather than read here so this
/// module doesn't need to know which crate's `Cargo.toml` is canonical.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub fn init_tracing(observability: &ObservabilitySection, service_version: &str) -> TracingGuard {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=debug"));
    let fmt_layer = tracing_subscriber::fmt::layer().json();

    if !observability.enable_distributed_tracing {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
        return TracingGuard {
            tracer_provider: None,
        };
    }

    // `AppConfig::validate()` (called by `main.rs` before this function
    // runs) already enforces `otlp_endpoint` is `Some`/non-blank whenever
    // this flag is true (attome-config/src/config.rs) — this is an invariant,
    // not a user-facing error path, same "validate() already checked this"
    // shape as other config-derived `.expect()`s in `main.rs`.
    let endpoint = observability
        .otlp_endpoint
        .as_deref()
        .expect("otlp_endpoint validated non-empty when enable_distributed_tracing=true");

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()
    {
        Ok(exporter) => exporter,
        Err(err) => {
            // Boot-time fail-loud, not fail-fast-panic: an exporter that
            // can't even be constructed (malformed endpoint URL, TLS config
            // error) means tracing was explicitly requested but cannot
            // possibly work. Falling back to fmt-only rather than panicking
            // the whole process keeps a config typo in an opt-in
            // observability feature from taking down the API/DB/auth path
            // it has nothing to do with — logged at `error` so it's not
            // silently swallowed either.
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();
            tracing::error!(
                error = %err,
                otlp_endpoint = endpoint,
                "failed to construct OTLP span exporter — tracing disabled for this boot, \
                 fmt logging unaffected; fix observability.otlp_endpoint and restart"
            );
            return TracingGuard {
                tracer_provider: None,
            };
        }
    };

    // "Configure sampling" — `TraceIdRatioBased` wrapped in `ParentBased` so
    // a sampled-in remote parent (an S2S caller already inside a trace) is
    // always honored regardless of this node's own ratio, per the plan's
    // design (§4).
    let sampler = opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(
        opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(observability.trace_sampling_rate),
    ));

    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(sampler)
        .with_resource(resource(service_version))
        .build();

    // `tracing-opentelemetry` bridges `tracing::Span::current().context()`/
    // `.set_parent(...)` — used by `attome_jobs::enqueue*`'s capture,
    // `attome_server::middleware::trace_context`'s inbound restore, and
    // `attome_auth::oidc`'s outbound injection — to this provider's tracer.
    // Every one of those call sites is a documented no-op without this layer
    // installed, which is exactly the `enable_distributed_tracing = false`
    // path above — nothing past this point is reachable in that case.
    let tracer = tracer_provider.tracer("attome-server");
    opentelemetry::global::set_tracer_provider(tracer_provider.clone());
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    tracing::info!(
        otlp_endpoint = endpoint,
        sampling_rate = observability.trace_sampling_rate,
        "OTLP distributed tracing enabled"
    );

    TracingGuard {
        tracer_provider: Some(tracer_provider),
    }
}
