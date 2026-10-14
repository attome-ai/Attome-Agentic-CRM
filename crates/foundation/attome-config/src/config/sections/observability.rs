//! Metrics/tracing/profiler wiring (`ObservabilitySection`), outbound SMTP
//! (`EmailSection`), and the one still-configured external-API credential
//! (`GoogleAiSection`).

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ObservabilitySection {
    pub metrics_port: u16,
    /// P-observability-completion — `TraceIdRatioBased` sampler ratio once
    /// `enable_distributed_tracing = true`. Meaningless (and unread) while
    /// that flag is false, same "declared but inert until its gate flips"
    /// shape as most other flag-gated fields in this file.
    pub trace_sampling_rate: f64,
    /// P-observability-completion — the enable switch for an OTLP trace
    /// exporter. `false` (every config file's value today) is byte-identical
    /// to today's tracing_subscriber::fmt()-only behavior: no OTel layer
    /// installed, no listener bound, no span exported anywhere.
    ///
    /// NOTE ON CURRENT IMPLEMENTATION STATE (be skeptical of any doc that
    /// claims this is fully wired — verify against `crates/server/src/main.rs`
    /// and this crate's Cargo.toml before trusting it): as of this comment,
    /// this flag and `otlp_endpoint` below are validated at boot (see
    /// `validate()`) and the W3C `traceparent` header is extracted/recorded
    /// on the request span by `attome_server::middleware::trace_context`
    /// (wired into `apply_outer_layers` unconditionally, since it degrades to
    /// a no-op when no `traceparent` header is present — which is every
    /// request today, since nothing yet sends one) — but `main.rs` does NOT
    /// yet install a real `tracing-opentelemetry` layer or ship any span to
    /// `otlp_endpoint`. That exporter wiring, and forwarding `traceparent` on
    /// the two outbound HTTP call sites (`attome_auth::oidc`'s discovery/JWKS
    /// fetch) and into `PlatformJob` enqueue call sites, remain unimplemented
    /// — see DECISIONS.md's P-observability-completion entry for the exact
    /// remaining scope and why it was deferred (unverifiable third-party
    /// crate/version surface in an environment with no Rust toolchain to
    /// compile against).
    pub enable_distributed_tracing: bool,
    /// P-observability-completion — the OTLP collector this deployment's own
    /// exporter would send spans to (Grafana Tempo / Jaeger / the OpenTelemetry
    /// Collector — a per-deployment adoption decision, never a hosted/shared
    /// endpoint per D-002). Required (fail-closed, see `validate()`) whenever
    /// `enable_distributed_tracing = true`; `None` otherwise. Currently
    /// validated but not yet read by any exporter — see
    /// `enable_distributed_tracing`'s doc comment above.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// attome-profiler: live per-probe call count/avg/min/max dashboard (the
    /// Angular "Profiler" admin page). Default false — byte-identical
    /// behavior (no profiler middleware layer, no Redis writes) until a
    /// deployment opts in, same "dark unless configured" posture as
    /// `metrics_port == 0`.
    #[serde(default)]
    pub profiler_enabled: bool,
    /// U4-T1: sample this process's metrics into `ops_metric_sample` every
    /// minute, kept 30 days. Unset: on for Solo (`cache.backend = "memory"`),
    /// off otherwise (several servers use Prometheus).
    #[serde(default)]
    pub builtin_store: Option<bool>,
    /// P-worker-process-split follow-up (the TODO `crates/server/src/bin/
    /// worker.rs` shipped with) — the dedicated `worker` binary has no HTTP
    /// listener at all today, so a split deployment's compose/k8s healthcheck
    /// can only prove the process exists (`pgrep`), not that it can actually
    /// reach Postgres/Redis. Unlike `metrics_port` (dark by default: every
    /// existing config has it at 0), this defaults **on** — a worker
    /// readiness probe should exist out of the box, not require every
    /// deployment to opt in. `0` still disables it, same "0 = off" convention
    /// as `metrics_port`, for a bare-metal/host-networking deployment that
    /// genuinely wants it off. Read by `crates/server/src/bin/worker.rs`
    /// only — `main.rs` never binds this (its own `/health/ready` already
    /// covers the inline-worker case via `app.port`).
    #[serde(default = "default_worker_health_port")]
    pub worker_health_port: u16,
}

fn default_worker_health_port() -> u16 {
    9091
}

#[derive(Clone, Deserialize)]
pub struct EmailSection {
    /// P-account-lifecycle — this section existed but nothing consumed it
    /// (dead config, audit finding E). `enabled` is the explicit opt-in: when
    /// false, `attome-email` is never constructed and reset/verification
    /// requests return 503 `feature_unavailable` instead of silently trying
    /// (and failing) to reach an SMTP host that was never meant to be live —
    /// same "ships dark behind a flag" pattern as `audit.chainer_enabled`.
    #[serde(default)]
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
    pub smtp_from_address: String,
    pub smtp_from_name: String,
    /// **Deprecated** (BEM-5): `true` = implicit TLS, `false` = plaintext.
    /// Superseded by [`Self::tls_mode`], which wins when both are set; kept
    /// deserializable for one release so an existing `config.json` keeps
    /// booting, and warned about by `validate()` so operators migrate.
    /// `Option` rather than `bool` so "absent" is distinguishable from an
    /// explicit `false` — the old key was mandatory, so an absent one means
    /// the file was written after the `tls_mode` rename.
    #[serde(default)]
    pub smtp_use_tls: Option<bool>,
    /// The SMTP transport security mode (BEM-5, attome-email plan §4.3):
    /// `"implicit"` (SMTPS, the default), `"starttls"` (upgrade required —
    /// lettre aborts if the relay does not offer it), or `"none"` (plaintext,
    /// refused outside `APP_ENV=debug`). Validated by `validate()`.
    ///
    /// A `String`, not an enum: the value crosses the `attome-config` boundary
    /// into `attome-email`'s transport builder, and this section's module is
    /// `pub(crate)` — a new public enum would need a re-export in
    /// `config/mod.rs` and `lib.rs`, which BEM-5 does not own.
    #[serde(default)]
    pub tls_mode: Option<String>,
}

impl EmailSection {
    /// The effective transport mode: `tls_mode` when set, otherwise the
    /// deprecated `smtp_use_tls` bool (`true` → `"implicit"`,
    /// `false` → `"none"`), otherwise `"implicit"` — the historical
    /// default and the only safe one.
    pub fn effective_tls_mode(&self) -> &str {
        match self.tls_mode.as_deref() {
            Some(mode) => mode,
            None => match self.smtp_use_tls {
                Some(false) => "none",
                _ => "implicit",
            },
        }
    }
}

/// Hand-rolled: `smtp_password` is a live SMTP credential — the derived
/// `Debug` would print it raw.
impl std::fmt::Debug for EmailSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailSection")
            .field("enabled", &self.enabled)
            .field("smtp_host", &self.smtp_host)
            .field("smtp_port", &self.smtp_port)
            .field("smtp_user", &self.smtp_user)
            .field("smtp_password", &"[REDACTED]")
            .field("smtp_from_address", &self.smtp_from_address)
            .field("smtp_from_name", &self.smtp_from_name)
            .field("smtp_use_tls", &self.smtp_use_tls)
            .field("tls_mode", &self.tls_mode)
            .finish()
    }
}

/// Only `api_key` is a real per-deployment credential today — no engine
/// crate calls the Gemini API yet, so
/// `base_url`/`default_model`/`timeout_seconds` were dropped (D-099-era
/// scaffolding for a feature that was never wired up); reintroduce them
/// alongside whatever crate actually builds the client once one exists.
#[derive(Clone, Deserialize)]
pub struct GoogleAiSection {
    pub api_key: String,
}

/// Hand-rolled: `api_key` is a live external-API credential — the derived
/// `Debug` would print it raw.
impl std::fmt::Debug for GoogleAiSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleAiSection")
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}
