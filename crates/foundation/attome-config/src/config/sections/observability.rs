//! Metrics/tracing/profiler wiring (`ObservabilitySection`), outbound SMTP
//! (`EmailSection`), and the one still-configured external-API credential
//! (`GoogleAiSection`).

use serde::Deserialize;

use crate::Secret;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
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
    /// AA1-T5: who gets a `Server-Timing` header splitting each response's
    /// time into middleware, authentication, permissions, database, handler
    /// and outside calls. `dev` (the default): every response, in a debug
    /// environment (`APP_ENV=debug`) only. `admins`: responses to signed-in
    /// administrators. `off`: nobody. Measuring the database phase reads
    /// sqlx's per-statement events, which costs a little on every query
    /// while the header can be sent.
    #[serde(default = "default_server_timing")]
    pub server_timing: String,
    /// U4-T1: sample this process's metrics into `ops_metric_sample` every
    /// minute, kept 30 days. Unset: on for Solo (`cache.backend = "memory"`),
    /// off otherwise (several servers use Prometheus).
    #[serde(default)]
    pub builtin_store: Option<bool>,
    /// AB10-T2: who hears about a built-in alert firing or resolving, by
    /// email (sent through the job queue and the `email` section's relay).
    #[serde(default)]
    pub alert_emails: Vec<String>,
    /// AB10-T2: incoming-webhook URLs (Slack, Teams, any service that takes
    /// `{"text": ...}`) told about a built-in alert firing or resolving.
    #[serde(default)]
    pub alert_webhooks: Vec<String>,
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

#[derive(Clone, Deserialize, schemars::JsonSchema)]
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
    pub smtp_password: Secret,
    pub smtp_from_address: String,
    pub smtp_from_name: String,
    /// Z8-T6: test mode. When set, every email goes to this one address
    /// instead of its recipients (named in an `X-Attome-Original-To`
    /// header), so a development or copied deployment never mails a real
    /// person.
    #[serde(default)]
    pub test_mode_catch_all: Option<String>,
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
    /// Z8-T1: which provider sends a message: SMTP (the fields above, the
    /// default), Amazon SES or SendGrid, chosen per sender identity.
    #[serde(default)]
    pub providers: EmailProviders,
    /// Z8-T3: messages per minute, per stream. Transactional mail (sign-in
    /// codes, resets, notifications) and bulk mail (surveys, campaigns) each
    /// have their own limits, so a campaign never holds up a sign-in code.
    /// Paced per worker node: a send over a limit waits for the minute to
    /// turn (up to a minute), then retries later.
    #[serde(default)]
    pub rate_limits: EmailRateLimits,
    /// Z8-T5: where providers report bounces, complaints and unsubscribes
    /// (`POST /api/v1/email/webhooks/{provider}`). Nothing is accepted from a
    /// provider not configured here.
    #[serde(default)]
    pub feedback: EmailFeedback,
    /// Z8-T4: the sending domains whose SPF, DKIM and DMARC records are
    /// checked (`GET /api/v1/admin/email/domains/{domain}/check`, and daily),
    /// and the DNS resolver asked.
    #[serde(default)]
    pub domain_check: EmailDomainCheck,
}

/// Z8-T4: `email.domain_check`.
#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
pub struct EmailDomainCheck {
    /// The DNS resolver the checks ask (an IP address, port 53 unless given).
    #[serde(default = "default_dns_resolver")]
    pub resolver: String,
    /// The domains this deployment sends from; the daily check raises the
    /// `SendingDomainBroken` alert when one of their records breaks.
    #[serde(default)]
    pub domains: Vec<SendingDomain>,
}

impl Default for EmailDomainCheck {
    fn default() -> Self {
        Self {
            resolver: default_dns_resolver(),
            domains: Vec::new(),
        }
    }
}

fn default_dns_resolver() -> String {
    "1.1.1.1:53".to_owned()
}

/// Z8-T4: one sending domain.
#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
pub struct SendingDomain {
    /// The domain (`example.com`).
    pub domain: String,
    /// The sending provider's SPF include (`amazonses.com`, `sendgrid.net`).
    #[serde(default)]
    pub spf_include: Option<String>,
    /// The sending provider's DKIM selector; unset skips the DKIM check.
    #[serde(default)]
    pub dkim_selector: Option<String>,
}

/// Z8-T5: `email.feedback`.
#[derive(Clone, Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct EmailFeedback {
    /// SendGrid's signed event webhook verification key (the base64
    /// SubjectPublicKeyInfo SendGrid shows); unset refuses SendGrid events.
    #[serde(default)]
    pub sendgrid_public_key: Option<String>,
    /// The SNS topics (ARNs) whose SES notifications are accepted; empty
    /// refuses SES events.
    #[serde(default)]
    pub ses_topic_arns: Vec<String>,
}

/// Z8-T3: `email.rate_limits`. Each stream's own limits; a stream with
/// none set sends as fast as the provider takes it.
#[derive(Clone, Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct EmailRateLimits {
    /// Limits on transactional mail.
    #[serde(default)]
    pub transactional: EmailStreamRates,
    /// Limits on bulk mail.
    #[serde(default)]
    pub bulk: EmailStreamRates,
}

/// Z8-T3: one stream's limits, in messages per minute.
#[derive(Clone, Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct EmailStreamRates {
    /// By provider name (`"smtp"`, `"ses"`, `"sendgrid"`):
    /// `{"ses": 600}`. A provider not named has no limit.
    #[serde(default)]
    pub providers: std::collections::BTreeMap<String, u32>,
    /// By recipient domain, any case: `{"gmail.com": 120}`. A domain not
    /// named has no limit.
    #[serde(default)]
    pub domains: std::collections::BTreeMap<String, u32>,
}

/// Z8-T1: `email.providers`. `by_sender` maps a From address (any case) to
/// a provider name; every other address takes `default`, SMTP when unset.
/// A provider named here needs its own block below.
#[derive(Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct EmailProviders {
    /// `"smtp"`, `"ses"` or `"sendgrid"`.
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub by_sender: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub ses: Option<SesSettings>,
    #[serde(default)]
    pub sendgrid: Option<SendGridSettings>,
}

/// Z8-T1: Amazon SES (v2 API) credentials.
#[derive(Clone, Deserialize, schemars::JsonSchema)]
pub struct SesSettings {
    /// e.g. `"eu-west-1"`.
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: Secret,
    /// A temporary credential's session token.
    #[serde(default)]
    pub session_token: Option<Secret>,
    /// Overrides `https://email.{region}.amazonaws.com` (a VPC endpoint, a
    /// test double).
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// Z8-T1: SendGrid (v3 API) credentials.
#[derive(Clone, Deserialize, schemars::JsonSchema)]
pub struct SendGridSettings {
    pub api_key: Secret,
    /// Overrides `https://api.sendgrid.com` (the EU region, a test double).
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// Hand-rolled: the secret key is never printed.
impl std::fmt::Debug for SesSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SesSettings")
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// Hand-rolled: the API key is never printed.
impl std::fmt::Debug for SendGridSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendGridSettings")
            .field("api_key", &"[REDACTED]")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl std::fmt::Debug for EmailProviders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailProviders")
            .field("default", &self.default)
            .field("by_sender", &self.by_sender)
            .field("ses", &self.ses)
            .field("sendgrid", &self.sendgrid)
            .finish()
    }
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
            .field("providers", &self.providers)
            .finish()
    }
}

/// Only `api_key` is a real per-deployment credential today — no engine
/// crate calls the Gemini API yet, so
/// `base_url`/`default_model`/`timeout_seconds` were dropped (D-099-era
/// scaffolding for a feature that was never wired up); reintroduce them
/// alongside whatever crate actually builds the client once one exists.
#[derive(Clone, Deserialize, schemars::JsonSchema)]
pub struct GoogleAiSection {
    pub api_key: Secret,
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

/// AA1-T5: `observability.server_timing` when unset.
fn default_server_timing() -> String {
    "dev".to_owned()
}

/// AA1-T5: the values `observability.server_timing` accepts.
pub const SERVER_TIMING_MODES: &[&str] = &["off", "dev", "admins"];
