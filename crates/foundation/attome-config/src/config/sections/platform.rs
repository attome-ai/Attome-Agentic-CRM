//! CORS, background-job worker tuning, the durable-idempotency-tier
//! mandatory-operation registry, the four-eyes-approval mandatory-action
//! registry, and stored-query execution policy.

use serde::Deserialize;

use crate::config::helpers::default_true;

// ── CORS section (Plan 1.3a) ────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default, schemars::JsonSchema)]
pub struct CorsSection {
    /// Explicit allow-list of origins (scheme + host + port), e.g.
    /// "https://app.example.com". Never a wildcard alongside credentials.
    /// When empty, `AppConfig::allowed_origins` derives a dev-only default
    /// from `app.frontend_host`/`app.frontend_port` (always `http://` — set
    /// this explicitly for any deployment behind TLS).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

// ── Jobs section (P1.4) ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct JobsSection {
    /// Max in-flight `PlatformJob`s the fast-queue worker processes
    /// concurrently. Tuned against `database.connection_number` (§14.1) —
    /// the remaining fast-queue work is low-volume and low-CPU, not a pool
    /// hog. (The API-key/S2S "touch" writes that used to be the bulk of it
    /// moved off apalis onto the Redis stream / coalescing-hash path in
    /// D-164.)
    #[serde(default = "default_jobs_worker_concurrency")]
    pub worker_concurrency: usize,
    /// P-job-queue-hardening (D-165) — max in-flight jobs the *batch* queue's
    /// worker processes concurrently. The batch set is exactly the variants
    /// `PlatformJob::is_batch` returns `true` for — the open-ended,
    /// record-count-proportional kinds (`BulkEntityOperation`,
    /// `ApplyStagedImport`, `RewrapSecrets`, `ApplySchemaChangePlan`,
    /// `ApplyMetadataBundle`, `CrawlWebsite`, `CascadeDeactivateDependents`,
    /// `DataExport`, `DataProfile`, `DataBulkTransform`,
    /// `RollbackMigrationRun`, `ReportRun`, `LegalMatterCollect`,
    /// `LegalMatterRelease`). That
    /// method is the authority; this list is a reading aid, not a second copy
    /// to keep in sync.
    /// Lower default than the fast queue's: these are individually heavier
    /// per unit of concurrency.
    #[serde(default = "default_jobs_batch_worker_concurrency")]
    pub batch_worker_concurrency: usize,
    /// P-job-queue-hardening (D-165) — how long a terminal (`Done`/`Killed`)
    /// `apalis.jobs` row is kept before `PlatformJob::PruneApalisJobHistory`
    /// deletes it. Keeps the dead-letter admin list and the table itself
    /// bounded; apalis never vacuums a finished job on its own.
    #[serde(default = "default_jobs_history_retention_days")]
    pub history_retention_days: i64,
    /// BJB-15 (attome-jobs plan) — how long a dead-lettered (`Killed`)
    /// `apalis.jobs` row is kept before `PlatformJob::PruneApalisJobHistory`
    /// deletes it. The same sweep, a longer window: a `Done` row is history,
    /// but an untriaged dead letter is the operator's only record that a job
    /// kept failing, so it outlives the history window and its deletion is
    /// logged with a count. Every dead letter the sweep deletes is a row an
    /// operator never replayed, discarded or investigated (BJB-F9).
    ///
    /// Plain serde default; no production-profile rule belongs in
    /// `loader.rs` for it — the value is neither a secret nor a
    /// safety-critical switch, so it is not validated there.
    #[serde(default = "default_jobs_dead_letter_retention_days")]
    pub dead_letter_retention_days: i64,
    /// M3-T4 — how long a finished workflow step keeps its recorded input
    /// and output before the daily prune clears them (the step's summary
    /// stays).
    #[serde(default = "default_jobs_workflow_payload_retention_days")]
    pub workflow_payload_retention_days: i64,
    /// P-worker-process-split — `true` (default, today's behavior unchanged)
    /// runs the apalis job `Monitor` inline inside the `server` process, same
    /// as before this flag existed. A deployment that has split the worker
    /// out into its own process/container (`crates/server/src/bin/worker.rs`,
    /// scaled and deployed independently of the HTTP tier) sets this `false`
    /// so `server` never builds/runs the `Monitor` or spawns the partition/
    /// upload-session maintenance schedulers — those move to `worker`
    /// entirely, avoiding double-enqueue from two schedulers ticking at once.
    /// Same "off by default until an operator opts in" posture as
    /// `database.migrate_on_boot`.
    #[serde(default = "default_true")]
    pub run_worker_inline: bool,
}

// A bare `#[derive(Default)]` would silently flip `run_worker_inline` to
// `false` (documented default `true`, "today's behavior unchanged") and
// zero `worker_concurrency`/`batch_worker_concurrency` whenever a config
// omits this whole `jobs` section — `server` would then never build its
// apalis `Monitor` or spawn the partition/upload-session maintenance
// schedulers, silently leaving every enqueued job unprocessed forever, with
// no boot error to flag it. See `S2SSection`'s identical note above.
impl Default for JobsSection {
    fn default() -> Self {
        Self {
            worker_concurrency: default_jobs_worker_concurrency(),
            batch_worker_concurrency: default_jobs_batch_worker_concurrency(),
            history_retention_days: default_jobs_history_retention_days(),
            dead_letter_retention_days: default_jobs_dead_letter_retention_days(),
            workflow_payload_retention_days: default_jobs_workflow_payload_retention_days(),
            run_worker_inline: default_true(),
        }
    }
}

fn default_jobs_worker_concurrency() -> usize {
    10
}

fn default_jobs_batch_worker_concurrency() -> usize {
    3
}

fn default_jobs_history_retention_days() -> i64 {
    30
}

/// BJB-15 — 3× the history default, so turning history retention down never
/// silently shortens how long an operator has to triage a dead letter.
fn default_jobs_dead_letter_retention_days() -> i64 {
    90
}

fn default_jobs_workflow_payload_retention_days() -> i64 {
    30
}

// ── Idempotency section (P-idempotency-hardening §4.4/§4.5) ────────────────────

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct IdempotencySection {
    /// Operation-name strings (`"{METHOD} {route-template}"`, e.g.
    /// `"POST /api/v1/{entity}/bulk"` — the same string
    /// `attome_server::middleware::idempotency::operation_name` derives via
    /// axum's `MatchedPath`) that must go through the durable Postgres tier
    /// (`base_idempotency_record`, migration `0066`) instead of the default
    /// Redis-only gate, and must require `X-Idempotency-Key` outright (a
    /// missing header on a listed route is `422 Validation`, not a silent
    /// skip). Empty by default — a deployment opts in explicitly.
    ///
    /// Validated at boot, not here: `AppConfig::validate()` has no
    /// visibility into the router (route templates are assembled in
    /// `crates/server`/`xrm-server`, several layers above `attome-config`), so
    /// `server::boot::init`'s `validate_operation_registries` (the
    /// composition root, which depends on both this crate and `xrm-server`)
    /// checks every entry here against `xrm_server::bulk::
    /// MANDATORY_TIER_OPERATIONS` and fails the boot closed on an
    /// unrecognized one, instead of silently never matching. D-327: the same
    /// function also fails boot closed when `app.deployment_profile =
    /// "production"` and this list is empty or missing any
    /// `MANDATORY_TIER_OPERATIONS` entry — `config.production.example.json`
    /// ships with the full list already filled in for exactly this reason.
    #[serde(default)]
    pub mandatory_operations: Vec<String>,
    /// How long a completed `base_idempotency_record` row is kept before
    /// `PlatformJob::PruneIdempotencyRecords` soft-deletes it. Same default
    /// window as the Redis tier's TTL (`idempotency.rs::TTL_SECS`).
    #[serde(default = "default_idempotency_durable_retention_hours")]
    pub durable_retention_hours: u64,
    /// S9-T2: how long a bulk job's durable record is kept (a bulk job may
    /// be retried days later). Seven days by default.
    #[serde(default = "default_idempotency_bulk_retention_hours")]
    pub bulk_retention_hours: u64,
    /// Largest successful response body the Redis idempotency gate stores
    /// for replay. A larger response still reaches the client in full, but a
    /// same-key retry gets `idempotency_replay_unavailable` instead of a
    /// replay. Bounds how much a single cached response can put on the
    /// coordination Redis. Must be at least 1.
    #[serde(default = "default_idempotency_replay_max_bytes")]
    pub replay_max_bytes: usize,
    /// S9-T3: the key ring that seals a durable record's stored response
    /// (AES-256-GCM, tagged with the key id, bound to the record's id). Unset
    /// stores responses as they are; set it on any deployment whose
    /// responses carry personal data. Keep a retired key in the ring until
    /// the records it sealed are past `bulk_retention_hours`.
    #[serde(default)]
    pub response_encryption_key: Option<crate::KeyRing>,
}

/// S9-T2: seven days.
fn default_idempotency_bulk_retention_hours() -> u64 {
    7 * 24
}

// A derived `Default` would zero `durable_retention_hours` — serde's
// field-level `#[serde(default = "fn")]` above only fires while
// deserializing a *present* "idempotency" object; when the whole key is
// absent (the expected common case, since this section is opt-in),
// `AppConfig`'s own `#[serde(default)]` on the `idempotency` field calls
// this `Default` impl directly, bypassing per-field serde defaults entirely
// (same footgun `RetentionSection`/`SecuritySection`/`QuerySection` already
// hand-implement `Default` to avoid).
impl Default for IdempotencySection {
    fn default() -> Self {
        Self {
            mandatory_operations: Vec::new(),
            durable_retention_hours: default_idempotency_durable_retention_hours(),
            bulk_retention_hours: default_idempotency_bulk_retention_hours(),
            replay_max_bytes: default_idempotency_replay_max_bytes(),
            response_encryption_key: None,
        }
    }
}

fn default_idempotency_durable_retention_hours() -> u64 {
    24
}

fn default_idempotency_replay_max_bytes() -> usize {
    1024 * 1024
}

// ── Approval section (D-195 / P-four-eyes-approval) ─────────────────────────

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct ApprovalSection {
    /// `action_type` strings (e.g. `"security.rewrap"`,
    /// `"security.role_grant"`; `xrm_server::KNOWN_ACTION_TYPES` is the list
    /// of record) that must go
    /// through `attome_approval::submit` instead of executing inline. Empty
    /// by default — a deployment opts in explicitly, same shape as
    /// `idempotency.mandatory_operations`.
    ///
    /// Validated at boot, not here (same shape as
    /// `IdempotencySection::mandatory_operations`): `server::boot::init`'s
    /// `validate_operation_registries` checks every entry here against
    /// `xrm_server::KNOWN_ACTION_TYPES` (mirroring `execute_approved`'s
    /// match arms) and fails the boot closed on an unrecognized action_type,
    /// instead of silently never gating anything. `attome-config` still has no
    /// visibility into this itself (guidelines §1: base-* has zero xrm-*
    /// knowledge) — the composition root owns the check.
    #[serde(default)]
    pub required_actions: Vec<String>,
    /// How long a submitted request stays decidable before
    /// `attome_approval::sweep_expired` reaps it as `expired`.
    #[serde(default = "default_approval_ttl_hours")]
    pub ttl_hours: i64,
}

// A derived `Default` would zero `ttl_hours` when the whole "approval" key
// is absent — same footgun `IdempotencySection` documents above.
impl Default for ApprovalSection {
    fn default() -> Self {
        Self {
            required_actions: Vec::new(),
            ttl_hours: default_approval_ttl_hours(),
        }
    }
}

fn default_approval_ttl_hours() -> i64 {
    72
}

// P-job-system-hardening (b)'s telemetry-buffer tuning (flush interval,
// stream maxlen, consumer batch size, reclaim-idle window) was removed from
// config entirely (config-surface reduction, item 23) — every caller used
// the same values and none were ever varied per-deployment. The constants
// now live next to their call sites: `crates/server/src/main.rs` and
// `crates/server/src/bin/worker.rs` (flush interval/batch size/reclaim idle)
// and `xrm_s2s::middleware`'s `STREAM_MAXLEN` (stream maxlen).

// ── Query section (P-stored-query-containment / D-126) ─────────────────────────

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct QuerySection {
    /// Phase 2's rollback switch: `query/execute` skips the per-request
    /// `EXPLAIN` cost check by default, trusting the cost estimate captured
    /// once in `xrm_core_sql_query_version` at publish time. `true` restores the
    /// pre-phase-2 behavior of re-running `EXPLAIN` on every execute call
    /// (defense against runtime plan drift the cached estimate can't see) —
    /// a kill switch, not a recommended steady-state setting.
    #[serde(default)]
    pub validate_on_execute: bool,
    /// `true` (default): `query/execute` requests with neither `after_id`
    /// nor `include_total: true` run in keyset/cursor mode from the start of
    /// the result set, instead of OFFSET. Set `false` to restore the pre-P-
    /// stored-query-containment default (plain OFFSET, no total) for one
    /// release as a rollback switch (§7 of the plan) — `include_total: true`
    /// always gets `COUNT(*) OVER()` totals regardless of this flag.
    #[serde(default = "default_query_cursor_default")]
    pub cursor_default: bool,
    /// AA4-T3: the deepest row an offset page may start at. OFFSET reads and
    /// throws away every row before it, so a deep page costs as much as
    /// reading them all; past this a request is refused with a pointer to
    /// `after_id` (keyset paging), which costs the same at any depth.
    #[serde(default = "default_query_max_offset_rows")]
    pub max_offset_rows: i64,
    /// AA4-T7: how long a query may run, by kind of request. A query past
    /// its limit answers `504 query_timeout` with a hint to run it as an
    /// export.
    #[serde(default)]
    pub timeouts_ms: QueryTimeouts,
    /// AA4-T5: a filterable text attribute gets a trigram (GIN) index, so a
    /// `contains` filter is index-backed, once its table's estimated row
    /// count reaches this. At least 1; default 100,000.
    #[serde(default = "default_trigram_index_min_rows")]
    pub trigram_index_min_rows: i64,
}

fn default_trigram_index_min_rows() -> i64 {
    100_000
}

/// AA4-T7: statement time limits in milliseconds, by kind of request.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct QueryTimeouts {
    /// A person waiting on a list or a view (default 500).
    #[serde(default = "default_interactive_timeout_ms")]
    pub interactive: u32,
    /// A stored query flagged as a report (default 5000).
    #[serde(default = "default_report_timeout_ms")]
    pub report: u32,
}

impl Default for QueryTimeouts {
    fn default() -> Self {
        Self {
            interactive: default_interactive_timeout_ms(),
            report: default_report_timeout_ms(),
        }
    }
}

fn default_interactive_timeout_ms() -> u32 {
    500
}

fn default_report_timeout_ms() -> u32 {
    5000
}

impl Default for QuerySection {
    fn default() -> Self {
        Self {
            validate_on_execute: false,
            cursor_default: true,
            max_offset_rows: default_query_max_offset_rows(),
            timeouts_ms: QueryTimeouts::default(),
            trigram_index_min_rows: default_trigram_index_min_rows(),
        }
    }
}

fn default_query_cursor_default() -> bool {
    true
}

fn default_query_max_offset_rows() -> i64 {
    10_000
}

// ── Change feed section (M01 §7 C-04 — outbox retention) ────────────────────

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct ChangeFeedSection {
    /// Floor for `PlatformJob::PruneChangeFeed`: how long a fully-processed
    /// `xrm_core_entity_change_event` row is kept before it becomes eligible
    /// for deletion. This is a floor, not a target — `xrm_foundation::
    /// change_feed::prune` additionally never deletes a row the slowest
    /// registered consumer cursor has not passed, however old it is, so
    /// raising this only ever makes pruning MORE conservative, never less.
    #[serde(default = "default_change_feed_retention_days")]
    pub retention_days: i64,
}

// A derived `Default` would zero `retention_days` when the whole
// "change_feed" key is absent from a deployment's config — same footgun
// `IdempotencySection`/`ApprovalSection` document above.
impl Default for ChangeFeedSection {
    fn default() -> Self {
        Self {
            retention_days: default_change_feed_retention_days(),
        }
    }
}

fn default_change_feed_retention_days() -> i64 {
    30
}
