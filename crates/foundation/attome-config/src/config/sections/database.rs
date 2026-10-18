//! `app` and `database` sections — process-identity/binding config
//! (`AppSection`) and the PostgreSQL connection/credential family
//! (`DatabaseSection` + its `readonly`/`migrator`/`runtime` credential
//! overrides).

use serde::Deserialize;

use crate::Secret;

use crate::config::helpers::{
    default_max_body, default_request_timeout, default_server_host, default_true,
};

#[derive(Debug, Clone, Deserialize)]
pub struct AppSection {
    pub port: u16,
    #[serde(default = "default_server_host")]
    pub server_host: String,
    pub frontend_host: String,
    pub frontend_port: u16,
    /// P-account-lifecycle — canonical public URL used to build links in
    /// emails (password reset, verification), e.g. "https://app.customer.com".
    /// `None` (the default) falls back to the same dev-only derived origin
    /// `allowed_origins()` uses (`http://{frontend_host}:{frontend_port}`) —
    /// any deployment behind TLS must set this explicitly, mirroring the
    /// `cors.allowed_origins` rule.
    #[serde(default)]
    pub public_frontend_url: Option<String>,
    #[serde(default = "default_max_body")]
    pub max_body_size_bytes: usize,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    /// S1 (BSV-F13 / BSV-D11) — how many seconds a draining node keeps
    /// answering `/health/ready` with 503 **before** it signals its HTTP
    /// listeners to stop accepting connections.
    ///
    /// `main.rs` flips `AppState::draining` and then waits this long; without
    /// it the flag and the graceful-shutdown signal fire in the same instant,
    /// axum stops `accept()` immediately, and the only way a load balancer
    /// could ever read the 503 was an already-open keep-alive connection — the
    /// probe it actually makes opens a new one and gets connection refused. One
    /// LB probe interval x failure threshold is the right value; `0` restores
    /// the pre-S1 behaviour (flip and signal in the same tick).
    ///
    /// D-205-safe default: hand-written `default_shutdown_drain_delay_secs`
    /// returns 10, not a derived `Default`'s 0 (which would silently disable
    /// the drain the moment the key is omitted). `AppSection` itself is not
    /// `#[serde(default)]` in `AppConfig` (its `frontend_host`/`port` are
    /// required), so an omitted `app` block already fails to deserialize and
    /// this default can only apply to an omitted key inside a present block.
    /// Bounded to `0..=SHUTDOWN_DRAIN_DELAY_MAX_SECS` by
    /// `AppConfig::validate`.
    #[serde(default = "default_shutdown_drain_delay_secs")]
    pub shutdown_drain_delay_secs: u64,
    /// P-production-safety-profile — one of `"development"`/`"production"`
    /// (see `VALID_DEPLOYMENT_PROFILES` in `validate()`). Default
    /// `"development"` — today's behavior, unchanged: every other field in
    /// this file keeps whatever value an operator gave it, validated only by
    /// the per-field checks that already existed. Setting `"production"` is
    /// an explicit, additional opt-in (never derived from `APP_ENV`, which
    /// already means "tolerate unresolved `${VAR}` placeholders for local
    /// dev" — a different concern) that runs `validate_production_profile`:
    /// a fixed set of individually-valid-but-unsafe-in-combination defaults
    /// (`database.ssl_mode = "prefer"`, `cache.tls_enabled = false`,
    /// `storage.s3_verify_ssl = false`,
    /// no `auth.apikey_default_expiry_days`,
    /// `audit.signing_enabled = false`, `database.migrate_on_boot = true`,
    /// `jobs.run_worker_inline = true`) become hard boot errors instead of
    /// silent template carry-overs. No per-check escape hatch by design — a
    /// hatch on any one of these would reopen exactly the gap this profile
    /// closes.
    ///
    /// Not the *only* thing gated on this field: `validate_production_profile`
    /// below is `attome-config`'s own complete list, but `server::boot::init`
    /// (the composition root, which has visibility this crate doesn't) reads
    /// this same value too — D-327's `idempotency.mandatory_operations`
    /// completeness floor is production-only for exactly the same reason,
    /// just enforced one layer up. Don't assume this field's production
    /// requirements begin and end with what's checked in this file.
    #[serde(default = "default_deployment_profile")]
    pub deployment_profile: String,
    /// The built web app's directory, served by `attome serve` for every
    /// GET outside the API (`attome_server::web`). Unset: a `web` directory
    /// next to the executable when one exists; otherwise the server serves
    /// the API only and the web app is hosted separately.
    #[serde(default)]
    pub web_root: Option<String>,
    /// Z5-T1: in a debug build, every response carries `x-attome-layers`,
    /// the layers the request passed, outermost first, so a test can pin
    /// the middleware order. Ignored in a release build.
    #[serde(default)]
    pub debug_pipeline_trace: bool,
    /// Packs applied at every boot, in order (`attome init --pack crm`): each
    /// pack's changesets from `<packs_root>/<name>/changesets/`, through the
    /// changeset ledger, so a second boot changes nothing.
    #[serde(default)]
    pub packs: Vec<String>,
    /// Where packs live. Unset: `packs` next to the executable.
    #[serde(default)]
    pub packs_root: Option<String>,
    /// A4-T1: the deployment's time zone, an IANA name such as `Asia/Riyadh`.
    /// Dates in autonumber formats and their yearly, monthly and daily resets
    /// follow it. Unset (or unknown): UTC.
    #[serde(default)]
    pub time_zone: Option<String>,
    /// U11-T1: the operator's contract or purchase-order reference, shown on
    /// the usage page. Free text; nothing is enforced by it.
    #[serde(default)]
    pub contract_reference: Option<String>,
}

fn default_deployment_profile() -> String {
    "development".to_string()
}

/// S1 (BSV-D11) — one LB probe interval x failure threshold is the point of
/// the drain delay; 10 s matches a 5 s probe with 2 failures and is short
/// enough that a restart still feels prompt. See
/// `AppSection::shutdown_drain_delay_secs`.
pub(crate) fn default_shutdown_drain_delay_secs() -> u64 {
    10
}

#[derive(Clone, Deserialize)]
pub struct DatabaseSection {
    pub host: String,
    pub port: u16,
    pub dbname: String,
    pub user: String,
    /// P-bootstrap-credential-scoping (D-204) — the schema-bootstrap/
    /// `CREATE ROLE`-capable identity (`database_url()`/`direct_database_url()`),
    /// needed ONLY by the one-shot `migrate` binary and, when
    /// `migrate_on_boot = true`, by the inline bootstrap sequence in
    /// `boot::init`. `server`/`worker` never legitimately reach either code
    /// path once `migrate_on_boot = false` and `migrator`/`runtime` below are
    /// configured (D-148) — so a deployment that renders those two
    /// processes' `config.json` without this field (and without `DB_PASSWORD`
    /// in their `.env`) keeps the bootstrap credential out of their container
    /// environment and out of the `AppState` they hold in memory for the
    /// life of the process, instead of it merely going unused. `None` is
    /// valid whenever nothing in this process can reach `database_url()`;
    /// `validate()` enforces `Some` when `migrate_on_boot = true`, and
    /// `bin/migrate.rs` independently requires `Some` unconditionally (that
    /// binary is not gated by `migrate_on_boot` — see its own module doc).
    #[serde(default)]
    pub password: Option<Secret>,
    pub schema: String,
    /// Pool size — plausibly scales with hardware/load. Has a default so a
    /// deployment that hasn't tuned it can omit the key entirely.
    #[serde(default = "default_db_connection_number")]
    pub connection_number: u32,
    /// Pool **acquire** timeout in seconds, fractional allowed (`0.5` is
    /// 500ms): how long a caller waits for a pooled connection, which
    /// includes opening a new one. Also bounds the connect of attome-db's
    /// unpooled direct/migrator connections. `AppConfig::validate` requires a
    /// finite value in `(0, 120]`.
    #[serde(default = "default_db_timeout")]
    pub timeout: f64,
    /// attome-db hardening Phase 2.3 — optional per-pool sizes. A pool with no
    /// entry here is sized from `connection_number`, so omitting the whole
    /// block keeps today's behavior. Each value must be `1..=1000`
    /// (`AppConfig::validate`). The direct pool (schema bootstrap and
    /// migrations) keeps its fixed size of 2 and has no entry.
    #[serde(default)]
    pub pools: DatabasePools,
    /// Z2-T2: how many processes share this database. With more than one,
    /// or with `max_server_connections` set, a pool with no
    /// `database.pools` entry is sized from PostgreSQL's connection budget
    /// split across the nodes instead of from `connection_number`.
    #[serde(default = "default_node_count")]
    pub node_count: u32,
    /// Z2-T5: per statement class, the statement, lock and
    /// idle-in-transaction timeouts that replace the class defaults. A class
    /// left out keeps its defaults.
    #[serde(default)]
    pub statement_classes: StatementClassOverrides,
    /// Z2-T2: PostgreSQL's (or pgbouncer's) `max_connections`, when known.
    /// `None` assumes 100 once sizing applies.
    #[serde(default)]
    pub max_server_connections: Option<u32>,
    /// SELECT-only role for `/api/v1/query/execute` (P1.1e) — reuses this
    /// section's host/port/dbname/schema, only the credentials differ.
    #[serde(default)]
    pub readonly: Option<ReadonlyDbCredentials>,
    /// P-db-privilege-separation / D-117 — DDL-capable identity for runtime
    /// entity/attribute provisioning (`xrm-entity::provision`) and boot-time
    /// entity seeding, reusing this section's host/port/dbname/schema, only
    /// the credentials differ (same shape as `readonly`). Deliberately NOT
    /// used for schema bootstrap/`sqlx::migrate!` — see
    /// `AppConfig::direct_database_url`'s doc comment for why that stays on
    /// `user`/`password` forever. `None` (the default) falls back to
    /// `user`/`password` above — today's behavior, unchanged. Set this once
    /// `migrations/0042_migrator_runtime_roles.sql`'s `attome_migrator` role
    /// exists and has had a login password applied
    /// (`server::db_role_seed::seed_migrator`).
    ///
    /// Fail-closed follow-up (supersedes D-117's original "additive, not
    /// fail-closed" framing — see DECISIONS.md): `main.rs` now refuses to
    /// boot with this unset outside `APP_ENV=debug`, same posture as
    /// `readonly` above (D-038). This field stays genuinely optional for
    /// local dev; the fallback above just isn't reachable in production
    /// without an explicit `APP_ENV=debug` opt-out anymore.
    #[serde(default)]
    pub migrator: Option<MigratorDbCredentials>,
    /// P-db-privilege-separation / D-117 — DML-only identity for ordinary
    /// request-time record CRUD (`attome_db::create_pool`, the pool
    /// `AppState.db`/entity_crud.rs uses). Same shape as `readonly`/
    /// `migrator`. `None` (the default) falls back to `user`/`password` —
    /// today's behavior, unchanged. This is a separate optional field, not a
    /// repurposing of `user`/`password` themselves, specifically so
    /// `user`/`password` can stay the schema-bootstrap identity
    /// (`direct_database_url()`, needs DDL/`CREATE ROLE` for migrations like
    /// 0042 itself) while this identity is locked down to DML — the two
    /// requirements are incompatible on one shared credential. Set this once
    /// migration 0042's `attome_runtime` role exists and has had a login
    /// password applied (`server::db_role_seed::seed_runtime`).
    ///
    /// Fail-closed follow-up (supersedes D-117's original "additive, not
    /// fail-closed" framing — see DECISIONS.md): `main.rs` now refuses to
    /// boot with this unset outside `APP_ENV=debug`, same posture as
    /// `readonly` above (D-038). This field stays genuinely optional for
    /// local dev; the fallback above just isn't reachable in production
    /// without an explicit `APP_ENV=debug` opt-out anymore.
    #[serde(default)]
    pub runtime: Option<RuntimeDbCredentials>,
    /// P1.12 — a raw `postgres://` URL used ONLY for schema bootstrap +
    /// migrations (`attome_db::create_direct_pool`), bypassing whatever
    /// `host`/`port` above point at. Set this when `host`/`port` point at a
    /// transaction-mode pgbouncer, since `sqlx::migrate!`'s internal
    /// session-level advisory lock is unsafe under transaction pooling.
    /// `None` (the default — no pgbouncer in front of this deployment) falls
    /// back to `database_url()`, i.e. identical to today's behavior. Stays
    /// on `user`/`password` even when `migrator` above is configured — see
    /// `AppConfig::direct_database_url`'s doc comment (P-db-privilege-
    /// separation) for why.
    #[serde(default)]
    pub direct_url: Option<String>,
    /// P1.12 — TTL (seconds) of the Redis "just wrote" pin
    /// (`attome-db:rw-pin:{user_id}`) that `AppState::read_pool` checks before
    /// routing a read to `readonly` instead of the primary. Widen this if a
    /// deployment's replica routinely lags past the default window.
    #[serde(default = "default_sticky_primary_ttl_secs")]
    pub sticky_primary_ttl_secs: u64,
    /// P-datastore-tls — one of Postgres's six `sslmode` values: "disable",
    /// "allow", "prefer" (the default — matches sqlx's own default, so
    /// unset is byte-for-byte identical to pre-TLS behavior), "require",
    /// "verify-ca", "verify-full". Validated against this fixed set at boot
    /// (`AppConfig::validate`, D-038) — `attome-db` parses the validated
    /// string into `sqlx::postgres::PgSslMode`, kept out of this crate to
    /// avoid a `sqlx` dependency here (attome-config stays DB-agnostic).
    #[serde(default = "default_ssl_mode")]
    pub ssl_mode: String,
    /// P-datastore-tls — path to a CA certificate file (PEM) used by
    /// "verify-ca"/"verify-full" modes. Deployment-provided (D-002: one
    /// customer, one set of certs) — no CA machinery lives in this platform.
    #[serde(default)]
    pub ssl_root_cert: Option<String>,
    /// P1.12 — disables sqlx's client-side prepared-statement cache. Found
    /// necessary while actually load-testing the pgbouncer recipe (P1.8d
    /// step 5, 2026-07-21, D-106): a transaction-mode pgbouncer without
    /// protocol-level prepared-statement support (added in pgbouncer 1.21)
    /// can hand a client's logical connection a different real backend
    /// between transactions, so a statement sqlx cached as prepared on one
    /// backend does not exist on the next — surfacing as `prepared
    /// statement "sqlx_s_N" already exists` or "does not exist" under real
    /// concurrent load. D-171: `pgbouncer/Dockerfile` (this platform's
    /// reference recipe) moved off the Debian bookworm apt package (1.18)
    /// onto a maintained >=1.21 image, so this flag is no longer needed for
    /// that recipe by default — it remains a general escape hatch for any
    /// deployment fronted by a pre-1.21 pooler. Set this `true` whenever
    /// `database.host`/`port` point at such a pooler; `false` (the default —
    /// no behavior change for a direct-to-Postgres deployment) keeps the
    /// cache on.
    #[serde(default)]
    pub disable_statement_cache: bool,
    /// P-ha-failover-hardening item (e), D-125 — consumed by
    /// `AppState::route_if_lag_ok` (P-read-your-writes-lsn) as an
    /// unconditional circuit breaker: whenever
    /// `replica_watermark::ReplicaWatermark.lag_seconds` (the always-on
    /// poller's cached value, `AppState.replica_watermark`) exceeds this
    /// threshold, every routed read falls back to the primary regardless of
    /// any specific user's pin. Also widens `pin_write_with_lsn`'s effective
    /// TTL to `max(sticky_primary_ttl_secs, replica_max_lag_secs)` so the
    /// pin never expires before this policy's own declared lag tolerance
    /// (`P-read-your-writes-lsn.md` §4(6)). `None` (the default) means "no
    /// max-lag policy configured" — today's behavior, unchanged: no circuit
    /// breaker, and the TTL formula reduces to `sticky_primary_ttl_secs`
    /// alone.
    #[serde(default)]
    pub replica_max_lag_secs: Option<u64>,
    /// P-db-privilege-separation follow-up (§1's "move migrations to a
    /// one-shot deployment job"). `true` (the default — today's behavior,
    /// unchanged) keeps `main.rs`'s inline `ensure_schema`, `run_migrations`,
    /// and role-password-seed sequence on every server boot, same as before
    /// this flag existed. Set `false` once a deployment's release process
    /// runs the dedicated `migrate` binary (`crates/server/src/bin/migrate.rs`,
    /// same `direct_database_url()` bootstrap identity, same migration set)
    /// as its own one-shot step ahead of starting/rolling any `server`
    /// process — the point being that the long-lived web process no longer
    /// needs to hold `CREATE ROLE`/DDL-capable bootstrap credentials at all
    /// once its deploy pipeline guarantees migrations already ran. `server`
    /// does not verify the schema is current when this is `false`; an
    /// operator who flips it without wiring the `migrate` step first will see
    /// ordinary runtime queries fail against a stale schema, not a boot error.
    #[serde(default = "default_true")]
    pub migrate_on_boot: bool,
}

/// Hand-rolled: `password` (and, transitively, `readonly`/`migrator`/
/// `runtime`'s own passwords via their `Debug` impls below) is live database
/// credential material — the derived `Debug` would print it raw.
impl std::fmt::Debug for DatabaseSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseSection")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("dbname", &self.dbname)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("schema", &self.schema)
            .field("connection_number", &self.connection_number)
            .field("timeout", &self.timeout)
            .field("pools", &self.pools)
            .field("statement_classes", &self.statement_classes)
            .field("node_count", &self.node_count)
            .field("max_server_connections", &self.max_server_connections)
            .field("readonly", &self.readonly)
            .field("migrator", &self.migrator)
            .field("runtime", &self.runtime)
            .field(
                "direct_url",
                &self.direct_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("sticky_primary_ttl_secs", &self.sticky_primary_ttl_secs)
            .field("ssl_mode", &self.ssl_mode)
            .field("ssl_root_cert", &self.ssl_root_cert)
            .field("disable_statement_cache", &self.disable_statement_cache)
            .field("replica_max_lag_secs", &self.replica_max_lag_secs)
            .field("migrate_on_boot", &self.migrate_on_boot)
            .finish()
    }
}

impl DatabaseSection {
    /// Z2-T6: whether reads may go to a replica: the read-only role points at
    /// its own endpoint (`database.readonly.host` or `.port`, D-155). Without
    /// one the read-only pool is the primary, so read-your-writes pinning has
    /// nothing to protect and is skipped (one server pays nothing for it).
    pub fn has_read_replica(&self) -> bool {
        self.readonly
            .as_ref()
            .is_some_and(|r| r.host.is_some() || r.port.is_some())
    }
}

/// attome-db hardening Phase 2.3 — `database.pools`: optional per-pool sizes.
/// A pool with no entry is sized from `DatabaseSection::connection_number`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct DatabasePools {
    #[serde(default)]
    pub runtime: Option<DatabasePoolSize>,
    #[serde(default)]
    pub readonly: Option<DatabasePoolSize>,
    #[serde(default)]
    pub readonly_primary: Option<DatabasePoolSize>,
    #[serde(default)]
    pub migrator: Option<DatabasePoolSize>,
    /// AB6-T6: the long pool reports and exports read through (the
    /// `attome_readonly` role on the primary), so they never take a
    /// connection an interactive request needs.
    #[serde(default)]
    pub long: Option<DatabasePoolSize>,
}

/// Z2-T5: `database.statement_classes`, one optional override per class.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatementClassOverrides {
    #[serde(default)]
    pub fast: Option<StatementClassTimeouts>,
    #[serde(default)]
    pub standard: Option<StatementClassTimeouts>,
    #[serde(default)]
    pub report: Option<StatementClassTimeouts>,
    #[serde(default)]
    pub admin: Option<StatementClassTimeouts>,
}

/// Z2-T5: one statement class's timeouts in milliseconds; each must be
/// above 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatementClassTimeouts {
    pub statement_timeout_ms: u64,
    pub lock_timeout_ms: u64,
    pub idle_in_transaction_timeout_ms: u64,
}

/// One pool's size override; `max_connections` is validated to `1..=1000`.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct DatabasePoolSize {
    pub max_connections: u32,
}

fn default_db_connection_number() -> u32 {
    10
}

fn default_node_count() -> u32 {
    1
}

fn default_db_timeout() -> f64 {
    5.0
}

fn default_ssl_mode() -> String {
    "prefer".into()
}

fn default_sticky_primary_ttl_secs() -> u64 {
    5
}

#[derive(Clone, Deserialize)]
pub struct ReadonlyDbCredentials {
    pub user: String,
    pub password: Secret,
    /// P-ha-failover-hardening follow-up / D-155 — closes the gap D-125
    /// flagged ("`ReadonlyDbCredentials` only overrides user/password, there
    /// is no host/port override for the readonly role"): lets the readonly
    /// pool point at a genuinely different endpoint than
    /// `database.host`/`.port` — e.g. a Patroni HAProxy replica-routing
    /// listener (`deploy/ha/haproxy.cfg`'s `postgres_replicas`, port 5433)
    /// or a pgbouncer `attome_ro` alias on its own port. `None` (the
    /// default) falls back to `database.host` — today's behavior, unchanged.
    /// Unlike `readonly` itself (required outside debug, D-038), leaving
    /// this unset is never a boot error: a deployment sharing one endpoint
    /// for both roles (today's default topology) is still fully supported.
    #[serde(default)]
    pub host: Option<String>,
    /// See `host` above — same override, for the port. `None` falls back to
    /// `database.port`.
    #[serde(default)]
    pub port: Option<u16>,
}

/// Hand-rolled: `password` is a live database credential — the derived
/// `Debug` would print it raw.
impl std::fmt::Debug for ReadonlyDbCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadonlyDbCredentials")
            .field("user", &self.user)
            .field("password", &"[REDACTED]")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish()
    }
}

/// P-db-privilege-separation / D-117 — same shape as `ReadonlyDbCredentials`,
/// for the DDL-capable `attome_migrator` role.
#[derive(Clone, Deserialize)]
pub struct MigratorDbCredentials {
    pub user: String,
    pub password: Secret,
}

/// Hand-rolled: `password` is a live database credential — the derived
/// `Debug` would print it raw.
impl std::fmt::Debug for MigratorDbCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigratorDbCredentials")
            .field("user", &self.user)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// P-db-privilege-separation / D-117 — same shape as `ReadonlyDbCredentials`,
/// for the DML-only `attome_runtime` role.
#[derive(Clone, Deserialize)]
pub struct RuntimeDbCredentials {
    pub user: String,
    pub password: Secret,
}

/// Hand-rolled: `password` is a live database credential — the derived
/// `Debug` would print it raw.
impl std::fmt::Debug for RuntimeDbCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeDbCredentials")
            .field("user", &self.user)
            .field("password", &"[REDACTED]")
            .finish()
    }
}
