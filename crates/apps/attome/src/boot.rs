//! P-worker-process-split — the boot sequence every long-lived process needs
//! regardless of whether it serves HTTP, processes jobs, or (today's default)
//! both: schema/migration gating, the privilege-separated pool checks,
//! infrastructure clients (db/redis/storage/jobs), and the full `EngineSystem`
//! build (seeds, license load, metadata registry pre-warm, pub/sub
//! subscriptions). `main.rs` (HTTP, plus the inline job worker when
//! `jobs.run_worker_inline` is true) and `bin/worker.rs` (job worker only, in
//! a split deployment) both call [`init`] so this security- and
//! correctness-sensitive sequence can never drift out of sync between the two
//! binaries — see `jobs.run_worker_inline`'s config doc for the deployment
//! shape this exists for.
//!
//! Deliberately does NOT include: anything HTTP-specific (router, auth
//! routes, the metrics HTTP listener, the profiler layer) or job-worker-
//! specific (the `Monitor`, the partition/upload-session maintenance
//! schedulers) — callers that need those build them from the returned
//! [`Boot`]'s `system.state()`.
//!
//! # Loading profile (`boot.*` probes)
//!
//! [`init`] wraps this sequence in a `attome-profiler` scope, so each loading
//! phase below records under a `boot.*` name (`boot.migrations`,
//! `boot.system_build`, …) and flushes once, when
//! `observability.profiler_enabled` is set, to the general Redis pool (never
//! the fail-closed coordination one, BPR-16) — the same store
//! `GET /api/v1/admin/profiler/stats` reads. Without this the
//! profiler measured only live HTTP requests, because `record` is a silent
//! no-op outside a request scope and boot is exactly that.
use attome_api::EngineSystem;
use attome_config::{AppConfig, CaptchaProvider};
use attome_core::EngineState;
use attome_server::AppState;

// D-792 lock 2 (FLEET-CONSOLE-DESIGN.md §2.1): the fleet console exists only
// in the developer's debug server. Even with `--features fleet-console`, a
// release build of this crate (every binary: server, worker, migrate, …) does
// not compile, so no customer image can carry the console's code.
#[cfg(all(feature = "fleet-console", not(debug_assertions)))]
compile_error!(
    "the `fleet-console` feature is for the developer's debug build only (D-792); build without it for release"
);

// Path is relative to this crate's Cargo.toml (crates/server) — sqlx::migrate!
// resolves at compile time against the crate root, not the source file (see
// attome_db::run_migrations for why the macro can't be called from attome-db
// itself). The one copy in the crate: `main.rs --bootstrap-admin` and
// `bin/migrate.rs` reach it through [`apply_schema_migrations`].
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

// P-migration-immutability follow-up (D-127): nothing else consults
// `checksums.sha256` (no repo check script since D-768), and sqlx's own
// runtime checksum tracking only
// catches tampering on a database that already applied that migration
// version, which a fresh per-customer database (D-002) never has. Embedding
// the baseline text here and checking it in `init` below (before any
// migration is applied) closes that gap with a boot-time, DB-independent
// check — see `attome_db::verify_migration_checksums`'s doc comment.
static MIGRATION_CHECKSUM_BASELINE: &str = include_str!("../migrations/checksums.sha256");

/// Z1-T7: writes this start's `config_start` row on a short-lived pool.
async fn record_config_start(config: &AppConfig) {
    let node = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_owned());
    let recorded = async {
        let db = attome_db::create_pool(config)
            .await
            .map_err(attome_types::AppError::internal)?;
        let result = attome_compliance::config_starts::record_start(
            &db,
            &node,
            env!("CARGO_PKG_VERSION"),
            &config.fingerprint(),
            config.fingerprint_view(),
        )
        .await;
        db.close().await;
        result
    }
    .await;
    match recorded {
        Ok(_) => {
            tracing::info!(fingerprint = %config.fingerprint(), "configuration fingerprint recorded")
        }
        Err(error) => tracing::warn!(
            event = "config.fingerprint.record_failed",
            %error,
            "could not record this start's configuration fingerprint; continuing"
        ),
    }
}

/// The migration sequence shared by every entry point that applies schema:
/// [`init`] (when `database.migrate_on_boot`), `server --bootstrap-admin`
/// and the one-shot `migrate` binary (CLEANUP-REVIEW 1.5 — it used to be
/// hand-copied into all three).
///
/// 1. D-127: verify the embedded `checksums.sha256` baseline against the
///    compiled migrations, before opening any database connection — a
///    tampered frozen migration fails immediately, not after authenticating.
/// 2. P1.12: open a direct pool (never a transaction-mode pgbouncer —
///    `sqlx::migrate!`'s session-level advisory lock is unsafe under
///    transaction pooling).
/// 3. `ensure_schema`, then `run_migrations`.
///
/// Returns the direct pool so the caller can run its own bootstrap-identity
/// follow-up (role seeds, first-admin grant) on it; the caller closes it.
pub async fn apply_schema_migrations(
    config: &AppConfig,
) -> Result<sqlx::PgPool, Box<dyn std::error::Error>> {
    attome_db::verify_migration_checksums(&MIGRATOR, MIGRATION_CHECKSUM_BASELINE)?;
    tracing::info!("migration checksum baseline verified");
    let migration_db = attome_db::create_direct_pool(config).await?;
    // Z2-T1: migrations run only as the bootstrap role, on the configured
    // database — the `migrate` binary and a migrate-on-boot node alike.
    let ids = expected_identities(config);
    attome_db::verify_pool_identity(&migration_db, ids.direct, ids.dbname).await?;
    attome_db::ensure_schema(&migration_db, config).await?;
    tracing::info!("schema ensured");
    attome_db::run_migrations(&migration_db, &MIGRATOR).await?;
    tracing::info!("migrations applied");
    Ok(migration_db)
}

/// The fully-built `EngineSystem` (license loaded, metadata registry
/// pre-warmed, pub/sub subscriptions live) — `system.state()` gives an
/// `EngineState` (for a job worker's `Data<EngineState>`), `system.state().base`
/// gives the `AppState` (`db`/`db_migrator`/`jobs`/`config`/…) either caller
/// needs, and only `main.rs`'s HTTP path calls `system.core_routes()`
/// (consumes `self` — clone what you need from `state()` first).
pub struct Boot {
    pub system: EngineSystem,
    /// The typed queue handles the worker registers its `WorkerBuilder`s on
    /// (V2-D482: `AppState` holds none; producers enqueue through the pool).
    pub jobs: attome_jobs::Jobs<attome_core::jobs::EngineJob>,
    /// D-792 — the fleet console's gate for this process: `true` only in a
    /// `fleet-console` build with every lock holding ([`fleet_console_gate`]).
    pub fleet_console_open: bool,
}

impl std::fmt::Debug for Boot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Boot").finish_non_exhaustive()
    }
}

/// D-792 — the variable that requests the fleet console
/// (`attome_fleet::gate::ENV_VAR`; restated here because a build without the
/// feature cannot name that crate).
pub const FLEET_CONSOLE_ENV_VAR: &str = "ATTOME_FLEET_CONSOLE";

/// D-792 §2.3 row 5 — the variable set on a binary built without the console:
/// a warning, never a boot error (a customer server must not fail to boot
/// because of a stray variable). `None` when there is nothing to say.
pub fn fleet_console_unavailable_warning(console_var: Option<&str>) -> Option<&'static str> {
    (console_var == Some("1"))
        .then_some("ATTOME_FLEET_CONSOLE is set but this binary has no fleet console")
}

/// D-792 — the fleet console's gate, decided once at boot (design §2.3): one
/// boot-log line for the result, and a half-open gate refuses boot.
#[cfg(feature = "fleet-console")]
pub fn fleet_console_gate(config: &AppConfig) -> Result<bool, String> {
    match attome_fleet::gate::open(config) {
        Ok(attome_fleet::Gate::Open) => {
            tracing::info!(
                event = "fleet_console.gate",
                "fleet console: open (D-792) — /api/v1/fleet/** on loopback only, FleetPoll every {} s",
                config.fleet.poll_interval_secs
            );
            Ok(true)
        }
        Ok(attome_fleet::Gate::Off) => {
            tracing::info!(event = "fleet_console.gate", "fleet console: off");
            Ok(false)
        }
        Err(e) => Err(format!("refusing to boot: {e}")),
    }
}

/// D-792 — without the `fleet-console` feature the console is always off;
/// the variable alone only warns.
#[cfg(not(feature = "fleet-console"))]
pub fn fleet_console_gate(_config: &AppConfig) -> Result<bool, String> {
    let value = std::env::var(FLEET_CONSOLE_ENV_VAR).ok();
    if let Some(message) = fleet_console_unavailable_warning(value.as_deref()) {
        tracing::warn!(event = "fleet_console.gate", "{message}");
    }
    Ok(false)
}

/// BCF-10 — report every unknown configuration key `from_file` recorded, one
/// `config.unknown_key` event per path.
///
/// `fail_closed = false` (boot) only warns: an N-1 binary must still boot on
/// an N config during a rollback, and a typo can only fall back to a default
/// that is either safe or refused by the production profile (BCF-D4).
/// `fail_closed = true` (`preflight`) turns any of them into an error, so the
/// typo is caught against a live config before the rolling upgrade rather than
/// discovered later from a feature that silently does nothing.
pub fn report_ignored_config_keys(config: &AppConfig, fail_closed: bool) -> Result<(), String> {
    // BIN-D7: a retired key warns on every binary but never fails preflight.
    for (path, message) in config.deprecated_keys() {
        tracing::warn!(path, "config.deprecated_key: {message}");
    }
    let ignored = config.ignored_keys();
    if ignored.is_empty() {
        return Ok(());
    }
    for path in ignored {
        if fail_closed {
            tracing::error!(path = %path, "config.unknown_key");
        } else {
            tracing::warn!(path = %path, "config.unknown_key");
        }
    }
    if fail_closed {
        return Err(format!(
            "unknown configuration key(s): {} — a key that names nothing is silently ignored; \
             remove it or fix the spelling",
            ignored.join(", ")
        ));
    }
    Ok(())
}

/// BCF-17 — the warning a production node deserves when its portal CAPTCHA
/// provider is `none`. `PortalSection`'s own doc promised this since D-588
/// and nothing emitted it (BCF-F17); boot is the right place, because only
/// the running server knows it is production and which portals it exposes.
fn warn_if_public_portal_without_captcha(config: &AppConfig) {
    // Z8-T6: say once that no email reaches its real recipient.
    if let Some(address) = attome_email::catch_all(&config.email) {
        tracing::warn!(
            catch_all = address,
            "email test mode: every email goes to the catch-all address, not its recipients"
        );
    }
    if let Some(message) = public_portal_without_captcha_warning(config) {
        tracing::warn!("{message}");
    }
}

/// The message `warn_if_public_portal_without_captcha` logs, or `None` when
/// there is nothing to warn about. Split out so a unit test can assert the
/// condition without a recording subscriber.
pub fn public_portal_without_captcha_warning(config: &AppConfig) -> Option<String> {
    (config.app.deployment_profile == "production"
        && config
            .portal
            .captcha
            .effective_provider(config.deployment.sovereign)
            == CaptchaProvider::None)
        .then(|| {
            "portal.captcha.provider = \"none\" in production — any portal that offers \
             self-signup is protected only by provider-side reachability checks; configure \
             turnstile, hcaptcha or pow, or keep signup disabled"
                .to_string()
        })
}

/// The runtime identity a `server`-shaped process expects the pool
/// `attome_db::create_pool` builds to connect as: `database.runtime`'s user
/// when configured, `database.user` otherwise (the `APP_ENV=debug` fallback
/// `init` already gates).
///
/// Exposed for the standalone audit binaries (`audit_chainer`,
/// `verify_audit_chain`), which build a pool without
/// `boot::init` and must still refuse to report a clean audit chain read from
/// the wrong database/role (BDB-F10, OD-6). `migrate` and `preflight` are
/// exempt: they are bootstrap by design.
pub fn expected_runtime_identity(config: &AppConfig) -> (&str, &str) {
    let ids = expected_identities(config);
    (ids.runtime, ids.dbname)
}

/// Z2-T1: the role each connection must arrive as, and the database, which
/// boot, `migrate` and `preflight` all check against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedIdentities<'a> {
    /// Request-time record work (`database.runtime`, else the bootstrap user).
    pub runtime: &'a str,
    /// Schema and entity DDL (`database.migrator`, else the bootstrap user).
    pub migrator: &'a str,
    /// The direct, non-pooled connection migrations run on: the bootstrap user.
    pub direct: &'a str,
    pub dbname: &'a str,
}

/// Z2-T1: the identities `config` expects.
pub fn expected_identities(config: &AppConfig) -> ExpectedIdentities<'_> {
    let bootstrap = config.database.user.as_str();
    ExpectedIdentities {
        runtime: config
            .database
            .runtime
            .as_ref()
            .map_or(bootstrap, |runtime| runtime.user.as_str()),
        migrator: config
            .database
            .migrator
            .as_ref()
            .map_or(bootstrap, |migrator| migrator.user.as_str()),
        direct: bootstrap,
        dbname: config.database.dbname.as_str(),
    }
}

/// Runs the shared boot sequence against an already-loaded, already-
/// validated `config`. Boot errors (missing
/// `database.runtime`/`database.migrator` outside `APP_ENV=debug`, a
/// mismatched `database.readonly` identity, an unreachable Redis/Postgres, a
/// license/metadata pre-warm failure) are all fail-fast — see the inline
/// comments below for why each one is a hard boot error rather than a
/// runtime fallback (D-038: security controls fail closed).
///
/// Wraps [`init_inner`] in a `attome-profiler` scope and, when
/// `observability.profiler_enabled` is set, queues the collected `boot.*`
/// loading-phase probes once on the process-wide `Flusher` over the general
/// Redis pool — the same store `GET /api/v1/admin/profiler/stats` reads. The
/// write is detached and fail-open, so it never delays or fails a boot; same
/// posture as `attome-server`'s per-request profiler middleware.
/// Where packs live: `app.packs_root`, else `packs` next to the executable.
fn packs_root(config: &AppConfig) -> std::path::PathBuf {
    match &config.app.packs_root {
        Some(dir) => std::path::PathBuf::from(dir),
        None => std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("packs")))
            .unwrap_or_else(|| std::path::PathBuf::from("packs")),
    }
}

/// Applies every configured pack's changesets in file order.
async fn apply_configured_packs(
    state: &attome_core::EngineState,
    config: &AppConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.app.packs.is_empty() {
        return Ok(());
    }
    let root = packs_root(config);
    for pack in &config.app.packs {
        if !pack
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!("pack name {pack:?} is not a plain name").into());
        }
        let dir = root.join(pack).join("changesets");
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .map_err(|e| format!("pack {pack}: cannot read {}: {e}", dir.display()))?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect();
        files.sort();
        for file in files {
            let text = std::fs::read_to_string(&file)
                .map_err(|e| format!("pack {pack}: cannot read {}: {e}", file.display()))?;
            let value: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| format!("pack {pack}: {} is not JSON: {e}", file.display()))?;
            attome_api::changeset::boot::apply_pack_document(state, &value).await?;
        }
        tracing::info!(pack, "pack applied");
    }
    Ok(())
}

pub async fn init(config: &AppConfig) -> Result<Boot, Box<dyn std::error::Error>> {
    warn_if_public_portal_without_captcha(config);
    // D-792 — decided before anything else boots, so a half-open fleet
    // console gate refuses boot before any connection is opened.
    let fleet_console_open = fleet_console_gate(config)?;
    // BAU-15a: before the first hash, verify or policy check fixes the KDF
    // settings (and sizes the executor) for the process.
    if !attome_auth::password::configure((&config.auth.kdf).into()) {
        tracing::warn!("auth.kdf: KDF settings were already fixed before boot; config not applied");
    }
    // Q7-T1: a configured breached-password file that cannot be read stops
    // boot rather than leave the check weaker than the operator asked for.
    if let Some(path) = config.auth.breach_list_file.as_deref() {
        let count = attome_auth::password_policy::load_file(std::path::Path::new(path))
            .map_err(|e| format!("auth.breach_list_file ({path}): {e}"))?;
        tracing::info!(count, "breached password set loaded");
    }
    // Z4-T9: the online range check, only when the customer turned it on.
    if config.auth.breach_check_online {
        let url = config
            .auth
            .breach_range_url
            .as_deref()
            .unwrap_or(attome_auth::password_policy::DEFAULT_RANGE_URL);
        attome_auth::password_policy::configure_online(Some(url));
        tracing::info!(url, "breached password online check on");
    } else {
        attome_auth::password_policy::configure_online(None);
    }
    // BPR-32 (BPR-F7): the profiler's posture was invisible at runtime; one
    // line per boot names it, next to the `profiler_enabled` gauge.
    tracing::info!(
        event = "profiler.posture",
        profiler_enabled = config.observability.profiler_enabled,
        deployment_profile = %config.app.deployment_profile,
        "request/boot profiler is {}",
        if config.observability.profiler_enabled { "enabled" } else { "disabled" }
    );
    let started = std::time::Instant::now();
    let (result, probes) = attome_profiler::scope(init_inner(config)).await;
    let result = result.map(|boot| Boot {
        fleet_console_open,
        ..boot
    });

    if config.observability.profiler_enabled
        && let Ok(boot) = &result
    {
        attome_profiler::Flusher::shared(&boot.system.state().base.redis).try_send(
            "boot",
            started.elapsed(),
            probes,
        );
    }

    result
}

/// The boot sequence proper: the loading phases [`init`]'s profiler wrapper
/// records. Every `attome_profiler::record` below is a silent no-op unless a
/// scope is active, so these calls cost nothing outside `init`.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
async fn init_inner(config: &AppConfig) -> Result<Boot, Box<dyn std::error::Error>> {
    // Multiple TLS consumers enable different rustls backends in the unified
    // dependency graph. rustls deliberately refuses to guess when both are
    // present, so select one before Redis/S3/SMTP constructs a TLS client.
    // A prior caller may already have installed the same process-wide value.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // ENTERPRISE-AUDIT-2026-07-24 finding #6 follow-up: `idempotency.
    // mandatory_operations` and `approval.required_actions` are free-form
    // `Vec<String>` config that neither `AppConfig::validate()` nor either
    // gate's own middleware can check against a real route/dispatch table —
    // `attome-config` has zero xrm-* knowledge (guidelines §1) and the gates
    // themselves only ever look for a match, never reject an unmatched
    // entry. A misspelled action/operation name used to silently never gate
    // anything while an operator believed it was active. This crate is the
    // first point in the boot sequence that depends on both `attome-config`
    // and `attome-api`, so it's where the two lists get checked against
    // their real known-value registries, before anything else boots.
    //
    // D-327 (external-feedback item #12): the same function also now fails
    // boot closed when `app.deployment_profile = "production"` and
    // `idempotency.mandatory_operations` doesn't list every entry of
    // `attome_records::bulk::MANDATORY_TIER_OPERATIONS` — an empty (or partial)
    // mandatory list is exactly as dangerous in production as a misspelled
    // one, since either way a critical operation ends up unprotected by the
    // durable idempotency tier with no boot-time signal.
    let t_validate = std::time::Instant::now();
    validate_operation_registries(config)?;
    warn_if_knowledge_article_entity_diverges(config);
    attome_profiler::record("boot.registry_validation", t_validate.elapsed());

    // P-environment-promotion Phase 0: authoring is a pure function of the
    // profile (`attome_server::middleware::authoring_gate`), so name the active
    // mode once here where the profile has just been validated.
    if config.app.deployment_profile == "production" {
        tracing::info!(
            "metadata authoring: locked (production profile; promote a bundle, or open an \
             approved break-glass window)"
        );
    } else {
        tracing::info!("metadata authoring: enabled (development profile)");
    }

    // P-db-privilege-separation follow-up (§1's "move migrations to a
    // one-shot deployment job"): `database.migrate_on_boot` (default true,
    // today's behavior unchanged) gates the entire schema-bootstrap +
    // migrations + role-password-seed + pepper-registry sequence below. A
    // deployment that has moved this to its own deploy-time step (the
    // `migrate` bin, `crates/server/src/bin/migrate.rs` — same sequence,
    // same bootstrap identity) sets this `false` so no long-lived process
    // ever needs to hold DDL-capable/`CREATE ROLE` bootstrap credentials at
    // all.
    let t_migrations = std::time::Instant::now();
    if config.database.migrate_on_boot {
        // D-127 checksum baseline, direct (non-pgbouncer) pool, schema +
        // migrations — see `apply_schema_migrations`. The pool is closed
        // right after the role seeds below.
        let migration_db = apply_schema_migrations(config).await?;
        // P-db-privilege-separation / D-117: role-password seeds run on the
        // bootstrap connection (must, per AppConfig::direct_database_url's doc
        // comment — neither attome_migrator nor attome_runtime can grant
        // itself a login password before it has one); no-ops when the
        // respective database.migrator/database.runtime block isn't
        // configured. Serialized against a concurrent `migrate`/boot on the
        // same database — see role_seed_lock's module doc for why that
        // matters (concurrent `ALTER ROLE` genuinely errors, not just waits).
        crate::role_seed_lock::seed_roles_and_pepper_registry(&migration_db, config).await?;
        migration_db.close().await;
    } else {
        tracing::info!(
            "database.migrate_on_boot is false — skipping schema bootstrap/migrations/role-seed; \
             assuming the `migrate` binary already ran them as a deploy-time step"
        );
    }
    attome_profiler::record("boot.migrations", t_migrations.elapsed());

    // Z1-T7: this start and its configuration fingerprint. A failure is
    // logged and boot goes on: the record is for operators, not a gate.
    record_config_start(config).await;

    // P-db-privilege-separation follow-up (supersedes D-117's "additive, not
    // fail-closed" stance — see DECISIONS.md, same posture change D-038
    // already applies to database.readonly below): a prod node must not
    // silently run ordinary request-time record CRUD on the FULL-PRIVILEGE
    // bootstrap identity just because database.runtime was never set.
    if config.database.runtime.is_none() {
        if attome_config::is_debug_env() {
            tracing::warn!(
                "database.runtime not configured — ordinary request-time record CRUD is \
                 running on the FULL-PRIVILEGE bootstrap identity (tolerated only because \
                 APP_ENV=debug)."
            );
        } else {
            return Err(
                "database.runtime is not configured — refusing to run ordinary \
                 request-time record CRUD on the FULL-PRIVILEGE bootstrap identity. Create the \
                 attome_runtime role (migrations/0042_migrator_runtime_roles.sql), set \
                 database.runtime in the config, or use APP_ENV=debug for local dev."
                    .into(),
            );
        }
    }
    let t_pool_runtime = std::time::Instant::now();
    let db = attome_db::create_pool(config).await?;
    tracing::info!("postgres pool connected");
    // P-db-privilege-separation follow-up: the `database.runtime.is_none()`
    // check above only confirms config *declares* the split identity — this
    // confirms the pool that actually got built connects as it. Catches a
    // stale/privileged DATABASE_URL (attome_db::create_pool only honors it
    // under APP_ENV=debug, but this is the independent second layer) as well
    // as a database.runtime credential typo that still parses. Runs
    // unconditionally, including in the APP_ENV=debug fallback, where
    // expected_runtime_user trivially matches the bootstrap role.
    let (expected_runtime_user, expected_dbname) = expected_runtime_identity(config);
    attome_db::verify_pool_identity(&db, expected_runtime_user, expected_dbname).await?;
    // D-612 item 4: the check above covers the runtime *pool*, not the path
    // `attome_workflow::scheduler`'s execution claim and `jobs::rewrap_secrets`
    // actually use — `create_runtime_session` opens an unpooled session on the
    // `database.direct_url` endpoint as `database.runtime`. Verify that path at
    // boot too, so a direct endpoint that refuses the runtime role (pg_hba,
    // HAProxy) fails here instead of at the first workflow delivery.
    let mut runtime_session = attome_db::create_runtime_session(config).await?;
    let runtime_session_identity = attome_db::verify_connection_identity(
        &mut runtime_session,
        expected_runtime_user,
        &config.database.dbname,
    )
    .await;
    let _ = sqlx::Connection::close(runtime_session).await;
    runtime_session_identity?;
    attome_profiler::record("boot.pool_runtime", t_pool_runtime.elapsed());

    // P-db-privilege-separation / D-117: built only now, after the migrator
    // role-seed above has had a chance to apply attome_migrator's login
    // password — see attome_db::create_migrator_pool's doc comment. Falls back
    // to the same identity as `db` when database.migrator isn't configured.
    //
    // Same fail-closed posture change as database.runtime immediately above:
    // a prod node must not silently run schema/entity DDL on the
    // FULL-PRIVILEGE bootstrap identity just because database.migrator was
    // never set.
    if config.database.migrator.is_none() {
        if attome_config::is_debug_env() {
            tracing::warn!(
                "database.migrator not configured — runtime entity/attribute schema \
                 provisioning is running on the FULL-PRIVILEGE bootstrap identity (tolerated \
                 only because APP_ENV=debug)."
            );
        } else {
            return Err(
                "database.migrator is not configured — refusing to run runtime \
                 entity/attribute schema provisioning on the FULL-PRIVILEGE bootstrap identity. \
                 Create the attome_migrator role (migrations/0042_migrator_runtime_roles.sql), \
                 set database.migrator in the config, or use APP_ENV=debug for local dev."
                    .into(),
            );
        }
    }
    let t_pool_migrator = std::time::Instant::now();
    let db_migrator = attome_db::create_migrator_pool(config).await?;
    // Same identity check as the runtime pool above, for the DDL-capable
    // migrator identity. Under APP_ENV=debug create_migrator_pool takes its
    // endpoint (host/port/database) from DATABASE_URL (M01 C-33), but keeps
    // database.migrator's credentials when that block is set, so the user
    // checked here is the configured one either way; the dbname check catches
    // an override naming a different database than config. The mismatch case (silently running schema/entity DDL as the
    // full-privilege bootstrap role) is exactly what D-148's boot-error gate
    // above exists to prevent, and that gate only checks config presence.
    let expected_migrator_user = expected_identities(config).migrator;
    attome_db::verify_pool_identity(
        &db_migrator,
        expected_migrator_user,
        &config.database.dbname,
    )
    .await?;
    // D-497: the check above covers the migrator *pool*, not the path
    // `attome-metadata::provision::sync_attribute_index` actually uses —
    // `create_migrator_connection` opens an unpooled session on the
    // `database.direct_url` endpoint (so its session advisory lock survives a
    // transaction-mode pgbouncer). Verify that path at boot too, so a wrong
    // direct_url, or a direct endpoint that refuses the migrator role, fails
    // here instead of at the first attribute index build.
    let mut migrator_connection = attome_db::create_migrator_connection(config).await?;
    let migrator_connection_identity = attome_db::verify_connection_identity(
        &mut migrator_connection,
        expected_migrator_user,
        &config.database.dbname,
    )
    .await;
    let _ = sqlx::Connection::close(migrator_connection).await;
    migrator_connection_identity?;

    attome_profiler::record("boot.pool_migrator", t_pool_migrator.elapsed());

    // P1.1e: a dedicated SELECT-only pool for /api/v1/query/execute. Missing
    // config is a BOOT ERROR outside debug (D-038 — security controls fail
    // closed): a prod node must never quietly run stored queries on the
    // full-privilege role. Only APP_ENV=debug keeps the warn+fallback, for
    // local dev without the attome_readonly role.
    let t_pool_readonly = std::time::Instant::now();
    let db_readonly = match attome_db::create_readonly_pool(config).await? {
        Some(pool) => {
            // P-ha-failover-hardening follow-up (D-156): D-155 let
            // `database.readonly.host`/`.port` point at a genuinely different
            // endpoint than the primary — this closes the gap that opened,
            // confirming the resolved endpoint is actually the same logical
            // database before any request ever routes a read there. Fails
            // boot unconditionally (not gated on APP_ENV=debug): a mismatched
            // database is a misconfiguration, not a missing-optional-role
            // situation, and D-002's one-customer-one-database model makes
            // silently reading from the wrong database a data-isolation
            // incident, not a staleness bug.
            attome_db::verify_readonly_identity(&pool, &config.database.dbname).await?;
            // Same D-117 role-identity check as the runtime/migrator pools
            // above — verify_readonly_identity only ever checked
            // current_database() (D-156's host/port-typo concern); this adds
            // the current_user half so a database.readonly credential
            // mismatch is caught too, not just a wrong endpoint.
            if let Some(readonly) = &config.database.readonly {
                attome_db::verify_pool_identity(&pool, &readonly.user, &config.database.dbname)
                    .await?;
            }
            pool
        }
        None if attome_config::is_debug_env() => {
            tracing::warn!(
                "database.readonly not configured — /api/v1/query/execute is running on the \
                 FULL-PRIVILEGE pool (tolerated only because APP_ENV=debug)."
            );
            db.clone()
        }
        None => {
            return Err("database.readonly is not configured — refusing to run \
                 /api/v1/query/execute on the FULL-PRIVILEGE pool. Create the attome_readonly \
                 role (migrations/0010_readonly_query_role.sql), set database.readonly in the \
                 config, or use APP_ENV=debug for local dev."
                .into());
        }
    };

    // P-api-consistency-hardening (a) — same attome_readonly role as
    // db_readonly above, pointed at the primary host, so a pinned
    // query/execute caller (AppState::readonly_query_pool) can read fresh
    // data without ever borrowing the full-privilege `db` pool. `None` under
    // the identical condition db_readonly's own `None` arm already handles
    // (database.readonly unconfigured); no separate boot-error gate needed
    // here — readonly_query_pool's own fallback (db_readonly, with a logged
    // warning) covers an unattached pool at request time, and that fallback
    // is already exactly today's pre-fix behavior, not a new failure mode.
    let db_readonly_primary = attome_db::create_readonly_primary_pool(config).await?;
    // Same D-117/D-201 identity check as db_readonly above — this pool uses
    // the identical attome_readonly credentials, just routed at the primary
    // host/port instead of database.readonly.host/.port, so the same
    // credential-mismatch risk applies to it.
    if let (Some(pool), Some(readonly)) = (&db_readonly_primary, &config.database.readonly) {
        attome_db::verify_pool_identity(pool, &readonly.user, &config.database.dbname).await?;
    }
    // AB6-T6 — reports and exports read through their own small pool on the
    // same attome_readonly role, so they never hold an interactive request's
    // connection; same identity check as db_readonly_primary.
    let db_long = attome_db::create_long_pool(config).await?;
    if let (Some(pool), Some(readonly)) = (&db_long, &config.database.readonly) {
        attome_db::verify_pool_identity(pool, &readonly.user, &config.database.dbname).await?;
    }
    attome_profiler::record("boot.pool_readonly", t_pool_readonly.elapsed());
    // Base-db hardening Phase 2.4: one structured `db.pool.capacity` line with
    // how many connections this process's pools may open, per endpoint.
    attome_db::log_pool_capacity(config);

    let t_infrastructure = std::time::Instant::now();
    // `cache.backend` picks Redis or the in-process store. With Redis, P1.15's
    // dedicated coordination pool exists only if `cache.roles.coordination` is
    // set, otherwise it is a clone of the general one.
    let (redis, redis_coordination) = attome_cache::Store::from_config(config).await?;
    warn_if_coordination_store_is_not_durable(config, &redis_coordination).await;
    // Y5-T2: a production deployment claims its cache, and refuses to start
    // when another deployment already has it.
    if config.app.deployment_profile == "production" {
        let id = attome_server::isolation::claim(&db, &redis).await?;
        tracing::info!(deployment = %id, "cache claimed for this deployment");
    }
    let storage = attome_storage::create_storage_client(config).await?;
    // P1.4 / P-job-queue-hardening (D-165): two `job_type` namespaces backed
    // by the checked-in migrations/0014_apalis_jobs.sql +
    // 0060_apalis_job_dedup.sql, not a runtime `PostgresStorage::setup()`
    // call. Every caller of `init` gets its own handle onto the same
    // underlying `apalis.jobs` table; `PlatformJobs` carries the fast/batch
    // pair so `main.rs`/`bin/worker.rs` can each register their own
    // per-queue `WorkerBuilder`/concurrency limit.
    let jobs = attome_jobs::Jobs::<attome_core::jobs::EngineJob>::new(db.clone());
    tracing::info!("infrastructure clients ready");
    attome_profiler::record("boot.infrastructure", t_infrastructure.elapsed());

    // P-migration-governance: derived from the compiled `MIGRATOR` itself
    // (not a hand-maintained constant) so it never drifts from the actual
    // set of migration files this binary was built against -- see
    // `expected_schema_version`'s doc comment on `AppState` for the
    // at-least-not-exact readiness semantics this feeds.
    let expected_schema_version = MIGRATOR
        .migrations
        .iter()
        .map(|m| m.version)
        .max()
        .expect("MIGRATOR must contain at least one migration");

    let base = AppState::new(
        config.clone(),
        db.clone(),
        db_readonly,
        db_migrator.clone(),
        redis,
        redis_coordination,
        storage,
    )
    .with_readonly_primary(db_readonly_primary)
    .with_long_pool(db_long)
    .with_expected_schema_version(Some(expected_schema_version))
    // D-344 — the configured flap threshold. Enforcement itself is set by
    // `spawn_capability_refresh`, which is also the only thing that ever
    // moves a capability off `Unknown`; a process that never spawns it
    // (the `worker` binary, every test) carries this registry inert and
    // gates nothing.
    .with_capabilities(std::sync::Arc::new(
        attome_server::capability::CapabilityRegistry::new(
            config.capability.failure_threshold,
            config.capability.enforcement_enabled,
        ),
    ));

    // P-read-your-writes-lsn Phase 2: unconditional on `database.readonly`
    // alone, in every process — the read-routing decision `AppState::read_pool`
    // makes is defined generically enough (any caller holding an `AppState`
    // could call it) that both the HTTP tier and a split-out worker keep a
    // correct cached watermark rather than only the process that happens to
    // serve HTTP today.
    if config.database.readonly.is_some() {
        // P-read-your-writes-lsn Phase 2 — deliberately tighter than
        // `spawn_replica_lag_refresh`'s 15s dashboard gauge since this cache
        // gates correctness, not just observability. Never varied
        // per-deployment (D-125's own design review picked this once); not a
        // config knob.
        const REPLICA_WATERMARK_POLL_INTERVAL_SECS: u64 = 2;
        attome_server::spawn_watermark_refresh(
            base.clone(),
            std::time::Duration::from_secs(REPLICA_WATERMARK_POLL_INTERVAL_SECS),
        );
        // P-read-your-writes-lsn §8's documented residual gap, made
        // operator-visible rather than silently relying on the default: with
        // no `replica_max_lag_secs` policy, `route_if_lag_ok`'s circuit
        // breaker never trips, so a replica that never catches up before its
        // pin's TTL ceiling still ships stale data once that TTL elapses.
        // Not a boot failure (unlike `readonly`/`migrator`/`runtime` above) —
        // this deployment shape was `read_pool`'s only behavior before this
        // plan shipped, so it stays a warning, not a break-boot regression
        // for every existing config that hasn't opted in yet.
        if config.database.replica_max_lag_secs.is_none() {
            tracing::warn!(
                "database.readonly is configured but database.replica_max_lag_secs is not — \
                 the read-your-writes lag circuit breaker (P-read-your-writes-lsn) is disabled, \
                 and a replica that never catches up will still serve stale reads once a pin's \
                 TTL (database.sticky_primary_ttl_secs) elapses. Set replica_max_lag_secs (e.g. \
                 matching the ReplicaLagHigh alert threshold) to close this gap."
            );
        }
    }

    let mut state = EngineState::new(base);

    // `EngineState::new` seeds `state.modules` with `ModuleSet::core_only()`
    // (zero module bits) — loaded for real here, before this function's own
    // platform-bundle applies immediately below (D-478: each checks
    // `requires.modules` against `state.modules`). D-778: every module,
    // narrowed only by Module Management; no licence is checked.
    let t_license = std::time::Instant::now();
    let license = attome_api::load_license(&state.base.db).await;
    state.modules = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(license));
    attome_profiler::record("boot.license", t_license.elapsed());

    // Every seed from here to the last seed below runs in each process that
    // calls this function — `server` and `worker` alike — so it is serialized
    // across processes (`platform_seed_lock`'s module doc has the failure it
    // prevents). Taken before the watermark prefetch, so a process that waited
    // reads the stamps the other one wrote and skips.
    let platform_seed_lock = crate::platform_seed_lock::PlatformSeedLock::acquire(config).await?;

    // One query for every seed watermark, ahead of the ~55 `run_if_stale` calls
    // a boot makes (52 `apply_platform_bundle` between this function and
    // `EngineSystem::build()`, plus the remaining seeds) — each of which used to
    // spend its own sequential round-trip just to learn nothing had changed.
    // Not fatal on failure: the snapshot stays unpopulated and every caller
    // reads for itself exactly as before.
    if let Err(e) = attome_core::seed_gate::prefetch(&state.base.db).await {
        tracing::warn!(error = %e, "seed watermark prefetch failed — falling back to per-module reads");
    }

    // Registers audit_header/audit_detail/audit_snapshot as
    // provisioned entities — moved ahead of this function's other early
    // platform-bundle applies (workflow/report/docgen/integration/action-*,
    // below), which was its own boot-ordering bug: `attome-api/src/system.rs
    // ::EngineSystem::build()` normally applies `attome-audit`'s bundle, but
    // `.build()` only runs after every seed in *this* function returns, and
    // `attome_records::query_admin::publish_new_query` (reached from the
    // workflow seed's own stored-query steps, D-384's audit trail for
    // publishing a query) writes an audit event via `attome_core::
    // crud::insert(tx, "audit_header", ...)`. That generic insert
    // resolves the entity by logicalname against `entity_info`
    // first (`attome_core::crud::resolve`) and returns a bare
    // `AppError::NotFound` — no message, indistinguishable in the logs from
    // a dozen other bare-NotFound sites — when `audit_header` isn't
    // registered yet, which it never was at this point in boot before this
    // fix. Watermark-gated like every other `apply_platform_bundle` call
    // (D-478), so `EngineSystem::build()`'s own later application of this same
    // bundle is a cheap no-op re-read, not a second real apply.
    let t_bundles_pre_build = std::time::Instant::now();
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-audit").await?;

    // Moved ahead of this function's `record_sets`-carrying bundles for exactly
    // the reason `attome-audit` above was, and it is the same defect twice:
    // `bundle::record_sets` writes its rows through
    // `attome_records::entity_mutation::create_one`, which calls
    // `attome_metadata::autovalue::generate_for_create` on every create, which reads
    // `autovalue` — a metadata-defined entity this very bundle
    // provisions. Five bundles applied below carry `record_sets`
    // (attome-ai-tone-data, xrm-core-authentication-type-data, attome-ai-provider-data,
    // attome-ai-model-catalog-data, attome-ai-agent-data) and every one of them ran
    // before `EngineSystem::build()`, which is where this bundle used to be applied
    // for the first time.
    //
    // On an existing database the table is already there from a previous boot,
    // so nothing ever failed. On an *empty* one — a new customer deployment,
    // D-002 — the first record set died on `relation "autovalue" does
    // not exist`, which is precisely the starting condition
    // `crates/server/tests/fresh_bootstrap.rs` exists to cover.
    //
    // `EngineSystem::build()` still applies this same bundle under the same
    // watermark key, so that later call is now a cheap no-op re-read rather
    // than the first application. (This call used to be made twice back to
    // back; the second was a watermark-gated no-op and was removed, CLEANUP-
    // REVIEW 1.5.)
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-metadata-autovalue")
        .await?;

    // Registers workflow_definition as a browsable XRM entity, so
    // workflows list/edit through the generic metadata-driven pages. Called
    // here rather than alongside the other engine seeds in
    // `EngineSystem::build` because attome-api has no (non-dev) dependency on
    // attome-workflow — the engine is registered from this binary, D-010 style,
    // and its seed follows the same composition point. Must run before
    // `.build()`, whose `entity_privileges::seed_all` mints the per-entity
    // privilege rows for whatever is registered by then. Same schema-adjacent
    // work as every other seed, so `db_migrator` (P-db-privilege-separation
    // / D-117), not the runtime pool.
    // REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478): replaces
    // `attome_workflow::seed::seed`'s imperative calls, proven a pure no-op
    // against the old seed's output by `attome-api/tests/
    // platform_bundle_apply.rs` before this swap.
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-workflow").await?;

    // D-479 (M26 R-09) gutted `platform-bundles/attome-report.json` to
    // `entities: []`, so its boot apply was a permanent no-op and was removed
    // (CLEANUP-REVIEW 1.5). The file stays in the repository; applying an
    // empty bundle never touched an upgraded deployment's legacy `dashboard`
    // table, so dropping the call changes no schema or data.

    // M57 Phase 1 (Document Generation, D-463) — same reasoning as the
    // workflow/report seeds above: `attome-docgen` has a real (non-dev)
    // dependency on `attome-api` (`entity_crud::read_record`/
    // `update_record_for` reuse in its merge-context builder and its
    // attach_to_field write), so `attome-api` cannot hold a dependency back
    // on it, and its `docgen_template` entity is seeded from this binary
    // instead. No lookup attribute onto `user_account` (see
    // `platform-bundles/attome-docgen.json`), so — unlike `attome_report::seed::
    // seed_reports` below — this has no ordering dependency on
    // `attome-security`'s platform bundle and can run before `.build()`.
    // REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478): replaces
    // the former `attome_docgen::seed::seed`'s imperative calls (module since
    // deleted), proven a pure no-op
    // against the old seed's output by `attome-api/tests/
    // platform_bundle_apply.rs` before this swap.
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-docgen").await?;

    // M59 Phase 1 (Integration & Connectors) — same reasoning as the
    // workflow seed above: `attome-integration` depends on `attome-api`
    // (entity-mutation reuse for the inbound-webhook service-principal
    // write, D-425), so `attome-api` cannot hold a real dependency back on
    // it, and its seed runs from this binary rather than from inside
    // `EngineSystem::build()`. Its one entity's lookup-shaped fields carry no
    // `lookup_entity_ref` (see `platform-bundles/attome-integration.json`), so
    // unlike attome-project/attome-service/attome-dashboard it has no ordering
    // dependency on `user_account` being registered first.
    // REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478): replaces
    // `attome_integration::seed::seed`'s imperative calls, proven a pure no-op
    // against the old seed's output by `attome-api/tests/
    // platform_bundle_apply.rs` before this swap.
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-integration").await?;

    // D-435 (M34 AI Governance) — same reasoning as the workflow/report/
    // integration seeds above: `attome-ai` has a real (non-dev) dependency
    // on `attome-api` (`entity_crud::read_record` reuse), so `attome-api`
    // cannot call back into it. The `attome-ai-quality` platform bundle (the
    // stored query feeding the `ai.acceptance_rate` metric; it replaced the
    // deleted `quality_seed` module) has no ordering dependency on
    // `attome-security`'s platform bundle (which only applies later, inside
    // `.build()`) and is seeded here for that reason. D-491 removed the separate
    // `ai_model_approval` registry entity/bundle this comment used to
    // describe — model approval is now `ai_model.approval_status`,
    // directly on the AI Model catalog bundle applied further below
    // (`attome-ai-model-catalog`), so there is no separate approval bundle to
    // apply here any more.
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-ai-quality").await?;
    // `ai_personality`/`ai_tone` apply before `attome-ai-agent` below,
    // whose `entity_a`/`entity_b` relationship references resolve their
    // target entities by logicalname at apply time.
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-ai-personality").await?;
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-ai-tone").await?;
    // Seed rows are a SEPARATE bundle for the same self-reference reason
    // `xrm-core-authentication-type-data` is split from its entity bundle
    // below: a bundle's plan is computed against live metadata as of the
    // start of that one `apply_platform_bundle` call, so `record_sets` for
    // an entity this same bundle also defines always comes back "not live".
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-ai-tone-data").await?;
    // `authentication_type` is core reference data (a reusable
    // Value/Purpose master list, not AI-specific); `ai_provider` no longer
    // references it. Its 8 seed rows are a SEPARATE bundle (`-data`), applied
    // right after: a bundle's
    // plan is computed against live metadata as of the start of that one
    // `apply_platform_bundle` call, so `record_sets` for an entity this same
    // bundle also defines always comes back "not live" — same reason
    // `trd-governance.json`'s `record_sets` target an entity defined
    // elsewhere, never its own file's `entities`.
    attome_api::changeset::boot::apply_platform_definition(&state, "xrm-core-authentication-type")
        .await?;
    attome_api::changeset::boot::apply_platform_definition(
        &state,
        "xrm-core-authentication-type-data",
    )
    .await?;
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-ai-provider").await?;
    // The "Example Provider" scaffold row -- inactive (status: closed),
    // ready for an operator to edit into a real provider or delete outright.
    // `attome-ai-model-catalog-data`/`attome-ai-agent-data` below still chain onto
    // THIS scaffold's rows by `derived_id` literal, which holds because those
    // rows are only ever created by these same bundles.
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-ai-provider-data")
        .await?;
    // AI Model catalog (provider/context-window/per-token-cost metadata for
    // an admin-authored model row — distinct from the old
    // `ai_model_approval` registry D-491 removed, see
    // `model_registry.rs`'s module doc). Applies after `attome-ai-provider` so
    // `provider_ref`'s lookup resolves against an already-live entity; its
    // own `replacement_model_ref` self-lookup resolves fine within this same
    // bundle (the planner's `known_entity` check accepts a target declared
    // anywhere in the SAME bundle, not only an already-live one —
    // `attome-api/src/bundle/plan.rs`'s
    // `new_entity_with_a_lookup_to_an_entity_in_the_bundle`-shaped test).
    // MUST apply before `attome-ai-agent` below: that bundle's
    // `primary_model_ref`/`fallback_model_ref`/`fallback_model_2_ref` lookups
    // target `ai_model` by logicalname too, and would otherwise resolve
    // against whatever (wrong, or absent) entity happened to be live under
    // that name first.
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-ai-model-catalog")
        .await?;
    // The "Example Model" scaffold row -- `approval_status: pending`, so
    // `model_registry::require_approved_model` refuses any action that would
    // try to invoke it. Its `provider_ref` literal chains onto
    // `attome-ai-provider-data`'s "Example Provider" row the same
    // derived-id-precomputed way that bundle's own comment explains.
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-ai-model-catalog-data")
        .await?;
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-ai-agent").await?;
    // C6 (D-556) -- capability packs. A named, versioned set of action ids an
    // `ai_agent_policy` references; the policy entity that carries
    // `capability_pack_refs` is applied just above. Its own entity is
    // API-first like every other metadata entity, and this bundle is how a
    // fresh deployment gets it (D-373/D-374's promotion path carries the same
    // file between deployments).
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-ai-capability-pack")
        .await?;
    // The "Example Agent" scaffold row -- `status: draft`. Its
    // `primary_model_ref` literal chains onto `attome-ai-model-catalog-data`'s
    // "Example Model" row, same derived-id scheme.
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-ai-agent-data").await?;
    // `api_key` (the auth layer's own API-key table, browsable as an
    // XRM entity — see `crates/server/src/auth`). Used to be
    // `crate::apikey_seed::seed(&db_migrator)` right after the migrator pool
    // came up; D-478 (seeds-to-bundles, second pass) moved its content to
    // `platform-bundles/xrm-core-api-key.json`, applied here because
    // `apply_platform_bundle` needs `state`. Same `"api_key"` watermark key
    // the old seed used, so an existing deployment's history carries over.
    // No lookup onto anything provisioned inside `.build()` (`user_ref` is
    // a target-less lookup column), so it has no ordering dependency.
    attome_api::changeset::boot::apply_platform_definition(&state, "api_key").await?;
    attome_profiler::record("boot.bundles_pre_build", t_bundles_pre_build.elapsed());

    // M11 Search gap list (D-366) — `saved_search`'s entity seed. Runs
    // from here, not from `attome-api/src/system.rs::EngineSystem::build()`
    // alongside the other entity-registering seeds, because `attome-api`'s
    // dependency on `attome-search` is dev-only (its Cargo.toml: only
    // `tests/license_gating.rs` mounts a real search model) — this crate has
    // no real compile-time access to `attome_search::`. Same reasoning and same
    // placement as the `attome-ai-quality`/`attome-ai-model-catalog` platform-bundle
    // applies above: `saved_search` carries no lookup attribute onto
    // `user_account` (unlike attome-project/attome-service/attome-dashboard,
    // which is why THEIR seeds run inside `.build()` instead), so running
    // this before `attome-security`'s platform bundle (applied inside `.build()`
    // below) is safe. `entity_privileges::seed_all` (also inside `.build()`)
    // still sweeps this entity correctly, since it runs after — this call
    // just needs to land somewhere before `.build()` finishes, not
    // specifically inside it.
    let t_seeds_pre_build = std::time::Instant::now();
    // D-478 (seeds-to-bundles, second pass): `platform-bundles/
    // attome-search-saved-search.json` replaces `attome_search::saved_search::
    // seed`'s imperative calls, under the same watermark key; proven a pure
    // no-op against the old seed's output by `attome-api/tests/
    // platform_bundle_apply.rs` before the swap.
    attome_api::changeset::boot::apply_platform_definition(&state, "attome-search-saved-search")
        .await?;

    // Dev-only local-access seeds: a known login password and a known API key,
    // so resetting the dev database doesn't lock you out or strand scripts.
    // Both are no-ops unless APP_ENV=debug *and* their own env var is set, and
    // neither exists in a release binary — see `dev_access_seed`'s module doc.
    //
    // Before `.build()`, not after, because the API key seed below needs a
    // user to own the key. `seed_login` only owns the credential — nothing in
    // boot grants it `system.admin` any more (that was
    // `security.bootstrap_admin_email`, retired in favour of
    // `server --bootstrap-admin <email>`, D-128), so a fresh database reaches a
    // usable admin by running that command once, not by restarting.
    #[cfg(debug_assertions)]
    {
        crate::dev_access_seed::seed_login(&state).await?;
        crate::dev_access_seed::seed_api_key(&state).await?;
    }
    attome_profiler::record("boot.seeds_pre_build", t_seeds_pre_build.elapsed());

    let t_system_build = std::time::Instant::now();
    // F4-T13: an issued invoice's PDF (through the docgen render sidecar)
    // and its sending, run by the `BillingAfterIssue` job.
    // AG2-T3: e-invoicing runs first, through ZATCA's API.
    let zatca =
        attome_einvoice::zatca::api::HttpTransport::new(attome_billing::einvoice::ZATCA_TIMEOUT)
            .map_err(|e| e.to_string())?;
    attome_billing::document::register_hooks(
        std::sync::Arc::new(attome_docgen::generate::SidecarRenderer),
        std::sync::Arc::new(zatca),
    );
    // Z12-T5: a person's calendar closes the days HR has them on leave.
    attome_core::calendar::register_absence_source(std::sync::Arc::new(
        attome_hr::leave::LeaveAbsences,
    ));
    let system = register_engines(EngineSystem::builder(state))
        .build()
        .await?;
    attome_profiler::record("boot.system_build", t_system_build.elapsed());
    let t_post_build = std::time::Instant::now();

    // M3.4 (MASTER-PLAN P0 0.5) — MCP `record.*` entity admission is
    // default-deny. `.build()` has just pre-warmed the runtime settings
    // snapshot, so this is the first point `ai.mcp_entity_admission` can be
    // read: warn the operator at boot when nothing is admitted, since every
    // MCP record tool call will then be refused. Log-only; never blocks boot.
    attome_ai::mcp::admission::warn_if_nothing_admitted(system.state());

    // M25 Phase 1 (Report, D-440) — `attome_report`/`report_schedule`
    // register here, *after* `.build()` returns, not with the pre-build
    // bundles above: their
    // `owner`/`run_as` lookups need `user_account`'s
    // `entity_info` row, which only exists once `.build()`'s
    // internal `attome_security::seed::seed` call has run — see
    // `attome_report::seed::seed_reports`'s own doc comment for the
    // fresh-database trap this avoids. (`report_run` is a
    // migration-owned infra table, not provisioned here — see
    // `0240_xrm_report_run.sql`'s header.) Because this also means these two
    // entities register too late for `.build()`'s own
    // `entity_privileges::seed_all` sweep to see them, re-running it here
    // (idempotent — a no-op for every entity it already covered) mints their
    // `attome_report{,_schedule}.{read,create,update,delete,bulk}` rows on this
    // same first boot instead of leaving them missing until a second one.
    //
    // REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478):
    // `platform-bundles/attome-report-reports.json` replaces `attome_report::
    // seed::seed_reports`'s imperative calls -- `owner`/`run_as` reference
    // `user_account` by logical name, resolved by the bundle engine
    // itself, so the same post-`.build()` ordering requirement applies and
    // is preserved by leaving this call here. Proven a pure no-op against
    // the old seed's output by `attome-api/tests/platform_bundle_apply.rs`.
    attome_api::changeset::boot::apply_platform_definition(system.state(), "attome-report-reports")
        .await?;

    // C10 B2b (chatbot plan) — the assistant's analytics as metrics. First
    // the five single-number stored queries over the conversation ledger
    // (`attome-ai-bot-analytics`), then the `dashboard_metric_definition`
    // rows that compute them (`-data`: a bundle cannot seed records for an
    // entity it defines, and this entity only exists once `.build()` has
    // applied `attome-metric`, which is why both run here, post-build). Each
    // metric's `query_ref` is its query's derived id (D-374 amendment), and
    // `chat_api::the_shipped_bot_metrics_equal_the_admin_route` proves every
    // one equals the admin analytics route over the same window.
    attome_api::changeset::boot::apply_platform_definition(
        system.state(),
        "attome-ai-bot-analytics",
    )
    .await?;
    attome_api::changeset::boot::apply_platform_definition(
        system.state(),
        "attome-ai-bot-analytics-data",
    )
    .await?;
    // AI4-T2, AI5-T1, AI6-T1, AK3-T2, W1-T2: the follow-up, collections,
    // meeting, work-share and contract-engine definitions. The follow-up and
    // meeting changesets seed draft `ai_agent` rows, so they run after
    // `attome-ai-agent`; before the second `seed_all` below, which mints
    // their entities' privileges.
    for name in [
        "attome-ai-followup",
        "attome-ai-collections",
        "attome-ai-meeting",
        "attome-ai-work-share",
        "attome-ai-work-share-data",
        "attome-contract",
        // D22-T2: the call-analysis entities.
        "attome-callintel",
        // P9-T1: metric scorecards, commentary, certification, dimensions and
        // cascading targets, on top of `attome-metric` (applied in build()).
        "attome-metric-governance",
        // R12-T1: regulatory changes and the controls they touch.
        "attome-grc-regulatory-change",
        // B16-T7: scan-action bindings (code pattern to action).
        "attome-scan",
        // W1-T3: counterparty match proposals.
        "attome-contract-counterparty",
        // V2-T2: task checklists and recurring tasks.
        "attome-task-checklist",
        // G9-T3: supplier SLA clocks.
        "attome-service-supplier-sla",
        // D18-T1: points models, rules and stored scores.
        "attome-sales-scoring",
    ] {
        attome_api::changeset::boot::apply_platform_definition(system.state(), name).await?;
    }

    // Not a duplicate of `.build()`'s own `seed_all` (CLEANUP-REVIEW 1.5
    // checked): `attome_report{,_schedule}`, the bot-analytics bundles and every
    // entity above register only after `.build()` returns, so this
    // second sweep is what mints their per-entity privileges on a fresh
    // database's first boot.
    attome_security::entity_privileges::seed_all(&system.state().base.db_migrator).await?;
    // D-588 item 4: fill the portal login-email column for credentials
    // created before migration 0489. Idempotent; runs after `.build()`
    // because it reads the runtime-provisioned `webportal_user` table.
    attome_portal::provision::backfill_login_emails(&system.state().base.db_migrator).await?;
    // Same reason as the second `seed_all` above: `attome_report{,_schedule}`,
    // the bot-analytics bundles  register only after
    // `.build()`'s own backfills ran, so a fresh database's first boot left
    // them without their readonly grant, RLS columns and category until the
    // next boot (seen by the Phase 1.5 equivalence test: a second boot moved
    // the metadata). All three are idempotent no-ops once current.
    {
        let db_migrator = &system.state().base.db_migrator;
        attome_metadata::provision::backfill_readonly_grants(db_migrator).await?;
        attome_metadata::provision::backfill_rls_columns(db_migrator).await?;
        attome_metadata::provision::backfill_entity_category(db_migrator).await?;
    }
    // Solution 7 (D-785, design §2.2 step 2): mark every row a platform
    // definition declares `owner_layer = 'platform'` — the compiled platform
    // definitions (inside `stamp_platform_owned`) plus the keys the imperative
    // seeds own (`sidebar_seed.rs`, `attome_project::seed`;
    // `attome_dashboard::seed` adds none). After every platform definition and
    // seed above, still under the platform seed lock; gated by its own seed
    // watermark, so an unchanged boot costs one read.
    {
        let db_migrator = &system.state().base.db_migrator;
        let keys = attome_api::changeset::boot::imperative_seed_keys(db_migrator).await?;
        attome_api::changeset::layers::stamp_platform_owned(db_migrator, &keys).await?;
        // D-788 (amends D-180): required is application-level. Drops any
        // physical NOT NULL the old required path left on a metadata-defined
        // column of a runtime-provisioned table. Runs once per deployment
        // (seed gate), and never touches a table a migration creates or
        // alters: those NOT NULLs are integrity constraints (review H1).
        attome_core::seed_gate::run_if_stale(
            db_migrator,
            "required-not-null-sweep",
            "1",
            || async {
                let migration_tables =
                    attome_metadata::provision::field_change::migration_owned_tables(
                        MIGRATOR.iter().map(|m| m.sql.as_ref()),
                    );
                let dropped = attome_metadata::provision::field_change::drop_required_not_null(
                    db_migrator,
                    &migration_tables,
                )
                .await?;
                if dropped > 0 {
                    tracing::info!(
                        dropped,
                        "D-788: dropped physical NOT NULL constraints of required fields"
                    );
                }
                Ok(())
            },
        )
        .await?;
    }
    // The packs this deployment installed (`attome init --pack`), after the
    // platform's own definitions so their lookups onto platform entities
    // resolve; idempotent through the changeset ledger.
    apply_configured_packs(system.state(), config).await?;
    platform_seed_lock.release().await;
    replay_erasures(system.state(), config).await?;
    enqueue_lookup_index_backfill(system.state()).await;
    attome_profiler::record("boot.post_build", t_post_build.elapsed());

    Ok(Boot {
        system,
        jobs,
        fleet_console_open: false,
    })
}

/// A stop asked for from outside the process's signals: the Windows service
/// control manager's Stop and Shutdown (roadmap U1-T1). It starts the same
/// graceful drain as Ctrl+C or SIGTERM.
static EXTERNAL_STOP: std::sync::LazyLock<tokio::sync::Notify> =
    std::sync::LazyLock::new(tokio::sync::Notify::new);

/// Asks a running `attome serve` in this process to shut down gracefully.
/// Safe to call before the server is listening: the request is kept until
/// [`wait_for_shutdown_signal`] picks it up.
pub fn request_stop() {
    EXTERNAL_STOP.notify_one();
}

/// R2-T1: applies the erasure ledger before anything serves. After
/// `attome restore` (which leaves [`crate::backup::RESTORE_PENDING`] in the
/// backup folder) a replay that fails stops the boot: the restored database
/// could otherwise serve erased people. On an ordinary boot a ledger that
/// cannot be read is logged and the boot goes on.
/// Y2-T3: every live lookup column without an index gets a durable
/// `BuildAttributeIndex` job (built `CONCURRENTLY` by the worker, never
/// inline at boot), deduplicated so a job still waiting from an earlier boot
/// is not queued twice. Best-effort: a failure is logged and the next boot
/// looks again.
async fn enqueue_lookup_index_backfill(state: &EngineState) {
    let missing =
        match attome_metadata::provision::lookup_columns_without_index(&state.base.db).await {
            Ok(missing) => missing,
            Err(error) => {
                tracing::warn!(%error, "lookup index backfill: could not list missing indexes");
                return;
            }
        };
    let mut queued = 0usize;
    for (entity, field) in missing {
        let key = format!("lookup-index:{entity}:{field}");
        let job = attome_core::jobs::EngineJob::BuildAttributeIndex {
            entity_logicalname: entity,
            field_logicalname: field,
        };
        match attome_jobs::enqueue_dedup(&state.base.db, job, &key).await {
            Ok(true) => queued += 1,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, "lookup index backfill: could not queue a build");
                return;
            }
        }
    }
    if queued > 0 {
        tracing::info!(queued, "lookup index backfill: index builds queued");
    }
}

async fn replay_erasures(
    state: &EngineState,
    config: &AppConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let marker = config
        .backup
        .resolved_dir()
        .join(crate::backup::RESTORE_PENDING);
    let after_restore = tokio::fs::metadata(&marker).await.is_ok();
    match attome_compliance::erasure_replay::replay(state).await {
        Ok(report) => {
            if report.replayed > 0 {
                tracing::warn!(
                    replayed = report.replayed,
                    keys_destroyed = report.keys_destroyed,
                    entries = report.entries,
                    "erasure ledger: erasures missing from the database were applied again"
                );
            }
            if after_restore && let Err(error) = tokio::fs::remove_file(&marker).await {
                tracing::warn!(%error, "erasure ledger: the restore marker could not be removed");
            }
            Ok(())
        }
        Err(error) if after_restore => Err(format!(
            "the database was restored and the erasure ledger could not be applied ({error}); start the file store and boot again"
        )
        .into()),
        Err(error) => {
            tracing::error!(%error, "erasure ledger: could not be read; erasures were not checked this boot");
            Ok(())
        }
    }
}

/// Ctrl-C (SIGINT), SIGTERM (what a container stop sends) or a
/// [`request_stop`] (the Windows service control manager). Shared by every
/// long-lived process built on [`init`] (the HTTP server and inline worker,
/// the standalone worker) so a split deployment drains identically on either.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
        "Ctrl+C"
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
        "SIGTERM"
    };
    // AB7-T1: Windows' own stops drain like SIGTERM: Ctrl+Break, closing
    // the console window and a system shutdown. (A service stop arrives
    // through `EXTERNAL_STOP` below.)
    #[cfg(windows)]
    let terminate = async {
        use tokio::signal::windows;
        let mut ctrl_break = windows::ctrl_break().expect("failed to install Ctrl+Break handler");
        let mut ctrl_close =
            windows::ctrl_close().expect("failed to install console-close handler");
        let mut ctrl_shutdown =
            windows::ctrl_shutdown().expect("failed to install system-shutdown handler");
        tokio::select! {
            _ = ctrl_break.recv() => "Ctrl+Break",
            _ = ctrl_close.recv() => "console close",
            _ = ctrl_shutdown.recv() => "system shutdown",
        }
    };
    #[cfg(not(any(unix, windows)))]
    let terminate = std::future::pending::<&'static str>();

    let source = tokio::select! {
        source = ctrl_c => source,
        source = terminate => source,
        _ = EXTERNAL_STOP.notified() => "stop request (service control)",
    };
    tracing::info!(source, "shutdown signal received");
}

pub async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|shutting_down| *shutting_down).await;
}

/// S1 (BSV-F13 / BSV-D11) — begin the drain.
///
/// Flips the readiness flag the load balancer probes (`AppState::draining`),
/// wakes every `AppState::shutdown_signal` waiter (a long-lived SSE stream ends
/// instead of holding the deadline open), waits `delay`, and only then signals
/// the listeners to stop accepting.
///
/// The wait is the whole point: before S1 the flag was set and the
/// graceful-shutdown channel signalled in the same instant, and axum 0.8 stops
/// `accept()` as soon as that signal fires. An LB probe opens a *new*
/// connection, so the only way it could ever observe the 503 was an
/// already-open keep-alive one — the probe it actually makes got connection
/// refused. Waiting one probe interval x failure threshold lets the LB read the
/// 503 and pull the node before new connections stop.
///
/// `delay == 0` restores the pre-S1 behaviour exactly (flip and signal in the
/// same tick).
pub async fn begin_drain(
    draining: std::sync::Arc<std::sync::atomic::AtomicBool>,
    drain_tx: tokio::sync::watch::Sender<bool>,
    delay: std::time::Duration,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) {
    draining.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = drain_tx.send(true);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let _ = shutdown_tx.send(true);
}

/// Fail-closed check for `idempotency.mandatory_operations` and
/// `approval.required_actions` (see the doc comment at `init`'s call site).
/// Each configured entry must exactly match a value from the owning crate's
/// own known-value registry (`attome_records::bulk::MANDATORY_TIER_OPERATIONS`,
/// `attome_api::KNOWN_ACTION_TYPES`) — an unrecognized entry is a boot error
/// naming exactly which value(s) are wrong and what the valid set is, not a
/// silent no-op.
///
/// D-327 (external-feedback item #12): a *misspelled* entry is only half the
/// problem an all-free-form `Vec<String>` creates — the other half is a
/// deployment that never lists the operation at all, since both sections
/// default to empty (`P-idempotency-hardening §4.4`'s deliberate "ships dark
/// behind a flag" posture for a non-production deployment). That posture is
/// wrong for `app.deployment_profile = "production"`: the two operations in
/// `MANDATORY_TIER_OPERATIONS` (`bulk`, `staged-import/{id}/approve`) were
/// specifically identified as irreversible/retry-sensitive enough to need the
/// durable Postgres tier, so a critical deployment must not be able to boot
/// with either one left on the best-effort Redis-only gate. This function is
/// the right place for that floor for the same reason it's already the right
/// place for the unknown-value check above: it's the first point in the boot
/// sequence with visibility into both `attome-config` (which owns
/// `deployment_profile`) and `attome-api` (which owns the registry) —
/// `attome-config::validate_production_profile` cannot express this itself
/// (guidelines §1: base-* has zero xrm-* knowledge).
///
/// D-355 — the coordination store holds the S2S replay nonces
/// (`s2s:nonce:{client}:{nonce}`, `SET NX EX 300`) and the unflushed S2S
/// access-log stream. If that store has no snapshot/AOF policy it drops both
/// on every restart, and losing the nonce set makes every nonce used in the
/// previous `NONCE_TTL_SECS` fresh again — replay protection failing open
/// (guidelines §5: security controls fail closed).
///
/// **Logs, does not refuse to boot** — a deliberate choice, not an oversight.
/// This is infrastructure state rather than malformed configuration, so
/// failing boot here would take an app node down over a Redis setting it does
/// not own, and would turn a fleet-wide misconfiguration into a fleet-wide
/// outage on the next rolling restart. The persistent signal is the
/// `redis_coordination_persistence_policy_configured` gauge and its
/// `RedisPersistenceDisabled` alert; this log is the boot-time copy so the
/// condition is visible to anyone reading startup output.
///
/// Only warns when `s2s.enabled` — the nonce keyspace is the reason this rises
/// above "your cache is cold after a restart", and an S2S-less deployment
/// genuinely does not care.
async fn warn_if_coordination_store_is_not_durable(
    config: &AppConfig,
    redis_coordination: &attome_cache::Store,
) {
    if !config.s2s.enabled {
        return;
    }

    match attome_cache::persistence::probe(redis_coordination).await {
        Ok(status) if !status.policy_configured => {
            tracing::error!(
                changes_since_last_save = status.changes_since_last_save,
                "coordination Redis has NO snapshot or AOF persistence policy: a restart \
                 drops its whole keyspace, including in-window S2S replay nonces (replay \
                 protection fails OPEN) and any access-log entries not yet flushed to \
                 s2s_access_log. Set Dragonfly's --snapshot_cron (see docker-compose.yml) \
                 or Redis's `save`/`appendonly yes`."
            );
        }
        Ok(_) => {}
        Err(e) => {
            // Unknown, not broken — never claim durability this failed to
            // establish, and never claim its absence either.
            tracing::warn!(
                error = %e,
                "could not determine whether the coordination Redis persists its keyspace"
            );
        }
    }
}

/// D-195/P-four-eyes-approval follow-up — closes what the paragraph
/// above used to leave open: `approval.required_actions` now gets the same
/// production floor, against `attome_api::PRODUCTION_MANDATORY_ACTIONS`
/// rather than the full `KNOWN_ACTION_TYPES` list. That constant's own doc
/// comment explains the narrower criterion (irreversible-on-execution, not
/// "every wired action") — most of `required_actions`' action types really
/// are dual-control policy a deployment opts into per its own regulatory
/// posture, same as this paragraph originally said; only the two whose
/// execution can never be undone (`security.erasure`, `retention.
/// approve_action`) are promoted to a mandatory production baseline.
fn validate_operation_registries(config: &AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    let unknown_mandatory: Vec<&str> = config
        .idempotency
        .mandatory_operations
        .iter()
        .map(String::as_str)
        .filter(|op| !attome_records::bulk::MANDATORY_TIER_OPERATIONS.contains(op))
        .collect();
    if !unknown_mandatory.is_empty() {
        return Err(format!(
            "idempotency.mandatory_operations names unrecognized operation(s) {unknown_mandatory:?} \
             — valid values are {:?}",
            attome_records::bulk::MANDATORY_TIER_OPERATIONS
        )
        .into());
    }

    if config.app.deployment_profile == "production" {
        let configured_mandatory: Vec<&str> = config
            .idempotency
            .mandatory_operations
            .iter()
            .map(String::as_str)
            .collect();
        let missing_mandatory: Vec<&str> = attome_records::bulk::MANDATORY_TIER_OPERATIONS
            .iter()
            .copied()
            .filter(|op| !configured_mandatory.contains(op))
            .collect();
        if !missing_mandatory.is_empty() {
            return Err(format!(
                "idempotency.mandatory_operations is missing {missing_mandatory:?} — every \
                 operation in attome_records::bulk::MANDATORY_TIER_OPERATIONS must be listed when \
                 app.deployment_profile = \"production\" (D-327): a critical deployment must not \
                 boot with an irreversible/retry-sensitive operation left unprotected by the \
                 durable idempotency tier"
            )
            .into());
        }
    }

    let unknown_actions: Vec<&str> = config
        .approval
        .required_actions
        .iter()
        .map(String::as_str)
        .filter(|action| !attome_api::KNOWN_ACTION_TYPES.contains(action))
        .collect();
    if !unknown_actions.is_empty() {
        return Err(format!(
            "approval.required_actions names unrecognized action_type(s) {unknown_actions:?} \
             — valid values are {:?}",
            attome_api::KNOWN_ACTION_TYPES
        )
        .into());
    }

    if config.app.deployment_profile == "production" {
        let configured_actions: Vec<&str> = config
            .approval
            .required_actions
            .iter()
            .map(String::as_str)
            .collect();
        let missing_actions: Vec<&str> = attome_api::PRODUCTION_MANDATORY_ACTIONS
            .iter()
            .copied()
            .filter(|action| !configured_actions.contains(action))
            .collect();
        if !missing_actions.is_empty() {
            return Err(format!(
                "approval.required_actions is missing {missing_actions:?} — every action_type in \
                 attome_api::PRODUCTION_MANDATORY_ACTIONS must be listed when \
                 app.deployment_profile = \"production\": a critical deployment must not boot \
                 with an irreversible-on-execution action (crypto-shredding erasure, retention \
                 archive/drop/purge) left unprotected by four-eyes approval"
            )
            .into());
        }
    }

    Ok(())
}

/// `inference.knowledge_article_entity`'s doc comment says a deployment "is
/// free to name its own article entity" — true only for where `article.draft`
/// *writes*. The chunking drain (`attome_search::drain`) and the knowledge-item
/// re-projection it calls (`attome_search::knowledge_index::reindex_item`) are
/// hardcoded to the canonical entity's own physical columns (title/text/
/// data_source_ref/lifecycle/is_active), not to whatever this config names —
/// so a deployment that overrides it to any *other* entity gets drafts
/// written successfully but never chunked, indexed, or retrievable, with no
/// error anywhere in that path (found reviewing D-489/M37).
///
/// A hard boot failure would be disproportionate — overriding this to `None`
/// (disabling `article.draft` entirely) is a legitimate, common choice, and
/// this file cannot tell a deployment's own compatible clone of the canonical
/// schema from an incompatible one. So this only warns, once, at the one
/// override value known for certain to silently break retrieval.
fn warn_if_knowledge_article_entity_diverges(config: &AppConfig) {
    if let Some(configured) = config.inference.knowledge_article_entity.as_deref()
        && configured != attome_search::knowledge_index::ITEM_ENTITY
    {
        tracing::warn!(
            configured_entity = configured,
            canonical_entity = attome_search::knowledge_index::ITEM_ENTITY,
            "inference.knowledge_article_entity does not name the canonical knowledge-base \
             entity — article.draft will write there, but attome-search's chunking drain only \
             projects knowledge_data_item, so drafts written under this override will \
             never be chunked, indexed, or retrievable by search.knowledge/the gap queue"
        );
    }
}

/// Registers every engine model, `MyWork` provider and workflow starter the
/// server mounts, in the order boot needs. One function so the integration
/// tests that drive the composed router build exactly the engines `attome
/// serve` does, instead of a hand-copied subset that leaves routes unmounted.
pub fn register_engines(
    builder: attome_api::EngineSystemBuilder,
) -> attome_api::EngineSystemBuilder {
    builder
        .register(attome_security::model::SecurityModel)
        .register(attome_notification::NotificationModel)
        .register(attome_workflow::WorkflowModel)
        // Route-mounting/license-gating only (D-010) — attome-project's seed
        // itself runs from inside `.build()` (`attome-api/src/system.rs`),
        // not from a pre-build call here like the `attome-workflow` platform
        // bundle above, because it needs `user_account` to already be
        // registered — see `attome_project::seed`'s module doc.
        .register(attome_project::ProjectModel)
        // Same ordering note as attome-project just above: attome-service's seed
        // also runs from inside `.build()`, after attome-project's own seed
        // (its `linked_project_id` lookup needs `attome_project` registered).
        .register(attome_service::ServiceModel)
        // D-576 — web portals. Its bundle is applied inside `.build()`
        // (`attome-api/src/system.rs`), after attome-security's seed.
        .register(attome_portal::PortalModel)
        // M20 Phase 1 (D-427) — same ordering note as attome-project/attome-service
        // above: attome-grc's seed also runs from inside `.build()`, after
        // attome-project's own (its additive `risk_ref` lookup onto
        // `project_issue` needs that entity already registered).
        .register(attome_grc::GrcModel)
        // Same ordering note as attome-project/attome-service above: attome-dashboard's
        // seed also runs from inside `.build()`.
        .register(attome_dashboard::DashboardModel)
        // D-480 (M26 R-14) — M27 (KPI & Metrics) split out of attome-dashboard
        // into its own crate. Route-mounting/license-gating only (D-383):
        // its two owned entities (`dashboard_metric_definition`/
        // `dashboard_metric_target`) are provisioned by `attome_dashboard::seed::seed`
        // (which calls `attome_metric::metric::seed` — see that file's own
        // comment), already covered by the `attome-dashboard` registration
        // immediately above, same shape as `ComplianceModel` below.
        .register(attome_metric::MetricModel)
        // D6-T1: the sales engine, gated on the `sales` module.
        .register(attome_sales::SalesModel)
        // D22-T1: gated on the `callintel` module.
        .register(attome_callintel::CallintelModel)
        // E6-T1: gated on the `marketing` module.
        .register(attome_marketing::MarketingModel)
        // F4-T1: gated on the `billing` module.
        .register(attome_billing::BillingModel)
        // AG2-T3: e-invoicing devices, gated on the `billing` module.
        .register(attome_einvoice::EinvoiceModel)
        // F10-T1: gated on the `commission` module.
        .register(attome_commission::CommissionModel)
        // F9-T1: gated on the `partner` module.
        .register(attome_partner::PartnerModel)
        // F6-T1: gated on the `fulfilment` module.
        .register(attome_fulfilment::FulfilmentModel)
        // G17-T1: gated on the `workforce` module.
        .register(attome_workforce::WorkforceModel)
        // W1-T1: gated on the `contract` module.
        .register(attome_contract::ContractModel)
        // B18-T1: gated on the `offline` module.
        .register(attome_offline::OfflineModel)
        .register(attome_procurement::ProcurementModel)
        .register(attome_hr::HrModel)
        // Route-mounting/license-gating only (D-383) — attome-compliance's own
        // seeds (`consent_seed`, `legal_matter_seed`) also run from inside
        // `.build()`, same shape as attome-project/attome-service/attome-grc/
        // attome-dashboard above; see `attome_compliance::model`'s own doc comment
        // for why this model exists at all (closing a generic-CRUD licence
        // hole on three provisioned entities, not mounting any routes).
        .register(attome_compliance::model::ComplianceModel)
        .register(attome_ai::ActionModel)
        // M28 Phase 1 — `/decisions/{id}/execute`. A separate `EngineModel` from
        // `attome_ai::ActionModel` (own routes, no owned entities) because
        // it needs `MODULE_DASHBOARD`, not `MODULE_AI` — see
        // `attome_ai::decision`'s module doc for why it lives in this crate
        // at all instead of alongside `DashboardModel`.
        .register(attome_ai::DecisionExecutionModel)
        // M97 Phase 1 (D-461) — `/admin/outcomes` + `/admin/outcomes/summary`,
        // the "proposals and their fates" read. A separate `EngineModel` from
        // `ActionModel`, same reason `DecisionExecutionModel` is: it needs
        // `MODULE_CORE`, not `MODULE_AI` — see `attome_ai::outcome`'s own
        // module doc for why this surface must not be locked behind AI.
        .register(attome_ai::OutcomeModel)
        // M55 Document Management (D-486) — route-mounting/license-gating
        // only. Mounts `documents_tree::routes()` and declares the
        // `attome_document` entity; the generic `file`-field path stays in
        // `attome-api`'s `core_routes()`, ungated, because it serves every
        // entity with a `file` attribute (see `attome_document`'s crate doc).
        // `attome_document` itself is provisioned by the platform bundle
        // `attome-document.json` applied in `system.rs`, so there is no seed to
        // call before `.build()`.
        .register(attome_document::DocumentModel)
        .register(attome_search::SearchModel)
        .register(attome_report::ReportModel)
        // M57 Phase 1 (Document Generation, D-463) — route-mounting/
        // license-gating only; the `attome-docgen` platform bundle (above, pre-
        // `.build()`) already registered `docgen_template`, same shape
        // as `attome_workflow::WorkflowModel`/`attome_report::ReportModel`.
        .register(attome_docgen::DocgenModel)
        // M07 Phase 1 (D-405/D-406) — route-mounting/license-gating only,
        // same shape as attome-project/attome-service/attome-dashboard above:
        // `state_model`/`state_transition` are migration-
        // owned infrastructure tables (0155_state_lifecycle.sql), not
        // runtime-provisioned entities, so there is no seed to call before
        // `.build()`.
        .register(attome_state::StateModel)
        // M59 Phase 1 — mounts the admin credential/test-connection routes
        // and the inbound webhook route, both license-gated on
        // MODULE_INTEGRATION (shared with attome-events/M62's admin surface,
        // D-403's precedent for that bit covering more than one engine).
        .register(attome_integration::IntegrationModel)
        // M41 Phase 1 (Process Intelligence, D-462) — route-mounting/
        // license-gating only, same shape as `attome_state::StateModel` above:
        // `process_case_def`/`process_event`/
        // `process_dfg_snapshot` are migration-owned infrastructure
        // tables (0296/0297/0298), not runtime-provisioned entities, so
        // there is no seed to call before `.build()`.
        .register(attome_process::ProcessModel)
        // M36 Phase 0+1 (Predictive Intelligence, D-473) — route-mounting/
        // license-gating only, same shape as `attome_state::StateModel`/
        // `attome_process::ProcessModel` above: `prediction_model`/
        // `prediction` are migration-owned infrastructure tables
        // (0420/0421), not runtime-provisioned entities, so there is no
        // seed to call before `.build()`.
        .register(attome_predict::PredictModel)
        // Dashboard 10/10 Phase 6 — the Approvals `MyWorkProvider`, listed by
        // `GET /api/v1/my-work/*`. Project/Decisions providers the plan also
        // names are follow-up work, not yet implemented.
        .register_my_work_provider(attome_api::my_work_approvals::ApprovalsMyWorkProvider)
        // Dashboard 10/10 Phase 6 — the Service work `MyWorkProvider`.
        .register_my_work_provider(attome_api::my_work_service::ServiceMyWorkProvider)
        // Dashboard 10/10 Phase 6 — the Workflow `MyWorkProvider`
        // (approval-wait case only; see its own module doc).
        .register_my_work_provider(attome_api::my_work_workflow::WorkflowMyWorkProvider)
        // Dashboard 10/10 Phase 6 — the Project work and Decisions
        // providers (the plan's remaining two provider rows).
        .register_my_work_provider(attome_api::my_work_project::ProjectMyWorkProvider)
        .register_my_work_provider(attome_api::my_work_decisions::DecisionsMyWorkProvider)
        // C5 (chatbot plan) — the one start path `attome-ai`'s `workflow.start`
        // reaches through `attome_core::WorkflowStarter`, since attome-ai
        // cannot depend on attome-workflow (the reverse edge exists).
        .register_workflow_starter(attome_workflow::instance_admin::PublishedWorkflowStarter)
}

#[cfg(test)]
mod tests {
    /// AB7-T1: a stop requested from outside the signals (the Windows
    /// service stop) starts the drain at once.
    #[tokio::test]
    async fn notify_trigger_starts_drain() {
        super::request_stop();
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            super::wait_for_shutdown_signal(),
        )
        .await
        .expect("a stop request ends the wait at once");
    }

    /// Z2-T1: the split roles when configured, else the bootstrap user.
    #[test]
    fn expected_identities_match_config() {
        let mut config: AppConfig =
            serde_json::from_str(include_str!("../../../../config.example.json"))
                .expect("the example config parses");
        let split = super::expected_identities(&config);
        assert_eq!(split.direct, config.database.user);
        assert_eq!(split.dbname, config.database.dbname);
        let runtime = config.database.runtime.as_ref().map(|r| r.user.clone());
        let migrator = config.database.migrator.as_ref().map(|m| m.user.clone());
        assert_eq!(
            Some(split.runtime.to_owned()),
            runtime.or(Some(config.database.user.clone()))
        );
        assert_eq!(
            Some(split.migrator.to_owned()),
            migrator.or(Some(config.database.user.clone()))
        );

        config.database.runtime = None;
        config.database.migrator = None;
        let bootstrap = super::expected_identities(&config);
        assert_eq!(bootstrap.runtime, config.database.user);
        assert_eq!(bootstrap.migrator, config.database.user);
    }
    use super::{
        begin_drain, public_portal_without_captcha_warning, report_ignored_config_keys,
        validate_operation_registries,
    };
    use attome_config::AppConfig;

    /// D-792 §2.3 row 5: a binary without the console only warns about the
    /// variable, and only for the exact value that would open it.
    #[test]
    fn the_fleet_console_variable_on_a_binary_without_it_only_warns() {
        assert!(super::fleet_console_unavailable_warning(Some("1")).is_some());
        assert!(super::fleet_console_unavailable_warning(None).is_none());
        assert!(super::fleet_console_unavailable_warning(Some("0")).is_none());
    }

    /// The restated variable name cannot drift from the gate's own.
    #[cfg(feature = "fleet-console")]
    #[test]
    fn the_fleet_console_variable_name_matches_the_gate() {
        assert_eq!(super::FLEET_CONSOLE_ENV_VAR, attome_fleet::gate::ENV_VAR);
    }

    /// BCF-10 — `preflight` must fail on a typo'd key, while boot only warns
    /// (an N-1 binary has to boot on an N config during a rollback, BCF-D4).
    #[test]
    #[allow(
        unsafe_code,
        reason = "the test sets and clears CONFIG_FILE/APP_ENV it alone reads"
    )]
    fn preflight_fails_on_unknown_key() {
        let document = serde_json::json!({
            "app": { "port": 0, "frontend_host": "localhost", "frontend_port": 4200 },
            "database": {
                "host": "localhost", "port": 5555, "dbname": "test", "user": "test",
                "password": "test", "schema": "test", "connection_number": 1, "timeout": 5.0
            },
            "cache": {
                "host": "localhost", "port": 6379, "password": "", "db": 0,
                "connection_pool_size": 1, "timeout": 500
            },
            "storage": {
                "s3_endpoint": "http://localhost:9000", "s3_region": "us-east-1",
                "s3_access_key": "test", "s3_secret_key": "test", "s3_bucket": "test"
            },
            "auth": {
                "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test",
                "apikey_hash_pepper": "test-only-throwaway-pepper-32-bytes-min"
            },
            "rate_limit": { "anonymous_rpm": 100, "authenticated_rpm": 1000 },
            "observability": {
                "metrics_port": 0, "trace_sampling_rate": 1.0, "enable_distributed_tracing": false
            },
            "email": {
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "", "smtp_password": "",
                "smtp_from_address": "a@b.c", "smtp_from_name": "t", "smtp_use_tls": false
            },
            "google_ai": { "api_key": "test" },
            "security": { "csrf_enforced": true }
        });
        let path = std::env::temp_dir().join("attome_server_bcf10_unknown_key.json");
        std::fs::write(&path, document.to_string()).expect("temp config written");
        // SAFETY: this test owns CONFIG_FILE/APP_ENV for its duration, and the
        // boot test module has no other config-file test.
        unsafe {
            std::env::set_var("CONFIG_FILE", &path);
            std::env::set_var("APP_ENV", "test-sentinel-not-debug");
        }
        let loaded = AppConfig::from_file();
        // SAFETY: same vars set above.
        unsafe {
            std::env::remove_var("CONFIG_FILE");
            std::env::remove_var("APP_ENV");
        }
        std::fs::remove_file(&path).ok();

        let config = loaded.expect("config must load");
        assert_eq!(
            config.ignored_keys().to_vec(),
            vec!["security.csrf_enforced".to_string()]
        );
        let err = report_ignored_config_keys(&config, true)
            .expect_err("preflight must fail on an unknown key");
        assert!(err.contains("security.csrf_enforced"), "{err}");
        assert!(
            report_ignored_config_keys(&config, false).is_ok(),
            "boot must only warn, never fail (BCF-D4)"
        );
    }

    /// BCF-17 — the warning is production-only, and only for provider `none`.
    #[test]
    fn production_without_a_captcha_provider_warns() {
        let mut config = config_with(&[], &[]);
        assert!(
            public_portal_without_captcha_warning(&config).is_none(),
            "a development deployment must not warn"
        );

        config.app.deployment_profile = "production".into();
        assert!(
            public_portal_without_captcha_warning(&config).is_some(),
            "production with portal.captcha.provider = none must warn"
        );

        config.portal.captcha.provider = attome_config::CaptchaProvider::Turnstile;
        assert!(
            public_portal_without_captcha_warning(&config).is_none(),
            "a configured provider must not warn"
        );
    }

    /// Same minimal-fixture shape as `attome_config::config`'s own
    /// `minimal_valid_config` test helper (duplicated here rather than
    /// exported cross-crate for a single test-only fixture) — every section
    /// filled with throwaway values so `serde_json::from_str` succeeds; the
    /// two sections under test are appended per case. Defaults
    /// `app.deployment_profile` to `"development"` (same as an absent key,
    /// via `AppSection`'s own serde default) — the D-327 floor only applies
    /// under `"production"`, see `config_with_profile` for that case.
    fn config_with(idempotency_ops: &[&str], approval_actions: &[&str]) -> AppConfig {
        config_with_profile(idempotency_ops, approval_actions, "development")
    }

    fn config_with_profile(
        idempotency_ops: &[&str],
        approval_actions: &[&str],
        deployment_profile: &str,
    ) -> AppConfig {
        let json = serde_json::json!({
            "app": {
                "port": 0, "frontend_host": "localhost", "frontend_port": 4200,
                "log_level": "error", "threads": 1, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "idle_connection_timeout": 30,
                "keepalive_requests": 100, "static_files_cache_time": 0,
                "server_header_field": "test", "deployment_profile": deployment_profile
            },
            "database": {
                "host": "localhost", "port": 5555, "dbname": "test", "user": "test",
                "password": "test", "schema": "test", "connection_number": 1,
                "timeout": 5.0
            },
            "cache": {
                "host": "localhost", "port": 6379, "password": "", "db": 0,
                "connection_pool_size": 1, "timeout": 500, "l1_cache_size_mb": 1,
                "l1_cache_ttl_seconds": 60
            },
            "storage": {
                "s3_endpoint": "http://localhost:9000", "s3_region": "us-east-1",
                "s3_access_key": "test", "s3_secret_key": "test", "s3_bucket": "test"
            },
            "auth": {
                "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test",
                "apikey_hash_pepper": "test-only-throwaway-pepper-32-bytes-min"
            },
            "rate_limit": { "anonymous_rpm": 100, "authenticated_rpm": 1000 },
            "observability": {
                "metrics_port": 0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            },
            "email": {
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "a@b.c",
                "smtp_from_name": "t", "smtp_use_tls": false,
                "queue_poll_seconds": 5, "max_retries": 1, "batch_size": 5
            },
            "google_ai": {
                "api_key": "test", "base_url": "http://localhost",
                "default_model": "test", "timeout_seconds": 5
            },
            "idempotency": { "mandatory_operations": idempotency_ops },
            "approval": { "required_actions": approval_actions },
        });
        serde_json::from_value(json).expect("test config must deserialize")
    }

    #[test]
    fn empty_lists_pass() {
        let config = config_with(&[], &[]);
        assert!(validate_operation_registries(&config).is_ok());
    }

    #[test]
    fn known_values_pass() {
        let config = config_with(
            &[
                "POST /api/v1/{entity}/bulk",
                "POST /api/v1/{entity}/staged-import/{id}/approve",
            ],
            &["security.rewrap", "security.role_grant"],
        );
        assert!(validate_operation_registries(&config).is_ok());
    }

    #[test]
    fn unrecognized_mandatory_operation_fails_closed() {
        let config = config_with(&["POST /api/v1/{entity}/frobnicate"], &[]);
        let err = validate_operation_registries(&config).unwrap_err();
        assert!(err.to_string().contains("POST /api/v1/{entity}/frobnicate"));
    }

    #[test]
    fn unrecognized_approval_action_fails_closed() {
        let config = config_with(&[], &["security.rewrap-typo"]);
        let err = validate_operation_registries(&config).unwrap_err();
        assert!(err.to_string().contains("security.rewrap-typo"));
    }

    // ── D-327: production-profile floor on idempotency.mandatory_operations ──

    #[test]
    fn development_profile_passes_with_empty_mandatory_list() {
        let config = config_with_profile(&[], &[], "development");
        assert!(validate_operation_registries(&config).is_ok());
    }

    #[test]
    fn production_profile_rejects_an_empty_mandatory_list() {
        let config = config_with_profile(&[], &[], "production");
        let err = validate_operation_registries(&config).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("POST /api/v1/{entity}/bulk"));
        assert!(message.contains("POST /api/v1/{entity}/staged-import/{id}/approve"));
    }

    #[test]
    fn production_profile_rejects_a_partial_mandatory_list() {
        let config = config_with_profile(&["POST /api/v1/{entity}/bulk"], &[], "production");
        let err = validate_operation_registries(&config).unwrap_err();
        assert!(
            err.to_string()
                .contains("POST /api/v1/{entity}/staged-import/{id}/approve")
        );
    }

    #[test]
    fn production_profile_passes_with_the_full_mandatory_list() {
        let config = config_with_profile(
            &[
                "POST /api/v1/{entity}/bulk",
                "POST /api/v1/{entity}/staged-import/{id}/approve",
            ],
            // Derived, not restated: a hardcoded copy silently fails this test
            // the next time an action joins the floor, which is exactly what
            // it did when `schema.entity_hard_delete` was added.
            attome_api::PRODUCTION_MANDATORY_ACTIONS,
            "production",
        );
        assert!(validate_operation_registries(&config).is_ok());
    }

    // ── P-four-eyes-approval follow-up: production-profile floor on
    // approval.required_actions (same shape as D-327's idempotency floor
    // above) ─────────────────────────────────────────────────────────────

    const FULL_MANDATORY_IDEMPOTENCY_OPS: &[&str] = &[
        "POST /api/v1/{entity}/bulk",
        "POST /api/v1/{entity}/staged-import/{id}/approve",
    ];

    #[test]
    fn production_profile_rejects_an_empty_approval_list() {
        let config = config_with_profile(FULL_MANDATORY_IDEMPOTENCY_OPS, &[], "production");
        let err = validate_operation_registries(&config).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("security.erasure"));
        assert!(message.contains("retention.approve_action"));
    }

    #[test]
    fn production_profile_rejects_a_partial_approval_list() {
        let config = config_with_profile(
            FULL_MANDATORY_IDEMPOTENCY_OPS,
            &["security.erasure"],
            "production",
        );
        let err = validate_operation_registries(&config).unwrap_err();
        assert!(err.to_string().contains("retention.approve_action"));
    }

    #[test]
    fn production_profile_passes_with_the_full_mandatory_approval_list() {
        let config = config_with_profile(
            FULL_MANDATORY_IDEMPOTENCY_OPS,
            attome_api::PRODUCTION_MANDATORY_ACTIONS,
            "production",
        );
        assert!(validate_operation_registries(&config).is_ok());
    }

    /// Same "the shipped template already clears the floor" guarantee as
    /// `production_example_template_already_satisfies_the_mandatory_floor`
    /// above, for `approval.required_actions` against
    /// `attome_api::PRODUCTION_MANDATORY_ACTIONS` instead of
    /// `idempotency.mandatory_operations` against `MANDATORY_TIER_OPERATIONS`.
    #[test]
    fn production_example_template_already_satisfies_the_approval_mandatory_floor() {
        let raw = include_str!("../../../../config.production.example.json");
        let value: serde_json::Value =
            serde_json::from_str(raw).expect("config.production.example.json must be valid JSON");
        let configured: Vec<&str> = value["approval"]["required_actions"]
            .as_array()
            .expect("config.production.example.json must set approval.required_actions")
            .iter()
            .map(|v| {
                v.as_str()
                    .expect("required_actions entries must be strings")
            })
            .collect();
        for action in attome_api::PRODUCTION_MANDATORY_ACTIONS {
            assert!(
                configured.contains(action),
                "config.production.example.json's approval.required_actions is missing \
                 {action:?} — this floor requires every PRODUCTION_MANDATORY_ACTIONS entry \
                 under app.deployment_profile = \"production\""
            );
        }
    }

    /// Proves the *shipped* production template already satisfies the D-327
    /// floor out of the box, so an operator copying it doesn't hit a boot
    /// error the moment they fill in the `__TODO__`s. Reads the raw JSON
    /// (rather than deserializing the whole file into `AppConfig`, which
    /// would need this crate to duplicate `attome_config`'s private
    /// `expand_env_vars`/placeholder-substitution test machinery for a
    /// section that has no `${VAR}`s or placeholders at all) and compares the
    /// configured list against the real registry, so this test breaks the
    /// moment either one drifts from the other.
    #[test]
    fn production_example_template_already_satisfies_the_mandatory_floor() {
        let raw = include_str!("../../../../config.production.example.json");
        let value: serde_json::Value =
            serde_json::from_str(raw).expect("config.production.example.json must be valid JSON");
        let configured: Vec<&str> = value["idempotency"]["mandatory_operations"]
            .as_array()
            .expect("config.production.example.json must set idempotency.mandatory_operations")
            .iter()
            .map(|v| {
                v.as_str()
                    .expect("mandatory_operations entries must be strings")
            })
            .collect();
        for op in attome_records::bulk::MANDATORY_TIER_OPERATIONS {
            assert!(
                configured.contains(op),
                "config.production.example.json's idempotency.mandatory_operations is missing \
                 {op:?} — D-327 requires every MANDATORY_TIER_OPERATIONS entry under \
                 app.deployment_profile = \"production\""
            );
        }
        assert_eq!(
            configured.len(),
            attome_records::bulk::MANDATORY_TIER_OPERATIONS.len(),
            "config.production.example.json's idempotency.mandatory_operations has an entry \
             not in attome_records::bulk::MANDATORY_TIER_OPERATIONS — validate_operation_registries \
             would reject it as unrecognized: {configured:?}"
        );
    }

    /// P0.4 / S1 (BSV-F13) — the readiness flip must be visible to the load
    /// balancer *before* the listener stops accepting, and the listener must
    /// stay up for the whole configured drain delay. An LB probe opens a new
    /// connection, so flipping the flag and closing `accept()` in the same tick
    /// means the probe is connection-refused rather than told not-ready.
    ///
    /// Uses a real (short) delay rather than `start_paused`: tokio's
    /// `test-util` feature is not enabled for this workspace's tokio, so
    /// `tokio::time::advance`/`Builder::start_paused` do not compile. See
    /// the plan's P0.4 note for the owed dev-dependency.
    #[tokio::test]
    async fn drain_flips_readiness_before_closing_the_listener() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        let draining = Arc::new(AtomicBool::new(false));
        let (drain_tx, mut drain_rx) = tokio::sync::watch::channel(false);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let delay = Duration::from_millis(300);
        let handle = tokio::spawn(begin_drain(draining.clone(), drain_tx, delay, shutdown_tx));

        // Wait for the flip itself (microseconds), never for the delay, so the
        // "shutdown not yet signalled" assertion below cannot race.
        for _ in 0..1000 {
            if draining.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(
            draining.load(Ordering::Relaxed),
            "the readiness flag must flip before anything else (BSV-F13)"
        );
        assert!(
            *drain_rx.borrow_and_update(),
            "stream owners must observe the drain the moment it starts (S3)"
        );
        assert!(
            !*shutdown_rx.borrow(),
            "the listener must still be accepting while readiness reads 503, or no LB probe \
             can ever see the 503 before the connection is refused (BSV-F13)"
        );

        tokio::time::timeout(
            Duration::from_secs(5),
            shutdown_rx.wait_for(|shutting_down| *shutting_down),
        )
        .await
        .expect("the listener must stop once the drain delay has elapsed")
        .expect("the drain task must still hold its sender");
        handle.await.expect("the drain task must not panic");
    }
}
