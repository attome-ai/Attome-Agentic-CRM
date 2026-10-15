use attome_config::AppConfig;
use sqlx::postgres::{PgConnectOptions, PgExecutor, PgPool, PgPoolOptions, PgSslMode};
use sqlx::{Connection, PgConnection};
use std::{str::FromStr, time::Duration};

/// Parses `url` into `PgConnectOptions` and applies `database.ssl_mode`/
/// `ssl_root_cert` (P-datastore-tls) — every pool constructor below goes
/// through this instead of `.connect(&url)` directly, so none of the three
/// is the unencrypted straggler the plan calls out. `ssl_mode` is validated
/// against a fixed string set at boot (`AppConfig::validate`, D-038) before
/// this ever runs, so the `.parse()` here cannot fail in practice — still
/// propagated as a real error rather than unwrapped, since this crate has no
/// way to prove that invariant held.
fn connect_options(url: &str, config: &AppConfig) -> Result<PgConnectOptions, sqlx::Error> {
    let mut options =
        PgConnectOptions::from_str(url)?.ssl_mode(PgSslMode::from_str(&config.database.ssl_mode)?);
    if let Some(ca_path) = &config.database.ssl_root_cert {
        options = options.ssl_root_cert(ca_path);
    }
    // P1.12/D-106 — see DatabaseSection::disable_statement_cache's doc comment:
    // a transaction-pooling pgbouncer without protocol-level prepared-statement
    // support can swap backends between transactions, making sqlx's default
    // client-side statement cache unsafe (`prepared statement already exists`).
    if config.database.disable_statement_cache {
        options = options.statement_cache_capacity(0);
    }
    Ok(options)
}

/// Which pool a builder is for (attome-db hardening Phase 2.1). Private on
/// purpose: callers keep using the `create_*` functions and `DbPool`, and no
/// role type leaks into the rest of the workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PoolRole {
    Runtime,
    Readonly,
    ReadonlyPrimary,
    Migrator,
    Direct,
}

impl PoolRole {
    /// The `application_name` this role's connections report, so
    /// `pg_stat_activity` can tell the pools apart (attome-db hardening Phase
    /// 2.2). A connection that goes through pgbouncer shows pgbouncer's own
    /// name instead: every pgbouncer template in this repo lists
    /// `application_name` in `ignore_startup_parameters`, because sqlx sends
    /// it and pgbouncer would otherwise refuse the connection. So the name is
    /// visible wherever a connection reaches PostgreSQL directly: deployments
    /// without pgbouncer, the direct pool, and the unpooled connections.
    fn application_name(self) -> &'static str {
        match self {
            PoolRole::Runtime => "attome-runtime",
            PoolRole::Readonly => "attome-readonly",
            PoolRole::ReadonlyPrimary => "attome-readonly-primary",
            PoolRole::Migrator => "attome-migrator",
            PoolRole::Direct => "attome-direct",
        }
    }
}

/// The direct pool only serves schema bootstrap, migrations, and the
/// role-password seeds, one at a time.
const DIRECT_POOL_MAX_CONNECTIONS: u32 = 2;

/// `role`'s pool size, shared by [`pool_options`] and the capacity report so
/// the two can't disagree. A `database.pools` entry sizes that pool; without
/// one the pool keeps `connection_number` (attome-db hardening Phase 2.3). The
/// direct pool's size is fixed.
fn pool_max_connections(role: PoolRole, config: &AppConfig) -> u32 {
    let pools = &config.database.pools;
    let fallback = config.database.connection_number;
    match role {
        PoolRole::Direct => DIRECT_POOL_MAX_CONNECTIONS,
        PoolRole::Runtime => pools.runtime.map_or(fallback, |size| size.max_connections),
        PoolRole::Readonly => pools.readonly.map_or(fallback, |size| size.max_connections),
        PoolRole::ReadonlyPrimary => pools
            .readonly_primary
            .map_or(fallback, |size| size.max_connections),
        PoolRole::Migrator => pools.migrator.map_or(fallback, |size| size.max_connections),
    }
}

/// Pool options for `role`.
///
/// **What a role may change:** pool size and per-connection session setup
/// (only `Direct` has any). **What it must never change:** TLS and the
/// statement cache. Those come from [`connect_options`], which takes no
/// role, so every pool gets the same TLS settings (P-datastore-tls) and the
/// same pgbouncer statement-cache rule (D-106). Adding a role-conditional
/// branch for either reopens the "one unencrypted straggler" gap.
fn pool_options(role: PoolRole, config: &AppConfig) -> Result<PgPoolOptions, sqlx::Error> {
    // BDB-F12 — the lifecycle knobs below are pinned to the values sqlx 0.8.6
    // happens to default to, written down so a future sqlx bump cannot change
    // connection lifecycle behavior silently. Changing one of them is its own
    // measured item, not a drive-by edit.
    let options = PgPoolOptions::new()
        .max_connections(pool_max_connections(role, config))
        .acquire_timeout(database_timeout(config)?)
        // No connections are opened ahead of demand; the pool grows to
        // `max_connections` under load and never holds an idle floor.
        .min_connections(0)
        // An idle connection is reaped after 10 minutes.
        .idle_timeout(Duration::from_secs(600))
        // A connection is recycled after 30 minutes regardless of use, so a
        // long-lived pool never pins one backend forever.
        .max_lifetime(Duration::from_secs(1800))
        // Validate a pooled connection before handing it to a caller:
        // PostgreSQL closes idle backends (a restart, an idle-session
        // timeout), and a caller should get a fresh connection rather than a
        // dead one.
        .test_before_acquire(true)
        // Log a connection acquire that took longer than 2s (sqlx emits its
        // own slow-acquire warning; nothing here reads it back).
        .acquire_slow_threshold(Duration::from_secs(2));
    Ok(match role {
        // See `create_direct_pool`'s doc comment for why this pool, and only
        // this pool, sets session state on connect.
        PoolRole::Direct => options.after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("SET statement_timeout = 0")
                    .execute(&mut *conn)
                    .await?;
                sqlx::query(&format!(
                    "SET lock_timeout = '{}'",
                    crate::MIGRATION_LOCK_TIMEOUT
                ))
                .execute(&mut *conn)
                .await?;
                Ok(())
            })
        }),
        PoolRole::Runtime | PoolRole::Readonly | PoolRole::ReadonlyPrimary | PoolRole::Migrator => {
            options
        }
    })
}

/// The connection target for `role`: the role-independent [`connect_options`]
/// (TLS, statement cache) plus the role's `application_name`, which is the
/// only thing a role adds here.
fn pool_connect_options(
    role: PoolRole,
    url: &str,
    config: &AppConfig,
) -> Result<PgConnectOptions, sqlx::Error> {
    Ok(connect_options(url, config)?.application_name(role.application_name()))
}

/// The one place a attome-db pool is built: `role`'s pool options joined to its
/// connection target. The role must never affect TLS or the statement cache;
/// see [`pool_options`] for the rule.
async fn build_pool(role: PoolRole, url: &str, config: &AppConfig) -> Result<PgPool, sqlx::Error> {
    let connect = pool_connect_options(role, url, config)?;
    pool_options(role, config)?.connect_with(connect).await
}

/// Every connection gets a baseline 500ms `statement_timeout` (the fast-read
/// class, guidelines §14.1) so a single slow query or lock wait can't pin a
/// connection and push the pool toward exhaustion. This is a **role-level**
/// default (`migrations/0018_role_statement_timeout.sql`, `ALTER ROLE ... SET
/// statement_timeout`), not a per-connection `after_connect` hook (P1.12) --
/// a hook here would be session-level state that leaks across clients once
/// connections are multiplexed by a transaction-mode pgbouncer. Handlers that
/// legitimately need longer (reports, bulk) raise it per-transaction via
/// `SET LOCAL` (`query_exec.rs` shows the pattern) rather than raising this
/// default.
///
/// P-db-privilege-separation / D-117: this is the DML-only "runtime" pool —
/// `config.runtime_database_url()`, not `database_url()` directly, so a
/// deployment that has configured `database.runtime` (a dedicated
/// `attome_runtime` role) actually connects as it. Falls back to
/// `database_url()`'s credentials when unconfigured, byte-identical to
/// pre-split behavior.
///
/// `DATABASE_URL` (test/CI convenience — every job that relies on it also
/// sets `APP_ENV=debug`) only overrides this
/// when `APP_ENV=debug`, same fail-closed posture as the rest of this
/// module's `APP_ENV` gates (D-038/D-148): outside debug, a stale or
/// privileged `DATABASE_URL` left behind by a CI runner or an operator's
/// shell must not silently swap the runtime pool onto a different role than
/// `database.runtime` configured. `boot.rs`'s post-connect
/// `verify_pool_identity` call is the second, independent layer that catches
/// a mismatch here even if this gate is ever bypassed.
pub async fn create_pool(config: &AppConfig) -> Result<PgPool, sqlx::Error> {
    let url = resolve_runtime_url(
        config,
        attome_config::app_env().as_deref(),
        std::env::var("DATABASE_URL").ok().as_deref(),
    );
    build_pool(PoolRole::Runtime, &url, config).await
}

/// Pure decision extracted from `create_pool` so its `APP_ENV=debug` gate is
/// unit-testable without a live Postgres connection (this crate has no
/// synchronous, DB-free way to test the `async fn` itself). Takes both env
/// values as parameters rather than reading `std::env` directly for the same
/// reason: it keeps this function a plain, race-free pure function instead of
/// a test that mutates shared process-global env vars.
fn resolve_runtime_url(
    config: &AppConfig,
    app_env: Option<&str>,
    database_url: Option<&str>,
) -> String {
    if attome_config::is_debug_app_env(app_env) {
        database_url
            .map(str::to_owned)
            .unwrap_or_else(|| config.runtime_database_url())
    } else {
        config.runtime_database_url()
    }
}

/// SELECT-only pool for `/api/v1/query/execute` (P1.1e) and, more generally
/// (P1.12), for any read routed through `AppState::read_pool` -- `Ok(None)`
/// if `database.readonly` isn't configured; callers must fall back to the
/// primary pool with a loud warning, never silently. `statement_timeout`
/// comes from the `attome_readonly` role's own default (see `create_pool`'s
/// doc comment); report-flagged queries raise it per-transaction at the call
/// site (`query_exec.rs`), not here.
pub async fn create_readonly_pool(config: &AppConfig) -> Result<Option<PgPool>, sqlx::Error> {
    let Some(url) = config.readonly_database_url() else {
        return Ok(None);
    };
    build_pool(PoolRole::Readonly, &url, config).await.map(Some)
}

/// P-api-consistency-hardening (a) — same SELECT-only `attome_readonly` role
/// as `create_readonly_pool`, but connected to the **primary** host/port
/// (`AppConfig::readonly_primary_database_url`) rather than wherever
/// `database.readonly.host`/`.port` (D-155) may have pointed the ordinary
/// replica pool. This is the pool `query_exec.rs` routes a pinned (just-
/// written) caller to: it needs primary-fresh data, but must never gain more
/// than the readonly role's `SELECT`-only grants (P1.1e) — routing a pinned
/// `query/execute` request to `create_pool`'s full-privilege pool instead
/// would reopen exactly the isolation hole P1.1e closed, just for the sake of
/// read freshness. `Ok(None)` under the identical condition as
/// `create_readonly_pool` (`database.readonly` unconfigured — there's no
/// readonly role to reuse); callers must fall back to `db_readonly` (never to
/// the full-privilege pool) with a loud warning, same convention as every
/// other optional pool in this module.
pub async fn create_readonly_primary_pool(
    config: &AppConfig,
) -> Result<Option<PgPool>, sqlx::Error> {
    let Some(url) = config.readonly_primary_database_url() else {
        return Ok(None);
    };
    build_pool(PoolRole::ReadonlyPrimary, &url, config)
        .await
        .map(Some)
}

/// P-ha-failover-hardening follow-up (D-156) — the residual gap left open by
/// D-155's `readonly.host`/`.port` override: nothing confirmed the resolved
/// endpoint is actually the same logical database as the primary. Without
/// this, an operator's `readonly.host`/`.port` typo, or a stale
/// HAProxy/pgbouncer target, would boot cleanly and `AppState::read_pool`
/// would silently start routing reads to an unrelated Postgres instance —
/// under D-002's one-customer-one-database model that's a data-isolation
/// incident, not just staleness.
///
/// Deliberately checks only `current_database()`, not `pg_is_in_recovery()`:
/// D-155's own doc comment on `ReadonlyDbCredentials::host` says a deployment
/// sharing one endpoint for both roles (today's default topology) stays fully
/// supported, so `db_readonly` legitimately equals `db` — not in recovery —
/// whenever `readonly.host`/`.port` are unset, and that must never be a boot
/// error. The "genuinely a standby" question is already handled at the right
/// layer, continuously, by `replica_watermark::refresh_once`'s
/// `replay_lsn: None` branch.
///
/// Callers should only run this against a pool actually built from
/// `database.readonly` (i.e. `create_readonly_pool`'s `Some(pool)` case) —
/// running it against a debug-mode fallback clone of the primary pool would
/// just re-verify the primary against itself, a harmless but pointless extra
/// round trip.
pub async fn verify_readonly_identity(
    pool: &PgPool,
    expected_dbname: &str,
) -> Result<(), sqlx::Error> {
    let (current_dbname,): (String,) = sqlx::query_as("SELECT current_database()")
        .fetch_one(pool)
        .await?;
    if current_dbname != expected_dbname {
        return Err(sqlx::Error::Configuration(
            format!(
                "database.readonly resolves to database '{current_dbname}', but the primary's \
                 database.dbname is '{expected_dbname}' — refusing to route reads to a \
                 mismatched database. Check database.readonly.host/.port."
            )
            .into(),
        ));
    }
    Ok(())
}

/// P-db-privilege-separation follow-up — closes the gap left by D-117/D-148's
/// boot checks only confirming `database.runtime`/`.migrator`/`.readonly`
/// are *configured*, never that the pool actually built from that config
/// connects as the role it claims to. Without this, a stale/privileged
/// `DATABASE_URL` (or, for the migrator/readonly pools, a config typo that
/// happens to still parse) can make a "privilege-separated" pool silently
/// authenticate as the full-privilege bootstrap role instead — the same
/// class of incident `verify_readonly_identity` already exists to catch for
/// `database.readonly.host`/`.port`, generalized to also check
/// `current_user`, and to run for all three split identities, not just
/// readonly.
///
/// `boot.rs` calls this once per pool, immediately after each is built —
/// cheap (one round trip), so it always runs, not just outside
/// `APP_ENV=debug`: an operator who deliberately falls back to the
/// bootstrap identity in debug still gets a working, self-consistent check
/// (expected == the bootstrap role, which the pool trivially satisfies)
/// rather than a special case to reason about.
pub async fn verify_pool_identity(
    pool: &PgPool,
    expected_user: &str,
    expected_dbname: &str,
) -> Result<(), sqlx::Error> {
    verify_identity(pool, expected_user, expected_dbname).await
}

/// D-497 — the unpooled-connection counterpart of `verify_pool_identity`.
/// `boot.rs` runs it on one `create_migrator_connection` session, because
/// that path resolves its endpoint differently from `create_migrator_pool`
/// (`database.direct_url`, not `database.host`), so the pool's check says
/// nothing about it.
pub async fn verify_connection_identity(
    conn: &mut PgConnection,
    expected_user: &str,
    expected_dbname: &str,
) -> Result<(), sqlx::Error> {
    verify_identity(&mut *conn, expected_user, expected_dbname).await
}

async fn verify_identity<'e>(
    executor: impl PgExecutor<'e>,
    expected_user: &str,
    expected_dbname: &str,
) -> Result<(), sqlx::Error> {
    let (current_user, current_dbname): (String, String) =
        sqlx::query_as("SELECT current_user, current_database()")
            .fetch_one(executor)
            .await?;
    if let Some(message) = identity_mismatch_message(
        &current_user,
        &current_dbname,
        expected_user,
        expected_dbname,
    ) {
        return Err(sqlx::Error::Configuration(message.into()));
    }
    Ok(())
}

/// Pure comparison + message extracted from `verify_pool_identity` so the
/// match/mismatch logic and the operator-facing wording are unit-testable
/// without a live Postgres connection — only the two `SELECT`ed strings
/// actually need the database; comparing them does not.
fn identity_mismatch_message(
    current_user: &str,
    current_dbname: &str,
    expected_user: &str,
    expected_dbname: &str,
) -> Option<String> {
    if current_user == expected_user && current_dbname == expected_dbname {
        return None;
    }
    Some(format!(
        "database identity mismatch: connected as role '{current_user}' on database \
         '{current_dbname}', but config expects role '{expected_user}' on database \
         '{expected_dbname}' — refusing to proceed. A stale DATABASE_URL, or a \
         database.runtime/.migrator/.readonly credential typo, can cause this; check both \
         before retrying."
    ))
}

/// P-db-privilege-separation / D-117 — pooled connection for the DDL-capable
/// migrator identity (`config.migrator_database_url()`): schema/entity
/// provisioning called from live admin HTTP handlers
/// (`xrm-entity::provision`) and boot-time entity/attribute seeding, neither
/// of which fits `create_direct_pool`'s narrow 2-connection/no-pgbouncer/
/// bootstrap-only shape — and neither of which `create_direct_pool` should
/// serve anyway, since that pool must stay on `database.user` regardless of
/// `database.migrator` (see `AppConfig::direct_database_url`'s doc comment
/// for the chicken-and-egg reason). Falls back to the same identity
/// `create_pool` uses when `database.migrator` isn't configured, so an
/// unconfigured deployment is unaffected — just a second pool authenticating
/// as the same role. Goes through ordinary connection pooling (unlike
/// `create_direct_pool`) because, unlike schema bootstrap/migrations, none of
/// `xrm-entity::provision`'s statements depend on a single pinned session —
/// `CREATE INDEX CONCURRENTLY` and friends already run as bare autocommit
/// statements (`exec_ddl_locked`), which is safe under a transaction-mode
/// pgbouncer too.
///
/// Callers must build this only after the migrator role-password seed
/// (`server::db_role_seed::seed_migrator`, run on `create_direct_pool`'s
/// bootstrap connection) has already applied — see `main.rs`'s boot
/// sequencing.
pub async fn create_migrator_pool(config: &AppConfig) -> Result<PgPool, sqlx::Error> {
    let connect = migrator_pool_connect_options_for(
        config,
        attome_config::app_env().as_deref(),
        std::env::var("DATABASE_URL").ok().as_deref(),
    )?;
    pool_options(PoolRole::Migrator, config)?
        .connect_with(connect)
        .await
}

/// The migrator pool's connection target: [`resolve_migrator_url`], with the
/// configured `database.migrator` credentials kept when a debug `DATABASE_URL`
/// override supplied the endpoint (see [`with_configured_migrator_credentials`]).
fn migrator_pool_connect_options_for(
    config: &AppConfig,
    app_env: Option<&str>,
    database_url: Option<&str>,
) -> Result<PgConnectOptions, sqlx::Error> {
    let url = resolve_migrator_url(config, app_env, database_url);
    let options = pool_connect_options(PoolRole::Migrator, &url, config)?;
    Ok(if url == config.migrator_database_url() {
        options
    } else {
        with_configured_migrator_credentials(options, config)
    })
}

/// M01 C-33 follow-up: a debug `DATABASE_URL` override chooses *where* the
/// migrator connects (host, port, database, query options), not *as whom*.
/// When `database.migrator` is configured its credentials are kept, so the
/// migrator identity stays what boot's `verify_pool_identity` /
/// `verify_connection_identity` expect (`database.migrator.user`) and the
/// D-117 privilege split holds in debug too. With `database.migrator` unset the
/// override's own credentials stand, exactly as the runtime pool's do — that
/// is the case C-33 fixed (a harness config whose `database.user` is a
/// placeholder).
fn with_configured_migrator_credentials(
    options: PgConnectOptions,
    config: &AppConfig,
) -> PgConnectOptions {
    match config.database.migrator.as_ref() {
        Some(migrator) => options
            .username(&migrator.user)
            .password(migrator.password.expose()),
        None => options,
    }
}

/// Same debug-mode `DATABASE_URL` convenience as `resolve_runtime_url`,
/// extended to the migrator identity (P-db-privilege-separation / D-117).
/// Without this, a debug-mode `DATABASE_URL` override reached the runtime
/// pool only: `create_pool` would correctly point at a developer's or test
/// harness's chosen database, while `create_migrator_pool`/
/// `create_migrator_connection` kept silently reading
/// `config.migrator_database_url()` — built from `database.host`/`.port`/
/// `.dbname` (`config.debug.json`'s checked-in dev database), regardless of
/// `DATABASE_URL`. Every write through the runtime pool (ordinary CRUD, and
/// `xrm-entity::provision`'s own attribute-row/column writes, which use the
/// runtime pool per D-117) lands on the intended database, but schema
/// bootstrap and every entity/attribute provisioning DDL routed through the
/// migrator identity — `sync_attribute_index` chief among them — silently
/// targets a *different*, unrelated database instead. The failure mode is
/// not a connection error (both databases are real and reachable): it is a
/// column that "does not exist" from the wrong database's point of view,
/// with no indication the DDL ran against the wrong target at all. Same
/// fail-closed posture as `resolve_runtime_url`: outside `APP_ENV=debug`,
/// always `config.migrator_database_url()`, never influenced by a stray
/// `DATABASE_URL` left in the environment.
///
/// The URL this returns carries the override's credentials; the pool and the
/// unpooled connection swap in `database.migrator`'s when it is configured
/// ([`with_configured_migrator_credentials`]), so only the endpoint of an
/// override is taken from `DATABASE_URL` in that case.
fn resolve_migrator_url(
    config: &AppConfig,
    app_env: Option<&str>,
    database_url: Option<&str>,
) -> String {
    if attome_config::is_debug_app_env(app_env) {
        database_url
            .map(str::to_owned)
            .unwrap_or_else(|| config.migrator_database_url())
    } else {
        config.migrator_database_url()
    }
}

/// A small, short-lived pool for schema bootstrap + migrations (P1.12) --
/// always a **direct** connection to Postgres (`database.direct_url`, falling
/// back to the same URL `create_pool` would use when unset), never through a
/// transaction-mode pgbouncer: `sqlx::migrate!` takes a session-level
/// advisory lock internally, which a transaction-pooled connection would
/// silently break (the session backing the lock can be handed to a different
/// logical client mid-migration).
///
/// This pool's `after_connect` disabling `statement_timeout` is a deliberate,
/// narrow exception to the "no per-connection session hooks" rule that
/// motivated deleting the hooks in `create_pool`/`create_readonly_pool`
/// above: this connection is never pooled by pgbouncer (that's the whole
/// point of it), so there's no cross-client leakage risk, and without this
/// override the new role-level 500ms default would apply here too and could
/// abort a legitimately slow migration (e.g. an index build on a non-trivial
/// table). Do not delete this hook by analogy with the other two.
///
/// F-003: disabling `statement_timeout` removes the only bound that existed
/// on a *lock wait* here, which is a different and much worse failure — a
/// migration queued behind a long analytics read blocks every write to that
/// table for as long as the read runs, because PostgreSQL's lock queue is
/// FIFO. `lock_timeout` restores a bound on the wait without bounding the
/// work, so the same hook sets both. [`crate::MIGRATION_LOCK_TIMEOUT`]
/// documents the value; `run_migrations` sets it again on its own connection
/// (so the guarantee doesn't depend on the caller's pool) and owns the
/// retry/abort policy, while setting it here also covers `ensure_schema` and
/// the role-password seeds that share this pool.
pub async fn create_direct_pool(config: &AppConfig) -> Result<PgPool, sqlx::Error> {
    let url = config.direct_database_url();
    build_pool(PoolRole::Direct, &url, config).await
}

/// BDB-F1 / D-612 — one owned, session-pinned PostgreSQL session for runtime
/// work:
///
/// - **Endpoint** from `database.direct_url` (falling back to
///   `database.host:port` when unset), exactly as D-497 requires: a session
///   advisory lock must not be handed to a transaction-mode pgbouncer.
/// - **Credentials, database and `search_path`** from `database.runtime`
///   (D-612 amending D-497). `direct_url`'s own embedded credentials and
///   `database.user` stay reserved for the bootstrap identity; no runtime
///   path authenticates as them.
/// - `application_name = attome-runtime-session`, distinct from the runtime
///   *pool*'s `attome-runtime`, so `pg_stat_activity` can tell a pinned
///   session from a pooled connection.
/// - `statement_timeout = 0` and `lock_timeout = MIGRATION_LOCK_TIMEOUT`,
///   the same session settings the removed `create_direct_connection` applied:
///   its callers only take `pg_try_advisory_lock`, which never waits, so the
///   bound guards future callers rather than today's.
///
/// A debug-mode `DATABASE_URL` override is honoured wholesale, exactly like
/// `create_migrator_connection` (see `migrator_connection_options_for`):
/// it names a concrete instance the harness chose, and blending it with
/// `direct_url` would reintroduce the split-identity mismatch it exists to
/// close. Outside `APP_ENV=debug`, an unconfigured `database.runtime` is a
/// configuration error, never a silent fallback to `database.user` (D-612
/// item 3).
pub async fn create_runtime_session(config: &AppConfig) -> Result<PgConnection, sqlx::Error> {
    let options = runtime_session_options(
        config,
        attome_config::app_env().as_deref(),
        std::env::var("DATABASE_URL").ok().as_deref(),
    )?;
    connect_unpooled(&options, config, Some(crate::MIGRATION_LOCK_TIMEOUT)).await
}

/// The `application_name` a session-pinned runtime connection reports. Kept
/// apart from [`PoolRole::Runtime`]'s `attome-runtime` on purpose: this is
/// not a pool, so it is not a [`PoolRole`] variant (no pool size, no
/// capacity entry) — but it must still be one obvious name an operator can
/// grep for in `pg_stat_activity`.
const RUNTIME_SESSION_APPLICATION_NAME: &str = "attome-runtime-session";

/// The role-independent [`connect_options`] plus the runtime session's
/// `application_name`. TLS and the statement cache come from
/// `connect_options` unchanged, so this path can never become the
/// unencrypted straggler.
fn runtime_session_connect_options(
    url: &str,
    config: &AppConfig,
) -> Result<PgConnectOptions, sqlx::Error> {
    Ok(connect_options(url, config)?.application_name(RUNTIME_SESSION_APPLICATION_NAME))
}

/// The pure half of [`create_runtime_session`]: takes both env values as
/// parameters, like `resolve_runtime_url`, so the resolution is
/// unit-testable without a live Postgres. The same shape as
/// `migrator_connection_options_for`, with the runtime identity instead of
/// the migrator one.
pub fn runtime_session_options(
    config: &AppConfig,
    app_env: Option<&str>,
    database_url: Option<&str>,
) -> Result<PgConnectOptions, sqlx::Error> {
    let runtime_url = resolve_runtime_session_url(config, app_env, database_url)?;
    // A debug-mode DATABASE_URL override names a concrete instance wholesale,
    // same rule as the migrator session (M01 C-33).
    if runtime_url != config.runtime_database_url() {
        return runtime_session_connect_options(&runtime_url, config);
    }
    let direct = PgConnectOptions::from_str(&config.direct_database_url())?;
    let options = runtime_session_connect_options(&runtime_url, config)?
        .host(direct.get_host())
        .port(direct.get_port());
    Ok(match direct.get_socket() {
        Some(socket) => options.socket(socket),
        None => options,
    })
}

/// D-612 item 3 — the only tolerated fallback to the bootstrap identity is
/// `APP_ENV=debug` with `database.runtime` unset. Outside debug, an
/// unconfigured runtime identity is a configuration error naming the key to
/// set, never a silent bootstrap session.
fn resolve_runtime_session_url(
    config: &AppConfig,
    app_env: Option<&str>,
    database_url: Option<&str>,
) -> Result<String, sqlx::Error> {
    if config.database.runtime.is_none() && !attome_config::is_debug_app_env(app_env) {
        return Err(sqlx::Error::Configuration(
            "database.runtime is not configured — refusing to open a session-pinned runtime \
             connection as the FULL-PRIVILEGE bootstrap identity (database.user). Set \
             database.runtime (the attome_runtime role, \
             migrations/0042_migrator_runtime_roles.sql), or use APP_ENV=debug for local dev \
             (D-612)."
                .to_string()
                .into(),
        ));
    }
    Ok(resolve_runtime_url(config, app_env, database_url))
}

/// P-db-privilege-separation / D-117, endpoint fixed by D-497 — one owned
/// session (`statement_timeout` disabled, never shared) authenticated as the
/// migrator identity. `xrm-entity::provision::sync_attribute_index` is the one
/// caller: it holds a *session* advisory lock across a catalog probe and
/// `CREATE`/`DROP INDEX CONCURRENTLY`, so every statement must reach the same
/// backend.
///
/// That is why the endpoint is `database.direct_url`, not `database.host`
/// (see `migrator_connection_options`): in a pooled deployment
/// `database.host` is a transaction-mode pgbouncer, which may run each
/// autocommit statement on a different backend and strand the lock. The
/// pooled `create_migrator_pool` stays on `database.host` — none of its
/// statements depend on a pinned session.
///
/// **No `lock_timeout`, deliberately** (attome-db hardening Phase 1.3c,
/// 2026-09-13). A lock timeout cuts a `CONCURRENTLY` build short, and that
/// failure is not automatically recovered on every path. The admin
/// create/update-attribute handlers and bundle apply run small-table index
/// builds inline, after the metadata commit, and return the error with `?`:
/// the caller would get a 500, nothing retries, and the index stays missing
/// (or INVALID) until some later sync touches that field. Only the
/// `BuildAttributeIndex` job retries. A build that waits is correct; a build
/// that silently never completes is not. `tests/unpooled_connection.rs` pins
/// this, and `xrm-entity/tests/attribute_index_lock_timeout.rs` records how
/// an interrupted build behaves.
pub async fn create_migrator_connection(config: &AppConfig) -> Result<PgConnection, sqlx::Error> {
    let options = migrator_connection_options(config)?;
    connect_unpooled(&options, config, None).await
}

/// D-497 — where and as whom `create_migrator_connection` connects: the
/// migrator credentials, database, and `search_path` from
/// `migrator_database_url()` (so its identity is exactly what it was before),
/// and the host/port (or socket) from `direct_database_url()`. With
/// `database.direct_url` unset the two endpoints are the same
/// `database.host:port`, so an unpooled deployment is unaffected.
///
/// A debug-mode `DATABASE_URL` override (`resolve_migrator_url`) supplies the
/// whole endpoint (host, port, database, query) instead of being spliced with
/// `direct_database_url()`'s host/port — only the configured
/// `database.migrator` credentials, when set, are kept
/// ([`with_configured_migrator_credentials`]): `direct_database_url()` exists to bypass a transaction-mode
/// pgbouncer sitting in front of the *configured* migrator endpoint, but a
/// `DATABASE_URL` override already names a concrete Postgres instance
/// directly (that is the whole point of the convenience) — blending the two
/// would reintroduce the exact split-identity mismatch this override exists
/// to close.
fn migrator_connection_options(config: &AppConfig) -> Result<PgConnectOptions, sqlx::Error> {
    migrator_connection_options_for(
        config,
        attome_config::app_env().as_deref(),
        std::env::var("DATABASE_URL").ok().as_deref(),
    )
}

/// The pure half of [`migrator_connection_options`]: takes both env values
/// as parameters, like [`resolve_runtime_url`], so tests do not depend on
/// the shell they run in.
fn migrator_connection_options_for(
    config: &AppConfig,
    app_env: Option<&str>,
    database_url: Option<&str>,
) -> Result<PgConnectOptions, sqlx::Error> {
    let migrator_url = resolve_migrator_url(config, app_env, database_url);
    if migrator_url != config.migrator_database_url() {
        return Ok(with_configured_migrator_credentials(
            pool_connect_options(PoolRole::Migrator, &migrator_url, config)?,
            config,
        ));
    }
    let direct = PgConnectOptions::from_str(&config.direct_database_url())?;
    let options = pool_connect_options(PoolRole::Migrator, &migrator_url, config)?
        .host(direct.get_host())
        .port(direct.get_port());
    Ok(match direct.get_socket() {
        Some(socket) => options.socket(socket),
        None => options,
    })
}

/// `database.timeout` as a `Duration`, used for every pool's acquire timeout
/// and the unpooled connect timeout. Fractional seconds are kept: `0.5` is
/// 500ms, where the pool builders used to truncate with `as u64` and get a
/// zero timeout. `AppConfig::validate` already rejects anything outside
/// `(0, 120]`; this still returns a configuration error, never a panic or a
/// silent rounding, for a config that skipped `validate` (tests build
/// `AppConfig` straight from JSON).
fn database_timeout(config: &AppConfig) -> Result<Duration, sqlx::Error> {
    let seconds = config.database.timeout;
    Duration::try_from_secs_f64(seconds)
        .ok()
        .filter(|timeout| !timeout.is_zero())
        .ok_or_else(|| {
            sqlx::Error::Configuration(
                format!(
                    "database.timeout must be a positive, finite number of seconds, got {seconds}"
                )
                .into(),
            )
        })
}

/// Opens an unpooled session with `statement_timeout` disabled. Unlike a pool,
/// `PgConnection::connect_with` has no acquire timeout of its own, so the
/// connect is bounded by `database.timeout` here — `boot.rs` opens a migrator
/// connection to verify its identity (D-497), and an unreachable direct
/// endpoint must fail boot rather than hang it on the OS TCP timeout.
///
/// `lock_timeout` is set per caller: `create_runtime_session` bounds lock
/// waits, `create_migrator_connection` deliberately does not (see their doc
/// comments).
async fn connect_unpooled(
    options: &PgConnectOptions,
    config: &AppConfig,
    lock_timeout: Option<&str>,
) -> Result<PgConnection, sqlx::Error> {
    let timeout = database_timeout(config)?;
    let mut conn = tokio::time::timeout(timeout, PgConnection::connect_with(options))
        .await
        .map_err(|_| {
            sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "connecting to PostgreSQL at {}:{} timed out after {timeout:?}",
                    options.get_host(),
                    options.get_port()
                ),
            ))
        })??;
    sqlx::query("SET statement_timeout = 0")
        .execute(&mut conn)
        .await?;
    // `SET` can't take a bind parameter; the value is always one of this
    // crate's own constants (`MIGRATION_LOCK_TIMEOUT`), never caller input.
    if let Some(lock_timeout) = lock_timeout {
        sqlx::query(&format!("SET lock_timeout = '{lock_timeout}'"))
            .execute(&mut conn)
            .await?;
    }
    Ok(conn)
}

/// attome-db hardening Phase 2.4 — logs once, at boot, how many connections each
/// long-lived pool in **this process** may open, grouped by endpoint.
///
/// **What it covers:** it reads the same config the pool builders read. The
/// runtime and migrator pools are always listed; the readonly and
/// readonly-primary pools only when `database.readonly` is configured.
///
/// **How it's grouped:** by `host:port`, never credentials, with a total per
/// endpoint and no grand total. One endpoint may be pgbouncer and another
/// PostgreSQL itself, so a single sum would mean nothing.
///
/// **Not counted, and the log line says so:**
/// - the direct pool, which only schema bootstrap and migrations open,
///   briefly;
/// - the unpooled direct and migrator sessions, which have no ceiling of their
///   own and are bounded by their callers.
///
/// How many nodes run this process, and how that compares with PostgreSQL's
/// `max_connections`, is deployment knowledge this crate doesn't have.
pub fn log_pool_capacity(config: &AppConfig) {
    let summary = pool_capacity_summary(
        config,
        attome_config::app_env().as_deref(),
        std::env::var("DATABASE_URL").ok().as_deref(),
    );
    tracing::info!(
        event = "db.pool.capacity",
        pools = %summary,
        not_counted = "direct pool (schema bootstrap and migrations only); unpooled \
                       sessions are exported live as db_unpooled_sessions_open (workflow \
                       claims <= jobs.worker_concurrency, attribute-index builds <= the \
                       index-build limit)",
        "database pool capacity for this process, per endpoint"
    );
}

/// The pure half of [`log_pool_capacity`]: `endpoint = total (pool max, ...)`
/// for each endpoint, sorted by endpoint and joined with `; `. Takes both env
/// values as parameters for the same reason [`resolve_runtime_url`] does, and
/// resolves the runtime pool's URL through it so the report matches what
/// `create_pool` really connects to.
fn pool_capacity_summary(
    config: &AppConfig,
    app_env: Option<&str>,
    database_url: Option<&str>,
) -> String {
    let mut pools = vec![
        (
            PoolRole::Runtime,
            resolve_runtime_url(config, app_env, database_url),
        ),
        (
            PoolRole::Migrator,
            resolve_migrator_url(config, app_env, database_url),
        ),
    ];
    if let Some(url) = config.readonly_database_url() {
        pools.push((PoolRole::Readonly, url));
    }
    if let Some(url) = config.readonly_primary_database_url() {
        pools.push((PoolRole::ReadonlyPrimary, url));
    }

    let mut by_endpoint: std::collections::BTreeMap<String, Vec<(PoolRole, u32)>> =
        std::collections::BTreeMap::new();
    for (role, url) in pools {
        by_endpoint
            .entry(endpoint_of(&url))
            .or_default()
            .push((role, pool_max_connections(role, config)));
    }
    by_endpoint
        .into_iter()
        .map(|(endpoint, pools)| {
            let total: u32 = pools.iter().map(|(_, max)| *max).sum();
            let detail = pools
                .iter()
                .map(|(role, max)| format!("{} {max}", role.application_name()))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{endpoint} = {total} ({detail})")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// `host:port` (or `socket-path:port`) of a connection URL, and nothing
/// else: credentials, database name and options never leave this function.
fn endpoint_of(url: &str) -> String {
    match PgConnectOptions::from_str(url) {
        Ok(options) => match options.get_socket() {
            Some(socket) => format!("{}:{}", socket.display(), options.get_port()),
            None => format!("{}:{}", options.get_host(), options.get_port()),
        },
        Err(_) => "<unparseable database URL>".to_string(),
    }
}

// P-db-privilege-separation follow-up (D-201) — pure-logic unit coverage for
// the `DATABASE_URL`/`APP_ENV` gate and the identity-mismatch comparison,
// which don't need a live Postgres. The parts of `create_pool`/
// `verify_pool_identity` that do (actually connecting, actually running
// `SELECT current_user, current_database()`) are covered separately by
// `tests/pool_identity.rs` (requires a live Postgres; it skips when
// `DATABASE_URL` is unset rather than being `#[ignore]`d).
#[cfg(test)]
mod tests {
    use super::{
        DIRECT_POOL_MAX_CONNECTIONS, PoolRole, database_timeout, identity_mismatch_message,
        migrator_connection_options_for, migrator_pool_connect_options_for, pool_connect_options,
        pool_options, resolve_migrator_url, resolve_runtime_url, runtime_session_options,
    };
    use attome_config::AppConfig;
    use sqlx::postgres::PgSslMode;

    use super::pool_capacity_summary;

    // attome-db hardening Phase 2.4 — the boot capacity report lists this
    // process's long-lived pools per endpoint, with their resolved sizes, and
    // never credentials.
    #[test]
    fn capacity_report_lists_runtime_and_migrator_by_default() {
        let config = config_with_database(serde_json::json!({}));
        assert_eq!(
            pool_capacity_summary(&config, None, None),
            "localhost:5555 = 2 (attome-runtime 1, attome-migrator 1)"
        );
    }

    #[test]
    fn capacity_report_groups_pools_by_endpoint_with_their_sizes() {
        let config = config_with_database(serde_json::json!({
            "connection_number": 5,
            "pools": { "runtime": { "max_connections": 20 } },
            "readonly": {
                "user": "ro", "password": "ro-secret", "host": "replica", "port": 5433
            },
        }));
        assert_eq!(
            pool_capacity_summary(&config, None, None),
            "localhost:5555 = 30 (attome-runtime 20, attome-migrator 5, \
             attome-readonly-primary 5); replica:5433 = 5 (attome-readonly 5)"
        );
    }

    #[test]
    fn capacity_report_follows_create_pools_url_and_never_prints_credentials() {
        let config = config_with_database(serde_json::json!({}));
        let summary = pool_capacity_summary(
            &config,
            Some("debug"),
            Some("postgres://ci_user:ci-secret@ci-host:6000/ci_db"),
        );
        assert_eq!(
            summary, "ci-host:6000 = 2 (attome-runtime 1, attome-migrator 1)",
            "C-33: in debug mode the migrator follows DATABASE_URL too"
        );
        for secret in [
            "ci-secret",
            "ci_user",
            "ci_db",
            "bootstrap_pw",
            "bootstrap_user",
        ] {
            assert!(
                !summary.contains(secret),
                "capacity report must not contain {secret:?}: {summary}"
            );
        }
    }

    // attome-db hardening Phase 2.2 — each role's connections carry their own
    // application_name, and the name is the only thing a role adds to the
    // connection target.
    const ALL_ROLES: [PoolRole; 5] = [
        PoolRole::Runtime,
        PoolRole::Readonly,
        PoolRole::ReadonlyPrimary,
        PoolRole::Migrator,
        PoolRole::Direct,
    ];

    #[test]
    fn every_role_connects_with_its_own_application_name() {
        let config = config_with_database(serde_json::json!({}));
        let url = config.database_url();
        let expected = [
            (PoolRole::Runtime, "attome-runtime"),
            (PoolRole::Readonly, "attome-readonly"),
            (PoolRole::ReadonlyPrimary, "attome-readonly-primary"),
            (PoolRole::Migrator, "attome-migrator"),
            (PoolRole::Direct, "attome-direct"),
        ];
        for (role, name) in expected {
            let options = pool_connect_options(role, &url, &config).expect("options must build");
            assert_eq!(options.get_application_name(), Some(name), "{role:?}");
        }
    }

    #[test]
    fn every_role_gets_the_same_tls_mode() {
        let config = config_with_database(serde_json::json!({ "ssl_mode": "require" }));
        let url = config.database_url();
        for role in ALL_ROLES {
            let options = pool_connect_options(role, &url, &config).expect("options must build");
            assert!(
                matches!(options.get_ssl_mode(), PgSslMode::Require),
                "{role:?} must use the configured ssl_mode"
            );
        }
    }

    #[test]
    fn the_migrator_connection_is_named_like_the_migrator_pool() {
        let config = config_with_database(serde_json::json!({
            "direct_url": "postgres://bootstrap_user:bootstrap_pw@direct-host:6543/attomedb_test",
        }));
        let options =
            migrator_connection_options_for(&config, None, None).expect("options must resolve");
        assert_eq!(options.get_application_name(), Some("attome-migrator"));
    }

    fn minimal_config() -> AppConfig {
        config_with_database(serde_json::json!({}))
    }

    // attome-db hardening Phase 2.1 — `pool_options` reproduces what the five
    // hand-written builders used to set. (The direct pool's session hook has
    // no getter; `tests/pool_session_settings.rs` checks it on a live pool.)
    const POOLED_ROLES: [PoolRole; 4] = [
        PoolRole::Runtime,
        PoolRole::Readonly,
        PoolRole::ReadonlyPrimary,
        PoolRole::Migrator,
    ];

    #[test]
    fn every_role_but_direct_is_sized_from_connection_number() {
        let config = config_with_database(serde_json::json!({ "connection_number": 7 }));
        for role in POOLED_ROLES {
            let options = pool_options(role, &config).expect("options must build");
            assert_eq!(options.get_max_connections(), 7, "{role:?}");
        }
        let direct = pool_options(PoolRole::Direct, &config).expect("options must build");
        assert_eq!(direct.get_max_connections(), DIRECT_POOL_MAX_CONNECTIONS);
        assert_eq!(DIRECT_POOL_MAX_CONNECTIONS, 2);
    }

    // attome-db hardening Phase 2.3 — a `database.pools` entry sizes only its
    // own pool; the rest keep `connection_number`, and the direct pool stays
    // fixed.
    #[test]
    fn a_pools_entry_sizes_only_its_own_pool() {
        let config = config_with_database(serde_json::json!({
            "connection_number": 7,
            "pools": {
                "runtime": { "max_connections": 20 },
                "migrator": { "max_connections": 2 },
            },
        }));
        let expected = [
            (PoolRole::Runtime, 20),
            (PoolRole::Readonly, 7),
            (PoolRole::ReadonlyPrimary, 7),
            (PoolRole::Migrator, 2),
            (PoolRole::Direct, DIRECT_POOL_MAX_CONNECTIONS),
        ];
        for (role, max_connections) in expected {
            let options = pool_options(role, &config).expect("options must build");
            assert_eq!(options.get_max_connections(), max_connections, "{role:?}");
        }
    }

    #[test]
    fn every_pools_entry_is_honored() {
        let config = config_with_database(serde_json::json!({
            "connection_number": 7,
            "pools": {
                "runtime": { "max_connections": 11 },
                "readonly": { "max_connections": 12 },
                "readonly_primary": { "max_connections": 13 },
                "migrator": { "max_connections": 14 },
            },
        }));
        let expected = [
            (PoolRole::Runtime, 11),
            (PoolRole::Readonly, 12),
            (PoolRole::ReadonlyPrimary, 13),
            (PoolRole::Migrator, 14),
        ];
        for (role, max_connections) in expected {
            let options = pool_options(role, &config).expect("options must build");
            assert_eq!(options.get_max_connections(), max_connections, "{role:?}");
        }
    }

    // BDB-F12 (4.3) — the pool lifecycle options are chosen, not inherited:
    // pinning them here means a sqlx bump that changes a default fails this
    // test instead of silently changing connection lifecycle behavior.
    #[test]
    fn lifecycle_options_are_pinned() {
        let config = config_with_database(serde_json::json!({}));
        let options = pool_options(PoolRole::Runtime, &config).expect("options must build");
        assert_eq!(options.get_min_connections(), 0);
        assert_eq!(
            options.get_idle_timeout(),
            Some(std::time::Duration::from_secs(600))
        );
        assert_eq!(
            options.get_max_lifetime(),
            Some(std::time::Duration::from_secs(1800))
        );
        assert!(options.get_test_before_acquire());
        assert_eq!(
            options.get_acquire_slow_threshold(),
            std::time::Duration::from_secs(2)
        );
    }

    #[test]
    fn every_role_uses_the_database_timeout_as_its_acquire_timeout() {
        let config = config_with_database(serde_json::json!({ "timeout": 0.5 }));
        for role in POOLED_ROLES.into_iter().chain([PoolRole::Direct]) {
            let options = pool_options(role, &config).expect("options must build");
            assert_eq!(
                options.get_acquire_timeout(),
                std::time::Duration::from_millis(500),
                "{role:?}"
            );
        }
    }

    #[test]
    fn an_invalid_timeout_fails_every_role_instead_of_panicking() {
        let mut config = minimal_config();
        config.database.timeout = -1.0;
        for role in POOLED_ROLES.into_iter().chain([PoolRole::Direct]) {
            assert!(pool_options(role, &config).is_err(), "{role:?}");
        }
    }

    // attome-db hardening Phase 1.1 — the pool acquire timeout keeps fractional
    // seconds, and a value `validate` would refuse is an error, not a panic.
    #[test]
    fn database_timeout_keeps_fractional_seconds() {
        let config = config_with_database(serde_json::json!({ "timeout": 0.5 }));
        assert_eq!(
            database_timeout(&config).expect("0.5 is a valid timeout"),
            std::time::Duration::from_millis(500)
        );
    }

    #[test]
    fn database_timeout_rejects_invalid_values_without_panicking() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let mut config = minimal_config();
            config.database.timeout = bad;
            assert!(
                database_timeout(&config).is_err(),
                "database.timeout {bad} must be a configuration error"
            );
        }
    }

    // Same minimal-fixture shape as `crates/server/src/boot.rs`'s own
    // `config_with` test helper (duplicated here rather than exported
    // cross-crate for a single test-only fixture — that file's own comment
    // documents this as the established convention): every section filled
    // with throwaway values so `serde_json::from_value` succeeds.
    // `idempotency`/`approval` are omitted since both are `#[serde(default)]`
    // on `AppConfig` and this fixture never needs to set them.
    // `database_overrides` keys replace or extend the `database` section.
    fn config_with_database(database_overrides: serde_json::Value) -> AppConfig {
        let mut json = serde_json::json!({
            "app": {
                "port": 0, "frontend_host": "localhost", "frontend_port": 4200,
                "log_level": "error", "threads": 1, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "idle_connection_timeout": 30,
                "keepalive_requests": 100, "static_files_cache_time": 0,
                "server_header_field": "test"
            },
            "database": {
                "host": "localhost", "port": 5555, "dbname": "attomedb_test",
                "user": "bootstrap_user", "password": "bootstrap_pw", "schema": "attome_dev",
                "connection_number": 1, "timeout": 5.0
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
        });
        if let (Some(database), Some(overrides)) = (
            json["database"].as_object_mut(),
            database_overrides.as_object(),
        ) {
            for (key, value) in overrides {
                database.insert(key.clone(), value.clone());
            }
        }
        serde_json::from_value(json).expect("test config must deserialize")
    }

    // D-497 — `create_migrator_connection`'s endpoint/identity resolution.
    #[test]
    fn migrator_connection_uses_direct_url_endpoint_with_migrator_credentials() {
        let config = config_with_database(serde_json::json!({
            "direct_url": "postgres://bootstrap_user:bootstrap_pw@direct-host:6543/attomedb_test",
            "migrator": { "user": "attome_migrator", "password": "migrator_pw" },
        }));
        let options =
            migrator_connection_options_for(&config, None, None).expect("options must resolve");
        assert_eq!(options.get_host(), "direct-host");
        assert_eq!(options.get_port(), 6543);
        assert_eq!(
            options.get_username(),
            "attome_migrator",
            "the endpoint comes from direct_url, but never its bootstrap credentials"
        );
        assert_eq!(options.get_database(), Some("attomedb_test"));
        assert!(
            options
                .get_options()
                .is_some_and(|o| o.contains("search_path=attome_dev")),
            "search_path must be kept from migrator_database_url, got {:?}",
            options.get_options()
        );
    }

    #[test]
    fn migrator_connection_without_direct_url_uses_database_host() {
        let config = config_with_database(serde_json::json!({
            "migrator": { "user": "attome_migrator", "password": "migrator_pw" },
        }));
        let options =
            migrator_connection_options_for(&config, None, None).expect("options must resolve");
        assert_eq!(options.get_host(), "localhost");
        assert_eq!(options.get_port(), 5555);
        assert_eq!(options.get_username(), "attome_migrator");
    }

    #[test]
    fn migrator_connection_without_migrator_block_keeps_bootstrap_identity() {
        let config = config_with_database(serde_json::json!({
            "direct_url": "postgres://someone_else:pw@direct-host:6543/attomedb_test",
        }));
        let options =
            migrator_connection_options_for(&config, None, None).expect("options must resolve");
        assert_eq!(options.get_host(), "direct-host");
        assert_eq!(
            options.get_username(),
            "bootstrap_user",
            "with database.migrator unset the identity stays database.user, as before D-497"
        );
    }

    // M01 C-33 — the migrator honours the same debug-only `DATABASE_URL`
    // override as the runtime pool, so bootstrap and provisioning DDL land on
    // the database the runtime pool writes to.
    #[test]
    fn migrator_debug_env_prefers_database_url_over_config() {
        let config = minimal_config();
        let url = resolve_migrator_url(&config, Some("debug"), Some("postgres://ci-convenience"));
        assert_eq!(url, "postgres://ci-convenience");
    }

    #[test]
    fn migrator_debug_env_without_database_url_falls_back_to_config() {
        let config = minimal_config();
        let url = resolve_migrator_url(&config, Some("debug"), None);
        assert_eq!(url, config.migrator_database_url());
    }

    #[test]
    fn migrator_non_debug_ignores_database_url_even_if_set() {
        let config = minimal_config();
        for app_env in [None, Some("production")] {
            let url = resolve_migrator_url(&config, app_env, Some("postgres://stale-leftover-url"));
            assert_eq!(
                url,
                config.migrator_database_url(),
                "outside APP_ENV=debug, DATABASE_URL must never override the migrator identity"
            );
        }
    }

    #[test]
    fn migrator_connection_debug_override_replaces_direct_endpoint_wholesale() {
        let config = config_with_database(serde_json::json!({
            "direct_url": "postgres://bootstrap_user:bootstrap_pw@direct-host:6543/attomedb_test",
            "migrator": { "user": "attome_migrator", "password": "migrator_pw" },
        }));
        let options = migrator_connection_options_for(
            &config,
            Some("debug"),
            Some("postgres://ci_user:ci-secret@ci-host:6000/ci_db"),
        )
        .expect("options must resolve");
        assert_eq!(
            options.get_host(),
            "ci-host",
            "the override names a concrete instance; it is not spliced with direct_url"
        );
        assert_eq!(options.get_port(), 6000);
        assert_eq!(
            options.get_username(),
            "attome_migrator",
            "the override picks the endpoint; a configured database.migrator keeps its identity, \
             which is what boot's identity check expects"
        );
        assert_eq!(options.get_database(), Some("ci_db"));
    }

    #[test]
    fn migrator_pool_debug_override_keeps_configured_migrator_credentials() {
        let config = config_with_database(serde_json::json!({
            "migrator": { "user": "attome_migrator", "password": "migrator_pw" },
        }));
        let options = migrator_pool_connect_options_for(
            &config,
            Some("debug"),
            Some("postgres://ci_user:ci-secret@ci-host:6000/ci_db"),
        )
        .expect("options must resolve");
        assert_eq!(options.get_host(), "ci-host");
        assert_eq!(options.get_port(), 6000);
        assert_eq!(options.get_database(), Some("ci_db"));
        assert_eq!(options.get_username(), "attome_migrator");
    }

    /// C-33's own case: no database.migrator, so the override's credentials
    /// stand for both the pool and the unpooled connection.
    #[test]
    fn migrator_debug_override_without_migrator_block_uses_override_credentials() {
        let config = config_with_database(serde_json::json!({}));
        let override_url = Some("postgres://ci_user:ci-secret@ci-host:6000/ci_db");
        let pool = migrator_pool_connect_options_for(&config, Some("debug"), override_url)
            .expect("options must resolve");
        let conn = migrator_connection_options_for(&config, Some("debug"), override_url)
            .expect("options must resolve");
        for options in [pool, conn] {
            assert_eq!(options.get_host(), "ci-host");
            assert_eq!(options.get_username(), "ci_user");
            assert_eq!(options.get_database(), Some("ci_db"));
        }
    }

    #[test]
    fn migrator_pool_outside_debug_uses_config_identity() {
        let config = config_with_database(serde_json::json!({
            "migrator": { "user": "attome_migrator", "password": "migrator_pw" },
        }));
        let options = migrator_pool_connect_options_for(
            &config,
            None,
            Some("postgres://ci_user:ci-secret@ci-host:6000/ci_db"),
        )
        .expect("options must resolve");
        assert_eq!(options.get_host(), "localhost");
        assert_eq!(options.get_username(), "attome_migrator");
    }

    #[test]
    fn debug_env_prefers_database_url_over_config() {
        let config = minimal_config();
        let url = resolve_runtime_url(&config, Some("debug"), Some("postgres://ci-convenience"));
        assert_eq!(url, "postgres://ci-convenience");
    }

    #[test]
    fn debug_env_without_database_url_falls_back_to_config() {
        let config = minimal_config();
        let url = resolve_runtime_url(&config, Some("debug"), None);
        assert_eq!(url, config.runtime_database_url());
    }

    #[test]
    fn non_debug_ignores_database_url_even_if_set() {
        let config = minimal_config();
        let url = resolve_runtime_url(&config, None, Some("postgres://stale-leftover-url"));
        assert_eq!(
            url,
            config.runtime_database_url(),
            "outside APP_ENV=debug, DATABASE_URL must never override the runtime pool's identity \
             — this is the exact gap D-201 closed"
        );
    }

    #[test]
    fn non_debug_app_env_value_also_ignores_database_url() {
        let config = minimal_config();
        let url = resolve_runtime_url(&config, Some("production"), Some("postgres://stale"));
        assert_eq!(url, config.runtime_database_url());
    }

    #[test]
    fn matching_identity_has_no_mismatch() {
        assert!(
            identity_mismatch_message("attome_runtime", "attomedb", "attome_runtime", "attomedb")
                .is_none()
        );
    }

    #[test]
    fn user_mismatch_is_reported() {
        let message =
            identity_mismatch_message("postgres", "attomedb", "attome_runtime", "attomedb")
                .expect("a role mismatch must be reported, never silently accepted");
        assert!(message.contains("postgres"), "got: {message}");
        assert!(message.contains("attome_runtime"), "got: {message}");
    }

    #[test]
    fn dbname_mismatch_is_reported() {
        let message =
            identity_mismatch_message("attome_runtime", "wrong_db", "attome_runtime", "attomedb")
                .expect("a database mismatch must be reported, never silently accepted");
        assert!(message.contains("wrong_db"), "got: {message}");
        assert!(message.contains("attomedb"), "got: {message}");
    }

    #[test]
    fn mismatch_on_both_fields_reports_all_four_values() {
        let message =
            identity_mismatch_message("role_a", "db_a", "role_b", "db_b").expect("must mismatch");
        assert!(message.contains("role_a") && message.contains("role_b"));
        assert!(message.contains("db_a") && message.contains("db_b"));
    }

    // BDB-F1 / D-612 (1.1a) — the runtime session takes the direct_url
    // endpoint and the database.runtime identity: never direct_url's own
    // bootstrap credentials, never database.user, and its own
    // application_name so pg_stat_activity can tell it from the pool.
    #[test]
    fn runtime_session_uses_direct_url_endpoint_with_runtime_credentials() {
        let config = config_with_database(serde_json::json!({
            "direct_url": "postgres://bootstrap_user:bootstrap_pw@direct-host:6543/attomedb_test",
            "runtime": { "user": "attome_runtime", "password": "runtime_pw" },
        }));
        let options = runtime_session_options(&config, None, None).expect("options must resolve");
        assert_eq!(options.get_host(), "direct-host");
        assert_eq!(options.get_port(), 6543);
        assert_eq!(
            options.get_username(),
            "attome_runtime",
            "the endpoint comes from direct_url, but never its bootstrap credentials"
        );
        assert_eq!(options.get_database(), Some("attomedb_test"));
        assert_eq!(
            options.get_application_name(),
            Some("attome-runtime-session")
        );
        assert!(
            options
                .get_options()
                .is_some_and(|o| o.contains("search_path=attome_dev")),
            "search_path must come from the runtime identity, got {:?}",
            options.get_options()
        );
    }

    #[test]
    fn runtime_session_app_name_is_distinct_from_the_runtime_pool() {
        let config = config_with_database(serde_json::json!({}));
        let session = runtime_session_options(&config, Some("debug"), None).unwrap();
        let pool = pool_connect_options(PoolRole::Runtime, &config.database_url(), &config)
            .expect("options must build");
        assert_eq!(
            session.get_application_name(),
            Some("attome-runtime-session")
        );
        assert_ne!(session.get_application_name(), pool.get_application_name());
    }

    // D-324 makes database.password optional; a config rendered that way must
    // never make a runtime session authenticate as database.user. This is the
    // unit half of P0-1.
    #[test]
    fn a_d_324_config_never_resolves_a_runtime_session_to_database_user() {
        let config = config_with_database(serde_json::json!({
            "password": null,
            "direct_url": "postgres://postgres@direct-host:6543/attomedb_test",
            "runtime": { "user": "attome_runtime", "password": "runtime_pw" },
        }));
        let options = runtime_session_options(&config, None, None).expect("options must resolve");
        assert_eq!(options.get_username(), "attome_runtime");
        assert_ne!(options.get_username(), config.database.user);
    }

    // D-612 item 3 — outside APP_ENV=debug an unconfigured database.runtime
    // is a configuration error, never a silent bootstrap fallback.
    #[test]
    fn runtime_session_outside_debug_refuses_an_unconfigured_runtime_identity() {
        let config = config_with_database(serde_json::json!({}));
        let err = runtime_session_options(&config, None, None)
            .expect_err("an unconfigured database.runtime must refuse, not fall back");
        assert!(
            err.to_string().contains("database.runtime"),
            "the refusal must name the config key to set, got: {err}"
        );
        assert!(
            runtime_session_options(&config, Some("debug"), None).is_ok(),
            "APP_ENV=debug is the one tolerated fallback"
        );
    }

    // Same shape as the migrator session (M01 C-33): a debug-mode DATABASE_URL
    // override names a concrete instance wholesale.
    #[test]
    fn runtime_session_debug_override_names_a_concrete_instance() {
        let config = config_with_database(serde_json::json!({
            "runtime": { "user": "attome_runtime", "password": "runtime_pw" },
        }));
        let options = runtime_session_options(
            &config,
            Some("debug"),
            Some("postgres://ci_user:ci-secret@ci-host:6000/ci_db"),
        )
        .expect("options must resolve");
        assert_eq!(options.get_host(), "ci-host");
        assert_eq!(options.get_port(), 6000);
        assert_eq!(options.get_username(), "ci_user");
        assert_eq!(options.get_database(), Some("ci_db"));
        assert_eq!(
            options.get_application_name(),
            Some("attome-runtime-session")
        );
    }
}
