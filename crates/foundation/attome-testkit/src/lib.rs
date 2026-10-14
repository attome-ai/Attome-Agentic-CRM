//! `attome-testkit`: shared support for database-backed tests.
//!
//! **One throwaway database per test process.** When `DATABASE_URL` points at
//! a PostgreSQL server, the first call to [`test_db_url`] in a process
//! creates a fresh, empty database on that server (named `attome_t_<uuid>`),
//! rewrites `DATABASE_URL` to point at it, and returns its URL. Every later
//! call returns the same URL. Each crate's tests apply the migrations they
//! need themselves.
//!
//! **Migrated databases are copies of a template.** The first process that
//! needs a migrated database on a server builds `attome_tmpl_<hash>` (every
//! migration applied, the hash over the migrations' versions and checksums);
//! every process then gets `CREATE DATABASE ... TEMPLATE` of it, which takes a
//! fraction of a second instead of a full migration run.
//!
//! **Two databases, both empty of data.** [`test_db_url`] is bare: crates that
//! test schema machinery (attome-db's migrator) apply their own fixtures to
//! it. [`migrated_db_url`] is a second one with every migration in
//! `crates/apps/attome/migrations` applied, for crates whose code reads and
//! writes the platform's own tables (jobs, email, ...).
//!
//! **Skip locally, fail in CI.** With no `DATABASE_URL`, database tests print
//! a `SKIP` line and return, so `cargo test` on a machine without Postgres is
//! green but honest about it. With [`REQUIRE_DB_ENV`] set (as the Linux CI job
//! does, next to its Postgres service), a missing database is a failure
//! instead: there it means the wiring broke.
//!
//! **Redis too.** [`test_redis`] and [`skip_if_no_redis!`] do the same for
//! tests that need Redis or Dragonfly, from `TEST_REDIS_HOST`/`TEST_REDIS_PORT`,
//! with [`REQUIRE_REDIS_ENV`] as the switch that makes a skip a failure.
//!
//! **Never a real database.** The URL's database name must not look like a
//! development or production database; [`test_db_url`] refuses names
//! containing `dev`, `prod` or `live`.

use std::sync::OnceLock;

use sqlx::Connection;
use sqlx::postgres::{PgConnection, PgPoolOptions};
use uuid::Uuid;

/// Set this to turn a missing test database into a failure.
pub const REQUIRE_DB_ENV: &str = "ATTOME_TEST_REQUIRE_DB";

/// Default pool size for a test that does not ask for one.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 5;

/// Words that mark a database this crate must never touch.
const FORBIDDEN_NAME_PARTS: [&str; 3] = ["dev", "prod", "live"];

/// This test process's throwaway database URL, or `None` when no test
/// database is configured. Panics when one is required ([`REQUIRE_DB_ENV`])
/// but missing or unusable; the outcome is decided once per process.
pub fn test_db_url() -> Option<String> {
    static URL: OnceLock<Result<Option<String>, String>> = OnceLock::new();
    match URL.get_or_init(|| provision(false)) {
        Ok(url) => url.clone(),
        Err(error) => panic!("attome-testkit: {error}"),
    }
}

/// This test process's migrated throwaway database URL: a second database,
/// separate from [`test_db_url`]'s, with every migration in
/// `crates/apps/attome/migrations` applied once. `None` when no test database
/// is configured; panics like [`test_db_url`] when one is required.
pub fn migrated_db_url() -> Option<String> {
    static URL: OnceLock<Result<Option<String>, String>> = OnceLock::new();
    match URL.get_or_init(|| provision(true)) {
        Ok(url) => url.clone(),
        Err(error) => panic!("attome-testkit: {error}"),
    }
}

/// A pool on this process's bare throwaway database, or `None` (see
/// [`test_db_url`]).
pub async fn test_pool(max_connections: u32) -> Option<sqlx::PgPool> {
    Some(connect(&test_db_url()?, max_connections).await)
}

/// A pool on this process's migrated throwaway database, or `None` (see
/// [`migrated_db_url`]).
pub async fn migrated_pool(max_connections: u32) -> Option<sqlx::PgPool> {
    Some(connect(&migrated_db_url()?, max_connections).await)
}

/// A pool on `url`; panics when it cannot connect.
pub async fn connect(url: &str, max_connections: u32) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await
        .unwrap_or_else(|error| panic!("attome-testkit: connect to the test database: {error}"))
}

/// A one-connection pool on this process's migrated database: proves a code
/// path never needs a second connection while its own transaction holds the
/// first.
pub async fn single_connection_pool() -> Option<sqlx::PgPool> {
    migrated_pool(1).await
}

/// The remedy printed on every `SKIP` line.
pub fn skip_remedy() -> String {
    format!("set {REQUIRE_DB_ENV}=1 to make a skip here a failure")
}

fn database_required() -> bool {
    std::env::var_os(REQUIRE_DB_ENV).is_some()
}

/// The server URL the test databases are created on: `DATABASE_URL` as the
/// process started, captured before [`provision`] rewrites it.
fn server_url() -> Option<String> {
    static BASE: OnceLock<Option<String>> = OnceLock::new();
    BASE.get_or_init(|| {
        std::env::var("DATABASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())
    })
    .clone()
}

fn provision(migrate: bool) -> Result<Option<String>, String> {
    let Some(base) = server_url() else {
        if database_required() {
            return Err(format!(
                "DATABASE_URL is not set, and {REQUIRE_DB_ENV} requires a test database"
            ));
        }
        return Ok(None);
    };

    let mut url =
        url::Url::parse(&base).map_err(|error| format!("DATABASE_URL is not a URL: {error}"))?;
    let current = url.path().trim_start_matches('/').to_ascii_lowercase();
    if let Some(part) = FORBIDDEN_NAME_PARTS
        .iter()
        .find(|part| current.contains(*part))
    {
        return Err(format!(
            "refusing DATABASE_URL: its database name `{current}` contains `{part}`; point it at a \
             throwaway server database such as `postgres`"
        ));
    }

    let name = format!("attome_t_{}", Uuid::now_v7().simple());
    url.set_path(&format!("/{name}"));
    let test_url = url.to_string();
    // The database is created (and migrated) from a separate thread with its
    // own runtime, so this works whether or not the caller is already inside
    // a Tokio runtime.
    let admin_url = base.clone();
    let create_name = name.clone();
    let migrate_url = test_url.clone();
    std::thread::spawn(move || {
        create_database(
            &admin_url,
            &create_name,
            migrate.then_some(migrate_url.as_str()),
        )
    })
    .join()
    .map_err(|_| "creating the test database panicked".to_owned())??;

    if migrate {
        // The bare database's URL is what `DATABASE_URL` points at; the
        // migrated one is reached only through `migrated_db_url`.
        return Ok(Some(test_url));
    }
    // SAFETY: `set_var` is unsafe because another thread may read the
    // environment at the same moment. This runs once per process, inside the
    // `OnceLock` initialiser, before any test reads `DATABASE_URL` through
    // this crate; tests that read it directly do so after calling
    // `test_db_url`, which is the point of rewriting it.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("DATABASE_URL", &test_url);
    }
    Ok(Some(test_url))
}

/// Every migration in `crates/apps/attome/migrations`, embedded at compile
/// time.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../apps/attome/migrations");

/// Server-wide advisory lock key serializing test-database migrations.
const MIGRATE_LOCK_KEY: i64 = 0x41_54_54_4f_4d_45_01;

/// The name of the migrated template database for this set of migrations:
/// `attome_tmpl_` and an FNV-1a hash of every migration's version and
/// checksum, so a changed or added migration gets a new template.
fn template_name() -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for migration in MIGRATOR.iter() {
        for byte in migration
            .version
            .to_le_bytes()
            .iter()
            .chain(migration.checksum.iter())
        {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("attome_tmpl_{hash:016x}")
}

/// Creates `name` on the server. With `migrate_url`, the database is a copy
/// of the migrated template (built once per migration set and server, under
/// a server-wide advisory lock), which is much faster than migrating every
/// test process's database from scratch.
fn create_database(admin_url: &str, name: &str, migrate_url: Option<&str>) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start a runtime: {error}"))?;
    runtime.block_on(async {
        let mut conn = PgConnection::connect(admin_url)
            .await
            .map_err(|error| format!("connect DATABASE_URL: {error}"))?;
        if migrate_url.is_none() {
            sqlx::query(&format!("CREATE DATABASE \"{name}\""))
                .execute(&mut conn)
                .await
                .map_err(|error| format!("CREATE DATABASE {name}: {error}"))?;
            return conn
                .close()
                .await
                .map_err(|error| format!("close: {error}"));
        }

        // Migration 0009 creates and alters cluster-wide roles, which two
        // processes migrating at once race on ("tuple concurrently
        // updated"), and the template must be built once. One session lock on
        // the server, held while the template is checked, built and copied,
        // serializes all of it; closing the session releases it.
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(MIGRATE_LOCK_KEY)
            .execute(&mut conn)
            .await
            .map_err(|error| format!("lock for migration: {error}"))?;
        let template = template_name();
        // A finished template is marked `datistemplate`; one without the mark
        // is left over from a run that died while building it.
        let state: Option<bool> =
            sqlx::query_scalar("SELECT datistemplate FROM pg_database WHERE datname = $1")
                .bind(&template)
                .fetch_optional(&mut conn)
                .await
                .map_err(|error| format!("look up {template}: {error}"))?;
        if state != Some(true) {
            if state.is_some() {
                sqlx::query(&format!("DROP DATABASE \"{template}\" WITH (FORCE)"))
                    .execute(&mut conn)
                    .await
                    .map_err(|error| format!("DROP DATABASE {template}: {error}"))?;
            }
            sqlx::query(&format!("CREATE DATABASE \"{template}\""))
                .execute(&mut conn)
                .await
                .map_err(|error| format!("CREATE DATABASE {template}: {error}"))?;
            let mut template_url = url::Url::parse(admin_url)
                .map_err(|error| format!("DATABASE_URL is not a URL: {error}"))?;
            template_url.set_path(&format!("/{template}"));
            let mut migrating = PgConnection::connect(template_url.as_str())
                .await
                .map_err(|error| format!("connect {template}: {error}"))?;
            MIGRATOR
                .run(&mut migrating)
                .await
                .map_err(|error| format!("migrate {template}: {error}"))?;
            migrating
                .close()
                .await
                .map_err(|error| format!("close: {error}"))?;
            sqlx::query(&format!("ALTER DATABASE \"{template}\" IS_TEMPLATE true"))
                .execute(&mut conn)
                .await
                .map_err(|error| format!("mark {template} as a template: {error}"))?;
        }
        sqlx::query(&format!(
            "CREATE DATABASE \"{name}\" TEMPLATE \"{template}\""
        ))
        .execute(&mut conn)
        .await
        .map_err(|error| format!("CREATE DATABASE {name} from {template}: {error}"))?;
        // Database-level grants are not copied with the template; restore the
        // one migration 0009 makes.
        sqlx::query(&format!(
            "GRANT CONNECT ON DATABASE \"{name}\" TO attome_readonly, attome_migrator, attome_runtime"
        ))
        .execute(&mut conn)
        .await
        .map_err(|error| format!("grant connect on {name}: {error}"))?;
        conn.close()
            .await
            .map_err(|error| format!("close: {error}"))
    })
}

/// Binds a live pool, or prints why it is skipping and returns from the
/// calling test.
///
/// ```ignore
/// let db = db_pool_or_skip!();      // DEFAULT_MAX_CONNECTIONS
/// let db = db_pool_or_skip!(20);    // a test that races connections
/// ```
#[macro_export]
macro_rules! db_pool_or_skip {
    () => {
        $crate::db_pool_or_skip!($crate::DEFAULT_MAX_CONNECTIONS)
    };
    ($max_connections:expr) => {
        match $crate::test_pool($max_connections).await {
            Some(db) => db,
            None => {
                eprintln!(
                    "SKIP {}:{}: set DATABASE_URL to a throwaway Postgres server to run this; {}",
                    module_path!(),
                    line!(),
                    $crate::skip_remedy(),
                );
                return;
            }
        }
    };
}

/// [`db_pool_or_skip!`] for the migrated database ([`migrated_pool`]).
///
/// ```ignore
/// let db = migrated_pool_or_skip!();
/// ```
#[macro_export]
macro_rules! migrated_pool_or_skip {
    () => {
        $crate::migrated_pool_or_skip!($crate::DEFAULT_MAX_CONNECTIONS)
    };
    ($max_connections:expr) => {
        match $crate::migrated_pool($max_connections).await {
            Some(db) => db,
            None => {
                eprintln!(
                    "SKIP {}:{}: set DATABASE_URL to a throwaway Postgres server to run this; {}",
                    module_path!(),
                    line!(),
                    $crate::skip_remedy(),
                );
                return;
            }
        }
    };
}

/// Unwraps an `Option`, or prints why it is skipping and returns from the
/// calling test.
///
/// ```ignore
/// let state = skip_if_no_db!(test_state().await);
/// ```
#[macro_export]
macro_rules! skip_if_no_db {
    ($opt:expr) => {
        match $opt {
            Some(value) => value,
            None => {
                eprintln!(
                    "SKIP {}:{}: set DATABASE_URL to a throwaway Postgres server to run this; {}",
                    module_path!(),
                    line!(),
                    $crate::skip_remedy(),
                );
                return;
            }
        }
    };
}

/// Set this to turn a missing test Redis into a failure.
pub const REQUIRE_REDIS_ENV: &str = "ATTOME_TEST_REQUIRE_REDIS";

/// The test Redis (or Dragonfly) as `(host, port)`, from `TEST_REDIS_HOST` and
/// `TEST_REDIS_PORT` (defaults `127.0.0.1` and `6379` when only one is set),
/// or `None` when neither is set. Panics when [`REQUIRE_REDIS_ENV`] is set
/// but no Redis is configured, or the port is not a number.
pub fn test_redis() -> Option<(String, u16)> {
    let read = |name: &str| {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
    };
    let host = read("TEST_REDIS_HOST");
    let port = read("TEST_REDIS_PORT");
    if host.is_none() && port.is_none() {
        assert!(
            std::env::var_os(REQUIRE_REDIS_ENV).is_none(),
            "attome-testkit: TEST_REDIS_HOST/TEST_REDIS_PORT are not set, and \
             {REQUIRE_REDIS_ENV} requires a test Redis"
        );
        return None;
    }
    let port = port
        .map_or(Ok(6379), |port| port.parse::<u16>())
        .unwrap_or_else(|error| {
            panic!("attome-testkit: TEST_REDIS_PORT is not a port number: {error}")
        });
    Some((host.unwrap_or_else(|| "127.0.0.1".to_owned()), port))
}

/// Unwraps an `Option`, or prints why it is skipping because no test Redis is
/// configured and returns from the calling test.
///
/// ```ignore
/// let pool = skip_if_no_redis!(test_pool().await);
/// ```
#[macro_export]
macro_rules! skip_if_no_redis {
    ($opt:expr) => {
        match $opt {
            Some(value) => value,
            None => {
                eprintln!(
                    "SKIP {}:{}: set TEST_REDIS_HOST/TEST_REDIS_PORT to a throwaway Redis to run \
                     this; set {}=1 to make a skip here a failure",
                    module_path!(),
                    line!(),
                    $crate::REQUIRE_REDIS_ENV,
                );
                return;
            }
        }
    };
}

/// A token stable for this process and different on every run.
pub fn run_id() -> &'static str {
    static RUN_ID: OnceLock<String> = OnceLock::new();
    RUN_ID.get_or_init(|| short(Uuid::now_v7()))
}

/// `prefix` with a fresh suffix, unique per call.
pub fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", short(Uuid::now_v7()))
}

/// A unique entity logical name: `prefix` plus a fresh suffix, lowercase and
/// underscore-separated, so a test's entity never collides with another's.
pub fn unique_logicalname(prefix: &str) -> String {
    format!("{prefix}_{}", short(Uuid::now_v7()))
}

/// A unique address at the reserved `.invalid` domain (RFC 2606), so a test
/// fixture can never be delivered.
pub fn unique_email(prefix: &str) -> String {
    format!("{}@example.invalid", unique(prefix))
}

fn short(id: Uuid) -> String {
    id.simple().to_string()[20..].to_owned()
}

/// An empty throwaway database of its own (no migrations), for a test that
/// runs migrations or a full boot itself. Dropped, with `WITH (FORCE)`, when
/// this value is dropped, so a test need not close its pools first.
#[derive(Debug)]
pub struct EmptyDatabase {
    name: String,
    url: String,
    admin_url: String,
}

impl EmptyDatabase {
    /// Connection URL for this database: the configured URL with only the
    /// database name swapped.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The database's name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for EmptyDatabase {
    fn drop(&mut self) {
        let admin_url = self.admin_url.clone();
        let name = self.name.clone();
        let dropped = std::thread::spawn(move || -> Result<(), String> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("start a runtime: {error}"))?;
            runtime.block_on(async {
                let mut conn = PgConnection::connect(&admin_url)
                    .await
                    .map_err(|error| format!("connect: {error}"))?;
                sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
                    .execute(&mut conn)
                    .await
                    .map_err(|error| format!("DROP DATABASE: {error}"))?;
                Ok(())
            })
        })
        .join();
        // Warn, never panic: a panicking Drop during an unwinding test would
        // replace the real failure with a cleanup message.
        if !matches!(dropped, Ok(Ok(()))) {
            eprintln!(
                "warning: failed to drop the throwaway database `{}`",
                self.name
            );
        }
    }
}

/// Creates an empty throwaway database, or `None` when no test database is
/// configured (and panics when one is required, like [`test_db_url`]).
/// `purpose` goes into the name, so a leftover is recognisable.
pub async fn empty_database(purpose: &str) -> Option<EmptyDatabase> {
    let Some(base) = server_url() else {
        assert!(
            !database_required(),
            "attome-testkit: DATABASE_URL is not set, and {REQUIRE_DB_ENV} requires a test database"
        );
        return None;
    };
    let purpose: String = purpose
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .take(20)
        .collect();
    let name = format!("attome_e_{purpose}_{}", short(Uuid::now_v7()));
    let mut url = url::Url::parse(&base)
        .unwrap_or_else(|error| panic!("attome-testkit: DATABASE_URL is not a URL: {error}"));
    url.set_path(&format!("/{name}"));
    let mut conn = PgConnection::connect(&base)
        .await
        .unwrap_or_else(|error| panic!("attome-testkit: connect DATABASE_URL: {error}"));
    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&mut conn)
        .await
        .unwrap_or_else(|error| panic!("attome-testkit: CREATE DATABASE {name}: {error}"));
    let _ = conn.close().await;
    Some(EmptyDatabase {
        name,
        url: url.to_string(),
        admin_url: base,
    })
}

/// The parts of a PostgreSQL URL a configuration's `database` section needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbUrlParts {
    /// The login role.
    pub user: String,
    /// The decoded password; empty when the URL carries none.
    pub password: String,
    /// Host name, address, or socket directory.
    pub host: String,
    /// Port; 5432 when the URL names none.
    pub port: u16,
    /// The database the driver will connect to.
    pub dbname: String,
}

impl DbUrlParts {
    /// Parses `url`; the error never carries the password.
    pub fn parse(url: &str) -> Result<Self, String> {
        let parsed = url::Url::parse(url).map_err(|error| format!("not a URL: {error}"))?;
        let dbname = parsed.path().trim_start_matches('/').to_owned();
        if dbname.is_empty() {
            return Err("the URL names no database".to_owned());
        }
        Ok(Self {
            user: percent_decode(parsed.username()),
            password: parsed.password().map(percent_decode).unwrap_or_default(),
            host: parsed.host_str().unwrap_or("localhost").to_owned(),
            port: parsed.port().unwrap_or(5432),
            dbname: percent_decode(&dbname),
        })
    }
}

/// Percent-decodes one URL component (`+` stays literal).
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Points `config.database` at `url`: the pool builders read their endpoint
/// and credentials from the configuration, never from `DATABASE_URL`. Panics
/// on an unparseable URL (test setup); the message never carries the password.
#[cfg(feature = "app-config")]
pub fn point_config_at(config: &mut attome_config::AppConfig, url: &str) {
    let parts = DbUrlParts::parse(url).unwrap_or_else(|msg| panic!("point_config_at: {msg}"));
    config.database.host = parts.host;
    config.database.port = parts.port;
    config.database.user = parts.user;
    config.database.password = (!parts.password.is_empty()).then_some(parts.password);
    config.database.dbname = parts.dbname;
}

/// `config` with its dedicated role credentials removed, so a pool built from
/// it connects as the bootstrap identity in `database.user`. The role-seed
/// tests need that: they create the `attome_runtime`/`attome_migrator` logins
/// themselves, so connecting as those roles first would fail.
#[cfg(feature = "app-config")]
pub fn bootstrap_identity(config: &attome_config::AppConfig) -> attome_config::AppConfig {
    let mut bootstrap = config.clone();
    bootstrap.database.runtime = None;
    bootstrap.database.migrator = None;
    bootstrap.database.readonly = None;
    bootstrap
}

/// `config` pointed at this process's throwaway database: the migrated one
/// when `migrated` is true, the bare one otherwise. Left unchanged when no
/// test database is configured, so the caller's skip path still works. A
/// test's config builder ends with this, so every pool built from it reaches
/// the throwaway database whatever `APP_ENV` is.
#[cfg(feature = "app-config")]
pub fn with_test_database(
    mut config: attome_config::AppConfig,
    migrated: bool,
) -> attome_config::AppConfig {
    let url = if migrated {
        migrated_db_url()
    } else {
        test_db_url()
    };
    if let Some(url) = url {
        point_config_at(&mut config, &url);
    }
    config
}

/// One multi-threaded runtime shared by every test in a binary that uses
/// [`run_shared`]: pools built in one test stay usable in the next, which a
/// per-test `#[tokio::test]` runtime would kill on exit.
pub fn shared_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("attome-shared-test-rt")
            .build()
            .unwrap_or_else(|error| {
                panic!("attome-testkit: build the shared test runtime: {error}")
            })
    })
}

/// Runs one test body on [`shared_runtime`]: `#[test] fn t() {
/// attome_testkit::run_shared(async { ... }) }` in place of `#[tokio::test]`.
pub fn run_shared<F: std::future::Future<Output = ()>>(body: F) {
    shared_runtime().block_on(body)
}

/// Environment switch that turns a missing object store into a failure, as
/// [`REQUIRE_DB_ENV`] does for the database.
pub const REQUIRE_S3_ENV: &str = "ATTOME_TEST_REQUIRE_S3";

/// A test-store credential from the environment (`S3_ACCESS_KEY`,
/// `S3_SECRET_KEY`). Without one it returns a placeholder, so the config the
/// test builds is still well formed; [`s3_or_skip`] is what decides whether
/// the test runs.
pub fn s3_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| "unset".to_owned())
}

/// `Some(())` when an object store is configured (`S3_ACCESS_KEY` and
/// `S3_SECRET_KEY`). Otherwise prints a `SKIP` line and returns `None`, or
/// panics when [`REQUIRE_S3_ENV`] is set. For tests that need a live
/// S3-compatible store (RustFS or MinIO) and a bucket named `attomebase`.
pub fn s3_or_skip() -> Option<()> {
    let configured =
        std::env::var("S3_ACCESS_KEY").is_ok() && std::env::var("S3_SECRET_KEY").is_ok();
    if configured {
        return Some(());
    }
    assert!(
        std::env::var_os(REQUIRE_S3_ENV).is_none(),
        "S3_ACCESS_KEY/S3_SECRET_KEY are not set, and {REQUIRE_S3_ENV} requires an object store"
    );
    eprintln!(
        "SKIP: set S3_ACCESS_KEY and S3_SECRET_KEY to a live RustFS/MinIO credential to run this test"
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_values_differ_and_keep_their_prefix() {
        let a = unique("case");
        let b = unique("case");
        assert_ne!(a, b);
        assert!(a.starts_with("case-"));
        assert!(unique_email("user").ends_with("@example.invalid"));
    }

    #[test]
    fn db_url_parts_decode_credentials_and_default_the_port() {
        let parts = DbUrlParts::parse("postgres://app%40x:p%2Fw%3Ad@db.local/attome_t").unwrap();
        assert_eq!(parts.user, "app@x");
        assert_eq!(parts.password, "p/w:d");
        assert_eq!(parts.host, "db.local");
        assert_eq!(parts.port, 5432);
        assert_eq!(parts.dbname, "attome_t");
        assert!(DbUrlParts::parse("postgres://u:p@h:6000/").is_err());
    }

    #[test]
    fn run_id_is_stable_within_a_process() {
        assert_eq!(run_id(), run_id());
    }
}
