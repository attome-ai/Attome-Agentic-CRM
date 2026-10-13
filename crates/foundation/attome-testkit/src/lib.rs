//! `attome-testkit`: shared support for database-backed tests.
//!
//! **One throwaway database per test process.** When `DATABASE_URL` points at
//! a PostgreSQL server, the first call to [`test_db_url`] in a process
//! creates a fresh, empty database on that server (named `attome_t_<uuid>`),
//! rewrites `DATABASE_URL` to point at it, and returns its URL. Every later
//! call returns the same URL. Each crate's tests apply the migrations they
//! need themselves.
//!
//! **Skip locally, fail in CI.** With no `DATABASE_URL`, database tests print
//! a `SKIP` line and return, so `cargo test` on a machine without Postgres is
//! green but honest about it. With [`REQUIRE_DB_ENV`] set (as the Linux CI job
//! does, next to its Postgres service), a missing database is a failure
//! instead: there it means the wiring broke.
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
    match URL.get_or_init(provision) {
        Ok(url) => url.clone(),
        Err(error) => panic!("attome-testkit: {error}"),
    }
}

/// A pool on this process's throwaway database, or `None` (see [`test_db_url`]).
pub async fn test_pool(max_connections: u32) -> Option<sqlx::PgPool> {
    let url = test_db_url()?;
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&url)
        .await
        .unwrap_or_else(|error| panic!("attome-testkit: connect to the test database: {error}"));
    Some(pool)
}

/// A one-connection pool: proves a code path never needs a second connection
/// while its own transaction holds the first.
pub async fn single_connection_pool() -> Option<sqlx::PgPool> {
    test_pool(1).await
}

/// The remedy printed on every `SKIP` line.
pub fn skip_remedy() -> String {
    format!("set {REQUIRE_DB_ENV}=1 to make a skip here a failure")
}

fn database_required() -> bool {
    std::env::var_os(REQUIRE_DB_ENV).is_some()
}

fn provision() -> Result<Option<String>, String> {
    let base = std::env::var("DATABASE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty());
    let Some(base) = base else {
        if database_required() {
            return Err(format!(
                "DATABASE_URL is not set, and {REQUIRE_DB_ENV} requires a test database"
            ));
        }
        return Ok(None);
    };

    let mut url = url::Url::parse(&base).map_err(|error| format!("DATABASE_URL is not a URL: {error}"))?;
    let current = url.path().trim_start_matches('/').to_ascii_lowercase();
    if let Some(part) = FORBIDDEN_NAME_PARTS.iter().find(|part| current.contains(*part)) {
        return Err(format!(
            "refusing DATABASE_URL: its database name `{current}` contains `{part}`; point it at a \
             throwaway server database such as `postgres`"
        ));
    }

    let name = format!("attome_t_{}", Uuid::now_v7().simple());
    // The database is created from a separate thread with its own runtime, so
    // this works whether or not the caller is already inside a Tokio runtime.
    let admin_url = base.clone();
    let create_name = name.clone();
    std::thread::spawn(move || create_database(&admin_url, &create_name))
        .join()
        .map_err(|_| "creating the test database panicked".to_owned())??;

    url.set_path(&format!("/{name}"));
    let test_url = url.to_string();
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

fn create_database(admin_url: &str, name: &str) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start a runtime: {error}"))?;
    runtime.block_on(async {
        let mut conn = PgConnection::connect(admin_url)
            .await
            .map_err(|error| format!("connect DATABASE_URL: {error}"))?;
        sqlx::query(&format!("CREATE DATABASE \"{name}\""))
            .execute(&mut conn)
            .await
            .map_err(|error| format!("CREATE DATABASE {name}: {error}"))?;
        conn.close().await.map_err(|error| format!("close: {error}"))?;
        Ok(())
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

/// A token stable for this process and different on every run.
pub fn run_id() -> &'static str {
    static RUN_ID: OnceLock<String> = OnceLock::new();
    RUN_ID.get_or_init(|| short(Uuid::now_v7()))
}

/// `prefix` with a fresh suffix, unique per call.
pub fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", short(Uuid::now_v7()))
}

/// A unique address at the reserved `.invalid` domain (RFC 2606), so a test
/// fixture can never be delivered.
pub fn unique_email(prefix: &str) -> String {
    format!("{}@example.invalid", unique(prefix))
}

fn short(id: Uuid) -> String {
    id.simple().to_string()[20..].to_owned()
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
    fn run_id_is_stable_within_a_process() {
        assert_eq!(run_id(), run_id());
    }
}
