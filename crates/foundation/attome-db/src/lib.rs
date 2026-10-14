//! PostgreSQL connectivity for the platform: the connection pools and the
//! identities they connect as, transactions, migration execution, schema
//! bootstrap, and database error classification.
//!
//! # Invariants
//!
//! What this crate guarantees today, and where. Change one only together with
//! the code and tests that enforce it.
//!
//! - **Driver errors never reach API clients.** [`classify`] and the [`tx`]
//!   helpers turn a `sqlx::Error` into an `AppError` with a fixed, generic
//!   message, or into a masked `AppError::internal`. They never forward the
//!   driver's own text.
//! - **`server::boot::init` checks every pool's identity before serving.** It
//!   runs [`verify_pool_identity`] on the runtime and migrator pools (and on
//!   the readonly and readonly-primary pools when `database.readonly` is
//!   configured), [`verify_readonly_identity`] on the readonly pool, and
//!   [`verify_connection_identity`] on one migrator connection. Any mismatch
//!   refuses boot. This covers the `server` and `worker` binaries; standalone
//!   tools that build a pool without `boot::init` (the audit binaries,
//!   `migrate`, `preflight`) don't run these checks.
//! - **`DATABASE_URL` is honored only under `APP_ENV=debug`.** The runtime pool
//!   ([`create_pool`]), the migrator pool ([`create_migrator_pool`]) and the
//!   migrator session ([`create_migrator_connection`]) each read it behind that
//!   same gate (M01 C-33: bootstrap and provisioning DDL must land on the
//!   database the runtime pool writes to). When `database.migrator` is set,
//!   the migrator paths take only the override's endpoint and keep the
//!   configured migrator credentials (D-117). No path honors it outside debug.
//! - **Migrations are serialized per database by an advisory lock; database
//!   lock waits and peer-migrator waits are bounded independently.**
//!   [`run_migrations`] bounds each lock wait with [`MIGRATION_LOCK_TIMEOUT`],
//!   retries a migration's own table-lock wait a fixed number of times, and
//!   waits for a peer migrator under a separate, longer budget (600s).
//! - **Session-pinned work uses the `database.direct_url` endpoint and a
//!   non-bootstrap identity** (D-497, D-612). [`create_runtime_session`] takes
//!   its endpoint from `direct_url` and its credentials, database and
//!   `search_path` from `database.runtime` — no runtime path authenticates as
//!   `database.user`. [`create_migrator_connection`] does the same with the
//!   migrator identity. Only when `direct_url` is unset do they fall back to
//!   `database.host`, which is correct only when no pgbouncer is in front, so a
//!   pooled deployment must set it. `direct_url`'s own credentials and
//!   `database.user` stay reserved for schema bootstrap.
//! - **A pool's role never changes TLS or the statement cache.** Every pool and
//!   unpooled connection gets both from one role-independent function. A role
//!   sets only pool size, per-session setup, and `application_name`.
//!
//! # Not owned here
//!
//! This crate provides the pools and the schema state that other crates read.
//! It does not own read routing or the read-your-writes pin (`attome-cache`'s
//! sticky primary, `attome-server`'s `AppState::read_pool`), health and readiness
//! (`attome-server`'s `health.rs`), or metrics (`attome-server`'s `metrics.rs`).
//! For pool acquire timeouts it exposes only [`set_acquire_timeout_hook`], a
//! callback attome-server uses to count them, and for unpooled sessions only
//! [`unpooled_sessions_open`], which attome-server reads; this crate has no
//! metrics dependency.

mod checksum;
mod error;
/// Audit plan 3.6: a caller-supplied step inside a base-layer transaction.
pub mod hook;
/// CLEANUP-REVIEW 3.4: the one SQL identifier validator and `quote_ident`.
pub mod ident;
mod migrate;
mod pool;
mod schema;
mod session;
pub mod tx;

pub use checksum::{ChecksumError, verify_migration_checksums};
pub use error::{
    PoolPressureHooks, classify, is_unique_violation, set_acquire_timeout_hook,
    set_pool_pressure_hooks, set_statement_timeout_hook, sqlstate,
};
pub use migrate::{
    MIGRATION_LOCK_TIMEOUT, SchemaState, run_migrations, run_migrations_with_migrator_lock_budget,
    schema_state,
};
pub use pool::{
    create_direct_pool, create_migrator_connection, create_migrator_pool, create_pool,
    create_readonly_pool, create_readonly_primary_pool, create_runtime_session, log_pool_capacity,
    runtime_session_options, verify_connection_identity, verify_pool_identity,
    verify_readonly_identity,
};
pub use schema::ensure_schema;
pub use session::{UnpooledSession, unpooled_sessions_open};
pub use sqlx::{
    PgConnection, PgPool, Postgres, Transaction, migrate::MigrateError, postgres::PgPoolOptions,
};

pub use hook::{BeforeCommit, Chain, HookFuture, NoHook};
pub type DbPool = PgPool;
pub type Tx<'a> = Transaction<'a, Postgres>;
