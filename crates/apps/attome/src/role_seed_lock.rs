//! Serializes the role-password-seed + api-key-pepper-registry sequence that
//! both `bin/migrate.rs` (one-shot deploy job) and `boot::init`'s inline
//! `database.migrate_on_boot = true` path run immediately after migrations.
//!
//! `sqlx::migrate!`'s own advisory lock only covers `run_migrations` itself —
//! it is released before this sequence starts. Two concurrent callers (a
//! multi-node deploy racing two `migrate` invocations against the same
//! database, or `docker compose up -d --scale server=N` with the default
//! `migrate_on_boot = true`) hit `readonly_role_seed`/`db_role_seed` at the
//! same time otherwise, and PostgreSQL genuinely *errors* on concurrent
//! `ALTER ROLE ... PASSWORD` against the same role rather than just
//! serializing the wait — reproduced live: `ERROR: tuple concurrently
//! updated`. Guarded here by `pg_try_advisory_xact_lock` (guidelines §2) —
//! the only permitted form on a pooled connection, which is what D-026
//! credits for making transaction-mode pgbouncer safe: a session-scoped
//! lock taken on a pooled connection outlives the checkout that took it and
//! comes back attached to an unrelated caller. Session-scoped locks are not
//! banned outright, only confined to a *dedicated direct* connection whose
//! close releases them, for work a single transaction genuinely cannot span
//! — `jobs.rs`'s secret rewrap (many batches), `attome-metadata`'s
//! `CREATE INDEX CONCURRENTLY` provisioning, and `sqlx::migrate!`'s own
//! internal lock, which is why migrations must never go through the pooler.
//! Every acquisition this codebase issues itself is a `try` variant — no
//! crate's SQL contains a blocking `pg_advisory_lock`; the one blocking
//! acquisition in the process is inside `sqlx::migrate!`. Held on a
//! dedicated transaction for the whole sequence's duration via a short
//! bounded retry loop rather than failing fast on first contention, since
//! this runs in a one-shot deploy job / boot path with no caller able to
//! retry a failure itself.

use attome_config::AppConfig;
use attome_db::DbPool;
use attome_types::AppError;
use std::time::{Duration, Instant};

use crate::{apikey_pepper_registry, db_role_seed, readonly_role_seed};

/// Advisory-lock namespace for every key taken under the `"server/…"` prefix
/// (guidelines §2's `"{crate}/{operation}:{resource}"` convention) — today
/// only [`LOCK_KEY`].
///
/// Bound as the first argument of the two-argument
/// `pg_try_advisory_xact_lock($1, hashtext($2))` so a `hashtext` collision
/// between two unrelated keys can only happen *within* this subsystem, never
/// across subsystems (L-1 / TODO-027). The workspace-wide assignment table,
/// and the test that proves the ids stay distinct, live in
/// `crates/server/tests/advisory_lock_namespaces.rs`. Never reuse or renumber
/// an id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 10;

const LOCK_KEY: &str = "server/migrate:role-seed";
const RETRY_INTERVAL: Duration = Duration::from_millis(100);
const RETRY_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs the readonly/migrator/runtime role-password seeds and the api-key
/// pepper-registry check, serialized against any concurrent caller running
/// this same sequence against the same database. Must be called after
/// migrations have applied — these steps depend on migrations 0010/0042's
/// roles/tables already existing.
pub async fn seed_roles_and_pepper_registry(
    db: &DbPool,
    config: &AppConfig,
) -> Result<(), AppError> {
    #[expect(
        clippy::disallowed_methods,
        reason = "boot-time role-seed lock that deliberately replaces the driver error with a fixed message; not an HTTP path"
    )]
    let mut lock_tx = db
        .begin()
        .await
        .map_err(|_| AppError::internal("role_seed_lock: failed to open lock transaction"))?;

    let deadline = Instant::now() + RETRY_TIMEOUT;
    loop {
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(ADVISORY_LOCK_NAMESPACE)
            .bind(LOCK_KEY)
            .fetch_one(&mut *lock_tx)
            .await
            .map_err(|_| AppError::internal("role_seed_lock: failed to attempt advisory lock"))?;
        if locked {
            break;
        }
        if Instant::now() >= deadline {
            return Err(AppError::internal(
                "role_seed_lock: timed out waiting for a concurrent migrate/boot to finish role-seeding",
            ));
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }

    readonly_role_seed::seed(db, config).await?;
    // P-db-privilege-separation / D-117: both no-op when the respective
    // database.migrator/database.runtime block isn't configured.
    db_role_seed::seed_migrator(db, config).await?;
    db_role_seed::seed_runtime(db, config).await?;
    // D-120: fail-closed check that no api-key pepper id has ever been
    // reused for a different secret.
    apikey_pepper_registry::check_and_register(db, config).await?;
    // BAU-12d: and no live key needs a pepper the ring has dropped.
    apikey_pepper_registry::check_referenced_peppers_present(db, config).await?;

    // Releases the advisory lock (transaction-scoped — ends on commit or
    // rollback either way). Nothing is ever written through lock_tx itself,
    // so commit is just the conventional close for a transaction opened
    // successfully.
    lock_tx
        .commit()
        .await
        .map_err(|_| AppError::internal("role_seed_lock: failed to release lock"))?;

    Ok(())
}
