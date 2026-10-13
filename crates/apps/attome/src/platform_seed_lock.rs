//! Serializes boot-time platform seeding across every process that runs
//! `boot::init` against the same database.
//!
//! `server` and `worker` share `boot::init`, and that function applies every
//! platform bundle (D-478) plus the remaining seeds. Nothing coordinated two
//! processes doing it at once. Staging-smoke run 34845417412 (a worker-split
//! deployment) showed the result: both processes planned the same bundles,
//! one's writes invalidated the other's basis (`Conflict("basis changed since
//! plan")`), their concurrent `CREATE INDEX CONCURRENTLY` on the same new
//! tables hit the migrator role's 500ms `statement_timeout`, and every one of
//! those errors failed boot — 5 server and 8 worker restarts before both came
//! up. `tests/concurrent_boot.rs` reproduces it.
//!
//! Held from before the seed-watermark prefetch until after the last seed, so
//! a process that waited reads the watermarks the other one stamped and skips
//! every bundle it already applied.
//!
//! **Why a session lock on its own connection.** Seeding spans hundreds of
//! short transactions, so `pg_try_advisory_xact_lock` (what `role_seed_lock`
//! uses) cannot cover it. A session-scoped lock is allowed only on a
//! dedicated direct connection whose close releases it (see
//! `role_seed_lock`'s module doc) — the same shape as
//! `attome_metadata::provision::sync_attribute_index`, on the same
//! `create_migrator_connection` session. A process that dies while holding
//! the lock closes that session, and PostgreSQL releases the lock with it.
//!
//! **Namespace.** The key's `server/` prefix puts it in
//! [`crate::role_seed_lock::ADVISORY_LOCK_NAMESPACE`] (10), the namespace
//! `crates/server/tests/advisory_lock_namespaces.rs` already assigns to that
//! prefix. A distinct key, so it never conflicts with the role-seed lock.

use std::time::{Duration, Instant};

use attome_config::AppConfig;
use attome_db::UnpooledSession;

use crate::role_seed_lock::ADVISORY_LOCK_NAMESPACE;

const LOCK_KEY: &str = "server/boot:platform-seed";
const RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// How long a boot waits for another process's seeding before failing. A
/// fresh database's full seeding measured about 18 s in the release image
/// (staging) and 88–169 s in a local debug build (`concurrent_boot.rs`), so
/// this leaves several times the slowest observed run.
const WAIT_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// The held lock. Release it with [`PlatformSeedLock::release`] once seeding
/// is done; dropping it instead (a boot error returning early) closes the
/// session, which releases the lock too.
pub struct PlatformSeedLock {
    conn: UnpooledSession,
}

impl std::fmt::Debug for PlatformSeedLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlatformSeedLock").finish_non_exhaustive()
    }
}

impl PlatformSeedLock {
    /// Waits, bounded by [`WAIT_TIMEOUT`], until no other process holds the
    /// platform-seed lock, then holds it.
    pub async fn acquire(config: &AppConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut conn = UnpooledSession::new(
            attome_db::create_migrator_connection(config)
                .await
                .map_err(|e| format!("platform seed lock: opening its session failed: {e}"))?,
        );

        let started = Instant::now();
        let mut waiting = false;
        loop {
            let locked: bool =
                match sqlx::query_scalar("SELECT pg_try_advisory_lock($1, hashtext($2))")
                    .bind(ADVISORY_LOCK_NAMESPACE)
                    .bind(LOCK_KEY)
                    .fetch_one(&mut *conn)
                    .await
                {
                    Ok(locked) => locked,
                    Err(e) => {
                        let _ = conn.close().await;
                        return Err(format!("platform seed lock: acquiring it failed: {e}").into());
                    }
                };
            if locked {
                if waiting {
                    tracing::info!(
                        waited_ms = started.elapsed().as_millis() as u64,
                        "platform seed lock acquired; seeding after the other process finished"
                    );
                }
                return Ok(Self { conn });
            }
            if started.elapsed() >= WAIT_TIMEOUT {
                let _ = conn.close().await;
                return Err(format!(
                    "platform seed lock: another process has been seeding platform metadata \
                     for over {} s; refusing to seed concurrently. Check the other \
                     server/worker process's boot log.",
                    WAIT_TIMEOUT.as_secs()
                )
                .into());
            }
            if !waiting {
                tracing::info!(
                    "another process is seeding platform metadata; waiting for it to finish"
                );
                waiting = true;
            }
            tokio::time::sleep(RETRY_INTERVAL).await;
        }
    }

    /// Unlocks and closes the session. Failing to unlock only logs: closing
    /// the session releases the lock regardless.
    pub async fn release(mut self) {
        match sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1, hashtext($2))")
            .bind(ADVISORY_LOCK_NAMESPACE)
            .bind(LOCK_KEY)
            .fetch_one(&mut *self.conn)
            .await
        {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                "platform seed lock was not held at release; the session was not pinned to one \
                 backend — check that database.direct_url bypasses any transaction-mode pgbouncer"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                "releasing the platform seed lock failed; closing its session releases it"
            ),
        }
        let _ = self.conn.close().await;
    }
}
