//! Skip-gate for the ~30 `*::seed::seed(db)` functions called from
//! `crates/server/src/boot.rs` and `EngineSystem::build()`. Each one is
//! idempotent by construction (`attome_metadata::provision::{ensure_entity,
//! ensure_attribute}`), but even the "unchanged" steady-state path costs a
//! round-trip per entity/attribute — multiplied across ~30 modules on every
//! single boot, that's the actual cause of slow dev restarts. `run_if_stale`
//! wraps a seed module's body: if `seed_watermark` already has this
//! module at this version, skip the body entirely.
//!
//! Not a replacement for `ensure_entity`/`ensure_attribute`'s own
//! correctness — this only decides *whether* to call them at all. See
//! migration `0388_seed_watermark.sql`'s header for the storage side.

use attome_db::DbPool;
use attome_types::AppError;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{LazyLock, RwLock};

/// Boot-time snapshot of `seed_watermark`, so the ~55 `run_if_stale`
/// calls a boot makes (52 `apply_platform_bundle` + the remaining seeds) cost
/// one query between them instead of one sequential round-trip each.
///
/// - **Source of truth:** `seed_watermark`. This is a read-through
///   snapshot of it, never an authority.
/// - **Population:** [`prefetch`], called once at boot after migrations. Until
///   then (and in tests, which never call it) the map is `None` and every
///   lookup falls back to its own query — byte-identical to the old behavior.
/// - **Invalidation:** [`upsert_stamp`] is the only writer of that table in
///   this process and updates the map in the same call, so the snapshot cannot
///   go stale against our own writes.
/// - **Failure behavior:** a failed `prefetch` leaves the map unpopulated and
///   every caller queries as before — slower, never wrong.
/// - **Another node writing a stamp concurrently** can leave this snapshot
///   behind that node's write. The consequence is re-running an idempotent
///   seed body that another node already ran, which is exactly what happened
///   before any watermark existed — safe in both directions.
static STAMPS: LazyLock<RwLock<Option<HashMap<String, String>>>> =
    LazyLock::new(|| RwLock::new(None));

/// Loads every watermark row once. Call after migrations and before the first
/// `run_if_stale`; calling it twice simply reloads the snapshot.
pub async fn prefetch(db: &DbPool) -> Result<(), AppError> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT module, version FROM seed_watermark")
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    let loaded = rows.len();
    if let Ok(mut guard) = STAMPS.write() {
        *guard = Some(rows.into_iter().collect());
    }
    tracing::info!(modules = loaded, "seed watermarks prefetched");
    Ok(())
}

/// Runs `body` only if `module`'s stored watermark doesn't already match
/// `version` (or `FORCE_RESEED` is set). On a match, returns `Ok(())`
/// immediately without calling `body` at all.
///
/// The watermark is written **only after `body` returns `Ok`** — never
/// before — so a mid-seed failure never leaves a stamp claiming success.
///
/// Callers: rename the existing `pub async fn seed(...)` body to
/// `async fn seed_body(...)` (unchanged), add a thin `pub async fn
/// seed(...)` that calls this with a `const SEED_VERSION: &str` bumped
/// whenever `seed_body` changes.
pub async fn run_if_stale<F, Fut>(
    db: &DbPool,
    module: &str,
    version: &str,
    body: F,
) -> Result<(), AppError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), AppError>>,
{
    if !force_reseed() && stamp_matches(db, module, version).await? {
        return Ok(());
    }
    body().await?;
    upsert_stamp(db, module, version).await
}

/// `FORCE_RESEED=1` (any non-empty value) bypasses every module's stamp
/// check for the current process — an escape hatch for "I changed seed
/// logic and don't want to hunt down which `SEED_VERSION` to bump."
fn force_reseed() -> bool {
    std::env::var_os("FORCE_RESEED").is_some_and(|v| !v.is_empty())
}

async fn stamp_matches(db: &DbPool, module: &str, version: &str) -> Result<bool, AppError> {
    // A populated snapshot answers without a round-trip; a missing key means
    // this module has never stamped, which is a mismatch either way.
    if let Ok(guard) = STAMPS.read()
        && let Some(map) = guard.as_ref()
    {
        return Ok(map.get(module).map(String::as_str) == Some(version));
    }
    let stored: Option<String> =
        sqlx::query_scalar("SELECT version FROM seed_watermark WHERE module = $1")
            .bind(module)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(stored.as_deref() == Some(version))
}

async fn upsert_stamp(db: &DbPool, module: &str, version: &str) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO seed_watermark (module, version, applied_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (module) DO UPDATE SET version = EXCLUDED.version, applied_at = now()",
    )
    .bind(module)
    .bind(version)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    // Keep the snapshot coherent with our own write — see `STAMPS`.
    if let Ok(mut guard) = STAMPS.write()
        && let Some(map) = guard.as_mut()
    {
        map.insert(module.to_string(), version.to_string());
    }
    Ok(())
}

/// [`run_if_stale`] with a second condition before the skip: the stamp must
/// match **and** `verify()` must confirm the state the body would produce is
/// still there. A stamp only says the body ran once; it cannot notice a test
/// (or an operator) deleting what the body created. When either check fails
/// the body runs in full, exactly as under [`run_if_stale`].
///
/// Used by the test-fixture seeds (`seed_for_tests`), which every DB-backed
/// test calls on setup: 2026-09-24, four of them re-walked ~430 attributes on
/// each of thousands of test boots (about 1.3 s each, all localhost round
/// trips) though the metadata was already correct.
pub async fn run_if_stale_verified<V, VFut, F, Fut>(
    db: &DbPool,
    module: &str,
    version: &str,
    verify: V,
    body: F,
) -> Result<(), AppError>
where
    V: FnOnce() -> VFut,
    VFut: Future<Output = Result<bool, AppError>>,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), AppError>>,
{
    if !force_reseed() && stamp_matches(db, module, version).await? && verify().await? {
        return Ok(());
    }
    body().await?;
    upsert_stamp(db, module, version).await
}

/// A change-detection fingerprint of `content` (FNV-1a, 64 bit, hex). Not a
/// security hash: it only has to differ when a bundle's text changes.
pub fn content_version(content: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in content.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}
