//! The deployment's current metadata version and each node's switch to it
//! (roadmap Y8-T4, on Y8-T3's tables).
//!
//! A cook's manifest is stored as one more artefact (kind `manifest`, keyed
//! by the SHA-256 of its JSON), so a recorded version can be loaded again
//! from `metadata_artefact` alone. [`record`] numbers a new manifest as the
//! next version and points `metadata_current` at it; [`set_current`] and
//! [`rollback`] only move the pointer to a version already recorded, so they
//! never cook. Every pointer move rings the Postgres doorbell, and each node
//! [`follow_current`]s the pointer on its metadata catch-up: it loads the
//! version's artefacts off the request path, swaps them in at once
//! ([`CookedRegistry::load_version`]) and records its `metadata_node_switch`
//! row.
//!
//! Pointer moves are serialised by one advisory lock ([`lock_pointer`]). A
//! publisher takes it *before* cooking, so whichever node records later also
//! cooked later, and an older cook can never become current after a newer
//! one.

use attome_db::{DbPool, Tx};
use attome_types::AppError;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::cooker::CookManifest;
use crate::runtime::CookedRegistry;

/// The artefact kind a version's manifest is stored under.
pub const MANIFEST_KIND: &str = "manifest";

/// `attome_core::METADATA_CHANGE_CHANNEL`, which this crate sits below.
const DOORBELL: &str = "attome_metadata_change";

/// The one key every pointer move locks.
const POINTER_LOCK_KEY: &str = "attome-model/version-pointer:current";

/// A pointer move: the version current before (none on the first record)
/// and after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Switched {
    pub from: Option<i64>,
    pub to: i64,
}

/// Takes the pointer lock for the rest of `tx`; `false` when another
/// transaction holds it.
pub async fn lock_pointer(tx: &mut Tx<'_>) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(POINTER_LOCK_KEY)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

async fn require_pointer_lock(tx: &mut Tx<'_>) -> Result<(), AppError> {
    if lock_pointer(tx).await? {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "a metadata version switch is already in progress",
        ))
    }
}

/// Stores `manifest` as an artefact (kept when already stored) and returns
/// its hash. A `BTreeMap` serialises in key order, so the same manifest
/// always has the same hash.
pub async fn store_manifest(pool: &DbPool, manifest: &CookManifest) -> Result<String, AppError> {
    let payload = serde_json::to_vec(manifest).map_err(AppError::internal)?;
    let hash = hex::encode(Sha256::digest(&payload));
    sqlx::query(
        "INSERT INTO metadata_artefact (content_hash, kind, payload) VALUES ($1, $2, $3) \
         ON CONFLICT (content_hash) DO NOTHING",
    )
    .bind(&hash)
    .bind(MANIFEST_KIND)
    .bind(&payload)
    .execute(pool)
    .await
    .map_err(AppError::internal)?;
    Ok(hash)
}

/// A stored manifest by its hash.
pub async fn load_manifest(pool: &DbPool, hash: &str) -> Result<CookManifest, AppError> {
    let payload: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT payload FROM metadata_artefact WHERE content_hash = $1 AND kind = $2",
    )
    .bind(hash)
    .bind(MANIFEST_KIND)
    .fetch_optional(pool)
    .await
    .map_err(AppError::internal)?;
    let payload = payload.ok_or_else(|| {
        AppError::internal(format!("manifest {hash} is missing from metadata_artefact"))
    })?;
    serde_json::from_slice(&payload).map_err(AppError::internal)
}

/// The current version and its manifest hash; `None` before the first
/// version is recorded.
pub async fn current<'e, E>(executor: E) -> Result<Option<(i64, String)>, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT c.version, p.manifest_hash \
         FROM metadata_current c JOIN metadata_published_version p ON p.version = c.version",
    )
    .fetch_optional(executor)
    .await
    .map_err(AppError::internal)
}

/// Points `metadata_current` at `version` and rings the doorbell, in `tx`.
async fn point(tx: &mut Tx<'_>, version: i64) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO metadata_current (singleton, version, switched_at) VALUES (true, $1, now()) \
         ON CONFLICT (singleton) DO UPDATE \
         SET version = EXCLUDED.version, switched_at = EXCLUDED.switched_at",
    )
    .bind(version)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query("SELECT pg_notify($1, '')")
        .bind(DOORBELL)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// Records the stored manifest `manifest_hash` as the next version and makes
/// it current, in `tx`, which must hold the pointer lock ([`lock_pointer`]).
/// When it is already the current manifest nothing changes and the current
/// version is returned.
pub async fn record(
    tx: &mut Tx<'_>,
    manifest_hash: &str,
    published_by: Option<Uuid>,
) -> Result<Switched, AppError> {
    let from = current(&mut **tx).await?;
    if let Some((version, hash)) = &from
        && hash == manifest_hash
    {
        return Ok(Switched {
            from: Some(*version),
            to: *version,
        });
    }
    let next: i64 =
        sqlx::query_scalar("SELECT COALESCE(max(version), 0) + 1 FROM metadata_published_version")
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO metadata_published_version (version, manifest_hash, published_by) \
         VALUES ($1, $2, $3)",
    )
    .bind(next)
    .bind(manifest_hash)
    .bind(published_by)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    point(tx, next).await?;
    Ok(Switched {
        from: from.map(|(version, _)| version),
        to: next,
    })
}

/// Makes the recorded `version` current. Not found when it was never
/// recorded; a conflict while another switch holds the pointer.
pub async fn set_current(tx: &mut Tx<'_>, version: i64) -> Result<Switched, AppError> {
    require_pointer_lock(tx).await?;
    let known: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM metadata_published_version WHERE version = $1)",
    )
    .bind(version)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if !known {
        return Err(AppError::NotFound);
    }
    let from = current(&mut **tx).await?.map(|(version, _)| version);
    if from != Some(version) {
        point(tx, version).await?;
    }
    Ok(Switched { from, to: version })
}

/// Makes the highest recorded version below the current one current. Its
/// artefacts are still stored, so nothing is cooked. A conflict when there is
/// no current version or none before it.
pub async fn rollback(tx: &mut Tx<'_>) -> Result<Switched, AppError> {
    require_pointer_lock(tx).await?;
    let Some((from, _)) = current(&mut **tx).await? else {
        return Err(AppError::Conflict("no metadata version is current yet"));
    };
    let previous: Option<i64> = sqlx::query_scalar(
        "SELECT max(version) FROM metadata_published_version WHERE version < $1",
    )
    .bind(from)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some(to) = previous else {
        return Err(AppError::Conflict(
            "there is no earlier metadata version to roll back to",
        ));
    };
    point(tx, to).await?;
    Ok(Switched {
        from: Some(from),
        to,
    })
}

/// Records that `node` now serves `version` (once per node and version).
pub async fn record_node_switch(pool: &DbPool, node: &str, version: i64) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO metadata_node_switch (node_id, version) VALUES ($1, $2) \
         ON CONFLICT (node_id, version) DO NOTHING",
    )
    .bind(node)
    .bind(version)
    .execute(pool)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Loads the current version into `registry` when it is not the one loaded,
/// and records `node`'s switch. Returns the version switched to, or `None`
/// when there was nothing to do (already current, or no version recorded).
pub async fn follow_current(
    pool: &DbPool,
    registry: &CookedRegistry,
    node: &str,
) -> Result<Option<i64>, AppError> {
    let Some((version, hash)) = current(pool).await? else {
        return Ok(None);
    };
    if registry.snapshot().version == version {
        return Ok(None);
    }
    let manifest = load_manifest(pool, &hash).await?;
    registry.load_version(pool, version, manifest).await?;
    record_node_switch(pool, node, version).await?;
    Ok(Some(version))
}
