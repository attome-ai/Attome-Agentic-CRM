//! One deployment per namespace (roadmap Y5-T2). The first server to boot
//! makes the deployment's id (`deployment_identity`); every server then
//! claims the shared cache with it as a marker key. A second deployment
//! pointed at the same Redis database finds another id there and refuses to
//! start, rather than reading and overwriting the first one's sessions,
//! caches and locks.

use attome_cache::Store;
use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// The marker key in the shared cache.
pub const MARKER_KEY: &str = "attome:deployment:identity";

/// This deployment's id, made on first boot.
pub async fn deployment_identity(db: &DbPool) -> Result<Uuid, AppError> {
    sqlx::query(
        "INSERT INTO deployment_identity (id) VALUES ($1) ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    sqlx::query_scalar("SELECT id FROM deployment_identity WHERE singleton")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// Whether a marker found in the cache lets deployment `mine` use it.
pub fn marker_verdict(held: Option<&str>, mine: &str) -> Result<(), String> {
    match held {
        None => Ok(()),
        Some(id) if id == mine => Ok(()),
        Some(other) => Err(format!(
            "this cache already belongs to deployment {other} (this one is {mine}); \
             give each deployment its own Redis database or server"
        )),
    }
}

/// Claims the shared cache for this deployment, or refuses: see the module
/// doc. Returns the deployment id.
pub async fn claim(db: &DbPool, cache: &Store) -> Result<Uuid, AppError> {
    let id = deployment_identity(db).await?;
    let mine = id.to_string();
    cache.set_nx(MARKER_KEY, &mine, None).await?;
    let held = cache.get(MARKER_KEY).await?;
    marker_verdict(held.as_deref(), &mine).map_err(|reason| {
        tracing::error!(%reason, "refusing to start: the cache belongs to another deployment");
        AppError::internal(reason)
    })?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolation_marker_refuses_another_deployment() {
        assert!(marker_verdict(None, "a").is_ok());
        assert!(marker_verdict(Some("a"), "a").is_ok());
        let refusal = marker_verdict(Some("b"), "a").unwrap_err();
        assert!(refusal.contains("deployment b"), "{refusal}");
    }
}
