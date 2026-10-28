//! Y11-T11: app layers in install order, and clashes between apps.
//!
//! An app is a `product` changeset's scope (a pack). Its first apply gives it
//! the next position in `app_layer` (migration 0083), the order the layer
//! stack reads apps in. While its changeset applies, [`with_app`] names it,
//! so the properties it sets are recorded on the `app` layer under its own
//! name rather than a blank one.
//!
//! A clash is a property another installed app already set on an entity or
//! field the new app's changeset touches: the plan lists them and blocks the
//! changeset unless the request accepts them.

use std::future::Future;

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;

tokio::task_local! {
    static CURRENT_APP: String;
}

/// Runs `f` with `app` as the app whose layer rows it writes.
pub async fn with_app<F: Future>(app: String, f: F) -> F::Output {
    CURRENT_APP.scope(app, f).await
}

/// The app [`with_app`] named; empty outside one.
pub fn current_app() -> String {
    CURRENT_APP.try_with(Clone::clone).unwrap_or_default()
}

/// A property two apps set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AppClash {
    /// `entity` or `attribute`.
    pub object_kind: String,
    /// The entity's logical name, or `<entity>.<field>`.
    pub object_key: String,
    pub property: String,
    /// The installed app that set it.
    pub other_app: String,
}

/// An installed app and its place in the layer order.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct AppLayer {
    pub app: String,
    /// 1 for the first app installed; later apps sit above earlier ones.
    pub position: i32,
    pub installed_at: DateTime<Utc>,
}

/// The properties other apps than `app` set on `targets` (`(kind, key)`
/// pairs), by object then property.
pub async fn clashes(
    db: &DbPool,
    app: &str,
    targets: &[(String, String)],
) -> Result<Vec<AppClash>, AppError> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let (kinds, keys): (Vec<String>, Vec<String>) = targets.iter().cloned().unzip();
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT l.object_kind, l.object_key, l.property, l.app \
           FROM metadata_property_layer l \
           JOIN unnest($2::text[], $3::text[]) AS t(kind, key) \
             ON t.kind = l.object_kind AND t.key = l.object_key \
          WHERE l.layer = 'app' AND l.app <> '' AND l.app <> $1 \
          ORDER BY l.object_kind, l.object_key, l.property, l.app",
    )
    .bind(app)
    .bind(&kinds)
    .bind(&keys)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(object_kind, object_key, property, other_app)| AppClash {
            object_kind,
            object_key,
            property,
            other_app,
        })
        .collect())
}

/// Gives `app` the next position when it is not installed yet. Two first
/// applies racing for one position: the loser's insert does nothing and it
/// tries once more.
pub async fn ensure_installed(db: &DbPool, app: &str) -> Result<(), AppError> {
    for _ in 0..2 {
        let done = sqlx::query(
            "INSERT INTO app_layer (app, position) \
             SELECT $1, COALESCE(MAX(position), 0) + 1 FROM app_layer \
              WHERE NOT EXISTS (SELECT 1 FROM app_layer WHERE app = $1) \
             ON CONFLICT DO NOTHING",
        )
        .bind(app)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        let installed: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM app_layer WHERE app = $1)")
                .bind(app)
                .fetch_one(db)
                .await
                .map_err(AppError::internal)?;
        if installed || done.rows_affected() > 0 {
            return Ok(());
        }
    }
    Err(AppError::Conflict(
        "another app was installed at the same moment; apply again",
    ))
}

/// The installed apps in layer order, a page and the total.
pub async fn list(db: &DbPool, limit: i64, offset: i64) -> Result<(Vec<AppLayer>, i64), AppError> {
    let items: Vec<AppLayer> = sqlx::query_as(
        "SELECT app, position, installed_at FROM app_layer ORDER BY position LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_layer")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    Ok((items, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_current_app_is_scoped() {
        assert_eq!(current_app(), "");
        let inside = with_app("itsm".to_owned(), async { current_app() }).await;
        assert_eq!(inside, "itsm");
        assert_eq!(current_app(), "");
    }
}
