use attome_db::DbPool;
use attome_types::AppError;
use chrono::NaiveDateTime;
use uuid::Uuid;

use crate::model::Notification;

/// Query-shaping row for `poll` — `Notification` plus the window-aggregated
/// unread count carried on every row.
#[derive(sqlx::FromRow)]
struct NotificationRow {
    id: Uuid,
    title: Option<String>,
    message: Option<String>,
    notif_type: Option<i32>,
    is_read: Option<bool>,
    route: Option<String>,
    created_on: Option<NaiveDateTime>,
    unread_count: i64,
}

impl From<NotificationRow> for Notification {
    fn from(r: NotificationRow) -> Self {
        Notification {
            id: r.id,
            title: r.title,
            message: r.message,
            notif_type: r.notif_type,
            is_read: r.is_read,
            route: r.route,
            created_on: r.created_on,
        }
    }
}

/// Reads and updates the per-user notification inbox
/// (`notification_recipient`). The recipient row is the authorization
/// boundary; organization/global audience flags are only used while
/// materializing rows and are never consulted by the read path.
pub struct NotificationInbox<'a> {
    db: &'a DbPool,
}

impl std::fmt::Debug for NotificationInbox<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationInbox").finish_non_exhaustive()
    }
}

impl<'a> NotificationInbox<'a> {
    pub fn new(db: &'a DbPool) -> Self {
        Self { db }
    }

    /// J11-T1: the user's unread count and a stamp that changes whenever a
    /// notification reaches them or one is read or removed, for the live
    /// channel to tell the bell when to refresh.
    pub async fn stamp(&self, user_id: Uuid) -> Result<(i64, String), AppError> {
        let row: (i64, String) = sqlx::query_as(
            "SELECT COUNT(*) FILTER (WHERE read_at IS NULL), \
                    COUNT(*)::text || '/' || COUNT(read_at)::text || '/' \
                        || COALESCE(max(created_at)::text, '') \
               FROM notification_recipient \
              WHERE user_ref = $1 AND is_deleted = FALSE",
        )
        .bind(user_id)
        .fetch_one(self.db)
        .await
        .map_err(AppError::internal)?;
        Ok(row)
    }

    /// Most recent active notifications addressed to this user, newest first,
    /// plus the unread count — one query instead of a separate list + COUNT
    /// (P1.11f). The unread count is a window aggregate over the whole
    /// matching set (computed before LIMIT applies), not just the returned
    /// page.
    pub async fn poll(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<(Vec<Notification>, i64), AppError> {
        let rows: Vec<NotificationRow> = sqlx::query_as(
            r#"SELECT id, title, message, notif_type,
                      (read_at IS NOT NULL) AS is_read, route,
                      created_at AT TIME ZONE 'UTC' AS created_on,
                      COUNT(*) FILTER (WHERE read_at IS NULL)
                          OVER () AS unread_count
               FROM notification_recipient
               WHERE user_ref = $1 AND is_deleted = FALSE
               ORDER BY created_at DESC
               LIMIT $2"#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(self.db)
        .await
        .map_err(AppError::internal)?;

        let unread_count = rows.first().map(|r| r.unread_count).unwrap_or(0);
        let notifications = rows.into_iter().map(Notification::from).collect();

        Ok((notifications, unread_count))
    }

    /// Marks one notification read. A row that is already read or belongs to
    /// another user is an intentional no-op, avoiding an ID-existence oracle.
    pub async fn mark_read(&self, user_id: Uuid, id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE notification_recipient
                SET read_at = NOW(), updated_at = NOW(), row_version = row_version + 1
              WHERE id = $1 AND user_ref = $2 AND is_deleted = FALSE AND read_at IS NULL",
        )
        .bind(id)
        .bind(user_id)
        .execute(self.db)
        .await
        .map_err(AppError::internal)?;

        Ok(())
    }

    /// Marks every notification addressed to the user read.
    pub async fn clear(&self, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE notification_recipient
                SET read_at = NOW(), updated_at = NOW(), row_version = row_version + 1
              WHERE user_ref = $1 AND is_deleted = FALSE AND read_at IS NULL",
        )
        .bind(user_id)
        .execute(self.db)
        .await
        .map_err(AppError::internal)?;

        Ok(())
    }
}
