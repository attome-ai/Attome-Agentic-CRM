use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Matches the notification `notif_type` column.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum NotificationType {
    Info = 0,
    Success = 1,
    Warning = 2,
    Error = 3,
}

/// One row from `notification_recipient`, exposed in the bell-icon API.
/// Each row belongs to exactly one authenticated user and carries that user's
/// independent read state.
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Notification {
    pub id: Uuid,
    pub title: Option<String>,
    pub message: Option<String>,
    #[sqlx(rename = "type")]
    pub notif_type: Option<i32>,
    pub is_read: Option<bool>,
    pub route: Option<String>,
    pub created_on: Option<NaiveDateTime>,
}
