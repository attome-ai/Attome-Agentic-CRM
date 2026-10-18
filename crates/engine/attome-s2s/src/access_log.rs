use attome_db::DbPool;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub struct LogEntry {
    pub client_ref: Option<Uuid>,
    pub client_name: Option<String>,
    pub method: String,
    pub path: String,
    pub status_code: Option<i16>,
    pub response_time_ms: Option<i32>,
    pub bytes_received: Option<i32>,
    pub bytes_sent: Option<i32>,
    pub correlation_id: Option<String>,
    pub ip_address: Option<String>,
    pub nonce: Option<String>,
    pub error_code: Option<String>,
    /// S1-T10: the user the client acted as, beside the client itself.
    pub acted_as_user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for LogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogEntry").finish_non_exhaustive()
    }
}

/// Returns `Err` on write failure (rather than swallowing it) so the P1.4
/// job handler that calls this can propagate the failure to apalis, which
/// then retries the job instead of silently marking it done.
pub async fn write(db: &DbPool, e: LogEntry) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO s2s_access_log
            (client_ref, client_name, method, path,
             status_code, response_time_ms, bytes_received, bytes_sent,
             correlation_id, ip_address, nonce, error_code, created_at, acted_as_user_id)
        VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        "#,
    )
    .bind(e.client_ref)
    .bind(e.client_name)
    .bind(e.method)
    .bind(e.path)
    .bind(e.status_code)
    .bind(e.response_time_ms)
    .bind(e.bytes_received)
    .bind(e.bytes_sent)
    .bind(e.correlation_id)
    .bind(e.ip_address)
    .bind(e.nonce)
    .bind(e.error_code)
    .bind(e.created_at)
    .bind(e.acted_as_user_id)
    .execute(db)
    .await?;

    Ok(())
}
