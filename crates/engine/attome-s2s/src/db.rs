use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub struct ClientKeyRow {
    pub client_db_id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub client_status: String,
    pub service_user_ref: Option<Uuid>,
    pub rate_limit_rpm: i32,
    pub max_concurrent: i32,
    pub allowed_cidrs: Option<Vec<String>>,
    pub max_payload_bytes: i64,
    pub auto_disable_days: i32,
    pub client_last_used: Option<DateTime<Utc>>,
    pub key_db_id: Uuid,
    pub key_slot: String,
    pub secret_encrypted: String,
    pub key_status: String,
    pub key_expires_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for ClientKeyRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKeyRow").finish_non_exhaustive()
    }
}

pub async fn load_client_and_key(
    db: &DbPool,
    client_id_slug: &str,
    key_public_id: &str,
) -> Result<Option<ClientKeyRow>, AppError> {
    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            String,
            Option<Uuid>,
            i32,
            i32,
            Option<Vec<String>>,
            i64,
            i32,
            Option<DateTime<Utc>>,
            Uuid,
            String,
            String,
            String,
            Option<DateTime<Utc>>,
        ),
    >(
        r#"
        SELECT
            c.id,
            c.client_id,
            c.name,
            c.status,
            c.service_user_ref,
            c.rate_limit_rpm,
            c.max_concurrent,
            c.allowed_cidrs,
            c.max_payload_bytes,
            c.auto_disable_days,
            c.last_used_at,
            k.id,
            k.key_slot,
            k.secret_encrypted,
            k.status,
            k.expires_at
        FROM s2s_client c
        JOIN s2s_client_key k ON k.client_ref = c.id
        WHERE c.client_id  = $1
          AND k.public_id  = $2
          AND c.is_deleted = FALSE
          AND k.is_deleted = FALSE
        "#,
    )
    .bind(client_id_slug)
    .bind(key_public_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    Ok(row.map(|r| ClientKeyRow {
        client_db_id: r.0,
        client_id: r.1,
        client_name: r.2,
        client_status: r.3,
        service_user_ref: r.4,
        rate_limit_rpm: r.5,
        max_concurrent: r.6,
        allowed_cidrs: r.7,
        max_payload_bytes: r.8,
        auto_disable_days: r.9,
        client_last_used: r.10,
        key_db_id: r.11,
        key_slot: r.12,
        secret_encrypted: r.13,
        key_status: r.14,
        key_expires_at: r.15,
    }))
}

/// S1-T10: whether the client may name a user to act as.
pub async fn client_can_act_as_user(db: &DbPool, client_db_id: Uuid) -> Result<bool, AppError> {
    let granted: Option<bool> =
        sqlx::query_scalar("SELECT can_act_as_user FROM s2s_client WHERE id = $1")
            .bind(client_db_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(granted.unwrap_or(false))
}

/// S1-T10: an active, ordinary user an S2S client may act as (not a
/// platform service principal), by id.
pub async fn act_as_user_is_usable(db: &DbPool, user_id: Uuid) -> Result<bool, AppError> {
    let row: Option<(bool, Option<String>)> =
        sqlx::query_as("SELECT is_active, email FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(row.is_some_and(|(active, email)| {
        active
            && !email
                .as_deref()
                .is_some_and(attome_security::accounts::is_reserved_service_email)
    }))
}

/// Returns `Err` on either write's failure (rather than swallowing it) so the
/// P1.4 job handler that calls this can propagate the failure to apalis,
/// which then retries the job instead of silently marking it done. Both
/// updates still run even if the first fails — retrying re-applies both,
/// which is idempotent (same or later `now`), so there's no reason to skip
/// the second on a first-write error.
pub async fn update_last_used(
    db: &DbPool,
    client_db_id: Uuid,
    key_db_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let client_res = sqlx::query("UPDATE s2s_client SET last_used_at = $1 WHERE id = $2")
        .bind(now)
        .bind(client_db_id)
        .execute(db)
        .await;

    let key_res = sqlx::query("UPDATE s2s_client_key SET last_used_at = $1 WHERE id = $2")
        .bind(now)
        .bind(key_db_id)
        .execute(db)
        .await;

    client_res?;
    key_res?;
    Ok(())
}

pub struct PermissionRow {
    pub entity_name: String,
    pub can_read: bool,
    pub can_create: bool,
    pub can_update: bool,
    pub can_delete: bool,
    pub can_export: bool,
    pub can_bulk: bool,
}

impl std::fmt::Debug for PermissionRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PermissionRow").finish_non_exhaustive()
    }
}

pub async fn load_permissions(
    db: &DbPool,
    client_db_id: Uuid,
) -> Result<Vec<PermissionRow>, AppError> {
    let rows = sqlx::query_as::<_, (String, bool, bool, bool, bool, bool, bool)>(
        r#"
        SELECT entity_name, can_read, can_create, can_update, can_delete, can_export, can_bulk
        FROM s2s_permission
        WHERE client_ref = $1 AND is_deleted = FALSE
        "#,
    )
    .bind(client_db_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(|r| PermissionRow {
            entity_name: r.0,
            can_read: r.1,
            can_create: r.2,
            can_update: r.3,
            can_delete: r.4,
            can_export: r.5,
            can_bulk: r.6,
        })
        .collect())
}

/// D-766: logs a warning naming each active client that has no live
/// `s2s_permission` row — such a client carries no entity ceiling, so its
/// service user's roles are its only bound. Warn-only: a boot never fails for
/// it, and a lookup error is logged, not propagated.
pub async fn warn_unbounded_clients(db: &DbPool) {
    let rows = sqlx::query_as::<_, (String, String)>(
        r#"
        SELECT c.client_id, c.name
        FROM s2s_client c
        WHERE c.is_deleted = FALSE AND c.status = 'active'
          AND NOT EXISTS (
              SELECT 1 FROM s2s_permission p
              WHERE p.client_ref = c.id AND p.is_deleted = FALSE
          )
        ORDER BY c.client_id
        "#,
    )
    .fetch_all(db)
    .await;
    match rows {
        Ok(rows) => {
            for (client_id, name) in rows {
                tracing::warn!(
                    client_id = %client_id,
                    "s2s: client '{name}' has no permission rows, so its service user's roles \
                     are its only limit (D-766) — add rows via \
                     POST /api/v1/admin/s2s/clients/{{id}}/permissions to restrict it"
                );
            }
        }
        Err(e) => tracing::warn!("s2s: unbounded-client check failed: {e}"),
    }

    let admin_capped = sqlx::query_scalar::<_, String>(
        r#"
        SELECT c.client_id
        FROM s2s_client c
        JOIN user_account_mm_privilege g
          ON g.user_ref = c.service_user_ref AND g.is_active = TRUE
        JOIN privilege p ON p.id = g.privilege_ref AND p.key = $1
        WHERE c.is_deleted = FALSE AND c.status = 'active'
          AND EXISTS (
              SELECT 1 FROM s2s_permission sp
              WHERE sp.client_ref = c.id AND sp.is_deleted = FALSE
          )
        ORDER BY c.client_id
        "#,
    )
    .bind(attome_server::security::ADMIN_PRIVILEGE_KEY)
    .fetch_all(db)
    .await;
    match admin_capped {
        Ok(ids) => {
            for client_id in ids {
                tracing::warn!(
                    client_id = %client_id,
                    "s2s: client has permission rows and a directly-granted admin service \
                     user, so every request it sends is refused (D-766)"
                );
            }
        }
        Err(e) => tracing::warn!("s2s: admin-capped client check failed: {e}"),
    }
}

/// M12 (data management) — the export endpoint's per-request check: does
/// this S2S client hold `can_export` for `entity_name`? Scoped to one
/// `(client, entity)` pair rather than reusing [`load_permissions`]'s
/// whole-client list, since the caller here already knows exactly which
/// entity it's checking. `false` on no matching row — an S2S client with no
/// `s2s_permission` row for an entity has no grant on it at all, matching
/// every other per-entity grant's absent-row-means-no-access convention in
/// this codebase.
pub async fn client_can_export(
    db: &DbPool,
    client_db_id: Uuid,
    entity_name: &str,
) -> Result<bool, AppError> {
    let can_export: Option<bool> = sqlx::query_scalar(
        "SELECT can_export FROM s2s_permission \
          WHERE client_ref = $1 AND entity_name = $2 AND is_deleted = FALSE",
    )
    .bind(client_db_id)
    .bind(entity_name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(can_export.unwrap_or(false))
}
