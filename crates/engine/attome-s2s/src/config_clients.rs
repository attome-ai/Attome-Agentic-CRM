//! D-771: S2S clients declared in `s2s.seeded_clients` are reconciled at
//! every boot, so a machine caller (a game world server, an ERP bridge) keeps
//! one stable credential across a database reset instead of needing a new key
//! issued through the admin API each time.
//!
//! What the config owns, and what it never touches:
//!
//! - The client row is created when missing; its name, description, service
//!   user and limits follow the config. A client an operator disabled stays
//!   disabled — the config never re-enables it.
//! - One key, found by its fixed `public_id`. The secret comes from `.env`
//!   (`${VAR}`), so this module never generates, logs or reveals one: a changed
//!   secret is a rotation on the next boot. A key an operator revoked stays
//!   revoked.
//! - The permission rows the config lists are upserted (D-766 ceiling). Rows
//!   it does not list are left alone.
//! - The service user is looked up, never created (D-495: no boot widens who
//!   exists). A missing one skips the client with a warning.
//!
//! Every write goes through `SecurityTx` as a `Credential` event with the nil
//! (system) actor, the same trail an admin-API change leaves.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_config::S2sSeededClient;
use attome_core::EngineState;
use attome_types::AppError;
use attome_types::text::normalize_email;
use chrono::Utc;
use uuid::Uuid;

use crate::crypto;

const DEFAULT_RPM: i32 = 1000;
const DEFAULT_CONCURRENT: i32 = 10;
const DEFAULT_PAYLOAD: i64 = 10 * 1024 * 1024;
const DEFAULT_DISABLE_DAYS: i32 = 90;

/// Reconciles every client in `s2s.seeded_clients`. A problem with one client
/// is logged and skipped so it cannot stop the boot; a database error is
/// returned.
pub async fn reconcile(state: &EngineState) -> Result<(), AppError> {
    reconcile_clients(state, &state.base.config.s2s.seeded_clients).await
}

/// [`reconcile`] over an explicit list (tests pass their own).
pub async fn reconcile_clients(
    state: &EngineState,
    clients: &[S2sSeededClient],
) -> Result<(), AppError> {
    let clients: Vec<&S2sSeededClient> = clients
        .iter()
        .filter(|c| c.configured_secret().is_some())
        .collect();
    if clients.is_empty() {
        return Ok(());
    }
    if !state.base.config.s2s.enabled {
        tracing::warn!(
            count = clients.len(),
            "s2s.seeded_clients has configured clients but s2s.enabled is false; not seeding them"
        );
        return Ok(());
    }
    let ring = state.base.secrets.load().s2s_key_encryption_key.clone();
    if ring.is_empty() {
        tracing::warn!("s2s.seeded_clients: s2s.key_encryption_key is empty; not seeding");
        return Ok(());
    }
    for client in clients {
        reconcile_one(state, &ring, client).await?;
    }
    Ok(())
}

/// D-786 follow-up L1: a platform service principal (`@internal.attome`) acts
/// only for the engine that owns it, never for an external S2S caller, so a
/// seeded client naming one is skipped like a missing user (one bad client
/// does not fail boot), logged at `error`.
fn names_service_principal(service_user_email: &str) -> bool {
    attome_security::accounts::is_reserved_service_email(service_user_email)
}

async fn reconcile_one(
    state: &EngineState,
    ring: &attome_config::KeyRing,
    cfg: &S2sSeededClient,
) -> Result<(), AppError> {
    let db = &state.base.db;
    let secret = cfg.configured_secret().unwrap_or_default().to_lowercase();
    let email = normalize_email(&cfg.service_user_email);
    if names_service_principal(&email) {
        tracing::error!(
            client_id = %cfg.client_id,
            "s2s seeded client skipped: its service_user_email is in the domain reserved \
             for platform service principals; point it at an ordinary service user"
        );
        return Ok(());
    }

    let service_user: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM user_account WHERE email = $1 AND is_active = TRUE")
            .bind(&email)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let Some(service_user) = service_user else {
        tracing::warn!(
            client_id = %cfg.client_id,
            service_user_email = %email,
            "s2s seeded client skipped: its service user does not exist or is disabled \
             (create it once via the admin API; this never creates users)"
        );
        return Ok(());
    };

    let client_db_id = ensure_client(state, cfg, service_user).await?;
    let Some(client_db_id) = client_db_id else {
        return Ok(());
    };
    ensure_key(state, ring, cfg, client_db_id, &secret).await?;
    ensure_permissions(state, cfg, client_db_id).await?;
    Ok(())
}

fn security_event(op: AuditOperation, entity: &str, name: String) -> SecurityEvent {
    SecurityEvent::new(MandatoryCategory::Credential, op, Uuid::nil(), entity, None).named(name)
}

/// Returns the client's row id, or `None` when an operator disabled it.
async fn ensure_client(
    state: &EngineState,
    cfg: &S2sSeededClient,
    service_user: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let rpm = cfg.rate_limit_rpm.unwrap_or(DEFAULT_RPM);
    let concurrent = cfg.max_concurrent.unwrap_or(DEFAULT_CONCURRENT);
    let existing = sqlx::query_as::<
        _,
        (Uuid, String, String, Option<String>, Option<Uuid>, i32, i32),
    >(
        "SELECT id, status, name, description, service_user_ref, rate_limit_rpm, max_concurrent \
           FROM s2s_client WHERE client_id = $1 AND is_deleted = FALSE",
    )
    .bind(&cfg.client_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    match existing {
        None => {
            let mut tx = SecurityTx::begin(
                state,
                security_event(
                    AuditOperation::Create,
                    "s2s_client",
                    format!("s2s_seeded_client:{}", cfg.client_id),
                ),
            )
            .await?;
            let now = Utc::now();
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO s2s_client \
                     (client_id, name, description, service_user_ref, rate_limit_rpm, max_concurrent, \
                      max_payload_bytes, auto_disable_days, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9) RETURNING id",
            )
            .bind(&cfg.client_id)
            .bind(cfg.name.trim())
            .bind(&cfg.description)
            .bind(service_user)
            .bind(rpm)
            .bind(concurrent)
            .bind(DEFAULT_PAYLOAD)
            .bind(DEFAULT_DISABLE_DAYS)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            tx.event_mut().set_record_id(id);
            tx.commit().await?;
            tracing::info!(client_id = %cfg.client_id, "s2s seeded client created");
            Ok(Some(id))
        }
        Some((id, status, name, description, user_ref, cur_rpm, cur_concurrent)) => {
            if status != "active" {
                tracing::warn!(
                    client_id = %cfg.client_id,
                    status = %status,
                    "s2s seeded client is not active (an operator changed it); leaving it as is"
                );
                return Ok(None);
            }
            let same = name == cfg.name.trim()
                && description == cfg.description
                && user_ref == Some(service_user)
                && cur_rpm == rpm
                && cur_concurrent == concurrent;
            if !same {
                let mut tx = SecurityTx::begin(
                    state,
                    security_event(
                        AuditOperation::Update,
                        "s2s_client",
                        format!("s2s_seeded_client:{}", cfg.client_id),
                    ),
                )
                .await?;
                sqlx::query(
                    "UPDATE s2s_client SET name = $2, description = $3, service_user_ref = $4, \
                            rate_limit_rpm = $5, max_concurrent = $6, updated_at = NOW(), \
                            row_version = row_version + 1 \
                      WHERE id = $1",
                )
                .bind(id)
                .bind(cfg.name.trim())
                .bind(&cfg.description)
                .bind(service_user)
                .bind(rpm)
                .bind(concurrent)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                tx.event_mut().set_record_id(id);
                tx.commit().await?;
                tracing::info!(client_id = %cfg.client_id, "s2s seeded client updated from config");
            }
            Ok(Some(id))
        }
    }
}

async fn ensure_key(
    state: &EngineState,
    ring: &attome_config::KeyRing,
    cfg: &S2sSeededClient,
    client_db_id: Uuid,
    secret: &str,
) -> Result<(), AppError> {
    let existing = sqlx::query_as::<_, (Uuid, Uuid, String, String, bool)>(
        "SELECT id, client_ref, secret_encrypted, status, is_deleted \
           FROM s2s_client_key WHERE public_id = $1",
    )
    .bind(&cfg.public_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let last4 = &secret[secret.len() - 4..];

    match existing {
        Some((key_id, client_ref, encrypted, status, is_deleted)) => {
            if client_ref != client_db_id {
                tracing::warn!(
                    public_id = %cfg.public_id,
                    "s2s seeded key skipped: this public_id belongs to another client"
                );
                return Ok(());
            }
            if is_deleted || status != "active" {
                tracing::warn!(
                    public_id = %cfg.public_id,
                    "s2s seeded key was revoked by an operator; leaving it revoked \
                     (choose a new public_id to issue a fresh one)"
                );
                return Ok(());
            }
            // A decrypt failure (the key ring moved on) is treated like a
            // changed secret: re-encrypting under the current ring fixes both.
            // Q18-T2: an unbound value is re-sealed bound to its row.
            if attome_auth::envelope::stored_is_bound(&encrypted)
                && crypto::decrypt_key_secret(ring, key_id, &encrypted).is_ok_and(|s| s == secret)
            {
                return Ok(());
            }
            let sealed = crypto::encrypt_key_secret(ring, key_id, secret)?;
            let mut tx = SecurityTx::begin(
                state,
                security_event(
                    AuditOperation::Update,
                    "s2s_client_key",
                    format!("s2s_seeded_key_rotated:{}", cfg.public_id),
                ),
            )
            .await?;
            sqlx::query(
                "UPDATE s2s_client_key SET secret_encrypted = $2, secret_last4 = $3 WHERE id = $1",
            )
            .bind(key_id)
            .bind(&sealed)
            .bind(last4)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            tx.event_mut().set_record_id(key_id);
            tx.commit().await?;
            tracing::info!(public_id = %cfg.public_id, "s2s seeded key secret updated from config");
        }
        None => {
            let slot_taken: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM s2s_client_key \
                   WHERE client_ref = $1 AND key_slot = $2 AND status = 'active' AND is_deleted = FALSE)",
            )
            .bind(client_db_id)
            .bind(&cfg.slot)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            if slot_taken {
                tracing::warn!(
                    client_id = %cfg.client_id,
                    slot = %cfg.slot,
                    "s2s seeded key skipped: the slot already holds another active key \
                     (revoke it or configure the other slot)"
                );
                return Ok(());
            }
            let new_key_id = Uuid::now_v7();
            let sealed = crypto::encrypt_key_secret(ring, new_key_id, secret)?;
            let mut tx = SecurityTx::begin(
                state,
                security_event(
                    AuditOperation::Create,
                    "s2s_client_key",
                    format!("s2s_seeded_key:{}", cfg.public_id),
                ),
            )
            .await?;
            let key_id: Uuid = sqlx::query_scalar(
                "INSERT INTO s2s_client_key \
                     (id, client_ref, key_slot, public_id, secret_encrypted, secret_last4, \
                      created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING id",
            )
            .bind(new_key_id)
            .bind(client_db_id)
            .bind(&cfg.slot)
            .bind(&cfg.public_id)
            .bind(&sealed)
            .bind(last4)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            tx.event_mut().set_record_id(key_id);
            tx.commit().await?;
            tracing::info!(public_id = %cfg.public_id, "s2s seeded key created");
        }
    }
    Ok(())
}

async fn ensure_permissions(
    state: &EngineState,
    cfg: &S2sSeededClient,
    client_db_id: Uuid,
) -> Result<(), AppError> {
    let current = crate::db::load_permissions(&state.base.db, client_db_id).await?;
    for p in &cfg.permissions {
        let entity = p.entity.trim().to_lowercase();
        let want = (p.read, p.create, p.update, p.delete, p.export, p.bulk);
        let have = current.iter().find(|r| r.entity_name == entity).map(|r| {
            (
                r.can_read,
                r.can_create,
                r.can_update,
                r.can_delete,
                r.can_export,
                r.can_bulk,
            )
        });
        if have == Some(want) {
            continue;
        }
        let mut tx = SecurityTx::begin(
            state,
            security_event(
                AuditOperation::Update,
                "s2s_permission",
                format!("s2s_permission:{entity}"),
            ),
        )
        .await?;
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO s2s_permission \
                 (client_ref, entity_name, can_read, can_create, can_update, can_delete, can_export, can_bulk) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (client_ref, entity_name) WHERE is_deleted = FALSE \
             DO UPDATE SET can_read = EXCLUDED.can_read, can_create = EXCLUDED.can_create, \
                           can_update = EXCLUDED.can_update, can_delete = EXCLUDED.can_delete, \
                           can_export = EXCLUDED.can_export, can_bulk = EXCLUDED.can_bulk, \
                           updated_at = NOW(), row_version = s2s_permission.row_version + 1 \
             RETURNING id",
        )
        .bind(client_db_id)
        .bind(&entity)
        .bind(p.read)
        .bind(p.create)
        .bind(p.update)
        .bind(p.delete)
        .bind(p.export)
        .bind(p.bulk)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        tx.event_mut().set_record_id(id);
        tx.commit().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::names_service_principal;

    #[test]
    fn a_seeded_client_cannot_name_a_service_principal() {
        assert!(names_service_principal("metric-service@internal.attome"));
        assert!(names_service_principal(" Workflow-System@Internal.Attome"));
        assert!(!names_service_principal("erp-bridge@example.test"));
    }
}
