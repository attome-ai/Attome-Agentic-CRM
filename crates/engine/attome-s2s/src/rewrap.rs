//! P-key-rotation-and-jwt (b) — background convergence for
//! `s2s_client_key.secret_encrypted` after an `s2s.key_encryption_key`
//! rotation. Same shape/reasoning as `attome_auth::mfa::rewrap_secrets`: write
//! under active / read under whatever key a blob names is already safe the
//! instant a new key becomes active; this job only shortens how long an old
//! key must stay configured by rewriting rows onto the new one.

use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

use crate::crypto;

/// See `attome_auth::mfa::RewrapProgress` — same cursor-driven-batch contract.
pub struct RewrapProgress {
    pub scanned: u64,
    pub rewrapped: u64,
    pub last_id: Option<Uuid>,
}

impl std::fmt::Debug for RewrapProgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RewrapProgress").finish_non_exhaustive()
    }
}

/// Re-encrypts every `s2s_client_key.secret_encrypted` row (with `id >
/// after_id`) not already under `ring`'s active key, in one bounded batch.
/// `row_version` guards a row changed mid-batch (a concurrent key
/// generate/revoke) — skipped, not clobbered. Callers loop (`after_id =
/// result.last_id`) until `scanned == 0`.
pub async fn rewrap_secrets(
    db: &DbPool,
    ring: &KeyRing,
    after_id: Option<Uuid>,
    batch_size: i64,
) -> Result<RewrapProgress, AppError> {
    let rows: Vec<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT id, secret_encrypted, row_version FROM s2s_client_key
         WHERE is_deleted = FALSE AND id > $1
         ORDER BY id
         LIMIT $2",
    )
    .bind(after_id.unwrap_or(Uuid::nil()))
    .bind(batch_size)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let scanned = rows.len() as u64;
    let mut rewrapped = 0u64;
    let mut last_id = after_id;
    for (id, secret_encrypted, row_version) in rows {
        last_id = Some(id);
        // Q18-T2: a row under the active key is still re-sealed until it is
        // bound to its row.
        if attome_auth::envelope::stored_key_id(&secret_encrypted).as_deref()
            == Some(ring.active_key_id.as_str())
            && attome_auth::envelope::stored_is_bound(&secret_encrypted)
        {
            continue;
        }
        let plaintext = crypto::decrypt_key_secret(ring, id, &secret_encrypted)?;
        let fresh = crypto::encrypt_key_secret(ring, id, &plaintext)?;

        let updated = sqlx::query(
            "UPDATE s2s_client_key
             SET secret_encrypted = $1, row_version = row_version + 1
             WHERE id = $2 AND row_version = $3",
        )
        .bind(&fresh)
        .bind(id)
        .bind(row_version)
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if updated > 0 {
            rewrapped += 1;
        }
    }
    Ok(RewrapProgress {
        scanned,
        rewrapped,
        last_id,
    })
}
