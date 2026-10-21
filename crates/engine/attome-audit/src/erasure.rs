//! P-data-lifecycle item (d) / D-107 — crypto-shredding.
//!
//! One data-encryption key (DEK) per entity record (`audit_erasure_key`,
//! migration 0039), wrapped under the deployment's `audit.erasure_key_encryption_key`
//! master key. `AuditService::write_in_tx` (service.rs) fetches-or-creates a
//! record's DEK and encrypts its `AuditEvent.changed_fields`/`snapshot_json`
//! **in place, once, before any persistence happens** — so every downstream
//! write path (the synchronous header/detail/snapshot insert, the P1.13
//! `audit_ingest` capture, and the chainer's later drain of that ingest
//! row into `audit_header`/`detail`) all persist the already-ciphertext
//! event, with zero further crypto awareness needed in any of them. This is
//! the design's load-bearing property: encrypt once, at the earliest point
//! the value exists in memory, not per storage location.
//!
//! Erasure (`destroy_key`) sets `wrapped_dek = NULL` — irreversible, no
//! plaintext or key material survives anywhere. It cannot break chain
//! verification (`crate::verify`, invariant I3): hash version 1 never hashed
//! field values, and hash version 2 (D-539) hashes the **stored ciphertext**,
//! never the plaintext, so destroying a key changes no stored byte that any
//! digest covers. (The pre-v2 rationale, "never hashed field values", is
//! amended by D-539.)

use attome_config::KeyRing;
use attome_types::AppError;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use sqlx::Postgres;
use uuid::Uuid;

use crate::model::AuditEvent;

const FIELD_NAME: &str = "audit.erasure_key_encryption_key";

/// Shown in place of a value whose record's key has been destroyed. Never
/// stored — computed at read time by whatever admin view decrypts audit
/// history (a dedicated read path is a documented follow-up; see D-107).
pub const ERASED_MARKER: &str = "[erased]";

/// Fetches the record's DEK, creating one if none exists yet, and
/// **re-provisioning a fresh one if the previous key was destroyed** — a
/// record that receives a new edit after its history was erased gets its
/// future edits protected under a new key; only the pre-erasure history
/// stays permanently unreadable under the destroyed key. This is a real
/// design choice (documented in D-107), not the only defensible one: the
/// alternative — falling back to plaintext for a record whose key was ever
/// destroyed — was rejected because it would silently stop protecting a
/// restored/reactivated record's *new* data.
///
/// `FOR UPDATE` inside the caller's transaction serializes concurrent
/// provisioning attempts for the same `record_id`.
type WrappedKeyRow = (Option<Vec<u8>>, Option<chrono::DateTime<chrono::Utc>>);

async fn fetch_or_create_dek(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    master_ring: &KeyRing,
    record_id: Uuid,
) -> Result<[u8; 32], AppError> {
    let existing: Option<WrappedKeyRow> = sqlx::query_as(
        "SELECT wrapped_dek, destroyed_at FROM audit_erasure_key WHERE record_id = $1 FOR UPDATE",
    )
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    if let Some((Some(wrapped), None)) = &existing {
        // P-key-rotation-and-jwt (a): versioned envelope over the ring — the
        // DEK's *wrapping* key can now rotate without bricking every
        // already-provisioned record's key (the DEK itself never rotates;
        // only what wraps it does). See `attome_auth::envelope`'s doc.
        let dek_bytes = attome_auth::envelope::decrypt_bytes(FIELD_NAME, master_ring, wrapped)?;
        return dek_bytes.try_into().map_err(|_| {
            AppError::internal("audit_erasure_key.wrapped_dek decrypted to the wrong length")
        });
    }

    // No row yet, or the previous key was destroyed: (re-)provision.
    let dek = attome_auth::envelope::generate_dek();
    let wrapped = attome_auth::envelope::encrypt_bytes(FIELD_NAME, master_ring, &dek)?;

    sqlx::query(
        "INSERT INTO audit_erasure_key (record_id, wrapped_dek)
         VALUES ($1, $2)
         ON CONFLICT (record_id) DO UPDATE
             SET wrapped_dek = EXCLUDED.wrapped_dek,
                 destroyed_at = NULL,
                 destroyed_by = NULL,
                 updated_at = NOW(),
                 row_version = audit_erasure_key.row_version + 1",
    )
    .bind(record_id)
    .bind(&wrapped)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    Ok(dek)
}

/// Destroys a record's key: `wrapped_dek = NULL`, irreversible. Returns
/// `false` if the record never had a key row at all (nothing was ever
/// encrypted for it — not an error, since an erasure request against a
/// record with no audit-encrypted history is a legitimate no-op) and `true`
/// if a live key existed and was destroyed (or already had been — idempotent,
/// so a retried erasure request is not an error either).
///
/// P-data-protection-governance §4: checks `attome_core::legal_hold::
/// record_is_held` first and refuses (`AppError::Conflict`) when an active
/// hold covers `(entity_logicalname, record_id)` — defense in depth,
/// checked at the point of action regardless of caller. A caller that needs
/// the specific matter reference for a user-facing message (e.g. the DSR
/// admin surface's fulfill-erasure path) should call `record_is_held`
/// itself first, since this generic message can't carry that detail (see
/// `attome_types::AppError::Conflict`'s `&'static str` payload).
pub async fn destroy_key(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    entity_logicalname: &str,
    record_id: Uuid,
    destroyed_by: Uuid,
) -> Result<bool, AppError> {
    if attome_core::legal_hold::record_is_held(&mut **tx, entity_logicalname, record_id)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(
            "record is under an active legal hold — erasure refused (P-data-protection-governance)",
        ));
    }

    // `AND wrapped_dek IS NOT NULL` is load-bearing, not defensive: without
    // it this UPDATE matches an already-destroyed row too (its record_id
    // still exists), so `rows_affected() > 0` would be true on every retry
    // and `destroy_key` would never report `false` for an idempotent
    // no-op — caught by `erasure.rs`'s own integration test actually
    // asserting a second call's return value, not just that it doesn't error.
    let result = sqlx::query(
        "UPDATE audit_erasure_key
             SET wrapped_dek = NULL, destroyed_at = COALESCE(destroyed_at, NOW()),
                 destroyed_by = COALESCE(destroyed_by, $2), updated_at = NOW(),
                 row_version = row_version + 1
         WHERE record_id = $1 AND wrapped_dek IS NOT NULL",
    )
    .bind(record_id)
    .bind(destroyed_by)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    Ok(result.rows_affected() > 0)
}

/// R2-T1: destroys a record's key again when the erasure ledger says it was
/// erased but a restored database still holds it. No legal-hold check: the
/// erasure already passed one when it happened, and a restored database can
/// carry a hold that was released before then. Returns whether a live key
/// was destroyed.
pub async fn replay_destroy(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    record_id: Uuid,
) -> Result<bool, AppError> {
    let result = sqlx::query(
        "UPDATE audit_erasure_key
             SET wrapped_dek = NULL, destroyed_at = COALESCE(destroyed_at, NOW()),
                 updated_at = NOW(), row_version = row_version + 1
         WHERE record_id = $1 AND wrapped_dek IS NOT NULL",
    )
    .bind(record_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(result.rows_affected() > 0)
}

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

/// P-key-rotation-and-jwt (b) — background convergence for
/// `audit_erasure_key.wrapped_dek` after an `audit.erasure_key_encryption_key`
/// rotation. Same shape as `attome_auth::mfa::rewrap_secrets`/
/// `attome_s2s::rewrap::rewrap_secrets`: only the DEK-*wrapping* key ever
/// rotates here — the DEK itself, and therefore every already-encrypted
/// `audit_detail`/`snapshot` field value, is untouched by this job.
/// Skips rows whose key was destroyed (`wrapped_dek IS NULL`) — nothing to
/// rewrap for those, so a long run of destroyed keys past the cursor
/// legitimately ends the scan (`scanned == 0`), same as reaching the true
/// end of the table. `row_version` guards a row changed mid-batch (a
/// concurrent write re-provisioning or destroying the same record's key).
/// Callers loop (`after_id = result.last_id`) until `scanned == 0`.
pub async fn rewrap_secrets(
    db: &attome_db::DbPool,
    master_ring: &KeyRing,
    after_id: Option<Uuid>,
    batch_size: i64,
) -> Result<RewrapProgress, AppError> {
    let rows: Vec<(Uuid, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT record_id, wrapped_dek, row_version FROM audit_erasure_key
         WHERE wrapped_dek IS NOT NULL AND record_id > $1
         ORDER BY record_id
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
    for (record_id, wrapped, row_version) in rows {
        last_id = Some(record_id);
        if attome_auth::envelope::stored_key_id_bytes(&wrapped).as_deref()
            == Some(master_ring.active_key_id.as_str())
        {
            continue;
        }
        let dek = attome_auth::envelope::decrypt_bytes(FIELD_NAME, master_ring, &wrapped)?;
        let fresh = attome_auth::envelope::encrypt_bytes(FIELD_NAME, master_ring, &dek)?;

        let updated = sqlx::query(
            "UPDATE audit_erasure_key
             SET wrapped_dek = $1, updated_at = NOW(), row_version = row_version + 1
             WHERE record_id = $2 AND row_version = $3 AND wrapped_dek IS NOT NULL",
        )
        .bind(&fresh)
        .bind(record_id)
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

fn encrypt_opt(dek: &[u8; 32], value: &Option<String>) -> Result<Option<String>, AppError> {
    match value {
        Some(s) => {
            let raw = attome_auth::envelope::seal_with_dek(dek, s.as_bytes())?;
            Ok(Some(B64.encode(raw)))
        }
        None => Ok(None),
    }
}

/// A record's key for reading its audit values, without creating one (AH1-T2,
/// collecting what an agent session changed). `None` when the record has no
/// key or its key was destroyed: its values are then unreadable for good.
pub async fn read_dek(
    db: &attome_db::DbPool,
    master_ring: &KeyRing,
    record_id: Uuid,
) -> Result<Option<[u8; 32]>, AppError> {
    let existing: Option<WrappedKeyRow> = sqlx::query_as(
        "SELECT wrapped_dek, destroyed_at FROM audit_erasure_key WHERE record_id = $1",
    )
    .bind(record_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(wrapped), None)) = existing else {
        return Ok(None);
    };
    let dek = attome_auth::envelope::decrypt_bytes(FIELD_NAME, master_ring, &wrapped)?;
    dek.try_into().map(Some).map_err(|_| {
        AppError::internal("audit_erasure_key.wrapped_dek decrypted to the wrong length")
    })
}

/// Decrypts a value previously produced by `encrypt_opt`. Exposed (not just
/// internal) for the future admin audit-history read path (D-107 follow-up)
/// to call once it exists.
pub fn decrypt_field(dek: &[u8; 32], encoded: &str) -> Result<String, AppError> {
    let raw = B64
        .decode(encoded)
        .map_err(|_| AppError::internal("encrypted audit field is not valid base64"))?;
    let bytes = attome_auth::envelope::open_with_dek(dek, &raw)?;
    String::from_utf8(bytes)
        .map_err(|_| AppError::internal("decrypted audit field is not valid UTF-8"))
}

/// Fetches-or-creates the event's record key (if it carries a `record_id`
/// and has anything worth protecting) and encrypts `changed_fields`'
/// value/display columns and `snapshot_json` **in place**. A no-op when
/// `changed_fields` is empty and `snapshot_json` is `None` — a value-less
/// event (login, security event, this module's own erasure-record event)
/// never provisions a key it would never use.
///
/// Called exactly once, from `AuditService::write_in_tx`, before branching
/// into the ingest-capture / chainer-cutover / synchronous write paths — see
/// this module's doc comment for why encrypting once, up front, is what
/// makes every downstream write path crypto-agnostic.
#[expect(
    clippy::expect_used,
    reason = "the value was matched as Some on the line before"
)]
pub(crate) async fn encrypt_event_in_place(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    master_ring: &KeyRing,
    event: &mut AuditEvent,
) -> Result<(), AppError> {
    let Some(record_id) = event.record_id else {
        return Ok(());
    };
    if event.changed_fields.is_empty() && event.snapshot_json.is_none() {
        return Ok(());
    }

    let dek = fetch_or_create_dek(tx, master_ring, record_id).await?;

    for field in &mut event.changed_fields {
        field.old_value = encrypt_opt(&dek, &field.old_value)?;
        field.new_value = encrypt_opt(&dek, &field.new_value)?;
        field.old_display_value = encrypt_opt(&dek, &field.old_display_value)?;
        field.new_display_value = encrypt_opt(&dek, &field.new_display_value)?;
    }

    if let Some(snapshot) = &event.snapshot_json {
        let raw = attome_auth::envelope::seal_with_dek(&dek, snapshot.to_string().as_bytes())?;
        *event.snapshot_json.as_mut().expect("just matched Some") =
            serde_json::Value::String(B64.encode(raw));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_opt_roundtrips_through_decrypt_field() {
        let dek = attome_auth::envelope::generate_dek();
        let value = Some("some field value".to_string());
        let encrypted = encrypt_opt(&dek, &value).unwrap().unwrap();
        assert_ne!(encrypted, "some field value");
        assert_eq!(decrypt_field(&dek, &encrypted).unwrap(), "some field value");
    }

    #[test]
    fn encrypt_opt_passes_none_through() {
        let dek = attome_auth::envelope::generate_dek();
        assert_eq!(encrypt_opt(&dek, &None).unwrap(), None);
    }

    #[test]
    fn decrypt_field_fails_with_wrong_key() {
        let dek_a = attome_auth::envelope::generate_dek();
        let dek_b = attome_auth::envelope::generate_dek();
        let encrypted = encrypt_opt(&dek_a, &Some("secret".to_string()))
            .unwrap()
            .unwrap();
        assert!(decrypt_field(&dek_b, &encrypted).is_err());
    }
}
