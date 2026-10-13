//! D-120 — closes D-119's residual #3 (api-key pepper-id reuse across time).
//!
//! `AppConfig::validate()` can only catch a duplicate pepper id *within one
//! config file* — it has no memory across separate boots or config edits, so
//! nothing stops an operator from reusing a retired id with a *different*
//! secret weeks or months later. That mistake silently and permanently
//! breaks every key still hashed under the old meaning of that id (a live
//! auth outage, not a lint warning), which is why this is a boot-time,
//! fail-closed check rather than a documentation-only convention.
//!
//! `migrations/0044_apikey_pepper_registry.sql` creates
//! `api_key_pepper_registry (pepper_id, secret_fingerprint,
//! first_seen_at)`. At every boot, [`check_and_register`] computes
//! SHA-256(pepper) for the current id and every `apikey_hash_previous_peppers`
//! entry, and either records a first sighting or verifies an existing one
//! still matches. Only the fingerprint is ever persisted — never the pepper
//! itself.

use attome_config::AppConfig;
use attome_db::DbPool;
use attome_types::AppError;
use sha2::{Digest, Sha256};

fn fingerprint(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// Checks (and records, on first sighting) every pepper id this config names
/// against `api_key_pepper_registry`. Fails closed — a mismatched
/// fingerprint is a boot error, not a warning, since continuing would mean
/// serving api-key auth traffic against a pepper the operator most likely
/// didn't intend (the id's original secret was something else).
pub async fn check_and_register(db: &DbPool, config: &AppConfig) -> Result<(), AppError> {
    let auth = &config.auth;
    let mut entries: Vec<(i32, &str)> = vec![(
        auth.apikey_hash_pepper_id as i32,
        auth.apikey_hash_pepper.as_str(),
    )];
    for prev in &auth.apikey_hash_previous_peppers {
        entries.push((prev.id as i32, prev.secret.as_str()));
    }

    for (pepper_id, secret) in entries {
        let fp = fingerprint(secret);

        let existing: Option<String> = sqlx::query_scalar(
            "SELECT secret_fingerprint FROM api_key_pepper_registry WHERE pepper_id = $1",
        )
        .bind(pepper_id)
        .fetch_optional(db)
        .await
        .map_err(|_| AppError::internal("apikey_pepper_registry: failed to read registry"))?;

        match existing {
            Some(recorded) if recorded == fp => {
                // Same secret as last time this id was seen — nothing to do.
            }
            Some(_) => {
                // Never log the fingerprint or the secret alongside this —
                // the fact of a mismatch is the only thing worth surfacing.
                return Err(AppError::internal(format!(
                    "apikey_hash pepper id {pepper_id} was previously registered with a \
                     different secret — pepper ids must never be reused for a different \
                     secret (D-120); every api_key row still hashed under this id's \
                     original meaning would silently stop verifying. Assign a new, never-used \
                     id instead."
                )));
            }
            None => {
                // First time this id has ever been configured — record it.
                // ON CONFLICT DO NOTHING: a concurrent boot on another node
                // racing this exact insert is harmless (same fingerprint
                // either way, first-writer-wins is fine — there is nothing
                // to reconcile).
                sqlx::query(
                    "INSERT INTO api_key_pepper_registry (pepper_id, secret_fingerprint) \
                     VALUES ($1, $2) ON CONFLICT (pepper_id) DO NOTHING",
                )
                .bind(pepper_id)
                .bind(&fp)
                .execute(db)
                .await
                .map_err(|_| {
                    AppError::internal("apikey_pepper_registry: failed to record new pepper id")
                })?;
                tracing::info!(pepper_id, "server: registered new api-key pepper id");
            }
        }
    }

    Ok(())
}

/// attome-auth plan BAU-12d — refuses to boot when a live API key is hashed
/// under a pepper id the configured ring no longer holds. Retiring a pepper
/// from `apikey_hash_previous_peppers` while a key still needs it would make
/// that key fail every request with no error anywhere; this replaces the
/// hand-run SQL in `attome_auth::apikey_hash`'s module doc. A bare `hmac256$`
/// row is id 0; a legacy Argon2 row needs no pepper.
pub async fn check_referenced_peppers_present(
    db: &DbPool,
    config: &AppConfig,
) -> Result<(), AppError> {
    let auth = &config.auth;
    let mut configured: Vec<i32> = vec![auth.apikey_hash_pepper_id as i32];
    configured.extend(
        auth.apikey_hash_previous_peppers
            .iter()
            .map(|p| p.id as i32),
    );

    let referenced: Vec<(i32, i64)> = sqlx::query_as(
        "SELECT CASE WHEN secret_hash LIKE 'hmac256:v%' \
                     THEN substring(secret_hash from '^hmac256:v([0-9]+)\\$')::int \
                     ELSE 0 END AS pepper_id, \
                count(*) AS live_keys \
         FROM api_key \
         WHERE is_active = TRUE AND (expires_at IS NULL OR expires_at > now()) \
           AND secret_hash LIKE 'hmac256%' \
         GROUP BY 1",
    )
    .fetch_all(db)
    .await
    .map_err(|_| AppError::internal("apikey_pepper_registry: failed to count live keys"))?;

    let missing: Vec<String> = referenced
        .iter()
        .filter(|(id, _)| !configured.contains(id))
        .map(|(id, n)| format!("pepper id {id} ({n} live key(s))"))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(AppError::internal(format!(
        "live API keys are hashed under pepper ids missing from auth.apikey_hash_pepper / \
         apikey_hash_previous_peppers: {}. Put each pepper back in \
         apikey_hash_previous_peppers until those keys are rotated or revoked (BAU-12d).",
        missing.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::fingerprint;

    #[test]
    fn fingerprint_is_deterministic_and_distinguishes_secrets() {
        let a = fingerprint("pepper-one-at-least-32-bytes-long-aaa");
        let b = fingerprint("pepper-one-at-least-32-bytes-long-aaa");
        let c = fingerprint("pepper-two-at-least-32-bytes-long-bbb");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64, "sha256 hex digest is 64 chars");
    }
}
