//! Dev-only: keeps local access working across a database reset — a known
//! login password ([`seed_login`]) and a known API key ([`seed_api_key`]), so
//! resetting `attome_dev` does not lock you out of your own dev environment or
//! silently strand every scripted caller.
//!
//! # Why this is not a production capability
//!
//! A deployment that manufactures its own admin credential is a backdoor —
//! nobody created it, so nobody audits it. Neither function here ever runs
//! outside local development, gated three independent ways (the same
//! convention `admin/dev_scaffold.rs` already uses, deliberately not a
//! fourth):
//!
//! 1. `#[cfg(debug_assertions)]` on the `mod` declaration in `lib.rs` — the
//!    code is physically absent from a release binary.
//! 2. `APP_ENV=debug`.
//! 3. The relevant secret env var is set. Unset is the default, and the
//!    default is inert: nothing created, nothing changed, no warning.
//!
//! # Why the secrets come from the environment
//!
//! The obvious design — generate them at boot — cannot work safely. A
//! generated secret is only useful if you can read it, which means logging it
//! or writing it to disk, and guidelines §7 forbids logging credential
//! material for good reason. Taking them from `.env` inverts that: you
//! already hold the values, so this module never has to reveal anything. Only
//! non-secret identifiers (public key, email) are ever logged.
//!
//! Rotation is editing `.env` and restarting — both seeds rewrite the stored
//! hash every boot, so what is stored always matches what is configured
//! rather than drifting from it.

use attome_auth::{NewPassword, email_identity::try_lock_email, hash_password_async};
use attome_core::EngineState;
use attome_types::AppError;
use attome_types::text::normalize_email;
use uuid::Uuid;

/// Default `public_key` when `ATTOME_AGENT_API_PUBLIC_KEY` is unset. Stable
/// and non-secret by design: scripts can hardcode it, and only the paired
/// secret grants anything.
const DEFAULT_PUBLIC_KEY: &str = "atk_pub_devagent";

/// Minimum accepted API secret length.
const MIN_SECRET_LEN: usize = 32;

/// Minimum accepted login password length. Nothing in the codebase enforces a
/// password policy today, so this is this module's own floor rather than a
/// shared rule — a weak password on an admin-owned account fails the boot
/// instead of being quietly accepted.
const MIN_PASSWORD_LEN: usize = 12;

fn dev_env_active() -> bool {
    attome_config::is_debug_env()
}

/// Reads an env var, treating unset and blank as the same "not configured".
fn configured(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

// ── Login password ───────────────────────────────────────────────────────────

/// Forces `ATTOME_DEV_LOGIN_EMAIL`'s password to `ATTOME_DEV_LOGIN_PASSWORD`,
/// creating the account if it does not exist.
///
/// This is the piece `server --bootstrap-admin <email>` does not cover: that
/// command mints a *random* password, prints it once, and deliberately leaves
/// an existing account untouched on re-run. Useful for standing up an admin,
/// useless for "I reset the database again and want my usual login back".
/// This resets unconditionally, to a password you already know.
///
/// Admin rights are **not** granted here — this only owns the credential.
/// Run `server --bootstrap-admin <email>` once against the same address for
/// that; it grants `system.admin` to the account this seed already created
/// rather than minting a second one. Keeping the two separate means no boot
/// can quietly widen who is an administrator (D-495).
pub async fn seed_login(state: &EngineState) -> Result<(), AppError> {
    if !dev_env_active() {
        return Ok(());
    }
    let Some(password) = configured("ATTOME_DEV_LOGIN_PASSWORD") else {
        return Ok(());
    };
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AppError::internal(format!(
            "ATTOME_DEV_LOGIN_PASSWORD must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    let Some(email) = configured("ATTOME_DEV_LOGIN_EMAIL") else {
        return Err(AppError::internal(
            "ATTOME_DEV_LOGIN_PASSWORD is set but ATTOME_DEV_LOGIN_EMAIL is not — \
             refusing to guess which account to reset",
        ));
    };

    // `login` looks the account up by normalized email, so a mixed-case value
    // here would otherwise write a row login could never match.
    let email = normalize_email(&email);
    let password_hash = hash_password_async(NewPassword::platform_generated(password)).await?;

    let db = &state.base.db_migrator;
    let mut tx = attome_db::tx::begin(db).await?;

    // The same per-email advisory lock every other account writer takes
    // (guidelines §2, D-121) — a concurrent register/disable for this email
    // cannot interleave with the check-then-write below.
    if !try_lock_email(&mut tx, &email).await? {
        return Err(AppError::Conflict(
            "email is concurrently held by another account operation, retry",
        ));
    }

    let existing: Option<(Uuid, Option<bool>)> =
        sqlx::query_as("SELECT id, is_active FROM user_account WHERE email = $1")
            .bind(&email)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;

    let (user_id, action) = match existing {
        Some((user_id, is_active)) => {
            // A disabled account is reactivated: on a dev box the intent of
            // setting this variable is unambiguously "let me log in", and
            // leaving it disabled would fail the login with nothing in the
            // log explaining why.
            sqlx::query(
                "UPDATE user_account \
                    SET password_hash = $2, is_active = TRUE, email_verified = TRUE \
                  WHERE id = $1",
            )
            .bind(user_id)
            .bind(&password_hash)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            let action = if is_active == Some(false) {
                "password reset, account re-enabled"
            } else {
                "password reset"
            };
            (user_id, action)
        }
        None => {
            let user_id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO user_account \
                     (id, email, password_hash, created_at, is_active, email_verified) \
                 VALUES ($1, $2, $3, NOW(), TRUE, TRUE)",
            )
            .bind(user_id)
            .bind(&email)
            .bind(&password_hash)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            (user_id, "account created")
        }
    };

    tx.commit().await.map_err(AppError::internal)?;

    // Email and id only — never the password.
    tracing::warn!(
        email = %email,
        user_id = %user_id,
        action,
        "development-only login password is active (ATTOME_DEV_LOGIN_PASSWORD is set)"
    );
    Ok(())
}

// ── API key ──────────────────────────────────────────────────────────────────

/// Upserts an API key whose secret is `ATTOME_AGENT_API_SECRET`, so scripted
/// and agent callers keep working across a database reset.
pub async fn seed_api_key(state: &EngineState) -> Result<(), AppError> {
    if !dev_env_active() {
        return Ok(());
    }
    let Some(secret) = configured("ATTOME_AGENT_API_SECRET") else {
        return Ok(());
    };
    if secret.chars().count() < MIN_SECRET_LEN {
        return Err(AppError::internal(format!(
            "ATTOME_AGENT_API_SECRET must be at least {MIN_SECRET_LEN} characters \
             (generate one with: openssl rand -hex 32)"
        )));
    }

    let public_key =
        configured("ATTOME_AGENT_API_PUBLIC_KEY").unwrap_or_else(|| DEFAULT_PUBLIC_KEY.to_owned());

    let db = &state.base.db_migrator;

    // Which user the key acts as. `ATTOME_AGENT_API_USER_EMAIL` pins it
    // explicitly; otherwise the oldest active user, which on a freshly
    // bootstrapped dev database is the bootstrap admin. Resolved rather than
    // created — this never mints a user (that is `seed_login`'s job, behind
    // its own separate opt-in), so it cannot widen who exists.
    let user_ref: Option<Uuid> = match configured("ATTOME_AGENT_API_USER_EMAIL") {
        Some(email) => {
            let email = normalize_email(&email);
            sqlx::query_scalar("SELECT id FROM user_account WHERE email = $1 AND is_active = TRUE")
                .bind(&email)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?
        }
        None => sqlx::query_scalar(
            "SELECT id FROM user_account WHERE is_active = TRUE \
             ORDER BY created_at ASC NULLS LAST, id LIMIT 1",
        )
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?,
    };

    let Some(user_ref) = user_ref else {
        // Not an error: on a brand-new database this can run before any user
        // exists. Configure `seed_login` above, or the next boot picks it up.
        tracing::warn!(
            "dev agent api key: no active system user to own the key yet; skipping this boot"
        );
        return Ok(());
    };

    // Same hashing path as `attome_security::api_keys::create_api_key` — built
    // from the secret bundle so a config-rotated pepper is honoured, and
    // always hashing with the ring's *current* pepper id (D-120).
    let ring = state.base.pepper_ring();
    let secret_hash = ring.hash(&secret);

    // Upsert on the partial unique index `core_apikey_public_key_unique`
    // (`UNIQUE (public_key) WHERE is_active = true`), so the predicate has to
    // be restated here for PostgreSQL to match that index. Rewriting
    // `secret_hash`/`user_ref` on conflict is what makes an edited `.env` take
    // effect on restart instead of silently disagreeing with the stored row.
    sqlx::query(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (public_key) WHERE is_active = true \
         DO UPDATE SET secret_hash = EXCLUDED.secret_hash, \
                       user_ref    = EXCLUDED.user_ref, \
                       modified_at  = NOW()",
    )
    .bind(user_ref)
    .bind("dev agent (ATTOME_AGENT_API_SECRET)")
    .bind(&public_key)
    .bind(&secret_hash)
    .execute(db)
    .await
    .map_err(AppError::internal)?;

    // Public key only — the secret is yours, and this has no reason to echo it.
    tracing::warn!(
        public_key = %public_key,
        user_ref = %user_ref,
        "development-only agent API key is active (ATTOME_AGENT_API_SECRET is set)"
    );
    Ok(())
}
