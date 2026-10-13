//! The `--bootstrap-admin` composition.
//!
//! `crates/server`'s CLI owns argv, the operator-facing messages and granting
//! `system.admin`; `attome_auth` owns how the row is written. This runs the
//! per-email lock and the insert in one transaction, which is why `attome-auth`
//! has `bootstrap_admin_in_tx`.
//!
//! It used to gate the insert on the licence's seat count as well (M04 Phase 2,
//! LIC-F2). D-778 removed seat enforcement, and CLEANUP-REVIEW 1.2 removed the
//! deployment-wide seat-admission lock that gate took; the name
//! `bootstrap_admin_gated` is kept for its caller.

use attome_auth::accounts::BootstrapOutcome;
use attome_db::DbPool;
use attome_types::AppError;

/// Creates or resolves the first administrator.
///
/// Idempotent: re-running `--bootstrap-admin` for an existing account resolves
/// it rather than failing, so a retry after a typo keeps working.
pub async fn bootstrap_admin_gated(db: &DbPool, email: &str) -> Result<BootstrapOutcome, AppError> {
    let normalized_email = attome_auth::email_identity::normalize_email(email);
    // The Argon2 hash is computed here, before the transaction opens, so the
    // per-email lock below is never held across the KDF wait (a concurrent
    // registration of the same email would otherwise get a `Conflict` for its
    // whole duration).
    let credentials = attome_auth::accounts::BootstrapCredentials::generate().await?;
    let mut tx = attome_db::tx::begin(db).await?;

    // Non-blocking `try_` form, so a contended email is a retryable conflict
    // rather than a block.
    if !attome_auth::email_identity::try_lock_email(&mut tx, &normalized_email).await? {
        return Err(AppError::Conflict(
            "the account email is held by a concurrent operation, retry",
        ));
    }

    let outcome = attome_auth::accounts::bootstrap_admin_in_tx(&mut tx, email, credentials).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(outcome)
}
