//! One canonical representation for `user_account.email`, used by every
//! writer and reader of that column (register, login, federation link, reset,
//! admin lookup) — extends D-113/P-account-state-enforcement's per-call-site
//! `lower(email)` patchwork (which formalized `login`'s existing
//! case-insensitivity but left `register`/`link_google_account`/
//! `link_external_identity` comparing the raw column, D-121) into one
//! function so a future call site can't reintroduce the mismatch.
//!
//! Postgres's `lower()` and Rust's `str::to_lowercase()` can diverge on
//! non-ASCII input (locale-independent Unicode case folding vs. Postgres's
//! encoding-dependent `lower()`), so normalization happens once, in Rust,
//! before a value is ever bound to a query — the SQL side then does plain
//! equality against an already-canonical column, never its own `lower()`
//! call.

/// Canonicalizes an email for storage/comparison: trims surrounding
/// whitespace, then lowercases. Applied before every INSERT/UPDATE that
/// writes `user_account.email` and before every WHERE clause that reads
/// it by value — never done in SQL (`lower()`/`btrim()`) except inside the
/// one migration that backfills existing rows.
///
/// Moved to `attome_types::text` (P-email-hardening) so `attome-email` can reuse
/// it without depending on this crate; re-exported here so no existing call
/// site in this crate needs to change.
pub use attome_types::text::normalize_email;

/// Acquires a non-blocking, per-normalized-email advisory lock inside the
/// caller's transaction (guidelines §2, Layer 2) — namespace
/// `attome-auth/account-email:{email}`. Every writer that can create, disable,
/// re-enable, or federation-link an account sharing this email must take
/// this lock before its own existence/state check, so two concurrent writers
/// (e.g. a registration and an admin disable) can't each observe a
/// pre-write snapshot and both proceed — a plain `SELECT` inside a
/// READ COMMITTED transaction does not serialize a check against a
/// concurrent writer touching a *different* row (D-121, extends D-113).
///
/// Returns `Ok(false)` (never blocks) when another transaction already holds
/// the lock for this email — the caller should surface this the same way it
/// would surface "email already in use", since a concurrent writer holding
/// this lock is, from this request's point of view, indistinguishable from
/// a losing race for the same identity.
pub async fn try_lock_email(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    normalized_email: &str,
) -> Result<bool, attome_types::AppError> {
    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-auth/account-email:{normalized_email}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(attome_types::AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_and_lowercases() {
        assert_eq!(normalize_email("  User@Example.com  "), "user@example.com");
    }

    #[test]
    fn idempotent() {
        let once = normalize_email("User@Example.com");
        assert_eq!(normalize_email(&once), once);
    }
}
