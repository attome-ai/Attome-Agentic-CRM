//! Small, dependency-free text-normalization helpers shared across crates
//! that otherwise have no reason to depend on each other.

/// Canonicalizes an email for storage/comparison: trims surrounding
/// whitespace, then lowercases. Moved here from `attome_auth::email_identity`
/// (P-email-hardening) so `attome-email` can normalize a recipient before
/// checking its suppression list without depending on the much heavier
/// `attome-auth` (argon2/jsonwebtoken/samael/etc.) for a two-line function —
/// `attome_auth::email_identity::normalize_email` is now a re-export of this.
///
/// Postgres's `lower()` and Rust's `str::to_lowercase()` can diverge on
/// non-ASCII input (locale-independent Unicode case folding vs. Postgres's
/// encoding-dependent `lower()`), so normalization happens once, in Rust,
/// before a value is ever bound to a query.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
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
