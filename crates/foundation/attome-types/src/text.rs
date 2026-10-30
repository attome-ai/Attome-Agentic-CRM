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

/// A host name as stored and matched: lower case, no port, no trailing
/// dot; `None` when it is not a plain host name. Pure. A content site's
/// domain (E12-T2) and a web portal's (G12-T3) are both kept this way.
pub fn normalise_domain(host: &str) -> Option<String> {
    let host = host.trim().to_ascii_lowercase();
    let host = host
        .split(':')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.');
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && host
            .split('.')
            .all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'))
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    valid.then(|| host.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_normalise_and_bad_ones_are_refused() {
        assert_eq!(
            normalise_domain("Portal.Example.COM:443").as_deref(),
            Some("portal.example.com")
        );
        assert!(normalise_domain("localhost").is_none());
        assert!(normalise_domain("bad_host.com").is_none());
    }

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
