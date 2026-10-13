//! Portal keywords: the path prefix a portal is served under,
//! `https://example.com/{keyword}/*` (D-572 item 4, carried by D-576).
//!
//! A keyword becomes the first URL segment of a public site and the scope of
//! its cookies, so it must never collide with a path the platform itself
//! serves. [`RESERVED`] names those paths; `xrm` is the staff app's prefix
//! (D-573).

/// First path segments a portal may never claim. Includes the segments nginx
/// and the backend already route (`api`, `health`, `version`, the staff app at
/// `xrm`), and the obvious well-known and asset paths.
pub const RESERVED: &[&str] = &[
    "xrm", "api", "admin", "app", "auth", "health", "version", "assets", "static", "public",
    "portal", "login", "logout", "favicon", "robots", "sitemap",
];

pub const MIN_LEN: usize = 3;
pub const MAX_LEN: usize = 40;

/// Normalizes and validates a keyword: trimmed, lowercased, 3 to 40 of
/// `[a-z0-9-]`, not starting or ending with `-`, and not reserved. Returns the
/// normalized form, which is what gets stored and compared.
pub fn normalize(raw: &str) -> Result<String, String> {
    let kw = raw.trim().to_ascii_lowercase();
    if kw.len() < MIN_LEN || kw.len() > MAX_LEN {
        return Err(format!(
            "keyword must be {MIN_LEN} to {MAX_LEN} characters long"
        ));
    }
    if !kw
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("keyword may contain only lowercase letters, digits and hyphens".into());
    }
    if kw.starts_with('-') || kw.ends_with('-') {
        return Err("keyword may not start or end with a hyphen".into());
    }
    if RESERVED.contains(&kw.as_str()) {
        return Err(format!("'{kw}' is reserved and cannot be a portal keyword"));
    }
    Ok(kw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_lowercases_a_plain_keyword() {
        assert_eq!(normalize("  Customers ").unwrap(), "customers");
        assert_eq!(normalize("partner-2026").unwrap(), "partner-2026");
    }

    #[test]
    fn refuses_the_staff_prefix_and_every_reserved_segment() {
        for kw in RESERVED {
            // Reserved words shorter than MIN_LEN are refused on length first;
            // either way they never become a keyword.
            assert!(normalize(kw).is_err(), "{kw} must be refused");
        }
        assert!(normalize("XRM").is_err(), "case must not bypass the list");
    }

    #[test]
    fn refuses_length_charset_and_edge_hyphens() {
        assert!(normalize("ab").is_err());
        assert!(normalize(&"a".repeat(MAX_LEN + 1)).is_err());
        assert!(normalize(&"a".repeat(MAX_LEN)).is_ok());
        for bad in [
            "cust omers",
            "cust_omers",
            "cust/omers",
            "cust.omers",
            "../x",
            "çustomer",
        ] {
            assert!(normalize(bad).is_err(), "{bad} must be refused");
        }
        assert!(normalize("-customers").is_err());
        assert!(normalize("customers-").is_err());
    }
}
