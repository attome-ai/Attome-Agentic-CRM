//! The one SQL identifier validator and the one identifier quoter
//! (CLEANUP-REVIEW 3.4, R-14).
//!
//! Identifiers cannot be bind parameters, so every name spliced into dynamic
//! SQL is first checked against a charset and a length cap, then quoted. The
//! charset logic lives here once; callers differ only in which of the two
//! shapes they need and which length cap applies, and each cap is a named
//! constant:
//!
//! - [`PG_MAX_IDENTIFIER_LEN`] (63): PostgreSQL's `NAMEDATALEN - 1`. Longer
//!   names are truncated with only a NOTICE, not an error.
//! - [`MAX_IDENTIFIER_LEN`] (48): the product cap on entity/attribute logical
//!   names and the configured schema name. It leaves room for names derived
//!   from an identifier (`idx_{name}_active` is the name plus 11 bytes).
//!
//! Callers with a different cap (for example `xrm_foundation::data_definition`'s
//! 128) keep their own named constant and pass it to [`valid_logical_name`].
//! Both charsets are pure ASCII, so `str::len` (bytes) equals the character
//! count Postgres sees for any string that passes.
//!
//! `attome-testkit` keeps a private copy of [`quote_ident`]: it deliberately
//! does not depend on `attome-db` (attome-db's own tests take it as a
//! dev-dependency).

/// PostgreSQL's identifier limit (`NAMEDATALEN - 1`), in bytes.
pub const PG_MAX_IDENTIFIER_LEN: usize = 63;

/// The product cap on entity/attribute logical names and the schema name.
/// P-provisioning-hardening item (a).
pub const MAX_IDENTIFIER_LEN: usize = 48;

/// Charset only: `^[a-z_][a-z0-9_]*$`. A leading underscore is allowed.
/// Used where the name is a physical SQL identifier (schema, table, column).
pub fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_') && rest_ok(chars)
}

/// Charset only: `^[a-z][a-z0-9_]*$`. The first character must be a letter.
/// The `xrm_core_attribute_info.logicalname` convention used by
/// definition/widget/chart validators.
pub fn is_logical_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase()) && rest_ok(chars)
}

/// [`is_identifier`] plus a byte-length cap.
pub fn valid_identifier(s: &str, max_len: usize) -> bool {
    s.len() <= max_len && is_identifier(s)
}

/// [`is_logical_name`] plus a byte-length cap.
pub fn valid_logical_name(s: &str, max_len: usize) -> bool {
    s.len() <= max_len && is_logical_name(s)
}

fn rest_ok(mut chars: std::str::Chars<'_>) -> bool {
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Wraps an already-validated identifier for interpolation into dynamic SQL,
/// doubling any embedded `"` (the standard Postgres escaping rule, as libpq's
/// `PQescapeIdentifier`). This is formatting, not validation: validate first.
pub fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_allows_leading_underscore_logical_name_does_not() {
        assert!(is_identifier("_a"));
        assert!(!is_logical_name("_a"));
        for ok in ["a", "abc", "a1", "a_b", "a__", "z9_9"] {
            assert!(is_identifier(ok), "{ok}");
            assert!(is_logical_name(ok), "{ok}");
        }
        for bad in [
            "", "A", "aB", "1a", "a-b", "a b", "a.b", "é", "a\"b", "ab\u{0}",
        ] {
            assert!(!is_identifier(bad), "{bad:?}");
            assert!(!is_logical_name(bad), "{bad:?}");
        }
        assert!(is_identifier("_"));
        assert!(!is_logical_name("_"));
    }

    #[test]
    fn caps_are_inclusive_byte_lengths() {
        let at = "a".repeat(MAX_IDENTIFIER_LEN);
        let over = "a".repeat(MAX_IDENTIFIER_LEN + 1);
        assert!(valid_identifier(&at, MAX_IDENTIFIER_LEN));
        assert!(!valid_identifier(&over, MAX_IDENTIFIER_LEN));
        assert!(valid_logical_name(&at, MAX_IDENTIFIER_LEN));
        assert!(!valid_logical_name(&over, MAX_IDENTIFIER_LEN));
        assert!(valid_identifier(&over, PG_MAX_IDENTIFIER_LEN));
    }

    #[test]
    fn quote_ident_doubles_quotes() {
        assert_eq!(quote_ident("order"), "\"order\"");
        assert_eq!(quote_ident("a\"b\"c"), "\"a\"\"b\"\"c\"");
    }
}
