//! D-540 (G2-1 a): the one shared list of credential columns that must never
//! leave plaintext or ciphertext at rest anywhere outside their owning table.
//! Two independent consumers read this same list so they can never disagree:
//! `attome-metadata`'s `attome_readonly` column-level grant (excludes these
//! columns from the read-only role's SELECT) and audit capture (`attome-audit`'s
//! `NotCaptured` value mode — these columns are never written to
//! `audit_detail`/`audit_snapshot` in any form, plaintext or cipher).
//!
//! No new metadata column and no migration (D-540): a customer-defined field
//! cannot be marked secret this way, only `is_sensitive` (`Restricted`:
//! encrypted and privileged, but still captured). Accepted cost, per D-540.

/// `(entity logicalname, credential column names)`.
pub const CREDENTIAL_ENTITY_EXCLUDED_COLUMNS: &[(&str, &[&str])] = &[
    ("user_account", &["password_hash"]),
    ("api_key", &["secret_hash"]),
];

/// Whether `field_name` on `entity_name` is a credential column that must
/// never be captured (D-540 `NotCaptured`). `entity_name` of `None` (an event
/// with no owning entity) is never a credential column.
pub fn is_credential_column(entity_name: Option<&str>, field_name: &str) -> bool {
    let Some(entity_name) = entity_name else {
        return false;
    };
    CREDENTIAL_ENTITY_EXCLUDED_COLUMNS
        .iter()
        .find(|(name, _)| *name == entity_name)
        .is_some_and(|(_, cols)| cols.contains(&field_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_listed_credential_columns() {
        assert!(is_credential_column(Some("user_account"), "password_hash"));
        assert!(is_credential_column(Some("api_key"), "secret_hash"));
    }

    #[test]
    fn does_not_flag_unrelated_fields_or_entities() {
        assert!(!is_credential_column(Some("user_account"), "email"));
        assert!(!is_credential_column(Some("contact"), "password_hash"));
        assert!(!is_credential_column(None, "password_hash"));
    }

    /// D-540's own guard test intent: a registered attribute whose name
    /// matches a credential-shaped pattern must be either listed here or in
    /// a reviewed allowlist. This crate has no attribute registry to scan,
    /// so this just pins the two known entries so an edit here is visible in
    /// review, rather than silently widening or narrowing the list.
    #[test]
    fn the_closed_list_is_exactly_these_two_entries() {
        assert_eq!(CREDENTIAL_ENTITY_EXCLUDED_COLUMNS.len(), 2);
        assert_eq!(
            CREDENTIAL_ENTITY_EXCLUDED_COLUMNS[0],
            ("user_account", &["password_hash"] as &[&str])
        );
        assert_eq!(
            CREDENTIAL_ENTITY_EXCLUDED_COLUMNS[1],
            ("api_key", &["secret_hash"] as &[&str])
        );
    }
}
