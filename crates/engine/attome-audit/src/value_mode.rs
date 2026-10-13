//! D-540 rulings 3/G2-1: the three `audit_detail.value_mode` capture
//! modes, derived entirely from existing metadata (no new attribute column,
//! no migration). Replaces plan item 1.4's interim `"********"` masking
//! (plan 5.3).
//!
//! | Mode | Rule | Stored |
//! |---|---|---|
//! | `Encrypted` (0) | default | ciphertext; readable where the field is readable now |
//! | `Restricted` (1) | attribute `is_sensitive` | ciphertext; also needs `audit.view_sensitive` |
//! | `NotCaptured` (2) | credential column (`attome_core::credential_columns`) | value/display/lookup columns NULL |
//!
//! `NotCaptured` wins over `Restricted` when both apply — a credential column
//! is never captured in any form, sensitive or not.

/// `audit_detail.value_mode` (`smallint`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueMode {
    Encrypted = 0,
    Restricted = 1,
    NotCaptured = 2,
}

impl ValueMode {
    pub const fn as_i16(self) -> i16 {
        self as i16
    }
}

/// Classifies one changed field. `entity_name` is the event's owning entity
/// (`None` for an event with no entity, e.g. a security/business event not
/// tied to a record) and `is_sensitive` is the attribute flag already carried
/// on `AuditFieldChange`.
pub fn classify(entity_name: Option<&str>, field_name: &str, is_sensitive: bool) -> ValueMode {
    if attome_core::credential_columns::is_credential_column(entity_name, field_name) {
        ValueMode::NotCaptured
    } else if is_sensitive {
        ValueMode::Restricted
    } else {
        ValueMode::Encrypted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_columns_are_never_captured_even_when_sensitive() {
        assert_eq!(
            classify(Some("user_account"), "password_hash", true),
            ValueMode::NotCaptured
        );
        assert_eq!(
            classify(Some("user_account"), "password_hash", false),
            ValueMode::NotCaptured
        );
    }

    #[test]
    fn sensitive_non_credential_fields_are_restricted() {
        assert_eq!(
            classify(Some("contact"), "national_id", true),
            ValueMode::Restricted
        );
    }

    #[test]
    fn ordinary_fields_are_encrypted() {
        assert_eq!(
            classify(Some("contact"), "email", false),
            ValueMode::Encrypted
        );
        assert_eq!(classify(None, "note", false), ValueMode::Encrypted);
    }
}
