//! The registry of encrypted columns (roadmap Q18-T3): every column that
//! holds a secret the platform must read back (so it is encrypted through
//! [`crate::envelope`], not hashed), with the key domain it is encrypted
//! under. The test `encrypted_column_registry` (crates/apps/attome/tests)
//! fails when a migration adds a credential-like column that is neither in
//! this list, nor a one-way hash or fingerprint, nor a reviewed plain column
//! in [`PLAIN_BY_DESIGN`]; the rewrap job (Q18-T4) walks this list.

/// One encrypted column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedColumn {
    pub table: &'static str,
    pub column: &'static str,
    /// The key domain (envelope field name or key ring) it is encrypted
    /// under.
    pub domain: &'static str,
}

const fn col(table: &'static str, column: &'static str, domain: &'static str) -> EncryptedColumn {
    EncryptedColumn {
        table,
        column,
        domain,
    }
}

/// Every encrypted column, by table.
pub const ENCRYPTED_COLUMNS: &[EncryptedColumn] = &[
    col("ai_provider_credential", "secret_encrypted", "ai_provider"),
    col("einvoice_device", "compliance_secret_encrypted", "einvoice"),
    col("einvoice_device", "private_key_encrypted", "einvoice"),
    col("einvoice_device", "production_secret_encrypted", "einvoice"),
    col(
        "environment_variable_value",
        "value_encrypted",
        "environment_variable",
    ),
    col(
        "event_subscription",
        "webhook_secret_encrypted",
        "events_webhook",
    ),
    col("fleet_deployment", "secret_enc", "fleet"),
    col("integration_credential", "secret_encrypted", "integration"),
    col("mcp_server", "credential_encrypted", "mcp"),
    col("oidc_provider", "client_secret_enc", "oidc"),
    col("recovery_archive", "value_enc", "recovery_archive"),
    col("release_report_item", "values_enc", "release_report"),
    col("s2s_client_key", "secret_encrypted", "s2s"),
    col("user_mail_connection", "access_token_enc", "integration"),
    col("user_mail_connection", "refresh_token_enc", "integration"),
    col("user_mfa", "secret_encrypted", "mfa"),
    col(
        "webportal_credential",
        "mfa_pending_secret_enc",
        "portal_mfa",
    ),
    col("webportal_credential", "mfa_secret_enc", "portal_mfa"),
];

/// Columns whose names look like credentials but hold nothing secret, each
/// with the reason it may stay plain.
pub const PLAIN_BY_DESIGN: &[(&str, &str, &str)] = &[
    (
        "oidc_domain",
        "verification_token",
        "published in the domain's DNS TXT record by design",
    ),
    (
        "einvoice_device",
        "compliance_token",
        "ZATCA's compliance CSID: the certificate it issued (public); its secret is encrypted apart",
    ),
    (
        "einvoice_device",
        "production_token",
        "ZATCA's production CSID: the certificate it issued (public); its secret is encrypted apart",
    ),
    (
        "theme",
        "tokens",
        "design tokens (colours, spacing), not credentials",
    ),
    (
        "environment_variable_history",
        "is_secret",
        "a flag saying whether the value is secret",
    ),
    (
        "setting",
        "is_secret",
        "a flag saying whether the value is secret",
    ),
];

/// Name parts that mark a column as holding a credential.
pub const CREDENTIAL_MARKERS: &[&str] = &[
    "secret",
    "password",
    "credential",
    "private_key",
    "api_key",
    "token",
    "_enc",
    "encrypted",
    "cipher",
];

/// Name endings of columns that are safe to keep plain: one-way hashes and
/// fingerprints, the last four characters shown to admins, references into
/// the secret store, timestamps, and counters.
pub const SAFE_SUFFIXES: &[&str] = &[
    "_hash",
    "_ref",
    "_fingerprint",
    "_last4",
    "_at",
    "_tokens",
    "_tokens_per_session",
];

/// Whether a column name looks like it holds a credential.
pub fn looks_like_credential(column: &str) -> bool {
    let column = column.to_ascii_lowercase();
    CREDENTIAL_MARKERS.iter().any(|m| column.contains(m))
        && !SAFE_SUFFIXES.iter().any(|s| column.ends_with(s))
}

/// Whether a credential-looking column is accounted for.
pub fn accounted_for(table: &str, column: &str) -> bool {
    ENCRYPTED_COLUMNS
        .iter()
        .any(|c| c.table == table && c.column == column)
        || PLAIN_BY_DESIGN
            .iter()
            .any(|(t, c, _)| *t == table && *c == column)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_and_safe_suffixes() {
        assert!(looks_like_credential("client_secret_enc"));
        assert!(looks_like_credential("api_key"));
        assert!(!looks_like_credential("secret_hash"));
        assert!(!looks_like_credential("secret_last4"));
        assert!(!looks_like_credential("input_tokens"));
        assert!(!looks_like_credential("name"));
        assert!(accounted_for("user_mfa", "secret_encrypted"));
        assert!(!accounted_for("user_mfa", "secret_plain"));
    }

    #[test]
    fn the_registry_has_no_duplicates() {
        for (i, a) in ENCRYPTED_COLUMNS.iter().enumerate() {
            for b in &ENCRYPTED_COLUMNS[i + 1..] {
                assert!(!(a.table == b.table && a.column == b.column), "{a:?}");
            }
        }
    }
}
