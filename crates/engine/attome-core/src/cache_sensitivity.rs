//! Z3-T3: how a cache holding an entity's fields must keep them. A cache
//! that stores record fields declares the sensitivity this answers for those
//! fields: a credential column is never cached at all, a sensitive field is
//! sealed before it reaches Redis, anything else is plain.
//!
//! When A1's data labels land they replace `is_sensitive` here: Financial,
//! Health and Personal fields give `EncryptedInRedis`, and Secret fields are
//! refused like credential columns.

use attome_cache::spec::CacheSensitivity;
use attome_types::AppError;

use crate::credential_columns::is_credential_column;

/// The sensitivity a cache of `entity`'s `fields` (`(name, is_sensitive)`)
/// needs. A credential column is refused: it may not be cached anywhere.
pub fn sensitivity_for_fields(
    entity: &str,
    fields: &[(&str, bool)],
) -> Result<CacheSensitivity, AppError> {
    if let Some((name, _)) = fields
        .iter()
        .find(|(name, _)| is_credential_column(Some(entity), name))
    {
        return Err(AppError::Validation(format!(
            "{entity}.{name} is a credential column and may not be cached"
        )));
    }
    Ok(if fields.iter().any(|(_, sensitive)| *sensitive) {
        CacheSensitivity::EncryptedInRedis
    } else {
        CacheSensitivity::Plain
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_column_refused() {
        assert!(
            sensitivity_for_fields(
                "user_account",
                &[("email", false), ("password_hash", false)]
            )
            .is_err()
        );
        assert!(sensitivity_for_fields("api_key", &[("secret_hash", true)]).is_err());
    }

    #[test]
    fn sensitive_fields_are_sealed_and_others_plain() {
        assert_eq!(
            sensitivity_for_fields("deal", &[("name", false), ("margin", true)]).unwrap(),
            CacheSensitivity::EncryptedInRedis
        );
        assert_eq!(
            sensitivity_for_fields("deal", &[("name", false)]).unwrap(),
            CacheSensitivity::Plain
        );
        // `password_hash` is only a credential on `user_account`.
        assert_eq!(
            sensitivity_for_fields("deal", &[("password_hash", false)]).unwrap(),
            CacheSensitivity::Plain
        );
    }
}
