//! Q19-T1: encryption of labelled attributes at the engine layer.
//!
//! An attribute opts in through its options, `{"encryption": {"mode":
//! "randomised"}}` or `{"encryption": {"mode": "deterministic"}}`, and only
//! when it is a text field whose confirmed sensitivity label is Personal,
//! Financial, Health or Secret ([`Sensitivity::is_gated`]).
//!
//! - **Randomised** (the default) seals each value with a fresh nonce, bound
//!   to its row (`attome_auth::envelope::encrypt_bound`, `table|column|id`):
//!   equal values look different at rest, and nothing but `is_null` and
//!   `is_not_null` can filter on it.
//! - **Deterministic** is for an attribute that must answer equality
//!   (`eq`, `neq`, `in`): the value is sealed with a synthetic nonce
//!   (`encrypt_deterministic`, bound to `table|column` only) and the search
//!   compares a blind index, a keyed HMAC of the normalised value truncated
//!   to 128 bits, never the value.
//!
//! Range filters, text matching and sorts are refused on every encrypted
//! attribute ([`check_filter`], [`check_sort`]): a ciphertext has no order and
//! no substrings, and answering them would mean decrypting the table.
//!
//! The key is a [`KeyRing`] of its own trust domain, so a rotation (Q19-T3)
//! reseals values under the active key while an old key still opens them,
//! and an equality search matches the index under every key in the ring.

use attome_auth::envelope::{self, RowBinding};
use attome_config::KeyRing;
use attome_core::{AttrInfo, FieldType};
use attome_types::AppError;
use attome_types::secret::SecretString;
use uuid::Uuid;

/// Shapes error messages only; never key material.
const KEY_FIELD: &str = "attribute encryption key";

/// The options key an attribute's encryption settings live under.
pub const OPTIONS_KEY: &str = "encryption";

/// How an encrypted attribute's values are sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrCryptoMode {
    /// A fresh nonce per write, bound to the row. No search.
    Randomised,
    /// The same value seals the same way in one column, with a blind index
    /// for equality search.
    Deterministic,
}

impl AttrCryptoMode {
    /// The value `options.encryption.mode` names, if it names one.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "randomised" | "randomized" => Some(Self::Randomised),
            "deterministic" => Some(Self::Deterministic),
            _ => None,
        }
    }

    /// Whether equality filters can be answered (through the blind index).
    pub fn equality_search(self) -> bool {
        self == Self::Deterministic
    }
}

/// Where one encrypted value lives.
#[derive(Debug, Clone, Copy)]
pub struct AttrBinding<'a> {
    pub table: &'a str,
    pub column: &'a str,
    pub row_id: Uuid,
}

impl AttrBinding<'_> {
    /// The context a deterministic value and its blind index are bound to:
    /// the column, not the row, so equal values in one column match.
    fn column_context(&self) -> Vec<u8> {
        column_context(self.table, self.column)
    }

    fn row(&self) -> RowBinding<'_> {
        RowBinding {
            table: self.table,
            column: self.column,
            row_id: self.row_id,
        }
    }
}

fn column_context(table: &str, column: &str) -> Vec<u8> {
    format!("{table}|{column}").into_bytes()
}

/// The `options.encryption` object of `attr`, if it carries one.
fn encryption_options(attr: &AttrInfo) -> Option<&serde_json::Value> {
    attr.options.as_ref()?.get(OPTIONS_KEY)
}

/// The mode `attr` is encrypted with, or `None` when it is stored in clear.
/// An attribute whose options ask for encryption but which is not eligible
/// ([`validate`] refuses it at the admin route) reads as not encrypted here
/// rather than failing every read of its entity.
pub fn mode_for(attr: &AttrInfo) -> Option<AttrCryptoMode> {
    let options = encryption_options(attr)?;
    let mode = match options.get("mode") {
        None => AttrCryptoMode::Randomised,
        Some(value) => AttrCryptoMode::parse(value.as_str()?)?,
    };
    is_eligible(attr).then_some(mode)
}

/// Whether `attr` may be encrypted: a text field with a confirmed label of
/// Personal, Financial, Health or Secret.
pub fn is_eligible(attr: &AttrInfo) -> bool {
    attr.field_type() == FieldType::Text
        && attr.sensitivity_confirmed
        && attr.sensitivity.is_gated()
}

/// The admin-side check of an attribute's encryption options: `Ok` when it
/// asks for none, or asks for a known mode on an eligible attribute that is
/// not sortable. Names the field and the reason; never a value.
pub fn validate(attr: &AttrInfo) -> Result<(), AppError> {
    let Some(options) = encryption_options(attr) else {
        return Ok(());
    };
    let field = &attr.logicalname;
    if !options.is_object() {
        return Err(AppError::Validation(format!(
            "{field}: options.encryption must be an object"
        )));
    }
    if let Some(mode) = options.get("mode")
        && mode.as_str().and_then(AttrCryptoMode::parse).is_none()
    {
        return Err(AppError::Validation(format!(
            "{field}: options.encryption.mode must be randomised or deterministic"
        )));
    }
    if attr.field_type() != FieldType::Text {
        return Err(AppError::Validation(format!(
            "{field}: only a text field can be encrypted"
        )));
    }
    if !(attr.sensitivity_confirmed && attr.sensitivity.is_gated()) {
        return Err(AppError::Validation(format!(
            "{field}: encryption needs a confirmed personal, financial, health or secret label"
        )));
    }
    if attr.is_sortable {
        return Err(AppError::Validation(format!(
            "{field}: an encrypted field cannot be sortable"
        )));
    }
    Ok(())
}

/// The filter operators an encrypted attribute answers in `mode`.
fn allowed_ops(mode: AttrCryptoMode) -> &'static [&'static str] {
    match mode {
        AttrCryptoMode::Randomised => &["is_null", "is_not_null"],
        AttrCryptoMode::Deterministic => &["is_null", "is_not_null", "eq", "neq", "in"],
    }
}

/// Refuses a filter `op` an encrypted `attr` cannot answer: ranges, text
/// matching and the tree and distance operators always, equality unless the
/// attribute is deterministic. `Ok` for an attribute stored in clear.
pub fn check_filter(attr: &AttrInfo, op: &str) -> Result<(), AppError> {
    let Some(mode) = mode_for(attr) else {
        return Ok(());
    };
    if allowed_ops(mode).contains(&op) {
        return Ok(());
    }
    Err(AppError::Validation(format!(
        "{}: the field is encrypted, so it can only be filtered with {}",
        attr.logicalname,
        allowed_ops(mode).join(", ")
    )))
}

/// Refuses a sort on an encrypted `attr`: a ciphertext has no order.
pub fn check_sort(attr: &AttrInfo) -> Result<(), AppError> {
    if mode_for(attr).is_some() {
        return Err(AppError::Validation(format!(
            "{}: the field is encrypted, so it cannot be sorted",
            attr.logicalname
        )));
    }
    Ok(())
}

/// What a blind index is computed over: the value trimmed and lowercased, so
/// equality on an encrypted field ignores case and surrounding spaces (an
/// email address or an identity number typed either way still matches).
pub fn normalise_for_index(value: &str) -> String {
    value.trim().to_lowercase()
}

/// Seals `plaintext` for storage at `binding` in `mode`.
pub fn seal(
    ring: &KeyRing,
    mode: AttrCryptoMode,
    binding: AttrBinding<'_>,
    plaintext: &str,
) -> Result<String, AppError> {
    match mode {
        AttrCryptoMode::Randomised => {
            envelope::encrypt_bound(KEY_FIELD, ring, plaintext, binding.row())
        }
        AttrCryptoMode::Deterministic => {
            envelope::encrypt_deterministic(KEY_FIELD, ring, plaintext, &binding.column_context())
        }
    }
}

/// Opens a value [`seal`] stored at `binding`, in whichever mode it was
/// sealed (the envelope's version byte says), so changing an attribute's mode
/// leaves its older values readable until they are resealed.
pub fn open(
    ring: &KeyRing,
    binding: AttrBinding<'_>,
    stored: &str,
) -> Result<SecretString, AppError> {
    if envelope::stored_is_deterministic(stored) {
        envelope::decrypt_deterministic(KEY_FIELD, ring, stored, &binding.column_context())
    } else {
        envelope::decrypt_bound(KEY_FIELD, ring, stored, binding.row())
    }
}

/// The blind index a write stores beside a deterministic value, under the
/// ring's active key.
pub fn blind_index(
    ring: &KeyRing,
    table: &str,
    column: &str,
    value: &str,
) -> Result<String, AppError> {
    envelope::blind_index(
        KEY_FIELD,
        ring,
        &column_context(table, column),
        &normalise_for_index(value),
    )
}

/// The blind indexes an equality search on `value` matches: one per key in
/// the ring, so rows a rotation has not reached yet are still found.
pub fn search_indexes(
    ring: &KeyRing,
    table: &str,
    column: &str,
    value: &str,
) -> Result<Vec<String>, AppError> {
    envelope::blind_indexes(
        KEY_FIELD,
        ring,
        &column_context(table, column),
        &normalise_for_index(value),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::{OnTargetDelete, Sensitivity};
    use serde_json::json;

    const TEXT: i32 = 3;
    const NUMBER: i32 = 1;

    fn attr(
        field_type_int: i32,
        label: Sensitivity,
        options: Option<serde_json::Value>,
    ) -> AttrInfo {
        AttrInfo {
            logicalname: "national_id".to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::Orphan,
            data_classification: Default::default(),
            sensitivity: label,
            sensitivity_confirmed: true,
            options,
        }
    }

    fn encrypted(mode: &str) -> AttrInfo {
        attr(
            TEXT,
            Sensitivity::Personal,
            Some(json!({ "encryption": { "mode": mode } })),
        )
    }

    fn ring(ids: &[(&str, u8)], active: &str) -> KeyRing {
        KeyRing {
            keys: ids
                .iter()
                .map(|(id, byte)| (id.to_string(), hex_key(*byte)))
                .collect(),
            active_key_id: active.to_string(),
        }
    }

    fn hex_key(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn binding(row_id: Uuid) -> AttrBinding<'static> {
        AttrBinding {
            table: "contact",
            column: "national_id",
            row_id,
        }
    }

    #[test]
    fn attr_crypto_mode_comes_from_options_on_an_eligible_field() {
        assert_eq!(
            mode_for(&encrypted("randomised")),
            Some(AttrCryptoMode::Randomised)
        );
        assert_eq!(
            mode_for(&encrypted("deterministic")),
            Some(AttrCryptoMode::Deterministic)
        );
        let default_mode = attr(TEXT, Sensitivity::Secret, Some(json!({ "encryption": {} })));
        assert_eq!(mode_for(&default_mode), Some(AttrCryptoMode::Randomised));
        assert_eq!(mode_for(&attr(TEXT, Sensitivity::Personal, None)), None);
    }

    #[test]
    fn attr_crypto_needs_a_confirmed_gated_label_on_text() {
        let options = Some(json!({ "encryption": { "mode": "randomised" } }));
        let internal = attr(TEXT, Sensitivity::Internal, options.clone());
        assert_eq!(mode_for(&internal), None);
        assert!(validate(&internal).is_err());

        let mut unconfirmed = attr(TEXT, Sensitivity::Health, options.clone());
        unconfirmed.sensitivity_confirmed = false;
        assert_eq!(mode_for(&unconfirmed), None);
        assert!(validate(&unconfirmed).is_err());

        let number = attr(NUMBER, Sensitivity::Financial, options.clone());
        assert_eq!(mode_for(&number), None);
        assert!(validate(&number).is_err());

        for label in [
            Sensitivity::Personal,
            Sensitivity::Financial,
            Sensitivity::Health,
            Sensitivity::Secret,
        ] {
            assert!(validate(&attr(TEXT, label, options.clone())).is_ok());
        }
    }

    #[test]
    fn attr_crypto_validate_refuses_bad_options_and_sortable() {
        let bad_mode = attr(
            TEXT,
            Sensitivity::Personal,
            Some(json!({ "encryption": { "mode": "rot13" } })),
        );
        assert!(validate(&bad_mode).is_err());
        let not_object = attr(
            TEXT,
            Sensitivity::Personal,
            Some(json!({ "encryption": true })),
        );
        assert!(validate(&not_object).is_err());
        let mut sortable = encrypted("deterministic");
        sortable.is_sortable = true;
        assert!(validate(&sortable).is_err());
        assert!(validate(&attr(NUMBER, Sensitivity::Internal, None)).is_ok());
    }

    #[test]
    fn attr_crypto_refuses_range_filters_and_sorts() {
        for mode in ["randomised", "deterministic"] {
            let field = encrypted(mode);
            for op in [
                "gt",
                "gte",
                "lt",
                "lte",
                "contains",
                "starts_with",
                "ends_with",
                "contains_any",
                "contains_all",
                "under",
                "above",
                "within_km",
            ] {
                let error = check_filter(&field, op).unwrap_err();
                assert!(matches!(error, AppError::Validation(_)), "{mode} {op}");
            }
            assert!(check_filter(&field, "is_null").is_ok());
            assert!(check_filter(&field, "is_not_null").is_ok());
            assert!(matches!(check_sort(&field), Err(AppError::Validation(_))));
        }
    }

    #[test]
    fn attr_crypto_equality_only_when_deterministic() {
        let randomised = encrypted("randomised");
        let deterministic = encrypted("deterministic");
        for op in ["eq", "neq", "in"] {
            assert!(check_filter(&randomised, op).is_err());
            assert!(check_filter(&deterministic, op).is_ok());
        }
        let clear = attr(TEXT, Sensitivity::Personal, None);
        assert!(check_filter(&clear, "gt").is_ok());
        assert!(check_sort(&clear).is_ok());
    }

    #[test]
    fn attr_crypto_randomised_round_trips_and_binds_the_row() {
        let ring = ring(&[("k1", 7)], "k1");
        let row = Uuid::now_v7();
        let a = seal(
            &ring,
            AttrCryptoMode::Randomised,
            binding(row),
            "784-1990-1234567-1",
        )
        .unwrap();
        let b = seal(
            &ring,
            AttrCryptoMode::Randomised,
            binding(row),
            "784-1990-1234567-1",
        )
        .unwrap();
        assert_ne!(a, b, "a randomised value never repeats");
        assert!(!a.contains("784"));
        assert_eq!(
            open(&ring, binding(row), &a).unwrap().expose_secret(),
            "784-1990-1234567-1"
        );
        assert!(
            open(&ring, binding(Uuid::now_v7()), &a).is_err(),
            "a value copied to another row must not open"
        );
    }

    #[test]
    fn attr_crypto_deterministic_round_trips_across_rows() {
        let ring = ring(&[("k1", 7)], "k1");
        let a = seal(
            &ring,
            AttrCryptoMode::Deterministic,
            binding(Uuid::now_v7()),
            "x",
        )
        .unwrap();
        let b = seal(
            &ring,
            AttrCryptoMode::Deterministic,
            binding(Uuid::now_v7()),
            "x",
        )
        .unwrap();
        assert_eq!(a, b, "equal values in one column seal alike");
        assert_eq!(
            open(&ring, binding(Uuid::now_v7()), &a)
                .unwrap()
                .expose_secret(),
            "x"
        );
        let other_column = AttrBinding {
            column: "passport_no",
            ..binding(Uuid::now_v7())
        };
        assert!(open(&ring, other_column, &a).is_err());
    }

    #[test]
    fn attr_crypto_blind_index_matches_equal_values_only() {
        let ring = ring(&[("k1", 7)], "k1");
        let stored = blind_index(&ring, "contact", "email", "Layla@Example.com ").unwrap();
        let search = search_indexes(&ring, "contact", "email", "layla@example.com").unwrap();
        assert!(search.contains(&stored), "case and spaces do not matter");
        let other = blind_index(&ring, "contact", "email", "omar@example.com").unwrap();
        assert!(!search.contains(&other));
        assert!(!stored.contains("layla"));
        let other_column =
            blind_index(&ring, "contact", "work_email", "layla@example.com").unwrap();
        assert_ne!(stored, other_column);
    }

    #[test]
    fn attr_crypto_search_finds_rows_under_an_old_key() {
        let before = ring(&[("k1", 7)], "k1");
        let stored_before_rotation = blind_index(&before, "contact", "email", "a@b.test").unwrap();
        let rotating = ring(&[("k1", 7), ("k2", 8)], "k2");
        let search = search_indexes(&rotating, "contact", "email", "a@b.test").unwrap();
        assert_eq!(search.len(), 2);
        assert!(search.contains(&stored_before_rotation));
        assert!(search.contains(&blind_index(&rotating, "contact", "email", "a@b.test").unwrap()));
    }

    #[test]
    fn attr_crypto_old_key_values_still_open_after_rotation() {
        let before = ring(&[("k1", 7)], "k1");
        let row = Uuid::now_v7();
        let random = seal(&before, AttrCryptoMode::Randomised, binding(row), "r").unwrap();
        let det = seal(&before, AttrCryptoMode::Deterministic, binding(row), "d").unwrap();
        let rotating = ring(&[("k1", 7), ("k2", 8)], "k2");
        assert_eq!(
            open(&rotating, binding(row), &random)
                .unwrap()
                .expose_secret(),
            "r"
        );
        assert_eq!(
            open(&rotating, binding(row), &det).unwrap().expose_secret(),
            "d"
        );
        let retired = ring(&[("k2", 8)], "k2");
        assert!(open(&retired, binding(row), &random).is_err());
    }
}
