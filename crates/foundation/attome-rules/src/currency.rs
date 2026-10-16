//! Currencies for the V2 currency functions (roadmap Z11-T5): the ISO 4217
//! minor units of the currencies the platform knows. Rates are never looked
//! up here; the caller supplies them on the [`crate::Context`].

/// ISO 4217 code and its number of minor-unit digits.
pub const MINOR_UNITS: &[(&str, u32)] = &[
    ("AED", 2),
    ("AUD", 2),
    ("BHD", 3),
    ("CAD", 2),
    ("CHF", 2),
    ("CNY", 2),
    ("DZD", 2),
    ("EGP", 2),
    ("EUR", 2),
    ("GBP", 2),
    ("INR", 2),
    ("IQD", 3),
    ("JOD", 3),
    ("JPY", 0),
    ("KWD", 3),
    ("LBP", 2),
    ("LYD", 3),
    ("MAD", 2),
    ("OMR", 3),
    ("PKR", 2),
    ("QAR", 2),
    ("SAR", 2),
    ("TND", 3),
    ("TRY", 2),
    ("USD", 2),
    ("YER", 2),
];

/// The minor-unit digits of `code` (case-insensitive), or `None` for a code
/// the table does not know.
pub fn minor_units(code: &str) -> Option<u32> {
    let code = code.trim();
    MINOR_UNITS
        .iter()
        .find(|(c, _)| c.eq_ignore_ascii_case(code))
        .map(|(_, digits)| *digits)
}

/// `code` upper-cased when the table knows it.
pub(crate) fn known(code: &str) -> Option<String> {
    minor_units(code).map(|_| code.trim().to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_decimal_gulf_currencies() {
        for code in ["KWD", "BHD", "OMR", "JOD"] {
            assert_eq!(minor_units(code), Some(3), "{code}");
        }
        assert_eq!(minor_units("sar"), Some(2));
        assert_eq!(minor_units("XYZ"), None);
    }
}
