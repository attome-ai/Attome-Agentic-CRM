//! Q15-T1: showing a field masked instead of in full.
//!
//! A field-security grant may carry a mask format
//! (`field_security_profile_field.mask_format`). Its holder sees the masked
//! form only. The mask is computed by PostgreSQL in the projection
//! ([`MaskFormat::sql`]), so the raw value never leaves the database for a
//! caller who may only see it masked. [`MaskFormat::apply`] is the same mask
//! in Rust, for values that are already in memory and for tests that pin the
//! two to each other.

/// The character that stands in for a hidden one.
pub const MASK_CHAR: char = '•';

/// What a fully masked value shows, whatever its length.
pub const FULL_MASK: &str = "••••••";

/// How a masked field is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskFormat {
    /// The last four characters; the rest masked.
    Last4,
    /// The first letter and the domain of an address: `a•••@example.com`.
    Email,
    /// The last three digits of a phone number; the rest masked.
    Phone,
    /// Nothing of the value.
    Full,
}

impl MaskFormat {
    pub const ALL: [&'static str; 4] = ["last4", "email", "phone", "full"];

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "last4" => Some(Self::Last4),
            "email" => Some(Self::Email),
            "phone" => Some(Self::Phone),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Last4 => "last4",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Full => "full",
        }
    }

    /// The SQL expression for column `col` (already quoted) masked: text, or
    /// NULL when the value is NULL. A value no longer than what the format
    /// keeps is masked whole, so a short value is never shown in full.
    pub fn sql(self, col: &str) -> String {
        let text = format!("({col})::text");
        let keep_tail = |n: usize| {
            format!(
                "CASE WHEN {col} IS NULL THEN NULL \
                 WHEN char_length({text}) <= {n} THEN repeat('{MASK_CHAR}', char_length({text})) \
                 ELSE repeat('{MASK_CHAR}', char_length({text}) - {n}) || right({text}, {n}) END"
            )
        };
        match self {
            Self::Last4 => keep_tail(4),
            Self::Phone => keep_tail(3),
            Self::Email => format!(
                "CASE WHEN {col} IS NULL THEN NULL \
                 WHEN strpos({text}, '@') > 1 \
                 THEN left({text}, 1) || '{MASK_CHAR}{MASK_CHAR}{MASK_CHAR}@' || split_part({text}, '@', 2) \
                 ELSE '{FULL_MASK}' END"
            ),
            Self::Full => format!("CASE WHEN {col} IS NULL THEN NULL ELSE '{FULL_MASK}' END"),
        }
    }

    /// [`Self::sql`] for a value already in hand.
    pub fn apply(self, value: &str) -> String {
        let keep_tail = |n: usize| {
            let chars: Vec<char> = value.chars().collect();
            if chars.len() <= n {
                MASK_CHAR.to_string().repeat(chars.len())
            } else {
                let mut out = MASK_CHAR.to_string().repeat(chars.len() - n);
                out.extend(&chars[chars.len() - n..]);
                out
            }
        };
        match self {
            Self::Last4 => keep_tail(4),
            Self::Phone => keep_tail(3),
            Self::Email => match value.split_once('@') {
                Some((local, domain)) if !local.is_empty() => {
                    let first: String = local.chars().take(1).collect();
                    let domain = domain.split('@').next().unwrap_or_default();
                    format!("{first}{MASK_CHAR}{MASK_CHAR}{MASK_CHAR}@{domain}")
                }
                _ => FULL_MASK.to_owned(),
            },
            Self::Full => FULL_MASK.to_owned(),
        }
    }
}

/// How one attribute is projected for a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnAccess {
    /// The value as stored.
    Full,
    /// The masked form, computed in the query.
    Masked(MaskFormat),
    /// Not selected at all.
    Hidden,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_mask_formats() {
        assert_eq!(
            MaskFormat::Last4.apply("4111111111111111"),
            "••••••••••••1111"
        );
        assert_eq!(MaskFormat::Last4.apply("123"), "•••");
        assert_eq!(MaskFormat::Phone.apply("+966501234567"), "••••••••••567");
        assert_eq!(
            MaskFormat::Email.apply("ahmed@example.com"),
            "a•••@example.com"
        );
        assert_eq!(MaskFormat::Email.apply("not-an-email"), FULL_MASK);
        assert_eq!(MaskFormat::Email.apply("@example.com"), FULL_MASK);
        assert_eq!(MaskFormat::Full.apply("anything"), FULL_MASK);
        assert_eq!(MaskFormat::Last4.apply("أحمدالسالم"), "••••••سالم");
        for name in MaskFormat::ALL {
            assert_eq!(MaskFormat::parse(name).map(MaskFormat::as_str), Some(name));
        }
        assert_eq!(MaskFormat::parse("half"), None);
    }
}
