//! Built-in Arabic data-quality checks (roadmap L2-T6), pure. Each check
//! looks at one value and returns findings with an English and an Arabic
//! message, so a quality issue reads the same in either interface:
//!
//! - mixed scripts: Arabic and Latin letters in one word;
//! - missing Arabic name: the English name is filled and the Arabic one is
//!   not, where the entity requires both;
//! - mixed digits: Western and Arabic-Indic (or Persian) digits in one value;
//! - Hijri/Gregorian mix-up: a date whose year belongs to the other
//!   calendar (a Hijri year such as 1446 stored as a Gregorian date, or a
//!   Gregorian year in a Hijri field).
//!
//! The checks become measure-only quality rules (off until enabled per
//! entity) when the rule mechanism of L2-T2 exists.

use serde::Serialize;

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub en: String,
    pub ar: String,
}

fn is_arabic_letter(c: char) -> bool {
    matches!(c, '\u{0621}'..='\u{064A}' | '\u{066E}'..='\u{06D3}' | '\u{06FA}'..='\u{06FF}')
}

fn is_latin_letter(c: char) -> bool {
    c.is_ascii_alphabetic() || matches!(c, '\u{00C0}'..='\u{024F}')
}

/// Words mixing Arabic and Latin letters.
pub fn mixed_script(value: &str) -> Option<Finding> {
    let word = value
        .split_whitespace()
        .find(|w| w.chars().any(is_arabic_letter) && w.chars().any(is_latin_letter))?;
    Some(Finding {
        code: "mixed_script",
        en: format!("\"{word}\" mixes Arabic and Latin letters"),
        ar: format!("الكلمة \"{word}\" تخلط بين الحروف العربية واللاتينية"),
    })
}

/// The English name is set and the Arabic one is empty or has no Arabic.
pub fn missing_arabic_name(name_en: Option<&str>, name_ar: Option<&str>) -> Option<Finding> {
    let has_en = name_en.is_some_and(|n| !n.trim().is_empty());
    let has_ar = name_ar.is_some_and(|n| n.chars().any(is_arabic_letter));
    (has_en && !has_ar).then(|| Finding {
        code: "missing_arabic_name",
        en: "The Arabic name is missing".into(),
        ar: "الاسم العربي غير موجود".into(),
    })
}

/// Western and Arabic-Indic or Persian digits in one value.
pub fn mixed_digits(value: &str) -> Option<Finding> {
    let western = value.chars().any(|c| c.is_ascii_digit());
    let eastern = value
        .chars()
        .any(|c| matches!(c, '\u{0660}'..='\u{0669}' | '\u{06F0}'..='\u{06F9}'));
    (western && eastern).then(|| Finding {
        code: "mixed_digits",
        en: format!("\"{value}\" mixes Western and Arabic-Indic digits"),
        ar: format!("القيمة \"{value}\" تخلط بين الأرقام الغربية والعربية الهندية"),
    })
}

/// Which calendar a date field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Calendar {
    Gregorian,
    Hijri,
}

/// A year that belongs to the other calendar. Hijri years run about 579
/// behind Gregorian ones: 1300 to 1600 is read as Hijri, 1800 and later as
/// Gregorian.
pub fn hijri_gregorian_mixup(year: i32, field: Calendar) -> Option<Finding> {
    let looks_hijri = (1300..=1600).contains(&year);
    let looks_gregorian = year >= 1800;
    match field {
        Calendar::Gregorian if looks_hijri => Some(Finding {
            code: "hijri_gregorian_mixup",
            en: format!("The year {year} looks like a Hijri year in a Gregorian date"),
            ar: format!("السنة {year} تبدو هجرية في تاريخ ميلادي"),
        }),
        Calendar::Hijri if looks_gregorian => Some(Finding {
            code: "hijri_gregorian_mixup",
            en: format!("The year {year} looks like a Gregorian year in a Hijri date"),
            ar: format!("السنة {year} تبدو ميلادية في تاريخ هجري"),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_script_flagged() {
        assert!(mixed_script("شركةAcme للتجارة").is_some());
        assert!(
            mixed_script("Acme للتجارة").is_none(),
            "separate words are fine"
        );
        assert!(mixed_script("Acme Trading").is_none());
    }

    #[test]
    fn missing_arabic_name_flagged() {
        assert!(missing_arabic_name(Some("Acme"), None).is_some());
        assert!(
            missing_arabic_name(Some("Acme"), Some("Acme")).is_some(),
            "no Arabic letters"
        );
        assert!(missing_arabic_name(Some("Acme"), Some("أكمي")).is_none());
        assert!(missing_arabic_name(None, None).is_none());
    }

    #[test]
    fn mixed_digits_flagged() {
        assert!(mixed_digits("05٠١٢٣٤").is_some());
        assert!(mixed_digits("0501234").is_none());
        assert!(mixed_digits("٠٥٠١٢٣٤").is_none());
    }

    #[test]
    fn hijri_gregorian_mixup_flagged() {
        assert!(hijri_gregorian_mixup(1446, Calendar::Gregorian).is_some());
        assert!(hijri_gregorian_mixup(2025, Calendar::Gregorian).is_none());
        assert!(hijri_gregorian_mixup(2025, Calendar::Hijri).is_some());
        assert!(hijri_gregorian_mixup(1446, Calendar::Hijri).is_none());
    }
}
