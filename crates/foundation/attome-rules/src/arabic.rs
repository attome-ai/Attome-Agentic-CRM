//! Arabic text normalisation (roadmap Z11-T2), for comparing names and
//! search text written with different alef forms, ya and taa marbuta, or
//! with diacritics and tatweel.

/// Folds the forms people type interchangeably: alef with madda, hamza
/// above or below and wasla become a bare alef; alef maqsura becomes ya;
/// taa marbuta becomes ha; diacritics (U+064B..U+065F, U+0670) and tatweel
/// (U+0640) are removed. Other characters are kept as they are.
pub fn normalize_ar(s: &str) -> String {
    s.chars()
        .filter_map(|c| match c {
            '\u{0622}' | '\u{0623}' | '\u{0625}' | '\u{0671}' => Some('\u{0627}'),
            '\u{0649}' => Some('\u{064A}'),
            '\u{0629}' => Some('\u{0647}'),
            '\u{064B}'..='\u{065F}' | '\u{0670}' | '\u{0640}' => None,
            other => Some(other),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::normalize_ar;

    #[test]
    fn folds_alef_ya_and_taa_marbuta() {
        assert_eq!(normalize_ar("أحمد"), normalize_ar("احمد"));
        assert_eq!(normalize_ar("إيمان"), "ايمان");
        assert_eq!(normalize_ar("مصطفى"), "مصطفي");
        assert_eq!(normalize_ar("فاطمة"), "فاطمه");
    }

    #[test]
    fn strips_diacritics_and_tatweel_and_keeps_latin() {
        assert_eq!(normalize_ar("مُحَمَّد"), "محمد");
        assert_eq!(normalize_ar("شـركة"), "شركه");
        assert_eq!(normalize_ar("Acme 12"), "Acme 12");
    }
}
