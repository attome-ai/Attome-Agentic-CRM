//! A15-T2: the normalizers duplicate matching and search share. Pure
//! functions: [`normalize_ar`] (the Arabic fold search indexes and queries
//! with, moved here from `attome-search` unchanged) and the match keys a
//! duplicate rule compares: phone, email, id, name and a transliteration key
//! that lets an Arabic name meet its Latin spelling.

/// Folds Arabic orthographic variation, strips diacritics, converts
/// Arabic-Indic digits, lowercases, and collapses whitespace.
///
/// Ordering matters and is not arbitrary: diacritics and tatweel come out
/// first so that a fold never has to reason about a combining mark sitting
/// between two letters, and whitespace is collapsed last so that removals
/// earlier in the pass cannot leave doubled spaces behind.
pub fn normalize_ar(input: &str) -> String {
    let mut out = String::with_capacity(input.len());

    for ch in input.chars() {
        // 1. Drop what carries no lexical meaning at all.
        if is_tashkeel(ch) || ch == TATWEEL {
            continue;
        }

        // 2. Fold orthographic variants onto one representative.
        let folded = fold_letter(ch);

        // 3. Arabic-Indic and Eastern Arabic-Indic digits to ASCII. Both
        //    ranges are in live use across the GCC — an invoice number typed
        //    ١٢٣ must find a record storing 123.
        let folded = fold_digit(folded);

        out.push(folded);
    }

    // 4. Lowercase for the Latin half. `to_lowercase` is a no-op for Arabic
    //    (it is unicameral), so this is safe to apply to the whole string
    //    rather than segmenting first.
    let lowered = out.to_lowercase();

    // 5. Collapse whitespace LAST, so that removing a tatweel or a harakat
    //    cannot leave a doubled space behind. Any Unicode whitespace becomes a
    //    single ASCII space — a non-breaking space pasted from a document is
    //    not a meaningful difference between two names.
    lowered.split_whitespace().collect::<Vec<_>>().join(" ")
}

const TATWEEL: char = '\u{0640}';

/// Arabic diacritics: the harakat block (U+064B–U+0652), the superscript alef
/// and its neighbours (U+0653–U+065F), the Quranic annotation marks
/// (U+06D6–U+06ED), and the standalone sukun/shadda variants.
///
/// Deliberately a range check rather than a match on named characters: the
/// block is contiguous by design, and enumerating it invites a missed
/// codepoint that then silently breaks matching for whatever word contains it.
fn is_tashkeel(ch: char) -> bool {
    matches!(ch,
        '\u{064B}'..='\u{065F}'   // fathatan … wavy hamza below
        | '\u{0670}'              // superscript alef
        | '\u{06D6}'..='\u{06ED}' // Quranic annotation
    )
}

/// The letter folds.
///
/// Each of these is a pair that native typists interchange in practice, not a
/// linguistic equivalence. Folding them is what makes `احمد` find `أحمد` —
/// the single highest-value normalization for name search, because a name is
/// what people search for and a name is exactly where the hamza is dropped.
fn fold_letter(ch: char) -> char {
    match ch {
        // Alef with any hamza or madda, and the Quranic wasla, all to bare alef.
        '\u{0622}' | '\u{0623}' | '\u{0625}' | '\u{0671}' => '\u{0627}',
        // Alef maksura to ya — ى and ي are interchanged constantly.
        '\u{0649}' => '\u{064A}',
        // Taa marbuta to haa — ة is commonly typed ه word-final.
        '\u{0629}' => '\u{0647}',
        // Hamza carriers to the bare hamza.
        '\u{0624}' | '\u{0626}' => '\u{0621}',
        other => other,
    }
}

fn fold_digit(ch: char) -> char {
    match ch {
        // Arabic-Indic ٠-٩
        '\u{0660}'..='\u{0669}' => char::from(b'0' + (ch as u32 - 0x0660) as u8),
        // Eastern Arabic-Indic ۰-۹ (Persian/Urdu forms, also seen in the Gulf)
        '\u{06F0}'..='\u{06F9}' => char::from(b'0' + (ch as u32 - 0x06F0) as u8),
        other => other,
    }
}

// ── Match keys ───────────────────────────────────────────────────────────────

/// The international calling code of a country (ISO 3166 alpha-2), for the
/// countries a local number is most often typed in; a caller may also pass
/// the code itself (`966`).
fn calling_code(country: &str) -> Option<&str> {
    let country = country.trim();
    if !country.is_empty() && country.chars().all(|c| c.is_ascii_digit()) {
        return Some(country);
    }
    Some(match country.to_ascii_uppercase().as_str() {
        "SA" => "966",
        "AE" => "971",
        "KW" => "965",
        "QA" => "974",
        "BH" => "973",
        "OM" => "968",
        "EG" => "20",
        "JO" => "962",
        "LB" => "961",
        "IQ" => "964",
        "MA" => "212",
        "TR" => "90",
        "GB" => "44",
        "US" | "CA" => "1",
        "IN" => "91",
        "PK" => "92",
        _ => return None,
    })
}

/// The comparable form of a phone number: `+` and the digits of the
/// international number (`+966501234567`). `00` before the country code
/// becomes `+`; a number with one leading `0` is local to `default_country`
/// (`SA` or `966`). `None` when fewer than 7 digits remain, or a local
/// number's country is unknown.
pub fn phone_key(raw: &str, default_country: &str) -> Option<String> {
    let raw = normalize_ar(raw);
    let trimmed = raw.trim();
    let plus = trimmed.starts_with('+');
    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    let international = if plus {
        digits
    } else if let Some(rest) = digits.strip_prefix("00") {
        rest.to_owned()
    } else if let Some(rest) = digits.strip_prefix('0') {
        format!("{}{rest}", calling_code(default_country)?)
    } else {
        digits
    };
    (international.len() >= 7).then(|| format!("+{international}"))
}

/// The comparable form of an email address: trimmed and lowercased. `None`
/// unless it holds exactly one `@` with text on both sides.
pub fn email_key(raw: &str) -> Option<String> {
    let email = raw.trim().to_lowercase();
    let mut parts = email.split('@');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(local), Some(domain), None) if !local.is_empty() && !domain.is_empty() => Some(email),
        _ => None,
    }
}

/// The comparable form of an identifier (a national id, a commercial
/// registration number): Arabic-Indic digits as ASCII, uppercase, without
/// spaces, dashes or dots.
pub fn id_key(raw: &str) -> String {
    normalize_ar(raw)
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '.' | '\u{2010}'..='\u{2015}'))
        .flat_map(char::to_uppercase)
        .collect()
}

/// Titles a name key leaves out (in their normalized form).
const TITLES: &[&str] = &[
    "mr",
    "mrs",
    "ms",
    "miss",
    "dr",
    "eng",
    "prof",
    "sheikh",
    "السيد",
    "السيده",
    "د",
    "م",
    "الشيخ",
    "الدكتور",
    "المهندس",
];

/// The comparable form of a person's name: Arabic folded ([`normalize_ar`]),
/// Latin lowercased, titles dropped, `عبد ال…` joined into one word, and the
/// words sorted so their order does not matter.
pub fn name_key(raw: &str) -> String {
    let normalized = normalize_ar(raw);
    let words: Vec<String> = normalized
        .split(' ')
        .map(|w| w.trim_matches(|c: char| c == '.' || c == ','))
        .filter(|w| !w.is_empty() && !TITLES.contains(w))
        .map(str::to_owned)
        .collect();
    let mut joined: Vec<String> = Vec::with_capacity(words.len());
    let mut iter = words.into_iter().peekable();
    while let Some(word) = iter.next() {
        // عبد الله, عبد الرحمن: one name written as two words.
        if word == "عبد"
            && let Some(next) = iter.peek()
            && next.starts_with("ال")
        {
            let next = iter.next().unwrap_or_default();
            joined.push(format!("{word}{next}"));
            continue;
        }
        joined.push(word);
    }
    joined.sort();
    joined.join(" ")
}

/// The Latin skeleton of one Arabic letter; vowels-like letters map to a
/// vowel so the skeleton drops them like Latin vowels.
fn translit_letter(ch: char) -> &'static str {
    match ch {
        'ا' | 'ع' | 'ء' => "a",
        'ب' => "b",
        'ت' | 'ط' => "t",
        'ث' => "th",
        'ج' => "j",
        'ح' | 'ه' => "h",
        'خ' => "kh",
        'د' | 'ض' => "d",
        'ذ' => "dh",
        'ر' => "r",
        'ز' | 'ظ' => "z",
        'س' | 'ص' => "s",
        'ش' => "sh",
        'غ' => "gh",
        'ف' => "f",
        'ق' => "q",
        'ك' => "k",
        'ل' => "l",
        'م' => "m",
        'ن' => "n",
        'و' => "u",
        'ي' => "i",
        _ => "",
    }
}

/// A key that lets a name meet its spelling in the other script: Arabic is
/// mapped letter by letter to a Latin skeleton, then (for both scripts) the
/// first letter is kept, later vowels are dropped and repeated letters
/// collapse, without spaces. `عبدالله`, `Abdullah`, `Abdallah` and
/// `Abd Allah` give one key; so do `يوسف` and `Yousef`.
pub fn translit_key(raw: &str) -> String {
    let normalized = normalize_ar(raw);
    let mut latin = String::with_capacity(normalized.len());
    let mut word_start = true;
    for ch in normalized.chars() {
        if ch.is_ascii_alphanumeric() {
            latin.push(ch);
        } else if word_start && matches!(ch, '\u{064A}' | '\u{0648}') {
            // A word-initial ya or waw is a consonant (Yousef, Walid);
            // inside a word it is a long vowel and drops like one.
            latin.push(if ch == '\u{064A}' { 'y' } else { 'w' });
        } else {
            latin.push_str(translit_letter(ch));
        }
        word_start = ch.is_whitespace();
    }
    let mut skeleton = String::with_capacity(latin.len());
    for (i, ch) in latin.chars().enumerate() {
        let vowel = matches!(ch, 'a' | 'e' | 'i' | 'o' | 'u');
        if i > 0 && vowel {
            continue;
        }
        if skeleton.ends_with(ch) {
            continue;
        }
        skeleton.push(ch);
    }
    skeleton
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_local_and_international_equal() {
        let international = Some("+966501234567".to_owned());
        assert_eq!(phone_key("0501234567", "SA"), international);
        assert_eq!(phone_key("+966 50 123 4567", "SA"), international);
        assert_eq!(phone_key("00966-50-123-4567", "AE"), international);
        assert_eq!(phone_key("٠٥٠١٢٣٤٥٦٧", "966"), international);
        assert_eq!(phone_key("12345", "SA"), None);
        assert_eq!(phone_key("0501234567", "ZZ"), None);
    }

    #[test]
    fn email_case_insensitive() {
        assert_eq!(
            email_key(" Ahmed@Example.COM "),
            Some("ahmed@example.com".to_owned())
        );
        assert_eq!(email_key("a@b@c"), None);
        assert_eq!(email_key("no-at-sign"), None);
        assert_eq!(email_key("@example.com"), None);
    }

    #[test]
    fn id_key_drops_separators() {
        assert_eq!(id_key("10-1234.567 8"), "1012345678");
        assert_eq!(id_key("cr-١٠١٢"), "CR1012");
    }

    #[test]
    fn name_order_and_titles_ignored() {
        assert_eq!(name_key("Dr. Ahmed Ali"), name_key("ali  AHMED"));
        assert_eq!(name_key("السيد محمد عبد الله"), name_key("عبدالله محمد"));
        assert_eq!(name_key("المهندس خالد"), "خالد");
    }

    #[test]
    fn alef_forms_equal() {
        assert_eq!(name_key("أحمد"), name_key("احمد"));
        assert_eq!(name_key("إحمد"), name_key("احمد"));
        assert_eq!(name_key("آمنة"), name_key("امنه"));
    }

    #[test]
    fn abdullah_variants_equal() {
        let key = translit_key("عبدالله");
        for variant in ["Abdullah", "Abdallah", "Abd Allah", "عبد الله", "ABDULLAH"] {
            assert_eq!(translit_key(variant), key, "{variant}");
        }
        assert_eq!(translit_key("يوسف"), translit_key("Yousef"));
        assert_eq!(translit_key("محمد"), translit_key("Mohammed"));
        assert_ne!(translit_key("محمد"), translit_key("Ahmed"));
    }
}
