//! L6-T3: pattern shapes and Arabic-aware measures of a text attribute.
//!
//! Every value's shape is counted: a digit (Western or Arabic-Indic) becomes
//! `9`, a Latin letter `A`, an Arabic letter `ع`, anything else stays, so
//! `0501234567` and `+966 50 123 4567` read as phone shapes and a profile of
//! a masked field still shows its formats without its values. The ten most
//! common shapes are kept with their share. When the attribute declares a
//! format (`options.pattern`, the A2/F012 anchored regex), the share of
//! values matching it is reported too.
//!
//! The Arabic measures are counts: values in Arabic, Latin or mixed script;
//! values written with Eastern (Arabic-Indic) or Western digits; values with
//! diacritics (tashkeel); date-like values that read as Hijri (year
//! 1300–1500, or marked `هـ`) or Gregorian (1900–2100); and, for a name
//! attribute, how many parts names have (1 to 5 or more).

use std::collections::HashMap;

use serde_json::{Value, json};

/// Shapes kept per attribute.
const TOP_SHAPES: usize = 10;

/// The most shapes counted before a new one is no longer tracked.
const MAX_SHAPES: usize = 10_000;

fn is_arabic_letter(c: char) -> bool {
    matches!(c, '\u{0621}'..='\u{064A}' | '\u{0671}'..='\u{06D3}' | '\u{06FA}'..='\u{06FF}')
}

fn is_arabic_diacritic(c: char) -> bool {
    matches!(c, '\u{064B}'..='\u{0652}' | '\u{0670}')
}

fn is_eastern_digit(c: char) -> bool {
    matches!(c, '\u{0660}'..='\u{0669}' | '\u{06F0}'..='\u{06F9}')
}

/// A value's shape: digits `9`, Latin letters `A`, Arabic letters `ع`,
/// diacritics dropped, the rest kept.
pub fn shape(value: &str) -> String {
    value
        .chars()
        .filter(|c| !is_arabic_diacritic(*c))
        .map(|c| {
            if c.is_ascii_digit() || is_eastern_digit(c) {
                '9'
            } else if c.is_ascii_alphabetic() {
                'A'
            } else if is_arabic_letter(c) {
                'ع'
            } else {
                c
            }
        })
        .collect()
}

/// The year a date-like value names, and whether it is marked Hijri: the
/// first run of four digits, read in Western digits.
fn date_year(value: &str) -> Option<(u32, bool)> {
    let western: String = value
        .chars()
        .map(|c| match c {
            '\u{0660}'..='\u{0669}' => char::from(b'0' + (c as u32 - 0x0660) as u8),
            '\u{06F0}'..='\u{06F9}' => char::from(b'0' + (c as u32 - 0x06F0) as u8),
            other => other,
        })
        .collect();
    let looks_like_date = western.chars().filter(|c| c.is_ascii_digit()).count() >= 6
        && western.chars().any(|c| matches!(c, '-' | '/' | '.'));
    if !looks_like_date {
        return None;
    }
    let digits: Vec<char> = western.chars().collect();
    let year = digits.windows(4).find_map(|w| {
        w.iter()
            .all(char::is_ascii_digit)
            .then(|| w.iter().collect::<String>().parse::<u32>().ok())
            .flatten()
    })?;
    Some((year, value.contains("هـ")))
}

/// A check of a value against an attribute's declared format.
pub type FormatCheck = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// One text attribute's shapes and Arabic measures.
pub struct PatternStats {
    shapes: HashMap<String, u64>,
    values: u64,
    format: Option<FormatCheck>,
    matched: u64,
    name_like: bool,
    arabic: u64,
    latin: u64,
    mixed: u64,
    eastern_digits: u64,
    western_digits: u64,
    diacritics: u64,
    hijri_dates: u64,
    gregorian_dates: u64,
    name_parts: [u64; 5],
}

impl std::fmt::Debug for PatternStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatternStats")
            .field("values", &self.values)
            .finish_non_exhaustive()
    }
}

impl PatternStats {
    /// `format` checks a value against the attribute's declared format;
    /// `name_like` counts name parts.
    pub fn new(format: Option<FormatCheck>, name_like: bool) -> Self {
        PatternStats {
            shapes: HashMap::new(),
            values: 0,
            format,
            matched: 0,
            name_like,
            arabic: 0,
            latin: 0,
            mixed: 0,
            eastern_digits: 0,
            western_digits: 0,
            diacritics: 0,
            hijri_dates: 0,
            gregorian_dates: 0,
            name_parts: [0; 5],
        }
    }

    /// Adds one non-empty value.
    pub fn push(&mut self, value: &str) {
        let value = value.trim();
        if value.is_empty() {
            return;
        }
        self.values += 1;
        let s = shape(value);
        if let Some(count) = self.shapes.get_mut(&s) {
            *count += 1;
        } else if self.shapes.len() < MAX_SHAPES {
            self.shapes.insert(s, 1);
        }
        if let Some(format) = &self.format
            && format(value)
        {
            self.matched += 1;
        }
        let has_arabic = value.chars().any(is_arabic_letter);
        let has_latin = value.chars().any(|c| c.is_ascii_alphabetic());
        match (has_arabic, has_latin) {
            (true, true) => self.mixed += 1,
            (true, false) => self.arabic += 1,
            (false, true) => self.latin += 1,
            (false, false) => {}
        }
        if value.chars().any(is_eastern_digit) {
            self.eastern_digits += 1;
        }
        if value.chars().any(|c| c.is_ascii_digit()) {
            self.western_digits += 1;
        }
        if value.chars().any(is_arabic_diacritic) {
            self.diacritics += 1;
        }
        if let Some((year, marked_hijri)) = date_year(value) {
            if marked_hijri || (1300..=1500).contains(&year) {
                self.hijri_dates += 1;
            } else if (1900..=2100).contains(&year) {
                self.gregorian_dates += 1;
            }
        }
        if self.name_like {
            let parts = value.split_whitespace().count().clamp(1, 5);
            self.name_parts[parts - 1] += 1;
        }
    }

    /// The summary: top shapes with their share, the format match rate, and
    /// the Arabic measures.
    pub fn finish(self) -> Value {
        let share = |n: u64| {
            if self.values == 0 {
                0.0
            } else {
                n as f64 * 100.0 / self.values as f64
            }
        };
        let mut top: Vec<(&String, &u64)> = self.shapes.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let top_shapes: Vec<Value> = top
            .into_iter()
            .take(TOP_SHAPES)
            .map(|(shape, count)| json!({ "shape": shape, "count": count, "share_pct": share(*count) }))
            .collect();
        let mut out = json!({
            "values": self.values,
            "top_shapes": top_shapes,
            "format_match_pct": self.format.as_ref().map(|_| share(self.matched)),
            "arabic": {
                "script": { "arabic": self.arabic, "latin": self.latin, "mixed": self.mixed },
                "digits": { "eastern": self.eastern_digits, "western": self.western_digits },
                "with_diacritics": self.diacritics,
                "dates": { "hijri": self.hijri_dates, "gregorian": self.gregorian_dates },
            },
        });
        if self.name_like {
            out["arabic"]["name_parts"] = json!({
                "1": self.name_parts[0], "2": self.name_parts[1], "3": self.name_parts[2],
                "4": self.name_parts[3], "5_or_more": self.name_parts[4],
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saudi_mobile_shape() {
        assert_eq!(shape("0501234567"), "9999999999");
        assert_eq!(shape("+966 50 123 4567"), "+999 99 999 9999");
        assert_eq!(
            shape("٠٥٠١٢٣٤٥٦٧"),
            "9999999999",
            "Eastern digits shape the same"
        );
        assert_eq!(shape("SA03 8000"), "AA99 9999");
        assert_eq!(shape("مُحَمَّد"), "عععع", "diacritics drop out of the shape");

        let mut stats = PatternStats::new(
            Some(Box::new(|v: &str| v.starts_with("05") && v.len() == 10)),
            false,
        );
        for v in ["0501234567", "0559876543", "+966501234567"] {
            stats.push(v);
        }
        let out = stats.finish();
        assert_eq!(out["top_shapes"][0]["shape"], "9999999999");
        assert_eq!(out["top_shapes"][0]["count"], 2);
        let rate = out["format_match_pct"].as_f64().unwrap();
        assert!((rate - 200.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn mixed_script_counted() {
        let mut stats = PatternStats::new(None, false);
        for v in ["شركة الأمل", "Al Amal Co", "شركة Amal", "12345"] {
            stats.push(v);
        }
        let out = stats.finish();
        assert_eq!(out["arabic"]["script"]["arabic"], 1);
        assert_eq!(out["arabic"]["script"]["latin"], 1);
        assert_eq!(out["arabic"]["script"]["mixed"], 1);
        assert!(
            out["format_match_pct"].is_null(),
            "no declared format, no match rate"
        );
    }

    #[test]
    fn eastern_digits_counted() {
        let mut stats = PatternStats::new(None, false);
        for v in ["١٤٤٥/٠٣/١٢ هـ", "2024-09-15", "١٢٣", "12"] {
            stats.push(v);
        }
        let out = stats.finish();
        assert_eq!(out["arabic"]["digits"]["eastern"], 2);
        assert_eq!(out["arabic"]["digits"]["western"], 2);
        assert_eq!(out["arabic"]["dates"]["hijri"], 1);
        assert_eq!(out["arabic"]["dates"]["gregorian"], 1);
    }

    #[test]
    fn name_parts_counted() {
        let mut stats = PatternStats::new(None, true);
        for v in [
            "محمد",
            "سارة أحمد",
            "عبد الله بن محمد",
            "Mohammed bin Abdullah bin Saad Al Qahtani",
            "مُنى",
        ] {
            stats.push(v);
        }
        let out = stats.finish();
        let parts = &out["arabic"]["name_parts"];
        assert_eq!(parts["1"], 2);
        assert_eq!(parts["2"], 1);
        assert_eq!(parts["4"], 1);
        assert_eq!(parts["5_or_more"], 1);
        assert_eq!(out["arabic"]["with_diacritics"], 1);
    }
}
