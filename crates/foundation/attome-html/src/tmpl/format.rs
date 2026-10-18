//! Region formatting (roadmap Z13-T4): the filters an output may end with,
//! `{{ value | currency('SAR') }}`, and the locale they read.
//!
//! - `date` or `date('short' | 'long' | 'iso' | 'datetime' | '<strftime>')`:
//!   a date in the render's zone; `long` names the month in the locale's
//!   language.
//! - `hijri` or `hijri('short')`: the Umm al-Qura date (`attome-calendar`),
//!   `12 Rabi al-Thani 1448 AH` / `12 ربيع الآخر 1448 هـ`, or `1448/04/12`.
//! - `number` or `number(N)`: N decimals (0 to 6), thousands grouped.
//! - `currency('SAR')`: the currency's minor-unit digits (`attome-rules`'s
//!   ISO 4217 table) and its code, or its Arabic symbol in Arabic.
//! - `digits('arabic' | 'western')`: the digits and separators of whatever
//!   came before.
//!
//! An Arabic locale (`ar`, `ar-SA`) writes Arabic-Indic digits and the
//! Arabic decimal and group separators by default; `digits('western')`
//! turns them back. A filter's name, argument and input type are checked
//! when the template compiles. The result is text, escaped like any value.

use attome_calendar::hijri;
use attome_rules::currency::minor_units;
use attome_rules::{Type, Value};
use chrono::format::{Item, StrftimeItems};
use chrono::{Datelike, NaiveDate};
use chrono_tz::Tz;

/// The most decimals `number(N)` takes.
pub const MAX_DECIMALS: u32 = 6;

/// The language a render formats for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Locale {
    arabic: bool,
    /// The language subtag, for `lang` (`ar`, `en`); ASCII letters only.
    lang: String,
}

impl Locale {
    pub(crate) fn parse(locale: &str) -> Self {
        let lang: String = locale
            .split(['-', '_'])
            .next()
            .unwrap_or("")
            .chars()
            .filter(char::is_ascii_alphabetic)
            .take(8)
            .collect::<String>()
            .to_ascii_lowercase();
        let lang = if lang.is_empty() {
            "en".to_owned()
        } else {
            lang
        };
        Self {
            arabic: lang == "ar",
            lang,
        }
    }

    pub(crate) fn is_arabic(&self) -> bool {
        self.arabic
    }

    pub(crate) fn lang(&self) -> &str {
        &self.lang
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigitSet {
    Arabic,
    Western,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DateStyle {
    Short,
    Long,
    Iso,
    DateTime,
    Pattern(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Filter {
    Date(DateStyle),
    Hijri { short: bool },
    Number(u32),
    Currency { code: String, decimals: u32 },
    Digits(DigitSet),
}

impl Filter {
    /// The type the filter takes; `None` takes anything.
    fn input(&self) -> Option<Type> {
        match self {
            Self::Date(_) | Self::Hijri { .. } => Some(Type::Date),
            Self::Number(_) | Self::Currency { .. } => Some(Type::Number),
            Self::Digits(_) => None,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Date(_) => "date",
            Self::Hijri { .. } => "hijri",
            Self::Number(_) => "number",
            Self::Currency { .. } => "currency",
            Self::Digits(_) => "digits",
        }
    }
}

/// Splits an output's source at its top-level `|`s (outside quotes): the
/// expression, then each filter's source.
pub(crate) fn split(src: &str) -> (&str, Vec<&str>) {
    let mut parts = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut start = 0;
    for (i, c) in src.char_indices() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '|' => {
                    parts.push(src[start..i].trim());
                    start = i + 1;
                }
                _ => {}
            },
        }
    }
    parts.push(src[start..].trim());
    let expr = parts.remove(0);
    (expr, parts)
}

/// One filter from its source, `name` or `name(arg)`.
pub(crate) fn parse_filter(src: &str) -> Result<Filter, String> {
    let (name, arg) = match src.split_once('(') {
        Some((name, rest)) => {
            let arg = rest
                .trim_end()
                .strip_suffix(')')
                .ok_or_else(|| format!("filter {src:?} has no closing ')'"))?;
            (name.trim(), Some(unquote(arg.trim())?))
        }
        None => (src.trim(), None),
    };
    match (name, arg.as_deref()) {
        ("date", None) => Ok(Filter::Date(DateStyle::Short)),
        ("date", Some(style)) => Ok(Filter::Date(match style {
            "short" => DateStyle::Short,
            "long" => DateStyle::Long,
            "iso" => DateStyle::Iso,
            "datetime" => DateStyle::DateTime,
            pattern => {
                if pattern.is_empty()
                    || StrftimeItems::new(pattern).any(|item| matches!(item, Item::Error))
                {
                    return Err(format!("{pattern:?} is not a date format"));
                }
                DateStyle::Pattern(pattern.to_owned())
            }
        })),
        ("hijri", None) => Ok(Filter::Hijri { short: false }),
        ("hijri", Some("short")) => Ok(Filter::Hijri { short: true }),
        ("hijri", Some(other)) => Err(format!("hijri takes 'short' or nothing, not {other:?}")),
        ("number", None) => Ok(Filter::Number(0)),
        ("number", Some(n)) => match n.parse::<u32>() {
            Ok(n) if n <= MAX_DECIMALS => Ok(Filter::Number(n)),
            _ => Err(format!(
                "number takes 0 to {MAX_DECIMALS} decimals, not {n:?}"
            )),
        },
        ("currency", Some(code)) => match minor_units(code) {
            Some(decimals) => Ok(Filter::Currency {
                code: code.trim().to_ascii_uppercase(),
                decimals,
            }),
            None => Err(format!("{code:?} is not a known currency code")),
        },
        ("currency", None) => Err("currency names its code: currency('SAR')".to_owned()),
        ("digits", Some("arabic")) => Ok(Filter::Digits(DigitSet::Arabic)),
        ("digits", Some("western")) => Ok(Filter::Digits(DigitSet::Western)),
        ("digits", _) => Err("digits takes 'arabic' or 'western'".to_owned()),
        (other, _) => Err(format!(
            "unknown filter {other:?} (date, hijri, number, currency, digits)"
        )),
    }
}

/// A filter argument: a quoted string or a bare word or number.
fn unquote(arg: &str) -> Result<String, String> {
    for q in ['\'', '"'] {
        if let Some(inner) = arg.strip_prefix(q) {
            return inner
                .strip_suffix(q)
                .map(str::to_owned)
                .ok_or_else(|| format!("filter argument {arg:?} is not closed"));
        }
    }
    if arg.is_empty() {
        return Err("an empty filter argument".to_owned());
    }
    Ok(arg.to_owned())
}

/// Checks the chain against the expression's type: each filter's input, and
/// text after the first one.
pub(crate) fn check(ty: &Type, filters: &[Filter]) -> Result<(), String> {
    let mut ty = ty.clone();
    for filter in filters {
        if let Some(want) = filter.input()
            && ty.unify(&want).is_none()
        {
            return Err(format!("filter {} takes a {want}, not {ty}", filter.name()));
        }
        ty = Type::Text;
    }
    Ok(())
}

/// Runs the chain; a null stays null (it renders as nothing).
pub(crate) fn apply(
    value: Value,
    filters: &[Filter],
    locale: &Locale,
    zone: Tz,
) -> Result<Value, String> {
    let mut value = value;
    for filter in filters {
        if value == Value::Null {
            return Ok(Value::Null);
        }
        let text = match (filter, &value) {
            (Filter::Date(style), Value::Date(at)) => {
                localise(&date(&at.with_timezone(&zone), style, locale), locale)
            }
            (Filter::Hijri { short }, Value::Date(at)) => {
                let day = at.with_timezone(&zone).date_naive();
                localise(&hijri_text(day, *short, locale)?, locale)
            }
            (Filter::Number(decimals), Value::Number(n)) => {
                localise(&number(*n, *decimals), locale)
            }
            (Filter::Currency { code, decimals }, Value::Number(n)) => {
                let amount = localise(&number(*n, *decimals), locale);
                match arabic_symbol(code).filter(|_| locale.is_arabic()) {
                    Some(symbol) => format!("{amount} {symbol}"),
                    None => format!("{code} {amount}"),
                }
            }
            (Filter::Digits(set), other) => digits(&super::escape::display(other), *set),
            (filter, other) => {
                return Err(format!(
                    "filter {} takes a {}, not {}",
                    filter.name(),
                    filter.input().map_or_else(String::new, |t| t.to_string()),
                    other.ty()
                ));
            }
        };
        value = Value::Text(text);
    }
    Ok(value)
}

const MONTHS_EN: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

const MONTHS_AR: [&str; 12] = [
    "يناير",
    "فبراير",
    "مارس",
    "أبريل",
    "مايو",
    "يونيو",
    "يوليو",
    "أغسطس",
    "سبتمبر",
    "أكتوبر",
    "نوفمبر",
    "ديسمبر",
];

fn date(at: &chrono::DateTime<Tz>, style: &DateStyle, locale: &Locale) -> String {
    match style {
        DateStyle::Short => at.format("%d/%m/%Y").to_string(),
        DateStyle::Iso => at.format("%Y-%m-%d").to_string(),
        DateStyle::DateTime => at.format("%d/%m/%Y %H:%M").to_string(),
        DateStyle::Long => {
            let months = if locale.is_arabic() {
                &MONTHS_AR
            } else {
                &MONTHS_EN
            };
            let month = months
                .get(usize::try_from(at.month0()).unwrap_or(0))
                .copied()
                .unwrap_or_default();
            format!("{} {month} {}", at.day(), at.year())
        }
        // Checked for `Item::Error` when the filter compiled, so formatting
        // cannot fail.
        DateStyle::Pattern(pattern) => at.format(pattern).to_string(),
    }
}

fn hijri_text(day: NaiveDate, short: bool, locale: &Locale) -> Result<String, String> {
    let h = hijri::to_hijri(day).map_err(|e| format!("hijri: {e}"))?;
    if short {
        return Ok(format!("{}/{:02}/{:02}", h.year, h.month, h.day));
    }
    let lang = if locale.is_arabic() { "ar" } else { "en" };
    let month = hijri::month_name(h.month, lang).unwrap_or_default();
    let era = if locale.is_arabic() { "هـ" } else { "AH" };
    Ok(format!("{} {month} {} {era}", h.day, h.year))
}

/// `n` with `decimals` places and `,` between thousands.
fn number(n: f64, decimals: u32) -> String {
    let fixed = format!("{:.*}", decimals as usize, n.abs());
    let (whole, frac) = fixed.split_once('.').unwrap_or((&fixed, ""));
    let mut grouped = String::with_capacity(whole.len() + whole.len() / 3);
    for (i, c) in whole.chars().enumerate() {
        if i > 0 && (whole.len() - i) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(c);
    }
    let sign = if n < 0.0 && fixed.chars().any(|c| matches!(c, '1'..='9')) {
        "-"
    } else {
        ""
    };
    if frac.is_empty() {
        format!("{sign}{grouped}")
    } else {
        format!("{sign}{grouped}.{frac}")
    }
}

/// Western text in the locale's digits.
fn localise(text: &str, locale: &Locale) -> String {
    if locale.is_arabic() {
        digits(text, DigitSet::Arabic)
    } else {
        text.to_owned()
    }
}

/// `text`'s digits, decimal point and group commas in `set`. Arabic turns
/// only a `.` or `,` that sits between two digits.
fn digits(text: &str, set: DigitSet) -> String {
    let chars: Vec<char> = text.chars().collect();
    let is_digit =
        |c: Option<&char>| c.is_some_and(|c| c.is_ascii_digit() || ('٠'..='٩').contains(c));
    let mut out = String::with_capacity(text.len());
    for (i, c) in chars.iter().enumerate() {
        let between = i > 0 && is_digit(chars.get(i - 1)) && is_digit(chars.get(i + 1));
        let mapped = match (set, *c) {
            (DigitSet::Arabic, d @ '0'..='9') => {
                char::from_u32(0x0660 + (d as u32 - '0' as u32)).unwrap_or(d)
            }
            (DigitSet::Arabic, '.') if between => '٫',
            (DigitSet::Arabic, ',') if between => '٬',
            (DigitSet::Western, d @ '٠'..='٩') => {
                char::from_u32('0' as u32 + (d as u32 - 0x0660)).unwrap_or(d)
            }
            (DigitSet::Western, '٫') => '.',
            (DigitSet::Western, '٬') => ',',
            (_, other) => other,
        };
        out.push(mapped);
    }
    out
}

fn arabic_symbol(code: &str) -> Option<&'static str> {
    Some(match code {
        "SAR" => "ر.س",
        "AED" => "د.إ",
        "KWD" => "د.ك",
        "BHD" => "د.ب",
        "OMR" => "ر.ع",
        "QAR" => "ر.ق",
        "EGP" => "ج.م",
        "JOD" => "د.أ",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;

    fn run(value: Value, chain: &str, locale: &str) -> String {
        let filters: Vec<Filter> = chain.split('|').map(|f| parse_filter(f).unwrap()).collect();
        match apply(
            value,
            &filters,
            &Locale::parse(locale),
            chrono_tz::Asia::Riyadh,
        )
        .unwrap()
        {
            Value::Text(t) => t,
            other => panic!("{other:?}"),
        }
    }

    fn day() -> Value {
        // 21:30 UTC is the next day in Riyadh.
        Value::Date(Utc.with_ymd_and_hms(2026, 10, 17, 21, 30, 0).unwrap())
    }

    #[test]
    fn format_date_en_and_ar() {
        assert_eq!(run(day(), "date", "en"), "18/10/2026");
        assert_eq!(run(day(), "date('long')", "en"), "18 October 2026");
        assert_eq!(run(day(), "date('long')", "ar-SA"), "١٨ أكتوبر ٢٠٢٦");
        assert_eq!(run(day(), "date('iso')", "en"), "2026-10-18");
        assert_eq!(run(day(), "date('%Y')", "ar"), "٢٠٢٦");
        assert!(parse_filter("date('%Q')").is_err());
    }

    #[test]
    fn format_hijri_en_and_ar() {
        let h = hijri::to_hijri(NaiveDate::from_ymd_opt(2026, 10, 18).unwrap()).unwrap();
        let en = hijri::month_name(h.month, "en").unwrap();
        let ar = hijri::month_name(h.month, "ar").unwrap();
        assert_eq!(
            run(day(), "hijri", "en"),
            format!("{} {en} {} AH", h.day, h.year)
        );
        assert_eq!(
            run(day(), "hijri | digits('western')", "ar"),
            format!("{} {ar} {} هـ", h.day, h.year)
        );
        assert_eq!(
            run(day(), "hijri('short')", "en"),
            format!("{}/{:02}/{:02}", h.year, h.month, h.day)
        );
    }

    #[test]
    fn format_number_en_and_ar() {
        assert_eq!(
            run(Value::Number(1234567.891), "number(2)", "en"),
            "1,234,567.89"
        );
        assert_eq!(run(Value::Number(-1234.6), "number", "en"), "-1,235");
        assert_eq!(run(Value::Number(-0.001), "number(2)", "en"), "0.00");
        assert_eq!(run(Value::Number(1234.5), "number(1)", "ar"), "١٬٢٣٤٫٥");
        assert!(parse_filter("number(7)").is_err());
    }

    #[test]
    fn format_currency_en_and_ar() {
        assert_eq!(
            run(Value::Number(1234.5), "currency('SAR')", "en"),
            "SAR 1,234.50"
        );
        assert_eq!(
            run(Value::Number(12.3456), "currency('kwd')", "en"),
            "KWD 12.346"
        );
        assert_eq!(
            run(Value::Number(1234.5), "currency('SAR')", "ar"),
            "١٬٢٣٤٫٥٠ ر.س"
        );
        assert_eq!(run(Value::Number(5.0), "currency('JPY')", "ar"), "JPY ٥");
        assert!(parse_filter("currency('XYZ')").is_err());
        assert!(parse_filter("currency").is_err());
    }

    #[test]
    fn format_digits_both_ways() {
        assert_eq!(
            run(
                Value::Number(1234.5),
                "currency('SAR') | digits('western')",
                "ar"
            ),
            "1,234.50 ر.س"
        );
        assert_eq!(
            run(
                Value::Text("Room 12, floor 3.".into()),
                "digits('arabic')",
                "en"
            ),
            "Room ١٢, floor ٣."
        );
        assert!(parse_filter("digits('roman')").is_err());
    }

    #[test]
    fn format_checks_input_types() {
        let chain = [parse_filter("number(2)").unwrap()];
        assert!(check(&Type::Number, &chain).is_ok());
        assert!(check(&Type::Text, &chain).is_err());
        let after_text = [
            parse_filter("date").unwrap(),
            parse_filter("number").unwrap(),
        ];
        assert!(check(&Type::Date, &after_text).is_err());
        assert!(parse_filter("upper").is_err());
    }

    #[test]
    fn format_split_ignores_quoted_pipes() {
        assert_eq!(
            split(r#"concat(name, "a|b") | digits('arabic')"#),
            (r#"concat(name, "a|b")"#, vec!["digits('arabic')"])
        );
        assert_eq!(split("amount"), ("amount", vec![]));
    }

    #[test]
    fn format_locale_lang() {
        assert!(Locale::parse("ar-SA").is_arabic());
        assert_eq!(Locale::parse("en_GB").lang(), "en");
        assert_eq!(Locale::parse("\"><x").lang(), "x");
        assert_eq!(Locale::parse("").lang(), "en");
    }
}
