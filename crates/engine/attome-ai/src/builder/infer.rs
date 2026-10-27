//! A1-T13 (part): what a spreadsheet's columns hold, for drafting a model
//! from an upload. [`parse_csv`] reads the file's text; [`infer_columns`]
//! looks at up to [`SAMPLE_ROWS`] rows and gives each column a type when at
//! least [`AGREEMENT`] of its filled cells agree: a Hijri date (Umm al-Qura
//! years 1300 to 1500, `1446/03/15`, `15-03-1446` or with an Arabic month
//! name, `هـ` allowed), a Gregorian date, a number (Arabic-Indic digits too),
//! an email, a phone, yes/no, Arabic text or text. [`duplicate_columns`]
//! names columns that repeat another: the same header once normalised, or
//! the same values row for row. Pure: nothing here calls a model or writes.

use serde::Serialize;

/// Rows looked at per file.
pub const SAMPLE_ROWS: usize = 1_000;
/// The share of a column's filled cells that must agree on a type.
pub const AGREEMENT: f64 = 0.9;

/// What a column holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnType {
    HijriDate,
    Date,
    Number,
    Email,
    Phone,
    Bool,
    ArabicText,
    Text,
}

impl ColumnType {
    /// The attribute type a draft gives the column.
    pub fn field_type(self) -> &'static str {
        match self {
            Self::HijriDate | Self::Date => "date",
            Self::Number => "number",
            Self::Bool => "bool",
            Self::Email | Self::Phone | Self::ArabicText | Self::Text => "text",
        }
    }
}

/// One column as inferred.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ColumnProfile {
    pub header: String,
    pub column_type: ColumnType,
    pub field_type: &'static str,
    /// Filled cells looked at.
    pub filled: usize,
    /// `islamic-umalqura` for a Hijri date column, so the draft keeps the calendar.
    pub calendar: Option<&'static str>,
}

const ARABIC_MONTHS: [&str; 12] = [
    "محرم",
    "صفر",
    "ربيع الأول",
    "ربيع الآخر",
    "جمادى الأولى",
    "جمادى الآخرة",
    "رجب",
    "شعبان",
    "رمضان",
    "شوال",
    "ذو القعدة",
    "ذو الحجة",
];

/// Arabic-Indic and Eastern Arabic-Indic digits as ASCII. Pure.
pub fn ascii_digits(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{0660}'..='\u{0669}' => char::from(b'0' + (c as u32 - 0x0660) as u8),
            '\u{06F0}'..='\u{06F9}' => char::from(b'0' + (c as u32 - 0x06F0) as u8),
            '\u{066B}' => '.',
            '\u{066C}' => ',',
            other => other,
        })
        .collect()
}

/// The three numbers of a `y/m/d` or `d/m/y` date (`/`, `-` or `.`), if it is one.
fn date_parts(text: &str) -> Option<(u32, u32, u32)> {
    let t = text
        .trim()
        .trim_end_matches("هـ")
        .trim_end_matches('ه')
        .trim();
    let parts: Vec<&str> = t.split(['/', '-', '.']).map(str::trim).collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    let n: Vec<u32> = parts.iter().filter_map(|p| p.parse().ok()).collect();
    if n.len() != 3 {
        return None;
    }
    // Year first when the first part has four digits, else last.
    let (y, m, d) = if parts[0].len() == 4 {
        (n[0], n[1], n[2])
    } else {
        (n[2], n[1], n[0])
    };
    ((1..=12).contains(&m) && (1..=31).contains(&d)).then_some((y, m, d))
}

fn is_hijri(text: &str) -> bool {
    let t = ascii_digits(text);
    if let Some((y, _, d)) = date_parts(&t) {
        return (1300..=1500).contains(&y) && d <= 30;
    }
    // `15 رمضان 1446` (a month name between a day and a year).
    ARABIC_MONTHS.iter().any(|m| t.contains(m))
        && t.split_whitespace()
            .filter_map(|w| w.trim_end_matches("هـ").parse::<u32>().ok())
            .any(|y| (1300..=1500).contains(&y))
}

fn is_gregorian(text: &str) -> bool {
    let t = ascii_digits(text);
    let head = t.split(['T', ' ']).next().unwrap_or_default();
    date_parts(head).is_some_and(|(y, _, _)| (1900..=2100).contains(&y))
}

fn is_number(text: &str) -> bool {
    let t = ascii_digits(text).replace(',', "");
    let t = t.trim().trim_start_matches(['+', '-']);
    !t.is_empty()
        && t.chars().filter(|c| *c == '.').count() <= 1
        && t.chars().all(|c| c.is_ascii_digit() || c == '.')
        && t.chars().any(|c| c.is_ascii_digit())
}

fn is_email(text: &str) -> bool {
    let t = text.trim();
    match t.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && !t.contains(' ')
        }
        None => false,
    }
}

fn is_phone(text: &str) -> bool {
    let t = ascii_digits(text);
    let t = t.trim();
    let digits = t.chars().filter(char::is_ascii_digit).count();
    let allowed = t.chars().all(|c| c.is_ascii_digit() || " +-()".contains(c));
    allowed
        && (8..=15).contains(&digits)
        && (t.starts_with('+') || t.starts_with("00") || t.starts_with('0'))
}

fn is_bool(text: &str) -> bool {
    matches!(
        text.trim().to_lowercase().as_str(),
        "yes" | "no" | "true" | "false" | "y" | "n" | "نعم" | "لا"
    )
}

fn is_arabic(text: &str) -> bool {
    let letters = text.chars().filter(|c| c.is_alphabetic()).count();
    let arabic = text
        .chars()
        .filter(|c| ('\u{0600}'..='\u{06FF}').contains(c))
        .count();
    letters > 0 && arabic * 2 >= letters
}

/// The type of one cell, most specific first. Pure.
pub fn cell_type(text: &str) -> ColumnType {
    if is_hijri(text) {
        ColumnType::HijriDate
    } else if is_gregorian(text) {
        ColumnType::Date
    } else if is_email(text) {
        ColumnType::Email
    } else if is_phone(text) {
        ColumnType::Phone
    } else if is_number(text) {
        ColumnType::Number
    } else if is_bool(text) {
        ColumnType::Bool
    } else if is_arabic(text) {
        ColumnType::ArabicText
    } else {
        ColumnType::Text
    }
}

/// Each column's type from up to [`SAMPLE_ROWS`] rows. Pure.
pub fn infer_columns(headers: &[String], rows: &[Vec<String>]) -> Vec<ColumnProfile> {
    headers
        .iter()
        .enumerate()
        .map(|(i, header)| {
            let cells: Vec<&str> = rows
                .iter()
                .take(SAMPLE_ROWS)
                .filter_map(|r| r.get(i).map(String::as_str))
                .filter(|c| !c.trim().is_empty())
                .collect();
            let column_type = majority(&cells);
            ColumnProfile {
                header: header.trim().to_owned(),
                column_type,
                field_type: column_type.field_type(),
                filled: cells.len(),
                calendar: (column_type == ColumnType::HijriDate).then_some("islamic-umalqura"),
            }
        })
        .collect()
}

fn majority(cells: &[&str]) -> ColumnType {
    if cells.is_empty() {
        return ColumnType::Text;
    }
    let types: Vec<ColumnType> = cells.iter().map(|c| cell_type(c)).collect();
    for candidate in [
        ColumnType::HijriDate,
        ColumnType::Date,
        ColumnType::Email,
        ColumnType::Phone,
        ColumnType::Number,
        ColumnType::Bool,
        ColumnType::ArabicText,
    ] {
        let agree = types.iter().filter(|t| **t == candidate).count();
        if agree as f64 >= AGREEMENT * types.len() as f64 {
            return candidate;
        }
    }
    ColumnType::Text
}

fn normalise_header(h: &str) -> String {
    h.trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// Pairs `(first, repeat)` of columns that repeat an earlier one: the same
/// header once normalised, or the same filled values row for row. Pure.
pub fn duplicate_columns(headers: &[String], rows: &[Vec<String>]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for j in 0..headers.len() {
        for i in 0..j {
            let same_header = !normalise_header(&headers[i]).is_empty()
                && normalise_header(&headers[i]) == normalise_header(&headers[j]);
            let sample: Vec<&Vec<String>> = rows.iter().take(SAMPLE_ROWS).collect();
            let same_values = !sample.is_empty()
                && sample
                    .iter()
                    .any(|r| r.get(i).is_some_and(|v| !v.trim().is_empty()))
                && sample
                    .iter()
                    .all(|r| r.get(i).map(|v| v.trim()) == r.get(j).map(|v| v.trim()));
            if same_header || same_values {
                out.push((i, j));
                break;
            }
        }
    }
    out
}

/// A CSV file's header row and data rows: comma or semicolon separated,
/// double quotes around a cell that holds the separator, a quote or a line
/// break, `""` for a quote inside one. Pure.
pub fn parse_csv(text: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let first_line = text.lines().next().unwrap_or_default();
    let sep = if first_line.matches(';').count() > first_line.matches(',').count() {
        ';'
    } else {
        ','
    };
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cell.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            c if c == sep && !quoted => row.push(std::mem::take(&mut cell)),
            '\r' if !quoted => {}
            '\n' if !quoted => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            c => cell.push(c),
        }
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows.retain(|r| r.iter().any(|c| !c.trim().is_empty()));
    let mut it = rows.into_iter();
    let headers = it.next().unwrap_or_default();
    (headers, it.collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn csv_type_inference_detects_hijri_dates() {
        let (headers, rows) = parse_csv(
            "تاريخ الميلاد,Joined,Phone,Email,Salary,Active,الاسم\n\
             1446/03/15,2026-01-05,+966500000001,a@x.sa,\"12,500\",yes,سارة علي\n\
             ١٤٤٥/٠٩/٠١,2025-12-31,0500000002,b@x.sa,9000,no,محمد\n\
             15 رمضان 1444هـ,2025-11-20T10:00:00Z,00966500000003,c@x.sa,7000.5,yes,ليلى\n",
        );
        let cols = infer_columns(&headers, &rows);
        let types: Vec<ColumnType> = cols.iter().map(|c| c.column_type).collect();
        assert_eq!(
            types,
            [
                ColumnType::HijriDate,
                ColumnType::Date,
                ColumnType::Phone,
                ColumnType::Email,
                ColumnType::Number,
                ColumnType::Bool,
                ColumnType::ArabicText
            ]
        );
        assert_eq!(cols[0].calendar, Some("islamic-umalqura"));
        assert_eq!(cols[0].field_type, "date");
        assert_eq!(cols[1].calendar, None);
        assert!(!is_hijri("2026/03/15"), "a Gregorian year is not Hijri");
    }

    #[test]
    fn mixed_columns_stay_text_and_repeats_are_named() {
        let headers = s(&["Code", "code ", "Notes", "Copy"]);
        let rows = vec![
            s(&["A1", "x", "12", "12"]),
            s(&["B2", "y", "hello", "hello"]),
        ];
        assert_eq!(
            infer_columns(&headers, &rows)[2].column_type,
            ColumnType::Text
        );
        assert_eq!(duplicate_columns(&headers, &rows), vec![(0, 1), (2, 3)]);
        let (h, r) = parse_csv("a;b\n\"x;1\";\"say \"\"hi\"\"\"\n\n");
        assert_eq!(h, s(&["a", "b"]));
        assert_eq!(r, vec![s(&["x;1", "say \"hi\""])]);
    }
}
