//! A23-T2: reading an uploaded import file into rows of text cells.
//!
//! - **Encoding.** A UTF-8 or UTF-16 byte-order mark decides; otherwise
//!   valid UTF-8 is UTF-8, and anything else is read as Windows-1256, the
//!   code page Arabic Excel saves CSV in.
//! - **CSV.** RFC 4180 quoting (doubled quotes, line breaks inside quotes).
//!   With no delimiter given, the one of `,` `;` tab `|` that splits the
//!   first five lines most evenly wins.
//! - **XLSX.** A ZIP of XML read with the same small ZIP reader and
//!   `quick-xml` as document text ([`crate::text_extract::zip_member`]), so no
//!   spreadsheet library joins the build. Text cells stay text (leading zeros
//!   survive); a number cell whose style is a date format becomes an ISO
//!   date; a merged range repeats its top-left value in every cell.
//! - **Cells.** [`normalize_cell`] turns Arabic-Indic and Eastern Arabic
//!   digits into ASCII and drops the invisible direction marks Excel and
//!   Arabic keyboards insert. [`parse_date`] reads ISO, `dd/mm/yyyy` and
//!   Hijri dates (`هـ` or `AH`) through the Umm al-Qura table.
//!
//! Everything here is pure; the import job decides what the rows mean.

use std::collections::HashMap;

use chrono::{Duration, NaiveDate};
use encoding_rs::Encoding;
use quick_xml::events::{BytesStart, Event};

use crate::text_extract::zip_member;

/// The most rows one file is read to.
pub const MAX_ROWS: usize = 1_000_000;
/// The most cells one row is read to.
pub const MAX_COLUMNS: usize = 1_000;

/// Why a file could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// A quoted CSV field never closed.
    UnclosedQuote { line: usize },
    /// Not an XLSX workbook, or a part of it is missing or malformed.
    NotAWorkbook(&'static str),
    /// The workbook has no sheet of that name.
    NoSuchSheet(String),
    /// More rows or columns than the reader takes.
    TooLarge,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnclosedQuote { line } => {
                write!(f, "a quoted value starting on line {line} never closes")
            }
            Self::NotAWorkbook(what) => write!(f, "not a readable XLSX workbook: {what}"),
            Self::NoSuchSheet(name) => write!(f, "the workbook has no sheet named '{name}'"),
            Self::TooLarge => write!(
                f,
                "the file has more than {MAX_ROWS} rows or {MAX_COLUMNS} columns"
            ),
        }
    }
}

impl std::error::Error for ImportError {}

// ── Encoding and CSV ────────────────────────────────────────────────────────

/// The encoding of a text file's bytes.
pub fn detect_encoding(bytes: &[u8]) -> &'static Encoding {
    if let Some((encoding, _)) = Encoding::for_bom(bytes) {
        return encoding;
    }
    if std::str::from_utf8(bytes).is_ok() {
        encoding_rs::UTF_8
    } else {
        encoding_rs::WINDOWS_1256
    }
}

/// `bytes` as text in its detected encoding, without the byte-order mark.
pub fn decode_text(bytes: &[u8]) -> String {
    let encoding = detect_encoding(bytes);
    let (text, _, _) = encoding.decode(bytes);
    text.into_owned()
}

const DELIMITERS: [u8; 4] = *b",;\t|";

/// How many times `delimiter` occurs outside quotes on each of the first
/// five lines.
fn counts_per_line(text: &str, delimiter: char) -> Vec<usize> {
    let mut counts = Vec::new();
    let mut current = 0;
    let mut quoted = false;
    for c in text.chars() {
        match c {
            '"' => quoted = !quoted,
            '\n' if !quoted => {
                counts.push(current);
                current = 0;
                if counts.len() == 5 {
                    return counts;
                }
            }
            c if c == delimiter && !quoted => current += 1,
            _ => {}
        }
    }
    if current > 0 || counts.is_empty() {
        counts.push(current);
    }
    counts
}

/// The delimiter that splits the first lines most evenly: the highest
/// count every line reaches, ties going to the earlier of `, ; tab |`.
pub fn sniff_delimiter(text: &str) -> u8 {
    let mut best = (b',', 0usize);
    for d in DELIMITERS {
        let counts = counts_per_line(text, char::from(d));
        let floor = counts.iter().copied().min().unwrap_or(0);
        if floor > best.1 {
            best = (d, floor);
        }
    }
    best.0
}

/// The rows of a CSV file: decoded in its detected encoding, split on
/// `delimiter` (sniffed when `None`). A blank last line is not a row.
pub fn read_csv(bytes: &[u8], delimiter: Option<u8>) -> Result<Vec<Vec<String>>, ImportError> {
    let text = decode_text(bytes);
    let delimiter = char::from(delimiter.unwrap_or_else(|| sniff_delimiter(&text)));
    let mut rows = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut quote_line = 0;
    let mut line = 1;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => quoted = false,
                '\n' => {
                    line += 1;
                    field.push('\n');
                }
                c => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => {
                quoted = true;
                quote_line = line;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' | '\r' => {
                line += 1;
                row.push(std::mem::take(&mut field));
                push_row(&mut rows, std::mem::take(&mut row))?;
            }
            c if c == delimiter => {
                row.push(std::mem::take(&mut field));
                if row.len() > MAX_COLUMNS {
                    return Err(ImportError::TooLarge);
                }
            }
            c => field.push(c),
        }
    }
    if quoted {
        return Err(ImportError::UnclosedQuote { line: quote_line });
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        push_row(&mut rows, row)?;
    }
    Ok(rows)
}

fn push_row(rows: &mut Vec<Vec<String>>, row: Vec<String>) -> Result<(), ImportError> {
    // A line with nothing on it (the file's trailing newline, a blank line)
    // is not a row.
    if row.len() == 1 && row[0].is_empty() {
        return Ok(());
    }
    if rows.len() >= MAX_ROWS {
        return Err(ImportError::TooLarge);
    }
    rows.push(row);
    Ok(())
}

// ── Cells and dates ─────────────────────────────────────────────────────────

/// `s` with Arabic-Indic (U+0660..) and Eastern Arabic (U+06F0..) digits as
/// ASCII digits, the Arabic decimal and thousands separators as `.` and
/// `,`, and the left-to-right, right-to-left and Arabic letter marks
/// removed.
pub fn normalize_cell(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\u{200E}' | '\u{200F}' | '\u{061C}'))
        .map(|c| match c {
            '\u{0660}'..='\u{0669}' => digit(c, 0x0660),
            '\u{06F0}'..='\u{06F9}' => digit(c, 0x06F0),
            '\u{066B}' => '.',
            '\u{066C}' => ',',
            c => c,
        })
        .collect()
}

fn digit(c: char, zero: u32) -> char {
    char::from_digit(u32::from(c) - zero, 10).unwrap_or(c)
}

/// Which calendar a date without a marker is read in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalendarHint {
    Gregorian,
    Hijri,
}

/// The three numbers of `yyyy-mm-dd`, `yyyy/mm/dd`, `dd/mm/yyyy`,
/// `dd-mm-yyyy` or `dd.mm.yyyy`, as (year, month, day).
fn ymd(s: &str) -> Option<(i32, u32, u32)> {
    let parts: Vec<&str> = s.split(['-', '/', '.']).map(str::trim).collect();
    let [a, b, c] = parts.as_slice() else {
        return None;
    };
    let (a, b, c) = (
        a.parse::<u32>().ok()?,
        b.parse::<u32>().ok()?,
        c.parse::<u32>().ok()?,
    );
    if parts[0].len() == 4 {
        Some((i32::try_from(a).ok()?, b, c))
    } else if parts[2].len() == 4 {
        Some((i32::try_from(c).ok()?, b, a))
    } else {
        None
    }
}

/// A date cell as a Gregorian date: ISO (`2026-03-01`, a time after it is
/// ignored), `dd/mm/yyyy`, or a Hijri date — marked with `هـ`/`ه` or `AH`,
/// or unmarked under [`CalendarHint::Hijri`] — converted through the Umm
/// al-Qura table. `None` when it is none of these or not a real date.
pub fn parse_date(s: &str, hint: CalendarHint) -> Option<NaiveDate> {
    let s = normalize_cell(s);
    let s = s.trim();
    let lower = s.to_lowercase();
    let marked = s.ends_with("هـ") || s.ends_with('ه') || lower.ends_with("ah");
    let core = s
        .trim_end_matches("هـ")
        .trim_end_matches('ه')
        .trim_end_matches(['A', 'a'].as_slice())
        .trim();
    let core = if lower.ends_with("ah") {
        core.trim_end_matches(['H', 'h', 'A', 'a'].as_slice())
            .trim()
    } else {
        core
    };
    // An ISO timestamp keeps only its date.
    let core = core.split(['T', ' ']).next().unwrap_or(core);
    let (year, month, day) = ymd(core)?;
    if marked || hint == CalendarHint::Hijri {
        let date = attome_core::calendar::hijri::HijriDate::new(
            u16::try_from(year).ok()?,
            u8::try_from(month).ok()?,
            u8::try_from(day).ok()?,
        );
        return attome_core::calendar::hijri::from_hijri(date).ok();
    }
    NaiveDate::from_ymd_opt(year, month, day)
}

// ── XLSX ────────────────────────────────────────────────────────────────────

/// One sheet's cells, row by row, every row as wide as the widest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SheetRows {
    /// Every sheet of the workbook, in tab order.
    pub sheet_names: Vec<String>,
    /// The sheet that was read.
    pub sheet: String,
    pub rows: Vec<Vec<String>>,
}

fn attr(e: &BytesStart<'_>, key: &[u8]) -> Option<String> {
    e.attributes().flatten().find_map(|a| {
        (a.key.as_ref() == key).then(|| {
            a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map(|v| v.into_owned())
                .unwrap_or_default()
        })
    })
}

fn member(bytes: &[u8], name: &str) -> Option<Vec<u8>> {
    zip_member(bytes, name)
}

/// Every element start (or empty element) of `xml` named `tag`, with the
/// attributes asked for.
fn elements(xml: &[u8], tag: &[u8], keys: &[&[u8]]) -> Vec<Vec<Option<String>>> {
    let mut reader = quick_xml::Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut out = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e) | Event::Empty(e)) if e.name().as_ref() == tag => {
                out.push(keys.iter().map(|k| attr(&e, k)).collect());
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

/// The text of every `<si>` of `xl/sharedStrings.xml`, rich runs joined.
fn shared_strings(xml: &[u8]) -> Vec<String> {
    let mut reader = quick_xml::Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_text = false;
    // Phonetic runs (`<rPh>`) repeat the reading, not the value.
    let mut in_phonetic = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"t" => in_text = !in_phonetic,
                b"rPh" => in_phonetic = true,
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"t" => in_text = false,
                b"rPh" => in_phonetic = false,
                b"si" => out.push(std::mem::take(&mut current)),
                _ => {}
            },
            Ok(Event::Empty(e)) if e.name().as_ref() == b"si" => out.push(String::new()),
            Ok(Event::Text(t)) if in_text => {
                if let Ok(text) = t.decode() {
                    current.push_str(&text);
                }
            }
            Ok(Event::GeneralRef(r)) if in_text => push_ref(&r, &mut current),
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

fn push_ref(r: &quick_xml::events::BytesRef<'_>, out: &mut String) {
    if let Ok(Some(c)) = r.resolve_char_ref() {
        out.push(c);
    } else if let Ok(name) = r.decode()
        && let Some(text) = quick_xml::escape::resolve_predefined_entity(&name)
    {
        out.push_str(text);
    }
}

/// Whether an Excel number format shows a date: the built-in date ids, or
/// a custom code with a day, month or year part outside quotes and
/// brackets.
fn is_date_format(id: u32, custom: Option<&str>) -> bool {
    if matches!(id, 14..=22 | 27..=36 | 45..=47 | 50..=58) {
        return true;
    }
    let Some(code) = custom else {
        return false;
    };
    let mut quoted = false;
    let mut bracket = false;
    for c in code.chars() {
        match c {
            '"' => quoted = !quoted,
            '[' if !quoted => bracket = true,
            ']' if !quoted => bracket = false,
            'd' | 'D' | 'm' | 'M' | 'y' | 'Y' if !quoted && !bracket => return true,
            _ => {}
        }
    }
    false
}

/// For each cell style index (`s`), whether it shows a date.
fn date_styles(styles: &[u8]) -> Vec<bool> {
    let custom: HashMap<u32, String> = elements(styles, b"numFmt", &[b"numFmtId", b"formatCode"])
        .into_iter()
        .filter_map(|a| Some((a[0].as_ref()?.parse().ok()?, a[1].clone()?)))
        .collect();
    // `<xf>` appears under both cellStyleXfs and cellXfs; cell `s` indexes
    // the cellXfs list, which comes last.
    let mut reader = quick_xml::Reader::from_reader(styles);
    let mut buf = Vec::new();
    let mut in_cell_xfs = false;
    let mut out = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.name().as_ref() == b"cellXfs" => in_cell_xfs = true,
            Ok(Event::End(e)) if e.name().as_ref() == b"cellXfs" => in_cell_xfs = false,
            Ok(Event::Start(e) | Event::Empty(e)) if in_cell_xfs && e.name().as_ref() == b"xf" => {
                let id = attr(&e, b"numFmtId")
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(0);
                out.push(is_date_format(id, custom.get(&id).map(String::as_str)));
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

/// An Excel date serial (1900 date system) as an ISO date, with the time
/// when it has one.
pub fn excel_serial_to_iso(serial: f64) -> Option<String> {
    if !serial.is_finite() || !(0.0..2_958_466.0).contains(&serial) {
        return None;
    }
    let days = serial.floor();
    // Excel counts 1900-02-29, which never was: from serial 61 on, day 0
    // is 1899-12-30; before it, 1899-12-31.
    let epoch = if days >= 61.0 {
        NaiveDate::from_ymd_opt(1899, 12, 30)?
    } else {
        NaiveDate::from_ymd_opt(1899, 12, 31)?
    };
    // Bounded above, so the cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    let date = epoch.checked_add_signed(Duration::days(days as i64))?;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let seconds = ((serial - days) * 86_400.0).round() as u32;
    if seconds == 0 {
        Some(date.format("%Y-%m-%d").to_string())
    } else {
        let seconds = seconds.min(86_399);
        Some(format!(
            "{}T{:02}:{:02}:{:02}",
            date.format("%Y-%m-%d"),
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60
        ))
    }
}

/// A number cell's text: an integer without `.0`, otherwise as stored.
fn number_text(raw: &str) -> String {
    match raw.parse::<f64>() {
        Ok(n) if n.fract() == 0.0 && n.abs() < 1e15 => format!("{n:.0}"),
        _ => raw.to_owned(),
    }
}

/// Zero-based (column, row) of a cell reference such as `B7` or `AA10`.
fn cell_position(reference: &str) -> Option<(usize, usize)> {
    let split = reference.find(|c: char| c.is_ascii_digit())?;
    let (letters, digits) = reference.split_at(split);
    if letters.is_empty() {
        return None;
    }
    let mut column = 0usize;
    for c in letters.chars() {
        if !c.is_ascii_uppercase() {
            return None;
        }
        column = column * 26 + usize::from(c as u8 - b'A') + 1;
    }
    let row: usize = digits.parse().ok()?;
    Some((column.checked_sub(1)?, row.checked_sub(1)?))
}

/// The sheet paths of a workbook in tab order, by name.
fn sheet_paths(bytes: &[u8]) -> Result<Vec<(String, String)>, ImportError> {
    let workbook = member(bytes, "xl/workbook.xml")
        .ok_or(ImportError::NotAWorkbook("xl/workbook.xml is missing"))?;
    let rels = member(bytes, "xl/_rels/workbook.xml.rels").ok_or(ImportError::NotAWorkbook(
        "the workbook relationships are missing",
    ))?;
    let targets: HashMap<String, String> = elements(&rels, b"Relationship", &[b"Id", b"Target"])
        .into_iter()
        .filter_map(|a| Some((a[0].clone()?, a[1].clone()?)))
        .collect();
    let sheets = elements(&workbook, b"sheet", &[b"name", b"r:id"]);
    if sheets.is_empty() {
        return Err(ImportError::NotAWorkbook("the workbook lists no sheets"));
    }
    sheets
        .into_iter()
        .map(|a| {
            let name = a[0].clone().unwrap_or_default();
            let target = a[1]
                .as_ref()
                .and_then(|id| targets.get(id))
                .ok_or(ImportError::NotAWorkbook("a sheet has no target"))?;
            // Targets are relative to xl/, or absolute from the archive root.
            let path = match target.strip_prefix('/') {
                Some(absolute) => absolute.to_owned(),
                None => format!("xl/{target}"),
            };
            Ok((name, path))
        })
        .collect()
}

/// One sheet of an XLSX workbook (`sheet`, or the first) as rows of text.
pub fn read_xlsx(bytes: &[u8], sheet: Option<&str>) -> Result<SheetRows, ImportError> {
    let sheets = sheet_paths(bytes)?;
    let sheet_names: Vec<String> = sheets.iter().map(|(name, _)| name.clone()).collect();
    let (name, path) = match sheet {
        Some(wanted) => sheets
            .iter()
            .find(|(name, _)| name == wanted)
            .ok_or_else(|| ImportError::NoSuchSheet(wanted.to_owned()))?,
        None => &sheets[0],
    };
    let xml = member(bytes, path).ok_or(ImportError::NotAWorkbook("a sheet part is missing"))?;
    let strings = member(bytes, "xl/sharedStrings.xml")
        .map(|x| shared_strings(&x))
        .unwrap_or_default();
    let dates = member(bytes, "xl/styles.xml")
        .map(|x| date_styles(&x))
        .unwrap_or_default();

    let mut cells: HashMap<(usize, usize), String> = HashMap::new();
    let mut merges: Vec<((usize, usize), (usize, usize))> = Vec::new();
    let mut reader = quick_xml::Reader::from_reader(xml.as_slice());
    let mut buf = Vec::new();
    // The cell being read: position, type, style, and its value text.
    let mut cell: Option<((usize, usize), String, usize)> = None;
    let mut value = String::new();
    let mut in_value = false;
    let mut next_column = 0usize;
    let mut row_index = 0usize;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) if e.name().as_ref() == b"row" => {
                row_index = attr(&e, b"r")
                    .and_then(|r| r.parse::<usize>().ok())
                    .and_then(|r| r.checked_sub(1))
                    .unwrap_or(row_index);
                next_column = 0;
                if row_index >= MAX_ROWS {
                    return Err(ImportError::TooLarge);
                }
            }
            Ok(Event::End(e)) if e.name().as_ref() == b"row" => row_index += 1,
            Ok(Event::Start(e)) if e.name().as_ref() == b"c" => {
                let position = attr(&e, b"r")
                    .and_then(|r| cell_position(&r))
                    .unwrap_or((next_column, row_index));
                if position.0 >= MAX_COLUMNS {
                    return Err(ImportError::TooLarge);
                }
                next_column = position.0 + 1;
                let kind = attr(&e, b"t").unwrap_or_default();
                let style = attr(&e, b"s").and_then(|s| s.parse().ok()).unwrap_or(0);
                cell = Some((position, kind, style));
                value.clear();
            }
            Ok(Event::Empty(e)) if e.name().as_ref() == b"c" => {
                next_column = attr(&e, b"r")
                    .and_then(|r| cell_position(&r))
                    .map_or(next_column + 1, |(c, _)| c + 1);
            }
            Ok(Event::Start(e)) if matches!(e.name().as_ref(), b"v" | b"t") => {
                in_value = cell.is_some();
            }
            Ok(Event::End(e)) if matches!(e.name().as_ref(), b"v" | b"t") => in_value = false,
            Ok(Event::Text(t)) if in_value => {
                if let Ok(text) = t.decode() {
                    value.push_str(&text);
                }
            }
            Ok(Event::GeneralRef(r)) if in_value => push_ref(&r, &mut value),
            Ok(Event::End(e)) if e.name().as_ref() == b"c" => {
                if let Some((position, kind, style)) = cell.take() {
                    let text = match kind.as_str() {
                        "s" => value
                            .trim()
                            .parse::<usize>()
                            .ok()
                            .and_then(|i| strings.get(i).cloned())
                            .unwrap_or_default(),
                        "b" => (if value.trim() == "1" { "true" } else { "false" }).to_owned(),
                        "str" | "inlineStr" | "e" => value.clone(),
                        _ if dates.get(style).copied().unwrap_or(false) => value
                            .trim()
                            .parse::<f64>()
                            .ok()
                            .and_then(excel_serial_to_iso)
                            .unwrap_or_else(|| value.clone()),
                        _ => number_text(value.trim()),
                    };
                    cells.insert(position, text);
                }
            }
            Ok(Event::Start(e) | Event::Empty(e)) if e.name().as_ref() == b"mergeCell" => {
                if let Some(range) = attr(&e, b"ref")
                    && let Some((from, to)) = range.split_once(':')
                    && let (Some(a), Some(b)) = (cell_position(from), cell_position(to))
                {
                    merges.push((a, b));
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(ImportError::NotAWorkbook("a sheet part is not valid XML")),
            _ => {}
        }
        buf.clear();
    }

    for ((c0, r0), (c1, r1)) in merges {
        let Some(top_left) = cells.get(&(c0, r0)).cloned() else {
            continue;
        };
        for r in r0..=r1.min(MAX_ROWS - 1) {
            for c in c0..=c1.min(MAX_COLUMNS - 1) {
                cells.entry((c, r)).or_insert_with(|| top_left.clone());
            }
        }
    }

    let height = cells.keys().map(|(_, r)| r + 1).max().unwrap_or(0);
    let width = cells.keys().map(|(c, _)| c + 1).max().unwrap_or(0);
    let mut rows = vec![vec![String::new(); width]; height];
    for ((c, r), text) in cells {
        rows[r][c] = text;
    }
    Ok(SheetRows {
        sheet_names,
        sheet: name.clone(),
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ZIP of stored (uncompressed) members, enough for the reader.
    fn stored_zip(members: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, body) in members {
            let offset = u32::try_from(out.len()).unwrap();
            let size = u32::try_from(body.len()).unwrap();
            let name_len = u16::try_from(name.len()).unwrap();
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&name_len.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(body.as_bytes());

            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&name_len.to_le_bytes());
            central.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let central_at = u32::try_from(out.len()).unwrap();
        let central_len = u32::try_from(central.len()).unwrap();
        let count = u16::try_from(members.len()).unwrap();
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&central_len.to_le_bytes());
        out.extend_from_slice(&central_at.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn workbook(sheet_xml: &str) -> Vec<u8> {
        stored_zip(&[
            (
                "xl/workbook.xml",
                r#"<workbook xmlns:r="r"><sheets><sheet name="Data" sheetId="1" r:id="rId1"/><sheet name="Other" sheetId="2" r:id="rId2"/></sheets></workbook>"#,
            ),
            (
                "xl/_rels/workbook.xml.rels",
                r#"<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Target="worksheets/sheet2.xml"/></Relationships>"#,
            ),
            (
                "xl/sharedStrings.xml",
                r#"<sst><si><t>Code</t></si><si><t>00123</t></si><si><r><t>Ri</t></r><r><t>yadh</t></r></si></sst>"#,
            ),
            (
                "xl/styles.xml",
                r#"<styleSheet><numFmts><numFmt numFmtId="164" formatCode="dd/mm/yyyy"/></numFmts><cellStyleXfs><xf numFmtId="0"/></cellStyleXfs><cellXfs><xf numFmtId="0"/><xf numFmtId="164"/><xf numFmtId="14"/></cellXfs></styleSheet>"#,
            ),
            ("xl/worksheets/sheet1.xml", sheet_xml),
            (
                "xl/worksheets/sheet2.xml",
                "<worksheet><sheetData/></worksheet>",
            ),
        ])
    }

    #[test]
    fn windows_1256_detected() {
        // "مرحبا" in Windows-1256.
        let bytes = [0xE3, 0xD1, 0xCD, 0xC8, 0xC7, b',', b'1', b'\n'];
        assert_eq!(detect_encoding(&bytes), encoding_rs::WINDOWS_1256);
        let rows = read_csv(&bytes, None).unwrap();
        assert_eq!(rows, vec![vec!["مرحبا".to_owned(), "1".to_owned()]]);
    }

    #[test]
    fn utf16_bom_detected() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "a;b\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(detect_encoding(&bytes), encoding_rs::UTF_16LE);
        assert_eq!(read_csv(&bytes, None).unwrap(), vec![vec!["a", "b"]]);
        let utf8_bom = b"\xEF\xBB\xBFx,y\n";
        assert_eq!(detect_encoding(utf8_bom), encoding_rs::UTF_8);
        assert_eq!(read_csv(utf8_bom, None).unwrap(), vec![vec!["x", "y"]]);
    }

    #[test]
    fn csv_quotes_and_sniffed_delimiter() {
        let text = "name;note\r\n\"Ali\";\"said \"\"hi\"\"\nthen left\"\r\nSara;ok\r\n";
        let rows = read_csv(text.as_bytes(), None).unwrap();
        assert_eq!(rows[0], vec!["name", "note"]);
        assert_eq!(rows[1], vec!["Ali", "said \"hi\"\nthen left"]);
        assert_eq!(rows[2], vec!["Sara", "ok"]);
        assert_eq!(sniff_delimiter("a\tb\tc\n1\t2\t3\n"), b'\t');
        assert_eq!(
            read_csv(b"\"open,1\n", None),
            Err(ImportError::UnclosedQuote { line: 1 })
        );
    }

    #[test]
    fn xlsx_date_serial_to_iso() {
        assert_eq!(excel_serial_to_iso(45_000.0).as_deref(), Some("2023-03-15"));
        assert_eq!(excel_serial_to_iso(1.0).as_deref(), Some("1900-01-01"));
        assert_eq!(
            excel_serial_to_iso(45_000.5).as_deref(),
            Some("2023-03-15T12:00:00")
        );
        let sheet = r#"<worksheet><sheetData>
            <row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" s="1"><v>45000</v></c><c r="C1" s="2"><v>45001</v></c><c r="D1"><v>45000</v></c></row>
            </sheetData></worksheet>"#;
        let read = read_xlsx(&workbook(sheet), None).unwrap();
        assert_eq!(read.sheet_names, vec!["Data", "Other"]);
        assert_eq!(
            read.rows[0],
            vec!["Code", "2023-03-15", "2023-03-16", "45000"]
        );
    }

    #[test]
    fn leading_zero_kept() {
        let sheet = r#"<worksheet><sheetData>
            <row r="1"><c r="A1" t="s"><v>1</v></c><c r="B1" t="inlineStr"><is><t>007</t></is></c><c r="C1" t="s"><v>2</v></c></row>
            <row r="3"><c r="B3"><v>12.5</v></c></row>
            </sheetData><mergeCells><mergeCell ref="A1:A3"/></mergeCells></worksheet>"#;
        let read = read_xlsx(&workbook(sheet), Some("Data")).unwrap();
        assert_eq!(read.rows[0], vec!["00123", "007", "Riyadh"]);
        // The merged range repeats its top-left value; an empty row stays.
        assert_eq!(read.rows[1], vec!["00123", "", ""]);
        assert_eq!(read.rows[2], vec!["00123", "12.5", ""]);
        assert_eq!(
            read_xlsx(&workbook(sheet), Some("Nope")),
            Err(ImportError::NoSuchSheet("Nope".into()))
        );
        assert!(matches!(
            read_xlsx(b"not a zip", None),
            Err(ImportError::NotAWorkbook(_))
        ));
    }

    #[test]
    fn arabic_digits_normalized() {
        assert_eq!(normalize_cell("٠٥٠١٢٣٤٥٦٧"), "0501234567");
        assert_eq!(normalize_cell("۱۲۳"), "123");
        assert_eq!(normalize_cell("\u{200F}١٢٫٥"), "12.5");
    }

    #[test]
    fn hijri_date_parsed() {
        let gregorian = NaiveDate::from_ymd_opt(2026, 3, 1).unwrap();
        assert_eq!(
            parse_date("2026-03-01", CalendarHint::Gregorian),
            Some(gregorian)
        );
        assert_eq!(
            parse_date("01/03/2026", CalendarHint::Gregorian),
            Some(gregorian)
        );
        assert_eq!(
            parse_date("2026-03-01T10:00:00Z", CalendarHint::Gregorian),
            Some(gregorian)
        );
        let hijri = attome_core::calendar::hijri::to_hijri(gregorian).unwrap();
        let written = format!("{}/{}/{} هـ", hijri.day, hijri.month, hijri.year);
        assert_eq!(
            parse_date(&written, CalendarHint::Gregorian),
            Some(gregorian)
        );
        let ah = format!("{}-{:02}-{:02} AH", hijri.year, hijri.month, hijri.day);
        assert_eq!(parse_date(&ah, CalendarHint::Gregorian), Some(gregorian));
        let bare = format!("{}/{}/{}", hijri.day, hijri.month, hijri.year);
        assert_eq!(parse_date(&bare, CalendarHint::Hijri), Some(gregorian));
        assert_eq!(parse_date("31/02/2026", CalendarHint::Gregorian), None);
        assert_eq!(parse_date("soon", CalendarHint::Gregorian), None);
    }
}
