//! CSV/XLSX cell rendering — the platform's one implementation.
//!
//! Two callers share it: a report run's collected rows (`crate::run`, rows
//! already in memory as `Vec<Value>` from `query_exec::execute_stored_query`
//! pages) and `attome_api::data_export`'s worker (rows streamed from SQL as
//! `row_to_json` objects). Both hand in a JSON object per row keyed by
//! column name plus the ordered header, so the cell formatting, CSV quoting
//! and XLSX cell typing live here once (CLEANUP-REVIEW 2.8 / R-10).
//!
//! **Formula-injection guard (P4-T1), on by default.** A text cell that
//! starts with `=`, `+`, `-`, `@`, a tab or a carriage return would run as
//! a formula when a spreadsheet opens the file; [`guard_formula`] prefixes
//! it with `'` so it shows as text. Numbers are written as numbers and are
//! never touched. The `records.export_formula_guard` setting
//! ([`formula_guard_enabled`]) turns it off for a deployment that needs the
//! raw text; the `*_with` functions take the choice, the plain ones guard.

use std::borrow::Cow;

use serde_json::Value;

/// The setting that turns the formula-injection guard off.
pub const FORMULA_GUARD_SETTING: &str = "records.export_formula_guard";

/// Whether exports guard formula-like cells: the deployment's
/// [`FORMULA_GUARD_SETTING`], on unless it is set to `false`.
pub fn formula_guard_enabled(state: &attome_core::EngineState) -> bool {
    attome_core::setting_registry()
        .get(FORMULA_GUARD_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// A text cell as a spreadsheet will show it: one that would start a
/// formula is prefixed with `'`. Pure.
pub fn guard_formula(text: &str) -> Cow<'_, str> {
    match text.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => Cow::Owned(format!("'{text}")),
        _ => Cow::Borrowed(text),
    }
}

fn cell_to_csv_string(value: &Value, guard: bool) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) if guard => guard_formula(s).into_owned(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// Quotes one CSV field (RFC 4180): wrapped in `"` with inner quotes doubled
/// when it holds a comma, quote, CR or LF; otherwise unchanged.
pub fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

/// B21-T3: the byte-order mark a CSV file starts with, so spreadsheet
/// programs (Excel above all) read it as UTF-8 and show Arabic correctly.
pub const CSV_BOM: &str = "\u{feff}";

/// Renders `rows` (each a JSON object keyed by column name) as CSV text,
/// [`CSV_BOM`] and `header` first. Bytes, not `String` — the caller uploads
/// this directly.
pub fn render_csv(header: &[String], rows: &[Value]) -> Vec<u8> {
    render_csv_with(header, rows, true)
}

/// [`render_csv`] with the formula guard on or off.
pub fn render_csv_with(header: &[String], rows: &[Value], guard: bool) -> Vec<u8> {
    let mut out = CSV_BOM.to_owned();
    out.push_str(&csv_header_line(header));
    out.push('\n');
    for row in rows {
        out.push_str(&csv_line_with(header, row, guard));
        out.push('\n');
    }
    out.into_bytes()
}

/// The CSV header line for `header`, without a line terminator.
pub fn csv_header_line(header: &[String]) -> String {
    header
        .iter()
        .map(|c| csv_escape(c))
        .collect::<Vec<_>>()
        .join(",")
}

/// One CSV data line for `row` (a JSON object keyed by column name), columns
/// in `header` order, without a line terminator. A missing column renders
/// as an empty field.
pub fn csv_line(header: &[String], row: &Value) -> String {
    csv_line_with(header, row, true)
}

/// [`csv_line`] with the formula guard on or off.
pub fn csv_line_with(header: &[String], row: &Value, guard: bool) -> String {
    header
        .iter()
        .map(|col| {
            csv_escape(&cell_to_csv_string(
                row.get(col).unwrap_or(&Value::Null),
                guard,
            ))
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn write_xlsx_cell(
    worksheet: &mut rust_xlsxwriter::Worksheet,
    row: u32,
    col: u16,
    value: &Value,
    guard: bool,
) -> Result<(), rust_xlsxwriter::XlsxError> {
    match value {
        Value::Null => Ok(()),
        Value::Bool(b) => worksheet.write_boolean(row, col, *b).map(|_| ()),
        Value::Number(n) => match n.as_f64() {
            Some(f) => worksheet.write_number(row, col, f).map(|_| ()),
            None => worksheet.write_string(row, col, n.to_string()).map(|_| ()),
        },
        Value::String(s) if guard => worksheet
            .write_string(row, col, guard_formula(s).as_ref())
            .map(|_| ()),
        Value::String(s) => worksheet.write_string(row, col, s).map(|_| ()),
        other => worksheet
            .write_string(row, col, other.to_string())
            .map(|_| ()),
    }
}

/// Renders `rows` as a one-sheet XLSX workbook (default sheet name, header
/// row first). Built in memory — an XLSX file is one zip archive whose
/// manifest isn't known until every row is written, so it cannot be
/// streamed row-by-row the way CSV can; callers bound the row count.
pub fn render_xlsx(header: &[String], rows: &[Value]) -> Result<Vec<u8>, attome_types::AppError> {
    render_xlsx_with(header, rows, true)
}

/// [`render_xlsx`] with the formula guard on or off.
pub fn render_xlsx_with(
    header: &[String],
    rows: &[Value],
    guard: bool,
) -> Result<Vec<u8>, attome_types::AppError> {
    let mut workbook = rust_xlsxwriter::Workbook::new();
    let worksheet = workbook.add_worksheet();
    for (col, name) in header.iter().enumerate() {
        worksheet
            .write_string(0, col as u16, name)
            .map_err(attome_types::AppError::internal)?;
    }
    for (row_idx, row) in rows.iter().enumerate() {
        for (col, name) in header.iter().enumerate() {
            let cell = row.get(name).unwrap_or(&Value::Null);
            write_xlsx_cell(worksheet, (row_idx + 1) as u32, col as u16, cell, guard)
                .map_err(attome_types::AppError::internal)?;
        }
    }
    workbook
        .save_to_buffer()
        .map_err(attome_types::AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formula_like_cells_are_written_as_text() {
        assert_eq!(guard_formula("=SUM(A1:A9)"), "'=SUM(A1:A9)");
        assert_eq!(guard_formula("+966 50"), "'+966 50");
        assert_eq!(guard_formula("-1+1"), "'-1+1");
        assert_eq!(guard_formula("@cmd"), "'@cmd");
        assert_eq!(guard_formula("\tx"), "'\tx");
        assert_eq!(guard_formula("Acme"), "Acme");
        assert_eq!(guard_formula(""), "");
        let header = vec!["name".to_owned(), "total".to_owned()];
        let row = serde_json::json!({ "name": "=HYPERLINK(\"x\")", "total": -5 });
        assert_eq!(
            csv_line(&header, &row),
            "\"'=HYPERLINK(\"\"x\"\")\",-5",
            "numbers stay numbers"
        );
        assert_eq!(
            csv_line_with(&header, &row, false),
            "\"=HYPERLINK(\"\"x\"\")\",-5"
        );
        assert!(render_xlsx_with(&header, &[row], true).is_ok());
    }

    #[test]
    fn csv_escapes_commas_and_quotes() {
        let header = vec!["a".to_string(), "b".to_string()];
        let rows = vec![serde_json::json!({"a": "x,y", "b": "he said \"hi\""})];
        let csv = String::from_utf8(render_csv(&header, &rows)).unwrap();
        assert_eq!(csv, "\u{feff}a,b\n\"x,y\",\"he said \"\"hi\"\"\"\n");
    }

    #[test]
    fn csv_missing_column_renders_empty() {
        let header = vec!["a".to_string(), "b".to_string()];
        let rows = vec![serde_json::json!({"a": "only-a"})];
        let csv = String::from_utf8(render_csv(&header, &rows)).unwrap();
        assert_eq!(csv, "\u{feff}a,b\nonly-a,\n");
    }

    #[test]
    fn csv_line_and_header_match_render_csv() {
        let header = vec!["a".to_string(), "b,c".to_string()];
        let row = serde_json::json!({"a": true, "b,c": 1.5});
        assert_eq!(csv_header_line(&header), "a,\"b,c\"");
        assert_eq!(csv_line(&header, &row), "true,1.5");
        let csv = String::from_utf8(render_csv(&header, std::slice::from_ref(&row))).unwrap();
        assert_eq!(csv, "\u{feff}a,\"b,c\"\ntrue,1.5\n");
    }

    #[test]
    fn csv_escape_quotes_line_breaks() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a\nb"), "\"a\nb\"");
        assert_eq!(csv_escape("a\rb"), "\"a\rb\"");
    }

    #[test]
    fn xlsx_renders_without_error() {
        let header = vec!["a".to_string()];
        let rows = vec![serde_json::json!({"a": 1}), serde_json::json!({"a": "two"})];
        let bytes = render_xlsx(&header, &rows).unwrap();
        assert!(!bytes.is_empty());
    }
}
