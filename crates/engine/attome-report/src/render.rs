//! CSV/XLSX cell rendering — the platform's one implementation.
//!
//! Two callers share it: a report run's collected rows (`crate::run`, rows
//! already in memory as `Vec<Value>` from `query_exec::execute_stored_query`
//! pages) and `attome_api::data_export`'s worker (rows streamed from SQL as
//! `row_to_json` objects). Both hand in a JSON object per row keyed by
//! column name plus the ordered header, so the cell formatting, CSV quoting
//! and XLSX cell typing live here once (CLEANUP-REVIEW 2.8 / R-10).
//!
//! No spreadsheet formula-injection guard is applied (a cell starting with
//! `=`, `+`, `-` or `@` is written as-is); neither former copy had one, and
//! adding it changes the exported bytes, so it is a separate decision.

use serde_json::Value;

fn cell_to_csv_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
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

/// Renders `rows` (each a JSON object keyed by column name) as CSV text,
/// `header` first. Bytes, not `String` — the caller uploads this directly.
pub fn render_csv(header: &[String], rows: &[Value]) -> Vec<u8> {
    let mut out = csv_header_line(header);
    out.push('\n');
    for row in rows {
        out.push_str(&csv_line(header, row));
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
    header
        .iter()
        .map(|col| csv_escape(&cell_to_csv_string(row.get(col).unwrap_or(&Value::Null))))
        .collect::<Vec<_>>()
        .join(",")
}

fn write_xlsx_cell(
    worksheet: &mut rust_xlsxwriter::Worksheet,
    row: u32,
    col: u16,
    value: &Value,
) -> Result<(), rust_xlsxwriter::XlsxError> {
    match value {
        Value::Null => Ok(()),
        Value::Bool(b) => worksheet.write_boolean(row, col, *b).map(|_| ()),
        Value::Number(n) => match n.as_f64() {
            Some(f) => worksheet.write_number(row, col, f).map(|_| ()),
            None => worksheet.write_string(row, col, n.to_string()).map(|_| ()),
        },
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
            write_xlsx_cell(worksheet, (row_idx + 1) as u32, col as u16, cell)
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
    fn csv_escapes_commas_and_quotes() {
        let header = vec!["a".to_string(), "b".to_string()];
        let rows = vec![serde_json::json!({"a": "x,y", "b": "he said \"hi\""})];
        let csv = String::from_utf8(render_csv(&header, &rows)).unwrap();
        assert_eq!(csv, "a,b\n\"x,y\",\"he said \"\"hi\"\"\"\n");
    }

    #[test]
    fn csv_missing_column_renders_empty() {
        let header = vec!["a".to_string(), "b".to_string()];
        let rows = vec![serde_json::json!({"a": "only-a"})];
        let csv = String::from_utf8(render_csv(&header, &rows)).unwrap();
        assert_eq!(csv, "a,b\nonly-a,\n");
    }

    #[test]
    fn csv_line_and_header_match_render_csv() {
        let header = vec!["a".to_string(), "b,c".to_string()];
        let row = serde_json::json!({"a": true, "b,c": 1.5});
        assert_eq!(csv_header_line(&header), "a,\"b,c\"");
        assert_eq!(csv_line(&header, &row), "true,1.5");
        let csv = String::from_utf8(render_csv(&header, std::slice::from_ref(&row))).unwrap();
        assert_eq!(csv, "a,\"b,c\"\ntrue,1.5\n");
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
