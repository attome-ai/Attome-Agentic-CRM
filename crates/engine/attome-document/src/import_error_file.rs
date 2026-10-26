//! A23-T9: an import's row errors as a file the person can fix and send
//! back.
//!
//! The file is CSV in UTF-8 with a byte order mark (so Excel opens Arabic
//! correctly): `attome_row` (the row's number in the import), the file's own
//! columns in their original order (kept in `counts.columns` when the file
//! was staged), `error` (each problem's message in the reader's language)
//! and an empty `fix` column. Rows come from `import_stage` with status
//! `invalid`, in row order, [`PAGE`] at a time, so a large import is never
//! held in memory.
//!
//! A message comes from its `message_key` (`import.error.<code>`): a
//! `ui_text` label of that key in the reader's locale (or the deployment's)
//! when an administrator wrote one, else the built-in English or Arabic
//! text ([`MESSAGES`]), else the key itself.
//!
//! Uploading the fixed file again with the option `source_job_id` keeps
//! that job's id in the new job's `counts.source_job_id`; its rows carry
//! their `attome_row`, which maps each one back to the row it fixes.

use attome_core::EngineState;
use attome_core::label_store::LabelSnapshot;
use attome_types::AppError;
use bytes::Bytes;
use serde_json::{Map, Value};
use uuid::Uuid;

/// Invalid rows read per page.
pub const PAGE: i64 = 1_000;

/// The byte order mark Excel needs to read the file as UTF-8.
pub const BOM: &str = "\u{feff}";

/// The column that numbers each row.
pub const ROW_COLUMN: &str = "attome_row";

/// Built-in messages by error code: English, Arabic.
pub const MESSAGES: &[(&str, &str, &str)] = &[
    (
        "invalid",
        "The value is not valid for this field.",
        "القيمة غير صالحة لهذا الحقل.",
    ),
    ("invalid_bool", "Use yes or no.", "استخدم نعم أو لا."),
    (
        "invalid_number",
        "The value is not a number.",
        "القيمة ليست رقمًا.",
    ),
    (
        "invalid_choice",
        "The value is not one of the allowed choices.",
        "القيمة ليست من الخيارات المسموح بها.",
    ),
    (
        "invalid_id",
        "The id is not a valid record id.",
        "المعرّف ليس معرّف سجل صالحًا.",
    ),
    (
        "not_importable",
        "This field cannot be imported.",
        "لا يمكن استيراد هذا الحقل.",
    ),
    ("required", "This field is required.", "هذا الحقل مطلوب."),
    (
        "too_long",
        "The value is too long.",
        "القيمة أطول من المسموح.",
    ),
    (
        "unknown_field",
        "There is no such field.",
        "لا يوجد حقل بهذا الاسم.",
    ),
    (
        "missing_lookup",
        "No record has this value.",
        "لا يوجد سجل بهذه القيمة.",
    ),
    (
        "ambiguous_lookup",
        "More than one record has this value.",
        "يوجد أكثر من سجل بهذه القيمة.",
    ),
    (
        "ambiguous_match",
        "More than one existing record matches this row.",
        "يطابق هذا الصف أكثر من سجل موجود.",
    ),
    (
        "rule_violation",
        "A business rule refused the row.",
        "رفضت قاعدة عمل هذا الصف.",
    ),
    (
        "forbidden",
        "You may not change this record.",
        "لا يحق لك تعديل هذا السجل.",
    ),
    (
        "not_found",
        "The record no longer exists.",
        "لم يعد السجل موجودًا.",
    ),
    (
        "changed_since_validation",
        "The record changed after the import was checked.",
        "تغيّر السجل بعد التحقق من الاستيراد.",
    ),
    (
        "duplicate_detected",
        "The row duplicates an existing record.",
        "الصف مكرر لسجل موجود.",
    ),
    (
        "conflict",
        "The row conflicts with another change.",
        "يتعارض الصف مع تغيير آخر.",
    ),
];

/// The message for `message_key` in `locale` (see the module doc).
pub fn message(
    labels: &LabelSnapshot,
    message_key: &str,
    locale: &str,
    deployment_locale: &str,
) -> String {
    if let Some(row) = labels.resolve("ui_text", message_key, Some(locale), deployment_locale) {
        return row.display_name.clone();
    }
    let code = message_key
        .strip_prefix("import.error.")
        .unwrap_or(message_key);
    match MESSAGES.iter().find(|(c, _, _)| *c == code) {
        Some((_, _, ar)) if locale == "ar" => (*ar).to_owned(),
        Some((_, en, _)) => (*en).to_owned(),
        None => message_key.to_owned(),
    }
}

/// One CSV field, quoted when it has to be. Pure.
fn field(text: &str) -> String {
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_owned()
    }
}

/// The header line, BOM first. Pure.
pub fn header(columns: &[String]) -> String {
    let mut names = vec![ROW_COLUMN.to_owned()];
    names.extend(columns.iter().map(|c| field(c)));
    names.push("error".into());
    names.push("fix".into());
    format!("{BOM}{}\r\n", names.join(","))
}

/// One staged row's line: its number, its original cells, its errors. Pure.
pub fn line(row_no: i32, raw: &Map<String, Value>, columns: &[String], error: &str) -> String {
    let mut cells = vec![row_no.to_string()];
    for column in columns {
        let text = match raw.get(column) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        };
        cells.push(field(&text));
    }
    cells.push(field(error));
    cells.push(String::new());
    format!("{}\r\n", cells.join(","))
}

/// A row's error JSON as one line of messages, `field: message; ...`.
pub fn render_errors(
    error: Option<&Value>,
    labels: &LabelSnapshot,
    locale: &str,
    deployment_locale: &str,
) -> String {
    error
        .and_then(|e| e.get("errors"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|e| {
            let key = e.get("message_key").and_then(Value::as_str).unwrap_or("");
            let text = message(labels, key, locale, deployment_locale);
            match e
                .get("field")
                .and_then(Value::as_str)
                .filter(|f| !f.is_empty())
            {
                Some(field) => format!("{field}: {text}"),
                None => text,
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The job's column order: `counts.columns` when staging kept it, else the
/// first invalid row's keys.
async fn columns_of(state: &EngineState, job_id: Uuid) -> Result<Vec<String>, AppError> {
    let kept: Option<Value> =
        sqlx::query_scalar("SELECT counts->'columns' FROM import_job WHERE id = $1")
            .bind(job_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    if let Some(columns) = kept.and_then(|c| serde_json::from_value::<Vec<String>>(c).ok()) {
        return Ok(columns);
    }
    let first: Option<Value> = sqlx::query_scalar(
        "SELECT raw FROM import_stage WHERE job_id = $1 AND status = 'invalid' ORDER BY row_no LIMIT 1",
    )
    .bind(job_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(first
        .and_then(|r| r.as_object().map(|o| o.keys().cloned().collect()))
        .unwrap_or_default())
}

/// The file as a stream of chunks: the header, then each page of invalid
/// rows. A page that fails to load ends the stream with the error.
pub async fn stream(
    state: EngineState,
    job_id: Uuid,
    locale: String,
) -> Result<impl futures_util::Stream<Item = Result<Bytes, AppError>> + Send + 'static, AppError> {
    let columns = columns_of(&state, job_id).await?;
    let first = Bytes::from(header(&columns));
    let deployment_locale = state.deployment_locale();
    let pages = futures_util::stream::unfold(Some(0_i32), move |after| {
        let state = state.clone();
        let columns = columns.clone();
        let locale = locale.clone();
        let deployment_locale = deployment_locale.clone();
        async move {
            let after = after?;
            let rows: Result<Vec<(i32, Value, Option<Value>)>, AppError> = sqlx::query_as(
                "SELECT row_no, raw, error FROM import_stage \
                  WHERE job_id = $1 AND status = 'invalid' AND row_no > $2 \
                  ORDER BY row_no LIMIT $3",
            )
            .bind(job_id)
            .bind(after)
            .bind(PAGE)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal);
            match rows {
                Err(e) => Some((Err(e), None)),
                Ok(rows) if rows.is_empty() => None,
                Ok(rows) => {
                    let labels = state.labels.load();
                    let mut chunk = String::new();
                    let mut last = after;
                    for (row_no, raw, error) in &rows {
                        let raw = raw.as_object().cloned().unwrap_or_default();
                        let text =
                            render_errors(error.as_ref(), &labels, &locale, &deployment_locale);
                        chunk.push_str(&line(*row_no, &raw, &columns, &text));
                        last = *row_no;
                    }
                    Some((Ok(Bytes::from(chunk)), Some(last)))
                }
            }
        }
    });
    Ok(futures_util::StreamExt::chain(
        futures_util::stream::once(async move { Ok(first) }),
        pages,
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn error_file_has_bom_and_arabic_message() {
        let labels = LabelSnapshot::default();
        let columns = vec!["title".to_owned(), "level".to_owned()];
        let head = header(&columns);
        assert!(head.starts_with(BOM), "Excel needs the byte order mark");
        assert_eq!(head, format!("{BOM}attome_row,title,level,error,fix\r\n"));

        let error = json!({"errors": [
            {"field": "level", "code": "invalid_number", "message_key": "import.error.invalid_number"}
        ]});
        let text = render_errors(Some(&error), &labels, "ar", "en");
        assert_eq!(text, "level: القيمة ليست رقمًا.");
        let raw = json!({"title": "شركة، الرياض", "level": "x"});
        let row = line(7, raw.as_object().unwrap(), &columns, &text);
        assert_eq!(row, "7,شركة، الرياض,x,level: القيمة ليست رقمًا.,\r\n");
        assert_eq!(
            render_errors(Some(&error), &labels, "en", "en"),
            "level: The value is not a number."
        );
    }

    #[test]
    fn a_field_with_a_comma_or_quote_is_quoted() {
        assert_eq!(field("a,b"), "\"a,b\"");
        assert_eq!(field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(field("plain"), "plain");
        assert_eq!(
            message(&LabelSnapshot::default(), "import.error.nope", "ar", "en"),
            "import.error.nope"
        );
    }

    #[test]
    fn every_validation_and_apply_code_has_both_languages() {
        for (code, en, ar) in MESSAGES {
            assert!(!en.is_empty() && !ar.is_empty(), "{code}");
        }
    }
}
