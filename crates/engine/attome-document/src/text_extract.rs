//! K1-T4: document text for global search.
//!
//! Once an upload's scan clears it (K2), `EngineJob::DocumentTextExtract`
//! reads the stored file and extracts its text — plain text, DOCX, and PDFs
//! whose text is stored as ordinary strings — into `document_text`, keyed by
//! the file's storage key. The search projection of an `attome_document`
//! (`attome_search::corpus::project_record`) appends the text of the file it
//! names, so a document is found by its contents with exactly the
//! permissions of the document record itself; nothing here decides who may
//! see it.
//!
//! **Ordering.** The text is committed first, then every live document
//! naming the file is re-announced on the change feed. A document created
//! before that announcement is re-indexed by it; one created after is
//! projected with the text already present. Either way it ends up indexed.
//!
//! **Pure Rust, no new parser.** DOCX is a ZIP of XML: a small central
//! directory reader plus `flate2` and `quick-xml`, both already in the build.
//! PDF text is read from content streams (`FlateDecode` or raw) between
//! `BT`/`ET`, literal strings only: a PDF that stores its text as glyph ids
//! (most Arabic PDFs and many generated with embedded subset fonts) yields
//! nothing rather than garbage, and is still found by its name.
//!
//! Every limit is explicit: files over [`MAX_FILE_BYTES`] are skipped, a ZIP
//! member inflates to at most [`MAX_INFLATED_BYTES`], and the stored text is
//! cut at [`MAX_TEXT_CHARS`].

use std::io::Read;

use attome_core::EngineState;
use attome_types::AppError;
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use quick_xml::events::Event;
use uuid::Uuid;

/// The largest file whose text is extracted.
pub const MAX_FILE_BYTES: u64 = 25 * 1024 * 1024;
/// The most one ZIP member or PDF stream may inflate to.
pub const MAX_INFLATED_BYTES: u64 = 64 * 1024 * 1024;
/// The most text kept per file.
pub const MAX_TEXT_CHARS: usize = 1_000_000;

/// The formats text is extracted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextFormat {
    Plain,
    Docx,
    Pdf,
}

impl TextFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "text",
            Self::Docx => "docx",
            Self::Pdf => "pdf",
        }
    }
}

/// The format of a file, from its sniffed content type first and its name
/// second; `None` for anything else. Pure.
pub fn format_of(content_type: &str, filename: &str) -> Option<TextFormat> {
    let content_type = content_type.split(';').next().unwrap_or_default().trim();
    let extension = filename
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match content_type {
        "application/pdf" => return Some(TextFormat::Pdf),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            return Some(TextFormat::Docx);
        }
        "text/plain" | "text/csv" | "text/markdown" => return Some(TextFormat::Plain),
        _ => {}
    }
    match extension.as_str() {
        "pdf" => Some(TextFormat::Pdf),
        "docx" => Some(TextFormat::Docx),
        "txt" | "csv" | "md" => Some(TextFormat::Plain),
        _ => None,
    }
}

/// The text of a file, or `None` when it holds none that can be read. Pure.
pub fn extract(format: TextFormat, bytes: &[u8]) -> Option<String> {
    let text = match format {
        TextFormat::Plain => String::from_utf8_lossy(bytes).into_owned(),
        TextFormat::Docx => docx_text(bytes)?,
        TextFormat::Pdf => pdf_text(bytes),
    };
    let text = tidy(&text);
    (!text.is_empty()).then(|| truncate_chars(&text, MAX_TEXT_CHARS))
}

fn tidy(text: &str) -> String {
    text.lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn truncate_chars(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((end, _)) => text[..end].to_owned(),
        None => text.to_owned(),
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<usize> {
    b.get(at..at + 2)
        .map(|s| usize::from(u16::from_le_bytes([s[0], s[1]])))
}

fn u32_at(b: &[u8], at: usize) -> Option<usize> {
    b.get(at..at + 4)
        .and_then(|s| usize::try_from(u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok())
}

/// One member of a ZIP archive, inflated. Stored and deflated members only;
/// anything else (encrypted, ZIP64, other methods) is `None`. Pure.
pub fn zip_member(archive: &[u8], name: &str) -> Option<Vec<u8>> {
    // End of central directory: the last `PK\x05\x06` within the final
    // 64 KiB (its comment is at most 65,535 bytes).
    let floor = archive.len().saturating_sub(22 + 65_535);
    let eocd = (floor..=archive.len().saturating_sub(22))
        .rev()
        .find(|&i| archive.get(i..i + 4) == Some(b"PK\x05\x06"))?;
    let entries = u16_at(archive, eocd + 10)?;
    let mut at = u32_at(archive, eocd + 16)?;
    for _ in 0..entries {
        if archive.get(at..at + 4) != Some(b"PK\x01\x02") {
            return None;
        }
        let method = u16_at(archive, at + 10)?;
        let compressed = u32_at(archive, at + 20)?;
        let name_len = u16_at(archive, at + 28)?;
        let extra_len = u16_at(archive, at + 30)?;
        let comment_len = u16_at(archive, at + 32)?;
        let local = u32_at(archive, at + 42)?;
        let member = archive.get(at + 46..at + 46 + name_len)?;
        if member == name.as_bytes() {
            if archive.get(local..local + 4) != Some(b"PK\x03\x04") {
                return None;
            }
            let data_at = local + 30 + u16_at(archive, local + 26)? + u16_at(archive, local + 28)?;
            let data = archive.get(data_at..data_at.checked_add(compressed)?)?;
            return match method {
                0 => Some(data.to_vec()),
                8 => inflate(flate2::read::DeflateDecoder::new(data)),
                _ => None,
            };
        }
        at += 46 + name_len + extra_len + comment_len;
    }
    None
}

fn inflate(reader: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(MAX_INFLATED_BYTES).read_to_end(&mut out).ok()?;
    Some(out)
}

/// The text of a DOCX: its paragraphs, one per line. Pure.
pub fn docx_text(bytes: &[u8]) -> Option<String> {
    let xml = zip_member(bytes, "word/document.xml")?;
    let mut reader = quick_xml::Reader::from_reader(xml.as_slice());
    let mut buf = Vec::new();
    let mut out = String::new();
    let mut in_text = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.name().as_ref() == b"w:t" => in_text = true,
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"w:t" => in_text = false,
                b"w:p" => out.push('\n'),
                _ => {}
            },
            Ok(Event::Empty(e)) if matches!(e.name().as_ref(), b"w:tab" | b"w:br") => {
                out.push(' ');
            }
            Ok(Event::Text(t)) if in_text => {
                if let Ok(text) = t.decode() {
                    out.push_str(&text);
                }
            }
            // quick-xml reports `&amp;` and `&#x41;` as their own events.
            Ok(Event::GeneralRef(r)) if in_text => {
                if let Ok(Some(c)) = r.resolve_char_ref() {
                    out.push(c);
                } else if let Ok(name) = r.decode()
                    && let Some(text) = quick_xml::escape::resolve_predefined_entity(&name)
                {
                    out.push_str(text);
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    Some(out)
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// The text of a PDF's content streams: literal strings shown between `BT`
/// and `ET`, a line per text block. Pure.
pub fn pdf_text(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut at = 0;
    while let Some(start) = find(bytes, b"stream", at) {
        // `endstream` also contains `stream`; skip it.
        if start >= 3 && &bytes[start - 3..start] == b"end" {
            at = start + 6;
            continue;
        }
        let mut data_at = start + 6;
        if bytes.get(data_at) == Some(&b'\r') {
            data_at += 1;
        }
        if bytes.get(data_at) == Some(&b'\n') {
            data_at += 1;
        }
        let Some(end) = find(bytes, b"endstream", data_at) else {
            break;
        };
        let dict_from = start.saturating_sub(512);
        let dict = &bytes[dict_from..start];
        let raw = &bytes[data_at..end];
        let content = if find(dict, b"/FlateDecode", 0).is_some() {
            inflate(flate2::read::ZlibDecoder::new(raw)).unwrap_or_default()
        } else {
            raw.to_vec()
        };
        content_text(&content, &mut out);
        at = end + 9;
    }
    out
}

/// Appends the literal strings shown in one content stream. Pure.
fn content_text(content: &[u8], out: &mut String) {
    let mut in_text = false;
    let mut i = 0;
    while i < content.len() {
        let c = content[i];
        if !in_text {
            if content[i..].starts_with(b"BT") && is_delimited(content, i, 2) {
                in_text = true;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if content[i..].starts_with(b"ET") && is_delimited(content, i, 2) {
            in_text = false;
            out.push('\n');
            i += 2;
            continue;
        }
        if c == b'(' {
            let (text, next) = literal_string(content, i + 1);
            if text.chars().all(|ch| !ch.is_control() || ch == ' ') {
                out.push_str(&text);
            }
            i = next;
            continue;
        }
        // A text-positioning operator that starts a new line.
        if (content[i..].starts_with(b"T*") || content[i..].starts_with(b"TD"))
            && is_delimited(content, i, 2)
        {
            out.push(' ');
        }
        i += 1;
    }
}

fn is_delimited(content: &[u8], at: usize, len: usize) -> bool {
    let before = at == 0 || content[at - 1].is_ascii_whitespace();
    let after = content
        .get(at + len)
        .is_none_or(|b| b.is_ascii_whitespace() || *b == b'[' || *b == b'(');
    before && after
}

/// A PDF literal string from just after its `(`: balanced parentheses and
/// backslash escapes, Latin-1 bytes. Returns the text and the index after
/// its closing `)`. Pure.
fn literal_string(content: &[u8], mut i: usize) -> (String, usize) {
    let mut depth = 1;
    let mut text = String::new();
    while i < content.len() {
        let c = content[i];
        match c {
            b'\\' => {
                i += 1;
                match content.get(i) {
                    Some(b'n') => text.push('\n'),
                    Some(b'r') | Some(b't') => text.push(' '),
                    Some(d @ b'0'..=b'7') => {
                        let mut value = u32::from(d - b'0');
                        let mut digits = 1;
                        while digits < 3 {
                            match content.get(i + 1) {
                                Some(d @ b'0'..=b'7') => {
                                    value = value * 8 + u32::from(d - b'0');
                                    i += 1;
                                    digits += 1;
                                }
                                _ => break,
                            }
                        }
                        if let Some(ch) = char::from_u32(value) {
                            text.push(ch);
                        }
                    }
                    Some(&other) => text.push(char::from(other)),
                    None => {}
                }
            }
            b'(' => {
                depth += 1;
                text.push('(');
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return (text, i + 1);
                }
                text.push(')');
            }
            _ => text.push(char::from(c)),
        }
        i += 1;
    }
    (text, i)
}

/// W1-T7: the text of a stored file: what the upload scan already extracted
/// into `document_text`, else the file read and extracted now, its format
/// from the key's extension (`.docx`, `.pdf`, `.txt`, or `.html`/`.htm`
/// with the tags dropped). `None` when the file is missing, too large or
/// holds no readable text. Reads no permission: the caller has checked that
/// the record naming the file is readable.
pub async fn stored_file_text(
    state: &EngineState,
    file_key: &str,
) -> Result<Option<String>, AppError> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT content_text FROM document_text WHERE file_key = $1")
            .bind(file_key)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if stored.is_some() {
        return Ok(stored);
    }
    let lower = file_key.to_ascii_lowercase();
    let html = lower.ends_with(".html") || lower.ends_with(".htm");
    let format = if html {
        Some(TextFormat::Plain)
    } else {
        format_of("", &lower)
    };
    let Some(format) = format else {
        return Ok(None);
    };
    let path = ObjectPath::parse(file_key)
        .map_err(|e| AppError::internal(format!("invalid stored file key: {e}")))?;
    let object = match state.base.storage.store().get(&path).await {
        Ok(object) => object,
        Err(object_store::Error::NotFound { .. }) => return Ok(None),
        Err(e) => return Err(AppError::internal(e)),
    };
    if object.meta.size > MAX_FILE_BYTES {
        return Ok(None);
    }
    let bytes = object.bytes().await.map_err(AppError::internal)?;
    tokio::task::spawn_blocking(move || {
        let text = extract(format, &bytes)?;
        Some(if html { strip_tags(&text) } else { text })
    })
    .await
    .map_err(AppError::internal)
}

/// HTML with its tags dropped and the common entities read; a block tag
/// (paragraph, heading, list item, row, line break, division) ends a line.
/// Pure.
pub fn strip_tags(html: &str) -> String {
    const BLOCKS: &[&str] = &[
        "p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "br", "tr", "section",
    ];
    let mut out = String::with_capacity(html.len());
    let mut tag: Option<String> = None;
    for c in html.chars() {
        match (&mut tag, c) {
            (None, '<') => tag = Some(String::new()),
            (Some(name), '>') => {
                let lower = name.trim_start_matches('/').to_ascii_lowercase();
                let word = lower
                    .split(|c: char| c.is_whitespace() || c == '/')
                    .next()
                    .unwrap_or_default();
                out.push(if BLOCKS.contains(&word) { '\n' } else { ' ' });
                tag = None;
            }
            (Some(name), c) => name.push(c),
            (None, c) => out.push(c),
        }
    }
    let out = out
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    tidy(&out)
}

/// Worker for `EngineJob::DocumentTextExtract`: extracts a clean upload's
/// text into `document_text` and re-announces the documents that name it.
/// Idempotent; a file with no readable text, or too large, is skipped.
pub async fn process(state: &EngineState, session_id: Uuid) -> Result<(), AppError> {
    let db = &state.base.db;
    let row: Option<(Option<String>, Option<String>, String)> = sqlx::query_as(
        "SELECT final_key, actual_content_type, declared_filename FROM upload_session \
          WHERE id = $1 AND status = 'clean'",
    )
    .bind(session_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(final_key), content_type, filename)) = row else {
        return Ok(());
    };
    let Some(format) = format_of(content_type.as_deref().unwrap_or_default(), &filename) else {
        return Ok(());
    };
    let path = ObjectPath::parse(&final_key)
        .map_err(|e| AppError::internal(format!("invalid stored file key: {e}")))?;
    let object = match state.base.storage.store().get(&path).await {
        Ok(object) => object,
        Err(object_store::Error::NotFound { .. }) => return Ok(()),
        Err(e) => return Err(AppError::internal(e)),
    };
    if object.meta.size > MAX_FILE_BYTES {
        tracing::info!(%session_id, size = object.meta.size, "document text: file too large; not extracted");
        return Ok(());
    }
    let bytes = object.bytes().await.map_err(AppError::internal)?;
    let text = tokio::task::spawn_blocking(move || extract(format, &bytes))
        .await
        .map_err(AppError::internal)?;
    let Some(text) = text else {
        return Ok(());
    };

    sqlx::query(
        "INSERT INTO document_text (file_key, format, content_text) VALUES ($1, $2, $3) \
         ON CONFLICT (file_key) DO UPDATE \
            SET format = EXCLUDED.format, content_text = EXCLUDED.content_text, \
                extracted_at = NOW()",
    )
    .bind(&final_key)
    .bind(format.as_str())
    .bind(&text)
    .execute(db)
    .await
    .map_err(AppError::internal)?;

    // After the text is committed (see the module doc's ordering).
    let mut tx = attome_db::tx::begin(db).await?;
    let documents: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM attome_document WHERE file = $1 AND is_active = true")
            .bind(&final_key)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    for id in &documents {
        attome_core::change_feed::emit_tx(
            &mut tx,
            "attome_document",
            *id,
            attome_core::ChangeOperation::Update,
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    tracing::info!(%session_id, format = format.as_str(), documents = documents.len(), "document text extracted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A one-member ZIP, stored or deflated.
    fn zip(name: &str, data: &[u8], deflate: bool) -> Vec<u8> {
        let (method, body) = if deflate {
            let mut e =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(data).unwrap_or_default();
            (8u16, e.finish().unwrap_or_default())
        } else {
            (0u16, data.to_vec())
        };
        let size = u32::try_from(body.len()).unwrap_or_default();
        let raw = u32::try_from(data.len()).unwrap_or_default();
        let name_len = u16::try_from(name.len()).unwrap_or_default();
        let mut out = Vec::new();
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&[20, 0, 0, 0]);
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&raw.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&body);
        let central = u32::try_from(out.len()).unwrap_or_default();
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&raw.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        let central_len = u32::try_from(out.len()).unwrap_or_default() - central;
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        out.extend_from_slice(&central_len.to_le_bytes());
        out.extend_from_slice(&central.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    const DOCUMENT_XML: &str = r#"<?xml version="1.0"?><w:document xmlns:w="w"><w:body><w:p><w:r><w:t>Service</w:t></w:r><w:r><w:t xml:space="preserve"> agreement</w:t></w:r></w:p><w:p><w:r><w:t>Term &amp; renewal</w:t></w:r></w:p></w:body></w:document>"#;

    #[test]
    fn document_text_reads_docx_paragraphs_stored_or_deflated() {
        for deflate in [false, true] {
            let docx = zip("word/document.xml", DOCUMENT_XML.as_bytes(), deflate);
            assert_eq!(
                extract(TextFormat::Docx, &docx).as_deref(),
                Some("Service agreement\nTerm & renewal"),
                "deflate {deflate}"
            );
        }
        let other = zip("word/other.xml", DOCUMENT_XML.as_bytes(), false);
        assert_eq!(extract(TextFormat::Docx, &other), None);
        assert_eq!(extract(TextFormat::Docx, b"not a zip"), None);
    }

    #[test]
    fn document_text_reads_pdf_literal_strings() {
        let content =
            b"BT /F1 12 Tf 72 712 Td (Invoice \\(final\\)) Tj T* [(Total) -250 (due)] TJ ET";
        let raw = [
            b"%PDF-1.4\n1 0 obj << /Length 80 >>\nstream\n".as_slice(),
            content,
            b"\nendstream\nendobj\n",
        ]
        .concat();
        assert_eq!(
            extract(TextFormat::Pdf, &raw).as_deref(),
            Some("Invoice (final) Totaldue")
        );
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(content).unwrap_or_default();
        let compressed = [
            b"%PDF-1.4\n1 0 obj << /Filter /FlateDecode >>\nstream\r\n".as_slice(),
            &z.finish().unwrap_or_default(),
            b"\r\nendstream\nendobj\n",
        ]
        .concat();
        assert_eq!(
            extract(TextFormat::Pdf, &compressed).as_deref(),
            Some("Invoice (final) Totaldue")
        );
        assert_eq!(extract(TextFormat::Pdf, b"%PDF-1.4\n%%EOF"), None);
    }

    #[test]
    fn document_text_formats_and_limits() {
        assert_eq!(format_of("application/pdf", "x.bin"), Some(TextFormat::Pdf));
        assert_eq!(
            format_of("application/zip", "Contract.DOCX"),
            Some(TextFormat::Docx)
        );
        assert_eq!(
            format_of("text/plain; charset=utf-8", "a"),
            Some(TextFormat::Plain)
        );
        assert_eq!(format_of("image/png", "scan.png"), None);
        assert_eq!(
            extract(TextFormat::Plain, "  a   b \n\n c ".as_bytes()).as_deref(),
            Some("a b\nc")
        );
        assert_eq!(extract(TextFormat::Plain, b"   \n "), None);
        assert_eq!(truncate_chars("عقد خدمة", 3), "عقد");
    }
}
