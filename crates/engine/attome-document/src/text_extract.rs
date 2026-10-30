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
//!
//! **Pages (A25-T6).** A PDF's text keeps its pages: they are separated by
//! [`PAGE_BREAK`] (a form feed), so search can open a passage at its page
//! ([`pages`]). A content stream is placed on the page whose `/Contents`
//! names it, pages in the order their objects appear in the file. A PDF
//! whose page objects sit inside compressed object streams has no visible
//! page objects; there each content stream that shows text counts as a page.
//! Other formats are one page. XLSX gives its cell strings (shared and
//! inline); an email (`.eml`) gives its subject, people, date, attachment
//! names and body, read with `mail-parser`.

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
/// A25-T6: separates the pages of extracted text.
pub const PAGE_BREAK: char = '\u{c}';
/// The most worksheets of an XLSX read.
const MAX_SHEETS: usize = 64;
/// How far before a `stream` keyword its object header is looked for.
const OBJECT_HEADER_WINDOW: usize = 4096;

/// The formats text is extracted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextFormat {
    Plain,
    Docx,
    Pdf,
    /// A25-T6.
    Xlsx,
    /// A25-T6: an RFC 822 message (`.eml`).
    Email,
}

impl TextFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "text",
            Self::Docx => "docx",
            Self::Pdf => "pdf",
            Self::Xlsx => "xlsx",
            Self::Email => "email",
        }
    }
}

/// The pages of extracted text, first page first; text without page breaks
/// is one page. Pure.
pub fn pages(text: &str) -> Vec<&str> {
    text.split(PAGE_BREAK).collect()
}

/// The format of a file, from its sniffed content type first and its name
/// second; `None` for anything else. Pure.
pub fn format_of(content_type: &str, filename: &str) -> Option<TextFormat> {
    let content_type = content_type.split(';').next().unwrap_or_default().trim();
    let extension = filename
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    // A message sniffs as plain text; read raw, its encoded parts are noise.
    if extension == "eml" {
        return Some(TextFormat::Email);
    }
    match content_type {
        "application/pdf" => return Some(TextFormat::Pdf),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            return Some(TextFormat::Docx);
        }
        "text/plain" | "text/csv" | "text/markdown" => return Some(TextFormat::Plain),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => {
            return Some(TextFormat::Xlsx);
        }
        "message/rfc822" => return Some(TextFormat::Email),
        _ => {}
    }
    match extension.as_str() {
        "pdf" => Some(TextFormat::Pdf),
        "docx" => Some(TextFormat::Docx),
        "xlsx" => Some(TextFormat::Xlsx),
        "eml" => Some(TextFormat::Email),
        "txt" | "csv" | "md" => Some(TextFormat::Plain),
        _ => None,
    }
}

/// The text of a file, or `None` when it holds none that can be read. Pages
/// stay separated by [`PAGE_BREAK`]. Pure.
pub fn extract(format: TextFormat, bytes: &[u8]) -> Option<String> {
    let text = match format {
        TextFormat::Plain => String::from_utf8_lossy(bytes).into_owned(),
        TextFormat::Docx => docx_text(bytes)?,
        TextFormat::Pdf => pdf_text(bytes),
        TextFormat::Xlsx => xlsx_text(bytes)?,
        TextFormat::Email => email_text(bytes)?,
    };
    let text = tidy_pages(&text);
    (!text.is_empty()).then(|| truncate_chars(&text, MAX_TEXT_CHARS))
}

/// [`tidy`] on each page, keeping empty pages inside the text (so later
/// page numbers stay right) and dropping the empty ones at its end; empty
/// when no page holds text.
fn tidy_pages(text: &str) -> String {
    let pages: Vec<String> = text.split(PAGE_BREAK).map(tidy).collect();
    if pages.iter().all(String::is_empty) {
        return String::new();
    }
    let joined = pages.join(&PAGE_BREAK.to_string());
    joined.trim_end_matches(PAGE_BREAK).to_owned()
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

/// The text of every `<t>` element of a SpreadsheetML part, a line per
/// `line_tag` element. Pure.
fn sheet_strings(xml: &[u8], line_tag: &[u8], out: &mut String) {
    let mut reader = quick_xml::Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut in_text = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.local_name().as_ref() == b"t" => in_text = true,
            Ok(Event::End(e)) => {
                let name = e.local_name();
                if name.as_ref() == b"t" {
                    in_text = false;
                } else if name.as_ref() == line_tag {
                    out.push('\n');
                }
            }
            Ok(Event::Text(t)) if in_text => {
                if let Ok(text) = t.decode() {
                    out.push_str(&text);
                }
            }
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
}

/// A25-T6: the text of an XLSX: its shared strings, a line each, then the
/// inline strings of its worksheets, a line per row. Numbers and formulas
/// are left out. `None` when it is not a readable workbook. Pure.
pub fn xlsx_text(bytes: &[u8]) -> Option<String> {
    let shared = zip_member(bytes, "xl/sharedStrings.xml");
    let first_sheet = zip_member(bytes, "xl/worksheets/sheet1.xml");
    if shared.is_none() && first_sheet.is_none() {
        return None;
    }
    let mut out = String::new();
    if let Some(xml) = shared {
        sheet_strings(&xml, b"si", &mut out);
    }
    let sheets = std::iter::once(first_sheet)
        .chain((2..=MAX_SHEETS).map(|n| zip_member(bytes, &format!("xl/worksheets/sheet{n}.xml"))));
    for sheet in sheets {
        let Some(xml) = sheet else { break };
        sheet_strings(&xml, b"row", &mut out);
    }
    Some(out)
}

/// A25-T6: the text of an email: its subject, sender, recipients, date and
/// attachment names, a line each, then its body (an HTML-only body read as
/// text). `None` when it does not parse. Pure.
pub fn email_text(bytes: &[u8]) -> Option<String> {
    let message = mail_parser::MessageParser::default().parse(bytes)?;
    let people = |list: Option<&mail_parser::Address>| -> String {
        list.map(|a| {
            a.iter()
                .map(|p| match (p.name(), p.address()) {
                    (Some(name), Some(address)) => format!("{name} <{address}>"),
                    (None, Some(address)) => address.to_owned(),
                    (Some(name), None) => name.to_owned(),
                    (None, None) => String::new(),
                })
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
    };
    let attachments: Vec<String> = message
        .attachments()
        .filter_map(|part| part.attachment_name().map(str::to_owned))
        .collect();
    let mut lines: Vec<String> = Vec::new();
    for (label, value) in [
        ("Subject", message.subject().unwrap_or_default().to_owned()),
        ("From", people(message.from())),
        ("To", people(message.to())),
        ("Cc", people(message.cc())),
        (
            "Date",
            message.date().map(|d| d.to_rfc3339()).unwrap_or_default(),
        ),
        ("Attachments", attachments.join(", ")),
    ] {
        if !value.trim().is_empty() {
            lines.push(format!("{label}: {value}"));
        }
    }
    if let Some(body) = message.body_text(0) {
        lines.push(String::new());
        lines.push(body.into_owned());
    }
    Some(lines.join("\n"))
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// The decimal number that ends just before `end` in `bytes` (spaces before
/// `end` skipped), with the index where it starts. Pure.
fn number_before(bytes: &[u8], end: usize) -> Option<(u32, usize)> {
    let mut i = end;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    let digits_end = i;
    while i > 0 && bytes[i - 1].is_ascii_digit() {
        i -= 1;
    }
    if i == digits_end {
        return None;
    }
    let n = std::str::from_utf8(&bytes[i..digits_end])
        .ok()?
        .parse()
        .ok()?;
    Some((n, i))
}

/// The object number of an `N G obj` header whose `obj` keyword starts at
/// `at`. Pure.
fn object_header_at(bytes: &[u8], at: usize) -> Option<u32> {
    if at >= 3 && &bytes[at - 3..at] == b"end" {
        return None;
    }
    let (_generation, generation_at) = number_before(bytes, at)?;
    let (number, _) = number_before(bytes, generation_at)?;
    Some(number)
}

/// The object a stream starting at `stream_at` belongs to: the nearest
/// `N G obj` header before it. Pure.
fn stream_object(bytes: &[u8], stream_at: usize) -> Option<u32> {
    let from = stream_at.saturating_sub(OBJECT_HEADER_WINDOW);
    let mut at = stream_at;
    while let Some(found) = bytes[from..at].windows(3).rposition(|w| w == b"obj") {
        let found = from + found;
        if let Some(number) = object_header_at(bytes, found) {
            return Some(number);
        }
        at = found;
    }
    None
}

/// The objects an indirect reference list names: `N G R` triples, as in
/// `/Contents 12 0 R` or `/Contents [12 0 R 13 0 R]`. Pure.
fn references(text: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(r) = text[i..].iter().position(|&b| b == b'R') {
        let at = i + r;
        if let Some((_, generation_at)) = number_before(text, at)
            && let Some((number, _)) = number_before(text, generation_at)
        {
            out.push(number);
        }
        i = at + 1;
    }
    out
}

/// The content stream objects of each page object, pages in file order.
/// Empty when the file shows no page objects (they may sit in compressed
/// object streams). Pure.
fn page_contents(bytes: &[u8]) -> Vec<Vec<u32>> {
    let mut pages = Vec::new();
    let mut at = 0;
    while let Some(found) = find(bytes, b"obj", at) {
        at = found + 3;
        if object_header_at(bytes, found).is_none() {
            continue;
        }
        let end = find(bytes, b"endobj", at).unwrap_or(bytes.len());
        let body = &bytes[at..end.min(at + OBJECT_HEADER_WINDOW)];
        // `/Type /Page`, not `/Type /Pages`.
        let is_page = [b"/Type /Page".as_slice(), b"/Type/Page".as_slice()]
            .iter()
            .any(|key| {
                find(body, key, 0).is_some_and(|k| {
                    body.get(k + key.len())
                        .is_none_or(|b| !b.is_ascii_alphanumeric())
                })
            });
        if !is_page {
            continue;
        }
        let Some(contents) = find(body, b"/Contents", 0) else {
            pages.push(Vec::new());
            continue;
        };
        let rest = &body[contents + 9..];
        let start = rest
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(0);
        let list = if rest.get(start) == Some(&b'[') {
            let close = rest[start..]
                .iter()
                .position(|&b| b == b']')
                .map_or(rest.len(), |p| start + p);
            &rest[start..close]
        } else {
            let close = rest[start..]
                .iter()
                .position(|&b| b == b'R')
                .map_or(rest.len(), |p| start + p + 1);
            &rest[start..close]
        };
        pages.push(references(list));
    }
    pages
}

/// The text of a PDF's content streams: literal strings shown between `BT`
/// and `ET`, a line per text block, pages separated by [`PAGE_BREAK`]. Pure.
pub fn pdf_text(bytes: &[u8]) -> String {
    let pages = page_contents(bytes);
    let page_of: std::collections::HashMap<u32, usize> = pages
        .iter()
        .enumerate()
        .flat_map(|(page, objects)| objects.iter().map(move |o| (*o, page)))
        .collect();
    // With page objects, a page's text goes in its slot; a stream no page
    // names (a form drawn on a page) joins the last page seen. Without them,
    // each stream that shows text is a page of its own.
    let mut by_page: Vec<String> = vec![String::new(); pages.len()];
    let mut loose: Vec<String> = Vec::new();
    let mut last_page = 0;
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
        let mut text = String::new();
        content_text(&content, &mut text);
        if !text.trim().is_empty() {
            if by_page.is_empty() {
                loose.push(text);
            } else {
                if let Some(page) = stream_object(bytes, start).and_then(|o| page_of.get(&o)) {
                    last_page = *page;
                }
                by_page[last_page].push_str(&text);
            }
        }
        at = end + 9;
    }
    let pages = if by_page.is_empty() { loose } else { by_page };
    pages.join(&PAGE_BREAK.to_string())
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

    /// A25-T6: each content stream lands on the page whose `/Contents`
    /// names it, whatever order the streams sit in the file.
    #[test]
    fn document_text_keeps_pdf_pages() {
        let pdf = b"%PDF-1.4\n\
            1 0 obj << /Type /Pages /Kids [2 0 R 3 0 R] /Count 2 >> endobj\n\
            2 0 obj << /Type /Page /Parent 1 0 R /Contents 5 0 R >> endobj\n\
            3 0 obj << /Type /Page /Parent 1 0 R /Contents [4 0 R] >> endobj\n\
            4 0 obj << /Length 30 >>\nstream\nBT (Renewal terms) Tj ET\nendstream\nendobj\n\
            5 0 obj << /Length 30 >>\nstream\nBT (Service agreement) Tj ET\nendstream\nendobj\n\
            %%EOF";
        let text = extract(TextFormat::Pdf, pdf).expect("text");
        assert_eq!(pages(&text), vec!["Service agreement", "Renewal terms"]);
        // A page with no text keeps the next page's number.
        let gap = b"%PDF-1.4\n\
            2 0 obj << /Type /Page /Contents 5 0 R >> endobj\n\
            3 0 obj << /Type /Page /Contents 4 0 R >> endobj\n\
            4 0 obj << /Length 9 >>\nstream\nBT (Two) Tj ET\nendstream\nendobj\n\
            %%EOF";
        assert_eq!(
            pages(&extract(TextFormat::Pdf, gap).expect("text")),
            vec!["", "Two"]
        );
        // No page objects: each stream showing text is a page.
        let loose = b"%PDF-1.4\n\
            1 0 obj << >>\nstream\nBT (One) Tj ET\nendstream\nendobj\n\
            2 0 obj << >>\nstream\nq 1 0 0 1 0 0 cm Q\nendstream\nendobj\n\
            3 0 obj << >>\nstream\nBT (Two) Tj ET\nendstream\nendobj\n";
        assert_eq!(
            pages(&extract(TextFormat::Pdf, loose).expect("text")),
            vec!["One", "Two"]
        );
        assert_eq!(pages("one page"), vec!["one page"]);
    }

    #[test]
    fn document_text_reads_xlsx_strings() {
        let shared = r#"<?xml version="1.0"?><sst xmlns="x"><si><t>Customer</t></si><si><r><t>Acme </t></r><r><t>Trading</t></r></si><si><t>R&amp;D</t></si></sst>"#;
        let workbook = zip("xl/sharedStrings.xml", shared.as_bytes(), true);
        assert_eq!(
            extract(TextFormat::Xlsx, &workbook).as_deref(),
            Some("Customer\nAcme Trading\nR&D")
        );
        let inline = r#"<worksheet><sheetData><row><c t="inlineStr"><is><t>Due</t></is></c><c><v>42</v></c></row></sheetData></worksheet>"#;
        let sheet = zip("xl/worksheets/sheet1.xml", inline.as_bytes(), false);
        assert_eq!(extract(TextFormat::Xlsx, &sheet).as_deref(), Some("Due"));
        assert_eq!(extract(TextFormat::Xlsx, b"not a zip"), None);
        assert_eq!(
            format_of(
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "a"
            ),
            Some(TextFormat::Xlsx)
        );
    }

    #[test]
    fn document_text_reads_email() {
        let eml = "From: Sara Ali <sara@example.com>\r\n\
            To: ops@example.com\r\n\
            Subject: Renewal quote\r\n\
            Date: Thu, 29 Oct 2026 10:00:00 +0300\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \r\n\
            Please find the revised price attached.\r\n";
        let text = extract(TextFormat::Email, eml.as_bytes()).expect("text");
        assert!(text.starts_with("Subject: Renewal quote\n"), "{text}");
        assert!(text.contains("From: Sara Ali <sara@example.com>"), "{text}");
        assert!(text.contains("To: ops@example.com"), "{text}");
        assert!(
            text.ends_with("Please find the revised price attached."),
            "{text}"
        );
        // A message is read as one even when it sniffs as plain text.
        assert_eq!(
            format_of("text/plain", "Quote.EML"),
            Some(TextFormat::Email)
        );
        assert_eq!(format_of("message/rfc822", "x"), Some(TextFormat::Email));
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
