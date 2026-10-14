//! `document.extract` (roadmap N21-T2): typed fields from an invoice or a
//! receipt, each with a confidence, and the fields a person must check.
//!
//! The input is the document's text (what `OcrClient::read_text` read from a
//! scan, or text pasted from a PDF) and, when the document carries one, the
//! payload of its ZATCA e-invoice QR code. The QR is exact: its TLV fields
//! (seller, VAT number, time, total, VAT) are decoded and carry confidence 1.
//! Everything else is found by rules over the text, in English and Arabic
//! (Arabic-Indic digits included): a single candidate scores 0.8, several
//! different ones 0.5. A field below [`REVIEW_THRESHOLD`] is listed in
//! `needs_review`; a field the QR and the text disagree on is listed too,
//! and the QR value wins.
//!
//! Local and free: no model call, nothing written. An agent that wants the
//! review as a task creates one with the write actions, under their approval
//! rules.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const DOCUMENT_EXTRACT: &str = "document.extract";
/// A field under this confidence needs a person.
pub const REVIEW_THRESHOLD: f64 = 0.75;
/// The longest text read.
pub const MAX_TEXT_CHARS: usize = 50_000;
/// The longest QR payload decoded.
pub const MAX_QR_CHARS: usize = 4_000;

/// One extracted field.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Field {
    pub value: String,
    pub confidence: f64,
    /// `qr` or `text`.
    pub source: &'static str,
}

/// The ZATCA (Saudi e-invoicing) QR fields, phase 1 tags 1–5.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZatcaQr {
    pub seller_name: Option<String>,
    pub vat_number: Option<String>,
    pub timestamp: Option<String>,
    pub total: Option<String>,
    pub vat_total: Option<String>,
}

/// Standard base64 (padding optional, whitespace ignored).
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in text.chars().filter(|c| !c.is_whitespace()) {
        if c == '=' {
            break;
        }
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// Decodes a ZATCA QR payload: base64 of tag-length-value records. Unknown
/// tags (the phase 2 signature fields) are skipped; a truncated record or a
/// non-UTF-8 value ends the decode with what was read.
pub fn decode_zatca_qr(payload: &str) -> Option<ZatcaQr> {
    let bytes = base64_decode(payload.trim())?;
    let mut qr = ZatcaQr::default();
    let mut i = 0;
    let mut any = false;
    while i + 2 <= bytes.len() {
        let tag = bytes[i];
        let len = bytes[i + 1] as usize;
        let Some(value) = bytes.get(i + 2..i + 2 + len) else {
            break;
        };
        i += 2 + len;
        let Ok(value) = std::str::from_utf8(value) else {
            continue;
        };
        let value = Some(value.trim().to_owned());
        match tag {
            1 => qr.seller_name = value,
            2 => qr.vat_number = value,
            3 => qr.timestamp = value,
            4 => qr.total = value,
            5 => qr.vat_total = value,
            _ => continue,
        }
        any = true;
    }
    any.then_some(qr)
}

/// Arabic-Indic and Eastern Arabic-Indic digits as ASCII, the Arabic
/// decimal and thousands separators as `.` and `,`.
fn ascii_digits(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{0660}'..='\u{0669}' => char::from(b'0' + (c as u32 - 0x0660) as u8),
            '\u{06F0}'..='\u{06F9}' => char::from(b'0' + (c as u32 - 0x06F0) as u8),
            '\u{066B}' => '.',
            '\u{066C}' => ',',
            c => c,
        })
        .collect()
}

/// An amount in a token: digits with optional thousands commas and one
/// decimal point, returned without the commas.
fn amount(token: &str) -> Option<String> {
    let t = token.trim_matches(|c: char| !c.is_ascii_digit());
    if t.is_empty()
        || !t
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == ',')
    {
        return None;
    }
    let plain: String = t.chars().filter(|c| *c != ',').collect();
    if plain.matches('.').count() > 1 {
        return None;
    }
    plain.parse::<f64>().ok().map(|_| plain)
}

/// A date token as `YYYY-MM-DD`: `2026-10-14`, `2026/10/14`, `14/10/2026`
/// or `14-10-2026`.
fn date(token: &str) -> Option<String> {
    let t = token.trim_matches(|c: char| !c.is_ascii_digit());
    let parts: Vec<&str> = t.split(['-', '/', '.']).collect();
    if parts.len() != 3
        || !parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    let (y, m, d) = if parts[0].len() == 4 {
        (parts[0], parts[1], parts[2])
    } else if parts[2].len() == 4 {
        (parts[2], parts[1], parts[0])
    } else {
        return None;
    };
    let (m, d): (u32, u32) = (m.parse().ok()?, d.parse().ok()?);
    ((1..=12).contains(&m) && (1..=31).contains(&d)).then(|| format!("{y}-{m:02}-{d:02}"))
}

const TOTAL_WORDS: &[&str] = &["total", "الإجمالي", "الاجمالي", "المجموع", "إجمالي", "اجمالي"];
const SUBTOTAL_WORDS: &[&str] = &[
    "subtotal",
    "sub total",
    "sub-total",
    "المجموع الفرعي",
    "قبل الضريبة",
];
const VAT_WORDS: &[&str] = &["vat", "tax", "ضريبة", "الضريبة", "القيمة المضافة"];
const INVOICE_NO_WORDS: &[&str] = &[
    "invoice no",
    "invoice number",
    "invoice #",
    "inv no",
    "رقم الفاتورة",
];

/// The distinct candidates of one field, as a [`Field`].
fn pick(candidates: Vec<String>) -> Option<Field> {
    let mut distinct: Vec<String> = Vec::new();
    for c in candidates {
        if !distinct.contains(&c) {
            distinct.push(c);
        }
    }
    let confidence = match distinct.len() {
        0 => return None,
        1 => 0.8,
        _ => 0.5,
    };
    Some(Field {
        value: distinct.swap_remove(0),
        confidence,
        source: "text",
    })
}

/// Fields found in the text of an invoice or receipt.
pub fn extract_text(text: &str) -> Map<String, Value> {
    let text = ascii_digits(text);
    let mut vat_numbers = Vec::new();
    let mut dates = Vec::new();
    let mut totals = Vec::new();
    let mut vats = Vec::new();
    let mut invoice_numbers = Vec::new();
    for line in text.lines() {
        let lower = line.to_lowercase();
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for token in &tokens {
            let digits = token.trim_matches(|c: char| !c.is_ascii_digit());
            if digits.len() == 15
                && digits.chars().all(|c| c.is_ascii_digit())
                && digits.starts_with('3')
                && digits.ends_with('3')
            {
                vat_numbers.push(digits.to_owned());
            }
            if let Some(d) = date(token) {
                dates.push(d);
            }
        }
        let amounts: Vec<String> = tokens
            .iter()
            .filter(|t| t.trim_matches(|c: char| !c.is_ascii_digit()).len() < 15)
            .filter_map(|t| amount(t))
            .filter(|a| a.contains('.') || a.len() <= 9)
            .collect();
        let is_vat = VAT_WORDS.iter().any(|w| lower.contains(w));
        let is_total = TOTAL_WORDS.iter().any(|w| lower.contains(w))
            && !SUBTOTAL_WORDS.iter().any(|w| lower.contains(w));
        if let Some(last) = amounts.last() {
            if is_vat && !lower.contains("number") && !lower.contains("رقم") {
                vats.push(last.clone());
            } else if is_total {
                totals.push(last.clone());
            }
        }
        if let Some(word) = INVOICE_NO_WORDS.iter().find(|w| lower.contains(*w))
            && let Some(at) = lower.find(word)
        {
            // `get`, not indexing: lowercasing may move a char boundary.
            let rest = line.get(at + word.len()..).unwrap_or_default();
            if let Some(token) = rest
                .split(|c: char| c.is_whitespace() || c == ':' || c == '#')
                .find(|t| t.chars().any(|c| c.is_ascii_digit()))
            {
                invoice_numbers.push(
                    token
                        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
                        .to_owned(),
                );
            }
        }
    }
    let mut fields = Map::new();
    for (name, candidates) in [
        ("vat_number", vat_numbers),
        ("invoice_number", invoice_numbers),
        ("date", dates),
        ("total", totals),
        ("vat_total", vats),
    ] {
        if let Some(field) = pick(candidates) {
            fields.insert(name.to_owned(), json!(field));
        }
    }
    fields
}

/// Merges the QR's exact fields over the text's, and lists the fields a
/// person must check: low confidence, missing, or disagreeing with the QR.
pub fn extract(text: &str, qr: Option<&ZatcaQr>) -> (Map<String, Value>, Vec<String>) {
    let mut fields = extract_text(text);
    let mut review = Vec::new();
    if let Some(qr) = qr {
        for (name, value) in [
            ("seller_name", &qr.seller_name),
            ("vat_number", &qr.vat_number),
            ("timestamp", &qr.timestamp),
            ("total", &qr.total),
            ("vat_total", &qr.vat_total),
        ] {
            let Some(value) = value else { continue };
            if let Some(found) = fields.get(name)
                && found["value"].as_str() != Some(value.as_str())
            {
                review.push(name.to_owned());
            }
            fields.insert(
                name.to_owned(),
                json!(Field {
                    value: value.clone(),
                    confidence: 1.0,
                    source: "qr",
                }),
            );
        }
    }
    for name in ["vat_number", "invoice_number", "date", "total", "vat_total"] {
        let low = fields
            .get(name)
            .and_then(|f| f["confidence"].as_f64())
            .is_none_or(|c| c < REVIEW_THRESHOLD);
        if low && !review.iter().any(|r| r == name) {
            review.push(name.to_owned());
        }
    }
    (fields, review)
}

const INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "text": { "type": "string", "description": "The document's text, e.g. what OCR read from a scan." },
    "qr": { "type": "string", "description": "The ZATCA e-invoice QR payload (base64), when the document has one." },
    "doc_type": { "type": "string", "enum": ["invoice", "receipt"] }
  },
  "required": ["text"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        DOCUMENT_EXTRACT,
        "Typed fields from an invoice or receipt's text (VAT number, invoice number, date, \
         total, VAT) with a confidence each, plus the exact fields of its ZATCA QR code when \
         given, and the fields a person should check. English and Arabic. Local; writes nothing.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(INPUT)
}

pub(crate) struct DocumentExtract;

impl Action for DocumentExtract {
    fn id(&self) -> ActionId {
        ActionId(DOCUMENT_EXTRACT)
    }

    fn execute<'a>(
        &'a self,
        _state: &'a EngineState,
        _ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let text = args["text"]
                .as_str()
                .ok_or_else(|| AppError::Validation("text is required".into()))?;
            if text.chars().count() > MAX_TEXT_CHARS {
                return Err(AppError::Validation(format!(
                    "text is longer than {MAX_TEXT_CHARS} characters"
                )));
            }
            let qr =
                match args["qr"].as_str().map(str::trim).filter(|q| !q.is_empty()) {
                    Some(payload) if payload.len() > MAX_QR_CHARS => {
                        return Err(AppError::Validation("qr is too long".into()));
                    }
                    Some(payload) => Some(decode_zatca_qr(payload).ok_or_else(|| {
                        AppError::Validation("qr is not a ZATCA QR payload".into())
                    })?),
                    None => None,
                };
            let (fields, needs_review) = extract(text, qr.as_ref());
            Ok(ActionResult::plain(json!({
                "doc_type": args["doc_type"].as_str().unwrap_or("invoice"),
                "fields": fields,
                "needs_review": needs_review,
                "review_threshold": REVIEW_THRESHOLD,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a phase 1 ZATCA QR payload.
    fn zatca(fields: &[(u8, &str)]) -> String {
        let mut bytes = Vec::new();
        for (tag, value) in fields {
            bytes.push(*tag);
            bytes.push(value.len() as u8);
            bytes.extend_from_slice(value.as_bytes());
        }
        encode(&bytes)
    }

    fn encode(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
                if i <= chunk.len() {
                    out.push(char::from(A[((n >> shift) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn a_zatca_qr_is_decoded_exactly() {
        let payload = zatca(&[
            (1, "شركة المثال"),
            (2, "300000000000003"),
            (3, "2026-10-14T09:30:00Z"),
            (4, "1150.00"),
            (5, "150.00"),
        ]);
        let qr = decode_zatca_qr(&payload).unwrap();
        assert_eq!(qr.seller_name.as_deref(), Some("شركة المثال"));
        assert_eq!(qr.vat_number.as_deref(), Some("300000000000003"));
        assert_eq!(qr.total.as_deref(), Some("1150.00"));
        assert_eq!(qr.vat_total.as_deref(), Some("150.00"));
        assert!(decode_zatca_qr("not base64 !!").is_none());
        assert!(decode_zatca_qr("").is_none());
    }

    #[test]
    fn invoice_fields_are_found_in_english_and_arabic_text() {
        let text = "Tax Invoice\nInvoice No: INV-1042\nDate: 14/10/2026\nVAT Number: 300000000000003\n\
                    Subtotal 1,000.00\nVAT 15% 150.00\nTotal 1,150.00 SAR";
        let fields = extract_text(text);
        assert_eq!(fields["vat_number"]["value"], "300000000000003");
        assert_eq!(fields["invoice_number"]["value"], "INV-1042");
        assert_eq!(fields["date"]["value"], "2026-10-14");
        assert_eq!(fields["total"]["value"], "1150.00");
        assert_eq!(fields["vat_total"]["value"], "150.00");
        assert_eq!(fields["total"]["confidence"], 0.8);

        let arabic = "فاتورة ضريبية\nرقم الفاتورة: ١٠٤٢\nالتاريخ ٢٠٢٦/١٠/١٤\nالإجمالي ١١٥٠٫٠٠ ريال";
        let fields = extract_text(arabic);
        assert_eq!(fields["invoice_number"]["value"], "1042");
        assert_eq!(fields["date"]["value"], "2026-10-14");
        assert_eq!(fields["total"]["value"], "1150.00");
    }

    #[test]
    fn the_qr_wins_and_disagreements_and_gaps_need_review() {
        let qr = ZatcaQr {
            vat_number: Some("300000000000003".into()),
            total: Some("1150.00".into()),
            ..ZatcaQr::default()
        };
        let text = "Invoice No: 77\nTotal 1,100.00\nTotal 1,150.00";
        let (fields, review) = extract(text, Some(&qr));
        assert_eq!(fields["total"]["value"], "1150.00");
        assert_eq!(fields["total"]["source"], "qr");
        assert_eq!(fields["vat_number"]["confidence"], 1.0);
        assert!(
            review.contains(&"total".to_owned()),
            "text disagreed: {review:?}"
        );
        assert!(review.contains(&"date".to_owned()), "no date: {review:?}");
        assert!(!review.contains(&"vat_number".to_owned()));
    }
}
