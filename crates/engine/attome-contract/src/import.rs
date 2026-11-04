//! W1-T12: old contracts in, through their text, with a person in between.
//!
//! A `contract_import` is created through the generic record API with the
//! old contract's file in its `file` field; the upload pipeline scans it and
//! extracts its text (K2, K1-T4), as for any file.
//!
//! - `POST /api/v1/contract/imports/{id}/propose` reads the file's text and
//!   proposes the contract's fields: the counterparty, start and end dates,
//!   value and currency, renewal and notice terms, and the obligations it
//!   states ([`propose`], local rules over English and Arabic text, no model
//!   call). Each field carries a confidence, and the low ones are listed in
//!   `needs_review`. The proposal is stored in `proposed_json` and the
//!   import becomes `proposed`. A 409 while the text is not ready yet.
//! - `POST /api/v1/contract/imports/{id}/accept` takes the proposal as a
//!   person reviewed and corrected it and creates the contract and its
//!   obligations through the generic record path, as the caller; the import
//!   becomes `accepted` and names the contract. No agent action reaches this
//!   route: a person accepts.

use std::sync::LazyLock;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use axum::{
    Json,
    extract::{Path, State},
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// A field under this confidence needs a person.
pub const REVIEW_THRESHOLD: f64 = 0.75;
/// The most obligations a proposal lists.
pub const MAX_OBLIGATIONS: usize = 20;
/// The most text read.
const MAX_TEXT_CHARS: usize = 200_000;
/// The contract fields an accepted proposal may set.
const CONTRACT_FIELDS: [&str; 11] = [
    "title",
    "counterparty",
    "description",
    "contract_value",
    "currency",
    "start_date",
    "end_date",
    "renewal_date",
    "auto_renew",
    "renewal_term_months",
    "notice_period_days",
];
/// The obligation fields an accepted proposal may set.
const OBLIGATION_FIELDS: [&str; 3] = ["title", "due_date", "owed_by"];
/// The currencies the contract's choice field offers.
const CURRENCIES: [&str; 5] = ["USD", "EUR", "GBP", "SAR", "AED"];

static ISO_DATE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\b(\d{4})-(\d{2})-(\d{2})\b").ok());
static DMY_DATE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b").ok());
static AMOUNT: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(USD|EUR|GBP|SAR|AED|ريال|درهم|\$|€|£)\s?([0-9][0-9,]*(?:\.[0-9]+)?)|([0-9][0-9,]*(?:\.[0-9]+)?)\s?(USD|EUR|GBP|SAR|AED|ريال|درهم)",
    )
    .ok()
});
static BETWEEN: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)between\s+(.{2,120}?)\s+and\s+(.{2,120}?)(?:[,.;(]|\s+\()").ok()
});
static BETWEEN_AR: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"بين\s+(.{2,120}?)\s+و\s*(.{2,120}?)(?:[،,.؛(])").ok());
static RENEW_TERM: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)renew\w*\s+(?:automatically\s+)?for\s+(?:an?\s+)?(?:additional\s+|further\s+|successive\s+)?(\d{1,3})\s*(month|year)")
        .ok()
});
static NOTICE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)(\d{1,3})\s*(?:\(\w+\)\s*)?days[’']?\s+(?:prior\s+)?(?:written\s+)?notice|(\d{1,3})\s*يوم")
        .ok()
});

/// One proposed field and how sure the rules are of it.
fn field(value: Value, confidence: f64) -> Value {
    json!({ "value": value, "confidence": confidence })
}

/// The dates in `text`, as `YYYY-MM-DD`, each with where it starts.
fn dates(text: &str) -> Vec<(usize, String)> {
    let valid = |y: u32, m: u32, d: u32| {
        chrono::NaiveDate::from_ymd_opt(y as i32, m, d)
            .map(|day| day.format("%Y-%m-%d").to_string())
    };
    let mut out: Vec<(usize, String)> = Vec::new();
    for c in ISO_DATE.iter().flat_map(|re| re.captures_iter(text)) {
        let (Ok(y), Ok(m), Ok(d)) = (c[1].parse(), c[2].parse(), c[3].parse()) else {
            continue;
        };
        if let (Some(day), Some(at)) = (valid(y, m, d), c.get(0)) {
            out.push((at.start(), day));
        }
    }
    for c in DMY_DATE.iter().flat_map(|re| re.captures_iter(text)) {
        let (Ok(d), Ok(m), Ok(y)) = (c[1].parse(), c[2].parse(), c[3].parse()) else {
            continue;
        };
        if let (Some(day), Some(at)) = (valid(y, m, d), c.get(0)) {
            out.push((at.start(), day));
        }
    }
    out.sort();
    out
}

/// The date nearest after one of `cues` (within 120 bytes), if any.
fn date_after(lower: &str, found: &[(usize, String)], cues: &[&str]) -> Option<String> {
    cues.iter()
        .filter_map(|cue| lower.find(cue).map(|at| at + cue.len()))
        .filter_map(|from| {
            found
                .iter()
                .find(|(at, _)| *at >= from && *at - from <= 120)
                .map(|(at, d)| (*at, d.clone()))
        })
        .min_by_key(|(at, _)| *at)
        .map(|(_, d)| d)
}

fn currency_of(token: &str) -> Option<&'static str> {
    match token.trim().to_uppercase().as_str() {
        "USD" | "$" => Some("USD"),
        "EUR" | "€" => Some("EUR"),
        "GBP" | "£" => Some("GBP"),
        "SAR" | "ريال" => Some("SAR"),
        "AED" | "درهم" => Some("AED"),
        _ => None,
    }
}

/// Arabic-Indic and Eastern Arabic-Indic digits as ASCII. Pure.
fn ascii_digits(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{0660}'..='\u{0669}' => char::from(b'0' + (c as u32 - 0x0660) as u8),
            '\u{06F0}'..='\u{06F9}' => char::from(b'0' + (c as u32 - 0x06F0) as u8),
            _ => c,
        })
        .collect()
}

/// The sentences of `text` that state an obligation.
fn obligations(text: &str) -> Vec<String> {
    let cues = ["shall ", "must ", "agrees to ", "يلتزم", "يجب على", "تلتزم"];
    let mut out = Vec::new();
    for sentence in text.split(['.', '\n', '؛', ';']) {
        let sentence = sentence.trim();
        if sentence.chars().count() < 12 {
            continue;
        }
        let lower = sentence.to_lowercase();
        if cues.iter().any(|c| lower.contains(c)) {
            out.push(sentence.chars().take(200).collect());
            if out.len() == MAX_OBLIGATIONS {
                break;
            }
        }
    }
    out
}

/// The proposed contract for an old contract's `text`: each field with a
/// confidence, the obligations it states, and the fields a person must
/// check. Local rules, English and Arabic. Pure.
pub fn propose(text: &str) -> Value {
    let text: String = ascii_digits(text).chars().take(MAX_TEXT_CHARS).collect();
    let lower = text.to_lowercase();
    let mut fields = Map::new();

    let title = text
        .lines()
        .map(str::trim)
        .find(|l| l.chars().count() >= 3)
        .map(|l| l.chars().take(200).collect::<String>());
    if let Some(title) = title {
        fields.insert("title".into(), field(json!(title), 0.6));
    }

    let parties = BETWEEN
        .as_ref()
        .and_then(|re| re.captures(&text))
        .or_else(|| BETWEEN_AR.as_ref().and_then(|re| re.captures(&text)))
        .map(|c| (c[1].trim().to_owned(), c[2].trim().to_owned()));
    if let Some((_, second)) = parties {
        // Which party is "us" is not in the text: a person confirms.
        fields.insert("counterparty".into(), field(json!(second), 0.5));
    }

    let found = dates(&text);
    let start = date_after(
        &lower,
        &found,
        &[
            "effective",
            "commence",
            "start",
            "يبدأ",
            "اعتبارا من",
            "اعتباراً من",
        ],
    );
    let end = date_after(
        &lower,
        &found,
        &["expire", "terminate on", "end on", "until", "ينتهي", "حتى"],
    );
    match (start, found.first()) {
        (Some(day), _) => {
            fields.insert("start_date".into(), field(json!(day), 0.8));
        }
        (None, Some((_, day))) => {
            fields.insert("start_date".into(), field(json!(day), 0.5));
        }
        _ => {}
    }
    match (end, found.last()) {
        (Some(day), _) => {
            fields.insert("end_date".into(), field(json!(day), 0.8));
        }
        (None, Some((_, day))) if found.len() > 1 => {
            fields.insert("end_date".into(), field(json!(day), 0.5));
        }
        _ => {}
    }

    let amounts: Vec<(f64, &'static str)> = AMOUNT
        .iter()
        .flat_map(|re| re.captures_iter(&text))
        .filter_map(|c| {
            let (cur, num) = match (c.get(1), c.get(2), c.get(3), c.get(4)) {
                (Some(cur), Some(num), _, _) | (_, _, Some(num), Some(cur)) => {
                    (cur.as_str(), num.as_str())
                }
                _ => return None,
            };
            let value: f64 = num.replace(',', "").parse().ok()?;
            Some((value, currency_of(cur)?))
        })
        .collect();
    if let Some((value, currency)) = amounts.iter().copied().max_by(|a, b| a.0.total_cmp(&b.0)) {
        let sure = if amounts.iter().filter(|(v, _)| *v == value).count() == amounts.len() {
            0.8
        } else {
            0.6
        };
        fields.insert("contract_value".into(), field(json!(value), sure));
        if CURRENCIES.contains(&currency) {
            fields.insert("currency".into(), field(json!(currency), sure));
        }
    }

    let auto = lower.contains("automatically renew")
        || lower.contains("renew automatically")
        || lower.contains("renews automatically")
        || lower.contains("يتجدد تلقائيا")
        || lower.contains("يجدد تلقائيا");
    if auto {
        fields.insert("auto_renew".into(), field(json!(true), 0.8));
    }
    if let Some(c) = RENEW_TERM.as_ref().and_then(|re| re.captures(&text)) {
        let n: i64 = c[1].parse().unwrap_or(0);
        let months = if c[2].eq_ignore_ascii_case("year") {
            n * 12
        } else {
            n
        };
        if months > 0 {
            fields.insert("renewal_term_months".into(), field(json!(months), 0.8));
        }
    }
    if let Some(c) = NOTICE.as_ref().and_then(|re| re.captures(&text)) {
        let days: Option<i64> = c
            .get(1)
            .or_else(|| c.get(2))
            .and_then(|m| m.as_str().parse().ok());
        if let Some(days) = days.filter(|d| *d > 0) {
            fields.insert("notice_period_days".into(), field(json!(days), 0.8));
        }
    }

    let needs_review: Vec<String> = fields
        .iter()
        .filter(|(_, f)| f["confidence"].as_f64().unwrap_or(0.0) < REVIEW_THRESHOLD)
        .map(|(k, _)| k.clone())
        .collect();
    let obligations: Vec<Value> = obligations(&text)
        .into_iter()
        .map(|title| json!({ "title": title }))
        .collect();
    json!({
        "fields": fields,
        "obligations": obligations,
        "needs_review": needs_review,
        "review_threshold": REVIEW_THRESHOLD,
    })
}

/// What a person accepts: the contract's fields and its obligations, as
/// reviewed.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ImportAcceptBody {
    /// The contract's fields (title, counterparty, description,
    /// contract_value, currency, start_date, end_date, renewal_date,
    /// auto_renew, renewal_term_months, notice_period_days).
    #[schema(value_type = Object)]
    pub contract: Map<String, Value>,
    /// Each obligation's title, due_date and owed_by (`us` or
    /// `counterparty`).
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub obligations: Vec<Map<String, Value>>,
}

/// An accepted import.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[schema(as = ContractImportAccepted)]
pub struct ImportAccepted {
    pub contract_id: Uuid,
    pub obligations: usize,
}

/// A stored proposal.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ImportProposal {
    pub import_id: Uuid,
    #[schema(value_type = Object)]
    pub proposal: Value,
}

fn only(fields: &[&str], body: &Map<String, Value>) -> Map<String, Value> {
    body.iter()
        .filter(|(k, v)| fields.contains(&k.as_str()) && !v.is_null())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

async fn import_row(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<(Value, i64), AppError> {
    let record =
        attome_records::entity_crud::read_record(state, ctx, "contract_import", id).await?;
    Ok((record.data().clone(), record.row_version()))
}

/// Proposes the contract from the import's file text, as `ctx`.
pub async fn propose_import(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<Value, AppError> {
    ctx.require("contract_import", "create")?;
    let (data, version) = import_row(state, ctx, id).await?;
    if data["status"].as_str() == Some("accepted") {
        return Err(AppError::Conflict("this import was already accepted"));
    }
    let Some(file) = data["file"].as_str().filter(|f| !f.trim().is_empty()) else {
        return Err(AppError::Validation("the import has no file".into()));
    };
    let Some(text) = attome_document::text_extract::stored_file_text(state, file).await? else {
        return Err(AppError::Conflict(
            "the file's text is not ready yet: it is scanned and read first",
        ));
    };
    let proposal = propose(&text);
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        "contract_import",
        id,
        version,
        json!({ "proposed_json": proposal.to_string(), "status": "proposed" }),
    )
    .await?;
    Ok(proposal)
}

/// Creates the contract and its obligations from the reviewed proposal, as
/// `ctx`, and marks the import accepted.
pub async fn accept_import(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    body: &ImportAcceptBody,
) -> Result<ImportAccepted, AppError> {
    ctx.require("contract", "create")?;
    let (data, version) = import_row(state, ctx, id).await?;
    if data["status"].as_str() != Some("proposed") {
        return Err(AppError::Conflict("only a proposed import can be accepted"));
    }
    let contract = only(&CONTRACT_FIELDS, &body.contract);
    if contract
        .get("title")
        .and_then(Value::as_str)
        .is_none_or(|t| t.trim().is_empty())
    {
        return Err(AppError::Validation("contract.title is required".into()));
    }
    if body.obligations.len() > MAX_OBLIGATIONS * 5 {
        return Err(AppError::Validation("too many obligations".into()));
    }
    // The import is claimed first, so a second accept cannot make a second
    // contract: its row version moves on.
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        "contract_import",
        id,
        version,
        json!({ "status": "accepted" }),
    )
    .await?;
    let (contract_id, _) = attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "contract",
        Value::Object(contract),
    )
    .await?;
    let mut created = 0;
    if !body.obligations.is_empty() {
        ctx.require("obligation", "create")?;
    }
    for obligation in &body.obligations {
        let mut row = only(&OBLIGATION_FIELDS, obligation);
        if row.get("title").and_then(Value::as_str).is_none() {
            continue;
        }
        row.insert("contract_ref".into(), json!(contract_id));
        attome_records::entity_crud::create_record_for(
            state,
            ctx,
            ctx.user_id,
            "obligation",
            Value::Object(row),
        )
        .await?;
        created += 1;
    }
    let (_, version) = import_row(state, ctx, id).await?;
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        "contract_import",
        id,
        version,
        json!({ "contract_id": contract_id.to_string() }),
    )
    .await?;
    Ok(ImportAccepted {
        contract_id,
        obligations: created,
    })
}

/// Propose a contract from an import's file
///
/// Reads the import's file text and stores a proposed contract: its fields
/// with a confidence each, the obligations the text states, and the fields
/// a person must check. Local rules; no model call. The caller needs to
/// create contract imports.
#[utoipa::path(
    post,
    path = "/api/v1/contract/imports/{id}/propose",
    operation_id = "post_contract_import_propose",
    tag = "contract",
    params(("id" = Uuid, Path, description = "The contract_import's id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The stored proposal", body = ImportProposal),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "The caller may not import contracts", body = attome_types::ErrorResponse),
        (status = 404, description = "No such import the caller may read", body = attome_types::ErrorResponse),
        (status = 409, description = "Already accepted, or the file's text is not ready yet", body = attome_types::ErrorResponse),
        (status = 422, description = "The import has no file", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn post_propose(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<ImportProposal>, AppError> {
    let proposal = propose_import(&state, &ctx, id).await?;
    Ok(Json(ImportProposal {
        import_id: id,
        proposal,
    }))
}

/// Accept a reviewed contract import
///
/// Creates the contract and its obligations from the proposal as a person
/// reviewed it, and marks the import accepted. The caller needs to create
/// contracts (and obligations, when it sends any).
#[utoipa::path(
    post,
    path = "/api/v1/contract/imports/{id}/accept",
    operation_id = "post_contract_import_accept",
    tag = "contract",
    params(("id" = Uuid, Path, description = "The contract_import's id")),
    request_body = ImportAcceptBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The contract created", body = ImportAccepted),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "The caller may not create contracts or obligations", body = attome_types::ErrorResponse),
        (status = 404, description = "No such import the caller may read", body = attome_types::ErrorResponse),
        (status = 409, description = "The import is not proposed, or another accept took it", body = attome_types::ErrorResponse),
        (status = 422, description = "No title, or a field the contract refuses", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn post_accept(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<ImportAcceptBody>,
) -> Result<Json<ImportAccepted>, AppError> {
    accept_import(&state, &ctx, id, &body).await.map(Json)
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_propose, post_accept),
    components(schemas(ImportAcceptBody, ImportAccepted, ImportProposal))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    const ENGLISH: &str = "Supply Agreement\n\
        This agreement is made between Attome Trading Co. and Gulf Cement LLC, (the Supplier).\n\
        It is effective from 2027-01-01 and shall expire on 2027-12-31.\n\
        The total value is SAR 1,250,000.\n\
        The agreement renews automatically for 12 months unless either party gives 60 days written notice.\n\
        The Supplier shall deliver cement within 10 days of each order.\n\
        The Buyer must pay each invoice within 30 days.";

    #[test]
    fn an_english_contract_proposes_its_terms() {
        let p = propose(ENGLISH);
        let f = &p["fields"];
        assert_eq!(f["title"]["value"], "Supply Agreement");
        assert_eq!(f["counterparty"]["value"], "Gulf Cement LLC");
        assert_eq!(f["start_date"]["value"], "2027-01-01");
        assert_eq!(f["end_date"]["value"], "2027-12-31");
        assert_eq!(f["contract_value"]["value"], 1_250_000.0);
        assert_eq!(f["currency"]["value"], "SAR");
        assert_eq!(f["renewal_term_months"]["value"], 12);
        assert_eq!(f["notice_period_days"]["value"], 60);
        let obligations = p["obligations"].to_string();
        assert!(obligations.contains("deliver cement"), "{obligations}");
        assert!(obligations.contains("pay each invoice"), "{obligations}");
        let review: Vec<&str> = p["needs_review"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(review.contains(&"counterparty"), "{review:?}");
        assert!(!review.contains(&"start_date"), "{review:?}");
    }

    #[test]
    fn arabic_digits_and_dates_are_read() {
        let p = propose(
            "عقد توريد\nيبدأ العقد في ٠١/٠٢/٢٠٢٧ وينتهي في 2028-01-31.\nالقيمة 500,000 ريال.",
        );
        assert_eq!(p["fields"]["start_date"]["value"], "2027-02-01");
        assert_eq!(p["fields"]["end_date"]["value"], "2028-01-31");
        assert_eq!(p["fields"]["currency"]["value"], "SAR");
    }

    #[test]
    fn accept_keeps_only_contract_fields() {
        let body: Map<String, Value> = serde_json::from_value(json!({
            "title": "X", "owner_ref": "someone", "contract_value": 5, "status": "active"
        }))
        .unwrap();
        let kept = only(&CONTRACT_FIELDS, &body);
        assert!(kept.contains_key("title") && kept.contains_key("contract_value"));
        assert!(!kept.contains_key("owner_ref") && !kept.contains_key("status"));
    }
}
