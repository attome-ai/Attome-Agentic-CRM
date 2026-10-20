//! W1-T7: comparing two versions of a contract, in the background, so
//! viewing a comparison does no work.
//!
//! `POST /api/v1/contract/contracts/{id}/compare` checks that the caller may
//! read the contract and both versions, creates a `contract_comparison`
//! (`queued`) and queues the `contract_compare` job in one transaction. The
//! job, as the requester:
//!
//! 1. reads each version's text (`attome_document::text_extract::
//!    stored_file_text`: the upload scan's extracted text, else DOCX
//!    paragraphs, a PDF's embedded text, or HTML without its tags);
//! 2. splits each into sections at headings ([`sections`]): numbered lines,
//!    "Article", "Section", "Clause", "المادة", "البند", or short lines in
//!    capitals;
//! 3. diffs each section word by word against the section of the same title
//!    in the other version ([`word_diff`]; whitespace-separated words, so an
//!    Arabic word is never split);
//! 4. flags a section of the newer version that matches a library clause
//!    (`clause`, by its key or title) but is like neither the clause's
//!    standard text nor any of its fallbacks ([`deviates`]);
//!
//! and stores `diff_json` and `deviations_json` with status `done` (or
//! `failed` with nothing stored when a version has no readable text).

use std::collections::HashMap;

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "contract_compare";
/// A section this like a library text (0 to 1) is not a deviation.
pub const MATCH_THRESHOLD: f64 = 0.9;
/// Word pairs past which a section is diffed as replaced whole.
const MAX_CELLS: usize = 4_000_000;
/// Library clauses read per comparison.
const MAX_LIBRARY: i64 = 2_000;

/// One section of a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub title: String,
    pub body: String,
}

/// One step of a diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    /// `equal`, `insert` or `delete`.
    pub op: &'static str,
    pub text: String,
}

/// A library clause, as compared.
#[derive(Debug, Clone, PartialEq)]
pub struct LibraryClause {
    pub id: Uuid,
    pub key: Option<String>,
    pub title: String,
    pub text: String,
    /// The clause this one is a fallback of.
    pub fallback_of: Option<Uuid>,
}

fn is_heading(line: &str) -> bool {
    let line = line.trim();
    let words = line.split_whitespace().count();
    if line.is_empty() || line.chars().count() > 90 || words > 12 {
        return false;
    }
    let lower = line.to_lowercase();
    let numbered = {
        let digits: String = line
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        !digits.is_empty()
            && digits.chars().next().is_some_and(|c| c.is_ascii_digit())
            && line[digits.len()..].starts_with([' ', ')', '-'])
    };
    let worded = ["article ", "section ", "clause ", "schedule ", "annex "]
        .iter()
        .any(|w| lower.starts_with(w))
        || ["المادة", "مادة", "البند", "بند", "الملحق"]
            .iter()
            .any(|w| line.starts_with(w));
    let letters: Vec<char> = line.chars().filter(|c| c.is_alphabetic()).collect();
    let capitals =
        letters.len() >= 3 && letters.iter().all(|c| c.is_uppercase()) && !line.ends_with('.');
    numbered || worded || capitals
}

/// The text split at its headings; text before the first heading is a
/// section with an empty title. Pure.
pub fn sections(text: &str) -> Vec<Section> {
    let mut out: Vec<Section> = Vec::new();
    let mut current = Section {
        title: String::new(),
        body: String::new(),
    };
    for line in text.lines() {
        if is_heading(line) {
            if !current.title.is_empty() || !current.body.trim().is_empty() {
                out.push(current);
            }
            current = Section {
                title: line.trim().to_owned(),
                body: String::new(),
            };
        } else if !line.trim().is_empty() {
            if !current.body.is_empty() {
                current.body.push('\n');
            }
            current.body.push_str(line.trim());
        }
    }
    if !current.title.is_empty() || !current.body.trim().is_empty() {
        out.push(current);
    }
    out
}

/// A title reduced for matching: lower case, numbering and punctuation gone.
/// Pure.
pub fn title_key(title: &str) -> String {
    let lower = title.to_lowercase().replace('_', " ");
    let mut words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    while words.first().is_some_and(|w| {
        w.chars().all(|c| c.is_ascii_digit())
            || ["article", "section", "clause", "المادة", "البند"].contains(w)
    }) {
        words.remove(0);
    }
    words.join(" ")
}

fn lcs_table(a: &[&str], b: &[&str]) -> Vec<Vec<u32>> {
    let mut t = vec![vec![0u32; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            t[i][j] = if a[i] == b[j] {
                t[i + 1][j + 1] + 1
            } else {
                t[i + 1][j].max(t[i][j + 1])
            };
        }
    }
    t
}

fn push(out: &mut Vec<Change>, op: &'static str, word: &str) {
    match out.last_mut() {
        Some(last) if last.op == op => {
            last.text.push(' ');
            last.text.push_str(word);
        }
        _ => out.push(Change {
            op,
            text: word.to_owned(),
        }),
    }
}

/// The word-level changes from `from` to `to`, runs of the same kind
/// joined. Words are whitespace-separated, so an Arabic word stays whole.
/// Pure.
pub fn word_diff(from: &str, to: &str) -> Vec<Change> {
    let a: Vec<&str> = from.split_whitespace().collect();
    let b: Vec<&str> = to.split_whitespace().collect();
    let mut out = Vec::new();
    if a.len().saturating_mul(b.len()) > MAX_CELLS {
        if a != b {
            if !a.is_empty() {
                out.push(Change {
                    op: "delete",
                    text: a.join(" "),
                });
            }
            if !b.is_empty() {
                out.push(Change {
                    op: "insert",
                    text: b.join(" "),
                });
            }
        } else if !a.is_empty() {
            out.push(Change {
                op: "equal",
                text: a.join(" "),
            });
        }
        return out;
    }
    let t = lcs_table(&a, &b);
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            push(&mut out, "equal", a[i]);
            i += 1;
            j += 1;
        } else if t[i + 1][j] >= t[i][j + 1] {
            push(&mut out, "delete", a[i]);
            i += 1;
        } else {
            push(&mut out, "insert", b[j]);
            j += 1;
        }
    }
    for w in &a[i..] {
        push(&mut out, "delete", w);
    }
    for w in &b[j..] {
        push(&mut out, "insert", w);
    }
    out
}

/// How alike two texts are, 0 to 1: shared words in order over their
/// average length (words compared case-insensitively). Pure.
pub fn similarity(a: &str, b: &str) -> f64 {
    let a: Vec<String> = a.split_whitespace().map(str::to_lowercase).collect();
    let b: Vec<String> = b.split_whitespace().map(str::to_lowercase).collect();
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let ar: Vec<&str> = a.iter().map(String::as_str).collect();
    let br: Vec<&str> = b.iter().map(String::as_str).collect();
    let common = if ar.len().saturating_mul(br.len()) > MAX_CELLS {
        let set: std::collections::HashSet<&str> = ar.iter().copied().collect();
        br.iter().filter(|w| set.contains(*w)).count() as f64
    } else {
        f64::from(lcs_table(&ar, &br)[0][0])
    };
    2.0 * common / (ar.len() + br.len()) as f64
}

/// Whether `text` is like neither the standard nor any fallback. Pure.
pub fn deviates(text: &str, standard: &str, fallbacks: &[&str]) -> bool {
    std::iter::once(standard)
        .chain(fallbacks.iter().copied())
        .all(|lib| similarity(text, lib) < MATCH_THRESHOLD)
}

/// The library clause a section is, by key or title. Pure.
pub fn match_clause<'a>(title: &str, library: &'a [LibraryClause]) -> Option<&'a LibraryClause> {
    let key = title_key(title);
    if key.is_empty() {
        return None;
    }
    let standards = library.iter().filter(|c| c.fallback_of.is_none());
    let mut by_title = None;
    for c in standards {
        if c.key.as_deref().map(title_key).as_deref() == Some(key.as_str()) {
            return Some(c);
        }
        if by_title.is_none() && title_key(&c.title) == key {
            by_title = Some(c);
        }
    }
    by_title
}

/// What a comparison stores, computed from the two texts. Pure.
pub fn compare_texts(from: &str, to: &str, library: &[LibraryClause]) -> (Value, Value) {
    let old = sections(from);
    let new = sections(to);
    let old_by: HashMap<String, &Section> = old.iter().map(|s| (title_key(&s.title), s)).collect();
    let new_keys: std::collections::HashSet<String> =
        new.iter().map(|s| title_key(&s.title)).collect();
    let mut diff = Vec::new();
    for s in &new {
        let key = title_key(&s.title);
        match old_by.get(&key) {
            Some(o) if o.body == s.body => {}
            Some(o) => diff.push(json!({
                "section": s.title, "status": "changed", "changes": word_diff(&o.body, &s.body),
            })),
            None => diff.push(json!({ "section": s.title, "status": "added", "text": s.body })),
        }
    }
    for o in &old {
        if !new_keys.contains(&title_key(&o.title)) {
            diff.push(json!({ "section": o.title, "status": "removed", "text": o.body }));
        }
    }
    let mut deviations = Vec::new();
    for s in &new {
        let Some(clause) = match_clause(&s.title, library) else {
            continue;
        };
        let fallbacks: Vec<&str> = library
            .iter()
            .filter(|c| c.fallback_of == Some(clause.id))
            .map(|c| c.text.as_str())
            .collect();
        if deviates(&s.body, &clause.text, &fallbacks) {
            deviations.push(json!({
                "section": s.title,
                "clause_id": clause.id,
                "clause_key": clause.key,
                "similarity": (similarity(&s.body, &clause.text) * 100.0).round() / 100.0,
            }));
        }
    }
    (Value::Array(diff), Value::Array(deviations))
}

/// The job's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompareJob {
    pub comparison_id: Uuid,
    pub user_id: Uuid,
}

/// Which versions to compare.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ContractCompareBody {
    pub from_version: Uuid,
    pub to_version: Uuid,
}

/// The queued comparison.
#[derive(Debug, Serialize, ToSchema)]
pub struct ContractCompareQueued {
    /// The `contract_comparison`; its `status` turns `done` when stored.
    pub comparison_id: Uuid,
}

fn data_text(data: &Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|s| !s.trim().is_empty())
}

/// Creates the comparison and queues it, as `ctx`; see the module doc.
pub async fn request_compare(
    state: &EngineState,
    ctx: &SecurityContext,
    contract: Uuid,
    body: &ContractCompareBody,
) -> Result<Uuid, AppError> {
    if body.from_version == body.to_version {
        return Err(AppError::Validation(
            "from_version and to_version must differ".into(),
        ));
    }
    attome_records::entity_crud::read_record(state, ctx, "contract", contract).await?;
    for version in [body.from_version, body.to_version] {
        let record =
            attome_records::entity_crud::read_record(state, ctx, "contract_version", version)
                .await?;
        if data_text(record.data(), "contract_id").as_deref() != Some(contract.to_string().as_str())
        {
            return Err(AppError::Validation(format!(
                "version {version} is not a version of this contract"
            )));
        }
    }
    let (comparison, _) = attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "contract_comparison",
        json!({
            "contract_id": contract.to_string(),
            "from_version_ref": body.from_version.to_string(),
            "to_version_ref": body.to_version.to_string(),
            "status": "queued",
        }),
    )
    .await?;
    let job = attome_core::jobs::JOB_TYPES
        .job(
            JOB,
            &CompareJob {
                comparison_id: comparison,
                user_id: ctx.user_id,
            },
        )
        .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "contract_comparison",
            comparison,
            attome_audit::AuditOperation::Create,
            "contract.compare_requested",
            ctx.user_id,
        )
        .comment(format!(
            "compare {} with {}",
            body.from_version, body.to_version
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(comparison)
}

async fn version_text(
    state: &EngineState,
    ctx: &SecurityContext,
    version: Uuid,
) -> Result<Option<String>, AppError> {
    let record =
        attome_records::entity_crud::read_record(state, ctx, "contract_version", version).await?;
    let Some(file) = data_text(record.data(), "file") else {
        return Ok(None);
    };
    attome_document::text_extract::stored_file_text(state, &file).await
}

/// Compares two versions of a contract.
///
/// Creates a comparison (status `queued`) and queues the work: each
/// version's text split into sections, a word-level diff per section, and
/// the sections that match a library clause but are like neither its
/// standard text nor its fallbacks. Read the stored result from the
/// `contract_comparison` record once its status is `done`. The caller needs
/// to read the contract and both versions.
#[utoipa::path(
    post,
    path = "/api/v1/contract/contracts/{id}/compare",
    operation_id = "post_contract_compare",
    tag = "contract",
    params(("id" = Uuid, Path, description = "The contract's id")),
    request_body = ContractCompareBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 202, description = "The comparison is queued", body = ContractCompareQueued),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "The caller may not create comparisons", body = attome_types::ErrorResponse),
        (status = 404, description = "No such contract or version the caller may read", body = attome_types::ErrorResponse),
        (status = 422, description = "The same version twice, or a version of another contract", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn post_compare(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    axum::extract::Path(contract): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<ContractCompareBody>,
) -> Result<(axum::http::StatusCode, axum::Json<ContractCompareQueued>), AppError> {
    let comparison_id = request_compare(&state, &ctx, contract, &body).await?;
    Ok((
        axum::http::StatusCode::ACCEPTED,
        axum::Json(ContractCompareQueued { comparison_id }),
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_compare),
    components(schemas(ContractCompareBody, ContractCompareQueued))
)]
pub(crate) struct ApiDocFragment;

/// The job: computes and stores one comparison, as its requester.
pub async fn run_compare(
    state: &EngineState,
    ctx: &SecurityContext,
    comparison: Uuid,
) -> Result<(), AppError> {
    let record =
        attome_records::entity_crud::read_record(state, ctx, "contract_comparison", comparison)
            .await?;
    let data = record.data();
    if data_text(data, "status").as_deref() != Some("queued") {
        return Ok(());
    }
    let id = |key: &str| {
        data_text(data, key)
            .and_then(|s| Uuid::parse_str(&s).ok())
            .ok_or(AppError::NotFound)
    };
    let (from, to) = (id("from_version_ref")?, id("to_version_ref")?);
    let texts = (
        version_text(state, ctx, from).await?,
        version_text(state, ctx, to).await?,
    );
    let changes = match texts {
        (Some(from), Some(to)) => {
            let library: Vec<LibraryClause> = sqlx::query_as::<
                _,
                (
                    Uuid,
                    Option<String>,
                    Option<String>,
                    Option<String>,
                    Option<String>,
                    Option<Uuid>,
                ),
            >(
                "SELECT id, clause_key, title, body, body_html, fallback_of_ref FROM clause \
                  WHERE (is_active IS NULL OR is_active = true) ORDER BY id LIMIT $1",
            )
            .bind(MAX_LIBRARY)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .map(|(id, key, title, body, html, fallback_of)| LibraryClause {
                id,
                key,
                title: title.unwrap_or_default(),
                text: body
                    .filter(|b| !b.trim().is_empty())
                    .or_else(|| html.map(|h| attome_document::text_extract::strip_tags(&h)))
                    .unwrap_or_default(),
                fallback_of,
            })
            .collect();
            let (diff, deviations) =
                tokio::task::spawn_blocking(move || compare_texts(&from, &to, &library))
                    .await
                    .map_err(AppError::internal)?;
            json!({
                "status": "done",
                "diff_json": diff.to_string(),
                "deviations_json": deviations.to_string(),
            })
        }
        _ => json!({ "status": "failed" }),
    };
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        "contract_comparison",
        comparison,
        record.row_version(),
        changes,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &str = "MASTER SERVICES AGREEMENT\n\
                      1. Payment\nInvoices are due within 30 days of receipt.\n\
                      2. Liability\nLiability is capped at the fees paid in the last 12 months.";
    const V2: &str = "MASTER SERVICES AGREEMENT\n\
                      1. Payment\nInvoices are due within 60 days of receipt.\n\
                      2. Liability\nLiability is capped at the fees paid in the last 12 months.";

    #[test]
    fn changed_word_detected_in_section() {
        let s = sections(V1);
        assert_eq!(
            s.iter().map(|s| s.title.as_str()).collect::<Vec<_>>(),
            vec!["MASTER SERVICES AGREEMENT", "1. Payment", "2. Liability"]
        );
        let (diff, _) = compare_texts(V1, V2, &[]);
        let diff = diff.as_array().unwrap();
        assert_eq!(diff.len(), 1, "{diff:?}");
        assert_eq!(diff[0]["section"], "1. Payment");
        let changes = diff[0]["changes"].as_array().unwrap();
        assert!(
            changes
                .iter()
                .any(|c| c["op"] == "delete" && c["text"] == "30")
        );
        assert!(
            changes
                .iter()
                .any(|c| c["op"] == "insert" && c["text"] == "60")
        );
    }

    #[test]
    fn fallback_clause_not_flagged() {
        let standard = Uuid::from_u128(1);
        let library = vec![
            LibraryClause {
                id: standard,
                key: Some("payment".into()),
                title: "Payment".into(),
                text: "Invoices are due within 30 days of receipt.".into(),
                fallback_of: None,
            },
            LibraryClause {
                id: Uuid::from_u128(2),
                key: Some("payment_fallback".into()),
                title: "Payment (fallback)".into(),
                text: "Invoices are due within 60 days of receipt.".into(),
                fallback_of: Some(standard),
            },
        ];
        // 60 days is the fallback: not a deviation.
        let (_, deviations) = compare_texts(V1, V2, &library);
        assert!(deviations.as_array().unwrap().is_empty(), "{deviations}");
        // 120 days is neither.
        let v3 = V2.replace("60 days", "120 days, or later if the client wishes");
        let (_, deviations) = compare_texts(V1, &v3, &library);
        let deviations = deviations.as_array().unwrap();
        assert_eq!(deviations.len(), 1);
        assert_eq!(deviations[0]["clause_key"], "payment");
    }

    #[test]
    fn arabic_text_diff_keeps_words_whole() {
        let from = "يلتزم الطرف الأول بالدفع خلال ثلاثين يوماً";
        let to = "يلتزم الطرف الأول بالدفع خلال ستين يوماً";
        let changes = word_diff(from, to);
        assert_eq!(
            changes,
            vec![
                Change {
                    op: "equal",
                    text: "يلتزم الطرف الأول بالدفع خلال".into()
                },
                Change {
                    op: "delete",
                    text: "ثلاثين".into()
                },
                Change {
                    op: "insert",
                    text: "ستين".into()
                },
                Change {
                    op: "equal",
                    text: "يوماً".into()
                },
            ]
        );
        let s = sections("المادة 1: الدفع\nيلتزم الطرف الأول بالدفع\nالمادة 2: المسؤولية\nنص");
        assert_eq!(s.len(), 2);
        assert_eq!(title_key("المادة 1: الدفع"), "الدفع");
    }
}
