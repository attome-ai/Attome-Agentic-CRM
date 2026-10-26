//! Asking search in words (roadmap A25-T7): `GET /api/v1/search?mode=ask`.
//!
//! The query goes to the model action `search.parse_filter` through the
//! [`attome_core::search_ask::SearchAsker`] seam (this crate sits below the
//! AI engine). A parsed filter is a QuerySpec `{entity, where}` already
//! checked against the caller's metadata; it is shown in the response
//! (`ask.filter`) and run through the query engine as the caller
//! (`attome_records::query_spec::execute_spec`: record and field security in
//! the SQL), so the results are exactly the filter's. A declined parse runs
//! the plain search and says why. A question ("who…", "هل…", "…?") also gets
//! a direct answer from the top [`ANSWER_FROM`] results, through
//! `search.answer_records`, which reads each as the caller and cites only
//! those.
//!
//! One page only: the query engine pages by cursor, not by page number.

use std::sync::Arc;

use attome_core::EngineState;
use attome_records::query_spec::{QuerySpec, RunResponse, execute_spec};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::Serialize;
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::router::Audience;
use crate::routes::{SearchHit, SearchOptions, SearchResponse, Total, execute_search_with};

/// The results a direct answer reads.
pub const ANSWER_FROM: usize = 10;

/// What asking did, beside the results.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AskResult {
    /// `parsed` (the filter ran) or `declined` (a plain search ran).
    pub status: String,
    /// The filter the words became: `{entity, where}`, the `query/run` form.
    #[schema(value_type = Option<Object>)]
    pub filter: Option<Value>,
    /// Why there is no filter, when declined.
    pub reason: Option<String>,
    /// For a question: `{answer, citations}` or `{answer: null, reason}`.
    #[schema(value_type = Option<Object>)]
    pub answer: Option<Value>,
}

/// Whether `q` reads as a question, in English or Arabic. Pure.
pub fn is_question(q: &str) -> bool {
    let q = q.trim();
    if q.ends_with('?') || q.ends_with('؟') {
        return true;
    }
    let first = q
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_lowercase();
    const WORDS: &[&str] = &[
        "what",
        "who",
        "which",
        "when",
        "where",
        "why",
        "how",
        "is",
        "are",
        "does",
        "do",
        "did",
        "can",
        "ما",
        "ماذا",
        "من",
        "متى",
        "أين",
        "اين",
        "كيف",
        "لماذا",
        "هل",
        "كم",
    ];
    WORDS.contains(&first.as_str())
}

/// The search for `q` in words, as `ctx` (see the module docs).
pub async fn ask_search(
    state: &EngineState,
    ctx: Arc<SecurityContext>,
    q: &str,
    page: i64,
    page_size: i64,
    audience: Audience,
    options: SearchOptions,
) -> Result<SearchResponse, AppError> {
    if page != 1 {
        return Err(AppError::Validation(
            "mode=ask answers one page; narrow the words instead of paging".into(),
        ));
    }
    let asker = state
        .search_asker
        .clone()
        .ok_or(AppError::CapabilityUnavailable("search_ask"))?;
    let parsed = asker.parse_filter(state, ctx.clone(), q).await?;

    let filter = (parsed.get("status").and_then(Value::as_str) == Some("parsed"))
        .then(|| parsed.get("filter").cloned())
        .flatten();
    let (mut response, mut ask) = match filter {
        Some(filter) => {
            let spec: QuerySpec = serde_json::from_value(json!({
                "entity": filter.get("entity").cloned().unwrap_or(Value::Null),
                "where": filter.get("where").cloned().unwrap_or(Value::Null),
                "page_size": page_size,
            }))
            .map_err(|_| AppError::internal("search ask: a parsed filter did not decode"))?;
            let response = run_filter(state, &ctx, spec, page_size).await?;
            let ask = AskResult {
                status: "parsed".into(),
                filter: Some(filter),
                reason: None,
                answer: None,
            };
            (response, ask)
        }
        None => {
            let response =
                execute_search_with(state, &ctx, q, page, page_size, audience, options).await?;
            let ask = AskResult {
                status: "declined".into(),
                filter: None,
                reason: parsed
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                answer: None,
            };
            (response, ask)
        }
    };

    if is_question(q) {
        let records: Vec<(String, Uuid)> = response
            .items
            .iter()
            .take(ANSWER_FROM)
            .map(|h| (h.entity_logicalname.clone(), h.record_id))
            .collect();
        ask.answer = Some(if records.is_empty() {
            json!({ "answer": null, "reason": "not_found" })
        } else {
            asker.answer(state, ctx.clone(), q, &records).await?
        });
    }
    response.ask = Some(ask);
    Ok(response)
}

/// Runs a parsed filter as `ctx` and shapes its rows as search hits.
async fn run_filter(
    state: &EngineState,
    ctx: &SecurityContext,
    spec: QuerySpec,
    page_size: i64,
) -> Result<SearchResponse, AppError> {
    let entity = spec.entity.clone();
    let primary = state
        .entities
        .load()
        .get(&entity)
        .and_then(|e| e.primary_name_attribute.clone());
    let RunResponse::Rows(page) = execute_spec(state, ctx, spec).await? else {
        return Err(AppError::internal(
            "search ask: a filter answered without rows",
        ));
    };
    let items: Vec<SearchHit> = page
        .items
        .iter()
        .filter_map(|row| {
            let record_id = row
                .0
                .get("id")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())?;
            let title = primary
                .as_ref()
                .and_then(|p| row.0.get(p))
                .and_then(Value::as_str)
                .map(str::to_owned);
            Some(SearchHit {
                entity_logicalname: entity.clone(),
                record_id,
                title,
                subtitle: None,
                score: 1.0,
                matched_legs: vec!["ask".to_owned()],
                explain: None,
            })
        })
        .collect();
    let has_more = page.next_cursor.is_some();
    let found = items.len() as u64;
    Ok(SearchResponse {
        total: if has_more {
            Total::AtLeast { value: found }
        } else {
            Total::Exact { value: found }
        },
        items,
        page: 1,
        page_size,
        has_more,
        route: "ask".into(),
        degraded: Vec::new(),
        route_hint: None,
        impression_id: None,
        limited: false,
        facets: None,
        ask: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn questions_are_told_from_searches() {
        assert!(is_question("who owns the Al-Faisal account?"));
        assert!(is_question("How many open cases"));
        assert!(is_question("هل لدى الفيصل شكاوى مفتوحة"));
        assert!(is_question("كم عدد الشكاوى؟"));
        assert!(!is_question("open complaints from Al-Faisal last month"));
        assert!(!is_question("شكاوى الفيصل المفتوحة"));
        assert!(!is_question(""));
    }
}
