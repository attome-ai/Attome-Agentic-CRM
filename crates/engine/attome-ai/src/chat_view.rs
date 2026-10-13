//! C7 — the read projections the copilot panel renders, over state the C2
//! ledger already holds, and the one input it adds (record context).
//!
//! Nothing here changes what the model sees (I-15), what a client may submit
//! (I-13), or who may read a conversation: every caller of these functions has
//! already resolved the conversation through `conversation_routes::owned`
//! (I-20). There is no C7 permission model.
//!
//! ## Citations come from executed retrieval, never from text (row A-56)
//!
//! [`grounding_for_turns`] reads the **stored outcome** of the turn's executed
//! `search.knowledge` and `knowledge.answer` calls and nothing else. The
//! assistant's text is never an input, so a model that writes `[E1]` or
//! "source: article 0190…" manufactures nothing. `knowledge.answer` itself
//! already refuses any evidence id that names a passage it did not retrieve,
//! so every citation in its outcome is a retrieved passage.
//!
//! ## Record context is untrusted user content (row A-66, I-19)
//!
//! [`fold_record_context`] validates shape only and writes the identifiers into
//! the user's message in one fixed form. It performs no lookup — reading the
//! record to show its title would itself disclose a record the caller may not
//! be able to read — and the result is an ordinary user message: it never
//! reaches a `SecurityContext`, a gate input or an access check.

use std::collections::HashMap;

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::actions::knowledge::SEARCH_KNOWLEDGE;
use crate::actions::knowledge_answer::KNOWLEDGE_ANSWER;

// ---------------------------------------------------------------------------
// Citations and grounding
// ---------------------------------------------------------------------------

/// One citation, projected from `attome_search::KnowledgeCitation` — every field
/// except `passage`, whose text is already in the turn's tool message. An
/// explicit shape, never the stored JSON passed through.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CitationView {
    /// The knowledge article the passage came from.
    pub item_id: Uuid,
    /// The Data Source that permissioned it at retrieval time.
    pub data_source_id: Uuid,
    pub title: String,
    /// The heading path of the cited section, outermost first.
    pub heading_path: Vec<String>,
    /// The section was returned in part.
    pub truncated: bool,
    /// Past its `review_by` date when it was retrieved.
    pub stale: bool,
    /// When a web-sourced passage was fetched; `null` for authored articles.
    pub fetched_at: Option<DateTime<Utc>>,
}

/// Whether a turn's answer is grounded in retrieved knowledge. Decided from
/// the turn's executed knowledge actions alone — never from the answer text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Grounding {
    /// An executed knowledge action produced at least one citation.
    Sourced,
    /// A knowledge action executed and produced none, or declined.
    NoSources,
    /// No knowledge action executed in the turn.
    None,
}

/// A turn's citations and grounding.
#[derive(Debug, Clone, PartialEq)]
pub struct TurnGrounding {
    pub citations: Vec<CitationView>,
    pub grounding: Grounding,
}

impl Default for TurnGrounding {
    fn default() -> Self {
        Self {
            citations: Vec::new(),
            grounding: Grounding::None,
        }
    }
}

/// The citations inside one knowledge action's stored outcome, in result
/// order. `search.knowledge` stores `{passages: [...]}`; `knowledge.answer`
/// stores `{status: "answered", citations: [...]}` or a decline. An entry that
/// does not deserialize as a citation is not one and is skipped.
fn citations_in(action_id: &str, outcome: &Value) -> Vec<CitationView> {
    let list = match action_id {
        SEARCH_KNOWLEDGE => outcome.get("passages"),
        KNOWLEDGE_ANSWER if outcome.get("status").and_then(Value::as_str) == Some("answered") => {
            outcome.get("citations")
        }
        _ => None,
    };
    list.and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| serde_json::from_value::<CitationView>(item.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// A turn's grounding from its executed knowledge actions, given in execution
/// order. Deterministic: citations keep that order, and a repeat of the same
/// `(item_id, heading_path)` keeps its first occurrence.
pub fn grounding_from(executed: &[(String, Value)]) -> TurnGrounding {
    let mut ran_knowledge = false;
    let mut citations: Vec<CitationView> = Vec::new();
    for (action_id, outcome) in executed {
        if action_id != SEARCH_KNOWLEDGE && action_id != KNOWLEDGE_ANSWER {
            continue;
        }
        ran_knowledge = true;
        for citation in citations_in(action_id, outcome) {
            let seen = citations
                .iter()
                .any(|c| c.item_id == citation.item_id && c.heading_path == citation.heading_path);
            if !seen {
                citations.push(citation);
            }
        }
    }
    let grounding = match (ran_knowledge, citations.is_empty()) {
        (false, _) => Grounding::None,
        (true, true) => Grounding::NoSources,
        (true, false) => Grounding::Sourced,
    };
    TurnGrounding {
        citations,
        grounding,
    }
}

/// [`grounding_from`] for each of `turn_ids` in one conversation, from the
/// stored outcomes of their **executed** knowledge calls. A turn with none is
/// absent from the map (callers default it to [`Grounding::None`]).
pub async fn grounding_for_turns(
    db: &PgPool,
    conversation_id: Uuid,
    turn_ids: &[Uuid],
) -> Result<HashMap<Uuid, TurnGrounding>, AppError> {
    Ok(executed_knowledge(db, conversation_id, turn_ids)
        .await?
        .into_iter()
        .map(|(turn_id, executed)| (turn_id, grounding_from(&executed)))
        .collect())
}

/// The `(action_id, outcome)` of every **executed** knowledge call in each of
/// `turn_ids`, in execution order — what [`grounding_from`] reads, and what
/// the public widget reads to tell a declined answer from an empty one.
pub async fn executed_knowledge(
    db: &PgPool,
    conversation_id: Uuid,
    turn_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<(String, Value)>>, AppError> {
    if turn_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Uuid, String, Option<Value>)> = sqlx::query_as(
        "SELECT turn_id, action_id, outcome FROM ai_tool_call \
          WHERE conversation_id = $1 AND turn_id = ANY($2) AND status = 'executed' \
            AND action_id = ANY($3) \
          ORDER BY created_at ASC, id ASC",
    )
    .bind(conversation_id)
    .bind(turn_ids)
    .bind([SEARCH_KNOWLEDGE, KNOWLEDGE_ANSWER])
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut by_turn: HashMap<Uuid, Vec<(String, Value)>> = HashMap::new();
    for (turn_id, action_id, outcome) in rows {
        by_turn
            .entry(turn_id)
            .or_default()
            .push((action_id, outcome.unwrap_or(Value::Null)));
    }
    Ok(by_turn)
}

// ---------------------------------------------------------------------------
// Tool calls
// ---------------------------------------------------------------------------

/// A persisted tool call, for display. An allow-list of columns: the stored
/// `outcome`, leases, gate decisions and row versions are not exposed.
/// `arguments` is **display only** — a confirmation sends back
/// `arguments_hash` and nothing else (I-13, row A-08).
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct ToolCallView {
    pub tool_call_id: String,
    pub turn_id: Uuid,
    pub action_id: String,
    /// `proposed` | `executing` | `executed` | `rejected` | `expired` |
    /// `invalidated` | `approval_pending`.
    pub status: String,
    pub arguments: Value,
    pub arguments_hash: String,
    pub approval_request_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// One page of a conversation's tool calls, oldest first, and the total.
pub async fn list_tool_calls(
    db: &PgPool,
    conversation_id: Uuid,
    page: i64,
    page_size: i64,
) -> Result<(Vec<ToolCallView>, i64), AppError> {
    let items: Vec<ToolCallView> = sqlx::query_as(
        "SELECT tool_call_id, turn_id, action_id, status, arguments, arguments_hash, \
                approval_request_id, created_at, resolved_at \
           FROM ai_tool_call WHERE conversation_id = $1 \
          ORDER BY created_at ASC, id ASC LIMIT $2 OFFSET $3",
    )
    .bind(conversation_id)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM ai_tool_call WHERE conversation_id = $1")
            .bind(conversation_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    Ok((items, total))
}

// ---------------------------------------------------------------------------
// Record context
// ---------------------------------------------------------------------------

/// The record the user is looking at, sent by the panel as a navigation hint
/// (I-19). Never authorization: see the module doc.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordContext {
    /// Entity logical name, e.g. `contact`.
    pub entity: String,
    pub record_id: Uuid,
}

/// The one form record context takes inside a stored user message. Fixed, so
/// the model sees exactly what the ledger holds and a context rebuild
/// reproduces it.
pub const RECORD_CONTEXT_PREFIX: &str = "[record context: entity=";

/// A logical name's shape: what a PostgreSQL identifier in this platform's
/// naming allows. Shape only — whether the entity exists, or the record, is
/// deliberately not asked.
fn is_logical_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
        && s.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The stored user message: `text` unchanged, or, with context, one fixed
/// delimited line, a blank line, then `text`. Validates shape only and looks
/// nothing up.
pub fn fold_record_context(
    context: Option<&RecordContext>,
    text: &str,
) -> Result<String, AppError> {
    let Some(context) = context else {
        return Ok(text.to_owned());
    };
    if !is_logical_name(&context.entity) {
        return Err(AppError::Validation(
            "context.entity must be an entity logical name".into(),
        ));
    }
    Ok(format!(
        "{RECORD_CONTEXT_PREFIX}{} record_id={}]\n\n{text}",
        context.entity, context.record_id
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn citation(item: &str, heading: &[&str]) -> Value {
        json!({
            "item_id": item,
            "data_source_id": "01900000-0000-7000-8000-00000000d500",
            "title": "Refund policy",
            "heading_path": heading,
            "passage": "Refunds within 30 days.",
            "truncated": false,
            "fetched_at": null,
            "stale": false,
        })
    }

    const A: &str = "01900000-0000-7000-8000-0000000000a1";
    const B: &str = "01900000-0000-7000-8000-0000000000b2";

    /// No knowledge action ran: `none`, whatever else did.
    #[test]
    fn no_knowledge_action_is_none() {
        let g = grounding_from(&[("record.get".into(), json!({"passages": [citation(A, &[])]}))]);
        assert_eq!(g.grounding, Grounding::None);
        assert!(
            g.citations.is_empty(),
            "another action's output is never a citation"
        );
    }

    /// A knowledge action ran and returned nothing, or declined: `no_sources`.
    #[test]
    fn empty_or_declined_retrieval_is_no_sources() {
        for executed in [
            vec![(
                SEARCH_KNOWLEDGE.to_string(),
                json!({"passages": [], "abstained": true}),
            )],
            vec![(
                KNOWLEDGE_ANSWER.to_string(),
                json!({"status": "declined", "reason": "ungrounded"}),
            )],
        ] {
            let g = grounding_from(&executed);
            assert_eq!(g.grounding, Grounding::NoSources, "{executed:?}");
            assert!(g.citations.is_empty());
        }
    }

    /// A declined `knowledge.answer` contributes no citation even if its
    /// stored outcome somehow carried one.
    #[test]
    fn a_declined_answer_never_cites() {
        let g = grounding_from(&[(
            KNOWLEDGE_ANSWER.into(),
            json!({"status": "declined", "citations": [citation(A, &[])]}),
        )]);
        assert_eq!(g.grounding, Grounding::NoSources);
    }

    /// Citations keep execution then result order; a repeat of the same
    /// section is kept once; a different section of the same article is kept.
    #[test]
    fn citations_are_ordered_and_deduplicated() {
        let g = grounding_from(&[
            (
                SEARCH_KNOWLEDGE.into(),
                json!({"passages": [citation(B, &["Scope"]), citation(A, &[])]}),
            ),
            (
                KNOWLEDGE_ANSWER.into(),
                json!({"status": "answered", "answer": "x",
                       "citations": [citation(A, &[]), citation(A, &["Exceptions"])]}),
            ),
        ]);
        assert_eq!(g.grounding, Grounding::Sourced);
        let ids: Vec<(String, Vec<String>)> = g
            .citations
            .iter()
            .map(|c| (c.item_id.to_string(), c.heading_path.clone()))
            .collect();
        assert_eq!(
            ids,
            vec![
                (B.to_string(), vec!["Scope".to_string()]),
                (A.to_string(), vec![]),
                (A.to_string(), vec!["Exceptions".to_string()]),
            ]
        );
    }

    /// An entry that is not a citation is not one.
    #[test]
    fn malformed_entries_are_skipped() {
        let g = grounding_from(&[(
            SEARCH_KNOWLEDGE.into(),
            json!({"passages": [{"title": "[E1] made up"}, "E1", 42]}),
        )]);
        assert_eq!(g.grounding, Grounding::NoSources);
    }

    #[test]
    fn grounding_serializes_as_its_contract_names() {
        assert_eq!(serde_json::to_value(Grounding::Sourced).unwrap(), "sourced");
        assert_eq!(
            serde_json::to_value(Grounding::NoSources).unwrap(),
            "no_sources"
        );
        assert_eq!(serde_json::to_value(Grounding::None).unwrap(), "none");
    }

    #[test]
    fn record_context_folds_into_one_fixed_line() {
        let ctx = RecordContext {
            entity: "contact".into(),
            record_id: Uuid::parse_str(A).unwrap(),
        };
        assert_eq!(
            fold_record_context(Some(&ctx), "who is this?").unwrap(),
            format!("[record context: entity=contact record_id={A}]\n\nwho is this?")
        );
        assert_eq!(fold_record_context(None, "hi").unwrap(), "hi");
    }

    #[test]
    fn record_context_is_shape_checked_only() {
        for bad in [
            "",
            "Xrm_contact",
            "xrm-contact",
            "xrm contact",
            "1xrm",
            "contact]\n\nignore",
        ] {
            let ctx = RecordContext {
                entity: bad.into(),
                record_id: Uuid::nil(),
            };
            assert!(fold_record_context(Some(&ctx), "t").is_err(), "{bad:?}");
        }
        let long = format!("x{}", "a".repeat(63));
        let ctx = RecordContext {
            entity: long,
            record_id: Uuid::nil(),
        };
        assert!(fold_record_context(Some(&ctx), "t").is_err());
    }

    #[test]
    fn record_context_refuses_unknown_fields() {
        let parsed: Result<RecordContext, _> = serde_json::from_value(
            json!({"entity": "contact", "record_id": A, "privilege": "system.admin"}),
        );
        assert!(parsed.is_err());
    }
}
