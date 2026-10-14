//! The closed catalogue.
//!
//! Every action the platform can invoke is declared here. Adding one is a code
//! change and a release (invariant I-5) — there is no runtime registration
//! path, no plugin loader, and no "temporarily, just for the chatbot" list.
//!
//! **P1-A's first slice is read-only and deliberately small.** `record.get`
//! and `query.execute` need no search engine and no knowledge base, which is
//! the whole reason AI fields ship before either: a summarise-this-record
//! field operates on the record already open in the form.
//! `search.knowledge` registered with the Knowledge Base pipeline (M37/D-489);
//! `search.records` registered at C5, wrapping the same `execute_search` the
//! `GET /api/v1/search` route calls.

pub mod agent_playground;
pub mod agent_supervise;
pub mod ai_field;
pub mod bot_handoff;
pub mod bulk;
pub mod business;
pub mod claim_check;
pub mod classify;
pub mod draft_article;
pub mod draft_email;
pub mod extract_document;
pub mod graph;
pub mod knowledge;
pub mod knowledge_answer;
pub mod memory;
pub mod model_edit;
pub mod nl_query;
pub mod read;
pub mod record_schema;
pub mod record_update_field;
pub mod record_write;
pub mod route_classify;
pub mod search_records;
pub mod sentiment;
pub mod summary_context;
pub mod system_status;
pub mod transition;
pub mod translate;
pub mod workflow;

use crate::descriptor::ActionDescriptor;

/// Every registered descriptor, in declaration order. `ActionRegistry` sorts
/// them; this is just the source of truth for what exists.
pub fn all() -> Vec<ActionDescriptor> {
    let mut all = read::descriptors();
    all.push(draft_article::descriptor());
    all.push(draft_email::descriptor());
    all.extend(graph::descriptors());
    all.push(knowledge::descriptor());
    all.push(knowledge_answer::descriptor());
    all.push(classify::descriptor());
    all.push(bot_handoff::descriptor());
    all.push(record_schema::descriptor());
    all.push(record_schema::validate_descriptor());
    all.push(record_update_field::descriptor());
    all.extend(business::descriptors());
    all.extend(record_write::descriptors());
    all.extend(bulk::descriptors());
    all.extend(transition::descriptors());
    all.push(translate::descriptor());
    all.push(sentiment::descriptor());
    all.push(extract_document::descriptor());
    all.push(ai_field::descriptor());
    all.extend(crate::mcp_client::descriptors());
    all.push(search_records::descriptor());
    all.push(system_status::descriptor());
    all.push(nl_query::descriptor());
    all.extend(workflow::descriptors());
    all.extend(memory::descriptors());
    all.extend(model_edit::descriptors());
    all.push(route_classify::descriptor());
    all.extend(agent_supervise::descriptors());
    all.push(agent_playground::descriptor());
    all.push(crate::orchestrate::descriptor());
    all
}

/// Every executor. `execute::executors_cover_every_registered_action` pins this
/// against `all()` — a descriptor with no executor is an action a model can see
/// and cannot invoke, which teaches it that refusals are normal.
///
/// `pub(crate)`: `execute::Executors` is the only holder, so no other crate can
/// obtain an executor and call it around `dispatch` and the gate (C5).
pub(crate) fn all_executors() -> Vec<Box<dyn crate::execute::Action>> {
    let mut all = read::executors();
    all.push(Box::new(draft_article::ArticleDraft));
    all.push(Box::new(draft_email::EmailDraft));
    all.extend(graph::executors());
    all.push(Box::new(knowledge::SearchKnowledge));
    all.push(Box::new(knowledge_answer::KnowledgeAnswer));
    all.push(Box::new(classify::RecordClassify));
    all.push(Box::new(bot_handoff::BotHandoff));
    all.push(Box::new(record_schema::RecordSchema));
    all.push(Box::new(record_schema::RecordValidate));
    all.push(Box::new(record_update_field::RecordUpdateField));
    all.extend(business::executors());
    all.extend(record_write::executors());
    all.extend(bulk::executors());
    all.push(Box::new(transition::RecordTransitions));
    all.push(Box::new(transition::RecordTransition));
    all.push(Box::new(translate::TextTranslate));
    all.push(Box::new(sentiment::TextSentiment));
    all.push(Box::new(extract_document::DocumentExtract));
    all.push(Box::new(ai_field::RecordAiField));
    all.extend(crate::mcp_client::executors());
    all.push(Box::new(search_records::SearchRecords));
    all.push(Box::new(system_status::SystemStatus));
    all.push(Box::new(nl_query::QueryPlan));
    all.extend(workflow::executors());
    all.extend(memory::executors());
    all.extend(model_edit::executors());
    all.push(Box::new(route_classify::RouteClassify));
    all.extend(agent_supervise::executors());
    all.push(Box::new(agent_playground::AgentPlaygroundComplete));
    all.push(Box::new(crate::orchestrate::AgentDelegate));
    all
}
