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
pub mod billing;
pub mod billing_payment;
pub mod billing_subscription;
pub mod bin;
pub mod bot_handoff;
pub mod bulk;
pub mod business;
pub mod claim_check;
pub mod classify;
pub mod commission;
/// E6-T12: deliverability explanation and a cleaner segment draft.
pub mod deliverability;
pub mod draft_article;
pub mod draft_email;
pub mod duplicates;
pub mod extract_document;
pub mod followup;
pub mod graph;
pub mod knowledge;
pub mod knowledge_answer;
pub mod memory;
pub mod model_edit;
pub mod nl_query;
pub mod ops_slo;
pub mod read;
pub mod record_schema;
pub mod record_update_field;
pub mod record_write;
pub mod route_classify;
pub mod sales_competitors;
/// D21-T9: draft call lists, reorder a list, draft call notes. Nothing dials.
pub mod sales_dialer;
pub mod sales_lines;
pub mod sales_orgchart;
pub mod sales_team;
/// B16-T13: scan.lookup and code.generate.
pub mod scan;
pub mod search_records;
pub mod secrets_list;
pub mod settings;
pub mod sentiment;
pub mod summary_context;
pub mod system_status;
/// Y2-T14, Y12-T12: read tools over an entity's table.
pub mod table;
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
    all.push(ops_slo::descriptor());
    all.push(secrets_list::descriptor());
    all.push(settings::list_descriptor());
    all.push(settings::set_descriptor());
    all.push(table::health_descriptor());
    all.push(table::index_proposals_descriptor());
    all.push(table::change_plan_descriptor());
    all.push(bin::descriptor());
    all.push(nl_query::descriptor());
    all.extend(workflow::descriptors());
    all.extend(memory::descriptors());
    all.extend(model_edit::descriptors());
    all.push(route_classify::descriptor());
    all.extend(agent_supervise::descriptors());
    all.push(agent_playground::descriptor());
    all.push(crate::orchestrate::descriptor());
    all.extend(duplicates::descriptors());
    all.extend(followup::descriptors());
    all.extend(commission::descriptors());
    all.extend(sales_lines::descriptors());
    all.extend(sales_competitors::descriptors());
    all.extend(billing::descriptors());
    all.extend(billing_payment::descriptors());
    all.extend(billing_subscription::descriptors());
    all.extend(deliverability::descriptors());
    all.extend(sales_dialer::descriptors());
    all.extend(sales_orgchart::descriptors());
    all.extend(sales_team::descriptors());
    all.extend(scan::descriptors());
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
    all.push(Box::new(ops_slo::OpsSloHealth));
    all.push(Box::new(secrets_list::SecretsList));
    all.push(Box::new(settings::SettingsList));
    all.push(Box::new(settings::SettingsSet));
    all.push(Box::new(table::TableHealthTool));
    all.push(Box::new(table::TableIndexProposalsTool));
    all.push(Box::new(table::TableChangePlanTool));
    all.push(Box::new(bin::RecordDeleted));
    all.push(Box::new(nl_query::QueryPlan));
    all.extend(workflow::executors());
    all.extend(memory::executors());
    all.extend(model_edit::executors());
    all.push(Box::new(route_classify::RouteClassify));
    all.extend(agent_supervise::executors());
    all.push(Box::new(agent_playground::AgentPlaygroundComplete));
    all.push(Box::new(crate::orchestrate::AgentDelegate));
    all.extend(duplicates::executors());
    all.extend(followup::executors());
    all.extend(commission::executors());
    all.extend(sales_lines::executors());
    all.extend(sales_competitors::executors());
    all.extend(billing::executors());
    all.extend(billing_payment::executors());
    all.extend(billing_subscription::executors());
    all.extend(deliverability::executors());
    all.extend(sales_dialer::executors());
    all.extend(sales_orgchart::executors());
    all.extend(sales_team::executors());
    all.extend(scan::executors());
    all
}
