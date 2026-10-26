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

/// M6-T2: `flow_template.adapt`, a template's parameters mapped to local entities.
pub mod adapt_flow_template;
pub mod agent_playground;
pub mod agent_stats;
pub mod agent_supervise;
pub mod ai_field;
/// Z10-T11: read approvals and recommend, never decide.
pub mod approvals;
pub mod billing;
pub mod billing_payment;
pub mod billing_subscription;
pub mod bin;
pub mod bot_handoff;
pub mod bulk;
pub mod business;
/// Z12-T12: holidays an agent lists and proposes.
pub mod calendar;
/// L4-T7: the data catalogue tools.
pub mod catalog;
pub mod claim_check;
pub mod classify;
pub mod collections;
pub mod commission;
/// E6-T12: deliverability explanation and a cleaner segment draft.
pub mod deliverability;
pub mod draft_article;
pub mod draft_email;
pub mod duplicates;
/// Z11-T12: expression.validate and expression.spec.
pub mod expression;
pub mod extract_document;
pub mod followup;
/// L3-T8: governance.list_overdue, governance.propose_domains, governance.draft_policy.
pub mod governance;
pub mod graph;
/// Q2-T5: identity.broker_steps, identity.explain_signin_failure.
pub mod identity_assist;
/// AI3-T1: filing an inbound email on the records made from it.
/// A23-T11: agent tools for file imports.
pub mod import;
pub mod inbox;
pub mod knowledge;
pub mod knowledge_answer;
/// AI1-T1: the lead qualifier's consent-checked contact steps.
pub mod lead_qualifier;
/// L5-T8: lineage.downstream, lineage.upstream, lineage.impact.
pub mod lineage;
/// L1-T10: master.xref, master.preview_ranking, master.propose_release.
pub mod master;
pub mod meeting;
pub mod memory;
pub mod model_edit;
pub mod nl_query;
/// AB2-T12: the cluster's status and a switchover proposal.
pub mod ops_cluster;
/// AB4-T12: drill freshness and one drill's evidence, read only.
pub mod ops_drills;
/// AB3-T11: recovery readiness and the live recovery point, read only.
pub mod ops_recovery;
pub mod ops_slo;
/// AB8-T9: the latest platform upgrade, read only.
pub mod ops_upgrade;
/// L6-T8: profile.summary, profile.explain.
pub mod profile;
/// L2-T9: quality.explain_drop, quality.record_score, quality.propose_rules.
pub mod quality;
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
/// A25-T7: search.parse_filter and search.answer_records, and the search seam.
pub mod search_ask;
pub mod search_records;
pub mod secrets_list;
/// AH8 — `email.send`: sends now, or after an undo window.
pub mod send_email;
pub mod sentiment;
pub mod settings;
pub mod summary_context;
pub mod system_status;
/// Y2-T14, Y12-T12: read tools over an entity's table.
pub mod table;
pub mod transition;
pub mod translate;
// T2-T5: a page drafted from a description.
pub mod draft_page;
/// F6-T16: read-only fulfilment tools.
pub mod fulfilment;
/// E13-T11: search titles, descriptions, FAQ and links drafted for a page.
pub mod seo_draft;
pub mod workflow;
pub mod workforce;

use crate::descriptor::ActionDescriptor;

/// Every registered descriptor, in declaration order. `ActionRegistry` sorts
/// them; this is just the source of truth for what exists.
pub fn all() -> Vec<ActionDescriptor> {
    let mut all = read::descriptors();
    all.push(draft_article::descriptor());
    all.push(draft_email::descriptor());
    all.push(send_email::descriptor());
    all.push(inbox::descriptor());
    all.extend(graph::descriptors());
    all.push(knowledge::descriptor());
    all.push(knowledge_answer::descriptor());
    all.push(classify::descriptor());
    all.push(bot_handoff::descriptor());
    all.push(bot_handoff::to_person_descriptor());
    all.push(record_schema::descriptor());
    all.push(record_schema::validate_descriptor());
    all.push(record_update_field::descriptor());
    all.extend(business::descriptors());
    all.extend(search_ask::descriptors());
    all.extend(catalog::descriptors());
    all.extend(record_write::descriptors());
    all.extend(bulk::descriptors());
    all.extend(transition::descriptors());
    all.push(translate::descriptor());
    all.push(draft_page::descriptor());
    all.push(seo_draft::descriptor());
    all.push(sentiment::descriptor());
    all.push(adapt_flow_template::descriptor());
    all.extend(lineage::descriptors());
    all.extend(profile::descriptors());
    all.extend(quality::descriptors());
    all.extend(governance::descriptors());
    all.extend(master::descriptors());
    all.extend(identity_assist::descriptors());
    all.extend(expression::descriptors());
    all.push(extract_document::descriptor());
    all.push(ai_field::descriptor());
    all.extend(crate::mcp_client::descriptors());
    all.push(search_records::descriptor());
    all.push(system_status::descriptor());
    all.extend(ops_cluster::descriptors());
    all.extend(ops_drills::descriptors());
    all.extend(import::descriptors());
    all.extend(ops_recovery::descriptors());
    all.push(ops_slo::descriptor());
    all.push(ops_upgrade::descriptor());
    all.extend(approvals::descriptors());
    all.extend(calendar::descriptors());
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
    all.extend(workforce::descriptors());
    all.extend(fulfilment::descriptors());
    all.extend(crate::meeting::brief::descriptors());
    all.extend(crate::meeting::notes::descriptors());
    all.extend(meeting::descriptors());
    all.extend(collections::descriptors());
    all.extend(agent_stats::descriptors());
    all.extend(lead_qualifier::descriptors());
    all.extend(crate::ops_agent::descriptors());
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
    all.push(Box::new(send_email::EmailSend));
    all.push(Box::new(inbox::FileMessage));
    all.extend(graph::executors());
    all.push(Box::new(knowledge::SearchKnowledge));
    all.push(Box::new(knowledge_answer::KnowledgeAnswer));
    all.push(Box::new(classify::RecordClassify));
    all.push(Box::new(bot_handoff::BotHandoff));
    all.push(Box::new(bot_handoff::HandoffToPerson));
    all.push(Box::new(record_schema::RecordSchema));
    all.push(Box::new(record_schema::RecordValidate));
    all.push(Box::new(record_update_field::RecordUpdateField));
    all.extend(business::executors());
    all.extend(search_ask::executors());
    all.extend(catalog::executors());
    all.extend(record_write::executors());
    all.extend(bulk::executors());
    all.push(Box::new(transition::RecordTransitions));
    all.push(Box::new(transition::RecordTransition));
    all.push(Box::new(translate::TextTranslate));
    all.push(Box::new(draft_page::PageDraft));
    all.push(Box::new(seo_draft::SeoDraft));
    all.push(Box::new(sentiment::TextSentiment));
    all.push(Box::new(adapt_flow_template::FlowTemplateAdapt));
    all.extend(lineage::executors());
    all.extend(profile::executors());
    all.extend(quality::executors());
    all.extend(governance::executors());
    all.extend(master::executors());
    all.extend(identity_assist::executors());
    all.extend(expression::executors());
    all.push(Box::new(extract_document::DocumentExtract));
    all.push(Box::new(ai_field::RecordAiField));
    all.extend(crate::mcp_client::executors());
    all.push(Box::new(search_records::SearchRecords));
    all.push(Box::new(system_status::SystemStatus));
    all.extend(ops_cluster::executors());
    all.extend(ops_drills::executors());
    all.extend(import::executors());
    all.extend(ops_recovery::executors());
    all.push(Box::new(ops_slo::OpsSloHealth));
    all.push(Box::new(ops_upgrade::OpsUpgradeStatus));
    all.extend(approvals::executors());
    all.extend(calendar::executors());
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
    all.extend(workforce::executors());
    all.extend(fulfilment::executors());
    all.extend(crate::meeting::brief::executors());
    all.extend(crate::meeting::notes::executors());
    all.extend(meeting::executors());
    all.extend(collections::executors());
    all.extend(agent_stats::executors());
    all.extend(lead_qualifier::executors());
    all.extend(crate::ops_agent::executors());
    all
}
