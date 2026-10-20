//! Dashboard 10/10 Phase 3.5 — health becomes a publish gate.
//!
//! [`do_publish_gate`] inspects the working copy exactly as publish would
//! capture it and sorts what it finds:
//!
//! **Blocking** (publish and activate refuse): a broken or unpublishable
//! query/view reference; an invalid `config.data`, `config.bindings` or
//! declarative config; a binding to a parameter the widget's page does not
//! declare or to a variable the widget does not listen to; a governed KPI
//! naming a missing metric; a tree over the page/section/widget ceilings; a page
//! with no root section.
//!
//! **Warnings** (shown, never block): a widget type with no renderer; a KPI
//! metric with no successful snapshot yet; a newer version of a pinned query.
//!
//! [`PUBLISH_GATE_WARN_ONLY`] is the one-release rollback switch the plan
//! requires: while `true` every blocking issue is reported but publish
//! proceeds.
use std::collections::BTreeSet;

use attome_core::EngineState;
use attome_core::data_definition::{Binding, BindingSource};
use attome_types::AppError;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::execution::{
    DataClass, classify, collect_widgets, declared_parameters, kpi_metric_refs, listened_variables,
    validate_widget_config, widget_config,
};
use crate::widget_registry::{RenderKind, registry};

/// While `true`, blocking issues are reported but do not refuse publish.
pub const PUBLISH_GATE_WARN_ONLY: bool = false;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GateIssue {
    /// A stable code, e.g. `invalid_data_definition`, `undeclared_parameter`.
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widget_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct PublishGate {
    pub blocking: Vec<GateIssue>,
    pub warnings: Vec<GateIssue>,
}

impl PublishGate {
    pub fn publishable(&self) -> bool {
        PUBLISH_GATE_WARN_ONLY || self.blocking.is_empty()
    }

    /// The 422 a refused publish or activate returns, naming every issue.
    pub fn refusal(&self) -> AppError {
        let issues = self
            .blocking
            .iter()
            .map(|issue| match &issue.widget_id {
                Some(widget) => format!("widget {widget}: {} ({})", issue.message, issue.code),
                None => format!("{} ({})", issue.message, issue.code),
            })
            .collect::<Vec<_>>()
            .join("; ");
        AppError::Validation(format!("publish blocked by the health gate: {issues}"))
    }

    fn block(&mut self, code: &str, message: String, page: Option<&str>, widget: Option<&str>) {
        self.blocking.push(GateIssue {
            code: code.to_owned(),
            message,
            page_id: page.map(str::to_owned),
            widget_id: widget.map(str::to_owned),
        });
    }

    fn warn(&mut self, code: &str, message: String, page: Option<&str>, widget: Option<&str>) {
        self.warnings.push(GateIssue {
            code: code.to_owned(),
            message,
            page_id: page.map(str::to_owned),
            widget_id: widget.map(str::to_owned),
        });
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
}

/// Checks a widget's bindings against what its page declares and what the
/// widget listens to.
fn check_bindings(
    gate: &mut PublishGate,
    bindings: &[Binding],
    declared: &BTreeSet<String>,
    listens: &[String],
    page: Option<&str>,
    widget: Option<&str>,
) {
    for binding in bindings {
        match binding.source {
            BindingSource::Parameter if !declared.contains(&binding.name) => gate.block(
                "undeclared_parameter",
                format!(
                    "binds parameter {} which this page does not declare",
                    binding.name
                ),
                page,
                widget,
            ),
            BindingSource::Variable if !listens.contains(&binding.name) => gate.block(
                "unlistened_variable",
                format!("binds variable {} without listening to it", binding.name),
                page,
                widget,
            ),
            _ => {}
        }
    }
}

/// The gate for `dashboard_id`'s working copy. Performs no authorization.
pub async fn do_publish_gate(
    state: &EngineState,
    dashboard_id: Uuid,
) -> Result<PublishGate, AppError> {
    let db = &state.base.db;
    let snapshot = crate::lifecycle::do_load_draft(db, dashboard_id).await?;
    let mut gate = PublishGate::default();
    let pages = snapshot
        .get("pages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if pages.len() > crate::layout::MAX_PAGES {
        gate.block(
            "tree_over_bounds",
            format!(
                "{} pages exceed the {} page ceiling",
                pages.len(),
                crate::layout::MAX_PAGES
            ),
            None,
            None,
        );
    }
    let mut widget_count = 0usize;
    let mut section_count = 0usize;
    for page in &pages {
        let page_id = text(page, "id");
        let sections = page
            .get("sections")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if sections.is_empty() {
            gate.block(
                "page_without_root_section",
                "this page has no root section".to_owned(),
                page_id,
                None,
            );
        }
        fn count_sections(sections: &[Value]) -> usize {
            sections
                .iter()
                .map(|s| {
                    1 + s
                        .get("children")
                        .and_then(Value::as_array)
                        .map_or(0, |c| count_sections(c))
                })
                .sum()
        }
        section_count += count_sections(&sections);

        let declared: BTreeSet<String> = declared_parameters(&snapshot, page_id)
            .into_iter()
            .map(|p| p.name)
            .collect();
        let mut widgets = Vec::new();
        collect_widgets(page, &mut widgets);
        widget_count += widgets.len();
        for widget in widgets {
            check_widget(state, &mut gate, page_id, widget, &declared).await?;
        }
    }
    if section_count > crate::layout::MAX_SECTIONS {
        gate.block(
            "tree_over_bounds",
            format!(
                "{section_count} sections exceed the {} section ceiling",
                crate::layout::MAX_SECTIONS
            ),
            None,
            None,
        );
    }
    if widget_count > crate::layout::MAX_WIDGETS {
        gate.block(
            "tree_over_bounds",
            format!(
                "{widget_count} widgets exceed the {} widget ceiling",
                crate::layout::MAX_WIDGETS
            ),
            None,
            None,
        );
    }

    let health = crate::health::do_health_check(db, dashboard_id).await?;
    for dep in health
        .live_version_dependencies
        .iter()
        .filter(|d| d.newer_version_available)
    {
        gate.warn(
            "newer_query_version",
            format!(
                "query {} has a newer version than the live one; publishing adopts it",
                dep.query_id
            ),
            None,
            Some(&dep.widget_id),
        );
    }
    Ok(gate)
}

/// Whether a declarative config names an action (`actions[]` or an `action`
/// column link) — Phase 4.5: the viewer renders them as text.
fn declares_actions(config: &serde_json::Map<String, Value>) -> bool {
    let listed = config
        .get("actions")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty());
    let linked = config
        .get("columns")
        .and_then(Value::as_array)
        .is_some_and(|columns| {
            columns.iter().any(|c| {
                c.get("link")
                    .and_then(|l| l.get("kind"))
                    .and_then(Value::as_str)
                    == Some("action")
            })
        });
    listed || linked
}

async fn check_widget(
    state: &EngineState,
    gate: &mut PublishGate,
    page_id: Option<&str>,
    widget: &Value,
    declared: &BTreeSet<String>,
) -> Result<(), AppError> {
    let db = &state.base.db;
    let widget_id = text(widget, "id");
    let widget_type = text(widget, "widget_type").unwrap_or_default();
    if registry().render_kind(widget_type) == RenderKind::Unsupported {
        gate.warn(
            "unsupported_widget_type",
            format!("widget type {widget_type} has no renderer; viewers see an unsupported state"),
            page_id,
            widget_id,
        );
    }
    let config = widget_config(widget);
    let listens = listened_variables(widget);
    for error in validate_widget_config(&config, &state.entities.load()) {
        gate.block("invalid_data_definition", error, page_id, widget_id);
    }

    match classify(widget).0 {
        DataClass::Structured => {
            if let Some(bindings) = config
                .get("data")
                .and_then(|d| d.get("bindings"))
                .and_then(|b| serde_json::from_value::<Vec<Binding>>(b.clone()).ok())
            {
                check_bindings(gate, &bindings, declared, &listens, page_id, widget_id);
            }
        }
        DataClass::Query => {
            if let Some(bindings) = config
                .get("bindings")
                .and_then(|b| serde_json::from_value::<Vec<Binding>>(b.clone()).ok())
            {
                check_bindings(gate, &bindings, declared, &listens, page_id, widget_id);
            }
            if widget_type == "declarative_widget" {
                match crate::declarative_widget::validate_config(&Value::Object(config.clone())) {
                    Err(errors) => {
                        for error in errors {
                            gate.block("invalid_declarative_config", error, page_id, widget_id);
                        }
                    }
                    Ok(_) if declares_actions(&config) => gate.warn(
                        "declarative_actions_not_executed",
                        "action links and actions render as plain text; dashboards do not invoke actions"
                            .to_string(),
                        page_id,
                        widget_id,
                    ),
                    Ok(_) => {}
                }
            }
            check_query_reference(db, gate, page_id, widget, &config).await?;
        }
        DataClass::Kpi => {
            for metric_id in kpi_metric_refs(widget) {
                let exists: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM dashboard_metric_definition \
                     WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
                )
                .bind(metric_id)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?;
                if exists.is_none() {
                    gate.block(
                        "missing_metric",
                        format!("metric {metric_id} is missing or inactive"),
                        page_id,
                        widget_id,
                    );
                    continue;
                }
                let has_snapshot: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM metric_snapshot \
                     WHERE metric_ref = $1 AND status <> 'failed' \
                       AND dimension_attribute IS NULL)",
                )
                .bind(metric_id)
                .fetch_one(db)
                .await
                .map_err(AppError::internal)?;
                if !has_snapshot {
                    gate.warn(
                        "metric_without_snapshot",
                        format!("metric {metric_id} has no successful snapshot yet"),
                        page_id,
                        widget_id,
                    );
                }
            }
        }
        DataClass::None => {}
    }
    Ok(())
}

async fn check_query_reference(
    db: &attome_db::DbPool,
    gate: &mut PublishGate,
    page_id: Option<&str>,
    widget: &Value,
    config: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    let widget_id = text(widget, "id");
    let query_uuid = match text(widget, "view_id") {
        Some(view) => {
            let Ok(view_id) = Uuid::parse_str(view) else {
                gate.block(
                    "broken_reference",
                    format!("view_id {view} is not a valid id"),
                    page_id,
                    widget_id,
                );
                return Ok(());
            };
            let query: Option<Uuid> = sqlx::query_scalar(
                "SELECT sql_query_ref FROM view \
                 WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
            )
            .bind(view_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
            match query {
                Some(query) => query,
                None => {
                    gate.block(
                        "broken_reference",
                        format!("view {view} no longer exists"),
                        page_id,
                        widget_id,
                    );
                    return Ok(());
                }
            }
        }
        None => {
            let raw = text(widget, "query_id")
                .or_else(|| config.get("query_ref").and_then(Value::as_str));
            let Some(raw) = raw else {
                return Ok(());
            };
            match Uuid::parse_str(raw) {
                Ok(id) => id,
                Err(_) => {
                    gate.block(
                        "broken_reference",
                        format!("query id {raw} is not a valid id"),
                        page_id,
                        widget_id,
                    );
                    return Ok(());
                }
            }
        }
    };
    let published: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sql_query_version v WHERE v.query_id = q.id) \
         FROM sql_query q \
         WHERE q.id = $1 AND (q.is_active IS NULL OR q.is_active = true)",
    )
    .bind(query_uuid)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    match published {
        None => gate.block(
            "broken_reference",
            format!("query {query_uuid} is missing or inactive"),
            page_id,
            widget_id,
        ),
        Some(false) => gate.block(
            "query_not_publishable",
            format!("query {query_uuid} has no published version"),
            page_id,
            widget_id,
        ),
        Some(true) => {}
    }
    Ok(())
}

/// The gate for making a stored version live (rollback): every query and
/// metric it was published against must still be active. A version whose
/// pinned query was deactivated would render nothing but errors.
pub async fn do_activate_gate(
    state: &EngineState,
    dashboard_id: Uuid,
    version_id: Uuid,
) -> Result<PublishGate, AppError> {
    let db = &state.base.db;
    let snapshot: Option<String> = sqlx::query_scalar(
        "SELECT snapshot_json FROM dashboard_version \
         WHERE id = $1 AND dashboard_id = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(version_id)
    .bind(dashboard_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let snapshot: Value = match snapshot {
        Some(raw) => serde_json::from_str(&raw)
            .map_err(|e| AppError::internal(format!("corrupt version snapshot: {e}")))?,
        None => return Err(AppError::NotFound),
    };
    let mut gate = PublishGate::default();
    for dep in snapshot
        .get("dependencies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let widget_id = text(&dep, "widget_id").map(str::to_owned);
        let Some(query_id) = text(&dep, "query_id").and_then(|q| Uuid::parse_str(q).ok()) else {
            continue;
        };
        let active: Option<bool> = sqlx::query_scalar(
            "SELECT (is_active IS NULL OR is_active = true) FROM sql_query WHERE id = $1",
        )
        .bind(query_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        if active != Some(true) {
            gate.block(
                "version_dependency_inactive",
                format!("query {query_id} this version was published with is missing or inactive"),
                None,
                widget_id.as_deref(),
            );
        }
    }
    for dep in snapshot
        .get("metric_dependencies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let widget_id = text(&dep, "widget_id").map(str::to_owned);
        let Some(metric_id) = text(&dep, "metric_id").and_then(|m| Uuid::parse_str(m).ok()) else {
            continue;
        };
        let active: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM dashboard_metric_definition \
             WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(metric_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        if active.is_none() {
            gate.block(
                "version_dependency_inactive",
                format!(
                    "metric {metric_id} this version was published with is missing or inactive"
                ),
                None,
                widget_id.as_deref(),
            );
        }
    }
    Ok(gate)
}

#[cfg(test)]
mod tests {
    use super::declares_actions;
    use serde_json::json;

    fn map(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn declared_actions_are_detected_in_either_place() {
        assert!(declares_actions(&map(
            json!({ "actions": ["record.get"], "columns": [] })
        )));
        assert!(declares_actions(&map(json!({
            "columns": [{ "field": "name", "link": { "kind": "action", "action_id": "record.get" } }]
        }))));
        assert!(!declares_actions(&map(json!({
            "actions": [],
            "columns": [{ "field": "name", "link": { "kind": "external", "target": "https://x/{id}" } }]
        }))));
    }
}
