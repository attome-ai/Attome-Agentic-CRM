//! L5-T2: the edge parsers for definitions `attome-core` can read on its own.
//!
//! - [`ExpressionSource`]: a formula, rollup or rule expression (the
//!   `attome-rules` language). Every field it reads becomes an attribute
//!   edge of the definition's entity; a lookup hop (`account.name`) is an
//!   edge on the lookup attribute, since the target entity is not known
//!   here. A lambda's parameter is not a field. An expression that does not
//!   parse becomes one `entity_only` edge.
//! - [`QueryTreeSource`]: a structured query (`{entity, select, filter, sort,
//!   group_by}`). The fields named in its select, filter (nested `and`/`or`
//!   included), sort and group become read edges. Raw SQL
//!   (`{sql, relations}`) is read as `entity_only` edges on every relation
//!   (before P2 adds column lineage).
//! - [`AttributeListSource`]: a view's columns or a form's fields.
//! - [`AgentSource`]: an agent definition's triggers. Its tools' argument
//!   schemas name no attributes of their own, so only the entities it is
//!   triggered by are edges.

use serde_json::Value;

use super::{Edge, EdgeKind, EdgeSource};

/// An expression over one entity's fields.
#[derive(Debug, Clone)]
pub struct ExpressionSource {
    pub entity: String,
    /// `Derives` for a formula or rollup, `Reads` for a rule condition.
    pub kind: EdgeKind,
}

fn walk(expr: &attome_rules::Expr, params: &mut Vec<String>, out: &mut Vec<String>) {
    use attome_rules::Expr;
    match expr {
        Expr::FieldRef(field) => {
            if !params.contains(&field.base) {
                out.push(field.base.clone());
            }
        }
        Expr::Path(segments) => {
            if let Some(first) = segments.first()
                && !params.contains(first)
            {
                out.push(first.clone());
            }
        }
        Expr::ListLit(items) => items.iter().for_each(|e| walk(e, params, out)),
        Expr::Unary { expr, .. } => walk(expr, params, out),
        Expr::Binary { lhs, rhs, .. } => {
            walk(lhs, params, out);
            walk(rhs, params, out);
        }
        Expr::Call { args, .. } => args.iter().for_each(|e| walk(e, params, out)),
        Expr::Lambda { param, body } => {
            params.push(param.clone());
            walk(body, params, out);
            params.pop();
        }
        Expr::NullLit | Expr::BoolLit(_) | Expr::NumberLit(_) | Expr::StringLit(_) => {}
    }
}

impl EdgeSource for ExpressionSource {
    fn edges(&self, def: &Value) -> Vec<Edge> {
        let src = match def {
            Value::String(s) => s.as_str(),
            other => other["expression"].as_str().unwrap_or_default(),
        };
        match attome_rules::parse(src) {
            Ok(expr) => {
                let mut fields = Vec::new();
                walk(&expr, &mut Vec::new(), &mut fields);
                fields
                    .iter()
                    .map(|f| Edge::attribute(&self.entity, f, self.kind))
                    .collect()
            }
            Err(_) => vec![Edge::entity_only(&self.entity, self.kind)],
        }
    }
}

/// A structured query, or raw SQL with its relations.
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryTreeSource;

fn field_names(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| field_names(v, out)),
        Value::Object(map) => {
            for key in ["field", "attribute", "name"] {
                if let Some(name) = map.get(key).and_then(Value::as_str) {
                    out.push(name.to_owned());
                    return;
                }
            }
        }
        _ => {}
    }
}

fn filter_fields(filter: &Value, out: &mut Vec<String>) {
    match filter {
        Value::Array(items) => items.iter().for_each(|f| filter_fields(f, out)),
        Value::Object(map) => {
            if let Some(field) = map.get("field").and_then(Value::as_str) {
                out.push(field.to_owned());
            }
            for key in ["and", "or", "not", "conditions", "filters"] {
                if let Some(inner) = map.get(key) {
                    filter_fields(inner, out);
                }
            }
        }
        _ => {}
    }
}

impl EdgeSource for QueryTreeSource {
    fn edges(&self, def: &Value) -> Vec<Edge> {
        if def.get("sql").is_some() {
            return def["relations"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|entity| Edge::entity_only(entity, EdgeKind::Reads))
                .collect();
        }
        let Some(entity) = def["entity"].as_str() else {
            return Vec::new();
        };
        let mut fields = Vec::new();
        for key in ["select", "columns", "sort", "order_by", "group_by"] {
            if let Some(list) = def.get(key) {
                field_names(list, &mut fields);
            }
        }
        if let Some(filter) = def.get("filter") {
            filter_fields(filter, &mut fields);
        }
        if fields.is_empty() {
            return vec![Edge::entity(entity, EdgeKind::Reads)];
        }
        fields
            .iter()
            .filter(|f| f.as_str() != "*")
            .map(|f| Edge::attribute(entity, f, EdgeKind::Reads))
            .collect()
    }
}

/// The attributes a view shows or a form edits.
#[derive(Debug, Clone)]
pub struct AttributeListSource {
    pub entity: String,
    /// `Reads` for a view, `Writes` for a form.
    pub kind: EdgeKind,
}

impl EdgeSource for AttributeListSource {
    fn edges(&self, def: &Value) -> Vec<Edge> {
        let mut fields = Vec::new();
        for key in ["columns", "fields", "attributes"] {
            if let Some(list) = def.get(key) {
                field_names(list, &mut fields);
            }
        }
        fields
            .iter()
            .map(|f| Edge::attribute(&self.entity, f, self.kind))
            .collect()
    }
}

/// An agent definition: the entities it is triggered by.
#[derive(Debug, Clone, Copy, Default)]
pub struct AgentSource;

impl EdgeSource for AgentSource {
    fn edges(&self, def: &Value) -> Vec<Edge> {
        def["triggers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t["entity"].as_str())
            .map(|entity| Edge::entity(entity, EdgeKind::Triggers))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lineage::{Confidence, merge};
    use serde_json::json;

    #[test]
    fn formula_edges_attribute_level() {
        let source = ExpressionSource {
            entity: "opportunity".into(),
            kind: EdgeKind::Derives,
        };
        let edges = source.edges(&json!("amount * (1 - discount / 100) + account.credit"));
        let attrs: Vec<&str> = edges
            .iter()
            .filter_map(|e| e.to_attribute.as_deref())
            .collect();
        assert_eq!(attrs, vec!["amount", "discount", "account"]);
        assert!(edges.iter().all(|e| e.confidence == Confidence::Parsed));
        let object = source.edges(&json!({ "expression": "stage == \"won\"" }));
        assert_eq!(
            object,
            vec![Edge::attribute("opportunity", "stage", EdgeKind::Derives)]
        );
    }

    #[test]
    fn query_tree_edges() {
        let edges = QueryTreeSource.edges(&json!({
            "entity": "lead",
            "select": ["name", { "field": "score" }],
            "filter": { "and": [{ "field": "status", "op": "eq", "value": "open" },
                                { "or": [{ "field": "source" }] }] },
            "sort": [{ "field": "created_at", "dir": "desc" }]
        }));
        let attrs: Vec<String> = merge(edges)
            .into_iter()
            .filter_map(|e| e.to_attribute)
            .collect();
        assert_eq!(
            attrs,
            vec!["created_at", "name", "score", "source", "status"]
        );
    }

    #[test]
    fn unparseable_is_entity_only() {
        let source = ExpressionSource {
            entity: "invoice".into(),
            kind: EdgeKind::Reads,
        };
        let edges = source.edges(&json!("amount >>> ("));
        assert_eq!(edges, vec![Edge::entity_only("invoice", EdgeKind::Reads)]);
        let sql = QueryTreeSource.edges(&json!({
            "sql": "SELECT * FROM invoice JOIN account ON true",
            "relations": ["invoice", "account"]
        }));
        assert_eq!(sql.len(), 2);
        assert!(
            sql.iter()
                .all(|e| e.confidence == Confidence::EntityOnly && e.to_attribute.is_none())
        );
    }

    #[test]
    fn lineage_merge_keeps_the_strongest_use() {
        let merged = merge(vec![
            Edge::attribute("case", "status", EdgeKind::Reads),
            Edge::attribute("case", "status", EdgeKind::Writes),
            Edge::entity_only("case", EdgeKind::Reads),
            Edge::entity("case", EdgeKind::Triggers),
        ]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[1].kind, EdgeKind::Writes);
        assert_eq!(merged[0].kind, EdgeKind::Reads, "reads outrank triggers");
        assert_eq!(merged[0].confidence, Confidence::Parsed);
        assert_eq!(
            AgentSource
                .edges(&json!({ "triggers": [{ "kind": "record_change", "entity": "case" }] })),
            vec![Edge::entity("case", EdgeKind::Triggers)]
        );
        let form = AttributeListSource {
            entity: "case".into(),
            kind: EdgeKind::Writes,
        };
        assert_eq!(form.edges(&json!({ "fields": ["subject"] })).len(), 1);
    }
}
