//! L5-T6: the lineage graph as OpenLineage events, for an enterprise data
//! catalogue to pull.
//!
//! `GET /api/v1/lineage/export/openlineage` (administrators) returns one
//! OpenLineage `RunEvent` (`COMPLETE`) per definition in the current graph:
//! the definition is the job (`<kind>:<id>`, its label as the documentation
//! facet, its kind as the job type), what it reads or derives from are its
//! input datasets and what it writes its outputs. A dataset is an entity
//! (with the attributes the job uses as its schema facet's fields) or, for
//! a definition used by another (a metric a dashboard shows), that
//! definition. Only names leave: no record value is read, and the edges
//! themselves hold none.
//!
//! The route is off unless the setting `lineage.export_enabled` is true,
//! and each export is audited as a data export. Nothing is pushed: the
//! customer's catalogue pulls.

use std::collections::{BTreeMap, BTreeSet};

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_core::lineage::graph::{self, Edge, NodeRef};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Query, State},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The setting that turns the export on.
pub const EXPORT_SETTING: &str = "lineage.export_enabled";

const PRODUCER: &str = "https://github.com/attome-ai/Attome-Agentic-CRM";
const RUN_EVENT_SCHEMA: &str =
    "https://openlineage.io/spec/2-0-2/OpenLineage.json#/definitions/RunEvent";
const JOB_TYPE_FACET: &str = "https://openlineage.io/spec/facets/2-0-3/JobTypeJobFacet.json";
const DOCUMENTATION_FACET: &str =
    "https://openlineage.io/spec/facets/1-0-1/DocumentationJobFacet.json";
const SCHEMA_FACET: &str = "https://openlineage.io/spec/facets/1-1-1/SchemaDatasetFacet.json";

/// The namespace when the caller names none.
const DEFAULT_NAMESPACE: &str = "attome";

/// What one job uses: dataset name to the attributes used.
type Datasets = BTreeMap<String, BTreeSet<String>>;

fn dataset(node: &NodeRef) -> (String, Option<String>) {
    match node {
        NodeRef::Data { entity, attribute } => (entity.clone(), attribute.clone()),
        NodeRef::Definition { .. } => (node.key(), None),
    }
}

fn datasets_json(namespace: &str, sets: &Datasets) -> Vec<Value> {
    sets.iter()
        .map(|(name, fields)| {
            let mut set = json!({ "namespace": namespace, "name": name });
            if !fields.is_empty() {
                set["facets"] = json!({
                    "schema": {
                        "_producer": PRODUCER,
                        "_schemaURL": SCHEMA_FACET,
                        "fields": fields.iter().map(|f| json!({ "name": f })).collect::<Vec<_>>(),
                    }
                });
            }
            set
        })
        .collect()
}

/// The OpenLineage events for `edges`: one per definition using anything.
/// Pure.
pub fn events(namespace: &str, at: DateTime<Utc>, edges: &[Edge]) -> Vec<Value> {
    let mut jobs: BTreeMap<String, (String, String, Datasets, Datasets)> = BTreeMap::new();
    for edge in edges {
        let NodeRef::Definition { kind, .. } = &edge.from else {
            continue;
        };
        let job = jobs.entry(edge.from.key()).or_insert_with(|| {
            (
                kind.clone(),
                edge.from_label.clone(),
                Datasets::new(),
                Datasets::new(),
            )
        });
        let (name, field) = dataset(&edge.to);
        let side = if edge.edge_kind == "writes" {
            &mut job.3
        } else {
            &mut job.2
        };
        let fields = side.entry(name).or_default();
        if let Some(field) = field {
            fields.insert(field);
        }
    }
    let time = at.to_rfc3339_opts(SecondsFormat::Millis, true);
    jobs.into_iter()
        .map(|(name, (kind, label, inputs, outputs))| {
            let mut facets = json!({
                "jobType": {
                    "_producer": PRODUCER,
                    "_schemaURL": JOB_TYPE_FACET,
                    "processingType": "BATCH",
                    "integration": "ATTOME",
                    "jobType": kind.to_ascii_uppercase(),
                }
            });
            if !label.is_empty() {
                facets["documentation"] = json!({
                    "_producer": PRODUCER,
                    "_schemaURL": DOCUMENTATION_FACET,
                    "description": label,
                });
            }
            json!({
                "eventType": "COMPLETE",
                "eventTime": time,
                "producer": PRODUCER,
                "schemaURL": RUN_EVENT_SCHEMA,
                "run": { "runId": Uuid::now_v7().to_string() },
                "job": { "namespace": namespace, "name": name, "facets": facets },
                "inputs": datasets_json(namespace, &inputs),
                "outputs": datasets_json(namespace, &outputs),
            })
        })
        .collect()
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OpenLineageQuery {
    /// The OpenLineage namespace the jobs and datasets are named in
    /// (default `attome`).
    pub namespace: Option<String>,
}

/// The exported events.
#[derive(Debug, Serialize, ToSchema)]
pub struct OpenLineageExport {
    /// OpenLineage `RunEvent`s, one per definition.
    #[schema(value_type = Vec<Object>)]
    pub events: Vec<Value>,
    /// The graph had more edges than one export reads.
    pub truncated: bool,
}

/// Export lineage as OpenLineage
///
/// Exports the lineage graph as OpenLineage events (metadata only).
#[utoipa::path(
    get,
    path = "/api/v1/lineage/export/openlineage",
    operation_id = "lineage_export_openlineage",
    tag = "admin",
    params(OpenLineageQuery),
    responses(
        (status = 200, description = "One OpenLineage RunEvent per definition", body = OpenLineageExport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "The export is off (lineage.export_enabled)", body = ErrorResponse),
        (status = 422, description = "The namespace is not a short name", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn openlineage(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Query(q): Query<OpenLineageQuery>,
) -> Result<Json<OpenLineageExport>, AppError> {
    let enabled = attome_core::setting_registry()
        .get(EXPORT_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !enabled {
        return Err(AppError::NotFound);
    }
    let namespace = q
        .namespace
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or(DEFAULT_NAMESPACE)
        .to_owned();
    if namespace.len() > 200 || namespace.chars().any(char::is_control) {
        return Err(AppError::Validation(
            "namespace is a name of at most 200 characters".into(),
        ));
    }
    let (edges, truncated) = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        graph::all_edges(&mut conn).await?
    };
    let events = events(&namespace, Utc::now(), &edges);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Export,
            ctx.user_id,
            "metadata_reference",
            None,
        )
        .named("lineage.export_openlineage")
        .comment(format!(
            "lineage exported as OpenLineage: {} job(s), namespace {namespace}",
            events.len()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(OpenLineageExport { events, truncated }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(from: &str, label: &str, to: NodeRef, kind: &str) -> Edge {
        let (k, id) = from.split_once(':').unwrap();
        Edge {
            from: NodeRef::Definition {
                kind: k.to_owned(),
                id: Uuid::parse_str(id).unwrap(),
            },
            from_label: label.to_owned(),
            to,
            edge_kind: kind.to_owned(),
            confidence: "exact".to_owned(),
        }
    }

    fn data(entity: &str, attribute: Option<&str>) -> NodeRef {
        NodeRef::Data {
            entity: entity.to_owned(),
            attribute: attribute.map(str::to_owned),
        }
    }

    const REPORT: &str = "query:01a16900-0000-7000-8000-000000000001";
    const FLOW: &str = "workflow:01a16900-0000-7000-8000-000000000002";

    #[test]
    fn maps_report_to_job_with_inputs() {
        let edges = vec![
            edge(
                REPORT,
                "Open deals by stage",
                data("opportunity", Some("stage")),
                "reads",
            ),
            edge(
                REPORT,
                "Open deals by stage",
                data("opportunity", Some("amount")),
                "reads",
            ),
            edge(
                REPORT,
                "Open deals by stage",
                data("account", None),
                "reads",
            ),
            edge(
                FLOW,
                "Close lost",
                data("opportunity", Some("status")),
                "writes",
            ),
        ];
        let out = events("acme", Utc::now(), &edges);
        assert_eq!(out.len(), 2);
        let report = out.iter().find(|e| e["job"]["name"] == REPORT).unwrap();
        assert_eq!(report["eventType"], "COMPLETE");
        assert_eq!(report["schemaURL"], RUN_EVENT_SCHEMA);
        assert_eq!(report["job"]["namespace"], "acme");
        assert_eq!(report["job"]["facets"]["jobType"]["jobType"], "QUERY");
        assert_eq!(
            report["job"]["facets"]["documentation"]["description"],
            "Open deals by stage"
        );
        let inputs = report["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0]["name"], "account");
        assert!(
            inputs[0].get("facets").is_none(),
            "an entity-only use has no fields"
        );
        assert_eq!(inputs[1]["name"], "opportunity");
        assert_eq!(
            inputs[1]["facets"]["schema"]["fields"],
            json!([{ "name": "amount" }, { "name": "stage" }])
        );
        assert!(report["outputs"].as_array().unwrap().is_empty());
        let flow = out.iter().find(|e| e["job"]["name"] == FLOW).unwrap();
        assert_eq!(flow["outputs"][0]["name"], "opportunity");
        assert!(flow["inputs"].as_array().unwrap().is_empty());
        assert!(Uuid::parse_str(report["run"]["runId"].as_str().unwrap()).is_ok());
    }

    /// Every string an event carries is a name from the graph or a fixed
    /// OpenLineage value: there is nowhere for a record value to be.
    #[test]
    fn no_record_values_exported() {
        let metric = "metric:01a16900-0000-7000-8000-000000000003";
        let edges = vec![
            edge(
                REPORT,
                "Deals",
                data("opportunity", Some("amount")),
                "derives",
            ),
            edge(
                REPORT,
                "Deals",
                NodeRef::Definition {
                    kind: "metric".into(),
                    id: Uuid::parse_str(&metric[7..]).unwrap(),
                },
                "reads",
            ),
        ];
        let at = Utc::now();
        let out = events("acme", at, &edges);
        let allowed: BTreeSet<String> = [
            "acme",
            REPORT,
            metric,
            "Deals",
            "opportunity",
            "amount",
            "COMPLETE",
            "BATCH",
            "ATTOME",
            "QUERY",
            PRODUCER,
            RUN_EVENT_SCHEMA,
            JOB_TYPE_FACET,
            DOCUMENTATION_FACET,
            SCHEMA_FACET,
        ]
        .into_iter()
        .map(str::to_owned)
        .chain([at.to_rfc3339_opts(SecondsFormat::Millis, true)])
        .collect();
        fn strings(v: &Value, keys: &mut Vec<String>, out: &mut Vec<(String, String)>) {
            match v {
                Value::String(s) => out.push((keys.join("."), s.clone())),
                Value::Array(items) => items.iter().for_each(|i| strings(i, keys, out)),
                Value::Object(map) => {
                    for (k, v) in map {
                        keys.push(k.clone());
                        strings(v, keys, out);
                        keys.pop();
                    }
                }
                _ => {}
            }
        }
        let mut found = Vec::new();
        strings(&Value::Array(out), &mut Vec::new(), &mut found);
        for (path, value) in found {
            if path == "run.runId" {
                continue;
            }
            assert!(allowed.contains(&value), "{path} = {value:?} is not a name");
        }
    }
}
