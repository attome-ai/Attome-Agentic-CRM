//! E8-T11 and E9-T9: the marketing pack's seven starter journeys and five
//! nurture programme journeys
//! (`packs/marketing/model/flow_template/marketing/*.json`) are valid
//! `flow_template` pack objects that instantiate, with a design for each
//! email, into a graph the workflow engine's publish validation accepts, made
//! only of trigger, wait, condition and marketing steps whose settings those
//! steps accept.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test: a broken template should panic with its file name"
)]

use std::path::Path;

use attome_core::workflow_step::WorkflowStepHandler;
use attome_model::Kind;
use attome_model::kinds::flow_template::{FlowTemplateKind, instantiate};
use serde_json::{Map, Value, json};

/// E8-T11's seven starter journeys and E9-T9's five nurture programme
/// journeys, in file-name order.
const STARTERS: [&str; 12] = [
    "journey-abandoned-form",
    "journey-event-reminder",
    "journey-onboarding",
    "journey-post-purchase-feedback",
    "journey-re-engagement",
    "journey-renewal-reminder",
    "journey-welcome",
    "nurture-content-download",
    "nurture-lost-deal",
    "nurture-new-subscriber",
    "nurture-recycled-lead",
    "nurture-webinar-attendee",
];

/// The marketing step behind a handler key, as the journey would run it.
fn step(key: &str) -> Box<dyn WorkflowStepHandler> {
    use attome_marketing::journey::{control_step, message_step};
    match key {
        "marketing.send_email" => Box::new(message_step::SendEmail),
        "marketing.nurture_run" => Box::new(attome_marketing::nurture_run::NurtureRun),
        "marketing.engagement" => Box::new(control_step::Engagement),
        other => panic!("a starter journey uses {other}, which it should not"),
    }
}

#[test]
fn starter_journeys_instantiate_and_validate() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/marketing/model/flow_template/marketing");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            (path.extension().is_some_and(|x| x == "json"))
                .then(|| path.file_stem().unwrap().to_string_lossy().into_owned())
        })
        .collect();
    names.sort();
    assert_eq!(
        names, STARTERS,
        "the marketing pack ships seven starter journeys and five nurture journeys"
    );

    for name in STARTERS {
        let file = dir.join(format!("{name}.json"));
        let object: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(object["app"], json!("marketing"), "{name}");
        assert_eq!(object["kind"], json!("flow_template"), "{name}");
        assert_eq!(object["name"], json!(name), "{name}");
        let doc = &object["doc"];
        FlowTemplateKind
            .validate_shape(doc)
            .unwrap_or_else(|issues| panic!("{name}: {issues:?}"));
        for key in ["description_en", "description_ar"] {
            assert!(
                doc[key].as_str().is_some_and(|d| !d.trim().is_empty()),
                "{name}: {key} is required"
            );
        }

        // Every parameter without a default is an email design.
        let mut args = Map::new();
        for parameter in doc["parameters"].as_array().unwrap() {
            if parameter.get("default").is_none() {
                let param = parameter["name"].as_str().unwrap();
                assert!(
                    param.ends_with("_design"),
                    "{name}: {param} needs a default"
                );
                args.insert(param.to_owned(), json!(uuid::Uuid::now_v7().to_string()));
            }
        }
        let graph = instantiate(doc, &args)
            .unwrap_or_else(|issues| panic!("{name}: instantiate: {issues:?}"));
        let parsed =
            attome_workflow::graph::Graph::parse(&graph).unwrap_or_else(|e| panic!("{name}: {e}"));
        attome_workflow::graph::validate(&parsed).unwrap_or_else(|e| panic!("{name}: {e}"));

        for node in graph["nodes"].as_array().unwrap() {
            let node_type = node["type"].as_str().unwrap();
            assert!(
                [
                    "trigger",
                    "wait",
                    "wait_for_event",
                    "condition",
                    "module_step"
                ]
                .contains(&node_type),
                "{name}: a journey uses no {node_type} node"
            );
            if node_type == "module_step" {
                let handler = node["config"]["handler"].as_str().unwrap();
                step(handler)
                    .validate_config(&node["config"]["config"])
                    .unwrap_or_else(|e| panic!("{name}/{}: {e}", node["id"]));
            }
        }
    }
}
