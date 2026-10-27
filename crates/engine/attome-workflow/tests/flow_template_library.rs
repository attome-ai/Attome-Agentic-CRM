//! M6-T3: every starter flow template (`templates/flows/*.json`) is a valid
//! `flow_template`, instantiates with its parameters' defaults, and the graph
//! it makes passes the workflow engine's publish validation.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test: a broken template should panic with its file name"
)]

use std::path::Path;

use attome_model::Kind;
use attome_model::kinds::flow_template::{FlowTemplateKind, instantiate};
use serde_json::{Map, Value};

#[test]
fn flow_template_library_instantiates_and_validates() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../templates/flows");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    assert_eq!(files.len(), 20, "the starter library has 20 templates");
    for file in &files {
        let name = file.display();
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        FlowTemplateKind
            .validate_shape(&doc)
            .unwrap_or_else(|issues| panic!("{name}: {issues:?}"));
        for key in ["description_en", "description_ar"] {
            assert!(
                doc[key].as_str().is_some_and(|d| !d.trim().is_empty()),
                "{name}: {key} is required"
            );
        }
        let graph = instantiate(&doc, &Map::new())
            .unwrap_or_else(|issues| panic!("{name}: instantiate: {issues:?}"));
        let parsed =
            attome_workflow::graph::Graph::parse(&graph).unwrap_or_else(|e| panic!("{name}: {e}"));
        attome_workflow::graph::validate(&parsed).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}
