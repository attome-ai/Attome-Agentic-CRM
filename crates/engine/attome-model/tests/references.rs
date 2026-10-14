//! The reference graph (roadmap Y1-T4), on a migrated throwaway database.

#![allow(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;

use attome_model::references::{self, target_key};
use attome_model::store::{self, ObjectSpec};
use attome_model::{
    Artefact, CookInput, Issue, Kind, KindName, KindRegistry, Layer, ObjectId, ObjectRef, RefMode,
    Reference, ValidationCtx,
};
use attome_types::{AppError, OnePageQuery};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// A kind whose documents list the objects they read: `{"reads": [{"kind", "id"}]}`.
struct LinkKind(&'static str);

impl Kind for LinkKind {
    fn name(&self) -> KindName {
        KindName(self.0)
    }
    fn schema_version(&self) -> u32 {
        1
    }
    fn json_schema(&self) -> Value {
        json!({ "type": "object" })
    }
    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        if doc.is_object() {
            Ok(())
        } else {
            Err(vec![Issue::new("", "not_an_object", "an object")])
        }
    }
    fn references(&self, doc: &Value) -> Vec<Reference> {
        doc["reads"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| {
                let kind = match item["kind"].as_str()? {
                    "test_source" => KindName("test_source"),
                    "test_target" => KindName("test_target"),
                    _ => KindName("test_unknown"),
                };
                let id = Uuid::parse_str(item["id"].as_str()?).ok()?;
                Some(Reference {
                    target: ObjectRef {
                        kind,
                        id: ObjectId(id),
                    },
                    mode: RefMode::Reads,
                })
            })
            .collect()
    }
    fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        Vec::new()
    }
    fn cook(&self, _docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        Ok(Vec::new())
    }
    fn agent_tool_description(&self) -> &'static str {
        "a test link"
    }
}

fn registry() -> KindRegistry {
    let mut registry = KindRegistry::default();
    registry
        .register(Arc::new(LinkKind("test_source")))
        .unwrap();
    registry
        .register(Arc::new(LinkKind("test_target")))
        .unwrap();
    registry
}

fn spec(prefix: &str) -> ObjectSpec {
    let id = ObjectId::new();
    ObjectSpec {
        id,
        name: format!("{prefix}-{id}"),
        app: "customer".to_owned(),
        layer: Layer::Customer,
    }
}

async fn pool() -> Option<sqlx::PgPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("connect"),
    )
}

async fn save(
    pool: &sqlx::PgPool,
    kind: &LinkKind,
    object: &ObjectSpec,
    doc: Value,
) -> store::DraftSaved {
    let mut tx = pool.begin().await.unwrap();
    let saved = store::save_draft(&mut tx, &registry(), kind, object, &doc, None)
        .await
        .expect("save");
    tx.commit().await.unwrap();
    saved
}

#[tokio::test]
async fn dangling_attribute_reference_is_reported() {
    let Some(pool) = pool().await else {
        return;
    };
    let target = spec("target");
    save(&pool, &LinkKind("test_target"), &target, json!({})).await;
    let missing = Uuid::now_v7();
    let source = spec("source");
    let saved = save(
        &pool,
        &LinkKind("test_source"),
        &source,
        json!({ "reads": [
            { "kind": "test_target", "id": target.id.to_string() },
            { "kind": "test_target", "id": missing.to_string() },
            { "kind": "nobody", "id": Uuid::now_v7().to_string() }
        ]}),
    )
    .await;
    // The draft saved anyway; two of its three references dangle.
    assert_eq!(saved.issues.len(), 2, "{:?}", saved.issues);
    assert!(saved.issues.iter().all(|i| i.code == "dangling_reference"));
    assert!(saved.issues[0].message.contains(&missing.to_string()));
}

#[tokio::test]
async fn references_in_and_out_agree() {
    let Some(pool) = pool().await else {
        return;
    };
    let target = spec("target");
    save(&pool, &LinkKind("test_target"), &target, json!({})).await;
    let source = spec("source");
    let doc = json!({ "reads": [{ "kind": "test_target", "id": target.id.to_string() }] });
    save(&pool, &LinkKind("test_source"), &source, doc.clone()).await;
    // Saving again replaces the set rather than adding to it.
    save(&pool, &LinkKind("test_source"), &source, doc).await;

    let page = OnePageQuery {
        page: None,
        page_size: None,
    };
    let target_ref = ObjectRef {
        kind: KindName("test_target"),
        id: target.id,
    };
    let source_ref = ObjectRef {
        kind: KindName("test_source"),
        id: source.id,
    };
    let incoming = references::references_in(&pool, &target_ref, &page)
        .await
        .unwrap();
    let outgoing = references::references_out(&pool, &source_ref, &page)
        .await
        .unwrap();
    assert_eq!(incoming.total, 1);
    assert_eq!(outgoing.total, 1);
    assert_eq!(incoming.items, outgoing.items);
    assert_eq!(outgoing.items[0].to_entity, target_key(&target_ref));
    assert_eq!(outgoing.items[0].mode, "reads");
}
