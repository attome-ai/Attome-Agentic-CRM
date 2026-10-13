//! Vector and fused knowledge retrieval against a real database (D-498 step 5),
//! with a stand-in embedding server on loopback. Nothing leaves this machine.
//!
//! The stand-in maps text to one of a few fixed directions by keyword, so a
//! question and a passage that share no word can still be neighbours — the case
//! only the vector leg can serve. What these tests prove:
//! * a question with no term in common with the answer is found by the vector
//!   leg and by fused retrieval, and not by lexical retrieval;
//! * a caller never receives a nearer chunk from a collection they cannot read,
//!   while a control caller who can read it does;
//! * chunks embedded by a different model are ignored;
//! * a failed query embedding degrades fused retrieval to exactly the lexical
//!   result, and fails vector-only retrieval.
//!
//! Every test writes vectors under the same model name: the writer re-embeds
//! any chunk whose model differs, so two models in one database would race.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-search --test knowledge_vector
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_inference::EmbeddingClient;
use attome_search::embedding_writer::{EMBED_BATCH, EMBEDDING_DIM, embed_pending_chunks};
use attome_search::{KnowledgeHit, RetrievalMode, search_knowledge, search_knowledge_with};
use attome_testkit::skip_if_no_db;
use serde_json::{Value, json};
use uuid::Uuid;

mod knowledge_harness;
use knowledge_harness::{
    assert_then_cleanup, caller_ctx, delete_article, drop_user, insert_article, insert_source,
    provision_kb, test_db, user_who_can_read,
};

const WRITER_MODEL: &str = "stand-in-concepts";

/// Refunds, in words that never appear in the question below.
const REFUNDS: &str = "\
# Reimbursement\n\n\
Submit expense claims with receipts within thirty days of returning.\n";

/// Something unrelated, so a readable collection is never empty.
const PARKING: &str = "\
# Parking\n\n\
Visitors park in the north lot and sign in at reception.\n";

/// Shares no content term with [`REFUNDS`].
const QUESTION: &str = "how do I get my money back";

/// The direction a text points in: which concept its keywords name.
fn concept(text: &str) -> usize {
    let lower = text.to_lowercase();
    if ["reimburse", "expense", "money back", "refund"]
        .iter()
        .any(|k| lower.contains(k))
    {
        0
    } else if ["park", "visitor"].iter().any(|k| lower.contains(k)) {
        1
    } else {
        2
    }
}

fn concept_vector(text: &str) -> Vec<f32> {
    let mut v = vec![0.001_f32; EMBEDDING_DIM];
    v[concept(text)] = 1.0;
    v
}

/// A loopback embedding server. `healthy = false` answers every request 503.
async fn stand_in(healthy: bool) -> String {
    let app = axum::Router::new().route(
        "/v1/embeddings",
        axum::routing::post(move |axum::Json(body): axum::Json<Value>| async move {
            if !healthy {
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    axum::Json(json!({ "error": "model loading" })),
                );
            }
            let data: Vec<Value> = body["input"]
                .as_array()
                .map(|inputs| {
                    inputs
                        .iter()
                        .enumerate()
                        .map(|(i, text)| {
                            json!({
                                "index": i,
                                "embedding": concept_vector(text.as_str().unwrap_or_default()),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            (
                axum::http::StatusCode::OK,
                axum::Json(json!({ "data": data, "usage": { "prompt_tokens": 10 } })),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stand-in embedding server");
    let port = listener.local_addr().expect("stand-in address").port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("stand-in server");
    });
    format!("http://127.0.0.1:{port}/v1")
}

fn client(base_url: &str, model: &str) -> EmbeddingClient {
    let section = attome_config::InferenceSection {
        embedding: attome_config::InferenceEndpoint {
            base_url: base_url.to_owned(),
            model: model.to_owned(),
            request_timeout_secs: 10,
            ..attome_config::InferenceEndpoint::default()
        },
        ..attome_config::InferenceSection::default()
    };
    EmbeddingClient::new(&section).expect("a loopback embedding client")
}

/// Publishes `text` into a new collection, indexes it and embeds every pending
/// chunk. Returns `(source, item)`.
async fn seed(db: &DbPool, writer: &EmbeddingClient, title: &str, text: &str) -> (Uuid, Uuid) {
    provision_kb(db).await;
    let source = insert_source(db, &format!("{title} {}", Uuid::now_v7().simple())).await;
    let item = insert_article(
        db,
        source,
        &format!("{title} {}", Uuid::now_v7().simple()),
        text,
        "published",
    )
    .await;
    attome_search::reindex_item(db, item)
        .await
        .expect("reindex the seeded article");
    for _ in 0..20 {
        let stats = embed_pending_chunks(db, writer, EMBED_BATCH)
            .await
            .expect("embedding pass");
        if stats.selected == 0 {
            return (source, item);
        }
    }
    panic!("embedding passes did not converge");
}

fn items(hits: &[KnowledgeHit]) -> Vec<Uuid> {
    let mut seen = Vec::new();
    for hit in hits {
        if !seen.contains(&hit.citation.item_id) {
            seen.push(hit.citation.item_id);
        }
    }
    seen
}

#[tokio::test]
async fn a_question_sharing_no_term_with_its_answer_is_found_by_the_vector_leg() {
    let db = skip_if_no_db!(test_db().await);
    let url = stand_in(true).await;
    let writer = client(&url, WRITER_MODEL);
    let (source, item) = seed(&db, &writer, "Refunds", REFUNDS).await;
    let (user, role) = user_who_can_read(&db, &[source]).await;

    let pool = db.clone();
    let body = async move {
        let db = pool;
        let ctx = caller_ctx(user);
        let lexical = search_knowledge(&db, &ctx, QUESTION, 5)
            .await
            .expect("lexical");
        assert!(
            lexical.is_empty(),
            "the premise: lexical retrieval cannot find it"
        );

        let vector =
            search_knowledge_with(&db, &ctx, QUESTION, 5, RetrievalMode::Vector, Some(&writer))
                .await
                .expect("vector");
        assert_eq!(items(&vector), vec![item]);
        assert_eq!(vector[0].citation.heading_path, vec!["Reimbursement"]);

        let fused =
            search_knowledge_with(&db, &ctx, QUESTION, 5, RetrievalMode::Fused, Some(&writer))
                .await
                .expect("fused");
        assert_eq!(items(&fused), vec![item]);
    };
    let cleanup = async {
        delete_article(&db, item, Some(source)).await;
        drop_user(&db, user, role).await;
    };
    assert_then_cleanup(body, cleanup).await;
}

/// **The permission case.** The nearest chunk to the question sits in a
/// collection the caller cannot read; a farther one sits in a collection they
/// can. The nearest must never come back, in either mode that reads vectors.
#[tokio::test]
async fn a_nearer_chunk_in_an_unreadable_collection_is_never_returned() {
    let db = skip_if_no_db!(test_db().await);
    let url = stand_in(true).await;
    let writer = client(&url, WRITER_MODEL);
    let (hidden_source, hidden_item) = seed(&db, &writer, "Refunds", REFUNDS).await;
    let (open_source, open_item) = seed(&db, &writer, "Parking", PARKING).await;
    let (restricted, restricted_role) = user_who_can_read(&db, &[open_source]).await;
    let (control, control_role) = user_who_can_read(&db, &[hidden_source]).await;

    let pool = db.clone();
    let body = async move {
        let db = pool;
        for mode in [RetrievalMode::Vector, RetrievalMode::Fused] {
            let hits = search_knowledge_with(
                &db,
                &caller_ctx(restricted),
                QUESTION,
                5,
                mode,
                Some(&writer),
            )
            .await
            .expect("restricted caller");
            let found = items(&hits);
            assert!(
                !found.contains(&hidden_item),
                "{mode:?}: a chunk from an unreadable collection was returned"
            );
            assert!(
                found.iter().all(|i| *i == open_item),
                "{mode:?}: only the readable collection may contribute, got {found:?}"
            );

            // The control proves the hidden chunk is really the nearest one,
            // so the restricted result above is the filter, not a miss.
            let control_hits =
                search_knowledge_with(&db, &caller_ctx(control), QUESTION, 5, mode, Some(&writer))
                    .await
                    .expect("control caller");
            assert_eq!(items(&control_hits).first(), Some(&hidden_item), "{mode:?}");
        }
    };
    let cleanup = async {
        delete_article(&db, hidden_item, Some(hidden_source)).await;
        delete_article(&db, open_item, Some(open_source)).await;
        drop_user(&db, restricted, restricted_role).await;
        drop_user(&db, control, control_role).await;
    };
    assert_then_cleanup(body, cleanup).await;
}

#[tokio::test]
async fn chunks_embedded_by_another_model_are_ignored() {
    let db = skip_if_no_db!(test_db().await);
    let url = stand_in(true).await;
    let writer = client(&url, WRITER_MODEL);
    let (source, item) = seed(&db, &writer, "Refunds", REFUNDS).await;
    let (user, role) = user_who_can_read(&db, &[source]).await;

    let pool = db.clone();
    let body = async move {
        let db = pool;
        // Same server, same vectors, different model name: the stored vectors
        // were not produced by this model and are not comparable to its output.
        let other = client(&url, "stand-in-other-model");
        let hits = search_knowledge_with(
            &db,
            &caller_ctx(user),
            QUESTION,
            5,
            RetrievalMode::Vector,
            Some(&other),
        )
        .await
        .expect("vector with another model");
        assert!(hits.is_empty(), "got {:?}", items(&hits));
    };
    let cleanup = async {
        delete_article(&db, item, Some(source)).await;
        drop_user(&db, user, role).await;
    };
    assert_then_cleanup(body, cleanup).await;
}

/// **The degradation case** (D-506 §3): an embedding server that is down must
/// not take lexical search with it.
#[tokio::test]
async fn a_failed_query_embedding_degrades_fused_retrieval_to_lexical() {
    let db = skip_if_no_db!(test_db().await);
    let writer = client(&stand_in(true).await, WRITER_MODEL);
    let (source, item) = seed(&db, &writer, "Refunds", REFUNDS).await;
    let (user, role) = user_who_can_read(&db, &[source]).await;
    let broken = client(&stand_in(false).await, WRITER_MODEL);

    let pool = db.clone();
    let body = async move {
        let db = pool;
        let ctx = caller_ctx(user);
        let lexical_question = "expense claims receipts";

        let lexical = search_knowledge(&db, &ctx, lexical_question, 5)
            .await
            .expect("lexical");
        assert_eq!(items(&lexical), vec![item], "the premise: lexical finds it");

        let fused = search_knowledge_with(
            &db,
            &ctx,
            lexical_question,
            5,
            RetrievalMode::Fused,
            Some(&broken),
        )
        .await
        .expect("fused retrieval must not fail when the embedding server does");
        let passages = |hits: &[KnowledgeHit]| {
            hits.iter()
                .map(|h| (h.citation.item_id, h.citation.passage.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(passages(&fused), passages(&lexical));

        let vector = search_knowledge_with(
            &db,
            &ctx,
            lexical_question,
            5,
            RetrievalMode::Vector,
            Some(&broken),
        )
        .await;
        assert!(
            vector.is_err(),
            "vector-only retrieval reports the failure instead of hiding it"
        );
    };
    let cleanup = async {
        delete_article(&db, item, Some(source)).await;
        drop_user(&db, user, role).await;
    };
    assert_then_cleanup(body, cleanup).await;
}
