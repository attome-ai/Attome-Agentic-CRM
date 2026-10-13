//! The knowledge embedding writer against a real database (D-498 step 5), with a
//! stand-in embedding server on loopback that speaks the OpenAI-compatible
//! `/embeddings` API. Nothing leaves this machine.
//!
//! What these tests prove, that the unit tests in `embedding_writer.rs` cannot:
//! * pending chunks get a vector, the model that produced it, and
//!   `embedding_locality = 'local'`, and a second pass has nothing left to do;
//! * a chunk whose text changes while its embedding is being computed is left
//!   for the next pass rather than given a vector describing the old text;
//! * switching the embedding model re-embeds every chunk;
//! * a model returning the wrong vector width writes nothing.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-search --test embedding_writer -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::{Arc, Mutex};

use attome_db::DbPool;
use attome_inference::EmbeddingClient;
use attome_search::embedding_writer::{EMBED_BATCH, EMBEDDING_DIM, embed_pending_chunks};
use attome_testkit::skip_if_no_db;
use serde_json::{Value, json};
use uuid::Uuid;

mod knowledge_harness;
use knowledge_harness::{
    assert_then_cleanup, delete_article, insert_article, insert_source, provision_kb, test_db,
};

const ARTICLE: &str = "\
Intro paragraph before any heading.\n\n\
# Claims\n\n\
Submit expense claims with receipts within thirty days of returning.\n\n\
# Per Diem\n\n\
The daily allowance covers meals and local transport.\n";

/// What the stand-in does when a request arrives, besides answering it.
type OnRequest =
    Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

struct StandIn {
    base_url: String,
    requests: Arc<Mutex<usize>>,
}

/// A loopback embedding server returning `width`-dimension vectors.
async fn stand_in(width: usize, on_request: OnRequest) -> StandIn {
    let requests: Arc<Mutex<usize>> = Arc::default();
    let seen = Arc::clone(&requests);
    // `base_url` below ends in `/v1`; the client appends attome-inference's path.
    let app = axum::Router::new().route(
        &format!("/v1{}", attome_inference::EMBEDDINGS_PATH),
        axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
            let seen = Arc::clone(&seen);
            let on_request = Arc::clone(&on_request);
            async move {
                *seen.lock().expect("stand-in lock") += 1;
                on_request().await;
                let count = body["input"].as_array().map_or(0, Vec::len);
                let data: Vec<Value> = (0..count)
                    .map(|i| json!({ "index": i, "embedding": vec![0.01_f32 + i as f32 * 1e-4; width] }))
                    .collect();
                axum::Json(json!({ "data": data, "usage": { "prompt_tokens": 10 } }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stand-in embedding server");
    let port = listener.local_addr().expect("stand-in address").port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("stand-in server");
    });
    StandIn {
        base_url: format!("http://127.0.0.1:{port}/v1"),
        requests,
    }
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

fn no_op() -> OnRequest {
    Arc::new(|| Box::pin(async {}))
}

/// `(ordinal, has embedding, model, locality)` for every chunk of `item`.
async fn chunk_vectors(
    db: &DbPool,
    item: Uuid,
) -> Vec<(i32, bool, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT ordinal, embedding IS NOT NULL, embedding_model, embedding_locality \
         FROM knowledge_chunk WHERE source_id = $1 ORDER BY ordinal",
    )
    .bind(item)
    .fetch_all(db)
    .await
    .expect("read chunk vectors")
}

async fn seed(db: &DbPool) -> (Uuid, Uuid) {
    provision_kb(db).await;
    let source = insert_source(db, &format!("Embeddings {}", Uuid::now_v7().simple())).await;
    let item = insert_article(
        db,
        source,
        &format!("Travel {}", Uuid::now_v7().simple()),
        ARTICLE,
        "published",
    )
    .await;
    attome_search::reindex_item(db, item)
        .await
        .expect("reindex the seeded article");
    (source, item)
}

/// Runs passes until none selects anything.
async fn drain_embeddings(db: &DbPool, client: &EmbeddingClient) {
    for _ in 0..20 {
        let stats = embed_pending_chunks(db, client, EMBED_BATCH)
            .await
            .expect("embedding pass");
        if stats.selected == 0 {
            return;
        }
    }
    panic!("embedding passes did not converge");
}

#[tokio::test]
async fn pending_chunks_are_embedded_with_their_model_and_locality() {
    let db = skip_if_no_db!(test_db().await);
    let (source, item) = seed(&db).await;
    let server = stand_in(EMBEDDING_DIM, no_op()).await;

    let pool = db.clone();
    let body = async move {
        let db = pool;
        let embedder = client(&server.base_url, "stand-in-embed-a");
        drain_embeddings(&db, &embedder).await;

        let vectors = chunk_vectors(&db, item).await;
        assert!(!vectors.is_empty());
        for (ordinal, embedded, model, locality) in &vectors {
            assert!(embedded, "chunk {ordinal} must have a vector");
            assert_eq!(model.as_deref(), Some("stand-in-embed-a"));
            assert_eq!(locality.as_deref(), Some("local"));
        }

        let requests_after_first = *server.requests.lock().expect("lock");
        let again = embed_pending_chunks(&db, &embedder, EMBED_BATCH)
            .await
            .expect("second pass");
        assert_eq!(again.selected, 0, "a second pass must have nothing to do");
        assert_eq!(
            *server.requests.lock().expect("lock"),
            requests_after_first,
            "a pass with nothing pending must not call the model"
        );
    };
    assert_then_cleanup(body, delete_article(&db, item, Some(source))).await;
}

/// **The race guard.** The stand-in rewrites one chunk's content hash while it
/// is computing the vectors, the way an article edit landing mid-pass would.
/// That chunk must keep an empty vector; the others are written.
#[tokio::test]
async fn a_chunk_changed_during_the_model_call_is_left_for_the_next_pass() {
    let db = skip_if_no_db!(test_db().await);
    let (source, item) = seed(&db).await;
    let target: Uuid = sqlx::query_scalar(
        "SELECT id FROM knowledge_chunk WHERE source_id = $1 ORDER BY ordinal LIMIT 1",
    )
    .bind(item)
    .fetch_one(&db)
    .await
    .expect("pick a chunk");

    let edit_db = db.clone();
    let on_request: OnRequest = Arc::new(move || {
        let db = edit_db.clone();
        // Awaited inside the handler, so the rewrite commits before the
        // response is sent and the ordering is deterministic.
        Box::pin(async move {
            sqlx::query("UPDATE knowledge_chunk SET content_hash = '\\x00'::bytea WHERE id = $1")
                .bind(target)
                .execute(&db)
                .await
                .expect("rewrite the chunk mid-pass");
        })
    });
    let server = stand_in(EMBEDDING_DIM, on_request).await;

    let pool = db.clone();
    let body = async move {
        let db = pool;
        let embedder = client(&server.base_url, "stand-in-embed-a");
        let stats = embed_pending_chunks(&db, &embedder, EMBED_BATCH)
            .await
            .expect("embedding pass");
        assert!(stats.skipped_changed >= 1, "{stats:?}");

        let target_embedded: bool =
            sqlx::query_scalar("SELECT embedding IS NOT NULL FROM knowledge_chunk WHERE id = $1")
                .bind(target)
                .fetch_one(&db)
                .await
                .expect("read the rewritten chunk");
        assert!(
            !target_embedded,
            "a vector computed from the old text must not be written to a changed chunk"
        );
        let others_embedded = chunk_vectors(&db, item)
            .await
            .iter()
            .filter(|(_, embedded, ..)| *embedded)
            .count();
        assert!(
            others_embedded >= 1,
            "unchanged chunks must still be written"
        );
    };
    assert_then_cleanup(body, delete_article(&db, item, Some(source))).await;
}

#[tokio::test]
async fn switching_the_embedding_model_re_embeds_every_chunk() {
    let db = skip_if_no_db!(test_db().await);
    let (source, item) = seed(&db).await;
    let server = stand_in(EMBEDDING_DIM, no_op()).await;

    let pool = db.clone();
    let body = async move {
        let db = pool;
        drain_embeddings(&db, &client(&server.base_url, "stand-in-embed-a")).await;
        drain_embeddings(&db, &client(&server.base_url, "stand-in-embed-b")).await;
        for (ordinal, embedded, model, _) in chunk_vectors(&db, item).await {
            assert!(embedded, "chunk {ordinal}");
            assert_eq!(
                model.as_deref(),
                Some("stand-in-embed-b"),
                "chunk {ordinal} must carry the new model's vector"
            );
        }
    };
    assert_then_cleanup(body, delete_article(&db, item, Some(source))).await;
}

#[tokio::test]
async fn a_model_returning_the_wrong_width_writes_nothing() {
    let db = skip_if_no_db!(test_db().await);
    let (source, item) = seed(&db).await;
    let server = stand_in(768, no_op()).await;

    let pool = db.clone();
    let body = async move {
        let db = pool;
        let embedder = client(&server.base_url, "stand-in-embed-narrow");
        let err = embed_pending_chunks(&db, &embedder, EMBED_BATCH)
            .await
            .expect_err("a 768-dimension model must be refused");
        assert!(format!("{err:?}").contains("dimensions"), "{err:?}");
        assert!(
            chunk_vectors(&db, item)
                .await
                .iter()
                .all(|(_, embedded, ..)| !*embedded),
            "no vector may be written from a wrong-width model"
        );
    };
    assert_then_cleanup(body, delete_article(&db, item, Some(source))).await;
}
