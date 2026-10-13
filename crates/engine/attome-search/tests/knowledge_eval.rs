//! The Knowledge Base retrieval benchmark (D-498 step 3), against a real
//! database.
//!
//! Seeds `fixtures/knowledge_benchmark.json` through the production producer
//! (`reindex_item`) and runs every question through `search_knowledge` as a
//! real, non-admin caller whose access comes from the production resolver.
//!
//! **While the fixture is `draft`, nothing is scored.** The run still does
//! everything that is not a quality number: it proves every judged section is
//! one the chunker really produces, that no question returns a passage from a
//! collection its caller cannot read, and that each permission case is hidden
//! from its caller and reachable by its control. Scores are withheld on purpose
//! — judgments adjusted after seeing what retrieval returns would benchmark the
//! system against its own behaviour (`knowledge_eval`'s module doc).
//!
//! **Once `frozen`,** the run scores against `fixtures/knowledge_baseline.json`,
//! refusing to compare against a baseline recorded on a different fixture.
//!
//! **Retrieval modes (D-498 step 5).** `KNOWLEDGE_EVAL_MODE` picks what is
//! measured. Unset or `lexical` is full-text retrieval, gated against
//! `knowledge_baseline.json`; that is the default mode. `vector` and `fused` need an
//! in-deployment embedding server (`KNOWLEDGE_EVAL_EMBEDDING_URL`,
//! `KNOWLEDGE_EVAL_EMBEDDING_MODEL`): the seeded corpus is embedded first, then
//! every question runs. `vector` is measured and never gated; `fused` is gated
//! against `knowledge_baseline_fused.json`, which records the embedding model
//! its scores came from. Every mode asserts the same permission cases.
//!
//! **Similarity calibration (D-498 step 5e).** `knowledge_similarity_calibration`
//! runs only with `KNOWLEDGE_EVAL_CALIBRATE=1` and the same embedding server. It
//! records the cosine similarity of every section vector retrieval ranks, and
//! rescores the benchmark under a grid of minimum-similarity floors. It is
//! measured, never gated, and changes nothing retrieval does.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-search --test knowledge_eval -- --test-threads=1 --nocapture
//! # after freezing, or after a deliberate retrieval change:
//! $env:UPDATE_KNOWLEDGE_BASELINE = "1"
//! # fused retrieval against a local model server:
//! $env:KNOWLEDGE_EVAL_MODE = "fused"
//! $env:KNOWLEDGE_EVAL_EMBEDDING_URL = "http://127.0.0.1:8088/v1"
//! $env:KNOWLEDGE_EVAL_EMBEDDING_MODEL = "BAAI/bge-m3"
//! # similarity calibration against the same server:
//! $env:KNOWLEDGE_EVAL_CALIBRATE = "1"
//! cargo test -p attome-search --test knowledge_eval knowledge_similarity_calibration -- --nocapture
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::{BTreeSet, HashMap, HashSet};

use attome_db::DbPool;
use attome_inference::{EmbedKind, EmbeddingClient};
use attome_search::embedding_writer::{EMBED_BATCH, embed_pending_chunks, vector_literal};
use attome_search::knowledge::MAX_KNOWLEDGE_LIMIT;
use attome_search::knowledge_eval::{
    Category, FixtureStatus, K_AGENT, K_WIDE, KnowledgeBaseline, KnowledgeBenchmark, Language,
    Retrieved, ScoredRetrieval, ScoredSection, SimilarityCalibration, check_regression,
    fixture_fingerprint, score, section_key,
};
use attome_search::{KnowledgeHit, RetrievalMode};
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

mod knowledge_harness;
use knowledge_harness::{
    assert_then_cleanup, caller_ctx, delete_article, drop_user, insert_article, insert_source,
    provision_kb, test_db, user_who_can_read,
};

const FIXTURE: &str = include_str!("fixtures/knowledge_benchmark.json");
const BASELINE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/knowledge_baseline.json"
);

const FUSED_BASELINE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/knowledge_baseline_fused.json"
);

/// The fused baseline: the lexical baseline's shape, plus the embedding model
/// its scores came from. Scores measured with another model are not comparable.
#[derive(serde::Serialize, serde::Deserialize)]
struct FusedBaseline {
    embedding_model: String,
    baseline: KnowledgeBaseline,
}

/// The retrieval a run measures, from `KNOWLEDGE_EVAL_MODE`.
struct RetrievalUnderTest {
    mode: RetrievalMode,
    embedder: Option<EmbeddingClient>,
}

impl RetrievalUnderTest {
    fn from_env() -> Self {
        let mode = match std::env::var("KNOWLEDGE_EVAL_MODE").as_deref() {
            Err(_) | Ok("lexical") => RetrievalMode::Lexical,
            Ok("vector") => RetrievalMode::Vector,
            Ok("fused") => RetrievalMode::Fused,
            Ok(other) => {
                panic!("KNOWLEDGE_EVAL_MODE must be lexical, vector or fused, not {other:?}")
            }
        };
        if mode == RetrievalMode::Lexical {
            return Self {
                mode,
                embedder: None,
            };
        }
        Self {
            mode,
            embedder: Some(embedder_from_env(&format!("KNOWLEDGE_EVAL_MODE={mode:?}"))),
        }
    }
}

/// The in-deployment embedding client named by `KNOWLEDGE_EVAL_EMBEDDING_URL`
/// and `KNOWLEDGE_EVAL_EMBEDDING_MODEL`. `purpose` names the run that needs it.
fn embedder_from_env(purpose: &str) -> EmbeddingClient {
    let var = |name: &str| {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} is required for {purpose}"))
    };
    let section = attome_config::InferenceSection {
        embedding: attome_config::InferenceEndpoint {
            base_url: var("KNOWLEDGE_EVAL_EMBEDDING_URL"),
            model: var("KNOWLEDGE_EVAL_EMBEDDING_MODEL"),
            request_timeout_secs: 300,
            ..attome_config::InferenceEndpoint::default()
        },
        ..attome_config::InferenceSection::default()
    };
    EmbeddingClient::new(&section)
        .expect("an in-deployment embedding endpoint (D-506 refuses any other)")
}

/// Embeds every seeded chunk, and proves none was left without a vector from
/// this model: a partly embedded corpus would score as a weaker model.
async fn embed_corpus(db: &DbPool, embedder: &EmbeddingClient, world: &World) {
    for _ in 0..1_000 {
        let stats = embed_pending_chunks(db, embedder, EMBED_BATCH)
            .await
            .expect("embed the benchmark corpus");
        if stats.selected == 0 {
            break;
        }
    }
    let items: Vec<Uuid> = world.item_by_article.values().copied().collect();
    let missing: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM knowledge_chunk \
         WHERE source_id = ANY($1) \
           AND (embedding IS NULL OR embedding_model IS DISTINCT FROM $2)",
    )
    .bind(&items)
    .bind(embedder.model_id())
    .fetch_one(db)
    .await
    .expect("count unembedded benchmark chunks");
    assert_eq!(
        missing, 0,
        "every benchmark chunk must carry a vector from the model under test"
    );
}

/// Answerable questions whose answer is in a language other than the
/// question's: the cases full-text matching cannot bridge. Reported per
/// question, from the frozen judgments; not part of any baseline.
fn cross_lingual_report(b: &KnowledgeBenchmark, retrieved: &[Retrieved]) -> String {
    use attome_search::eval::{recall_at_k, reciprocal_rank};

    let language: HashMap<&str, Language> = b
        .articles
        .iter()
        .map(|a| (a.key.as_str(), a.language))
        .collect();
    let by_id: HashMap<&str, &Retrieved> =
        retrieved.iter().map(|r| (r.question.as_str(), r)).collect();
    let mut out = String::from(
        "supplementary cross-lingual probe (answer in another language than the question; \
         derived from the frozen judgments, not a benchmark category, not in any score or baseline)\n",
    );
    let (mut r5, mut r10, mut mrr, mut n) = (0.0, 0.0, 0.0, 0usize);
    for q in b
        .questions
        .iter()
        .filter(|q| q.answerable && q.category != Category::PermissionRestricted)
    {
        let answer_languages: BTreeSet<Language> = q
            .judgments
            .iter()
            .filter(|j| j.grade >= 2)
            .filter_map(|j| language.get(j.doc.split('#').next().unwrap_or_default()))
            .copied()
            .collect();
        if answer_languages.is_empty() || answer_languages == BTreeSet::from([q.language]) {
            continue;
        }
        let Some(r) = by_id.get(q.id.as_str()) else {
            continue;
        };
        let q_r5 = recall_at_k(&r.ranked, &q.judgments, K_AGENT).unwrap_or(0.0);
        let q_r10 = recall_at_k(&r.ranked, &q.judgments, K_WIDE).unwrap_or(0.0);
        let q_mrr = reciprocal_rank(&r.ranked, &q.judgments, K_WIDE);
        out.push_str(&format!(
            "  {:<8} {:?} -> {:?}  R@5 {q_r5:.3}  R@10 {q_r10:.3}  MRR {q_mrr:.3}\n",
            q.id, q.language, answer_languages
        ));
        (r5, r10, mrr, n) = (r5 + q_r5, r10 + q_r10, mrr + q_mrr, n + 1);
    }
    if n > 0 {
        let n_f = n as f64;
        out.push_str(&format!(
            "  {:<8} n={n}  R@5 {:.3}  R@10 {:.3}  MRR {:.3}\n",
            "overall",
            r5 / n_f,
            r10 / n_f,
            mrr / n_f
        ));
    }
    out
}

fn benchmark() -> KnowledgeBenchmark {
    let b = KnowledgeBenchmark::parse(FIXTURE).expect("knowledge_benchmark.json must parse");
    b.validate()
        .expect("knowledge_benchmark.json must be internally valid");
    b
}

/// The fixture is valid and still covers every group the baseline breaks down
/// by. No database.
///
/// A benchmark that silently lost its Arabic or unanswerable cases would keep
/// reporting a healthy number — those are exactly the groups that degrade
/// without an error.
#[test]
fn the_fixture_is_valid_and_covers_every_group() {
    let b = benchmark();
    let scored = |q: &&attome_search::knowledge_eval::KnowledgeQuestion| {
        q.category != Category::PermissionRestricted
    };

    for lang in [Language::En, Language::Ar, Language::Mixed] {
        let answerable = b
            .questions
            .iter()
            .filter(scored)
            .filter(|q| q.language == lang && q.answerable)
            .count();
        let unanswerable = b
            .questions
            .iter()
            .filter(|q| q.language == lang && !q.answerable)
            .count();
        assert!(answerable >= 3, "{lang:?} needs answerable questions");
        assert!(unanswerable >= 2, "{lang:?} needs unanswerable questions");
    }
    for cat in [
        Category::ExactTerminology,
        Category::NaturalQuestion,
        Category::PartialOverlap,
        Category::Paraphrase,
    ] {
        assert!(
            b.questions
                .iter()
                .any(|q| q.category == cat && q.answerable),
            "{cat:?} needs an answerable question"
        );
    }
    let count = |pred: &dyn Fn(&attome_search::knowledge_eval::KnowledgeQuestion) -> bool| {
        b.questions.iter().filter(|q| pred(q)).count()
    };
    assert!(count(&|q| q.category == Category::LooseMatch) >= 3);
    assert!(count(&|q| q.category == Category::PermissionRestricted) >= 3);
    assert!(count(&|q| q.multi_hop) >= 3);

    assert_eq!(
        std::path::Path::new(BASELINE_PATH).exists(),
        b.status == FixtureStatus::Frozen,
        "a baseline exists exactly when the fixture is frozen: a draft has not \
         been reviewed, and a frozen fixture without a baseline gates nothing"
    );
}

/// What seeding produced: the ids each fixture key received.
#[derive(Clone)]
struct World {
    article_by_item: HashMap<Uuid, String>,
    item_by_article: HashMap<String, Uuid>,
    collection_by_source: HashMap<Uuid, String>,
    user_by_caller: HashMap<String, Uuid>,
    roles: Vec<(Uuid, Uuid)>,
}

async fn seed(db: &DbPool, b: &KnowledgeBenchmark) -> World {
    provision_kb(db).await;

    let mut source_by_collection = HashMap::new();
    let mut collection_by_source = HashMap::new();
    for c in &b.collections {
        let id = insert_source(db, &format!("{} {}", c.name, Uuid::now_v7().simple())).await;
        source_by_collection.insert(c.key.clone(), id);
        collection_by_source.insert(id, c.key.clone());
    }

    let mut article_by_item = HashMap::new();
    let mut item_by_article = HashMap::new();
    for a in &b.articles {
        let source = source_by_collection[&a.collection];
        let item = insert_article(db, source, &a.title, &a.text, "published").await;
        attome_search::reindex_item(db, item)
            .await
            .expect("reindex a benchmark article");
        article_by_item.insert(item, a.key.clone());
        item_by_article.insert(a.key.clone(), item);
    }

    let mut user_by_caller = HashMap::new();
    let mut roles = Vec::new();
    for c in &b.callers {
        let sources: Vec<Uuid> = c.readable.iter().map(|k| source_by_collection[k]).collect();
        let (user, role) = user_who_can_read(db, &sources).await;
        user_by_caller.insert(c.key.clone(), user);
        roles.push((user, role));
    }

    World {
        article_by_item,
        item_by_article,
        collection_by_source,
        user_by_caller,
        roles,
    }
}

/// Runs one question as `caller`, asserting the permission invariant on every
/// passage, and returns the section keys in rank order, each once.
async fn run(
    db: &DbPool,
    b: &KnowledgeBenchmark,
    world: &World,
    retrieval: &RetrievalUnderTest,
    id: &str,
    caller: &str,
    question: &str,
) -> Vec<String> {
    let user = world.user_by_caller[caller];
    let ctx = caller_ctx(user);
    let limit = K_WIDE as i64;
    let embedder = retrieval.embedder.as_ref();
    let hits = match retrieval.mode {
        RetrievalMode::Lexical => attome_search::search_knowledge(db, &ctx, question, limit).await,
        RetrievalMode::Vector => {
            attome_search::search_knowledge_with(
                db,
                &ctx,
                question,
                limit,
                RetrievalMode::Vector,
                embedder,
            )
            .await
        }
        RetrievalMode::Fused => {
            // Fused retrieval falls back to lexical when the vector leg fails,
            // which here would record lexical scores as fused ones. The vector
            // leg must succeed on this question first.
            attome_search::search_knowledge_with(
                db,
                &ctx,
                question,
                limit,
                RetrievalMode::Vector,
                embedder,
            )
            .await
            .unwrap_or_else(|e| {
                panic!("{id}: the vector leg failed, so fused would be lexical: {e:?}")
            });
            attome_search::search_knowledge_with(
                db,
                &ctx,
                question,
                limit,
                RetrievalMode::Fused,
                embedder,
            )
            .await
        }
    }
    .expect("knowledge search");
    ranked_keys(b, world, id, caller, hits)
}

/// Asserts the permission invariant on every passage, and returns the section
/// keys in rank order, each once.
fn ranked_keys(
    b: &KnowledgeBenchmark,
    world: &World,
    id: &str,
    caller: &str,
    hits: Vec<KnowledgeHit>,
) -> Vec<String> {
    let readable = b.readable_by(caller).expect("a fixture caller");
    let mut seen = HashSet::new();
    let mut ranked = Vec::new();
    for hit in hits {
        let collection = world
            .collection_by_source
            .get(&hit.citation.data_source_id)
            .unwrap_or_else(|| panic!("{id}: a passage from a data source this run never seeded"));
        assert!(
            readable.contains(collection.as_str()),
            "{id}: caller {caller} received a passage from unreadable collection {collection}"
        );
        let article = &world.article_by_item[&hit.citation.item_id];
        let key = section_key(article, &hit.citation.heading_path);
        if seen.insert(key.clone()) {
            ranked.push(key);
        }
    }
    ranked
}

#[tokio::test]
async fn knowledge_retrieval_benchmark() {
    let db = skip_if_no_db!(test_db().await);
    let b = benchmark();
    let world = seed(&db, &b).await;
    let retrieval = RetrievalUnderTest::from_env();

    let pool = db.clone();
    let bench = b.clone();
    let seeded = world.clone();
    let body = async move {
        let (db, b, world) = (pool, bench, seeded);
        if let Some(embedder) = &retrieval.embedder {
            embed_corpus(&db, embedder, &world).await;
        }

        // Every judged section is one the chunker really produced.
        let fixture_sections: BTreeSet<String> = b.sections().into_keys().collect();
        let mut produced = BTreeSet::new();
        for (article, item) in &world.item_by_article {
            let paths: Vec<Vec<String>> = sqlx::query_scalar(
                "SELECT DISTINCT heading_path FROM knowledge_chunk WHERE source_id = $1",
            )
            .bind(item)
            .fetch_all(&db)
            .await
            .expect("read chunk heading paths");
            produced.extend(paths.iter().map(|p| section_key(article, p)));
        }
        assert_eq!(
            produced, fixture_sections,
            "the fixture's section keys must be exactly the sections the chunker produced"
        );

        let mut retrieved = Vec::new();
        for q in &b.questions {
            let ranked = run(&db, &b, &world, &retrieval, &q.id, &q.caller, &q.question).await;
            if q.category != Category::PermissionRestricted {
                retrieved.push(Retrieved {
                    question: q.id.clone(),
                    ranked,
                });
                continue;
            }
            // The permission case and its positive control.
            let judged: HashSet<&str> = q.judgments.iter().map(|j| j.doc.as_str()).collect();
            assert!(
                !ranked.iter().any(|s| judged.contains(s.as_str())),
                "{}: the answer leaked to {}: {ranked:?}",
                q.id,
                q.caller
            );
            let control = q.control_caller.as_deref().expect("validated");
            let allowed = run(&db, &b, &world, &retrieval, &q.id, control, &q.question).await;
            assert!(
                q.judgments
                    .iter()
                    .any(|j| j.grade >= 2 && allowed.contains(&j.doc)),
                "{}: the control caller {control} did not reach the answer, so the \
                 caller's empty result proves nothing about permissions",
                q.id
            );
        }

        if b.status == FixtureStatus::Draft {
            println!(
                "knowledge benchmark is a DRAFT: {} questions ran, every permission \
                 check passed, every judged section exists. Scores are withheld until \
                 the fixture is reviewed and frozen.",
                b.questions.len()
            );
            return;
        }

        let report = score(&b, &retrieved).expect("every scored question ran");
        let model = retrieval.embedder.as_ref().map(|e| e.model_id().to_owned());
        println!(
            "retrieval mode {:?}, embedding model {}",
            retrieval.mode,
            model.as_deref().unwrap_or("none")
        );
        println!("{}", report.render());
        println!("{}", cross_lingual_report(&b, &retrieved));
        let fingerprint = fixture_fingerprint(&b);

        let (path, model) = match (retrieval.mode, model) {
            (RetrievalMode::Vector, _) => {
                println!(
                    "vector-only retrieval is measured, not gated: no baseline is read or written"
                );
                return;
            }
            (RetrievalMode::Fused, Some(model)) => (FUSED_BASELINE_PATH, Some(model)),
            _ => (BASELINE_PATH, None),
        };

        if std::env::var("UPDATE_KNOWLEDGE_BASELINE").is_ok() {
            let baseline = KnowledgeBaseline {
                fixture_fingerprint: fingerprint,
                scores: report.scores.clone(),
            };
            let json = match model {
                None => serde_json::to_string_pretty(&baseline),
                Some(embedding_model) => serde_json::to_string_pretty(&FusedBaseline {
                    embedding_model,
                    baseline,
                }),
            };
            std::fs::write(path, json.expect("baseline serializes") + "\n")
                .expect("write baseline");
            println!("re-recorded {path}");
            return;
        }

        let raw = std::fs::read_to_string(path).unwrap_or_else(|_| {
            panic!("no baseline at {path}; a frozen fixture has one per gated mode")
        });
        let baseline: KnowledgeBaseline = match model {
            None => serde_json::from_str(&raw).expect("baseline must parse"),
            Some(model) => {
                let fused: FusedBaseline =
                    serde_json::from_str(&raw).expect("fused baseline must parse");
                assert_eq!(
                    fused.embedding_model, model,
                    "the fused baseline was measured with another embedding model; its scores \
                     are not comparable"
                );
                fused.baseline
            }
        };
        assert_eq!(
            baseline.fixture_fingerprint, fingerprint,
            "the fixture changed since its baseline was recorded; re-record with \
             UPDATE_KNOWLEDGE_BASELINE=1 and review the diff"
        );
        let failures = check_regression(&report.scores, &baseline.scores);
        assert!(
            failures.is_empty(),
            "knowledge retrieval regressed:\n  {}\n\n{}",
            failures.join("\n  "),
            report.render()
        );
    };

    assert_then_cleanup(body, cleanup_world(&db, &world)).await;
}

/// Removes everything [`seed`] created.
async fn cleanup_world(db: &DbPool, world: &World) {
    for item in world.item_by_article.values() {
        delete_article(db, *item, None).await;
    }
    for source in world.collection_by_source.keys() {
        let _ = sqlx::query("DELETE FROM knowledge_data_source WHERE id = $1")
            .bind(source)
            .execute(db)
            .await;
    }
    for (user, role) in &world.roles {
        drop_user(db, *user, *role).await;
    }
}

/// How far apart the calibration's floors are (D-498 step 5e).
const FLOOR_STEP: f64 = 0.01;

/// Every section `caller` can read, ranked as vector retrieval ranks them, each
/// with the cosine similarity of its closest chunk to the question.
///
/// Retrieval returns at most `MAX_KNOWLEDGE_LIMIT` sections and no scores, and
/// every benchmark caller with any access reads more sections than that. A
/// floor applied to retrieval's own output would miss what the floor lets
/// through past that limit. So the whole ranking is rebuilt from each chunk's
/// distance, by the rule retrieval applies: items in order of their closest
/// chunk, each item's sections in document order. The run fails unless the
/// rebuilt ranking equals retrieval's at every position retrieval returns, and
/// unless retrieval, when it returns fewer sections than its limit, returned
/// every readable one.
async fn scored_run(
    db: &DbPool,
    b: &KnowledgeBenchmark,
    world: &World,
    embedder: &EmbeddingClient,
    id: &str,
    caller: &str,
    question: &str,
) -> ScoredRetrieval {
    let user = world.user_by_caller[caller];
    let hits = attome_search::search_knowledge_with(
        db,
        &caller_ctx(user),
        question,
        MAX_KNOWLEDGE_LIMIT,
        RetrievalMode::Vector,
        Some(embedder),
    )
    .await
    .expect("vector knowledge search");
    let returned = ranked_keys(b, world, id, caller, hits);

    let (vectors, _usage) = embedder
        .embed(&[question.trim()], EmbedKind::Query)
        .await
        .expect("embed the question");
    let literal = vector_literal(&vectors[0]).expect("the question's vector literal");
    let readable = b.readable_by(caller).expect("a fixture caller");
    let sources: Vec<Uuid> = world
        .collection_by_source
        .iter()
        .filter(|(_, collection)| readable.contains(collection.as_str()))
        .map(|(source, _)| *source)
        .collect();
    let items: Vec<Uuid> = world.item_by_article.values().copied().collect();
    let chunks: Vec<(Uuid, i32, Vec<String>, f64)> = sqlx::query_as(
        "SELECT source_id, ordinal, heading_path, 1 - (embedding <=> $1::halfvec) \
         FROM knowledge_chunk \
         WHERE source_id = ANY($2) AND collection_ref = ANY($3) \
           AND lifecycle = 'published' AND embedding_model = $4 \
         ORDER BY embedding <=> $1::halfvec",
    )
    .bind(&literal)
    .bind(&items)
    .bind(&sources)
    .bind(embedder.model_id())
    .fetch_all(db)
    .await
    .expect("read chunk similarities");

    // Items in order of their closest chunk. Within an item, chunks by ordinal,
    // so its sections come out in document order.
    let mut item_order: Vec<Uuid> = Vec::new();
    let mut by_item: HashMap<Uuid, Vec<(i32, Vec<String>, f64)>> = HashMap::new();
    for (item, ordinal, heading_path, similarity) in chunks {
        by_item
            .entry(item)
            .or_insert_with(|| {
                item_order.push(item);
                Vec::new()
            })
            .push((ordinal, heading_path, similarity));
    }
    let mut sections: Vec<ScoredSection> = Vec::new();
    for item in item_order {
        let mut item_chunks = by_item.remove(&item).unwrap_or_default();
        item_chunks.sort_by_key(|(ordinal, _, _)| *ordinal);
        let article = &world.article_by_item[&item];
        let first = sections.len();
        for (_, heading_path, similarity) in item_chunks {
            let key = section_key(article, &heading_path);
            match sections[first..].iter().position(|s| s.key == key) {
                Some(i) => {
                    let section = &mut sections[first + i];
                    section.similarity = section.similarity.max(similarity);
                }
                None => sections.push(ScoredSection { key, similarity }),
            }
        }
    }

    let rebuilt: Vec<&str> = sections
        .iter()
        .take(returned.len())
        .map(|s| s.key.as_str())
        .collect();
    assert_eq!(
        rebuilt, returned,
        "{id}: for {caller}, the rebuilt ranking differs from vector retrieval's own, so a \
         floor applied to it is not the floor retrieval would apply"
    );
    assert!(
        returned.len() == MAX_KNOWLEDGE_LIMIT as usize || returned.len() == sections.len(),
        "{id}: retrieval returned {} sections for {caller}, below its limit, but {} are readable",
        returned.len(),
        sections.len()
    );
    ScoredRetrieval {
        question: id.to_owned(),
        sections,
    }
}

/// D-498 step 5e: can dense similarity alone provide an evidence-acceptance
/// boundary? Opt-in (module doc): runs only with `KNOWLEDGE_EVAL_CALIBRATE=1`
/// and an embedding server. Every question runs as its fixture caller, and each
/// permission case also as its control caller. Measured, never gated.
#[tokio::test]
async fn knowledge_similarity_calibration() {
    if std::env::var("KNOWLEDGE_EVAL_CALIBRATE").is_err() {
        return;
    }
    let db = skip_if_no_db!(test_db().await);
    let b = benchmark();
    assert_eq!(
        b.status,
        FixtureStatus::Frozen,
        "calibration reads reviewed judgments only"
    );
    let embedder = embedder_from_env("KNOWLEDGE_EVAL_CALIBRATE");
    let world = seed(&db, &b).await;

    let pool = db.clone();
    let bench = b.clone();
    let seeded = world.clone();
    let body = async move {
        let (db, b, world) = (pool, bench, seeded);
        embed_corpus(&db, &embedder, &world).await;

        let (mut runs, mut restricted, mut controls) = (Vec::new(), Vec::new(), Vec::new());
        for q in &b.questions {
            let run = scored_run(&db, &b, &world, &embedder, &q.id, &q.caller, &q.question).await;
            if q.category == Category::PermissionRestricted {
                let control = q.control_caller.as_deref().expect("validated");
                controls.push(
                    scored_run(&db, &b, &world, &embedder, &q.id, control, &q.question).await,
                );
                restricted.push(run);
            } else {
                runs.push(run);
            }
        }

        let calibration =
            SimilarityCalibration::measure(&b, &runs, &restricted, &controls, FLOOR_STEP)
                .expect("every scored question ran");
        println!(
            "similarity calibration, embedding model {}",
            embedder.model_id()
        );
        println!("{}", calibration.render());
    };
    assert_then_cleanup(body, cleanup_world(&db, &world)).await;
}
