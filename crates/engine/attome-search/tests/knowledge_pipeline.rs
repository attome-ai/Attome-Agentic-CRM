//! The Knowledge Base pipeline against a real database (D-489).
//!
//! What this file proves, end to end, that the unit tests cannot:
//! * the producer chunks a **published** item, writes nothing for a draft, and
//!   **removes** the chunks when the item stops being published;
//! * retrieval returns the enclosing section — including the qualifier a
//!   chunk-sized window would have severed — with the heading path a citation
//!   resolves against;
//! * a caller with no readable collection gets nothing, **with a positive
//!   control**, because a query that returns nothing for everybody passes a
//!   security assertion silently;
//! * a question matches when **any** of its content terms does, not only when
//!   every word appears in one chunk (D-498 step 2); a question with no
//!   matching content term still returns nothing; and a caller limited to one
//!   collection — through the production resolver, not a hand-built access
//!   map — retrieves only from that collection;
//! * an empty result is recorded as a knowledge gap only for a caller who could
//!   read at least one collection;
//! * the gap queue reads and triages.
//!
//! The fragment-level permission composition (share rows, the admin
//! unfiltered path, the `parent_record_id` precedence trap) is covered by
//! `knowledge_visibility.rs`; this file covers the production caller of it.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test knowledge_pipeline -- --test-threads=1
//! ```
//!
//! `--test-threads=1` is declared, not incidental: the producer resolves the
//! platform's **real** entity names (`knowledge_data_item`), so two tests
//! in this binary share those tables and must not run concurrently.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

mod knowledge_harness;
use knowledge_harness::{
    assert_then_cleanup, delete_article, drop_user, insert_article, insert_source, provision_kb,
    test_db, user_who_can_read,
};

/// An unfiltered caller: `is_admin` short-circuits the *record* predicate and
/// makes `readable_collections` return every active Data Source. Used as the
/// positive control — it proves the query path works before a zero from a
/// restricted caller is read as a permission result.
fn admin_ctx() -> SecurityContext {
    SecurityContext {
        user_id: Uuid::now_v7(),
        is_admin: true,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        unit_scope: Default::default(),
        field_masks: Default::default(),
        service_principal: false,
    }
}

/// A caller with no grants at all: every entity-access lookup resolves to
/// nothing, so `readable_collections` is empty and clause 1 of the visibility
/// rule binds `ANY(ARRAY[])`.
fn unprivileged_ctx() -> SecurityContext {
    let mut ctx = admin_ctx();
    ctx.is_admin = false;
    ctx
}

const ARTICLE: &str = "\
Intro paragraph before any heading.\n\n\
# Refunds\n\n\
Goods may be returned within thirty days of the invoice date.\n\n\
## Exceptions\n\n\
Custom orders are non-refundable unless the contract was renewed after March.\n";

async fn insert_item(db: &DbPool, source: Uuid, lifecycle: &str) -> Uuid {
    let title = format!("Refunds policy {}", Uuid::now_v7().simple());
    insert_article(db, source, &title, ARTICLE, lifecycle).await
}

async fn chunks_for(db: &DbPool, item: Uuid) -> Vec<(i32, Vec<String>)> {
    sqlx::query_as(
        "SELECT ordinal, heading_path FROM knowledge_chunk \
         WHERE source_type = 'article' AND source_id = $1 ORDER BY ordinal",
    )
    .bind(item)
    .fetch_all(db)
    .await
    .expect("read chunks")
}

async fn cleanup(db: &DbPool, source: Uuid, item: Uuid) {
    delete_article(db, item, Some(source)).await;
}

/// The producer maintains chunks only while the item is published, and
/// un-publishing **removes** them rather than hiding them — the D-489 branch
/// of `P-knowledge-base` §14.1, and the invariant whose failure is a draft
/// answering a customer with a citation.
#[tokio::test]
async fn publishing_creates_chunks_and_unpublishing_removes_them() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let source = insert_source(&db, &format!("Policy {}", Uuid::now_v7().simple())).await;
    let draft = insert_item(&db, source, "draft").await;

    let pool = db.clone();
    let body = async move {
        let db = pool;
        let stats = attome_search::reindex_item(&db, draft)
            .await
            .expect("reindex a draft");
        assert_eq!(stats.written, 0, "a draft must produce no chunks");
        assert!(chunks_for(&db, draft).await.is_empty());

        sqlx::query("UPDATE knowledge_data_item SET lifecycle = 'published' WHERE id = $1")
            .bind(draft)
            .execute(&db)
            .await
            .expect("publish");
        let stats = attome_search::reindex_item(&db, draft)
            .await
            .expect("reindex a published item");
        assert!(
            stats.written >= 2,
            "a published article must chunk: {stats:?}"
        );
        let chunks = chunks_for(&db, draft).await;
        assert!(
            chunks
                .iter()
                .any(|(_, path)| path == &vec!["Refunds".to_string(), "Exceptions".to_string()]),
            "the heading path must be captured at chunk time: {chunks:?}"
        );

        // Re-projecting unchanged content must write nothing (the hash gate).
        let again = attome_search::reindex_item(&db, draft)
            .await
            .expect("reindex idempotently");
        assert_eq!(
            again.written, 0,
            "an unchanged article must not be rewritten"
        );

        sqlx::query("UPDATE knowledge_data_item SET lifecycle = 'draft' WHERE id = $1")
            .bind(draft)
            .execute(&db)
            .await
            .expect("unpublish");
        let stats = attome_search::reindex_item(&db, draft)
            .await
            .expect("reindex an unpublished item");
        assert!(
            stats.removed > 0,
            "un-publishing must remove chunks: {stats:?}"
        );
        assert!(
            chunks_for(&db, draft).await.is_empty(),
            "an un-published article must leave nothing retrievable behind"
        );
    };
    assert_then_cleanup(body, cleanup(&db, source, draft)).await;
}

/// Retrieval returns the enclosing section, not the matched chunk.
#[tokio::test]
async fn retrieval_returns_the_section_with_a_resolvable_citation() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let source = insert_source(&db, &format!("Policy {}", Uuid::now_v7().simple())).await;
    let item = insert_item(&db, source, "published").await;
    attome_search::reindex_item(&db, item)
        .await
        .expect("reindex");

    let pool = db.clone();
    let body = async move {
        let db = pool;
        let hits = attome_search::search_knowledge(&db, &admin_ctx(), "non-refundable", 5)
            .await
            .expect("knowledge search");
        let hit = hits
            .iter()
            .find(|h| h.citation.item_id == item)
            .expect("the published article must be retrievable");
        assert_eq!(
            hit.citation.heading_path,
            vec!["Refunds".to_string(), "Exceptions".to_string()],
            "a citation needs the full heading path, not the leaf"
        );
        assert!(
            hit.citation.passage.contains("renewed after March"),
            "the qualifier a chunk-sized window would sever must survive: {}",
            hit.citation.passage
        );
        assert_eq!(hit.citation.data_source_id, source);
        assert!(
            !hit.chunk_ids.is_empty(),
            "the chunk ids feed retrieval telemetry"
        );
    };
    assert_then_cleanup(body, cleanup(&db, source, item)).await;
}

/// **The security assertion and its control.** A caller who can read no
/// collection gets zero passages; the same query as an unfiltered caller
/// returns one. Without the control a broken query that returns nothing for
/// everybody would pass the first half silently.
#[tokio::test]
async fn a_caller_without_collection_access_gets_nothing_and_the_control_works() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let source = insert_source(&db, &format!("Policy {}", Uuid::now_v7().simple())).await;
    let item = insert_item(&db, source, "published").await;
    attome_search::reindex_item(&db, item)
        .await
        .expect("reindex");

    let pool = db.clone();
    let body = async move {
        let db = pool;
        let denied = attome_search::search_knowledge(&db, &unprivileged_ctx(), "non-refundable", 5)
            .await
            .expect("knowledge search");
        assert!(
            denied.is_empty(),
            "a caller with no readable collection must get zero passages"
        );

        let allowed = attome_search::search_knowledge(&db, &admin_ctx(), "non-refundable", 5)
            .await
            .expect("control search");
        assert!(
            allowed.iter().any(|h| h.citation.item_id == item),
            "the control must return the passage, or the zero above proves nothing"
        );
    };
    assert_then_cleanup(body, cleanup(&db, source, item)).await;
}

/// The gap queue reads and triages, and a status other than `addressed` clears
/// the link.
#[tokio::test]
async fn the_gap_queue_reads_and_triages() {
    let db = skip_if_no_db!(test_db().await);
    let phrase = "refund escalation matrix";

    let pool = db.clone();
    let body = async move {
        let db = pool;
        attome_search::record_gap_topic(&db, phrase)
            .await
            .expect("record a gap");

        let (topics, _) = attome_search::list_gap_topics(&db, None, 1000, 0)
            .await
            .expect("list gaps");
        let topic = topics
            .iter()
            .find(|t| t.normalized_phrase == phrase)
            .expect("the recorded phrase must appear in the queue")
            .clone();

        let addressed =
            attome_search::triage_gap_topic(&db, topic.id, "addressed", Some(Uuid::now_v7()))
                .await
                .expect("triage");
        let addressed = addressed.expect("the topic exists");
        assert_eq!(addressed.status, "addressed");
        assert!(addressed.addressed_item_ref.is_some());

        let reopened = attome_search::triage_gap_topic(&db, topic.id, "open", None)
            .await
            .expect("reopen")
            .expect("the topic exists");
        assert_eq!(reopened.status, "open");
        assert!(
            reopened.addressed_item_ref.is_none(),
            "a status other than addressed must clear the link"
        );
    };
    // By phrase rather than by id: the id is only known once the body has read
    // the queue, and a body that panicked before then never hands it back.
    // `phrase` is already in normalized form, so it is its own stored key.
    assert_then_cleanup(body, clear_gap(&db, phrase)).await;
}

// ── D-498 step 2: any-term matching and gap recording ──────────────────────

/// An ordinary support question about [`ARTICLE`]. Most of its words —
/// *what, is, our, refund, policy, for, placed* — appear nowhere in the
/// Exceptions section, so a query that requires every word matches nothing.
/// It ends on "March?" rather than "orders?" because trailing punctuation
/// defeats stemming on a token, a separate limitation this step leaves alone.
const NATURAL_QUESTION: &str = "What is our refund policy for custom orders placed after March?";

/// A letters-only word no seeded content contains.
///
/// Letters only because `normalize_gap_phrase` drops any token carrying a
/// digit (D-452 step 3), and the gap assertions need the word to survive into
/// the stored phrase. Taken from the random tail of a v7 UUID, not its
/// timestamp prefix, so two calls in one test differ.
fn unique_word() -> String {
    Uuid::now_v7()
        .simple()
        .to_string()
        .chars()
        .rev()
        .take(16)
        .map(|c| {
            if c.is_ascii_digit() {
                char::from(b'g' + (c as u8 - b'0'))
            } else {
                c
            }
        })
        .collect()
}

fn gap_phrase(query: &str) -> String {
    attome_search::telemetry::normalize_gap_phrase(query)
        .expect("the test query must survive gap scrubbing, or a missing row proves nothing")
}

/// The gap queue's hit count for `query`'s scrubbed phrase, if a row exists.
async fn gap_count(db: &DbPool, query: &str) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT hit_count::bigint FROM knowledge_gap_topic WHERE normalized_phrase = $1",
    )
    .bind(gap_phrase(query))
    .fetch_optional(db)
    .await
    .expect("read gap topic")
}

async fn clear_gap(db: &DbPool, query: &str) {
    let _ = sqlx::query("DELETE FROM knowledge_gap_topic WHERE normalized_phrase = $1")
        .bind(gap_phrase(query))
        .execute(db)
        .await;
}

/// **Partial term overlap.** "warranty" appears nowhere in the article; the
/// other two terms do. Before D-498 step 2 every term had to match.
#[tokio::test]
async fn a_query_matches_when_only_some_of_its_terms_appear() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let source = insert_source(&db, &format!("Policy {}", Uuid::now_v7().simple())).await;
    let item = insert_item(&db, source, "published").await;
    attome_search::reindex_item(&db, item)
        .await
        .expect("reindex");

    let pool = db.clone();
    let body = async move {
        let db = pool;
        assert!(
            !ARTICLE.contains("warranty"),
            "the fixture must lack one term"
        );
        let hits = attome_search::search_knowledge(&db, &admin_ctx(), "custom orders warranty", 20)
            .await
            .expect("knowledge search");
        assert!(
            hits.iter().any(|h| h.citation.item_id == item),
            "an article holding two of three terms must be retrieved: {hits:?}"
        );
    };
    assert_then_cleanup(body, cleanup(&db, source, item)).await;
}

/// **A normal natural-language question** retrieves the section that answers
/// it, not only a keyword lifted out of it.
#[tokio::test]
async fn a_natural_language_question_retrieves_the_section_that_answers_it() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let source = insert_source(&db, &format!("Policy {}", Uuid::now_v7().simple())).await;
    let item = insert_item(&db, source, "published").await;
    attome_search::reindex_item(&db, item)
        .await
        .expect("reindex");

    let pool = db.clone();
    let body = async move {
        let db = pool;
        let hits = attome_search::search_knowledge(&db, &admin_ctx(), NATURAL_QUESTION, 20)
            .await
            .expect("knowledge search");
        assert!(
            hits.iter().any(|h| h.citation.item_id == item
                && h.citation.heading_path
                    == vec!["Refunds".to_string(), "Exceptions".to_string()]),
            "the question must retrieve the Exceptions section: {hits:?}"
        );
    };
    assert_then_cleanup(body, cleanup(&db, source, item)).await;
}

/// **No result.** A question whose content terms match nothing returns
/// nothing, and — for a caller who can read the corpus — is recorded as a gap.
///
/// The article contains "the", and so does the question. Any-term matching
/// that kept function words would retrieve it, empty results would stop
/// meaning "not covered", and this is the test that says so.
#[tokio::test]
async fn a_question_with_no_matching_content_term_returns_nothing_and_is_a_gap() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let source = insert_source(&db, &format!("Policy {}", Uuid::now_v7().simple())).await;
    let item = insert_item(&db, source, "published").await;
    attome_search::reindex_item(&db, item)
        .await
        .expect("reindex");

    let query = format!("how do I calibrate the {} {}", unique_word(), unique_word());
    clear_gap(&db, &query).await;

    let pool = db.clone();
    let asked = query.clone();
    let body = async move {
        let db = pool;
        let query = asked;
        assert!(
            ARTICLE.contains(" the "),
            "the fixture must share a function word with the query"
        );

        let hits = attome_search::search_knowledge_recorded(&db, &admin_ctx(), &query, 20, None)
            .await
            .expect("knowledge search");
        assert!(
            hits.is_empty(),
            "a shared function word must not retrieve anything: {hits:?}"
        );
        assert_eq!(
            gap_count(&db, &query).await,
            Some(1),
            "an unmatched question from a caller who can read the corpus is a gap"
        );
    };
    assert_then_cleanup(body, async {
        clear_gap(&db, &query).await;
        cleanup(&db, source, item).await;
    })
    .await;
}

/// **Permission-restricted.** A caller who can read one Data Source retrieves
/// from it and never from another holding the same article — resolved by the
/// production resolver — with an unfiltered control proving the hidden
/// article is retrievable at all.
#[tokio::test]
async fn a_caller_limited_to_one_collection_retrieves_only_from_it() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let readable = insert_source(&db, &format!("Readable {}", Uuid::now_v7().simple())).await;
    let hidden = insert_source(&db, &format!("Hidden {}", Uuid::now_v7().simple())).await;
    let readable_item = insert_item(&db, readable, "published").await;
    let hidden_item = insert_item(&db, hidden, "published").await;
    attome_search::reindex_item(&db, readable_item)
        .await
        .expect("reindex readable");
    attome_search::reindex_item(&db, hidden_item)
        .await
        .expect("reindex hidden");

    let (user_id, role_id) = user_who_can_read(&db, &[readable]).await;

    let pool = db.clone();
    let body = async move {
        let db = pool;
        let mut restricted = unprivileged_ctx();
        restricted.user_id = user_id;

        let got = attome_search::search_knowledge(&db, &restricted, NATURAL_QUESTION, 20)
            .await
            .expect("restricted search");
        assert!(
            got.iter().any(|h| h.citation.item_id == readable_item),
            "the readable collection's article must be retrieved: {got:?}"
        );
        assert!(
            !got.iter()
                .any(|h| h.citation.item_id == hidden_item || h.citation.data_source_id == hidden),
            "nothing from an unreadable collection may be retrieved: {got:?}"
        );

        let control = attome_search::search_knowledge(&db, &admin_ctx(), NATURAL_QUESTION, 20)
            .await
            .expect("control search");
        assert!(
            control.iter().any(|h| h.citation.item_id == hidden_item),
            "the control must retrieve the hidden article, or its absence above proves nothing"
        );
    };
    assert_then_cleanup(body, async {
        drop_user(&db, user_id, role_id).await;
        cleanup(&db, readable, readable_item).await;
        cleanup(&db, hidden, hidden_item).await;
    })
    .await;
}

/// **A caller who can read no collection is never recorded as a gap** (D-498).
///
/// Their empty result is a permission outcome. Recording it would put "not
/// permitted" in the authors' queue as "missing" — here, for an article that
/// exists. The admin control proves the same unmatched query *is* recorded,
/// so the missing rows are the permission decision, not a broken write.
#[tokio::test]
async fn a_caller_who_can_read_no_collection_is_never_recorded_as_a_gap() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let source = insert_source(&db, &format!("Policy {}", Uuid::now_v7().simple())).await;
    let item = insert_item(&db, source, "published").await;
    attome_search::reindex_item(&db, item)
        .await
        .expect("reindex");

    let nonsense = format!("calibrate the {} {}", unique_word(), unique_word());
    clear_gap(&db, NATURAL_QUESTION).await;
    clear_gap(&db, &nonsense).await;

    let pool = db.clone();
    let unmatched = nonsense.clone();
    let body = async move {
        let db = pool;
        let nonsense = unmatched;

        // The answer exists; this caller cannot read its collection.
        let denied = attome_search::search_knowledge_recorded(
            &db,
            &unprivileged_ctx(),
            NATURAL_QUESTION,
            20,
            None,
        )
        .await
        .expect("denied search");
        assert!(denied.is_empty(), "no readable collection, no passages");
        assert_eq!(
            gap_count(&db, NATURAL_QUESTION).await,
            None,
            "an article this caller may not read must not be recorded as missing"
        );

        // Nothing matches anywhere, and still this caller's empty result is not evidence.
        let denied =
            attome_search::search_knowledge_recorded(&db, &unprivileged_ctx(), &nonsense, 20, None)
                .await
                .expect("denied search");
        assert!(denied.is_empty());
        assert_eq!(gap_count(&db, &nonsense).await, None);

        // The control.
        let allowed =
            attome_search::search_knowledge_recorded(&db, &admin_ctx(), &nonsense, 20, None)
                .await
                .expect("control search");
        assert!(allowed.is_empty());
        assert_eq!(
            gap_count(&db, &nonsense).await,
            Some(1),
            "the same unmatched query from a caller who can read the corpus must be recorded, \
             or the missing rows above prove nothing"
        );
    };
    assert_then_cleanup(body, async {
        clear_gap(&db, NATURAL_QUESTION).await;
        clear_gap(&db, &nonsense).await;
        cleanup(&db, source, item).await;
    })
    .await;
}

/// Gives every chunk of `item` a placeholder embedding with its provenance.
async fn set_all_embeddings(db: &DbPool, item: Uuid) {
    sqlx::query(
        "UPDATE knowledge_chunk SET \
             embedding = (SELECT ('[' || string_agg('0.01', ',') || ']')::halfvec \
                          FROM generate_series(1, 1024)), \
             embedding_model = 'test-model', embedding_locality = 'local' \
         WHERE source_id = $1",
    )
    .bind(item)
    .execute(db)
    .await
    .expect("set placeholder embeddings");
}

/// `(ordinal, has an embedding)` for every chunk of `item`.
async fn embedding_states(db: &DbPool, item: Uuid) -> Vec<(i32, bool)> {
    sqlx::query_as(
        "SELECT ordinal, embedding IS NOT NULL FROM knowledge_chunk \
         WHERE source_id = $1 ORDER BY ordinal",
    )
    .bind(item)
    .fetch_all(db)
    .await
    .expect("read embedding states")
}

/// **D-498 step 5a.** A chunk's embedding describes its text. Moving an article
/// to another Data Source keeps every vector, because no text changed; editing
/// one section clears only that section's vector, so the embedding pass
/// re-embeds exactly what changed.
#[tokio::test]
async fn an_embedding_is_cleared_when_its_text_changes_and_kept_when_only_its_source_moves() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let source = insert_source(&db, &format!("Policy {}", Uuid::now_v7().simple())).await;
    let other = insert_source(&db, &format!("Other {}", Uuid::now_v7().simple())).await;
    let item = insert_item(&db, source, "published").await;
    attome_search::reindex_item(&db, item)
        .await
        .expect("reindex");

    let pool = db.clone();
    let body = async move {
        let db = pool;
        set_all_embeddings(&db, item).await;

        sqlx::query("UPDATE knowledge_data_item SET data_source_ref = $2 WHERE id = $1")
            .bind(item)
            .bind(other)
            .execute(&db)
            .await
            .expect("move the article to another Data Source");
        attome_search::reindex_item(&db, item)
            .await
            .expect("reindex after the move");
        let states = embedding_states(&db, item).await;
        assert!(
            !states.is_empty() && states.iter().all(|(_, embedded)| *embedded),
            "moving an article changes no text, so every vector must be kept: {states:?}"
        );

        sqlx::query(
            "UPDATE knowledge_data_item \
             SET text = text || E'\\n\\nClaims must quote the invoice number.' WHERE id = $1",
        )
        .bind(item)
        .execute(&db)
        .await
        .expect("edit the last section");
        attome_search::reindex_item(&db, item)
            .await
            .expect("reindex after the edit");
        let states = embedding_states(&db, item).await;
        assert!(
            states.iter().any(|(_, embedded)| !*embedded),
            "the edited section's vector must be cleared: {states:?}"
        );
        assert!(
            states.iter().any(|(_, embedded)| *embedded),
            "sections whose text did not change must keep their vectors: {states:?}"
        );
    };
    assert_then_cleanup(body, async {
        cleanup(&db, source, item).await;
        let _ = sqlx::query("DELETE FROM knowledge_data_source WHERE id = $1")
            .bind(other)
            .execute(&db)
            .await;
    })
    .await;
}
