//! **The knowledge retrieval security suite** (C8, `document/chatbot/07` § H).
//!
//! Every row runs through `attome_search::search_knowledge_recorded` — the one
//! retrieval enforcement point `search.knowledge` and `knowledge.answer` both
//! call, with the agent session's knowledge scope — against real Data Source
//! and article records, a real non-admin caller whose access comes from the
//! production resolver (role + per-source share rows), and the real producer.
//!
//! Fixture (A-49…A-53): collection A holds `secret-A`, collection B holds
//! `secret-B`; caller U can read A and cannot read B. Each test seeds its own
//! pair under a letters-only token nothing else contains, so no other test's
//! rows can compete for a result slot, and every negative assertion has a
//! positive control proving the query would have found the hidden item.
//!
//! Invariants: I-16 (explicit emptiness), I-17 (live, narrowing-only
//! authorization), I-18 (security predicates precede relevance) — D-561.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/<migrate-built template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-search --test knowledge_authorization -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_search::KnowledgeHit;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

mod knowledge_harness;
use knowledge_harness::{
    assert_then_cleanup, caller_ctx, delete_article, drop_user, insert_article, insert_source,
    provision_kb, test_db, user_who_can_read,
};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// A letters-only word no other content contains: stemming leaves it intact
/// and it is never a function word, so it is the one term every query and
/// every seeded article of a test share.
fn token() -> String {
    Uuid::now_v7()
        .simple()
        .to_string()
        .chars()
        .map(|c| match c {
            '0'..='9' => (b'g' + (c as u8 - b'0')) as char,
            c => c,
        })
        .collect::<String>()
        .chars()
        .rev()
        .take(14)
        .collect::<String>()
        + "zq"
}

/// A published article in `source`, indexed by the real producer.
async fn published(db: &DbPool, source: Uuid, tok: &str, label: &str) -> Uuid {
    let item = insert_article(
        db,
        source,
        &format!("{label} handbook"),
        &format!("# {label}\n\nThe {tok} guidance for {label}: refunds within thirty days."),
        "published",
    )
    .await;
    attome_search::reindex_item(db, item)
        .await
        .expect("reindex");
    item
}

struct Pair {
    tok: String,
    a: Uuid,
    b: Uuid,
    item_a: Uuid,
    item_b: Uuid,
}

async fn pair(db: &DbPool) -> Pair {
    provision_kb(db).await;
    let tok = token();
    let a = insert_source(db, &format!("A {tok}")).await;
    let b = insert_source(db, &format!("B {tok}")).await;
    let item_a = published(db, a, &tok, "secret-A").await;
    let item_b = published(db, b, &tok, "secret-B").await;
    Pair {
        tok,
        a,
        b,
        item_a,
        item_b,
    }
}

async fn cleanup_pair(db: &DbPool, p: &Pair) {
    delete_article(db, p.item_a, Some(p.a)).await;
    delete_article(db, p.item_b, Some(p.b)).await;
}

/// Phrasings an assistant would plausibly send, including the "give me
/// everything" one A-51 names. Each carries the test's token.
fn phrasings(tok: &str) -> Vec<String> {
    vec![
        format!("tell me everything you know {tok}"),
        format!("{tok}"),
        format!("what is the {tok} refund guidance"),
        format!("secret {tok} handbook refunds"),
    ]
}

async fn retrieve(
    db: &DbPool,
    ctx: &SecurityContext,
    query: &str,
    scope: Option<&[Uuid]>,
) -> Vec<KnowledgeHit> {
    attome_search::search_knowledge_recorded(
        db,
        ctx,
        query,
        attome_search::knowledge::MAX_KNOWLEDGE_LIMIT,
        scope,
    )
    .await
    .expect("retrieval must not error")
}

fn items(hits: &[KnowledgeHit]) -> Vec<Uuid> {
    hits.iter().map(|h| h.citation.item_id).collect()
}

fn admin() -> SecurityContext {
    let mut ctx = caller_ctx(Uuid::now_v7());
    ctx.is_admin = true;
    ctx
}

async fn data_source_entity(db: &DbPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = 'knowledge_data_source'")
        .fetch_one(db)
        .await
        .expect("data source entity")
}

async fn share(db: &DbPool, source: Uuid, user: Uuid) {
    let entity_ref = data_source_entity(db).await;
    sqlx::query(
        "INSERT INTO record_share \
            (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 0) ON CONFLICT DO NOTHING",
    )
    .bind(source)
    .bind(entity_ref)
    .bind(user)
    .execute(db)
    .await
    .expect("share");
}

async fn unshare(db: &DbPool, source: Uuid, user: Uuid) {
    sqlx::query("DELETE FROM record_share WHERE record_id = $1 AND principal_id = $2")
        .bind(source)
        .bind(user)
        .execute(db)
        .await
        .expect("unshare");
}

// ---------------------------------------------------------------------------
// A-51 — written first: the row that fails loudly if the intersection is a union
// ---------------------------------------------------------------------------

/// **Row A-51 — cross-collection isolation, then reversed.**
///
/// Scope `Some([A])`; U can read A, cannot read B. For every phrasing,
/// `secret-A` may appear and `secret-B` never does. Then the permissions are
/// reversed (U loses A, gains B) and the same scope is re-run: **neither**
/// appears — the scope still names only A, and U can no longer read it. A
/// union would return B after the reversal; a scope treated as a grant would
/// return A. Control: after the reversal U reaches B unscoped, so B's absence
/// under the scope is the intersection, not a broken query.
#[tokio::test]
async fn a51_scope_intersects_live_access_and_never_unions() {
    let db = skip_if_no_db!(test_db().await);
    let p = pair(&db).await;
    let (user, role) = user_who_can_read(&db, &[p.a]).await;
    let pool = db.clone();
    let (tok, a, b, item_a, item_b) = (p.tok.clone(), p.a, p.b, p.item_a, p.item_b);
    let body = async move {
        let db = pool;
        let u = caller_ctx(user);
        let scope = [a];
        for q in phrasings(&tok) {
            let got = items(&retrieve(&db, &u, &q, Some(&scope)).await);
            assert!(
                !got.contains(&item_b),
                "secret-B must never appear ({q}): {got:?}"
            );
        }
        let got = items(
            &retrieve(
                &db,
                &u,
                &format!("tell me everything you know {tok}"),
                Some(&scope),
            )
            .await,
        );
        assert!(
            got.contains(&item_a),
            "control: secret-A is reachable under the scope: {got:?}"
        );

        // Reverse the permissions: U loses A, gains B.
        unshare(&db, a, user).await;
        share(&db, b, user).await;
        for q in phrasings(&tok) {
            let got = items(&retrieve(&db, &u, &q, Some(&scope)).await);
            assert!(
                !got.contains(&item_a) && !got.contains(&item_b),
                "after reversal neither may appear under scope [A] ({q}): {got:?}"
            );
        }
        let unscoped =
            items(&retrieve(&db, &u, &format!("tell me everything you know {tok}"), None).await);
        assert!(
            unscoped.contains(&item_b) && !unscoped.contains(&item_a),
            "control: unscoped, U now reaches B and not A: {unscoped:?}"
        );
    };
    assert_then_cleanup(body, async {
        drop_user(&db, user, role).await;
        cleanup_pair(&db, &p).await;
    })
    .await;
}

// ---------------------------------------------------------------------------
// A-49, A-50, A-55 — no scope: the caller's live permissions alone
// ---------------------------------------------------------------------------

/// **Row A-49.** Scope `None`, U can read A: `secret-A` is returned — asserted
/// on the chunk ids, not on a result count.
#[tokio::test]
async fn a49_a_readable_collection_is_retrieved_by_chunk_id() {
    let db = skip_if_no_db!(test_db().await);
    let p = pair(&db).await;
    let (user, role) = user_who_can_read(&db, &[p.a]).await;
    let pool = db.clone();
    let (tok, item_a) = (p.tok.clone(), p.item_a);
    let body = async move {
        let db = pool;
        let expected: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM knowledge_chunk WHERE source_id = $1")
                .bind(item_a)
                .fetch_all(&db)
                .await
                .expect("A's chunks");
        assert!(!expected.is_empty(), "the producer wrote A's chunks");
        let hits = retrieve(
            &db,
            &caller_ctx(user),
            &format!("{tok} refund guidance"),
            None,
        )
        .await;
        let returned: Vec<Uuid> = hits
            .iter()
            .flat_map(|h| h.chunk_ids.iter().copied())
            .collect();
        assert!(
            returned.iter().any(|id| expected.contains(id)),
            "a chunk of secret-A must be returned: expected one of {expected:?}, got {returned:?}"
        );
    };
    assert_then_cleanup(body, async {
        drop_user(&db, user, role).await;
        cleanup_pair(&db, &p).await;
    })
    .await;
}

/// **Row A-50.** Scope `None`, U cannot read B: `secret-B` is absent from
/// every result set, for every phrasing. Control: an administrator retrieves
/// B with the same phrasings, so absence is the permission decision.
#[tokio::test]
async fn a50_an_unreadable_collection_is_absent_from_every_result() {
    let db = skip_if_no_db!(test_db().await);
    let p = pair(&db).await;
    let (user, role) = user_who_can_read(&db, &[p.a]).await;
    let pool = db.clone();
    let (tok, item_b) = (p.tok.clone(), p.item_b);
    let body = async move {
        let db = pool;
        let u = caller_ctx(user);
        for q in phrasings(&tok) {
            let got = items(&retrieve(&db, &u, &q, None).await);
            assert!(
                !got.contains(&item_b),
                "secret-B must be absent ({q}): {got:?}"
            );
            let control = items(&retrieve(&db, &admin(), &q, None).await);
            assert!(
                control.contains(&item_b),
                "control: B is retrievable ({q}): {control:?}"
            );
        }
    };
    assert_then_cleanup(body, async {
        drop_user(&db, user, role).await;
        cleanup_pair(&db, &p).await;
    })
    .await;
}

/// **Row A-55.** Scope `None`: the caller's own **live** permissions alone
/// decide — granting B takes effect on the very next retrieval, and revoking
/// A does too.
#[tokio::test]
async fn a55_without_a_scope_live_permissions_alone_decide() {
    let db = skip_if_no_db!(test_db().await);
    let p = pair(&db).await;
    let (user, role) = user_who_can_read(&db, &[p.a]).await;
    let pool = db.clone();
    let (tok, a, b, item_a, item_b) = (p.tok.clone(), p.a, p.b, p.item_a, p.item_b);
    let body = async move {
        let db = pool;
        let u = caller_ctx(user);
        let q = format!("tell me everything you know {tok}");
        let before = items(&retrieve(&db, &u, &q, None).await);
        assert!(
            before.contains(&item_a) && !before.contains(&item_b),
            "{before:?}"
        );

        share(&db, b, user).await;
        let granted = items(&retrieve(&db, &u, &q, None).await);
        assert!(
            granted.contains(&item_a) && granted.contains(&item_b),
            "{granted:?}"
        );

        unshare(&db, a, user).await;
        let revoked = items(&retrieve(&db, &u, &q, None).await);
        assert!(
            !revoked.contains(&item_a) && revoked.contains(&item_b),
            "{revoked:?}"
        );
    };
    assert_then_cleanup(body, async {
        drop_user(&db, user, role).await;
        cleanup_pair(&db, &p).await;
    })
    .await;
}

// ---------------------------------------------------------------------------
// A-52, A-53 — a scope is not authorization, and absent looks like forbidden
// ---------------------------------------------------------------------------

/// **Row A-52.** Scope `Some([A])` for a caller who **cannot** read A: zero
/// results. Control: the same caller, unscoped, reaches what they can read
/// (B), so zero is the scope-and-permission intersection, not a dead query.
#[tokio::test]
async fn a52_a_scope_naming_an_unreadable_collection_returns_nothing() {
    let db = skip_if_no_db!(test_db().await);
    let p = pair(&db).await;
    let (user, role) = user_who_can_read(&db, &[p.b]).await;
    let pool = db.clone();
    let (tok, a, item_b) = (p.tok.clone(), p.a, p.item_b);
    let body = async move {
        let db = pool;
        let u = caller_ctx(user);
        for q in phrasings(&tok) {
            let got = retrieve(&db, &u, &q, Some(&[a])).await;
            assert!(
                got.is_empty(),
                "a policy naming A is not authorization to read it ({q}): {:?}",
                items(&got)
            );
        }
        let control =
            items(&retrieve(&db, &u, &format!("tell me everything you know {tok}"), None).await);
        assert!(control.contains(&item_b), "control: {control:?}");
    };
    assert_then_cleanup(body, async {
        drop_user(&db, user, role).await;
        cleanup_pair(&db, &p).await;
    })
    .await;
}

/// **Row A-53.** A scope naming a collection that does not exist, or one that
/// was deleted: zero results and **no error** — the same `Ok(empty)` a
/// forbidden collection gives, so the answer never distinguishes "absent"
/// from "forbidden".
#[tokio::test]
async fn a53_an_absent_or_deleted_collection_is_indistinguishable_from_a_forbidden_one() {
    let db = skip_if_no_db!(test_db().await);
    let p = pair(&db).await;
    let (user, role) = user_who_can_read(&db, &[p.a]).await;
    let pool = db.clone();
    let (tok, a, b, item_a) = (p.tok.clone(), p.a, p.b, p.item_a);
    let body = async move {
        let db = pool;
        let u = caller_ctx(user);
        let q = format!("tell me everything you know {tok}");
        let before = items(&retrieve(&db, &u, &q, Some(&[a])).await);
        assert!(
            before.contains(&item_a),
            "control before deletion: {before:?}"
        );

        let absent =
            attome_search::search_knowledge_recorded(&db, &u, &q, 20, Some(&[Uuid::now_v7()]))
                .await;
        let forbidden = attome_search::search_knowledge_recorded(&db, &u, &q, 20, Some(&[b])).await;
        sqlx::query("UPDATE knowledge_data_source SET is_active = FALSE WHERE id = $1")
            .bind(a)
            .execute(&db)
            .await
            .expect("deactivate A");
        let deleted = attome_search::search_knowledge_recorded(&db, &u, &q, 20, Some(&[a])).await;
        for (what, outcome) in [
            ("absent", absent),
            ("forbidden", forbidden),
            ("deleted", deleted),
        ] {
            let hits = outcome.unwrap_or_else(|e| panic!("{what}: must not error: {e:?}"));
            assert!(hits.is_empty(), "{what}: zero results: {:?}", items(&hits));
        }
    };
    assert_then_cleanup(body, async {
        drop_user(&db, user, role).await;
        cleanup_pair(&db, &p).await;
    })
    .await;
}

// ---------------------------------------------------------------------------
// A-54 — explicit empty scope: no retrieval at all
// ---------------------------------------------------------------------------

/// **Row A-54 — `Some([])` issues no query.**
///
/// Proven on a pool that cannot connect: a lazy pool pointed at a closed
/// port, where **any** query fails. With `Some(&[])` retrieval still returns
/// `Ok(empty)`, so it reached the database zero times — not "ran and found
/// nothing". Control: the same pool with `None` errors, so the pool really
/// does fail every query. Distinct from `None`, which is asserted by A-55.
#[tokio::test]
async fn a54_an_explicit_empty_scope_issues_no_query() {
    let dead = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/no_database")
        .expect("a lazy pool never connects at construction");
    let u = caller_ctx(Uuid::now_v7());

    let empty =
        attome_search::search_knowledge_recorded(&dead, &u, "tell me everything", 20, Some(&[]))
            .await
            .expect("an explicit empty scope must not touch the database");
    assert!(empty.is_empty());

    let control =
        attome_search::search_knowledge_recorded(&dead, &u, "tell me everything", 20, None).await;
    assert!(
        control.is_err(),
        "control: an unscoped retrieval on this pool must fail"
    );
}

/// **Row A-54 on a real database.** `Some([])` retrieves nothing even for a
/// caller who can read the collection holding a matching article, and records
/// no gap topic. Control: `Some([A])` retrieves it.
#[tokio::test]
async fn a54_an_explicit_empty_scope_retrieves_nothing_for_a_reader() {
    let db = skip_if_no_db!(test_db().await);
    let p = pair(&db).await;
    let (user, role) = user_who_can_read(&db, &[p.a]).await;
    let pool = db.clone();
    let (tok, a, item_a) = (p.tok.clone(), p.a, p.item_a);
    let body = async move {
        let db = pool;
        let u = caller_ctx(user);
        let q = format!("tell me everything you know {tok} nothingmatcheszq");
        let got = retrieve(&db, &u, &q, Some(&[])).await;
        assert!(got.is_empty(), "{:?}", items(&got));
        let gaps: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM knowledge_gap_topic WHERE normalized_phrase ILIKE $1",
        )
        .bind(format!("%{tok}%"))
        .fetch_one(&db)
        .await
        .expect("count gap topics");
        assert_eq!(gaps, 0, "no retrieval ran, so no gap is recorded");
        let control = items(
            &retrieve(
                &db,
                &u,
                &format!("tell me everything you know {tok}"),
                Some(&[a]),
            )
            .await,
        );
        assert!(control.contains(&item_a), "control: {control:?}");
    };
    assert_then_cleanup(body, async {
        drop_user(&db, user, role).await;
        cleanup_pair(&db, &p).await;
    })
    .await;
}

// ---------------------------------------------------------------------------
// A-57 — lifecycle is a security predicate, not a ranking one
// ---------------------------------------------------------------------------

/// Inserts one chunk directly — the storage shape no producer writes today
/// (a draft chunk, or a chunk with a parent record) — with the producer's own
/// chunking, so it matches a query exactly as a real chunk would.
async fn seed_chunk(
    db: &DbPool,
    collection: Uuid,
    item: Uuid,
    lifecycle: &str,
    parent: Option<(&str, Uuid)>,
    title: &str,
    body: &str,
) -> Uuid {
    let chunk = attome_search::chunk_article(title, body)
        .into_iter()
        .next()
        .expect("one chunk");
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO knowledge_chunk \
            (id, collection_ref, source_type, source_id, parent_entity, parent_record_id, \
             lifecycle, ordinal, heading_path, text_display, text_indexed, tsv, content_hash, indexed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                 to_tsvector('attome_search', $11), $12, NOW())",
    )
    .bind(id)
    .bind(collection)
    .bind(attome_search::knowledge_index::SOURCE_TYPE)
    .bind(item)
    .bind(parent.map(|(e, _)| e.to_owned()))
    .bind(parent.map(|(_, r)| r))
    .bind(lifecycle)
    .bind(chunk.ordinal)
    .bind(&chunk.heading_path)
    .bind(&chunk.text_display)
    .bind(&chunk.text_indexed)
    .bind(&chunk.content_hash)
    .execute(db)
    .await
    .expect("seed chunk");
    id
}

/// **Row A-57.** A draft and a published article both match; the draft never
/// appears at any K — here the maximum K with only these two in play, so
/// ranking cannot be the reason. The draft is present twice over: through the
/// real producer (which writes nothing for it) and as a seeded draft chunk in
/// a collection the caller reads, the case the retrieval-time lifecycle
/// predicate exists for.
#[tokio::test]
async fn a57_a_draft_never_appears_at_any_k() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let tok = token();
    let a = insert_source(&db, &format!("A {tok}")).await;
    let pub_item = published(&db, a, &tok, "Published policy").await;
    let body_text = format!(
        "# Draft policy\n\nThe {tok} guidance for Draft policy: refunds within thirty days."
    );
    let draft_item = insert_article(&db, a, "Draft policy handbook", &body_text, "draft").await;
    attome_search::reindex_item(&db, draft_item)
        .await
        .expect("reindex draft");
    let seeded = seed_chunk(
        &db,
        a,
        draft_item,
        "draft",
        None,
        "Draft policy handbook",
        &body_text,
    )
    .await;
    let (user, role) = user_who_can_read(&db, &[a]).await;
    let pool = db.clone();
    let tok2 = tok.clone();
    let body = async move {
        let db = pool;
        for ctx in [caller_ctx(user), admin()] {
            for q in phrasings(&tok2) {
                let hits = retrieve(&db, &ctx, &q, None).await;
                let got = items(&hits);
                assert!(
                    !got.contains(&draft_item),
                    "the draft never appears ({q}): {got:?}"
                );
                assert!(
                    !hits.iter().any(|h| h.chunk_ids.contains(&seeded)),
                    "the draft chunk never reaches a result ({q})"
                );
            }
            let control = items(
                &retrieve(
                    &db,
                    &ctx,
                    &format!("tell me everything you know {tok2}"),
                    None,
                )
                .await,
            );
            assert!(
                control.contains(&pub_item),
                "the published article is eligible: {control:?}"
            );
        }
    };
    assert_then_cleanup(body, async {
        drop_user(&db, user, role).await;
        let _ = sqlx::query("DELETE FROM knowledge_chunk WHERE id = $1")
            .bind(seeded)
            .execute(&db)
            .await;
        delete_article(&db, draft_item, None).await;
        delete_article(&db, pub_item, Some(a)).await;
    })
    .await;
}

// ---------------------------------------------------------------------------
// A-58 — record visibility is live, per retrieval
// ---------------------------------------------------------------------------

/// **Row A-58.** A chunk whose parent record becomes inaccessible between two
/// retrievals is returned by the first and **not** by the second — live
/// authorization per retrieval, not a snapshot. No producer writes parented
/// chunks today, so the chunk is seeded in the storage shape the visibility
/// rule governs; its parent is a record U reads through a share, and the
/// share is revoked between the two calls.
#[tokio::test]
async fn a58_a_parent_record_lost_between_retrievals_hides_its_chunk() {
    let db = skip_if_no_db!(test_db().await);
    provision_kb(&db).await;
    let tok = token();
    let a = insert_source(&db, &format!("A {tok}")).await;
    let parent = insert_source(&db, &format!("Parent {tok}")).await;
    let body_text =
        format!("# Case notes\n\nThe {tok} guidance for Case notes: refunds within thirty days.");
    let item = insert_article(&db, a, "Case notes", &body_text, "published").await;
    let seeded = seed_chunk(
        &db,
        a,
        item,
        attome_search::knowledge_index::PUBLISHED,
        Some(("knowledge_data_source", parent)),
        "Case notes",
        &body_text,
    )
    .await;
    let (user, role) = user_who_can_read(&db, &[a, parent]).await;
    let pool = db.clone();
    let tok2 = tok.clone();
    let body = async move {
        let db = pool;
        let u = caller_ctx(user);
        let q = format!("tell me everything you know {tok2}");
        let first = retrieve(&db, &u, &q, None).await;
        assert!(
            first.iter().any(|h| h.chunk_ids.contains(&seeded)),
            "first retrieval: {:?}",
            items(&first)
        );

        unshare(&db, parent, user).await;
        let second = retrieve(&db, &u, &q, None).await;
        assert!(
            !second.iter().any(|h| h.chunk_ids.contains(&seeded)),
            "after losing the parent record, the chunk is not retrievable: {:?}",
            items(&second)
        );
    };
    assert_then_cleanup(body, async {
        drop_user(&db, user, role).await;
        let _ = sqlx::query("DELETE FROM knowledge_chunk WHERE id = $1")
            .bind(seeded)
            .execute(&db)
            .await;
        delete_article(&db, item, Some(a)).await;
        let _ = sqlx::query("DELETE FROM knowledge_data_source WHERE id = $1")
            .bind(parent)
            .execute(&db)
            .await;
    })
    .await;
}
