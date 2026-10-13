//! Integration tests for `attome_security::db::resolve_accessible_org_ids` — the
//! BusinessUnit-tier data source behind `SecurityContext::accessible_org_ids`
//! and therefore behind `rls_predicate`'s `organization_ref = ANY(...)` fast
//! path (D-133 §4).
//!
//! This function had no coverage of any kind before migration
//! `0102_default_root_organization.sql` added the home-org seed, and its body
//! is a recursive CTE — the one shape where "it compiles" proves nothing.
//! `rls_property.rs` deliberately tests only generated SQL *text*; this file
//! is the counterpart that makes Postgres actually execute the query.
//!
//! Requires a live Postgres (`DATABASE_URL`), same convention as
//! `tests/resolver.rs`. No Redis needed — this function takes a `DbPool`
//! directly and does no caching of its own. Run manually against a throwaway
//! database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-security --test accessible_orgs -- --test-threads=1
//! ```
//!
//! Every test seeds its own random-UUID rows and cleans them up; nothing here
//! truncates a shared table or depends on the root org migration 0102 seeds
//! (that row's presence is irrelevant to these assertions, which only ever
//! look at their own orgs).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_security::db::resolve_accessible_org_ids;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// Inserts a throwaway org, optionally under `parent`.
async fn seed_org(db: &DbPool, parent: Option<Uuid>) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO organization (id, name, organization_ref, is_active) \
         VALUES ($1, $2, $3, true)",
    )
    .bind(id)
    .bind(format!("test-org-{id}"))
    .bind(parent)
    .execute(db)
    .await
    .expect("insert throwaway organization");
    id
}

/// Inserts a throwaway user whose home org is `home_org` (NULL when `None`).
async fn seed_user(db: &DbPool, home_org: Option<Uuid>) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, organization_ref, is_active) \
         VALUES ($1, $2, $2 || '@test.invalid', $3, true)",
    )
    .bind(id)
    .bind(format!("test-user-{id}"))
    .bind(home_org)
    .execute(db)
    .await
    .expect("insert throwaway user_account");
    id
}

async fn add_membership(db: &DbPool, user_id: Uuid, org_id: Uuid) {
    sqlx::query(
        "INSERT INTO user_account_mm_organization (id, user_ref, organization_ref) \
         VALUES ($1, $2, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(org_id)
    .execute(db)
    .await
    .expect("insert throwaway user_account_mm_organization");
}

/// Deletes the user (membership rows cascade via the FK) and then the orgs.
async fn cleanup(db: &DbPool, user_id: Uuid, org_ids: &[Uuid]) {
    sqlx::query("DELETE FROM user_account WHERE id = $1")
        .bind(user_id)
        .execute(db)
        .await
        .expect("cleanup user");
    for org in org_ids {
        sqlx::query("DELETE FROM organization WHERE id = $1")
            .bind(org)
            .execute(db)
            .await
            .expect("cleanup org");
    }
}

fn sorted(mut ids: Vec<Uuid>) -> Vec<Uuid> {
    ids.sort();
    ids
}

/// The behavior migration 0102 exists to enable: a user with a home org but
/// NO explicit `user_account_mm_organization` row still resolves that
/// org. Before the home-org seed this returned an empty vec, which made
/// `organization_ref = ANY('{}')` match nothing and a BusinessUnit-depth role
/// see zero records.
#[tokio::test]
async fn home_org_alone_is_reachable_without_a_membership_row() {
    let db = skip_if_no_db!(test_db().await);
    let org = seed_org(&db, None).await;
    let user = seed_user(&db, Some(org)).await;

    let got = resolve_accessible_org_ids(&db, user)
        .await
        .expect("resolve_accessible_org_ids");

    assert_eq!(got, vec![org], "home org must seed the walk on its own");
    cleanup(&db, user, &[org]).await;
}

/// The home-org seed must walk the same `organization_ref` self-reference the
/// membership seed does — "my business unit and everything under it", not just
/// the one row.
#[tokio::test]
async fn home_org_seed_still_descends_the_org_tree() {
    let db = skip_if_no_db!(test_db().await);
    let root = seed_org(&db, None).await;
    let child = seed_org(&db, Some(root)).await;
    let grandchild = seed_org(&db, Some(child)).await;
    let user = seed_user(&db, Some(root)).await;

    let got = resolve_accessible_org_ids(&db, user)
        .await
        .expect("resolve_accessible_org_ids");

    assert_eq!(
        sorted(got),
        sorted(vec![root, child, grandchild]),
        "the recursive term must descend from a home-org seed too"
    );
    cleanup(&db, user, &[grandchild, child, root]).await;
}

/// Regression guard on D-133 §4's original seed: explicit membership must keep
/// working exactly as before, including for an org that is NOT the user's home
/// org (the multi-org staffer case D-133 called out — an HR consultant working
/// across more than one client org).
#[tokio::test]
async fn explicit_membership_still_resolves_independently_of_home_org() {
    let db = skip_if_no_db!(test_db().await);
    let home = seed_org(&db, None).await;
    let other = seed_org(&db, None).await;
    let other_child = seed_org(&db, Some(other)).await;
    let user = seed_user(&db, Some(home)).await;
    add_membership(&db, user, other).await;

    let got = resolve_accessible_org_ids(&db, user)
        .await
        .expect("resolve_accessible_org_ids");

    assert_eq!(
        sorted(got),
        sorted(vec![home, other, other_child]),
        "both seeds must contribute, and both must descend"
    );
    cleanup(&db, user, &[other_child, other, home]).await;
}

/// A user who is a member of their own home org (the shape migration 0102's
/// backfill plus a later admin membership add would produce) must not get the
/// org back twice — the CTE's UNION, not UNION ALL, is load-bearing here.
#[tokio::test]
async fn overlapping_seeds_do_not_duplicate_an_org() {
    let db = skip_if_no_db!(test_db().await);
    let org = seed_org(&db, None).await;
    let user = seed_user(&db, Some(org)).await;
    add_membership(&db, user, org).await;

    let got = resolve_accessible_org_ids(&db, user)
        .await
        .expect("resolve_accessible_org_ids");

    assert_eq!(
        got,
        vec![org],
        "overlapping seeds must dedupe, not duplicate"
    );
    cleanup(&db, user, &[org]).await;
}

/// A soft-deleted membership must not grant reach — the `is_deleted = false`
/// filter on the membership seed is what `remove_organization_member` relies
/// on, and the home-org seed must not accidentally paper over it.
#[tokio::test]
async fn soft_deleted_membership_grants_nothing() {
    let db = skip_if_no_db!(test_db().await);
    let org = seed_org(&db, None).await;
    let user = seed_user(&db, None).await;
    add_membership(&db, user, org).await;
    sqlx::query("UPDATE user_account_mm_organization SET is_deleted = true WHERE user_ref = $1")
        .bind(user)
        .execute(&db)
        .await
        .expect("soft-delete membership");

    let got = resolve_accessible_org_ids(&db, user)
        .await
        .expect("resolve_accessible_org_ids");

    assert!(
        got.is_empty(),
        "a removed membership must grant no reach, got {got:?}"
    );
    cleanup(&db, user, &[org]).await;
}

/// Fail-closed floor: no home org and no membership resolves to an empty set,
/// which `rls_predicate` renders as `organization_ref = ANY('{}')` — matches
/// nothing rather than erroring or matching everything.
#[tokio::test]
async fn no_home_org_and_no_membership_resolves_empty() {
    let db = skip_if_no_db!(test_db().await);
    let user = seed_user(&db, None).await;

    let got = resolve_accessible_org_ids(&db, user)
        .await
        .expect("resolve_accessible_org_ids");

    assert!(got.is_empty(), "expected no reach at all, got {got:?}");
    cleanup(&db, user, &[]).await;
}

/// A home org pointing at an org row that does not exist (possible on a
/// deployment whose org was hard-deleted — there is no FK on
/// `user_account.organization_ref`) must resolve empty, not error: the
/// seed is an `IN` against `organization`, so a dangling ref simply
/// matches no row.
#[tokio::test]
async fn dangling_home_org_reference_resolves_empty_without_erroring() {
    let db = skip_if_no_db!(test_db().await);
    let user = seed_user(&db, Some(Uuid::now_v7())).await;

    let got = resolve_accessible_org_ids(&db, user)
        .await
        .expect("a dangling home-org ref must not fail the query");

    assert!(got.is_empty(), "expected no reach at all, got {got:?}");
    cleanup(&db, user, &[]).await;
}
