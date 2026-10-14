//! Authentication context on refresh families, and the session id that names
//! the family (D-510 rule 2, attome-auth hardening 2.1a).
//!
//! Requires a live Postgres migrated through 0462, same convention as
//! `refresh_flow.rs`. Run manually:
//!
//! ```powershell
//! cargo test -p attome-auth --test session_context -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::accounts::issue_access_token;
use attome_auth::auth_context::AuthContext;
use attome_auth::refresh::{
    self, IssuedRefresh, RedeemedRefresh, RefreshLifetimes, SessionContext,
};
use attome_auth::{PepperRing, SessionId, validate_session_token};
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use fred::prelude::{Builder, RedisConfig};
use uuid::Uuid;

const THIRTY_DAYS_SECS: i64 = 30 * 86_400;
const ISSUER: &str = "attome-session-context-test";

async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

fn lifetimes() -> RefreshLifetimes {
    RefreshLifetimes {
        idle_secs: 3600,
        absolute_secs: THIRTY_DAYS_SECS,
    }
}

fn ring() -> PepperRing {
    PepperRing::new(0, "session-context-test-pepper-0123456789abcdef", &[])
}

fn jwt_ring() -> KeyRing {
    KeyRing::single("session-context-test-jwt-secret-0123456789".to_string())
}

/// Built but never connected: `redeem_session` touches Redis only to invalidate
/// the epoch cache after reuse detection, which is best-effort. Only the
/// rotation race can reach it here, and it asserts nothing about Redis.
fn unconnected_redis() -> attome_cache::RedisPool {
    let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
    Builder::from_config(config).build_pool(1).unwrap()
}

async fn create_test_user(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, created_at, is_active)
         VALUES ($1, $2, now(), true)",
    )
    .bind(id)
    .bind(format!("session-context-{id}@example.invalid"))
    .execute(db)
    .await
    .expect("insert test user");
    id
}

async fn db_now(db: &DbPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT NOW()")
        .fetch_one(db)
        .await
        .expect("read the database clock")
}

async fn issue(db: &DbPool, user_id: Uuid, context: &AuthContext) -> IssuedRefresh {
    refresh::issue(db, user_id, context, lifetimes(), &ring())
        .await
        .expect("issue refresh token")
}

async fn try_rotate(db: &DbPool, bearer: &str) -> Result<RedeemedRefresh, AppError> {
    refresh::redeem_session(
        db,
        &attome_cache::Store::Redis(unconnected_redis()),
        bearer,
        lifetimes(),
        &ring(),
    )
    .await
}

async fn rotate(db: &DbPool, bearer: &str) -> RedeemedRefresh {
    try_rotate(db, bearer).await.expect("rotate refresh token")
}

async fn context_of(db: &DbPool, user_id: Uuid, family_id: Uuid) -> Option<SessionContext> {
    refresh::session_context(db, user_id, SessionId(family_id), THIRTY_DAYS_SECS)
        .await
        .expect("read session context")
}

fn public_id_of(bearer: &str) -> Uuid {
    bearer
        .split_once('.')
        .expect("token shape")
        .0
        .parse()
        .expect("public_id is a uuid")
}

/// The session token's `sid` is the id of the family `issue` created, and
/// rotation stays in that family.
#[tokio::test]
async fn the_session_token_sid_names_the_family_issue_created() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let issued = issue(&db, user_id, &AuthContext::password()).await;

    let row_family: Option<Uuid> =
        sqlx::query_scalar("SELECT family_id FROM refresh_token WHERE public_id = $1")
            .bind(public_id_of(&issued.bearer))
            .fetch_one(&db)
            .await
            .expect("refresh row");
    assert_eq!(row_family, Some(issued.family_id));

    let token = issue_access_token(
        &db,
        user_id,
        issued.family_id,
        &jwt_ring(),
        ISSUER,
        ISSUER,
        900,
    )
    .await
    .expect("issue access token");
    let (claims, sid) =
        validate_session_token(&token, &jwt_ring(), ISSUER, ISSUER).expect("validate token");
    assert_eq!(claims.sub, user_id);
    assert_eq!(sid, SessionId(issued.family_id));

    let rotated = rotate(&db, &issued.bearer).await;
    assert_eq!(
        rotated.family_id, issued.family_id,
        "a rotation stays in the family the sid names"
    );
    assert_eq!(rotated.user_id, user_id);
}

/// A local sign-in records the database clock at issue and the methods the
/// caller verified, and starts unelevated.
#[tokio::test]
async fn issue_records_server_derived_auth_time_and_the_verified_methods() {
    let db = skip_if_no_db!(pool().await);
    let cases = [
        (AuthContext::password(), vec!["pwd"]),
        (AuthContext::password_and_totp(), vec!["pwd", "otp"]),
        (
            AuthContext::password_and_recovery_code(),
            vec!["pwd", "rcode"],
        ),
    ];
    for (context, expected_amr) in cases {
        let user_id = create_test_user(&db).await;
        let before = db_now(&db).await;
        let issued = issue(&db, user_id, &context).await;
        let after = db_now(&db).await;

        let recorded = context_of(&db, user_id, issued.family_id)
            .await
            .expect("a live family has a context");
        let auth_time = recorded
            .auth_time
            .expect("a local sign-in records its authentication time");
        assert!(
            before <= auth_time && auth_time <= after,
            "auth_time {auth_time} must come from the database clock at issue ({before}..{after})"
        );
        assert_eq!(recorded.amr, expected_amr);
        assert_eq!(
            recorded.elevated_until, None,
            "a new sign-in starts unelevated"
        );
    }
}

/// A federated sign-in records no time unless the provider asserted one, and an
/// asserted time is never stored later than the moment of issue.
#[tokio::test]
async fn a_federated_sign_in_records_only_an_asserted_time_and_never_a_later_one() {
    let db = skip_if_no_db!(pool().await);

    let user_id = create_test_user(&db).await;
    let issued = issue(&db, user_id, &AuthContext::federated(None)).await;
    let recorded = context_of(&db, user_id, issued.family_id)
        .await
        .expect("live");
    assert_eq!(
        recorded.auth_time, None,
        "no asserted time means no recorded time"
    );
    assert_eq!(recorded.amr, vec!["fed"]);

    let user_id = create_test_user(&db).await;
    let asserted = db_now(&db).await - Duration::minutes(3);
    let issued = issue(&db, user_id, &AuthContext::federated(Some(asserted))).await;
    let recorded = context_of(&db, user_id, issued.family_id)
        .await
        .expect("live");
    assert_eq!(recorded.auth_time, Some(asserted));

    let user_id = create_test_user(&db).await;
    let future = db_now(&db).await + Duration::hours(1);
    let issued = issue(&db, user_id, &AuthContext::federated(Some(future))).await;
    let after = db_now(&db).await;
    let recorded = context_of(&db, user_id, issued.family_id)
        .await
        .expect("live");
    assert!(
        recorded.auth_time.expect("asserted") <= after,
        "an asserted time in the future must not be stored as fresher than issue"
    );
}

/// Rotation copies the context unchanged, however often it runs. It never
/// advances `auth_time`, adds to `amr` or sets `elevated_until`.
#[tokio::test]
async fn refresh_copies_the_context_unchanged_and_never_advances_it() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let issued = issue(&db, user_id, &AuthContext::password_and_totp()).await;
    // Age the recorded authentication so any advance would be visible.
    sqlx::query(
        "UPDATE refresh_token SET auth_time = NOW() - interval '20 minutes'
         WHERE family_id = $1",
    )
    .bind(issued.family_id)
    .execute(&db)
    .await
    .expect("age auth_time");
    let original = context_of(&db, user_id, issued.family_id)
        .await
        .expect("live family");

    let mut bearer = issued.bearer;
    for _ in 0..3 {
        let rotated = rotate(&db, &bearer).await;
        assert_eq!(rotated.family_id, issued.family_id);
        assert_eq!(
            context_of(&db, user_id, issued.family_id).await,
            Some(original.clone()),
            "a rotation must copy the authentication context unchanged"
        );
        bearer = rotated.bearer;
    }
}

/// A new sign-in starts its own family with a fresh, unelevated context, and
/// leaves an earlier family's context as it was.
#[tokio::test]
async fn a_new_sign_in_starts_a_new_unelevated_context() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let first = issue(&db, user_id, &AuthContext::password_and_totp()).await;
    // Simulate an earlier step-up on the first family.
    sqlx::query(
        "UPDATE refresh_token
         SET auth_time = NOW() - interval '30 minutes',
             elevated_until = NOW() + interval '5 minutes'
         WHERE family_id = $1",
    )
    .bind(first.family_id)
    .execute(&db)
    .await
    .expect("elevate the first family");
    let first_context = context_of(&db, user_id, first.family_id)
        .await
        .expect("live first family");

    let before = db_now(&db).await;
    let second = issue(&db, user_id, &AuthContext::password()).await;

    assert_ne!(second.family_id, first.family_id);
    let second_context = context_of(&db, user_id, second.family_id)
        .await
        .expect("live second family");
    assert!(second_context.auth_time.expect("recorded") >= before);
    assert_eq!(second_context.amr, vec!["pwd"]);
    assert_eq!(
        second_context.elevated_until, None,
        "elevation never carries over to a new sign-in"
    );
    assert_eq!(
        context_of(&db, user_id, first.family_id).await,
        Some(first_context),
        "the earlier family keeps its own context"
    );
}

/// A session id reaches only its own account's live family: never another
/// user's, an unknown one, or a revoked one. Rotating one family leaves another
/// untouched.
#[tokio::test]
async fn a_session_id_cannot_reach_another_users_or_a_dead_family() {
    let db = skip_if_no_db!(pool().await);
    let alice = create_test_user(&db).await;
    let bob = create_test_user(&db).await;
    let alices = issue(&db, alice, &AuthContext::password_and_totp()).await;
    let bobs = issue(&db, bob, &AuthContext::password()).await;

    assert!(context_of(&db, bob, alices.family_id).await.is_none());
    assert!(context_of(&db, alice, bobs.family_id).await.is_none());
    assert!(context_of(&db, alice, Uuid::now_v7()).await.is_none());

    let bobs_context = context_of(&db, bob, bobs.family_id).await.expect("live");
    rotate(&db, &alices.bearer).await;
    assert_eq!(
        context_of(&db, bob, bobs.family_id).await,
        Some(bobs_context),
        "rotating one family must not touch another"
    );

    refresh::revoke(&db, &bobs.bearer, &ring())
        .await
        .expect("revoke");
    assert!(
        context_of(&db, bob, bobs.family_id).await.is_none(),
        "a revoked family has no live context"
    );
}

/// After two concurrent rotations of one token the family can only have lost
/// elevation. Which of two outcomes occurs depends on timing:
///
/// - both redeemers read the token unused, one loses the CAS, and the family
///   stays live with exactly `ceiling`; or
/// - the winner commits before the loser reads, the loser sees a used token,
///   and D-129 reuse detection revokes the whole family.
///
/// Either way exactly one replacement exists, no row carries anything but
/// `ceiling`, and a live context, if any, carries `ceiling` unchanged.
async fn assert_the_race_only_lost_elevation(
    db: &DbPool,
    user_id: Uuid,
    family_id: Uuid,
    results: [&Result<RedeemedRefresh, AppError>; 2],
    ceiling: Option<DateTime<Utc>>,
) {
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "exactly one concurrent rotation wins: {results:?}"
    );
    let rows: Vec<Option<DateTime<Utc>>> =
        sqlx::query_scalar("SELECT elevated_until FROM refresh_token WHERE family_id = $1")
            .bind(family_id)
            .fetch_all(db)
            .await
            .expect("family rows");
    assert_eq!(rows.len(), 2, "the original plus exactly one replacement");
    assert!(
        rows.iter().all(|row| *row == ceiling),
        "no row may gain or extend elevation: {rows:?} vs {ceiling:?}"
    );
    if let Some(live) = context_of(db, user_id, family_id).await {
        assert_eq!(
            live.elevated_until, ceiling,
            "a surviving family keeps elevated_until exactly"
        );
    }
}

#[tokio::test]
async fn concurrent_rotations_never_create_or_extend_elevation() {
    let db = skip_if_no_db!(pool().await);

    let user_id = create_test_user(&db).await;
    let unelevated = issue(&db, user_id, &AuthContext::password_and_totp()).await;
    let (first, second) = tokio::join!(
        try_rotate(&db, &unelevated.bearer),
        try_rotate(&db, &unelevated.bearer)
    );
    assert_the_race_only_lost_elevation(
        &db,
        user_id,
        unelevated.family_id,
        [&first, &second],
        None,
    )
    .await;

    let user_id = create_test_user(&db).await;
    let elevated = issue(&db, user_id, &AuthContext::password_and_totp()).await;
    let until: DateTime<Utc> = sqlx::query_scalar(
        "UPDATE refresh_token SET elevated_until = NOW() + interval '5 minutes'
         WHERE family_id = $1 RETURNING elevated_until",
    )
    .bind(elevated.family_id)
    .fetch_one(&db)
    .await
    .expect("elevate the family");
    let (first, second) = tokio::join!(
        try_rotate(&db, &elevated.bearer),
        try_rotate(&db, &elevated.bearer)
    );
    assert_the_race_only_lost_elevation(
        &db,
        user_id,
        elevated.family_id,
        [&first, &second],
        Some(until),
    )
    .await;
}
