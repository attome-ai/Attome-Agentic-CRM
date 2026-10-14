//! Integration tests for `attome_auth::refresh`.
//!
//! - P-account-state-enforcement (audit finding #2): a disabled user's live
//!   refresh token must stop minting new access tokens immediately, not just
//!   once the refresh token's own expiry eventually catches up (up to 30
//!   days by default).
//! - P-session-refresh-hardening (D-129): `redeem` rotates on every use and
//!   detects reuse of an already-redeemed token by revoking its whole family.
//! - Base-auth hardening 2.2 (D-504): a family ends at its absolute lifetime
//!   however often it rotates, and reuse detection also bumps `auth_epoch`.
//!
//! Requires a live Postgres with migrations 0020 and 0049 applied â€” same
//! convention as `reset_flow.rs`. Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://Computia.me:<pw>@127.0.0.1:5555/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-auth --test refresh_flow -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::auth_context::AuthContext;
use attome_auth::refresh::RefreshLifetimes;
use attome_auth::{PepperRing, refresh};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use fred::prelude::{Builder, RedisConfig};
use uuid::Uuid;

/// `None` when no throwaway test database is configured. Unwrap it with
/// `skip_if_no_db!`, which prints the reason and returns from the test â€”
/// see `attome_testkit` for why a missing `DATABASE_URL` skips locally but
/// still fails loudly under `CI` (F-008).
async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

/// Inserts a throwaway active user, returning its id.
async fn create_test_user(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, created_at, is_active)
         VALUES ($1, $2, now(), true)",
    )
    .bind(id)
    .bind(format!("refresh-test-{id}@example.invalid"))
    .execute(db)
    .await
    .expect("insert test user");
    id
}

/// Any >=32-byte string works — `check_secret`'s length floor is enforced by
/// `AppConfig::validate`, which these unit-level tests bypass by constructing
/// the ring directly.
const TEST_PEPPER: &str = "refresh-flow-test-pepper-0123456789abcdef";

fn ring() -> PepperRing {
    PepperRing::new(0, TEST_PEPPER, &[])
}

async fn issue(db: &DbPool, user_id: Uuid, ttl_secs: i64) -> Result<String, AppError> {
    refresh::issue(
        db,
        user_id,
        &AuthContext::password(),
        lifetimes(ttl_secs),
        &ring(),
    )
    .await
    .map(|issued| issued.bearer)
}

async fn redeem(db: &DbPool, presented: &str, ttl_secs: i64) -> Result<(Uuid, String), AppError> {
    refresh::redeem(
        db,
        &attome_cache::Store::Redis(unconnected_redis()),
        presented,
        lifetimes(ttl_secs),
        &ring(),
    )
    .await
}

/// The production default absolute family lifetime (D-504).
const THIRTY_DAYS_SECS: i64 = 30 * 86_400;

/// `idle_secs` per call, with the default 30-day absolute lifetime.
fn lifetimes(idle_secs: i64) -> RefreshLifetimes {
    RefreshLifetimes {
        idle_secs,
        absolute_secs: THIRTY_DAYS_SECS,
    }
}

/// A Redis pool that is built but never connected. `redeem` touches Redis
/// only to invalidate the epoch cache after reuse detection, a bounded
/// best-effort call (`epoch::invalidate_cache`), so an unreachable pool is safe.
fn unconnected_redis() -> attome_cache::RedisPool {
    let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
    Builder::from_config(config).build_pool(1).unwrap()
}

fn public_id_of(token: &str) -> Uuid {
    token
        .split_once('.')
        .expect("token shape")
        .0
        .parse()
        .expect("public_id is a uuid")
}

/// `(family_id, family_started_at, expires_at, used_at)` of one token's row.
type TokenRow = (
    Option<Uuid>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

async fn row_of(db: &DbPool, token: &str) -> TokenRow {
    sqlx::query_as(
        "SELECT family_id, family_started_at, expires_at, used_at
         FROM refresh_token WHERE public_id = $1",
    )
    .bind(public_id_of(token))
    .fetch_one(db)
    .await
    .expect("token row")
}

/// Moves a used token's rotation `secs` into the past, past D-626's grace
/// window when `secs > REUSE_GRACE_SECS`.
async fn age_rotation(db: &DbPool, token: &str, secs: i64) {
    sqlx::query(
        "UPDATE refresh_token SET used_at = used_at - make_interval(secs => $2::float8)
         WHERE public_id = $1",
    )
    .bind(public_id_of(token))
    .bind(secs)
    .execute(db)
    .await
    .expect("age the rotation");
}

const PAST_GRACE_SECS: i64 = refresh::REUSE_GRACE_SECS + 1;

/// Moves a token's anchor to `age_secs` before now, simulating an older family.
async fn age_anchor(db: &DbPool, token: &str, age_secs: i64) {
    sqlx::query(
        "UPDATE refresh_token
         SET family_started_at = NOW() - make_interval(secs => $2::float8)
         WHERE public_id = $1",
    )
    .bind(public_id_of(token))
    .bind(age_secs)
    .execute(db)
    .await
    .expect("age the anchor");
}

async fn user_token_count(db: &DbPool, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM refresh_token WHERE user_ref = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .expect("count tokens")
}

#[tokio::test]
async fn a_live_token_for_an_active_user_redeems() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");

    let (redeemed_user_id, _new_token) = redeem(&db, &token, 3600).await.expect("redeem");
    assert_eq!(redeemed_user_id, user_id);
}

/// The regression this plan closes: previously `validate` only checked
/// `refresh_token` (`revoked_at IS NULL AND expires_at > NOW()`), never
/// the owning user's `is_active` â€” a disabled user's refresh cookie kept
/// minting fresh access tokens for the token's full remaining lifetime.
#[tokio::test]
async fn a_live_token_for_a_disabled_user_is_rejected() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");

    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("disable the test user");

    let result = redeem(&db, &token, 3600).await;
    assert!(
        matches!(result, Err(AppError::Unauthorized)),
        "a disabled user's live refresh token must be rejected, got {result:?}"
    );
}

/// A row inserted without `is_active` takes the column's TRUE default
/// (migration 0460, which also backfilled the legacy NULL rows this test used
/// to simulate), so the JOIN on the owning user admits it.
#[tokio::test]
async fn a_live_token_for_a_user_inserted_without_is_active_redeems() {
    let db = skip_if_no_db!(pool().await);
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, created_at)
         VALUES ($1, $2, now())",
    )
    .bind(user_id)
    .bind(format!("refresh-defaulted-{user_id}@example.invalid"))
    .execute(&db)
    .await
    .expect("insert a user without an explicit is_active");
    let token = issue(&db, user_id, 3600).await.expect("issue");

    let result = redeem(&db, &token, 3600).await;
    assert_eq!(
        result.expect("a defaulted active row must redeem").0,
        user_id
    );
}

/// Redeeming a token returns a different bearer string every time (a fresh
/// public_id/secret pair) â€” the core rotation guarantee.
#[tokio::test]
async fn redeem_returns_a_different_token_than_the_one_presented() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");

    let (_, new_token) = redeem(&db, &token, 3600).await.expect("redeem");
    assert_ne!(token, new_token);
}

/// The new token from a redemption is itself live and redeemable â€” rotation
/// must chain indefinitely, not just once.
#[tokio::test]
async fn a_rotated_token_can_itself_be_redeemed_again() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");

    let (_, second_token) = redeem(&db, &token, 3600).await.expect("first redeem");
    let (third_user_id, _third_token) = redeem(&db, &second_token, 3600)
        .await
        .expect("second redeem");
    assert_eq!(third_user_id, user_id);
}

/// The core reuse-detection guarantee: presenting an already-redeemed token
/// a second time is rejected AND kills the whole family â€” including the
/// legitimate replacement token issued by the first redemption. This is the
/// bug ENTERPRISE-AUDIT-2026-07-24.md #8 flags â€” expected to fail against the
/// pre-D-129 `validate` (which had no concept of "already used" at all).
#[tokio::test]
async fn reusing_an_already_redeemed_token_is_rejected_and_revokes_the_family() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");

    let (_, new_token) = redeem(&db, &token, 3600).await.expect("first redeem");
    age_rotation(&db, &token, PAST_GRACE_SECS).await;

    // Replay the original (now-used) token â€” must be rejected.
    let reuse_result = redeem(&db, &token, 3600).await;
    assert!(
        matches!(reuse_result, Err(AppError::Unauthorized)),
        "reusing an already-redeemed token must be rejected, got {reuse_result:?}"
    );

    // The family is now dead â€” even the legitimate rotated replacement must
    // no longer redeem.
    let replacement_result = redeem(&db, &new_token, 3600).await;
    assert!(
        matches!(replacement_result, Err(AppError::Unauthorized)),
        "the entire family must be revoked once reuse is detected, got {replacement_result:?}"
    );
}

/// A legitimate concurrent double-redeem of the SAME still-unused token (a
/// flaky retry, or two tabs racing) must NOT be treated as theft: the loser
/// gets a plain 401 via the one-row CAS, but the winner's own rotated token
/// stays alive â€” no family kill for this case.
#[tokio::test]
async fn concurrent_redeem_of_the_same_token_loses_cleanly_without_killing_the_family() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");
    let (family_id, anchor, _, _) = row_of(&db, &token).await;
    let epoch_before = auth_epoch_of(&db, user_id).await;

    let (r1, r2) = tokio::join!(redeem(&db, &token, 3600), redeem(&db, &token, 3600),);
    let results = [r1, r2];
    let winners = results.iter().filter(|r| r.is_ok()).count();
    let losers = results.iter().filter(|r| r.is_err()).count();
    assert_eq!(
        winners, 1,
        "exactly one concurrent redeemer must win: {results:?}"
    );
    assert_eq!(
        losers, 1,
        "exactly one concurrent redeemer must lose: {results:?}"
    );

    let winning_token = results
        .into_iter()
        .find_map(|r| r.ok())
        .expect("one redeem must have won")
        .1;

    // D-504: the race cannot extend the family. The loser's transaction rolled
    // back, so exactly one replacement exists, it carries the original family
    // and anchor, nothing was revoked, and the epoch did not move.
    assert_eq!(
        user_token_count(&db, user_id).await,
        2,
        "the original plus exactly one replacement"
    );
    let (winner_family_id, winner_anchor, _, _) = row_of(&db, &winning_token).await;
    assert_eq!(
        winner_family_id, family_id,
        "the replacement stays in the family"
    );
    assert_eq!(
        winner_anchor, anchor,
        "the replacement keeps the original family_started_at"
    );
    let revoked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_token WHERE user_ref = $1 AND revoked_at IS NOT NULL",
    )
    .bind(user_id)
    .fetch_one(&db)
    .await
    .expect("count revoked tokens");
    assert_eq!(revoked, 0, "losing the race must not revoke anything");
    assert_eq!(
        auth_epoch_of(&db, user_id).await,
        epoch_before,
        "losing the race is not reuse and must not bump auth_epoch"
    );

    // The winner's own replacement must still be redeemable â€” the loser's
    // race was not reuse, so the family must not have been killed.
    let follow_up = redeem(&db, &winning_token, 3600).await;
    assert!(
        follow_up.is_ok(),
        "the winning token's replacement must still be live, got {follow_up:?}"
    );
}

/// `revoke_all_for_user` (password-reset-confirm, admin disable) must still
/// kill every live token regardless of which family it belongs to.
#[tokio::test]
async fn revoke_all_for_user_kills_every_family() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token_a = issue(&db, user_id, 3600).await.expect("issue a");
    let token_b = issue(&db, user_id, 3600).await.expect("issue b");

    refresh::revoke_all_for_user(&db, user_id)
        .await
        .expect("revoke all");

    assert!(matches!(
        redeem(&db, &token_a, 3600).await,
        Err(AppError::Unauthorized)
    ));
    assert!(matches!(
        redeem(&db, &token_b, 3600).await,
        Err(AppError::Unauthorized)
    ));
}

async fn auth_epoch_of(db: &DbPool, user_id: Uuid) -> i32 {
    sqlx::query_scalar("SELECT auth_epoch FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .expect("read auth_epoch")
}

/// Every refresh row the user holds, as
/// `(id, used_at, revoked_at, expires_at, family_started_at, replaced_by_ref)`.
type RefreshRowSnapshot = (
    Uuid,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<Uuid>,
);

async fn refresh_rows_of(db: &DbPool, user_id: Uuid) -> Vec<RefreshRowSnapshot> {
    sqlx::query_as(
        "SELECT id, used_at, revoked_at, expires_at, family_started_at, replaced_by_ref
         FROM refresh_token WHERE user_ref = $1 ORDER BY id",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .expect("snapshot refresh rows")
}

/// D-504 rule 5: presenting a revoked token is a 401 that writes nothing. No
/// row changes, no replacement is inserted, and `auth_epoch` stays put.
///
/// An already-used token is deliberately different. Presenting it again is
/// reuse detection, which revokes the lineage and bumps `auth_epoch`
/// (`reusing_an_already_redeemed_token_is_rejected_and_revokes_the_family`,
/// `reuse_detection_bumps_the_accounts_auth_epoch`). That write is the
/// security response, not a leak.
#[tokio::test]
async fn a_revoked_token_is_rejected_without_writing_anything() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");
    refresh::revoke(&db, &token, &ring()).await.expect("revoke");

    let rows_before = refresh_rows_of(&db, user_id).await;
    let epoch_before = auth_epoch_of(&db, user_id).await;

    let result = redeem(&db, &token, 3600).await;
    assert!(
        matches!(result, Err(AppError::Unauthorized)),
        "a revoked token must be rejected, got {result:?}"
    );

    assert_eq!(
        refresh_rows_of(&db, user_id).await,
        rows_before,
        "a rejected revoked token must not change or add any refresh row"
    );
    assert_eq!(
        auth_epoch_of(&db, user_id).await,
        epoch_before,
        "a rejected revoked token must not bump auth_epoch"
    );
}

// ── Peppered-HMAC secret hashing ──────────────────────────────────────────────

/// A wrong secret fails closed — the constant-time `Mac::verify_slice`
/// compare, not a lucky prefix match.
#[tokio::test]
async fn a_wrong_secret_is_rejected_on_the_hmac_path() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;

    let token = refresh::issue(
        &db,
        user_id,
        &AuthContext::password(),
        lifetimes(3600),
        &ring(),
    )
    .await
    .expect("issue hmac")
    .bearer;
    let public_id = token.split_once('.').expect("token shape").0;
    let forged = format!("{public_id}.{}", "z".repeat(48));

    assert!(matches!(
        refresh::redeem(
            &db,
            &attome_cache::Store::Redis(unconnected_redis()),
            &forged,
            lifetimes(3600),
            &ring(),
        )
        .await,
        Err(AppError::Unauthorized)
    ));
    // The real token is untouched by the failed attempt.
    refresh::redeem(
        &db,
        &attome_cache::Store::Redis(unconnected_redis()),
        &token,
        lifetimes(3600),
        &ring(),
    )
    .await
    .expect("the genuine token still redeems");
}

/// Reuse detection (D-129) is independent of the hash format — a replayed
/// HMAC-format token must still revoke its whole rotation family.
#[tokio::test]
async fn reuse_detection_still_fires_on_an_hmac_row() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;

    let token = refresh::issue(
        &db,
        user_id,
        &AuthContext::password(),
        lifetimes(3600),
        &ring(),
    )
    .await
    .expect("issue hmac")
    .bearer;
    let (_, replacement) = refresh::redeem(
        &db,
        &attome_cache::Store::Redis(unconnected_redis()),
        &token,
        lifetimes(3600),
        &ring(),
    )
    .await
    .expect("first redemption");
    age_rotation(&db, &token, PAST_GRACE_SECS).await;

    assert!(
        matches!(
            refresh::redeem(
                &db,
                &attome_cache::Store::Redis(unconnected_redis()),
                &token,
                lifetimes(3600),
                &ring(),
            )
            .await,
            Err(AppError::Unauthorized)
        ),
        "replaying a used hmac token must be rejected"
    );
    assert!(
        matches!(
            refresh::redeem(
                &db,
                &attome_cache::Store::Redis(unconnected_redis()),
                &replacement,
                lifetimes(3600),
                &ring(),
            )
            .await,
            Err(AppError::Unauthorized)
        ),
        "the replacement must be revoked along with the rest of the family"
    );
}

/// A row whose pepper id is not in the ring fails closed (no verification
/// bypass, no 500) — the same posture `verify_api_key_secret` gives an
/// api-key row referencing a prematurely retired pepper.
#[tokio::test]
async fn a_row_hashed_under_an_unknown_pepper_fails_closed() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;

    let token = refresh::issue(
        &db,
        user_id,
        &AuthContext::password(),
        lifetimes(3600),
        &ring(),
    )
    .await
    .expect("issue hmac")
    .bearer;

    let other_ring = PepperRing::new(7, "a-completely-different-pepper-0123456789", &[]);
    assert!(matches!(
        refresh::redeem(
            &db,
            &attome_cache::Store::Redis(unconnected_redis()),
            &token,
            lifetimes(3600),
            &other_ring,
        )
        .await,
        Err(AppError::Unauthorized)
    ));
}

// ── Absolute family lifetime (D-504) ─────────────────────────────────────────

/// Rules 1 and 4: `issue` anchors the family on the database clock, and caps
/// `expires_at` at the absolute lifetime when that is shorter than the idle one.
#[tokio::test]
async fn issue_anchors_the_family_and_caps_expires_at_at_the_absolute_lifetime() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let short = RefreshLifetimes {
        idle_secs: 7 * 86_400,
        absolute_secs: 3600,
    };

    let token = refresh::issue(&db, user_id, &AuthContext::password(), short, &ring())
        .await
        .expect("issue")
        .bearer;

    let (family_id, anchor, expires_at, _) = row_of(&db, &token).await;
    assert!(family_id.is_some(), "issue must start a family");
    let anchor = anchor.expect("issue must write an anchor");
    assert_eq!(
        expires_at,
        anchor + ChronoDuration::seconds(3600),
        "a new token must not outlive its family's absolute lifetime"
    );
}

/// Rule 3, just inside the boundary: a family one minute short of its absolute
/// lifetime still rotates, the replacement keeps the anchor, and it expires at
/// the boundary rather than an idle window later.
#[tokio::test]
async fn a_family_one_minute_inside_its_absolute_lifetime_rotates_up_to_the_boundary() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");
    age_anchor(&db, &token, THIRTY_DAYS_SECS - 60).await;
    let anchor = row_of(&db, &token).await.1.expect("anchor");

    let (_, replacement) = redeem(&db, &token, 3600)
        .await
        .expect("a family inside its absolute lifetime must still rotate");

    let (_, new_anchor, new_expires_at, _) = row_of(&db, &replacement).await;
    assert_eq!(
        new_anchor,
        Some(anchor),
        "rotation must copy the anchor verbatim"
    );
    assert_eq!(
        new_expires_at,
        anchor + ChronoDuration::seconds(THIRTY_DAYS_SECS),
        "the replacement must expire at the family boundary, not an idle window later"
    );
}

/// Rules 3 and 5, at the boundary: a family exactly one absolute lifetime old
/// is expired, and the rejection writes nothing.
#[tokio::test]
async fn a_family_at_its_absolute_lifetime_is_rejected_and_nothing_is_written() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");
    age_anchor(&db, &token, THIRTY_DAYS_SECS).await;

    let result = redeem(&db, &token, 3600).await;
    assert!(
        matches!(result, Err(AppError::Unauthorized)),
        "a family at its absolute lifetime must be rejected, got {result:?}"
    );
    assert!(
        row_of(&db, &token).await.3.is_none(),
        "a rejected redemption must not consume the token"
    );
    assert_eq!(
        user_token_count(&db, user_id).await,
        1,
        "a rejected redemption must not insert a replacement"
    );
}

/// Rule 1: however often a family rotates, every replacement carries the same
/// anchor and never expires after the boundary, so the family still ends.
#[tokio::test]
async fn continuous_rotation_never_moves_the_anchor_and_the_family_still_expires() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let mut token = issue(&db, user_id, 3600).await.expect("issue");
    let anchor = row_of(&db, &token).await.1.expect("anchor");

    for _ in 0..3 {
        let (_, next) = redeem(&db, &token, 3600).await.expect("rotate");
        let (_, next_anchor, next_expires_at, _) = row_of(&db, &next).await;
        assert_eq!(
            next_anchor,
            Some(anchor),
            "rotation must not move the anchor"
        );
        assert!(
            next_expires_at <= anchor + ChronoDuration::seconds(THIRTY_DAYS_SECS),
            "no replacement may expire after the family boundary"
        );
        token = next;
    }

    age_anchor(&db, &token, THIRTY_DAYS_SECS).await;
    assert!(
        matches!(redeem(&db, &token, 3600).await, Err(AppError::Unauthorized)),
        "a continuously rotated family must still end at its absolute lifetime"
    );
}

/// Rule 4: the idle expiry still applies on its own to a young family.
#[tokio::test]
async fn idle_expiry_still_rejects_a_young_family() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");
    sqlx::query(
        "UPDATE refresh_token SET expires_at = NOW() - interval '1 second'
         WHERE public_id = $1",
    )
    .bind(public_id_of(&token))
    .execute(&db)
    .await
    .expect("expire the token's idle window");

    assert!(matches!(
        redeem(&db, &token, 3600).await,
        Err(AppError::Unauthorized)
    ));
}

/// Rule 9: reuse detection also bumps `auth_epoch`, so access tokens already
/// minted for the account stop working too.
#[tokio::test]
async fn reuse_detection_bumps_the_accounts_auth_epoch() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let epoch_of = |db: DbPool| async move {
        sqlx::query_scalar::<_, i32>("SELECT auth_epoch FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_one(&db)
            .await
            .expect("read auth_epoch")
    };
    let before = epoch_of(db.clone()).await;

    let token = issue(&db, user_id, 3600).await.expect("issue");
    redeem(&db, &token, 3600).await.expect("first redemption");
    age_rotation(&db, &token, PAST_GRACE_SECS).await;
    assert!(matches!(
        redeem(&db, &token, 3600).await,
        Err(AppError::Unauthorized)
    ));

    assert_eq!(
        epoch_of(db.clone()).await,
        before + 1,
        "detected reuse must bump auth_epoch exactly once"
    );
}

/// `(auth_time, amr, elevated_until)` of one token's row.
type Assurance = (
    Option<DateTime<Utc>>,
    Option<Vec<String>>,
    Option<DateTime<Utc>>,
);

async fn assurance_of(db: &DbPool, token: &str) -> Assurance {
    sqlx::query_as("SELECT auth_time, amr, elevated_until FROM refresh_token WHERE public_id = $1")
        .bind(public_id_of(token))
        .fetch_one(db)
        .await
        .expect("assurance columns")
}

/// Rule 10 (security contract I13): since item 2.1a `issue` records the
/// sign-in's `auth_time` and `amr` but never `elevated_until`, and rotation
/// copies whatever the three hold unchanged, never computing them.
#[tokio::test]
async fn rotation_copies_auth_time_amr_and_elevated_until_unchanged() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");
    let (auth_time, amr, elevated_until) = assurance_of(&db, &token).await;
    assert!(auth_time.is_some(), "issue must record auth_time");
    assert_eq!(amr, Some(vec!["pwd".to_owned()]), "issue must record amr");
    assert_eq!(elevated_until, None, "a new sign-in is never elevated");

    let written: Assurance = sqlx::query_as(
        "UPDATE refresh_token
         SET auth_time = NOW() - interval '1 hour',
             amr = ARRAY['pwd', 'otp'],
             elevated_until = NOW() + interval '5 minutes'
         WHERE public_id = $1
         RETURNING auth_time, amr, elevated_until",
    )
    .bind(public_id_of(&token))
    .fetch_one(&db)
    .await
    .expect("write the 2.1 columns as a credential verification would");

    let (_, replacement) = redeem(&db, &token, 3600).await.expect("rotate");

    assert_eq!(
        assurance_of(&db, &replacement).await,
        written,
        "rotation must copy auth_time, amr and elevated_until unchanged"
    );
}

// ── D-626 (BAU-10): a lost response is not theft ─────────────────────────────

/// A retry inside the grace window, while the replacement is unused, is a
/// plain 401: no row changes, no epoch bump, and the replacement still works.
#[tokio::test]
async fn a_retry_inside_the_grace_window_revokes_nothing() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");
    let (_, replacement) = redeem(&db, &token, 3600).await.expect("first redeem");

    let rows_before = refresh_rows_of(&db, user_id).await;
    let epoch_before = auth_epoch_of(&db, user_id).await;
    let retry = redeem(&db, &token, 3600).await;
    assert!(
        matches!(retry, Err(AppError::Unauthorized)),
        "a retry of a rotated token is refused, got {retry:?}"
    );
    assert_eq!(
        refresh_rows_of(&db, user_id).await,
        rows_before,
        "a lost-response retry writes nothing"
    );
    assert_eq!(auth_epoch_of(&db, user_id).await, epoch_before);
    redeem(&db, &replacement, 3600)
        .await
        .expect("the replacement is still live");
}

/// Once the replacement has been redeemed, a replay of the original is reuse
/// even inside the window: the family dies and the epoch moves.
#[tokio::test]
async fn a_retry_after_the_replacement_rotated_is_reuse() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");
    let (_, replacement) = redeem(&db, &token, 3600).await.expect("first redeem");
    let (_, third) = redeem(&db, &replacement, 3600)
        .await
        .expect("replacement redeems");
    let epoch_before = auth_epoch_of(&db, user_id).await;

    assert!(matches!(
        redeem(&db, &token, 3600).await,
        Err(AppError::Unauthorized)
    ));
    assert_eq!(auth_epoch_of(&db, user_id).await, epoch_before + 1);
    assert!(
        matches!(redeem(&db, &third, 3600).await, Err(AppError::Unauthorized)),
        "the whole family is revoked"
    );
}

/// After the window, a replay is reuse even while the replacement is unused.
#[tokio::test]
async fn a_retry_after_the_grace_window_is_reuse() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = issue(&db, user_id, 3600).await.expect("issue");
    let (_, replacement) = redeem(&db, &token, 3600).await.expect("first redeem");
    age_rotation(&db, &token, PAST_GRACE_SECS).await;
    let epoch_before = auth_epoch_of(&db, user_id).await;

    assert!(matches!(
        redeem(&db, &token, 3600).await,
        Err(AppError::Unauthorized)
    ));
    assert_eq!(auth_epoch_of(&db, user_id).await, epoch_before + 1);
    assert!(matches!(
        redeem(&db, &replacement, 3600).await,
        Err(AppError::Unauthorized)
    ));
}

// ── BAU-11: logout proves possession ─────────────────────────────────────────

/// Knowing a `public_id` is not enough to end a session: a wrong secret
/// revokes nothing, and the right one still does.
#[tokio::test]
async fn logout_with_a_wrong_secret_revokes_nothing() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let token = refresh::issue(
        &db,
        user_id,
        &AuthContext::password(),
        lifetimes(3600),
        &ring(),
    )
    .await
    .expect("issue")
    .bearer;
    let forged = format!("{}.{}", public_id_of(&token), "x".repeat(48));

    let owner = refresh::revoke_returning_user(&db, &forged, &ring())
        .await
        .expect("a wrong secret is a silent no-op");
    assert_eq!(owner, None);
    let (_, token) = redeem(&db, &token, 3600)
        .await
        .expect("the session is still live");

    let owner = refresh::revoke_returning_user(&db, &token, &ring())
        .await
        .expect("revoke");
    assert_eq!(owner, Some(user_id));
}

// ── BAU-13c / BAU-12e: the session is issued in one transaction ──────────────

fn jwt_ring() -> attome_config::KeyRing {
    attome_config::KeyRing::single("refresh-flow-jwt-secret".to_string())
}

fn access_spec(jwt_ring: &attome_config::KeyRing) -> refresh::AccessTokenSpec<'_> {
    refresh::AccessTokenSpec {
        jwt_ring,
        issuer: "attome-test",
        audience: "attome-test",
        expiry_secs: 900,
    }
}

/// A mint that fails leaves no refresh row and no `last_login` behind: the
/// family and the access token commit together or not at all.
#[tokio::test]
async fn a_failed_mint_leaves_no_refresh_row() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    let mut broken = jwt_ring();
    broken.active_key_id = "no-such-key".to_string();

    let result = refresh::issue_session_with(
        &db,
        user_id,
        &AuthContext::password(),
        lifetimes(3600),
        &ring(),
        &access_spec(&broken),
        &attome_db::NoHook,
    )
    .await;
    assert!(result.is_err(), "a mint without an active key fails");
    assert_eq!(user_token_count(&db, user_id).await, 0);
    assert_eq!(last_login_of(&db, user_id).await, None);

    let good = jwt_ring();
    let issued = refresh::issue_session_with(
        &db,
        user_id,
        &AuthContext::password(),
        lifetimes(3600),
        &ring(),
        &access_spec(&good),
        &attome_db::NoHook,
    )
    .await
    .expect("issue a session");
    let (claims, sid) = attome_auth::validate_session_token(
        &issued.access_token,
        &good,
        "attome-test",
        "attome-test",
    )
    .expect("the minted token validates");
    assert_eq!(claims.sub, user_id);
    assert_eq!(sid, attome_auth::SessionId(issued.family_id));
    assert_eq!(claims.epoch, auth_epoch_of(&db, user_id).await);
    assert_eq!(user_token_count(&db, user_id).await, 1);
    assert!(
        last_login_of(&db, user_id).await.is_some(),
        "issuing a session stamps last_login"
    );
}

async fn last_login_of(db: &DbPool, user_id: Uuid) -> Option<DateTime<Utc>> {
    sqlx::query_scalar("SELECT last_login FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .expect("read last_login")
}

// ── BAU-13a (F15): pruning dead refresh families ─────────────────────────────

const PRUNE_RETENTION_SECS: i64 = 30 * 86_400;

async fn prune_until_done(db: &DbPool) {
    while refresh::prune_dead_families(db, PRUNE_RETENTION_SECS, 500)
        .await
        .expect("prune")
        > 0
    {}
}

/// Moves every row of a token's family `secs` into the past: expiry,
/// revocation and anchor alike.
async fn age_family(db: &DbPool, token: &str, secs: i64) {
    sqlx::query(
        "UPDATE refresh_token
         SET expires_at = expires_at - make_interval(secs => $2::float8),
             revoked_at = revoked_at - make_interval(secs => $2::float8),
             family_started_at = family_started_at - make_interval(secs => $2::float8)
         WHERE family_id = (SELECT family_id FROM refresh_token WHERE public_id = $1)",
    )
    .bind(public_id_of(token))
    .bind(secs)
    .execute(db)
    .await
    .expect("age the family");
}

/// A live family keeps every row, its used anchor included; a family dead for
/// longer than the retention goes whole; one dead inside the retention stays.
#[tokio::test]
async fn pruning_keeps_every_live_familys_anchor() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;

    let live = issue(&db, user_id, 3600).await.expect("issue live");
    let (_, live_replacement) = redeem(&db, &live, 3600).await.expect("rotate live");
    // The used anchor row alone looks long dead; its replacement is live.
    sqlx::query(
        "UPDATE refresh_token SET expires_at = NOW() - interval '40 days'
         WHERE public_id = $1",
    )
    .bind(public_id_of(&live))
    .execute(&db)
    .await
    .expect("age the used row");

    let long_dead = issue(&db, user_id, 3600).await.expect("issue dead");
    refresh::revoke(&db, &long_dead, &ring())
        .await
        .expect("revoke");
    age_family(&db, &long_dead, 40 * 86_400).await;

    let recently_dead = issue(&db, user_id, 3600).await.expect("issue recent");
    refresh::revoke(&db, &recently_dead, &ring())
        .await
        .expect("revoke");

    prune_until_done(&db).await;

    let exists = |token: String| {
        let db = db.clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM refresh_token WHERE public_id = $1)",
            )
            .bind(public_id_of(&token))
            .fetch_one(&db)
            .await
            .expect("probe")
        }
    };
    assert!(
        exists(live.clone()).await,
        "a live family keeps its used anchor row"
    );
    assert!(exists(live_replacement.clone()).await);
    assert!(
        !exists(long_dead).await,
        "a family dead past the retention is pruned"
    );
    assert!(
        exists(recently_dead).await,
        "the retention window is honoured"
    );
    redeem(&db, &live_replacement, 3600)
        .await
        .expect("the live family still rotates");
}

/// Pruning racing a redemption of a live family never loses the live row: the
/// family always has a live member, so it is never dead.
#[tokio::test]
async fn prune_racing_a_redeem_never_loses_the_live_row() {
    let db = skip_if_no_db!(pool().await);
    let user_id = create_test_user(&db).await;
    for _ in 0..5 {
        let token = issue(&db, user_id, 3600).await.expect("issue");
        let (redeemed, _) = tokio::join!(redeem(&db, &token, 3600), prune_until_done(&db));
        let (_, replacement) = redeemed.expect("the redemption wins");
        redeem(&db, &replacement, 3600)
            .await
            .expect("the replacement survived the prune");
    }
}
