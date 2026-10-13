//! Local step-up (D-510 rules 3, 4, 6, 7 and 8; attome-auth hardening 2.1b):
//! the guard, single-use challenges, factor rules, and the elevation they
//! write.
//!
//! Requires a live Postgres migrated through 0462 and a reachable Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`), same convention as `login_mfa.rs`.
//! Run manually:
//!
//! ```powershell
//! cargo test -p attome-auth --test step_up -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::auth_context::AuthContext;
use attome_auth::mfa;
use attome_auth::refresh::{self, IssuedRefresh, RefreshLifetimes};
use attome_auth::step_up::{
    self, Caller, Operation, StartedChallenge, StepUpStores, Submission, TOTP_ENROLLMENT_REQUIRED,
};
use attome_auth::{PepperRing, SessionId, hash_password_async};
use attome_cache::RedisPool;
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use fred::prelude::*;
use totp_rs::{Algorithm, Secret, Totp};
use uuid::Uuid;

const THIRTY_DAYS_SECS: i64 = 30 * 86_400;
const PASSWORD: &str = "step-up-test-password-0123";

fn lifetimes() -> RefreshLifetimes {
    RefreshLifetimes {
        idle_secs: 3600,
        absolute_secs: THIRTY_DAYS_SECS,
    }
}

fn pepper() -> PepperRing {
    PepperRing::new(0, "step-up-test-pepper-0123456789abcdef", &[])
}

fn mfa_ring() -> KeyRing {
    KeyRing::single("ab".repeat(32))
}

async fn redis_pool() -> RedisPool {
    let host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into());
    let config = RedisConfig::from_url(&format!("redis://{host}:{port}")).expect("redis config");
    let pool = RedisPool::new(config, None, None, None, 4).expect("build redis pool");
    pool.connect();
    pool.wait_for_connect()
        .await
        .expect("connect to test Redis");
    pool
}

fn unreachable_redis() -> RedisPool {
    let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
    Builder::from_config(config).build_pool(1).unwrap()
}

struct Env {
    db: DbPool,
    redis: RedisPool,
}

async fn env() -> Option<Env> {
    let db = attome_testkit::connect(&attome_testkit::migrated_db_url()?, 10).await;
    Some(Env {
        db,
        redis: redis_pool().await,
    })
}

impl Env {
    fn stores(&self) -> StepUpStores<'_> {
        StepUpStores {
            db: &self.db,
            redis: &self.redis,
            absolute_lifetime_secs: THIRTY_DAYS_SECS,
        }
    }

    async fn guard(
        &self,
        caller: Caller,
        user_id: Uuid,
        operation: Operation,
    ) -> Result<(), AppError> {
        step_up::require_recent_auth(&self.db, caller, user_id, operation, THIRTY_DAYS_SECS).await
    }

    async fn start(
        &self,
        caller: Caller,
        user_id: Uuid,
        operation: Operation,
    ) -> Result<StartedChallenge, AppError> {
        step_up::start_challenge(self.stores(), caller, user_id, operation).await
    }

    async fn verify(
        &self,
        caller: Caller,
        user_id: Uuid,
        operation: Operation,
        challenge_id: &str,
        factor: &str,
        credential: &str,
    ) -> Result<DateTime<Utc>, AppError> {
        step_up::verify_challenge(
            self.stores(),
            &mfa_ring(),
            &pepper(),
            caller,
            user_id,
            operation,
            Submission {
                challenge_id,
                factor,
                credential,
            },
        )
        .await
    }

    async fn db_now(&self) -> DateTime<Utc> {
        sqlx::query_scalar("SELECT NOW()")
            .fetch_one(&self.db)
            .await
            .expect("database clock")
    }
}

async fn create_user(db: &DbPool, password: Option<&str>, google: bool) -> Uuid {
    let id = Uuid::now_v7();
    let hash = match password {
        Some(password) => Some(
            hash_password_async(attome_auth::NewPassword::platform_generated(password))
                .await
                .expect("hash"),
        ),
        None => None,
    };
    sqlx::query(
        "INSERT INTO user_account
             (id, email, password_hash, google_sub, created_at, is_active, email_verified)
         VALUES ($1, $2, $3, $4, now(), true, true)",
    )
    .bind(id)
    .bind(format!("step-up-{id}@example.invalid"))
    .bind(hash)
    .bind(google.then(|| format!("google-sub-{id}")))
    .execute(db)
    .await
    .expect("insert test user");
    id
}

async fn link_federated(db: &DbPool, user_id: Uuid) {
    sqlx::query(
        "INSERT INTO user_identity (user_ref, provider_key, provider_sub, email)
         VALUES ($1, 'oidc:step-up-test', $2, $3)",
    )
    .bind(user_id)
    .bind(format!("sub-{user_id}"))
    .bind(format!("step-up-{user_id}@example.invalid"))
    .execute(db)
    .await
    .expect("link a federated identity");
}

async fn enroll_totp(db: &DbPool, user_id: Uuid) -> (Totp, Vec<String>) {
    let enrolled = mfa::enroll(db, &mfa_ring(), user_id).await.expect("enroll");
    let totp = totp_rs::Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(Secret::try_from_base32(&enrolled.secret_base32).unwrap())
        .with_account_name("test".to_string())
        .build()
        .unwrap();
    let code = totp.generate_current().to_string();
    let recovery_codes = mfa::confirm_enrollment(db, &mfa_ring(), &pepper(), user_id, &code)
        .await
        .expect("confirm enrollment");
    (totp, recovery_codes)
}

/// A code for the next TOTP step, so it never replays the step that confirmed
/// enrollment.
fn next_code(totp: &Totp) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    totp.generate(now + 30).to_string()
}

async fn sign_in(db: &DbPool, user_id: Uuid, context: &AuthContext) -> IssuedRefresh {
    refresh::issue(db, user_id, context, lifetimes(), &pepper())
        .await
        .expect("issue refresh token")
}

fn session(issued: &IssuedRefresh) -> Caller {
    Caller::Session(SessionId(issued.family_id))
}

/// `(elevated_until, auth_time, amr, live)` for every row of a family, oldest
/// first.
type ElevationRow = (
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<Vec<String>>,
    bool,
);

async fn family_rows(db: &DbPool, family_id: Uuid) -> Vec<ElevationRow> {
    sqlx::query_as(
        "SELECT elevated_until, auth_time, amr, (used_at IS NULL AND revoked_at IS NULL)
         FROM refresh_token WHERE family_id = $1 ORDER BY created_at",
    )
    .bind(family_id)
    .fetch_all(db)
    .await
    .expect("family rows")
}

async fn live_row(db: &DbPool, family_id: Uuid) -> ElevationRow {
    family_rows(db, family_id)
        .await
        .into_iter()
        .rev()
        .find(|row| row.3)
        .expect("a live row")
}

async fn assert_unelevated(db: &DbPool, family_id: Uuid) {
    for row in family_rows(db, family_id).await {
        assert_eq!(row.0, None, "no row of this family may be elevated");
    }
}

fn assert_reauth<T: std::fmt::Debug>(
    result: Result<T, AppError>,
    operation: &str,
    factors: &[&str],
) {
    match result {
        Err(AppError::ReauthRequired {
            operation: got_operation,
            acceptable_factors,
        }) => {
            assert_eq!(got_operation, operation);
            assert_eq!(acceptable_factors, factors);
        }
        other => panic!("expected reauth_required for {operation}, got {other:?}"),
    }
}

// ── Guard: who may ask ───────────────────────────────────────────────────────

/// Rule 7 and the `sid` rule: the guard only ever reads the caller's own live
/// family.
#[tokio::test]
async fn the_guard_refuses_callers_without_their_own_live_family() {
    let env = skip_if_no_db!(env().await);
    let alice = create_user(&env.db, Some(PASSWORD), false).await;
    let bob = create_user(&env.db, Some(PASSWORD), false).await;
    let alices = sign_in(&env.db, alice, &AuthContext::password()).await;
    let bobs = sign_in(&env.db, bob, &AuthContext::password()).await;

    for operation in Operation::ALL {
        assert!(matches!(
            env.guard(Caller::NonSession, alice, operation).await,
            Err(AppError::Forbidden)
        ));
        assert!(
            matches!(
                env.guard(session(&bobs), alice, operation).await,
                Err(AppError::Unauthorized)
            ),
            "another user's family is never alice's"
        );
    }

    refresh::revoke(&env.db, &alices.bearer, &pepper())
        .await
        .expect("revoke");
    for operation in Operation::ALL {
        assert!(
            matches!(
                env.guard(session(&alices), alice, operation).await,
                Err(AppError::Unauthorized)
            ),
            "a revoked family is not live"
        );
    }
    assert!(matches!(
        env.start(Caller::NonSession, bob, Operation::IdentityLink)
            .await,
        Err(AppError::Forbidden)
    ));
}

/// A new sign-in is never elevated, so it never satisfies an elevation
/// operation by itself.
#[tokio::test]
async fn a_new_sign_in_never_satisfies_an_elevation_operation() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let issued = sign_in(&env.db, user, &AuthContext::password()).await;
    assert_reauth(
        env.guard(session(&issued), user, Operation::IdentityLink)
            .await,
        "identity_link",
        &["password"],
    );
    assert_reauth(
        env.guard(session(&issued), user, Operation::ApiKeyCreate)
            .await,
        "api_key_create",
        &["password"],
    );
}

// ── Elevation ────────────────────────────────────────────────────────────────

/// A password step-up elevates the caller's own family, bounded to 15 minutes,
/// and nothing else.
#[tokio::test]
async fn a_password_step_up_elevates_only_the_callers_family() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let other = create_user(&env.db, Some(PASSWORD), false).await;
    let first = sign_in(&env.db, user, &AuthContext::password()).await;
    let second = sign_in(&env.db, user, &AuthContext::password()).await;
    let others = sign_in(&env.db, other, &AuthContext::password()).await;

    let started = env
        .start(session(&first), user, Operation::IdentityLink)
        .await
        .expect("start");
    assert_eq!(started.operation, Operation::IdentityLink);
    assert_eq!(started.expires_in_secs, 300);
    assert_eq!(started.acceptable_factors, vec![step_up::Factor::Password]);

    let before = env.db_now().await;
    let until = env
        .verify(
            session(&first),
            user,
            Operation::IdentityLink,
            &started.challenge_id.to_string(),
            "password",
            PASSWORD,
        )
        .await
        .expect("a correct password elevates");
    let after = env.db_now().await;

    assert!(
        before + chrono::Duration::minutes(15) <= until
            && until <= after + chrono::Duration::minutes(15),
        "elevated_until {until} must be the verification time + 15 min"
    );
    let (elevated_until, auth_time, amr, _) = live_row(&env.db, first.family_id).await;
    assert_eq!(elevated_until, Some(until));
    let auth_time = auth_time.expect("auth_time");
    assert!(before <= auth_time && auth_time <= after);
    assert_eq!(amr, Some(vec!["pwd".to_owned()]));

    env.guard(session(&first), user, Operation::IdentityLink)
        .await
        .expect("an elevated, fresh session passes identity_link");
    env.guard(session(&first), user, Operation::ApiKeyCreate)
        .await
        .expect("and api_key_create");

    assert_unelevated(&env.db, second.family_id).await;
    assert_unelevated(&env.db, others.family_id).await;
    assert_reauth(
        env.guard(session(&second), user, Operation::IdentityLink)
            .await,
        "identity_link",
        &["password"],
    );
}

/// Each operation's max age applies to `auth_time`, and a lapsed
/// `elevated_until` fails every operation.
#[tokio::test]
async fn freshness_windows_follow_each_operations_max_age() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let issued = sign_in(&env.db, user, &AuthContext::password()).await;
    let started = env
        .start(session(&issued), user, Operation::ApiKeyCreate)
        .await
        .expect("start");
    env.verify(
        session(&issued),
        user,
        Operation::ApiKeyCreate,
        &started.challenge_id.to_string(),
        "password",
        PASSWORD,
    )
    .await
    .expect("elevate");

    let set_auth_age = |minutes: i64| {
        sqlx::query(
            "UPDATE refresh_token SET auth_time = NOW() - make_interval(mins => $2::int)
             WHERE family_id = $1 AND used_at IS NULL",
        )
        .bind(issued.family_id)
        .bind(minutes)
    };

    set_auth_age(4).execute(&env.db).await.unwrap();
    env.guard(session(&issued), user, Operation::IdentityLink)
        .await
        .expect("4 minutes is inside identity_link's 5");

    set_auth_age(6).execute(&env.db).await.unwrap();
    assert_reauth(
        env.guard(session(&issued), user, Operation::IdentityLink)
            .await,
        "identity_link",
        &["password"],
    );
    env.guard(session(&issued), user, Operation::ApiKeyCreate)
        .await
        .expect("6 minutes is inside api_key_create's 15");

    set_auth_age(16).execute(&env.db).await.unwrap();
    for operation in [Operation::IdentityLink, Operation::ApiKeyCreate] {
        assert_reauth(
            env.guard(session(&issued), user, operation).await,
            operation.as_str(),
            &["password"],
        );
    }

    set_auth_age(0).execute(&env.db).await.unwrap();
    sqlx::query(
        "UPDATE refresh_token SET elevated_until = NOW() - interval '1 second'
         WHERE family_id = $1 AND used_at IS NULL",
    )
    .bind(issued.family_id)
    .execute(&env.db)
    .await
    .unwrap();
    for operation in [Operation::IdentityLink, Operation::ApiKeyCreate] {
        assert_reauth(
            env.guard(session(&issued), user, operation).await,
            operation.as_str(),
            &["password"],
        );
    }
}

/// Elevation never outlives the family (D-504): near its absolute end,
/// `elevated_until` is the end itself.
#[tokio::test]
async fn elevation_is_capped_at_the_familys_absolute_end() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let issued = sign_in(&env.db, user, &AuthContext::password()).await;
    let anchor: DateTime<Utc> = sqlx::query_scalar(
        "UPDATE refresh_token
         SET family_started_at = NOW() - make_interval(secs => $2::float8)
         WHERE family_id = $1 RETURNING family_started_at",
    )
    .bind(issued.family_id)
    .bind(THIRTY_DAYS_SECS - 5 * 60)
    .fetch_one(&env.db)
    .await
    .expect("move the anchor to five minutes before the end");

    let started = env
        .start(session(&issued), user, Operation::ApiKeyCreate)
        .await
        .expect("start");
    let until = env
        .verify(
            session(&issued),
            user,
            Operation::ApiKeyCreate,
            &started.challenge_id.to_string(),
            "password",
            PASSWORD,
        )
        .await
        .expect("elevate");
    assert_eq!(
        until,
        anchor + chrono::Duration::seconds(THIRTY_DAYS_SECS),
        "elevation is capped at the family's absolute end, not NOW() + 15 min"
    );
}

// ── Factors (rule 4) ─────────────────────────────────────────────────────────

/// A TOTP-enrolled account steps up with TOTP or a recovery code, never a
/// password; a refused factor neither counts nor consumes the challenge.
#[tokio::test]
async fn a_totp_account_steps_up_with_totp_or_a_recovery_code_never_a_password() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let (totp, recovery_codes) = enroll_totp(&env.db, user).await;
    let issued = sign_in(&env.db, user, &AuthContext::password_and_totp()).await;

    let started = env
        .start(session(&issued), user, Operation::IdentityLink)
        .await
        .expect("start");
    assert_eq!(
        started.acceptable_factors,
        vec![step_up::Factor::Totp, step_up::Factor::RecoveryCode]
    );
    let id = started.challenge_id.to_string();

    assert_reauth(
        env.verify(
            session(&issued),
            user,
            Operation::IdentityLink,
            &id,
            "password",
            PASSWORD,
        )
        .await,
        "identity_link",
        &["totp", "recovery_code"],
    );
    assert_unelevated(&env.db, issued.family_id).await;

    env.verify(
        session(&issued),
        user,
        Operation::IdentityLink,
        &id,
        "totp",
        &next_code(&totp),
    )
    .await
    .expect("the same challenge still takes TOTP");
    let (_, _, amr, _) = live_row(&env.db, issued.family_id).await;
    assert_eq!(
        amr.as_deref()
            .and_then(<[String]>::last)
            .map(String::as_str),
        Some("otp")
    );
    env.guard(session(&issued), user, Operation::IdentityLink)
        .await
        .expect("TOTP satisfies a TOTP-enrolled account");

    let started = env
        .start(session(&issued), user, Operation::ApiKeyCreate)
        .await
        .expect("start");
    env.verify(
        session(&issued),
        user,
        Operation::ApiKeyCreate,
        &started.challenge_id.to_string(),
        "recovery_code",
        &recovery_codes[0],
    )
    .await
    .expect("a recovery code steps up too");
    let (_, _, amr, _) = live_row(&env.db, issued.family_id).await;
    assert_eq!(
        amr,
        Some(vec!["pwd".to_owned(), "otp".to_owned(), "rcode".to_owned()])
    );
}

/// Google-only accounts get a `federated` challenge they answer on the Google
/// step-up route (BAU-8c, D-628); federated-only accounts get a challenge they
/// complete at their IdP (2.1c); `federated` is never a local factor.
#[tokio::test]
async fn an_account_without_a_local_factor_is_refused() {
    let env = skip_if_no_db!(env().await);

    let google_only = create_user(&env.db, None, true).await;
    let issued = sign_in(&env.db, google_only, &AuthContext::federated(None)).await;
    for operation in [Operation::IdentityLink, Operation::ApiKeyCreate] {
        let started = env
            .start(session(&issued), google_only, operation)
            .await
            .expect("a Google-only account gets a challenge");
        assert_eq!(started.acceptable_factors, vec![step_up::Factor::Federated]);
        assert_reauth(
            env.guard(session(&issued), google_only, operation).await,
            operation.as_str(),
            &["federated"],
        );
    }

    let nothing = create_user(&env.db, None, false).await;
    let issued = sign_in(&env.db, nothing, &AuthContext::federated(None)).await;
    assert_reauth(
        env.start(session(&issued), nothing, Operation::IdentityLink)
            .await,
        "identity_link",
        &[TOTP_ENROLLMENT_REQUIRED],
    );

    let federated_only = create_user(&env.db, None, false).await;
    link_federated(&env.db, federated_only).await;
    let issued = sign_in(&env.db, federated_only, &AuthContext::federated(None)).await;
    let started = env
        .start(session(&issued), federated_only, Operation::IdentityLink)
        .await
        .expect("a federated-only account gets a challenge for its IdP");
    assert_eq!(started.acceptable_factors, vec![step_up::Factor::Federated]);
    assert_reauth(
        env.verify(
            session(&issued),
            federated_only,
            Operation::IdentityLink,
            &started.challenge_id.to_string(),
            "password",
            PASSWORD,
        )
        .await,
        "identity_link",
        &["federated"],
    );
    assert_unelevated(&env.db, issued.family_id).await;

    let both = create_user(&env.db, Some(PASSWORD), false).await;
    link_federated(&env.db, both).await;
    let issued = sign_in(&env.db, both, &AuthContext::password()).await;
    let started = env
        .start(session(&issued), both, Operation::IdentityLink)
        .await
        .expect("a password account with a link can start");
    assert_eq!(
        started.acceptable_factors,
        vec![step_up::Factor::Password, step_up::Factor::Federated]
    );
    assert_reauth(
        env.verify(
            session(&issued),
            both,
            Operation::IdentityLink,
            &started.challenge_id.to_string(),
            "federated",
            "anything",
        )
        .await,
        "identity_link",
        &["password", "federated"],
    );
    assert_unelevated(&env.db, issued.family_id).await;
}

/// The guard evaluates the account now: a password step-up taken before TOTP
/// enrollment no longer satisfies it.
#[tokio::test]
async fn a_step_up_factor_from_before_totp_enrollment_stops_counting() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let issued = sign_in(&env.db, user, &AuthContext::password()).await;
    let started = env
        .start(session(&issued), user, Operation::ApiKeyCreate)
        .await
        .expect("start");
    env.verify(
        session(&issued),
        user,
        Operation::ApiKeyCreate,
        &started.challenge_id.to_string(),
        "password",
        PASSWORD,
    )
    .await
    .expect("elevate");
    env.guard(session(&issued), user, Operation::ApiKeyCreate)
        .await
        .expect("password satisfies a password account");

    enroll_totp(&env.db, user).await;
    assert_reauth(
        env.guard(session(&issued), user, Operation::ApiKeyCreate)
            .await,
        "api_key_create",
        &["totp", "recovery_code"],
    );
}

// ── Challenges (rule 6) ──────────────────────────────────────────────────────

/// Malformed, unknown, wrong-operation, wrong-family and wrong-user
/// submissions all fail closed without consuming or counting; a used or expired
/// challenge is gone.
#[tokio::test]
async fn challenges_reject_every_mismatch_replay_and_expiry_without_elevating() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let intruder = create_user(&env.db, Some(PASSWORD), false).await;
    let mine = sign_in(&env.db, user, &AuthContext::password()).await;
    let my_other = sign_in(&env.db, user, &AuthContext::password()).await;
    let theirs = sign_in(&env.db, intruder, &AuthContext::password()).await;

    let started = env
        .start(session(&mine), user, Operation::IdentityLink)
        .await
        .expect("start");
    let id = started.challenge_id.to_string();
    let key = format!("auth:step_up:{id}");
    let ttl: i64 = env.redis.ttl(&key).await.expect("ttl");
    assert!(
        0 < ttl && ttl <= 300,
        "the challenge expires within 5 minutes"
    );

    let factors: &[&str] = &["password"];
    let cases: [(&str, Caller, Uuid, Operation, String, &str); 6] = [
        (
            "malformed id",
            session(&mine),
            user,
            Operation::IdentityLink,
            "not-a-uuid".into(),
            "password",
        ),
        (
            "unknown id",
            session(&mine),
            user,
            Operation::IdentityLink,
            Uuid::now_v7().to_string(),
            "password",
        ),
        (
            "wrong operation",
            session(&mine),
            user,
            Operation::ApiKeyCreate,
            id.clone(),
            "password",
        ),
        (
            "wrong family",
            session(&my_other),
            user,
            Operation::IdentityLink,
            id.clone(),
            "password",
        ),
        (
            "wrong user",
            session(&theirs),
            intruder,
            Operation::IdentityLink,
            id.clone(),
            "password",
        ),
        (
            "unknown factor",
            session(&mine),
            user,
            Operation::IdentityLink,
            id.clone(),
            "sms",
        ),
    ];
    for (case, caller, user_id, operation, challenge_id, factor) in cases {
        let result = env
            .verify(caller, user_id, operation, &challenge_id, factor, PASSWORD)
            .await;
        assert!(
            matches!(result, Err(AppError::ReauthRequired { .. })),
            "{case} must be rejected, got {result:?}"
        );
    }
    for family in [mine.family_id, my_other.family_id, theirs.family_id] {
        assert_unelevated(&env.db, family).await;
    }
    let attempts: Option<i64> = env
        .redis
        .get(format!("{key}:attempts"))
        .await
        .expect("attempts");
    assert_eq!(attempts, None, "no mismatch counted as an attempt");

    env.verify(
        session(&mine),
        user,
        Operation::IdentityLink,
        &id,
        "password",
        PASSWORD,
    )
    .await
    .expect("the owner's challenge survived every mismatch");

    assert_reauth(
        env.verify(
            session(&mine),
            user,
            Operation::IdentityLink,
            &id,
            "password",
            PASSWORD,
        )
        .await,
        "identity_link",
        factors,
    );

    let started = env
        .start(session(&my_other), user, Operation::IdentityLink)
        .await
        .expect("start");
    let expired_key = format!("auth:step_up:{}", started.challenge_id);
    let _: i64 = env
        .redis
        .del(&expired_key)
        .await
        .expect("expire the challenge");
    assert_reauth(
        env.verify(
            session(&my_other),
            user,
            Operation::IdentityLink,
            &started.challenge_id.to_string(),
            "password",
            PASSWORD,
        )
        .await,
        "identity_link",
        factors,
    );
    assert_unelevated(&env.db, my_other.family_id).await;
    assert_unelevated(&env.db, theirs.family_id).await;
}

/// Four wrong credentials leave the challenge usable; the fifth ends it.
#[tokio::test]
async fn the_fifth_wrong_credential_ends_the_challenge() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let issued = sign_in(&env.db, user, &AuthContext::password()).await;

    let started = env
        .start(session(&issued), user, Operation::IdentityLink)
        .await
        .expect("start");
    let id = started.challenge_id.to_string();
    for _ in 0..4 {
        assert_reauth(
            env.verify(
                session(&issued),
                user,
                Operation::IdentityLink,
                &id,
                "password",
                "wrong",
            )
            .await,
            "identity_link",
            &["password"],
        );
    }
    assert_unelevated(&env.db, issued.family_id).await;
    env.verify(
        session(&issued),
        user,
        Operation::IdentityLink,
        &id,
        "password",
        PASSWORD,
    )
    .await
    .expect("four wrong attempts leave the challenge alive");

    let started = env
        .start(session(&issued), user, Operation::ApiKeyCreate)
        .await
        .expect("start");
    let id = started.challenge_id.to_string();
    let elevated_before = live_row(&env.db, issued.family_id).await.0;
    for _ in 0..5 {
        assert_reauth(
            env.verify(
                session(&issued),
                user,
                Operation::ApiKeyCreate,
                &id,
                "password",
                "wrong",
            )
            .await,
            "api_key_create",
            &["password"],
        );
    }
    assert_reauth(
        env.verify(
            session(&issued),
            user,
            Operation::ApiKeyCreate,
            &id,
            "password",
            PASSWORD,
        )
        .await,
        "api_key_create",
        &["password"],
    );
    assert_eq!(
        live_row(&env.db, issued.family_id).await.0,
        elevated_before,
        "a dead challenge writes nothing"
    );
}

/// Two concurrent correct answers to one challenge elevate exactly once.
#[tokio::test]
async fn concurrent_answers_to_one_challenge_succeed_exactly_once() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let issued = sign_in(&env.db, user, &AuthContext::password()).await;
    let started = env
        .start(session(&issued), user, Operation::IdentityLink)
        .await
        .expect("start");
    let id = started.challenge_id.to_string();

    let (first, second) = tokio::join!(
        env.verify(
            session(&issued),
            user,
            Operation::IdentityLink,
            &id,
            "password",
            PASSWORD
        ),
        env.verify(
            session(&issued),
            user,
            Operation::IdentityLink,
            &id,
            "password",
            PASSWORD
        ),
    );
    assert_eq!(
        [first.is_ok(), second.is_ok()]
            .iter()
            .filter(|ok| **ok)
            .count(),
        1,
        "exactly one concurrent answer wins: {first:?} {second:?}"
    );
}

/// Security contract §6: an unreachable challenge store fails closed and
/// writes no elevation.
#[tokio::test]
async fn an_unreachable_challenge_store_rejects_without_elevating() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let issued = sign_in(&env.db, user, &AuthContext::password()).await;
    let broken = Env {
        db: env.db.clone(),
        redis: unreachable_redis(),
    };

    assert!(
        broken
            .start(session(&issued), user, Operation::IdentityLink)
            .await
            .is_err(),
        "no challenge can be started without the store"
    );

    let started = env
        .start(session(&issued), user, Operation::IdentityLink)
        .await
        .expect("start on the working store");
    assert_reauth(
        broken
            .verify(
                session(&issued),
                user,
                Operation::IdentityLink,
                &started.challenge_id.to_string(),
                "password",
                PASSWORD,
            )
            .await,
        "identity_link",
        &["password"],
    );
    assert_unelevated(&env.db, issued.family_id).await;
}

// ── Google step-up (BAU-8c, D-628) ───────────────────────────────────────────

impl Env {
    async fn google(
        &self,
        caller: Caller,
        user_id: Uuid,
        operation: Operation,
        challenge_id: &str,
        subject: &str,
        auth_time: Option<DateTime<Utc>>,
    ) -> Result<DateTime<Utc>, AppError> {
        step_up::complete_google_step_up_with(
            self.stores(),
            caller,
            user_id,
            operation,
            challenge_id,
            subject,
            auth_time,
            &attome_db::NoHook,
        )
        .await
    }
}

fn google_sub_of(user_id: Uuid) -> String {
    format!("google-sub-{user_id}")
}

/// A Google-only account elevates with its own Google account's fresh
/// `auth_time`, and with nothing else: another `sub`, a missing, stale or
/// future time, a replayed challenge, a TOTP-enrolled account, an OIDC-only
/// account and an unreachable store all refuse without elevating.
#[tokio::test]
async fn a_google_only_account_steps_up_with_its_own_fresh_google_sign_in() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, None, true).await;
    let issued = sign_in(&env.db, user, &AuthContext::federated(None)).await;
    let operation = Operation::IdentityLink;
    let started = env
        .start(session(&issued), user, operation)
        .await
        .expect("start");
    let challenge = started.challenge_id.to_string();
    step_up::check_google_step_up(env.stores(), session(&issued), user, operation, &challenge)
        .await
        .expect("the pre-check passes for the account's own session");
    let now = env.db_now().await;
    let own = google_sub_of(user);

    // Another Google account; no auth_time; a stale one; one in the future.
    for (subject, auth_time) in [
        ("google-sub-someone-else".to_owned(), Some(now)),
        (own.clone(), None),
        (
            own.clone(),
            Some(now - chrono::Duration::seconds(operation.max_age_secs() + 120)),
        ),
        (own.clone(), Some(now + chrono::Duration::seconds(600))),
    ] {
        assert_reauth(
            env.google(
                session(&issued),
                user,
                operation,
                &challenge,
                &subject,
                auth_time,
            )
            .await,
            "identity_link",
            &["federated"],
        );
        assert_unelevated(&env.db, issued.family_id).await;
    }

    let asserted = now - chrono::Duration::seconds(30);
    let elevated_until = env
        .google(
            session(&issued),
            user,
            operation,
            &challenge,
            &own,
            Some(asserted),
        )
        .await
        .expect("a fresh sign-in at the account's own Google account elevates");
    let (row_elevated, row_auth_time, amr, _) = live_row(&env.db, issued.family_id).await;
    assert_eq!(row_elevated, Some(elevated_until));
    assert_eq!(
        row_auth_time.map(|t| t.timestamp()),
        Some(asserted.timestamp()),
        "the verification time is Google's own auth_time"
    );
    assert_eq!(
        amr.unwrap_or_default().last().map(String::as_str),
        Some("fed")
    );
    env.guard(session(&issued), user, operation)
        .await
        .expect("the guard now passes");

    // The challenge was consumed.
    assert_reauth(
        env.google(
            session(&issued),
            user,
            operation,
            &challenge,
            &own,
            Some(env.db_now().await),
        )
        .await,
        "identity_link",
        &["federated"],
    );

    // Not for another session's family, or another user.
    let other = sign_in(&env.db, user, &AuthContext::federated(None)).await;
    let started = env
        .start(session(&other), user, operation)
        .await
        .expect("start");
    assert_reauth(
        env.google(
            session(&issued),
            user,
            operation,
            &started.challenge_id.to_string(),
            &own,
            Some(env.db_now().await),
        )
        .await,
        "identity_link",
        &["federated"],
    );
    assert_unelevated(&env.db, other.family_id).await;
}

/// The Google route is only for an account whose accepted factors include
/// `federated` and which has a Google link: a TOTP-enrolled Google account
/// answers with TOTP, and an OIDC-only account at its IdP.
#[tokio::test]
async fn the_google_step_up_needs_a_google_link_and_no_totp() {
    let env = skip_if_no_db!(env().await);
    let operation = Operation::IdentityLink;

    let enrolled = create_user(&env.db, None, true).await;
    enroll_totp(&env.db, enrolled).await;
    let issued = sign_in(&env.db, enrolled, &AuthContext::federated(None)).await;
    let started = env
        .start(session(&issued), enrolled, operation)
        .await
        .expect("start");
    assert_reauth(
        env.google(
            session(&issued),
            enrolled,
            operation,
            &started.challenge_id.to_string(),
            &google_sub_of(enrolled),
            Some(env.db_now().await),
        )
        .await,
        "identity_link",
        &["totp", "recovery_code"],
    );
    assert_unelevated(&env.db, issued.family_id).await;

    let oidc_only = create_user(&env.db, None, false).await;
    link_federated(&env.db, oidc_only).await;
    let issued = sign_in(&env.db, oidc_only, &AuthContext::federated(None)).await;
    let started = env
        .start(session(&issued), oidc_only, operation)
        .await
        .expect("start");
    assert_reauth(
        env.google(
            session(&issued),
            oidc_only,
            operation,
            &started.challenge_id.to_string(),
            &format!("sub-{oidc_only}"),
            Some(env.db_now().await),
        )
        .await,
        "identity_link",
        &["federated"],
    );
    assert_unelevated(&env.db, issued.family_id).await;

    // API-key/S2S callers never step up.
    let user = create_user(&env.db, None, true).await;
    let result = env
        .google(
            Caller::NonSession,
            user,
            operation,
            &Uuid::now_v7().to_string(),
            &google_sub_of(user),
            Some(env.db_now().await),
        )
        .await;
    assert!(matches!(result, Err(AppError::Forbidden)), "{result:?}");
}

/// An unreachable challenge store fails closed on the Google path too.
#[tokio::test]
async fn an_unreachable_store_refuses_a_google_step_up() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, None, true).await;
    let issued = sign_in(&env.db, user, &AuthContext::federated(None)).await;
    let started = env
        .start(session(&issued), user, Operation::IdentityLink)
        .await
        .expect("start");
    let broken = Env {
        db: env.db.clone(),
        redis: unreachable_redis(),
    };
    assert!(
        broken
            .google(
                session(&issued),
                user,
                Operation::IdentityLink,
                &started.challenge_id.to_string(),
                &google_sub_of(user),
                Some(env.db_now().await),
            )
            .await
            .is_err()
    );
    assert_unelevated(&env.db, issued.family_id).await;
}

// ── Refresh and rotation ─────────────────────────────────────────────────────

/// Refresh copies an elevation exactly, a new sign-in never inherits one, and
/// a lapsed one stays lapsed.
#[tokio::test]
async fn refresh_keeps_elevation_exactly_and_never_creates_or_moves_it() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let issued = sign_in(&env.db, user, &AuthContext::password()).await;
    let started = env
        .start(session(&issued), user, Operation::ApiKeyCreate)
        .await
        .expect("start");
    let until = env
        .verify(
            session(&issued),
            user,
            Operation::ApiKeyCreate,
            &started.challenge_id.to_string(),
            "password",
            PASSWORD,
        )
        .await
        .expect("elevate");

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let rotated =
        refresh::redeem_session(&env.db, &env.redis, &issued.bearer, lifetimes(), &pepper())
            .await
            .expect("rotate");
    assert_eq!(rotated.family_id, issued.family_id);
    assert_eq!(
        live_row(&env.db, issued.family_id).await.0,
        Some(until),
        "rotation copies elevated_until exactly, never later"
    );
    env.guard(session(&issued), user, Operation::ApiKeyCreate)
        .await
        .expect("still elevated after refresh");

    let fresh = sign_in(&env.db, user, &AuthContext::password()).await;
    assert_unelevated(&env.db, fresh.family_id).await;

    sqlx::query(
        "UPDATE refresh_token SET elevated_until = NOW() - interval '1 second'
         WHERE family_id = $1 AND used_at IS NULL",
    )
    .bind(issued.family_id)
    .execute(&env.db)
    .await
    .unwrap();
    let lapsed: Option<DateTime<Utc>> = live_row(&env.db, issued.family_id).await.0;
    refresh::redeem_session(&env.db, &env.redis, &rotated.bearer, lifetimes(), &pepper())
        .await
        .expect("rotate again");
    assert_eq!(live_row(&env.db, issued.family_id).await.0, lapsed);
    assert_reauth(
        env.guard(session(&issued), user, Operation::ApiKeyCreate)
            .await,
        "api_key_create",
        &["password"],
    );
}

/// A rotation racing a step-up can only drop the new elevation: no row ever
/// carries anything but NULL or the value the step-up wrote.
#[tokio::test]
async fn a_rotation_racing_a_step_up_can_only_lose_the_elevation() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let mut won = 0;
    let mut lost = 0;

    for _ in 0..8 {
        let issued = sign_in(&env.db, user, &AuthContext::password()).await;
        let started = env
            .start(session(&issued), user, Operation::IdentityLink)
            .await
            .expect("start");
        let id = started.challenge_id.to_string();
        let ring = pepper();
        let (step_up, rotation) = tokio::join!(
            env.verify(
                session(&issued),
                user,
                Operation::IdentityLink,
                &id,
                "password",
                PASSWORD
            ),
            refresh::redeem_session(&env.db, &env.redis, &issued.bearer, lifetimes(), &ring,),
        );
        rotation.expect("the rotation itself succeeds");

        let rows = family_rows(&env.db, issued.family_id).await;
        assert_eq!(rows.len(), 2, "the original plus one replacement");
        match step_up {
            Ok(until) => {
                for row in &rows {
                    assert!(
                        row.0.is_none() || row.0 == Some(until),
                        "a row carries {:?}, not NULL or the written {until}",
                        row.0
                    );
                }
                let live = rows.iter().find(|row| row.3).expect("live row");
                if live.0 == Some(until) {
                    won += 1;
                } else {
                    lost += 1;
                }
            }
            Err(error) => {
                assert!(
                    matches!(error, AppError::Unauthorized),
                    "a step-up losing the race finds no live row: {error:?}"
                );
                for row in &rows {
                    assert_eq!(row.0, None, "a lost step-up leaves no elevation");
                }
                lost += 1;
            }
        }
    }
    assert_eq!(won + lost, 8);
}

// ── In-request factor (rule 8) ───────────────────────────────────────────────

/// MFA disable and recovery-code regeneration take their freshness from the
/// code in the request: the guard needs only the live session, no challenge
/// exists for them, and one code is verified exactly once.
#[tokio::test]
async fn mfa_operations_take_freshness_from_the_code_in_the_request() {
    let env = skip_if_no_db!(env().await);
    let user = create_user(&env.db, Some(PASSWORD), false).await;
    let (totp, recovery_codes) = enroll_totp(&env.db, user).await;
    let issued = sign_in(&env.db, user, &AuthContext::password_and_totp()).await;
    let before = live_row(&env.db, issued.family_id).await;

    for operation in [Operation::MfaDisable, Operation::RecoveryCodesRegenerate] {
        env.guard(session(&issued), user, operation)
            .await
            .expect("an unelevated live session passes the guard");
        assert!(matches!(
            env.guard(Caller::NonSession, user, operation).await,
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            env.start(session(&issued), user, operation).await,
            Err(AppError::NotFound)
        ));
        assert_eq!(Operation::from_step_up_route(operation.as_str()), None);
    }

    // The guard plus the operation verify the TOTP code once: a second
    // verification of the same code would be refused as a replay.
    let code = next_code(&totp);
    env.guard(session(&issued), user, Operation::RecoveryCodesRegenerate)
        .await
        .expect("guard");
    mfa::regenerate_recovery_codes(&env.db, &mfa_ring(), &pepper(), user, &code)
        .await
        .expect("one code regenerates, with no second verification");
    assert!(
        mfa::verify_code(&env.db, &mfa_ring(), user, &code)
            .await
            .is_err(),
        "the code was consumed by the single verification"
    );

    let fresh_codes: Vec<String> = recovery_codes;
    assert!(!fresh_codes.is_empty());
    assert_eq!(
        live_row(&env.db, issued.family_id).await,
        before,
        "neither operation reads or writes elevation"
    );
}
