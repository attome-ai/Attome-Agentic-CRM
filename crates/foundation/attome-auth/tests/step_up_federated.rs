//! Federated step-up (D-510 rule 5; attome-auth hardening 2.1c) over OIDC,
//! against a local mock provider that serves discovery, JWKS and a token
//! endpoint issuing ID tokens signed with a throwaway RSA key.
//!
//! Each round runs the real path: a 2.1b challenge, the federated start
//! binding, `oidc::start_step_up_login`, the provider's signed ID token,
//! `oidc::complete_login` (signature, issuer, audience, expiry, nonce), and
//! `step_up::complete_federated_step_up`.
//!
//! Requires a live Postgres migrated through 0462 and a reachable Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`), same convention as `step_up.rs`.
//! Run manually:
//!
//! ```powershell
//! cargo test -p attome-auth --test step_up_federated -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use attome_auth::auth_context::AuthContext;
use attome_auth::mfa;
use attome_auth::oidc;
use attome_auth::refresh::{self, IssuedRefresh, RefreshLifetimes};
use attome_auth::step_up::{
    self, Caller, FederatedProtocol, FederatedStepUp, Operation, StepUpStores,
};
use attome_auth::{PepperRing, SessionId, hash_password_async};
use attome_cache::RedisPool;
use attome_config::{KeyRing, OidcProviderConfig};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use fred::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const THIRTY_DAYS_SECS: i64 = 30 * 86_400;
const PASSWORD: &str = "step-up-federated-password-0123";
const CLIENT_ID: &str = "step-up-federated-client";
const KID: &str = "step-up-federated-kid";
const REDIRECT_URI: &str = "https://app.example/api/v1/auth/step-up-callback/oidc/test";

// ── Mock OIDC provider ───────────────────────────────────────────────────────

fn signing_key() -> &'static rsa::RsaPrivateKey {
    static KEY: OnceLock<rsa::RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("generate a test RSA key")
    })
}

fn jwks() -> serde_json::Value {
    use rsa::traits::PublicKeyParts;
    let key = signing_key();
    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
        }]
    })
}

fn sign(claims: &serde_json::Value) -> String {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    let pem = signing_key()
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .expect("pem");
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    jsonwebtoken::encode(&header, claims, &key).expect("sign the ID token")
}

/// A provider on a local port. The token endpoint answers with whatever
/// [`MockIdp::issue`] last queued, once, or 500 when down or empty.
#[derive(Clone)]
struct MockIdp {
    issuer: String,
    next_id_token: Arc<Mutex<Option<String>>>,
    token_endpoint_up: Arc<AtomicBool>,
}

impl MockIdp {
    fn issue(&self, claims: &serde_json::Value) {
        *self.next_id_token.lock().unwrap() = Some(sign(claims));
    }

    fn provider(&self) -> OidcProviderConfig {
        OidcProviderConfig {
            display_name: "Mock IdP".into(),
            issuer: self.issuer.clone(),
            client_id: CLIENT_ID.into(),
            client_secret: "mock-client-secret".into(),
            scopes: vec!["openid".into(), "email".into()],
            email_claim: "email".into(),
            require_email_verified_claim: false,
        }
    }
}

async fn read_request_path(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    head.lines()
        .next()?
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
}

async fn mock_idp() -> MockIdp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp = MockIdp {
        issuer: format!("http://{}", listener.local_addr().unwrap()),
        next_id_token: Arc::new(Mutex::new(None)),
        token_endpoint_up: Arc::new(AtomicBool::new(true)),
    };
    let served = idp.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let idp = served.clone();
            tokio::spawn(async move {
                let Some(path) = read_request_path(&mut socket).await else {
                    return;
                };
                let (status, body) = if path.starts_with("/.well-known/openid-configuration") {
                    (
                        200,
                        serde_json::json!({
                            "issuer": idp.issuer,
                            "authorization_endpoint": format!("{}/authorize", idp.issuer),
                            "token_endpoint": format!("{}/token", idp.issuer),
                            "jwks_uri": format!("{}/jwks", idp.issuer),
                        })
                        .to_string(),
                    )
                } else if path.starts_with("/jwks") {
                    (200, jwks().to_string())
                } else if path.starts_with("/token") {
                    let queued = idp.next_id_token.lock().unwrap().take();
                    match queued {
                        Some(id_token) if idp.token_endpoint_up.load(Ordering::SeqCst) => (
                            200,
                            serde_json::json!({ "id_token": id_token, "token_type": "Bearer" })
                                .to_string(),
                        ),
                        _ => (500, "{}".to_owned()),
                    }
                } else {
                    (404, "{}".to_owned())
                };
                let reason = match status {
                    200 => "OK",
                    404 => "Not Found",
                    _ => "Internal Server Error",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    idp
}

fn id_token_claims(
    issuer: &str,
    subject: &str,
    nonce: &str,
    auth_time: Option<i64>,
) -> serde_json::Value {
    let now = Utc::now().timestamp();
    let mut claims = serde_json::json!({
        "iss": issuer,
        "aud": CLIENT_ID,
        "sub": subject,
        "email": format!("{subject}@idp.example"),
        "email_verified": true,
        "nonce": nonce,
        "iat": now,
        "exp": now + 300,
    });
    if let Some(auth_time) = auth_time {
        claims["auth_time"] = serde_json::json!(auth_time);
    }
    claims
}

fn query_param(url: &str, name: &str) -> String {
    url.split_once('?')
        .expect("a query")
        .1
        .split('&')
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
        .unwrap_or_else(|| panic!("no {name} in {url}"))
}

// ── Accounts and sessions ────────────────────────────────────────────────────

fn lifetimes() -> RefreshLifetimes {
    RefreshLifetimes {
        idle_secs: 3600,
        absolute_secs: THIRTY_DAYS_SECS,
    }
}

fn pepper() -> PepperRing {
    PepperRing::new(0, "step-up-federated-pepper-0123456789ab", &[])
}

fn mfa_ring() -> KeyRing {
    KeyRing::single("ab".repeat(32))
}

async fn redis_pool() -> attome_cache::Store {
    let host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into());
    let config = RedisConfig::from_url(&format!("redis://{host}:{port}")).expect("redis config");
    let pool = RedisPool::new(config, None, None, None, 4).expect("build redis pool");
    pool.connect();
    pool.wait_for_connect()
        .await
        .expect("connect to test Redis");
    attome_cache::Store::Redis(pool)
}

fn unreachable_redis() -> attome_cache::Store {
    let config = RedisConfig::from_url("redis://127.0.0.1:1/0").unwrap();
    attome_cache::Store::Redis(Builder::from_config(config).build_pool(1).unwrap())
}

struct Env {
    db: DbPool,
    redis: attome_cache::Store,
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

    async fn db_now(&self) -> DateTime<Utc> {
        sqlx::query_scalar("SELECT NOW()")
            .fetch_one(&self.db)
            .await
            .expect("database clock")
    }
}

/// A unique provider key per test, so the cached discovery document and JWKS
/// always belong to that test's mock.
fn provider_key() -> String {
    format!("step-up-oidc-{}", Uuid::now_v7())
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
    .bind(format!("step-up-federated-{id}@example.invalid"))
    .bind(hash)
    .bind(google.then(|| format!("google-sub-{id}")))
    .execute(db)
    .await
    .expect("insert test user");
    id
}

async fn link(db: &DbPool, user_id: Uuid, provider_key: &str) -> String {
    let subject = format!("subject-{user_id}");
    sqlx::query(
        "INSERT INTO user_identity (user_ref, provider_key, provider_sub, email)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(provider_key)
    .bind(&subject)
    .bind(format!("{subject}@idp.example"))
    .execute(db)
    .await
    .expect("link a federated identity");
    subject
}

async fn sign_in(db: &DbPool, user_id: Uuid, context: &AuthContext) -> IssuedRefresh {
    refresh::issue(db, user_id, context, lifetimes(), &pepper())
        .await
        .expect("issue refresh token")
}

fn session(issued: &IssuedRefresh) -> Caller {
    Caller::Session(SessionId(issued.family_id))
}

struct Account {
    user_id: Uuid,
    subject: String,
    issued: IssuedRefresh,
}

/// A password account with a linked identity at `provider_key`, signed in.
async fn linked_account(env: &Env, provider_key: &str) -> Account {
    let user_id = create_user(&env.db, Some(PASSWORD), false).await;
    let subject = link(&env.db, user_id, provider_key).await;
    let issued = sign_in(&env.db, user_id, &AuthContext::password()).await;
    Account {
        user_id,
        subject,
        issued,
    }
}

/// `(elevated_until, auth_time, amr)` of a family's live row.
async fn live_row(
    db: &DbPool,
    family_id: Uuid,
) -> (
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<Vec<String>>,
) {
    sqlx::query_as(
        "SELECT elevated_until, auth_time, amr FROM refresh_token
         WHERE family_id = $1 AND used_at IS NULL AND revoked_at IS NULL
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(family_id)
    .fetch_one(db)
    .await
    .expect("live row")
}

fn is_reauth<T>(result: &Result<T, AppError>) -> bool {
    matches!(result, Err(AppError::ReauthRequired { .. }))
}

/// One federated round up to, but not including, the step-up completion.
struct Round {
    authorize_url: String,
    state: String,
    binding: FederatedStepUp,
    subject: String,
    auth_time: Option<DateTime<Utc>>,
}

/// Starts a challenge and its federated half for `account`, lets the mock
/// issue an ID token for `subject` with `auth_time`, and validates it through
/// `oidc::complete_login`.
async fn federated_round(
    env: &Env,
    idp: &MockIdp,
    provider_key: &str,
    account: &Account,
    operation: Operation,
    subject: &str,
    auth_time: Option<i64>,
) -> Round {
    let started = step_up::start_challenge(
        env.stores(),
        session(&account.issued),
        account.user_id,
        operation,
    )
    .await
    .expect("start a challenge");
    let binding = step_up::begin_federated_step_up(
        env.stores(),
        session(&account.issued),
        account.user_id,
        operation,
        FederatedProtocol::Oidc,
        provider_key,
        &started.challenge_id.to_string(),
    )
    .await
    .expect("begin the federated step-up");
    let authorize_url = oidc::start_step_up_login(
        &env.redis,
        &env.redis,
        &idp.provider(),
        provider_key,
        REDIRECT_URI,
        binding,
    )
    .await
    .expect("authorize url");
    let state = query_param(&authorize_url, "state");
    let nonce = query_param(&authorize_url, "nonce");
    idp.issue(&id_token_claims(&idp.issuer, subject, &nonce, auth_time));
    let identity = oidc::complete_login(
        &env.redis,
        &env.redis,
        &idp.provider(),
        provider_key,
        "authorization-code",
        // This harness *is* the browser that started the flow, so it presents
        // the state back as the binding — what a real callback's cookie does.
        oidc::bind_to_browser(Some(&state), &state).expect("the starting browser"),
    )
    .await
    .expect("the provider's ID token validates");
    Round {
        authorize_url,
        state,
        binding: identity
            .step_up
            .expect("the step-up binding comes back from the state"),
        subject: identity.sub,
        auth_time: identity.auth_time,
    }
}

async fn complete(env: &Env, provider_key: &str, round: &Round) -> Result<DateTime<Utc>, AppError> {
    step_up::complete_federated_step_up(
        env.stores(),
        &round.binding,
        FederatedProtocol::Oidc,
        provider_key,
        &round.subject,
        round.auth_time,
    )
    .await
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// A fresh provider authentication elevates exactly the bound family, with the
/// provider's `auth_time` as the verification time.
#[tokio::test]
async fn a_fresh_oidc_step_up_elevates_the_bound_family_with_the_providers_auth_time() {
    let env = skip_if_no_db!(env().await);
    let idp = mock_idp().await;
    let key = provider_key();
    let account = linked_account(&env, &key).await;
    let other_session = sign_in(&env.db, account.user_id, &AuthContext::password()).await;

    let authenticated = env.db_now().await.timestamp() - 60;
    let round = federated_round(
        &env,
        &idp,
        &key,
        &account,
        Operation::IdentityLink,
        &account.subject.clone(),
        Some(authenticated),
    )
    .await;
    assert_eq!(query_param(&round.authorize_url, "prompt"), "login");
    assert_eq!(query_param(&round.authorize_url, "max_age"), "300");
    assert_eq!(round.binding.family_id, account.issued.family_id);
    assert_eq!(round.binding.user_id, account.user_id);

    let until = complete(&env, &key, &round).await.expect("fresh step-up");
    let authenticated_at = DateTime::<Utc>::from_timestamp(authenticated, 0).unwrap();
    assert_eq!(
        until,
        authenticated_at + Duration::minutes(15),
        "elevation runs from the provider's authentication time, not callback time"
    );
    let (elevated_until, auth_time, amr) = live_row(&env.db, account.issued.family_id).await;
    assert_eq!(elevated_until, Some(until));
    assert_eq!(auth_time, Some(authenticated_at));
    assert_eq!(
        amr.as_deref()
            .and_then(<[String]>::last)
            .map(String::as_str),
        Some("fed")
    );
    step_up::require_recent_auth(
        &env.db,
        session(&account.issued),
        account.user_id,
        Operation::IdentityLink,
        THIRTY_DAYS_SECS,
    )
    .await
    .expect("the guard accepts the federated elevation");

    assert_eq!(
        live_row(&env.db, other_session.family_id).await.0,
        None,
        "another session of the same user is not elevated"
    );
}

/// Stale, missing, future and callback-time authentication times never elevate.
#[tokio::test]
async fn stale_missing_future_and_callback_time_authentication_is_refused() {
    let env = skip_if_no_db!(env().await);
    let idp = mock_idp().await;
    let key = provider_key();
    let account = linked_account(&env, &key).await;
    let now = env.db_now().await.timestamp();
    let subject = account.subject.clone();

    let cases: [(&str, Operation, Option<i64>); 4] = [
        (
            "stale for identity_link (5 min)",
            Operation::IdentityLink,
            Some(now - 301),
        ),
        (
            "stale for api_key_create (15 min)",
            Operation::ApiKeyCreate,
            Some(now - 901),
        ),
        ("missing auth_time", Operation::IdentityLink, None),
        (
            "auth_time in the future",
            Operation::IdentityLink,
            Some(now + 600),
        ),
    ];
    for (case, operation, auth_time) in cases {
        let round =
            federated_round(&env, &idp, &key, &account, operation, &subject, auth_time).await;
        let result = complete(&env, &key, &round).await;
        assert!(is_reauth(&result), "{case} must be refused, got {result:?}");
        assert_eq!(
            live_row(&env.db, account.issued.family_id).await.0,
            None,
            "{case}"
        );
    }

    // Callback-time substitution: the token is issued at callback time (`iat`
    // is now) but asserts no authentication time. Nothing stands in for it.
    let round = federated_round(
        &env,
        &idp,
        &key,
        &account,
        Operation::ApiKeyCreate,
        &subject,
        None,
    )
    .await;
    assert_eq!(round.auth_time, None);
    assert!(is_reauth(&complete(&env, &key, &round).await));

    // A future time that reached the engine directly, past the token filter.
    let round = federated_round(
        &env,
        &idp,
        &key,
        &account,
        Operation::IdentityLink,
        &subject,
        Some(now - 30),
    )
    .await;
    let future = step_up::complete_federated_step_up(
        env.stores(),
        &round.binding,
        FederatedProtocol::Oidc,
        &key,
        &round.subject,
        Some(env.db_now().await + Duration::minutes(10)),
    )
    .await;
    assert!(is_reauth(&future));
    assert_eq!(live_row(&env.db, account.issued.family_id).await.0, None);

    // Inside api_key_create's 15 minutes but outside identity_link's 5.
    let ten_minutes_ago = env.db_now().await.timestamp() - 600;
    let round = federated_round(
        &env,
        &idp,
        &key,
        &account,
        Operation::ApiKeyCreate,
        &subject,
        Some(ten_minutes_ago),
    )
    .await;
    complete(&env, &key, &round)
        .await
        .expect("10 minutes satisfies api_key_create");
}

/// The subject, family, user, operation, provider and protocol must all match
/// the challenge; a mismatch neither elevates nor consumes it.
#[tokio::test]
async fn a_mismatched_subject_family_user_operation_or_provider_is_refused() {
    let env = skip_if_no_db!(env().await);
    let idp = mock_idp().await;
    let key = provider_key();
    let alice = linked_account(&env, &key).await;
    let bob = linked_account(&env, &key).await;
    let alice_other = sign_in(&env.db, alice.user_id, &AuthContext::password()).await;
    let fresh = env.db_now().await.timestamp() - 30;

    // Another linked user's subject in the provider's token.
    let round = federated_round(
        &env,
        &idp,
        &key,
        &alice,
        Operation::IdentityLink,
        &bob.subject.clone(),
        Some(fresh),
    )
    .await;
    assert!(is_reauth(&complete(&env, &key, &round).await));
    assert_eq!(live_row(&env.db, alice.issued.family_id).await.0, None);
    assert_eq!(live_row(&env.db, bob.issued.family_id).await.0, None);

    let started = step_up::start_challenge(
        env.stores(),
        session(&alice.issued),
        alice.user_id,
        Operation::IdentityLink,
    )
    .await
    .expect("start");
    let id = started.challenge_id.to_string();
    let begin = |caller: Caller, user_id: Uuid, operation: Operation, provider: String| {
        let id = id.clone();
        let stores = env.stores();
        async move {
            step_up::begin_federated_step_up(
                stores,
                caller,
                user_id,
                operation,
                FederatedProtocol::Oidc,
                &provider,
                &id,
            )
            .await
        }
    };
    assert!(
        is_reauth(
            &begin(
                session(&alice_other),
                alice.user_id,
                Operation::IdentityLink,
                key.clone()
            )
            .await
        ),
        "wrong family"
    );
    assert!(
        is_reauth(
            &begin(
                session(&bob.issued),
                bob.user_id,
                Operation::IdentityLink,
                key.clone()
            )
            .await
        ),
        "wrong user"
    );
    assert!(
        is_reauth(
            &begin(
                session(&alice.issued),
                alice.user_id,
                Operation::ApiKeyCreate,
                key.clone()
            )
            .await
        ),
        "wrong operation"
    );
    assert!(
        is_reauth(
            &begin(
                session(&alice.issued),
                alice.user_id,
                Operation::IdentityLink,
                provider_key()
            )
            .await
        ),
        "unlinked provider"
    );
    assert!(matches!(
        begin(
            Caller::NonSession,
            alice.user_id,
            Operation::IdentityLink,
            key.clone()
        )
        .await,
        Err(AppError::Forbidden)
    ));

    let binding = begin(
        session(&alice.issued),
        alice.user_id,
        Operation::IdentityLink,
        key.clone(),
    )
    .await
    .expect("the right session, user, operation and provider begin");
    let at = Some(env.db_now().await - Duration::seconds(30));
    let finish = |binding: FederatedStepUp, protocol: FederatedProtocol, provider: String| {
        let subject = alice.subject.clone();
        let stores = env.stores();
        async move {
            step_up::complete_federated_step_up(stores, &binding, protocol, &provider, &subject, at)
                .await
        }
    };
    assert!(
        is_reauth(&finish(binding.clone(), FederatedProtocol::Oidc, provider_key()).await),
        "wrong provider"
    );
    let moved = FederatedStepUp {
        family_id: alice_other.family_id,
        ..binding.clone()
    };
    assert!(
        is_reauth(&finish(moved, FederatedProtocol::Oidc, key.clone()).await),
        "moved to another family"
    );
    let transferred = FederatedStepUp {
        user_id: bob.user_id,
        ..binding.clone()
    };
    assert!(
        is_reauth(&finish(transferred, FederatedProtocol::Oidc, key.clone()).await),
        "transferred to another user"
    );
    for family in [
        alice.issued.family_id,
        alice_other.family_id,
        bob.issued.family_id,
    ] {
        assert_eq!(live_row(&env.db, family).await.0, None);
    }

    finish(binding, FederatedProtocol::Oidc, key.clone())
        .await
        .expect("the challenge survived every mismatch");
    assert!(live_row(&env.db, alice.issued.family_id).await.0.is_some());
    assert_eq!(live_row(&env.db, alice_other.family_id).await.0, None);
}

/// The provider state and the challenge are both single-use, and an expired
/// challenge is gone.
#[tokio::test]
async fn a_replayed_state_or_a_consumed_or_expired_challenge_is_refused() {
    let env = skip_if_no_db!(env().await);
    let idp = mock_idp().await;
    let key = provider_key();
    let account = linked_account(&env, &key).await;
    let subject = account.subject.clone();
    let fresh = env.db_now().await.timestamp() - 30;

    let round = federated_round(
        &env,
        &idp,
        &key,
        &account,
        Operation::IdentityLink,
        &subject,
        Some(fresh),
    )
    .await;
    let until = complete(&env, &key, &round)
        .await
        .expect("first completion");

    idp.issue(&id_token_claims(
        &idp.issuer,
        &subject,
        &query_param(&round.authorize_url, "nonce"),
        Some(fresh),
    ));
    assert!(
        matches!(
            oidc::complete_login(
                &env.redis,
                &env.redis,
                &idp.provider(),
                &key,
                "code",
                oidc::bind_to_browser(Some(&round.state), &round.state)
                    .expect("the starting browser")
            )
            .await,
            Err(AppError::Unauthorized)
        ),
        "the provider state is single-use"
    );
    assert!(
        is_reauth(&complete(&env, &key, &round).await),
        "the challenge is single-use"
    );

    let round = federated_round(
        &env,
        &idp,
        &key,
        &account,
        Operation::ApiKeyCreate,
        &subject,
        Some(fresh),
    )
    .await;
    let _: i64 = env
        .redis
        .del(format!("auth:step_up:{}", round.binding.challenge_id))
        .await
        .expect("expire the challenge");
    assert!(
        is_reauth(&complete(&env, &key, &round).await),
        "an expired challenge is gone"
    );
    assert_eq!(
        live_row(&env.db, account.issued.family_id).await.0,
        Some(until),
        "refusals leave the earlier elevation exactly as it was"
    );
}

/// Rule 4 decides who may use the provider: never a TOTP-enrolled account,
/// never a Google-only account, and a federated-only account can.
#[tokio::test]
async fn only_accounts_that_accept_federated_can_step_up_at_the_provider() {
    let env = skip_if_no_db!(env().await);
    let idp = mock_idp().await;
    let key = provider_key();

    let totp_user = create_user(&env.db, Some(PASSWORD), false).await;
    link(&env.db, totp_user, &key).await;
    let enrolled = mfa::enroll(&env.db, &mfa_ring(), totp_user)
        .await
        .expect("enroll");
    let totp = totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(totp_rs::Secret::try_from_base32(&enrolled.secret_base32).unwrap())
        .with_account_name("test".to_string())
        .build()
        .unwrap();
    mfa::confirm_enrollment(
        &env.db,
        &mfa_ring(),
        &pepper(),
        totp_user,
        &totp.generate_current().to_string(),
    )
    .await
    .expect("confirm enrollment");
    let totp_session = sign_in(&env.db, totp_user, &AuthContext::password_and_totp()).await;
    let started = step_up::start_challenge(
        env.stores(),
        session(&totp_session),
        totp_user,
        Operation::IdentityLink,
    )
    .await
    .expect("start");
    let begun = step_up::begin_federated_step_up(
        env.stores(),
        session(&totp_session),
        totp_user,
        Operation::IdentityLink,
        FederatedProtocol::Oidc,
        &key,
        &started.challenge_id.to_string(),
    )
    .await;
    assert!(
        is_reauth(&begun),
        "a TOTP-enrolled account needs TOTP, not its IdP"
    );

    let google_only = create_user(&env.db, None, true).await;
    let google_session = sign_in(&env.db, google_only, &AuthContext::federated(None)).await;
    // BAU-8c: a Google-only account is offered `federated`, answered on the
    // Google step-up route, never at an OIDC provider it is not linked to.
    let started = step_up::start_challenge(
        env.stores(),
        session(&google_session),
        google_only,
        Operation::IdentityLink,
    )
    .await
    .expect("a Google-only account gets a challenge");
    assert_eq!(started.acceptable_factors, vec![step_up::Factor::Federated]);
    let begun = step_up::begin_federated_step_up(
        env.stores(),
        session(&google_session),
        google_only,
        Operation::IdentityLink,
        FederatedProtocol::Oidc,
        &key,
        &started.challenge_id.to_string(),
    )
    .await;
    assert!(is_reauth(&begun), "no OIDC link for this provider");

    let federated_only = create_user(&env.db, None, false).await;
    let subject = link(&env.db, federated_only, &key).await;
    let issued = sign_in(&env.db, federated_only, &AuthContext::federated(None)).await;
    let account = Account {
        user_id: federated_only,
        subject: subject.clone(),
        issued,
    };
    let fresh = env.db_now().await.timestamp() - 30;
    let round = federated_round(
        &env,
        &idp,
        &key,
        &account,
        Operation::IdentityLink,
        &subject,
        Some(fresh),
    )
    .await;
    complete(&env, &key, &round)
        .await
        .expect("a federated-only account steps up at its provider");
}

/// An unavailable provider or challenge store refuses and writes nothing.
#[tokio::test]
async fn an_unavailable_provider_or_store_refuses_without_elevating() {
    let env = skip_if_no_db!(env().await);
    let idp = mock_idp().await;
    let key = provider_key();
    let account = linked_account(&env, &key).await;
    let fresh = env.db_now().await.timestamp() - 30;

    let started = step_up::start_challenge(
        env.stores(),
        session(&account.issued),
        account.user_id,
        Operation::IdentityLink,
    )
    .await
    .expect("start");
    let binding = step_up::begin_federated_step_up(
        env.stores(),
        session(&account.issued),
        account.user_id,
        Operation::IdentityLink,
        FederatedProtocol::Oidc,
        &key,
        &started.challenge_id.to_string(),
    )
    .await
    .expect("begin");
    let url = oidc::start_step_up_login(
        &env.redis,
        &env.redis,
        &idp.provider(),
        &key,
        REDIRECT_URI,
        binding.clone(),
    )
    .await
    .expect("authorize url");
    idp.token_endpoint_up.store(false, Ordering::SeqCst);
    idp.issue(&id_token_claims(
        &idp.issuer,
        &account.subject,
        &query_param(&url, "nonce"),
        Some(fresh),
    ));
    let state_id = query_param(&url, "state");
    let exchanged = oidc::complete_login(
        &env.redis,
        &env.redis,
        &idp.provider(),
        &key,
        "code",
        oidc::bind_to_browser(Some(&state_id), &state_id).expect("the starting browser"),
    )
    .await;
    assert!(
        exchanged.is_err(),
        "an unavailable token endpoint fails the exchange"
    );
    assert_eq!(live_row(&env.db, account.issued.family_id).await.0, None);
    idp.token_endpoint_up.store(true, Ordering::SeqCst);

    let broken = Env {
        db: env.db.clone(),
        redis: unreachable_redis(),
    };
    let refused = step_up::complete_federated_step_up(
        broken.stores(),
        &binding,
        FederatedProtocol::Oidc,
        &key,
        &account.subject,
        Some(env.db_now().await - Duration::seconds(30)),
    )
    .await;
    assert!(
        is_reauth(&refused),
        "an unreachable challenge store refuses"
    );
    assert_eq!(live_row(&env.db, account.issued.family_id).await.0, None);
}

/// Federated elevation never outlives the family, rotation copies it exactly,
/// and a new sign-in does not inherit it.
#[tokio::test]
async fn federated_elevation_is_capped_copied_by_rotation_and_never_transferred() {
    let env = skip_if_no_db!(env().await);
    let idp = mock_idp().await;
    let key = provider_key();
    let account = linked_account(&env, &key).await;
    let anchor: DateTime<Utc> = sqlx::query_scalar(
        "UPDATE refresh_token
         SET family_started_at = NOW() - make_interval(secs => $2::float8)
         WHERE family_id = $1 RETURNING family_started_at",
    )
    .bind(account.issued.family_id)
    .bind(THIRTY_DAYS_SECS - 120)
    .fetch_one(&env.db)
    .await
    .expect("move the anchor to two minutes before the end");

    let fresh = env.db_now().await.timestamp() - 30;
    let subject = account.subject.clone();
    let round = federated_round(
        &env,
        &idp,
        &key,
        &account,
        Operation::ApiKeyCreate,
        &subject,
        Some(fresh),
    )
    .await;
    let until = complete(&env, &key, &round).await.expect("elevate");
    assert_eq!(
        until,
        anchor + Duration::seconds(THIRTY_DAYS_SECS),
        "capped at the family's end"
    );

    let rotated = refresh::redeem_session(
        &env.db,
        &env.redis,
        &account.issued.bearer,
        lifetimes(),
        &pepper(),
    )
    .await
    .expect("rotate");
    assert_eq!(rotated.family_id, account.issued.family_id);
    assert_eq!(
        live_row(&env.db, account.issued.family_id).await.0,
        Some(until)
    );

    let fresh_sign_in = sign_in(&env.db, account.user_id, &AuthContext::federated(None)).await;
    assert_eq!(live_row(&env.db, fresh_sign_in.family_id).await.0, None);
}
