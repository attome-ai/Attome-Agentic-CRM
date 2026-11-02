//! V2-D1532 (7): a Teams bot's activities reach the integration webhook with a
//! Bot Framework token. A token signed for this bot and endpoint lands one
//! event, the same activity again lands nothing, and a token for another bot,
//! or none, is a 401 that stores nothing.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_integration::botframework::{AUTH_TYPE, ISSUER, KEYS_CACHE};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use uuid::Uuid;

const PRIVATE_PEM: &str =
    include_str!("../../attome-integration/tests/fixtures/botframework_test_key.pem");
const MODULUS_B64: &str =
    include_str!("../../attome-integration/tests/fixtures/botframework_test_key.n");
const APP: &str = "11111111-2222-3333-4444-555555555555";
const SERVICE: &str = "https://smba.trafficmanager.net/emea/";

/// A Teams bot system acting as the administrator, its credential the bot's
/// app id and secret.
async fn bot(app: &TestApp) -> Uuid {
    attome_api::changeset::boot::apply_platform_definition(&app.state, "attome-integration")
        .await
        .unwrap();
    let system = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO integration_system \
            (id, name, kind, base_url, auth_type, service_principal_ref, status, created_at) \
         VALUES ($1, 'Teams bot', 'rest', 'https://smba.trafficmanager.net', $2, $3, 'active', NOW())",
    )
    .bind(system)
    .bind(AUTH_TYPE)
    .bind(app.admin.id.to_string())
    .execute(app.db())
    .await
    .unwrap();
    let ring = app
        .state
        .base
        .secrets
        .load()
        .integration_credential_key
        .clone();
    let mut tx = attome_db::tx::begin(app.db()).await.unwrap();
    let credential =
        attome_integration::credential::store(&mut tx, &ring, system, &format!("{APP}:s3cret"))
            .await
            .unwrap();
    sqlx::query("UPDATE integration_system SET credential_ref = $2 WHERE id = $1")
        .bind(system)
        .bind(credential.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    attome_db::tx::commit(tx).await.unwrap();
    // The published key set, as if just fetched from Bot Framework.
    let keys = json!({ "keys": [{
        "kty": "RSA", "use": "sig", "kid": "k1",
        "n": MODULUS_B64.trim(), "e": URL_SAFE_NO_PAD.encode([1u8, 0, 1]),
        "endorsements": ["msteams"],
    }]});
    app.state
        .base
        .redis_coordination
        .set(KEYS_CACHE, keys.to_string(), None)
        .await
        .unwrap();
    system
}

fn token(aud: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("k1".to_owned());
    jsonwebtoken::encode(
        &header,
        &json!({ "iss": ISSUER, "aud": aud, "nbf": now - 10, "exp": now + 600,
                 "serviceUrl": SERVICE }),
        &EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn activity() -> Value {
    json!({
        "id": format!("act-{}", Uuid::now_v7().simple()),
        "type": "message",
        "channelId": "msteams",
        "serviceUrl": SERVICE,
        "text": "hello",
    })
}

async fn post(
    app: &TestApp,
    system: Uuid,
    auth: Option<String>,
    body: &Value,
) -> (StatusCode, Value) {
    let path = format!("/api/v1/integrations/{system}/webhook");
    let header = auth.map(|t| format!("Bearer {t}"));
    let mut headers = vec![("content-type", "application/json")];
    if let Some(h) = header.as_deref() {
        headers.push(("authorization", h));
    }
    app.request_public(Method::POST, &path, &headers, body.to_string().into_bytes())
        .await
}

async fn events(app: &TestApp, system: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM integration_event WHERE system_ref = $1")
        .bind(system)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: C5
#[test]
fn a_signed_activity_lands_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let system = bot(&app).await;
        let activity = activity();
        let (status, body) = post(&app, system, Some(token(APP)), &activity).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["accepted"], 1);
        let event_type: String =
            sqlx::query_scalar("SELECT event_type FROM integration_event WHERE system_ref = $1")
                .bind(system)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(event_type, "teams.message");
        // Teams retries with the same activity id.
        let (status, body) = post(&app, system, Some(token(APP)), &activity).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["accepted"], 0);
        assert_eq!(events(&app, system).await, 1);
    });
}

// feature: C5
#[test]
fn an_unsigned_or_misaddressed_activity_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let system = bot(&app).await;
        let (status, _) = post(&app, system, None, &activity()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = post(&app, system, Some(token("another-bot")), &activity()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let mut elsewhere = activity();
        elsewhere["serviceUrl"] = json!("https://evil.example/");
        let (status, _) = post(&app, system, Some(token(APP)), &elsewhere).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(events(&app, system).await, 0);
    });
}
