//! AB11-T6: following the public status. Consent is required, an unconfirmed
//! subscriber gets nothing, the one-click unsubscribe works once, a webhook
//! to a private address is refused, and every public route answers 404
//! while the deployment does not publish its status.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

async fn publish_status(app: &TestApp, on: bool) {
    let (status, body) = app
        .request(
            Method::PUT,
            "/api/v1/admin/settings/ops.status.enabled",
            Some(json!({ "scope": "deployment", "value": on })),
        )
        .await;
    assert!(status.is_success(), "{status}: {body}");
}

async fn subscribe(app: &TestApp, body: serde_json::Value) -> StatusCode {
    app.request_public(
        Method::POST,
        "/api/v1/public/status/subscribe",
        &[("content-type", "application/json")],
        serde_json::to_vec(&body).unwrap(),
    )
    .await
    .0
}

async fn get(app: &TestApp, path: &str) -> StatusCode {
    app.request_public(Method::GET, path, &[], Vec::new())
        .await
        .0
}

async fn subscriber_id(app: &TestApp, address: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM ops_status_subscriber WHERE address = $1")
        .bind(address)
        .fetch_one(app.db())
        .await
        .unwrap()
}

/// A public incident with one update published a second from now.
async fn public_update(app: &TestApp) {
    let incident: Uuid = sqlx::query_scalar(
        "INSERT INTO ops_incident (title_en, audience, state, components, impact, created_by) \
         VALUES ('Payments are slow', 'public', 'investigating', ARRAY['records'], 'major', $1) \
         RETURNING id",
    )
    .bind(app.admin.id)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO ops_incident_update (incident_id, stage, body_en, published_by, published_at) \
         VALUES ($1, 'identified', 'A card network is slow.', $2, now() + interval '1 second')",
    )
    .bind(incident)
    .bind(app.admin.id)
    .execute(app.db())
    .await
    .unwrap();
}

async fn deliveries(app: &TestApp, subscriber: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM ops_status_delivery WHERE subscriber_id = $1")
        .bind(subscriber)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: AB11
// negative: POST /api/v1/public/status/subscribe
#[test]
fn subscribe_needs_consent() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        publish_status(&app, true).await;
        let address = format!("{}@example.com", Uuid::now_v7().simple());
        let without = json!({ "channel": "email", "address": address, "components": [] });
        assert_eq!(
            subscribe(&app, without).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let stored: i64 =
            sqlx::query_scalar("SELECT count(*) FROM ops_status_subscriber WHERE address = $1")
                .bind(&address)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(stored, 0);
        let sms = json!({ "channel": "sms", "address": "+966500000000", "consent": true });
        assert_eq!(subscribe(&app, sms).await, StatusCode::UNPROCESSABLE_ENTITY);
        let with = json!({ "channel": "email", "address": address, "consent": true });
        assert_eq!(subscribe(&app, with).await, StatusCode::ACCEPTED);
    });
}

// feature: AB11
#[test]
fn unconfirmed_subscriber_gets_nothing() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        publish_status(&app, true).await;
        let address = format!("{}@example.com", Uuid::now_v7().simple());
        let body = json!({ "channel": "email", "address": address, "consent": true });
        assert_eq!(subscribe(&app, body).await, StatusCode::ACCEPTED);
        let id = subscriber_id(&app, &address).await;
        public_update(&app).await;
        attome_ops::subscribers::deliver_due(&app.state)
            .await
            .unwrap();
        assert_eq!(deliveries(&app, id).await, 0, "not confirmed yet");

        // Confirm with a token whose hash is the stored one.
        let token = "a-known-confirmation-token";
        sqlx::query(
            "UPDATE ops_status_subscriber \
                SET confirm_token_hash = encode(sha256(convert_to($2, 'UTF8')), 'hex') \
              WHERE id = $1",
        )
        .bind(id)
        .bind(token)
        .execute(app.db())
        .await
        .unwrap();
        let confirm = format!("/api/v1/public/status/confirm?token={token}");
        assert_eq!(get(&app, &confirm).await, StatusCode::OK);
        assert_eq!(
            get(&app, &confirm).await,
            StatusCode::NOT_FOUND,
            "single use"
        );

        public_update(&app).await;
        attome_ops::subscribers::deliver_due(&app.state)
            .await
            .unwrap();
        assert_eq!(deliveries(&app, id).await, 1, "the update after confirming");
        attome_ops::subscribers::deliver_due(&app.state)
            .await
            .unwrap();
        assert_eq!(deliveries(&app, id).await, 1, "once");
    });
}

// feature: AB11
// negative: GET /api/v1/public/status/unsubscribe
#[test]
fn unsubscribe_token_works_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        publish_status(&app, true).await;
        let address = format!("{}@example.com", Uuid::now_v7().simple());
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/ops/status-subscribers",
                Some(json!({ "channel": "email", "address": address, "consent": true })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
        let mac = app
            .state
            .base
            .pepper_ring()
            .hash(&format!("ops-status-unsubscribe:{id}"));
        let token: String = url_encode(&format!("{id}.{mac}"));
        let path = format!("/api/v1/public/status/unsubscribe?token={token}");
        assert_eq!(
            get(
                &app,
                &format!("/api/v1/public/status/unsubscribe?token={id}.forged")
            )
            .await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(get(&app, &path).await, StatusCode::OK);
        assert_eq!(get(&app, &path).await, StatusCode::NOT_FOUND, "works once");
        let ended: bool = sqlx::query_scalar(
            "SELECT unsubscribed_at IS NOT NULL FROM ops_status_subscriber WHERE id = $1",
        )
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(ended);
    });
}

fn url_encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

// feature: AB11
// negative: POST /api/v1/public/status/subscribe
#[test]
fn webhook_to_private_ip_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        publish_status(&app, true).await;
        for address in [
            "https://127.0.0.1/hook",
            "https://169.254.169.254/latest",
            "https://10.0.0.5/hook",
        ] {
            let body = json!({ "channel": "webhook", "address": address, "consent": true });
            assert_eq!(
                subscribe(&app, body).await,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{address}"
            );
        }
    });
}

// feature: AB11
// negative: GET /api/v1/public/status/feed.rss
#[test]
fn public_routes_404_when_disabled() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let body = json!({ "channel": "email", "address": "a@example.com", "consent": true });
        assert_eq!(subscribe(&app, body).await, StatusCode::NOT_FOUND);
        for path in [
            "/api/v1/public/status/confirm?token=x",
            "/api/v1/public/status/unsubscribe?token=x",
            "/api/v1/public/status/feed.rss",
        ] {
            assert_eq!(get(&app, path).await, StatusCode::NOT_FOUND, "{path}");
        }
        publish_status(&app, true).await;
        assert_eq!(
            get(&app, "/api/v1/public/status/feed.rss").await,
            StatusCode::OK
        );
    });
}
