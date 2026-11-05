//! Y3-T1: the SQL gateway end to end, through a real PostgreSQL client
//! (sqlx's simple-query protocol, as `psql` sends). An API key signs in as
//! user name and secret; a wrong secret and a key whose user lacks
//! `attome_report.author_sql` are refused; an author reads entities as
//! tables (simple and extended protocol), sees only rows and fields they may read, cannot reach a
//! platform table, and every query leaves an audit event without its text.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::net::SocketAddr;

use attome_sqlgateway::{EVENT, GatewayConfig, PRIVILEGE};
use attome_testapp::{TestApp, seed_user};
use axum::http::Method;
use serde_json::json;
use sqlx::{Connection, Executor, Row};
use uuid::Uuid;

/// A key for `user`: (public part, secret).
async fn mint_key(app: &TestApp, user: Uuid) -> (String, String) {
    let public_key = format!("atk_pub_gw{}", Uuid::now_v7().simple());
    let secret = format!("atk_sec_gw{}", Uuid::now_v7().simple());
    let secret_hash = app.state.base.pepper_ring().hash(&secret);
    sqlx::query(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash) VALUES ($1, $2, $3, $4)",
    )
    .bind(user)
    .bind(format!("gateway-{}", Uuid::now_v7()))
    .bind(&public_key)
    .bind(&secret_hash)
    .execute(app.db())
    .await
    .expect("insert the key");
    (public_key, secret)
}

async fn grant(app: &TestApp, user: Uuid, key: &str) {
    attome_security::db::ensure_privilege(
        app.db(),
        key,
        key,
        "test grant",
        attome_core::changeset::Layer::Project,
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT uuidv7(), $1, id, true, now() FROM privilege WHERE key = $2",
    )
    .bind(user)
    .bind(key)
    .execute(app.db())
    .await
    .unwrap();
    app.state.base.security.invalidate(user).await;
}

async fn connect(addr: SocketAddr, user: &str, password: &str) -> Result<sqlx::PgConnection, sqlx::Error> {
    sqlx::PgConnection::connect(&format!(
        "postgres://{user}:{password}@{addr}/attome?sslmode=disable"
    ))
    .await
}

// feature: Y3
#[test]
fn bi_clients_read_only_what_their_user_may() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        app.install_packs(&["crm"]).await;
        let addr = attome_sqlgateway::start(
            app.state.clone(),
            GatewayConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                max_connections: 4,
            },
        )
        .await
        .expect("bind the gateway");

        let marker = format!("Gateway Co {}", Uuid::now_v7().simple());
        let (status, body) = app
            .request(Method::POST, "/api/v1/account", Some(json!({ "name": marker })))
            .await;
        assert!(status.is_success(), "{status}: {body}");

        // A wrong secret, and a key whose user may not author SQL.
        let (admin_key, admin_secret) = mint_key(&app, app.admin.id).await;
        assert!(connect(addr, &admin_key, "not-the-secret").await.is_err());
        let analyst = seed_user(app.db(), "gw-analyst").await;
        let (analyst_key, analyst_secret) = mint_key(&app, analyst.id).await;
        let refused = connect(addr, &analyst_key, &analyst_secret).await;
        assert!(refused.is_err(), "no {PRIVILEGE}: refused at sign-in");

        // The administrator reads the account as a table.
        let mut admin = connect(addr, &admin_key, &admin_secret).await.expect("sign in");
        let rows = admin
            .fetch_all(format!("SELECT name FROM account WHERE name = '{marker}'").as_str())
            .await
            .expect("query the account");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].try_get::<String, _>(0).unwrap(), marker);
        // The extended protocol (prepare, describe, execute), as JDBC and
        // ODBC drivers send by default; a bound parameter is refused.
        let prepared = sqlx::query(&format!("SELECT name FROM account WHERE name = '{marker}'"))
            .fetch_all(&mut admin)
            .await
            .expect("an extended-protocol query");
        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].try_get::<String, _>("name").unwrap(), marker);
        let bound = sqlx::query("SELECT name FROM account WHERE name = $1")
            .bind(&marker)
            .fetch_all(&mut admin)
            .await;
        assert!(bound.is_err(), "bound parameters are not taken yet");
        // A platform table that is no entity view stays out of reach.
        assert!(admin.fetch_all("SELECT secret_hash FROM api_key").await.is_err());
        admin.close().await.ok();

        // An author with no read on accounts sees no account view.
        grant(&app, analyst.id, PRIVILEGE).await;
        let mut analyst_conn = connect(addr, &analyst_key, &analyst_secret)
            .await
            .expect("an author signs in");
        assert!(
            analyst_conn.fetch_all("SELECT name FROM account").await.is_err(),
            "no account.read: no account view"
        );
        let one = analyst_conn.fetch_one("SELECT 1 AS n").await.expect("a plain select");
        assert_eq!(one.try_get::<String, _>("n").unwrap(), "1");
        analyst_conn.close().await.ok();

        // Every query is audited, by fingerprint, never by text.
        let (events, leaked): (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE payload->>'event_name' = $1), \
                    count(*) FILTER (WHERE payload::text LIKE '%' || $2 || '%') \
               FROM audit_ingest",
        )
        .bind(EVENT)
        .bind(&marker)
        .fetch_one(app.db())
        .await
        .expect("count gateway events");
        assert!(events >= 5, "one event per query: {events}");
        assert_eq!(leaked, 0, "the SQL text is never in the audit trail");
    });
}
