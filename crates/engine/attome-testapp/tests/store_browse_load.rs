//! F8-T13 (load): the guest catalogue under 10,000 requests from 100 clients.
//! Serves the test router on a local port and runs
//! `scripts/load-store-browse.ps1` against it, so the p95 is measured on a
//! throwaway database and never the shared dev server.
//!
//! Run on purpose: `cargo test --release -p attome-testapp --test
//! store_browse_load -- --ignored --nocapture`. Windows PowerShell only.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "a load measurement prints its numbers; a failed setup step should panic"
)]

use std::net::SocketAddr;
use std::process::Command;

use attome_testapp::TestApp;
use axum::http::Method;
use serde_json::{Value, json};
use uuid::Uuid;

const PACKS: [&str; 8] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
    "billing",
    "fulfilment",
];

async fn install(app: &TestApp) {
    for pack in PACKS {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs")
            .join(pack)
            .join("changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

async fn set(app: &TestApp, key: &str, value: Value) {
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/api/v1/admin/settings/{key}"),
            Some(json!({ "scope": "deployment", "value": value })),
        )
        .await;
    assert!(status.is_success(), "{key}: {status} {body}");
}

// feature: F8
#[test]
#[ignore = "load: run on purpose, not with the suite"]
fn guest_catalogue_browse_load() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let account: Uuid =
            sqlx::query_scalar("INSERT INTO account (name) VALUES ('Guests') RETURNING id")
                .fetch_one(app.db())
                .await
                .unwrap();
        set(&app, "commerce.enabled", json!(true)).await;
        set(&app, "commerce.guest_account", json!(account.to_string())).await;
        let keyword = format!("shop{}", &Uuid::now_v7().simple().to_string()[..10]);
        sqlx::query(
            "INSERT INTO webportal (name, keyword, portal_type, is_enabled) \n             VALUES ('Shop', $1, 'authenticated', true)",
        )
        .bind(&keyword)
        .execute(app.db())
        .await
        .unwrap();
        let list: Uuid = sqlx::query_scalar(
            "INSERT INTO price_list (name, currency, is_active_list) VALUES ('Retail', 'SAR', true) \
             RETURNING id",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        for n in 0..50 {
            let product: Uuid = sqlx::query_scalar(
                "INSERT INTO product (name, sku, is_orderable, portal_visible) \
                 VALUES ($1, $2, true, true) RETURNING id",
            )
            .bind(format!("Lamp {n}"))
            .bind(format!("LAMP-{n}"))
            .fetch_one(app.db())
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO price_list_item (price_list_ref, product_ref, price) VALUES ($1, $2, 100)",
            )
            .bind(list)
            .bind(product)
            .execute(app.db())
            .await
            .unwrap();
        }

        let portal = app.portal_router();
        let response = tower::ServiceExt::oneshot(
            portal.clone(),
            axum::http::Request::builder()
                .uri(format!("/{keyword}/api/v1/shop/guest/catalogue"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        println!("probe status={status} bytes={}", body.len());
        assert!(
            status.is_success(),
            "the catalogue must answer before the load"
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = portal;
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../scripts/load-store-browse.ps1");
        let base = format!("http://{addr}");
        let out = tokio::task::spawn_blocking(move || {
            Command::new("powershell")
                .args(["-NoProfile", "-File"])
                .arg(script)
                .args(["-BaseUrl", &base, "-Keyword", &keyword])
                .output()
                .expect("powershell runs")
        })
        .await
        .unwrap();
        println!("{}", String::from_utf8_lossy(&out.stdout));
        println!("{}", String::from_utf8_lossy(&out.stderr));
        println!("script_exit={:?}", out.status.code());
    });
}
