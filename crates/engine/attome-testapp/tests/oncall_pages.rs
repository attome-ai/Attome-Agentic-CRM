//! H7-T2: a stored page is listed for the paged person, who acknowledges it
//! once; nobody else sees or acknowledges it.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use uuid::Uuid;

// feature: H7
#[test]
fn the_paged_person_acknowledges_their_page_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let paged = attome_testapp::seed_user(app.db(), "oncall-paged").await;
        let other = attome_testapp::seed_user(app.db(), "oncall-other").await;
        let page: Uuid = sqlx::query_scalar(
            "INSERT INTO oncall_page (ticket_ref, user_ref, subject) VALUES ($1, $2, 'Major incident: payments down') RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(paged.id)
        .fetch_one(app.db())
        .await
        .unwrap();

        let (code, mine) = app
            .request_as(
                &paged.cookie,
                Method::GET,
                "/api/v1/service/oncall/pages",
                None,
            )
            .await;
        assert_eq!(code, StatusCode::OK, "{mine}");
        assert_eq!(mine["items"][0]["id"], page.to_string(), "{mine}");
        assert!(mine["items"][0]["acknowledged_at"].is_null());

        let ack = format!("/api/v1/service/oncall/pages/{page}/acknowledge");
        let (code, _) = app
            .request_as(&other.cookie, Method::POST, &ack, None)
            .await;
        assert_eq!(code, StatusCode::NOT_FOUND, "not someone else's page");
        let (code, first) = app
            .request_as(&paged.cookie, Method::POST, &ack, None)
            .await;
        assert_eq!(code, StatusCode::OK, "{first}");
        assert!(first["acknowledged_at"].is_string(), "{first}");
        let (code, again) = app
            .request_as(&paged.cookie, Method::POST, &ack, None)
            .await;
        assert_eq!(code, StatusCode::OK, "{again}");
        assert_eq!(again["acknowledged_at"], first["acknowledged_at"]);

        let (_, theirs) = app
            .request_as(
                &other.cookie,
                Method::GET,
                "/api/v1/service/oncall/pages",
                None,
            )
            .await;
        assert_eq!(theirs["total"], 0, "{theirs}");
    });
}
