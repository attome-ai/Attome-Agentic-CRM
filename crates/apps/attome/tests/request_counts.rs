//! AA14-T3: SQL statement and Redis command budgets for the key requests:
//! get a record, list 50 records, update a record, global search and sign in.
//!
//! Each request runs through the whole router (authentication included) with
//! the sign-in and search routes mounted, and `attome_testkit::query_counter`
//! counts what its task ran. Every request is measured warm: an earlier
//! request of the same shape, on other data, fills the session and privilege
//! caches first, and the measured one never repeats an earlier request, so no
//! repeat-query cache answers it.
//!
//! The budgets are `request_counts.json`. A count above its budget fails; a
//! count below it is printed, so the change that lowered it also lowers the
//! budget. Raise a budget only on purpose, with the reason in the commit.
//!
//! This binary installs its own global tracing subscriber (the counter);
//! nothing else in it may install one.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod key_requests;

use std::collections::BTreeMap;

use attome_testkit::query_counter::{Calls, count_calls};
use axum::http::{Method, StatusCode};
use key_requests::{App, PASSWORD, fixture, if_match, seed_password_user, start};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct Budget {
    queries: usize,
    redis: usize,
}

fn budgets() -> BTreeMap<String, Budget> {
    serde_json::from_str(include_str!("request_counts.json"))
        .expect("request_counts.json is a map of request name to budget")
}

/// Sends one request inside a counting scope; asserts it succeeded.
async fn measure(
    app: &App,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Calls {
    let ((status, response), calls) = count_calls(app.send(method, path, headers, body)).await;
    assert!(status.is_success(), "{path}: {status} {response}");
    calls
}

async fn update(app: &App, entity: &str, id: Uuid, counted: bool) -> Calls {
    let version = if_match(app, entity, id).await;
    let path = format!("/api/v1/{entity}/{id}");
    let headers = [("if-match", version.as_str())];
    let body = Some(json!({ "title": format!("updated {id}") }));
    if counted {
        measure(app, Method::PATCH, &path, &headers, body).await
    } else {
        let (status, response) = app.send(Method::PATCH, &path, &headers, body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        Calls::default()
    }
}

// feature: AA14
#[test]
fn key_requests_within_their_call_budgets() {
    attome_testkit::query_counter::install();
    attome_testkit::run_shared(async {
        let Some(app) = start().await else {
            return;
        };
        let (child, ids) = fixture(&app).await;
        let email = seed_password_user(&app).await;
        let login = |email: &str| json!({ "email": email, "password": PASSWORD });
        let list = |page_size: i64| json!({ "entity": child, "page_size": page_size });
        let record = |id: Uuid| format!("/api/v1/{child}/{id}");

        let mut measured: BTreeMap<&str, Calls> = BTreeMap::new();

        app.send(Method::GET, &record(ids[1]), &[], None).await;
        measured.insert(
            "record_get",
            measure(&app, Method::GET, &record(ids[0]), &[], None).await,
        );

        app.send(Method::POST, "/api/v1/query/execute", &[], Some(list(10)))
            .await;
        measured.insert(
            "record_list_50",
            measure(
                &app,
                Method::POST,
                "/api/v1/query/execute",
                &[],
                Some(list(50)),
            )
            .await,
        );

        update(&app, &child, ids[2], false).await;
        measured.insert("record_update", update(&app, &child, ids[3], true).await);

        app.send(Method::GET, "/api/v1/search?q=warm", &[], None)
            .await;
        measured.insert(
            "global_search",
            measure(&app, Method::GET, "/api/v1/search?q=counted", &[], None).await,
        );

        app.send(Method::POST, "/api/v1/auth/login", &[], Some(login(&email)))
            .await;
        measured.insert(
            "sign_in",
            measure(
                &app,
                Method::POST,
                "/api/v1/auth/login",
                &[],
                Some(login(&email)),
            )
            .await,
        );

        let budgets = budgets();
        let mut over = Vec::new();
        for (name, calls) in &measured {
            let budget = budgets
                .get(*name)
                .unwrap_or_else(|| panic!("request_counts.json has no budget for {name}"));
            println!(
                "{name}: {} SQL statements (budget {}), {} Redis commands (budget {})",
                calls.queries, budget.queries, calls.redis, budget.redis
            );
            if calls.queries > budget.queries || calls.redis > budget.redis {
                over.push(*name);
            } else if calls.queries < budget.queries || calls.redis < budget.redis {
                println!(
                    "{name} now makes fewer calls: lower its budget in request_counts.json \
                     to {{ \"queries\": {}, \"redis\": {} }} in this change",
                    calls.queries, calls.redis
                );
            }
        }
        assert!(
            over.is_empty(),
            "over their call budgets: {over:?} (counts above; raise a budget only on purpose)"
        );
    });
}
