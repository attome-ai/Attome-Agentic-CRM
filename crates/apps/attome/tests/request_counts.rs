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

use std::collections::BTreeMap;
use std::net::SocketAddr;

use attome::auth;
use attome_api::EngineSystem;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::query_counter::{Calls, count_calls};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const PASSWORD: &str = "request-counts-password-1";

#[derive(Debug, Deserialize)]
struct Budget {
    queries: usize,
    redis: usize,
}

fn budgets() -> BTreeMap<String, Budget> {
    serde_json::from_str(include_str!("request_counts.json"))
        .expect("request_counts.json is a map of request name to budget")
}

struct App {
    router: axum::Router,
    state: EngineState,
    cookie: String,
}

/// The engine system with the search engine, and the sign-in routes, on the
/// test database; `None` when no test database is configured.
async fn start() -> Option<App> {
    attome_testkit::migrated_db_url()?;
    let config = attome_testapp::test_config();
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect the test database");
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("connect the test Redis");
    let coordination = attome_cache::create_role_redis_pool(
        &config,
        attome_cache::CacheRole::Coordination,
        &redis,
    )
    .await
    .expect("connect the coordination Redis");
    let storage = attome_storage::create_storage_client(&config)
        .await
        .expect("build the storage client");
    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db,
        redis,
        coordination,
        storage,
    );
    let system = EngineSystem::builder(EngineState::new(base))
        .register(attome_security::model::SecurityModel)
        .register(attome_search::SearchModel)
        .build()
        .await
        .expect("build the engine system");
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
    let state = system.state().clone();
    let base_state = state.base.clone();
    let auth_bundle = attome_server::RouteBundle::new(
        auth::public_routes(
            state.modules.clone(),
            attome_audit::security::SecurityAuditor::from_state(&state),
        )
        .with_state(base_state.clone()),
    );
    let router =
        attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
            .add_bundle(system.core_routes())
            .add_bundle(auth_bundle)
            .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
    let admin = attome_testapp::seed_admin(&state.base.db).await;
    Some(App {
        router,
        state,
        cookie: admin.cookie,
    })
}

impl App {
    /// One request as the administrator, from a fixed peer address.
    async fn send(
        &self,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("cookie", self.cookie.as_str())
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let body = match body {
            Some(value) => {
                builder = builder.header("content-type", "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let mut request = builder.body(body).expect("a well-formed request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 7], 40_007))));
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read the response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn post(&self, path: &str, body: Value) -> Value {
        let (status, created) = self.send(Method::POST, path, &[], Some(body)).await;
        assert!(status.is_success(), "POST {path}: {status} {created}");
        created
    }
}

/// An entity with a text attribute and a lookup, and 60 records. Returns its
/// name and the record ids.
async fn fixture(app: &App) -> (String, Vec<Uuid>) {
    let token = Uuid::now_v7().simple().to_string();
    let target = format!("rc_target_{}", &token[..12]);
    let child = format!("rc_child_{}", &token[..12]);
    let target_id = app
        .post(
            "/api/v1/admin/entities",
            json!({ "logicalname": target, "name": target }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    app.post(
        &format!("/api/v1/admin/entities/{target_id}/fields"),
        json!({ "logicalname": "name", "name": "name", "field_type": "text" }),
    )
    .await;
    let child_id = app
        .post(
            "/api/v1/admin/entities",
            json!({ "logicalname": child, "name": child }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    app.post(
        &format!("/api/v1/admin/entities/{child_id}/fields"),
        json!({ "logicalname": "title", "name": "title", "field_type": "text" }),
    )
    .await;
    app.post(
        &format!("/api/v1/admin/entities/{child_id}/fields"),
        json!({ "logicalname": "target_ref", "name": "target_ref",
                "field_type": "lookup", "lookup_entity_ref": target_id }),
    )
    .await;
    let registry = attome_core::build_registry(&app.state.base.db)
        .await
        .unwrap();
    app.state.entities.swap(registry);
    let target_record = app
        .post(
            &format!("/api/v1/{target}"),
            json!({ "name": "the target" }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut ids = Vec::new();
    for n in 0..60 {
        let created = app
            .post(
                &format!("/api/v1/{child}"),
                json!({ "title": format!("counted row {n}"), "target_ref": target_record }),
            )
            .await;
        ids.push(created["id"].as_str().unwrap().parse().unwrap());
    }
    (child, ids)
}

/// A password account the sign-in request uses; returns its email.
async fn seed_password_user(app: &App) -> String {
    let id = Uuid::now_v7();
    let email = format!("request-counts-{id}@example.test");
    let hash =
        attome_auth::hash_password_async(attome_auth::NewPassword::platform_generated(PASSWORD))
            .await
            .expect("hash the throwaway password");
    sqlx::query(
        "INSERT INTO user_account \
         (id, user_name, email, password_hash, is_active, email_verified) \
         VALUES ($1, $2, $3, $4, true, true)",
    )
    .bind(id)
    .bind(format!("request-counts-{id}"))
    .bind(&email)
    .bind(hash)
    .execute(&app.state.base.db)
    .await
    .expect("insert the throwaway account");
    email
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

async fn if_match(app: &App, entity: &str, id: Uuid) -> String {
    let (status, current) = app
        .send(Method::GET, &format!("/api/v1/{entity}/{id}"), &[], None)
        .await;
    assert_eq!(status, StatusCode::OK, "{current}");
    format!(
        "\"{}\"",
        current["row_version"].to_string().trim_matches('"')
    )
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
