//! The key requests' shared fixture (AA14-T3, AA14-T4): the engine system
//! with search and the sign-in routes on the test database, an entity with 60
//! records, and a password account. `request_counts` counts the calls each
//! key request makes; `request_allocs` counts the bytes it allocates.

#![allow(
    dead_code,
    reason = "each test binary that includes this module uses a different part of it"
)]

use std::net::SocketAddr;

use attome::auth;
use attome_api::EngineSystem;
use attome_core::EngineState;
use attome_server::AppState;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

pub const PASSWORD: &str = "request-counts-password-1";

pub struct App {
    pub router: axum::Router,
    pub state: EngineState,
    pub cookie: String,
}

/// The engine system with the search engine, and the sign-in routes, on the
/// test database; `None` when no test database is configured.
pub async fn start() -> Option<App> {
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
    pub async fn send(
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

    pub async fn post(&self, path: &str, body: Value) -> Value {
        let (status, created) = self.send(Method::POST, path, &[], Some(body)).await;
        assert!(status.is_success(), "POST {path}: {status} {created}");
        created
    }
}

/// An entity with a text attribute and a lookup, and 60 records. Returns its
/// name and the record ids.
pub async fn fixture(app: &App) -> (String, Vec<Uuid>) {
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
pub async fn seed_password_user(app: &App) -> String {
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

pub async fn if_match(app: &App, entity: &str, id: Uuid) -> String {
    let (status, current) = app
        .send(Method::GET, &format!("/api/v1/{entity}/{id}"), &[], None)
        .await;
    assert_eq!(status, StatusCode::OK, "{current}");
    format!(
        "\"{}\"",
        current["row_version"].to_string().trim_matches('"')
    )
}
