//! S6-T1: the GraphQL read API answers from the caller's schema, reads
//! through the record engine, and answers errors in GraphQL's shape.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

async fn graphql(app: &TestApp, query: &str) -> Value {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/graphql",
            Some(json!({ "query": query })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

// feature: S6
#[test]
fn graphql_reads_through_the_callers_schema() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (status, schema) = app
            .request(Method::GET, "/api/v1/graphql/schema", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{schema}");
        let sdl = schema["sdl"].as_str().unwrap();
        assert!(sdl.contains("type Query {"), "{sdl}");

        // The first entity in the schema, read as a list.
        let entity = sdl
            .lines()
            .find_map(|l| l.trim().split_once("(id: ID!)").map(|(name, _)| name))
            .expect("an entity the administrator may read")
            .to_owned();
        let answer = graphql(
            &app,
            &format!("{{ page: {entity}_list(first: 2) {{ items {{ id __typename }} next_cursor __typename }} }}"),
        )
        .await;
        assert!(answer.get("errors").is_none(), "{answer}");
        assert!(answer["data"]["page"]["items"].is_array(), "{answer}");
        assert!(
            answer["data"]["page"]["__typename"]
                .as_str()
                .unwrap()
                .ends_with("Page")
        );

        assert_eq!(
            graphql(&app, "{ __typename }").await["data"]["__typename"],
            "Query"
        );
        for (query, needle) in [
            ("{ no_such_entity_x { id } }", "no root field"),
            ("mutation { a }", "not supported"),
            ("{ a", "expected"),
        ] {
            let answer = graphql(&app, query).await;
            assert!(answer["data"].is_null(), "{answer}");
            let message = answer["errors"][0]["message"].as_str().unwrap();
            assert!(message.contains(needle), "{query}: {message}");
        }
        let unknown = graphql(
            &app,
            &format!("{{ {entity}_list {{ items {{ no_such_field_y }} }} }}"),
        )
        .await;
        assert!(
            unknown["errors"][0]["message"]
                .as_str()
                .unwrap()
                .contains("has no field no_such_field_y"),
            "{unknown}"
        );

        // A person with no privileges gets a schema of what they may read,
        // never more than the administrator's.
        let nobody = seed_user(app.db(), "graphql").await;
        let (status, theirs) = app
            .request_as(&nobody.cookie, Method::GET, "/api/v1/graphql/schema", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{theirs}");
        let theirs = theirs["sdl"].as_str().unwrap();
        assert!(theirs.contains("type Query {"), "{theirs}");
        assert!(theirs.len() < sdl.len(), "{theirs}");
    });
}
