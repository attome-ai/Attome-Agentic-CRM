//! AH3-T2: an account's principal kind is set once (migration 0389), and an
//! agent principal row names its account and sponsor (migration 0390).

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use uuid::Uuid;

// feature: AH3
#[test]
fn a_principal_kind_never_changes() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let person = seed_user(app.db(), "pk-person").await;
        let kind: i16 = sqlx::query_scalar("SELECT principal_kind FROM user_account WHERE id = $1")
            .bind(person.id)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(kind, 0, "an existing account is a person");

        let changed = sqlx::query("UPDATE user_account SET principal_kind = 2 WHERE id = $1")
            .bind(person.id)
            .execute(app.db())
            .await;
        let error = changed.expect_err("the kind is immutable");
        assert!(
            error.to_string().contains("principal kind never changes"),
            "{error}"
        );
        // Other columns still update.
        sqlx::query("UPDATE user_account SET user_name = 'renamed' WHERE id = $1")
            .bind(person.id)
            .execute(app.db())
            .await
            .unwrap();

        // An agent is made with its kind and gets its principal row.
        let agent: Uuid = sqlx::query_scalar(
            "INSERT INTO user_account (email, user_name, principal_kind) \
             VALUES ($1, 'agent', 2) RETURNING id",
        )
        .bind(format!("agent-{}@agents.invalid", Uuid::now_v7().simple()))
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_principal (user_ref, sponsor_user_ref, created_by) VALUES ($1, $2, $2)",
        )
        .bind(agent)
        .bind(person.id)
        .execute(app.db())
        .await
        .unwrap();
        let state: String =
            sqlx::query_scalar("SELECT lifecycle_state FROM agent_principal WHERE user_ref = $1")
                .bind(agent)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(state, "active");
        let bad =
            sqlx::query("UPDATE agent_principal SET lifecycle_state = 'gone' WHERE user_ref = $1")
                .bind(agent)
                .execute(app.db())
                .await;
        assert!(bad.is_err(), "lifecycle states are a closed set");
        let out_of_range =
            sqlx::query("INSERT INTO user_account (email, principal_kind) VALUES ($1, 3)")
                .bind(format!("x-{}@agents.invalid", Uuid::now_v7().simple()))
                .execute(app.db())
                .await;
        assert!(out_of_range.is_err(), "kinds are 0, 1 and 2");
    });
}
