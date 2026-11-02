//! D22-T7: only a manager of the call's owner confirms a score, a finding
//! makes one task however often it is asked, and a rep sees only their own
//! comments on another rep's call.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_callintel::analysis::coach::{
    add_comment, comments, confirm_answer, create_task_from_finding,
};
use attome_testapp::{TestApp, seed_user};
use attome_types::AppError;
use uuid::Uuid;

/// A manager's position above a rep's; returns (manager, rep, peer).
async fn team(app: &TestApp) -> (Uuid, Uuid, Uuid) {
    let manager = seed_user(app.db(), "ci-manager").await.id;
    let rep = seed_user(app.db(), "ci-rep").await.id;
    let peer = seed_user(app.db(), "ci-peer").await.id;
    let top = Uuid::now_v7();
    let below = Uuid::now_v7();
    for (id, name, parent) in [
        (top, "Sales manager", None),
        (below, "Sales rep", Some(top)),
    ] {
        sqlx::query("INSERT INTO position (id, name, parent_position_ref) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(format!("{name} {}", Uuid::now_v7().simple()))
            .bind(parent)
            .execute(app.db())
            .await
            .unwrap();
    }
    for (user, position) in [(manager, top), (rep, below), (peer, below)] {
        sqlx::query(
            "INSERT INTO user_account_mm_position (id, user_ref, position_ref) VALUES ($1, $2, $3)",
        )
        .bind(Uuid::now_v7())
        .bind(user)
        .bind(position)
        .execute(app.db())
        .await
        .unwrap();
    }
    (manager, rep, peer)
}

async fn analysis(app: &TestApp, owner: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO call_analysis (id, activity_id, status, owner_user, is_active, row_version) \
         VALUES ($1, $2, 'done', $3, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7().to_string())
    .bind(owner)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn ctx(app: &TestApp, user: Uuid) -> attome_server::security::SecurityContext {
    attome_security::resolve_uncached(app.db(), user)
        .await
        .unwrap()
}

// feature: D22
#[test]
fn only_manager_confirms_score() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (manager, rep, peer) = team(&app).await;
        let call = analysis(&app, rep).await;
        let answer: Uuid = sqlx::query_scalar(
            "INSERT INTO call_scorecard_answer (id, analysis_ref, question_key, proposed_value, \
                 is_active, row_version) \
             VALUES ($1, $2, 'asked_budget', 'yes', true, 0) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(call)
        .fetch_one(app.db())
        .await
        .unwrap();
        for who in [rep, peer] {
            let refused = confirm_answer(&app.state, &ctx(&app, who).await, answer, "no", 0).await;
            assert!(matches!(refused, Err(AppError::Forbidden)), "{refused:?}");
        }
        confirm_answer(&app.state, &ctx(&app, manager).await, answer, "no", 0)
            .await
            .unwrap();
        let stale = confirm_answer(&app.state, &ctx(&app, manager).await, answer, "yes", 0).await;
        assert!(matches!(stale, Err(AppError::VersionConflict)), "{stale:?}");
        let (value, by): (Option<String>, Option<Uuid>) = sqlx::query_as(
            "SELECT confirmed_value::text, confirmed_by FROM call_scorecard_answer WHERE id = $1",
        )
        .bind(answer)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!((value.as_deref(), by), (Some("no"), Some(manager)));
    });
}

// feature: D22
#[test]
fn task_from_finding_is_created_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let call = analysis(&app, app.admin.id).await;
        let finding: Uuid = sqlx::query_scalar(
            "INSERT INTO call_finding (id, analysis_ref, kind, text, start_ms, is_active, \
                 row_version) \
             VALUES ($1, $2, 'next_step', 'Send the revised quote by Thursday', 120000, true, 0) \
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(call)
        .fetch_one(app.db())
        .await
        .unwrap();
        let admin = ctx(&app, app.admin.id).await;
        let first = create_task_from_finding(&app.state, &admin, finding)
            .await
            .unwrap();
        let again = create_task_from_finding(&app.state, &admin, finding)
            .await
            .unwrap();
        assert_eq!(first, again);
        let tasks: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM activity WHERE subject = 'Send the revised quote by Thursday'",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(tasks, 1);
    });
}

// feature: D22
#[test]
fn comment_hidden_from_other_reps() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (manager, rep, peer) = team(&app).await;
        let call = analysis(&app, rep).await;
        add_comment(
            &app.state,
            &ctx(&app, manager).await,
            call,
            90_000,
            "Ask about budget earlier",
            None,
        )
        .await
        .unwrap();
        // A peer without call_comment.create may not comment on someone else's call.
        let refused = add_comment(
            &app.state,
            &ctx(&app, peer).await,
            call,
            1_000,
            "Nice",
            None,
        )
        .await;
        assert!(matches!(refused, Err(AppError::Forbidden)), "{refused:?}");

        assert_eq!(
            comments(&app.state, &ctx(&app, rep).await, call)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            comments(&app.state, &ctx(&app, manager).await, call)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            comments(&app.state, &ctx(&app, peer).await, call)
                .await
                .unwrap()
                .is_empty(),
            "another rep sees none of it"
        );
    });
}
