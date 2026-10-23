//! R9-T1: the daily policy sweep reminds an owner of a near review once,
//! asks a campaign's role holders who have not acknowledged the policy's
//! current version, and expires approved exceptions past their end; a
//! second run the same day does nothing.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_grc::policy::{PolicySweep, campaign_progress, sweep};
use attome_testapp::TestApp;
use chrono::{Duration, Utc};
use uuid::Uuid;

async fn install(app: &TestApp) {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs/grc/changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in &files {
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

// feature: R9
#[test]
fn sweep_reminds_attests_and_expires_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let db = app.db();
        let today = Utc::now().date_naive();
        let tag = Uuid::now_v7().simple().to_string();

        let policy: Uuid = sqlx::query_scalar(
            "INSERT INTO grc_policy (id, title, owner_id, status, version, review_by, created_by, \
                                     owner_ref, is_active) \
             VALUES ($1, $2, $3, 'active', '2', $4, $3, $3, true) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(format!("Acceptable use {tag}"))
        .bind(app.admin.id)
        .bind(today + Duration::days(5))
        .fetch_one(db)
        .await
        .unwrap();

        let role = Uuid::now_v7();
        sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'customer')")
            .bind(role)
            .bind(format!("Staff {tag}"))
            .execute(db)
            .await
            .unwrap();
        let read = attome_testapp::seed_user(db, "read").await;
        let unread = attome_testapp::seed_user(db, "unread").await;
        for user in [read.id, unread.id] {
            sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)")
                .bind(user)
                .bind(role)
                .execute(db)
                .await
                .unwrap();
        }
        // An acknowledgement of an older version does not count.
        for (user, version) in [(read.id, "2"), (unread.id, "1")] {
            sqlx::query(
                "INSERT INTO grc_policy_ack (id, policy_id, user_id, policy_version, acked_at, \
                                             created_by, owner_ref, is_active) \
                 VALUES ($1, $2, $3, $4, now(), $3, $3, true)",
            )
            .bind(Uuid::now_v7())
            .bind(policy)
            .bind(user)
            .bind(version)
            .execute(db)
            .await
            .unwrap();
        }
        let campaign: Uuid = sqlx::query_scalar(
            "INSERT INTO grc_attestation_campaign (id, name, policy_ref, role_ref, due_on, status, \
                                                   created_by, owner_ref, is_active) \
             VALUES ($1, $2, $3, $4, $5, 'open', $6, $6, true) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(format!("Q4 attestation {tag}"))
        .bind(policy)
        .bind(role)
        .bind(today + Duration::days(10))
        .bind(app.admin.id)
        .fetch_one(db)
        .await
        .unwrap();
        let exception: Uuid = sqlx::query_scalar(
            "INSERT INTO grc_policy_exception (id, name, policy_ref, status, expires_on, \
                                               created_by, owner_ref, is_active) \
             VALUES ($1, $2, $3, 'approved', $4, $5, $5, true) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(format!("Legacy laptop {tag}"))
        .bind(policy)
        .bind(today - Duration::days(1))
        .bind(app.admin.id)
        .fetch_one(db)
        .await
        .unwrap();

        let (done, missing) = campaign_progress(db, campaign).await.expect("progress");
        assert_eq!(done, vec![read.id]);
        assert_eq!(missing, vec![unread.id]);

        let first = sweep(&app.state, today).await.expect("sweep");
        assert!(first.review_reminders >= 1, "{first:?}");
        assert!(first.attestation_requests >= 1, "{first:?}");
        assert!(first.exceptions_expired >= 1, "{first:?}");
        let status: String =
            sqlx::query_scalar("SELECT status::text FROM grc_policy_exception WHERE id = $1")
                .bind(exception)
                .fetch_one(db)
                .await
                .unwrap();
        assert_eq!(status, "expired");
        let reminded: bool = sqlx::query_scalar(
            "SELECT review_reminded_on::date = review_by::date FROM grc_policy WHERE id = $1",
        )
        .bind(policy)
        .fetch_one(db)
        .await
        .unwrap();
        assert!(reminded, "the review is claimed for its date");

        let second = sweep(&app.state, today).await.expect("second sweep");
        assert_eq!(
            second,
            PolicySweep::default(),
            "a second run the same day does nothing"
        );
    });
}
