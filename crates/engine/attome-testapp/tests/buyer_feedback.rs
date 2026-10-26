//! D25-T7: buyer feedback after a close goes only to consented contacts;
//! an interview is a task regarding the review.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_sales::buyer_feedback::{FeedbackMode, SalesBuyerFeedbackBody, request_feedback};
use attome_testapp::TestApp;
use serde_json::Value;
use uuid::Uuid;

const PACKS: [&str; 2] = ["crm", "sales"];

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
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
}

/// A lost deal's review and two buyer contacts with addresses.
async fn review_and_contacts(app: &TestApp) -> (Uuid, [Uuid; 2]) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Buyer Co') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let deal: Uuid = sqlx::query_scalar(
        "INSERT INTO opportunity (name, account_ref, stage, amount, currency, close_date) \
         VALUES ('Lost deal', $1, 'closed_lost', 1000, 'SAR', CURRENT_DATE) RETURNING id",
    )
    .bind(account)
    .fetch_one(app.db())
    .await
    .unwrap();
    let review: Uuid = sqlx::query_scalar(
        "INSERT INTO win_loss_review (opportunity_ref, outcome) VALUES ($1, 'lost') RETURNING id",
    )
    .bind(deal)
    .fetch_one(app.db())
    .await
    .unwrap();
    let mut contacts = [Uuid::nil(); 2];
    for (i, slot) in contacts.iter_mut().enumerate() {
        *slot = sqlx::query_scalar(
            "INSERT INTO contact (full_name, email) VALUES ($1, $2) RETURNING id",
        )
        .bind(format!("Buyer {i}"))
        .bind(format!(
            "buyer{i}-{}@example.invalid",
            Uuid::now_v7().simple()
        ))
        .fetch_one(app.db())
        .await
        .unwrap();
    }
    (review, contacts)
}

// feature: D25
#[test]
fn survey_skips_contacts_without_consent() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let admin = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let (review, contacts) = review_and_contacts(&app).await;

        // Neither contact has consented to surveys: nobody is mailed, and no
        // survey is needed to say so.
        let outcome = request_feedback(
            &app.state,
            &admin,
            review,
            SalesBuyerFeedbackBody {
                mode: FeedbackMode::Survey,
                contact_ids: contacts.to_vec(),
            },
        )
        .await
        .unwrap();
        assert!(outcome.sent.is_empty(), "{outcome:?}");
        assert_eq!(outcome.skipped.len(), 2);
        assert!(outcome.skipped.iter().all(|s| s.reason == "no_consent"));
        assert_eq!(outcome.task_id, None);

        // An interview is a task regarding the review.
        let outcome = request_feedback(
            &app.state,
            &admin,
            review,
            SalesBuyerFeedbackBody {
                mode: FeedbackMode::Interview,
                contact_ids: contacts.to_vec(),
            },
        )
        .await
        .unwrap();
        let task = outcome.task_id.expect("a task");
        let (kind, regarding): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT activity_type, regarding_id FROM activity WHERE id = $1")
                .bind(task)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(kind.as_deref(), Some("task"));
        assert_eq!(regarding, Some(review.to_string()));

        // No contacts at all is refused.
        assert!(
            request_feedback(
                &app.state,
                &admin,
                review,
                SalesBuyerFeedbackBody {
                    mode: FeedbackMode::Survey,
                    contact_ids: Vec::new(),
                },
            )
            .await
            .is_err()
        );
    });
}
