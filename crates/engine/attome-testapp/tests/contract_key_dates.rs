//! W1-T4: the contract key-date run, twice in one night, creates each
//! renewal task, reminder, escalation and next occurrence once.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_contract::dates::{self, KeyDateRun, KeyDateSettings};
use attome_testapp::TestApp;
use chrono::NaiveDate;
use uuid::Uuid;

async fn install(app: &TestApp, pack: &str) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs")
        .join(pack)
        .join("changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in &files {
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(file).expect("read"))
                .expect("pack changeset JSON");
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

fn day(m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, m, d).expect("date")
}

async fn obligation(
    app: &TestApp,
    contract: Uuid,
    owner: Uuid,
    title: &str,
    due: NaiveDate,
    complete: bool,
    rule: Option<&str>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO obligation (title, contract_ref, owner_ref, due_date, is_complete, \
         recurrence_rule) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(title)
    .bind(contract)
    .bind(owner)
    .bind(due)
    .bind(complete)
    .bind(rule)
    .fetch_one(app.db())
    .await
    .expect("insert obligation")
}

#[test]
fn key_dates_run_once_per_night() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        for pack in ["crm", "vendor-supplier", "contract-management"] {
            install(&app, pack).await;
        }
        let owner = attome_testapp::seed_user(app.db(), "contract-owner")
            .await
            .id;
        let obligation_owner = attome_testapp::seed_user(app.db(), "obligation-owner")
            .await
            .id;
        let today = day(6, 1);

        // Ends 30 June with 10 days' notice; an approved amendment
        // (W1-T11) effective last week moves the end to 10 July, so the
        // deadline is 30 June and the renewal task opens 30 days before it.
        // A second amendment, effective next month, waits.
        let contract: Uuid = sqlx::query_scalar(
            "INSERT INTO contract (title, status, end_date, notice_period_days, owner_ref) \
             VALUES ('Key dates test', 'active', $1, 10, $2) RETURNING id",
        )
        .bind(day(6, 30))
        .bind(owner)
        .fetch_one(app.db())
        .await
        .expect("insert contract");
        let soon = obligation(
            &app,
            contract,
            obligation_owner,
            "Quarterly report",
            day(6, 3),
            false,
            None,
        )
        .await;
        let late = obligation(
            &app,
            contract,
            obligation_owner,
            "Insurance proof",
            day(5, 20),
            false,
            None,
        )
        .await;
        let done = obligation(
            &app,
            contract,
            obligation_owner,
            "Monthly fee",
            day(5, 31),
            true,
            Some("monthly"),
        )
        .await;

        for (effective, terms) in [
            (day(5, 25), r#"{"end_date":"2026-07-10","payment_days":45}"#),
            (day(7, 1), r#"{"payment_days":60}"#),
        ] {
            sqlx::query(
                "INSERT INTO amendment (title, contract_ref, effective_date, changed_terms, status) \
                 VALUES ('Extension', $1, $2, $3, 'approved')",
            )
            .bind(contract)
            .bind(effective)
            .bind(terms)
            .execute(app.db())
            .await
            .expect("insert amendment");
        }

        let cfg = &app.state.base.config.notification;
        let first = dates::run(app.db(), cfg, KeyDateSettings::default(), today)
            .await
            .expect("first run");
        assert_eq!(
            first.amendments_applied, 1,
            "only the amendment already in effect"
        );
        assert!(first.deadlines_written >= 1);
        assert_eq!(first.renewal_tasks, 1, "renewal_task_created_once");
        assert!(first.reminders >= 1, "obligation_reminded_once");
        assert!(first.escalations >= 1, "overdue_escalates_once");
        assert!(
            first.rolled_forward >= 1,
            "recurring_obligation_rolls_forward"
        );

        let second = dates::run(app.db(), cfg, KeyDateSettings::default(), today)
            .await
            .expect("second run");
        assert_eq!(second, KeyDateRun::default(), "the second run does nothing");

        let deadline: Option<NaiveDate> =
            sqlx::query_scalar("SELECT notice_deadline::date FROM contract WHERE id = $1")
                .bind(contract)
                .fetch_one(app.db())
                .await
                .expect("read deadline");
        assert_eq!(
            deadline,
            Some(day(6, 30)),
            "10 days before the amended end date"
        );
        let (terms, end): (Option<String>, Option<NaiveDate>) =
            sqlx::query_as("SELECT current_terms, end_date::date FROM contract WHERE id = $1")
                .bind(contract)
                .fetch_one(app.db())
                .await
                .expect("read terms");
        assert_eq!(end, Some(day(7, 10)));
        let terms: serde_json::Value =
            serde_json::from_str(terms.as_deref().unwrap_or("{}")).expect("terms JSON");
        assert_eq!(terms["payment_days"], 45);
        let tasks: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM activity WHERE entity_name = 'contract' AND record_id = $1 \
             AND activity_type = 'task' AND subject = $2",
        )
        .bind(contract.to_string())
        .bind(dates::RENEWAL_TASK_SUBJECT)
        .fetch_one(app.db())
        .await
        .expect("count tasks");
        assert_eq!(tasks, 1);

        let reminded: Option<NaiveDate> =
            sqlx::query_scalar("SELECT last_reminded_on::date FROM obligation WHERE id = $1")
                .bind(soon)
                .fetch_one(app.db())
                .await
                .expect("read reminder");
        assert_eq!(reminded, Some(today));
        let escalated: Option<NaiveDate> =
            sqlx::query_scalar("SELECT escalated_on::date FROM obligation WHERE id = $1")
                .bind(late)
                .fetch_one(app.db())
                .await
                .expect("read escalation");
        assert_eq!(escalated, Some(today));

        let old_rule: Option<String> =
            sqlx::query_scalar("SELECT recurrence_rule FROM obligation WHERE id = $1")
                .bind(done)
                .fetch_one(app.db())
                .await
                .expect("read old rule");
        assert_eq!(old_rule, None, "the rule moved to the next occurrence");
        let next: Vec<(NaiveDate, Option<String>, Option<bool>)> = sqlx::query_as(
            "SELECT due_date::date, recurrence_rule, is_complete FROM obligation \
             WHERE contract_ref = $1 AND title = 'Monthly fee' AND id <> $2",
        )
        .bind(contract)
        .bind(done)
        .fetch_all(app.db())
        .await
        .expect("read next occurrence");
        assert_eq!(
            next,
            vec![(day(6, 30), Some("monthly".to_owned()), Some(false))]
        );
    });
}
