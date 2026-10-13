//! D-435 (M34 AI Governance), simplified by D-491, money-path tests,
//! exercised directly against `attome_ai::model_registry`/`compliance_report` —
//! same test shape as `attome-dashboard/tests/metric.rs` exercising
//! `metric.rs`'s functions directly rather than standing up a full
//! authenticated HTTP request. Also covers `comparison_report.rs` (M96
//! Phase 1) — the DB-backed grouping and filtering behaviour that the
//! module's own `#[cfg(test)]` unit tests (pure Wilson-interval math, no DB)
//! do not exercise.
//!
//! Requires a live Postgres (`DATABASE_URL`) with migration `0118`
//! (`ai_suggestion_outcome`) applied — skips (loudly) when `DATABASE_URL`
//! is unset, except under `CI`, per the P1.8 testing-baseline convention.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-ai --test ai_governance -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// D-491 removed `ai_model_approval` — `model_registry::require_approved_model`
/// now reads `approval_status` straight off `ai_model` (the AI Model
/// catalog, `platform-bundles/attome-ai-model-catalog.json`). This fixture
/// provisions only the two columns the gate and the compliance report
/// actually read (`provider_model_id`, `approval_status`), not the full
/// catalog schema (`provider_ref`, `model_type`, cost fields, …) — those
/// carry their own lookup dependencies (`ai_provider`, in turn
/// `authentication_type`) this suite has no need to stand up, same
/// "bypass the full schema, provision only what the gate reads" posture the
/// old `model_registry_seed.rs` documented for the entity it used to own.
async fn seed_once(db: &DbPool) {
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    let entity_id =
        attome_metadata::provision::ensure_entity(db, "ai_model", "AI Model", Some("name"), false)
            .await
            .expect("ensure_entity ai_model");
    attome_metadata::provision::ensure_attribute(
        db, entity_id, "name", "Name", "text", true, false, true, true, None, None,
    )
    .await
    .expect("ensure_attribute name");
    attome_metadata::provision::ensure_attribute(
        db,
        entity_id,
        "provider_model_id",
        "Provider Model ID",
        "text",
        true,
        false,
        true,
        true,
        None,
        None,
    )
    .await
    .expect("ensure_attribute provider_model_id");
    attome_metadata::provision::ensure_attribute(
        db,
        entity_id,
        "approval_status",
        "Approval Status",
        "choice",
        true,
        false,
        true,
        true,
        None,
        Some(serde_json::json!({ "choices": ["pending", "approved", "blocked"], "multi": false })),
    )
    .await
    .expect("ensure_attribute approval_status");
}

/// Bypasses the generic entity engine's own validation — this suite tests
/// `model_registry.rs`'s gate logic directly, not entity CRUD, same reason
/// `attome-dashboard/tests/metric.rs::insert_manual_metric` inserts a bare row.
async fn insert_model(db: &DbPool, provider_model_id: &str, approval_status: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_model (id, name, provider_model_id, approval_status, created_at) \
         VALUES ($1, $2, $3, $4, NOW())",
    )
    .bind(id)
    .bind(provider_model_id)
    .bind(provider_model_id)
    .bind(approval_status)
    .execute(db)
    .await
    .expect("insert ai_model row");
    id
}

async fn insert_outcome(
    db: &DbPool,
    model_id: &str,
    prompt_version: &str,
    action_id: &str,
    outcome: &str,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_suggestion_outcome \
            (id, model_id, prompt_version, action_id, entity_logicalname, outcome, decided_at) \
         VALUES ($1, $2, $3, $4, 'account', $5, \
                 CASE WHEN $5 = 'pending' THEN NULL ELSE NOW() END)",
    )
    .bind(id)
    .bind(model_id)
    .bind(prompt_version)
    .bind(action_id)
    .bind(outcome)
    .execute(db)
    .await
    .expect("insert ai_suggestion_outcome row");
    id
}

// ── model_registry::require_approved_model ─────────────────────────────────

#[tokio::test]
async fn an_unregistered_model_is_refused() {
    let db = attome_testkit::skip_if_no_db!(test_db().await);
    seed_once(&db).await;

    let model_id = format!("no-such-model-{}", Uuid::now_v7());
    let result =
        attome_ai::model_registry::require_approved_model(&db, &model_id, "record.summarize").await;
    assert!(
        matches!(result, Err(attome_types::AppError::NotFound)),
        "an unregistered model_id must be refused"
    );
}

#[tokio::test]
async fn a_pending_catalog_row_is_refused() {
    let db = attome_testkit::skip_if_no_db!(test_db().await);
    seed_once(&db).await;

    // `pending` is the safe default (D-491) — a freshly registered catalog
    // row must not be usable until an admin explicitly flips it to
    // `approved`.
    let model_id = format!("pending-model-{}", Uuid::now_v7());
    insert_model(&db, &model_id, "pending").await;

    let result =
        attome_ai::model_registry::require_approved_model(&db, &model_id, "record.summarize").await;
    assert!(
        matches!(result, Err(attome_types::AppError::NotFound)),
        "approval_status = 'pending' must refuse"
    );
}

#[tokio::test]
async fn a_blocked_catalog_row_is_refused() {
    let db = attome_testkit::skip_if_no_db!(test_db().await);
    seed_once(&db).await;

    let model_id = format!("blocked-model-{}", Uuid::now_v7());
    insert_model(&db, &model_id, "blocked").await;

    let result =
        attome_ai::model_registry::require_approved_model(&db, &model_id, "record.summarize").await;
    assert!(
        matches!(result, Err(attome_types::AppError::NotFound)),
        "approval_status = 'blocked' must refuse"
    );
}

#[tokio::test]
async fn an_approved_catalog_row_is_accepted() {
    let db = attome_testkit::skip_if_no_db!(test_db().await);
    seed_once(&db).await;

    let model_id = format!("approved-model-{}", Uuid::now_v7());
    insert_model(&db, &model_id, "approved").await;

    let result =
        attome_ai::model_registry::require_approved_model(&db, &model_id, "record.summarize").await;
    assert!(
        result.is_ok(),
        "an approved catalog row must be accepted: {result:?}"
    );
}

// ── compliance_report: outcomes_without_provenance ──────────────────────────

#[tokio::test]
async fn outcomes_without_provenance_is_zero_on_a_healthy_fixture() {
    let db = attome_testkit::skip_if_no_db!(test_db().await);
    seed_once(&db).await;

    // A healthy fixture: every row carries real provenance, the same shape
    // `telemetry::record_suggestion` always writes.
    let model_id = format!("healthy-model-{}", Uuid::now_v7());
    insert_outcome(
        &db,
        &model_id,
        "record.summarize/v1",
        "record.summarize",
        "accepted",
    )
    .await;
    insert_outcome(
        &db,
        &model_id,
        "record.summarize/v1",
        "record.summarize",
        "rejected",
    )
    .await;
    insert_outcome(
        &db,
        &model_id,
        "article.draft/v1",
        "article.draft",
        "pending",
    )
    .await;

    let report = attome_ai::compliance_report::build_report(&db)
        .await
        .expect("build_report");
    assert_eq!(
        report.outcomes_without_provenance, 0,
        "a healthy fixture must report zero outcomes without provenance"
    );

    let row = report
        .models
        .iter()
        .find(|m| m.model_id == model_id)
        .expect("the healthy model must appear in the report");
    assert!(row.in_use);
    assert_eq!(row.total_suggestions, 3);
}

#[tokio::test]
async fn outcomes_without_provenance_is_nonzero_after_injecting_a_bad_row() {
    let db = attome_testkit::skip_if_no_db!(test_db().await);
    seed_once(&db).await;

    // The before count, from whatever this database already holds (this
    // suite may share a database with the healthy-fixture test above under
    // `--test-threads=1`) — the assertion is about the DELTA this bad row
    // causes, not an absolute zero, so the two tests cannot interfere.
    let before = attome_ai::compliance_report::build_report(&db)
        .await
        .expect("build_report")
        .outcomes_without_provenance;

    // Bypasses the application entirely — a hand-run INSERT against a
    // throwaway test database, the sanctioned exemption `/xrm-api-first`
    // documents for exactly this: proving a detector fires. `model_id = ''`
    // satisfies the `NOT NULL` constraint while still carrying no real
    // provenance.
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_suggestion_outcome \
            (id, model_id, prompt_version, action_id, entity_logicalname, outcome, decided_at) \
         VALUES ($1, '', 'record.summarize/v1', 'record.summarize', 'account', 'accepted', NOW())",
    )
    .bind(id)
    .execute(&db)
    .await
    .expect("insert a provenance-less row directly");

    let after = attome_ai::compliance_report::build_report(&db)
        .await
        .expect("build_report")
        .outcomes_without_provenance;

    assert_eq!(
        after,
        before + 1,
        "injecting one bad row must move the count by exactly one"
    );
    assert!(
        after > 0,
        "the compliance check must detect the injected bad row"
    );
}

// ── comparison_report: M96 Phase 1 grouping + filtering over the ledger ────

#[tokio::test]
async fn comparison_report_groups_champion_and_challenger_as_separate_rows() {
    let db = attome_testkit::skip_if_no_db!(test_db().await);
    seed_once(&db).await;

    // A unique model_id isolates this test's rows from any other test or
    // session sharing this database (same reasoning `insert_model`'s callers
    // already use above).
    let model_id = format!("cmp-model-{}", Uuid::now_v7());

    // Champion: v1, 9 accepted / 1 rejected.
    for _ in 0..9 {
        insert_outcome(
            &db,
            &model_id,
            "record.summarize/v1",
            "record.summarize",
            "accepted",
        )
        .await;
    }
    insert_outcome(
        &db,
        &model_id,
        "record.summarize/v1",
        "record.summarize",
        "rejected",
    )
    .await;

    // Challenger: v2, 4 accepted / 6 rejected.
    for _ in 0..4 {
        insert_outcome(
            &db,
            &model_id,
            "record.summarize/v2",
            "record.summarize",
            "accepted",
        )
        .await;
    }
    for _ in 0..6 {
        insert_outcome(
            &db,
            &model_id,
            "record.summarize/v2",
            "record.summarize",
            "rejected",
        )
        .await;
    }

    // A row for a DIFFERENT action must not leak into this action's filter.
    insert_outcome(
        &db,
        &model_id,
        "article.draft/v1",
        "article.draft",
        "accepted",
    )
    .await;

    let filter = attome_ai::comparison_report::ComparisonFilter {
        action: Some("record.summarize".to_string()),
        model_id: Some(model_id.clone()),
        prompt_version: None,
    };
    let report = attome_ai::comparison_report::build_report(&db, &filter)
        .await
        .expect("build_report");

    assert_eq!(
        report.groups.len(),
        2,
        "champion and challenger must appear as two distinct rows: {:?}",
        report.groups
    );

    let champion = report
        .groups
        .iter()
        .find(|g| g.prompt_version == "record.summarize/v1")
        .expect("champion row");
    assert_eq!(champion.total_decided, 10);
    assert_eq!(champion.accepted, 9);
    assert_eq!(champion.accepted_rate, Some(0.9));
    let champion_ci = champion.accepted_ci.expect("champion must have a CI");
    assert!(champion_ci.lower <= 0.9 && champion_ci.upper >= 0.9);

    let challenger = report
        .groups
        .iter()
        .find(|g| g.prompt_version == "record.summarize/v2")
        .expect("challenger row");
    assert_eq!(challenger.total_decided, 10);
    assert_eq!(challenger.accepted, 4);
    assert_eq!(challenger.accepted_rate, Some(0.4));
    assert!(
        challenger.accepted_rate.unwrap() < champion.accepted_rate.unwrap(),
        "the challenger's lower acceptance rate must be visible in the same report"
    );

    // Narrowing the filter with prompt_version returns exactly the one row.
    let narrow = attome_ai::comparison_report::ComparisonFilter {
        action: Some("record.summarize".to_string()),
        model_id: Some(model_id),
        prompt_version: Some("record.summarize/v1".to_string()),
    };
    let narrow_report = attome_ai::comparison_report::build_report(&db, &narrow)
        .await
        .expect("build_report narrow");
    assert_eq!(narrow_report.groups.len(), 1);
    assert_eq!(
        narrow_report.groups[0].prompt_version,
        "record.summarize/v1"
    );
}
