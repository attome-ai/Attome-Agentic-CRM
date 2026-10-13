//! Phase 3 money path: `dashboard_widget`'s bespoke duplicate action
//! (`widget_actions.rs`'s `pub` `do_duplicate_widget`) exercised directly
//! against a live database, same shape as `tests/dashboard_crud.rs`. The
//! freeform group/ungroup/align actions were deleted (D-790).
//!
//! R-07 (`document/xrm/module/M26-dashboard/remediation.md`) routed
//! `do_duplicate_widget` through the generic entity engine
//! (`attome_records::entity_crud::create_record_for`), so exercising them here now needs a full `EngineState` + a `SecurityContext`
//! — see `tests/common/mod.rs::test_state`/`admin_ctx`.
//!
//! Requires a live Postgres (`DATABASE_URL`) — skips (loudly) when unset,
//! except under `CI`. Run with `--test-threads=1` (idempotent provisioning
//! DDL shared with the other suites in this crate):
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-dashboard --test widget_actions -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
mod common;

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use uuid::Uuid;

async fn insert_section(db: &DbPool) -> Uuid {
    let dashboard_id = Uuid::now_v7();
    sqlx::query("INSERT INTO attome_dashboard (id, name, dashboard_type) VALUES ($1, $2, 'team')")
        .bind(dashboard_id)
        .bind("Widget Test Dashboard")
        .execute(db)
        .await
        .expect("insert test attome_dashboard row");
    let page_id = Uuid::now_v7();
    sqlx::query("INSERT INTO dashboard_page (id, dashboard_id, name) VALUES ($1, $2, 'Page')")
        .bind(page_id)
        .bind(dashboard_id)
        .execute(db)
        .await
        .expect("insert test dashboard_page row");
    let section_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_section (id, page_id, section_type, layout_mode) \
         VALUES ($1, $2, 'row', 'freeform')",
    )
    .bind(section_id)
    .bind(page_id)
    .execute(db)
    .await
    .expect("insert test dashboard_section row");
    section_id
}

#[allow(clippy::too_many_arguments)]
async fn insert_widget(
    db: &DbPool,
    section_id: Uuid,
    name: &str,
    x: Option<f64>,
    y: Option<f64>,
    width: Option<f64>,
    height: Option<f64>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_widget \
         (id, section_id, widget_type, name, freeform_x, freeform_y, freeform_width, freeform_height) \
         VALUES ($1, $2, 'rich_text', $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(section_id)
    .bind(name)
    .bind(x)
    .bind(y)
    .bind(width)
    .bind(height)
    .execute(db)
    .await
    .expect("insert test dashboard_widget row");
    id
}

async fn widget_row(
    db: &DbPool,
    id: Uuid,
) -> (Uuid, Option<String>, Option<f64>, Option<f64>, i64) {
    sqlx::query_as(
        "SELECT section_id, group_id, freeform_x::double precision, \
                freeform_y::double precision, row_version \
         FROM dashboard_widget WHERE id = $1",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .expect("read dashboard_widget row")
}

/// Number of `entity_change_event` rows recorded for one widget —
/// the R-07 regression this suite pins: before R-07, `duplicate` wrote with
/// hand SQL and never touched this outbox table at all.
async fn change_event_count(db: &DbPool, entity_logicalname: &str, record_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM entity_change_event \
         WHERE entity_logicalname = $1 AND record_id = $2",
    )
    .bind(entity_logicalname)
    .bind(record_id)
    .fetch_one(db)
    .await
    .expect("count entity_change_event rows")
}

#[tokio::test]
async fn duplicate_copies_into_target_section_with_an_offset_position() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state);
    common::seed_once(&state).await;
    let actor = Uuid::now_v7();
    let ctx = common::admin_ctx(actor);

    let section_id = insert_section(db).await;
    let other_section_id = insert_section(db).await;
    let source_id = insert_widget(
        db,
        section_id,
        "Source Widget",
        Some(10.0),
        Some(20.0),
        Some(100.0),
        Some(50.0),
    )
    .await;
    sqlx::query(
        "UPDATE dashboard_widget SET query_id = $1, view_id = $2, query_params = $3 \
         WHERE id = $4",
    )
    .bind("source-query-id")
    .bind("source-view-id")
    .bind(r#"{"filters":[]}"#)
    .bind(source_id)
    .execute(db)
    .await
    .expect("set the source widget's data source before duplicating");

    // Duplicate in place (no target_section_id) stays in the source section.
    let in_place_id =
        attome_dashboard::widget_actions::do_duplicate_widget(&state, &ctx, actor, source_id, None)
            .await
            .expect("duplicate in place");
    let (dup_section, _, dup_x, dup_y, _) = widget_row(db, in_place_id).await;
    assert_eq!(dup_section, section_id);
    assert_eq!(
        dup_x,
        Some(26.0),
        "duplicate must offset x by DUPLICATE_OFFSET"
    );
    assert_eq!(
        dup_y,
        Some(36.0),
        "duplicate must offset y by DUPLICATE_OFFSET"
    );
    let (dup_query_id, dup_view_id, dup_query_params): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT query_id, view_id, query_params FROM dashboard_widget WHERE id = $1",
    )
    .bind(in_place_id)
    .fetch_one(db)
    .await
    .expect("read the duplicated widget's data source columns");
    assert_eq!(
        dup_query_id.as_deref(),
        Some("source-query-id"),
        "duplicate must copy query_id"
    );
    assert_eq!(
        dup_view_id.as_deref(),
        Some("source-view-id"),
        "duplicate must copy view_id"
    );
    assert_eq!(
        dup_query_params.as_deref(),
        Some(r#"{"filters":[]}"#),
        "duplicate must copy query_params"
    );
    assert_eq!(
        change_event_count(db, "dashboard_widget", in_place_id).await,
        1,
        "duplicate must go through the engine's own create path, which writes a change event"
    );

    // "Paste" into a different section.
    let pasted_id = attome_dashboard::widget_actions::do_duplicate_widget(
        &state,
        &ctx,
        actor,
        source_id,
        Some(other_section_id),
    )
    .await
    .expect("duplicate into another section");
    let (pasted_section, _, _, _, _) = widget_row(db, pasted_id).await;
    assert_eq!(pasted_section, other_section_id);
}
