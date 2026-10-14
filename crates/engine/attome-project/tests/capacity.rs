//! Integration tests for M72's resource capacity aggregate (`capacity.rs`):
//! (1) over-allocation detection — a resource allocated past 100% of the
//! period's capacity must be flagged; (2) permission scoping by team — a
//! caller without access to a team must not be able to query it. Both call
//! the crate's exported functions directly (no HTTP/router layer), same
//! convention `tests/rollup.rs`/`tests/portfolio_program.rs` already use for
//! this crate's other bespoke aggregation endpoints.
//!
//! Requires a live Postgres (`DATABASE_URL`) with the platform's migrations
//! already applied — same convention as the sibling test files. Run
//! manually against a throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-project --test capacity -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use attome_project::capacity::{
    authorize_capacity_scope, base_capacity_hours, fetch_capacity_page,
};
use attome_server::security::AccessLevel;
use attome_server::security::SecurityContext;
use chrono::NaiveDate;
use sqlx::postgres::PgPoolOptions;
use std::collections::{HashMap, HashSet};
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

/// Idempotent — safe at the top of every test, even concurrently against
/// the shared per-binary test database (D-343).
async fn ensure_seeded(db: &DbPool) {
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    attome_project::seed::seed_for_tests(db)
        .await
        .expect("attome_project::seed::seed");
    // Mints "{logicalname}.{action}" privilege rows for every entity just
    // registered, including `resource_allocation.read` — needed by the
    // team-scoping test's role grant below. Same ordering
    // `attome-api/src/system.rs`'s `EngineSystem::build()` uses in production
    // (seed security -> register readonly entities -> attome_project::seed ->
    // entity_privileges::seed_all).
    attome_security::entity_privileges::seed_all(db)
        .await
        .expect("attome_security::entity_privileges::seed_all");
}

async fn resource_allocation_entity_id(db: &DbPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = 'resource_allocation'")
        .fetch_one(db)
        .await
        .expect("resource_allocation entity id")
}

async fn insert_user(db: &DbPool, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(id)
        .bind(format!("{name}-{id}"))
        .execute(db)
        .await
        .expect("insert user_account");
    id
}

async fn insert_allocation(
    db: &DbPool,
    user_id: Uuid,
    percent: f64,
    start: NaiveDate,
    end: NaiveDate,
) {
    sqlx::query(
        "INSERT INTO resource_allocation \
         (id, user_id, regarding_entity, regarding_id, allocation_percent, start_date, end_date) \
         VALUES ($1, $2, 'attome_project', $3, $4, $5, $6)",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(Uuid::now_v7().to_string())
    .bind(percent)
    .bind(start)
    .bind(end)
    .execute(db)
    .await
    .expect("insert resource_allocation");
}

/// A resource allocated 70% to one project and 60% to another, for the
/// whole requested period, totals 130% — past the period's 100% nominal
/// capacity. `fetch_capacity_page` must report `allocated_hours >
/// capacity_hours` for that resource.
#[tokio::test]
async fn over_allocation_detection() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let user_id = insert_user(&db, "capacity-test-overallocated").await;
    let from = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let to = NaiveDate::from_ymd_opt(2026, 9, 7).unwrap(); // Mon-Sun, one week
    insert_allocation(&db, user_id, 70.0, from, to).await;
    insert_allocation(&db, user_id, 60.0, from, to).await;

    let calendar = attome_calendar::BusinessCalendar::simple(
        chrono_tz::UTC,
        HashSet::from([
            chrono::Weekday::Mon,
            chrono::Weekday::Tue,
            chrono::Weekday::Wed,
            chrono::Weekday::Thu,
            chrono::Weekday::Fri,
        ]),
        attome_calendar::TimeRange::new(9 * 60, 17 * 60),
    )
    .expect("a Mon-Fri 9-5 calendar is valid");
    let base_hours = base_capacity_hours(&calendar, from, to).expect("one week of capacity");
    let period_days = ((to - from).num_days() + 1) as f64;

    let rows = fetch_capacity_page(&db, from, to, None, None, base_hours, period_days, 5000, 0)
        .await
        .expect("fetch_capacity_page");

    let row = rows
        .iter()
        .find(|r| r.id == user_id)
        .expect("the seeded resource must appear in the page");
    assert!(
        row.allocated_hours > row.capacity_hours,
        "130% allocation over one week must exceed nominal capacity: \
         allocated={} capacity={}",
        row.allocated_hours,
        row.capacity_hours
    );
    // Sanity: allocated_hours should be materially close to 130% of the
    // nominal (pre-leave) week capacity — not just "nonzero and over".
    let nominal_pct = row.allocated_hours / base_hours * 100.0;
    assert!(
        (125.0..=135.0).contains(&nominal_pct),
        "expected ~130% of nominal capacity, got {nominal_pct}%"
    );
}

/// A resource with zero allocations must never be reported over-allocated.
#[tokio::test]
async fn no_allocation_is_never_over_allocated() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let user_id = insert_user(&db, "capacity-test-idle").await;
    let from = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();
    let to = NaiveDate::from_ymd_opt(2026, 9, 7).unwrap();

    let calendar = attome_calendar::BusinessCalendar::simple(
        chrono_tz::UTC,
        HashSet::from([
            chrono::Weekday::Mon,
            chrono::Weekday::Tue,
            chrono::Weekday::Wed,
            chrono::Weekday::Thu,
            chrono::Weekday::Fri,
        ]),
        attome_calendar::TimeRange::new(9 * 60, 17 * 60),
    )
    .expect("a Mon-Fri 9-5 calendar is valid");
    let base_hours = base_capacity_hours(&calendar, from, to).expect("one week of capacity");
    let period_days = ((to - from).num_days() + 1) as f64;

    let rows = fetch_capacity_page(&db, from, to, None, None, base_hours, period_days, 5000, 0)
        .await
        .expect("fetch_capacity_page");
    let row = rows.iter().find(|r| r.id == user_id).expect("row present");
    assert_eq!(row.allocated_hours, 0.0);
    assert!(row.allocated_hours <= row.capacity_hours);
}

fn ctx(user_id: Uuid, team_ids: &[Uuid]) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: false,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: team_ids.to_vec(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        service_principal: false,
    }
}

async fn insert_team(db: &DbPool, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO team (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("{name}-{id}"))
        .execute(db)
        .await
        .expect("insert team");
    id
}

async fn link_user_to_team(db: &DbPool, user_id: Uuid, team_id: Uuid) {
    sqlx::query("INSERT INTO user_account_mm_team (id, user_ref, team_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(team_id)
        .execute(db)
        .await
        .expect("insert user_account_mm_team");
}

async fn seed_role(db: &DbPool) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO role (id, name, description, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(role_id)
    .bind(format!("test-role-{role_id}"))
    .bind("throwaway test role")
    .execute(db)
    .await
    .expect("insert throwaway role");
    role_id
}

async fn link_user_to_role(db: &DbPool, user_id: Uuid, role_id: Uuid) {
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("insert throwaway user-role link");
}

/// Grants `role_id` a Team-tier (`read_depth = 1`, `AccessLevel::Team`) read
/// grant on `resource_allocation`, reusing the privilege row
/// `entity_privileges::seed_all` already minted in `ensure_seeded`. Same
/// recipe `attome-security/tests/resolver.rs`'s `set_role_entity_depth` uses.
async fn grant_team_tier_resource_allocation_read(db: &DbPool, role_id: Uuid, entity_id: Uuid) {
    let privilege_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM privilege WHERE key = 'resource_allocation.read' AND is_active = true",
    )
    .fetch_one(db)
    .await
    .expect("resource_allocation.read privilege must exist after entity_privileges::seed_all");

    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("insert throwaway role privilege grant");

    sqlx::query(
        "INSERT INTO role_mm_entity_access \
         (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         VALUES ($1, $2, $3, $4, $4, $4, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(entity_id)
    .bind(AccessLevel::Team as i16)
    .execute(db)
    .await
    .expect("insert throwaway role entity-access depth");
}

/// A caller whose only role grants Team-tier `resource_allocation.read`,
/// and who belongs only to `team_a`, must be denied when asking for
/// `team_b`'s capacity — and allowed (scoped to exactly `team_a`) when
/// asking for their own team.
#[tokio::test]
async fn team_scoping_denies_a_caller_without_team_access() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;
    let entity_id = resource_allocation_entity_id(&db).await;

    let user_id = insert_user(&db, "capacity-test-team-scoped-caller").await;
    let team_a = insert_team(&db, "capacity-test-team-a").await;
    let team_b = insert_team(&db, "capacity-test-team-b").await;
    link_user_to_team(&db, user_id, team_a).await;

    let role_id = seed_role(&db).await;
    link_user_to_role(&db, user_id, role_id).await;
    grant_team_tier_resource_allocation_read(&db, role_id, entity_id).await;

    let caller = ctx(user_id, &[team_a]);

    // Denied: team_b is not one of the caller's teams.
    let denied = authorize_capacity_scope(&db, entity_id, &caller, Some(team_b)).await;
    assert!(
        matches!(denied, Err(attome_types::AppError::Forbidden)),
        "expected Forbidden querying a team outside the caller's own teams, got {denied:?}"
    );

    // Allowed: team_a is the caller's own team, scoped to exactly it.
    let allowed = authorize_capacity_scope(&db, entity_id, &caller, Some(team_a))
        .await
        .expect("querying the caller's own team must be allowed");
    assert_eq!(allowed, Some(vec![team_a]));

    // Unfiltered request scopes to the union of the caller's own teams.
    let unfiltered = authorize_capacity_scope(&db, entity_id, &caller, None)
        .await
        .expect("an unfiltered request must be allowed, scoped to the caller's own teams");
    assert_eq!(unfiltered, Some(vec![team_a]));
}

/// A caller holding no grant at all on `resource_allocation` (no role
/// ever links them to a privilege) is forbidden outright, regardless of
/// team membership — `AccessLevel::None` denies before the team check ever
/// runs.
#[tokio::test]
async fn a_caller_with_no_grant_at_all_is_forbidden() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;
    let entity_id = resource_allocation_entity_id(&db).await;

    let user_id = insert_user(&db, "capacity-test-no-grant").await;
    let team_a = insert_team(&db, "capacity-test-no-grant-team").await;
    link_user_to_team(&db, user_id, team_a).await;
    // No role, no privilege grant at all.

    let caller = ctx(user_id, &[team_a]);
    let result = authorize_capacity_scope(&db, entity_id, &caller, Some(team_a)).await;
    assert!(
        matches!(result, Err(attome_types::AppError::Forbidden)),
        "a caller with zero grant on the entity must be forbidden even for their own team, got {result:?}"
    );
}
