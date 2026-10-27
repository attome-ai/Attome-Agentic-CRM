//! P-environment-promotion §5 step 13 — `attome_security::reconcile`: roles
//! (with grants, conditions, entity access and profile links as a set),
//! privileges and field-security profiles, plus retire/reactivate.
//!
//! Covers:
//! - `reconcile_role` create / `Unchanged` / `Admin` marks / `Seed` skips a
//!   customized row / `Bundle { false }` clears the marker and applies;
//! - set semantics: a grant absent from the description is soft-deleted,
//!   a changed condition set is replaced, an entity-access row and a profile
//!   link absent from the description are soft-deleted;
//! - retire/reactivate round-trips for roles and profiles (retire also
//!   soft-deletes the role's live grants; a later `reconcile_role` restores
//!   them);
//! - `reconcile_privilege` create / unchanged / update;
//! - `reconcile_field_security_profile` member set semantics (an extra
//!   member row is removed).
//!
//! Requires a live Postgres (`DATABASE_URL`, cloned per binary by
//! `attome_testkit`) — same convention as `tests/accounts.rs`. Entity fixtures
//! are bare `entity_info` rows plus a one-column stand-in table
//! (see `view_admin.rs` in attome-server for why the table is load-bearing).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-security --test reconcile_security -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_security::reconcile::{
    FieldSecurityProfileDesc, GrantConditionDesc, PrivilegeDesc, ProfileFieldDesc,
    ReconcileOutcome, ReconcilePolicy, RoleDesc, RoleEntityAccessDesc, RoleGrantDesc,
    reactivate_field_security_profile, reactivate_role, reconcile_field_security_profile,
    reconcile_privilege, reconcile_role, retire_field_security_profile, retire_role,
};
use attome_testkit::skip_if_no_db;
use serde_json::json;
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

fn unique(prefix: &str) -> String {
    let suffix = Uuid::now_v7().simple().to_string();
    format!("{prefix}_{}", &suffix[suffix.len() - 10..])
}

const BUNDLE_PLATFORM: ReconcilePolicy = ReconcilePolicy::Bundle {
    is_customized: false,
};

/// A throwaway live entity row (+ stand-in physical table) for entity-access
/// rows to reference. Returns its logicalname.
async fn seed_entity(db: &DbPool) -> String {
    let logicalname = unique("rs_ent");
    sqlx::query(
        "INSERT INTO entity_info (logicalname, name, is_active, owner_layer) VALUES ($1, $2, true, 'project')",
    )
    .bind(&logicalname)
    .bind(&logicalname)
    .execute(db)
    .await
    .expect("insert entity fixture");
    assert!(
        logicalname
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    );
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS \"{logicalname}\" (id uuid PRIMARY KEY)"
    ))
    .execute(db)
    .await
    .expect("create stand-in table");
    logicalname
}

async fn role_row(db: &DbPool, id: Uuid) -> (Option<String>, i16, bool, bool, bool) {
    sqlx::query_as(
        "SELECT description, access_level, position_hierarchy_enabled, is_customized, is_deleted \
         FROM role WHERE id = $1",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .expect("role row")
}

async fn live_grant_keys(db: &DbPool, role_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT p.key FROM role_mm_privilege rp \
         JOIN privilege p ON p.id = rp.privilege_ref \
         WHERE rp.role_ref = $1 AND rp.is_deleted = false ORDER BY p.key",
    )
    .bind(role_id)
    .fetch_all(db)
    .await
    .expect("grants")
}

async fn live_condition_count(db: &DbPool, role_id: Uuid, key: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_privilege_condition c \
         JOIN role_mm_privilege rp ON rp.id = c.role_privilege_ref \
         JOIN privilege p ON p.id = rp.privilege_ref \
         WHERE rp.role_ref = $1 AND p.key = $2 AND c.is_deleted = false",
    )
    .bind(role_id)
    .bind(key)
    .fetch_one(db)
    .await
    .expect("conditions")
}

async fn live_entity_access(db: &DbPool, role_id: Uuid) -> Vec<(String, i16)> {
    sqlx::query_as(
        "SELECT ei.logicalname, ea.read_access_level FROM role_mm_entity_access ea \
         JOIN entity_info ei ON ei.id = ea.entity_ref \
         WHERE ea.role_ref = $1 AND ea.is_deleted = false ORDER BY ei.logicalname",
    )
    .bind(role_id)
    .fetch_all(db)
    .await
    .expect("entity access")
}

async fn live_profile_links(db: &DbPool, role_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT p.name FROM role_mm_field_security_profile rp \
         JOIN field_security_profile p ON p.id = rp.profile_ref \
         WHERE rp.role_ref = $1 AND rp.is_deleted = false ORDER BY p.name",
    )
    .bind(role_id)
    .fetch_all(db)
    .await
    .expect("profile links")
}

fn grant(privilege: &str, conditions: Vec<GrantConditionDesc>) -> RoleGrantDesc {
    RoleGrantDesc {
        privilege: privilege.to_owned(),
        conditions,
    }
}

fn access(entity: &str, level: i16) -> RoleEntityAccessDesc {
    RoleEntityAccessDesc {
        entity: entity.to_owned(),
        read_access_level: level,
        write_access_level: level,
        delete_access_level: level,
        read_owner_visible: false,
        write_owner_visible: false,
        delete_owner_visible: false,
        operations: Default::default(),
    }
}

#[tokio::test]
async fn reconcile_role_set_semantics_policy_matrix_and_retire_round_trip() {
    let db = skip_if_no_db!(test_db().await);
    let entity_a = seed_entity(&db).await;
    let entity_b = seed_entity(&db).await;
    let profile_name = unique("rs_prof");
    let (profile_id, outcome) = reconcile_field_security_profile(
        &db,
        &FieldSecurityProfileDesc {
            name: profile_name.clone(),
            description: None,
            fields: vec![],
        },
        BUNDLE_PLATFORM,
        None,
    )
    .await
    .unwrap();
    assert_eq!(outcome, ReconcileOutcome::Created);

    let role_name = unique("rs_role");
    let priv_a = format!("{entity_a}.read");
    let priv_b = format!("{entity_b}.read");
    let cond = GrantConditionDesc {
        field: "status".into(),
        operator: 0,
        value: json!("open"),
    };
    let desc = RoleDesc {
        name: role_name.clone(),
        description: Some("first".into()),
        access_level: 3,
        position_hierarchy_enabled: false,
        privileges: vec![grant(&priv_a, vec![cond.clone()]), grant(&priv_b, vec![])],
        entity_access: vec![access(&entity_a, 1), access(&entity_b, 2)],
        field_security_profiles: vec![profile_name.clone()],
    };

    // Create (privileges minted on demand, as the admin grant handler does).
    let (role_id, outcome) = reconcile_role(&db, &desc, BUNDLE_PLATFORM, None)
        .await
        .unwrap();
    assert_eq!(outcome, ReconcileOutcome::Created);
    let (description, level, phe, customized, deleted) = role_row(&db, role_id).await;
    assert_eq!(description.as_deref(), Some("first"));
    assert_eq!((level, phe, customized, deleted), (3, false, false, false));
    let mut expected_keys = vec![priv_a.clone(), priv_b.clone()];
    expected_keys.sort();
    assert_eq!(live_grant_keys(&db, role_id).await, expected_keys);
    assert_eq!(live_condition_count(&db, role_id, &priv_a).await, 1);
    assert_eq!(live_condition_count(&db, role_id, &priv_b).await, 0);
    let mut ea = live_entity_access(&db, role_id).await;
    ea.sort();
    let mut expected_ea = vec![(entity_a.clone(), 1), (entity_b.clone(), 2)];
    expected_ea.sort();
    assert_eq!(ea, expected_ea);
    assert_eq!(
        live_profile_links(&db, role_id).await,
        vec![profile_name.clone()]
    );

    // Identical: Unchanged (grants compared as a set, order-independent).
    let mut reordered = desc.clone();
    reordered.privileges.reverse();
    reordered.entity_access.reverse();
    let (same, outcome) = reconcile_role(&db, &reordered, BUNDLE_PLATFORM, None)
        .await
        .unwrap();
    assert_eq!((same, outcome), (role_id, ReconcileOutcome::Unchanged));

    // Admin marks the row.
    let (_, outcome) = reconcile_role(&db, &desc, ReconcilePolicy::Admin, None)
        .await
        .unwrap();
    assert_eq!(outcome, ReconcileOutcome::Updated);
    assert!(role_row(&db, role_id).await.3);

    // Set semantics: drop grant B, replace A's conditions, drop B's entity
    // access, drop the profile link. Seed must skip (customized); Bundle
    // applies and clears the marker.
    let cond2 = GrantConditionDesc {
        field: "status".into(),
        operator: 1,
        value: json!("closed"),
    };
    let narrowed = RoleDesc {
        description: Some("second".into()),
        access_level: 2,
        position_hierarchy_enabled: true,
        privileges: vec![grant(&priv_a, vec![cond2.clone(), cond.clone()])],
        entity_access: vec![access(&entity_a, 0)],
        field_security_profiles: vec![],
        ..desc.clone()
    };
    let (_, outcome) = reconcile_role(&db, &narrowed, ReconcilePolicy::Seed, None)
        .await
        .unwrap();
    assert_eq!(outcome, ReconcileOutcome::SkippedCustomized);
    assert_eq!(
        live_grant_keys(&db, role_id).await,
        expected_keys,
        "seed must not touch it"
    );

    let (_, outcome) = reconcile_role(&db, &narrowed, BUNDLE_PLATFORM, None)
        .await
        .unwrap();
    assert_eq!(outcome, ReconcileOutcome::Updated);
    let (description, level, phe, customized, _) = role_row(&db, role_id).await;
    assert_eq!(description.as_deref(), Some("second"));
    assert_eq!((level, phe, customized), (2, true, false));
    assert_eq!(live_grant_keys(&db, role_id).await, vec![priv_a.clone()]);
    assert_eq!(live_condition_count(&db, role_id, &priv_a).await, 2);
    assert_eq!(
        live_entity_access(&db, role_id).await,
        vec![(entity_a.clone(), 0)]
    );
    assert!(live_profile_links(&db, role_id).await.is_empty());
    // The removed grant row is soft-deleted, not gone.
    let soft_deleted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_mm_privilege rp \
         JOIN privilege p ON p.id = rp.privilege_ref \
         WHERE rp.role_ref = $1 AND p.key = $2 AND rp.is_deleted = true",
    )
    .bind(role_id)
    .bind(&priv_b)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(soft_deleted, 1);

    // Re-adding grant B reactivates the soft-deleted row (no duplicate).
    let (_, outcome) = reconcile_role(&db, &desc, BUNDLE_PLATFORM, None)
        .await
        .unwrap();
    assert_eq!(outcome, ReconcileOutcome::Updated);
    assert_eq!(live_grant_keys(&db, role_id).await, expected_keys);
    let total_b: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_mm_privilege rp \
         JOIN privilege p ON p.id = rp.privilege_ref \
         WHERE rp.role_ref = $1 AND p.key = $2",
    )
    .bind(role_id)
    .bind(&priv_b)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(total_b, 1);

    // Retire: role soft-deleted, live grants soft-deleted; reactivate flips
    // the role back; reconcile restores the grant set on the same row.
    assert_eq!(
        retire_role(&db, &role_name).await.unwrap(),
        ReconcileOutcome::Updated
    );
    assert!(role_row(&db, role_id).await.4);
    assert!(live_grant_keys(&db, role_id).await.is_empty());
    assert_eq!(
        retire_role(&db, &role_name).await.unwrap(),
        ReconcileOutcome::Unchanged
    );
    assert_eq!(
        reactivate_role(&db, &role_name).await.unwrap(),
        ReconcileOutcome::Updated
    );
    assert!(!role_row(&db, role_id).await.4);
    assert_eq!(
        reactivate_role(&db, &role_name).await.unwrap(),
        ReconcileOutcome::Unchanged
    );
    let (again, outcome) = reconcile_role(&db, &desc, BUNDLE_PLATFORM, None)
        .await
        .unwrap();
    assert_eq!((again, outcome), (role_id, ReconcileOutcome::Updated));
    assert_eq!(live_grant_keys(&db, role_id).await, expected_keys);

    // Reconcile over a retired role reactivates the same row too.
    retire_role(&db, &role_name).await.unwrap();
    let (again, outcome) = reconcile_role(&db, &desc, BUNDLE_PLATFORM, None)
        .await
        .unwrap();
    assert_eq!((again, outcome), (role_id, ReconcileOutcome::Updated));
    assert!(!role_row(&db, role_id).await.4);
    assert_eq!(profile_id, profile_id);

    // Validation: bad access level, too many conditions, unknown profile.
    let mut bad = desc.clone();
    bad.access_level = 9;
    assert!(matches!(
        reconcile_role(&db, &bad, BUNDLE_PLATFORM, None).await,
        Err(attome_types::AppError::Validation(_))
    ));
    let mut bad = desc.clone();
    bad.privileges = vec![grant(&priv_a, vec![cond.clone(); 4])];
    assert!(matches!(
        reconcile_role(&db, &bad, BUNDLE_PLATFORM, None).await,
        Err(attome_types::AppError::Validation(_))
    ));
    let mut bad = desc.clone();
    bad.field_security_profiles = vec!["no_such_profile_xyz".into()];
    assert!(matches!(
        reconcile_role(&db, &bad, BUNDLE_PLATFORM, None).await,
        Err(attome_types::AppError::Validation(_))
    ));
}

#[tokio::test]
async fn reconcile_privilege_create_unchanged_update() {
    let db = skip_if_no_db!(test_db().await);
    let key = unique("rs_priv.custom");
    let desc = PrivilegeDesc {
        key: key.clone(),
        name: "Custom".into(),
        description: Some("d1".into()),
    };
    let (id, outcome) =
        reconcile_privilege(&db, &desc, None, attome_core::changeset::Layer::Project)
            .await
            .unwrap();
    assert_eq!(outcome, ReconcileOutcome::Created);
    let (same, outcome) =
        reconcile_privilege(&db, &desc, None, attome_core::changeset::Layer::Project)
            .await
            .unwrap();
    assert_eq!((same, outcome), (id, ReconcileOutcome::Unchanged));
    let changed = PrivilegeDesc {
        name: "Custom v2".into(),
        description: None,
        ..desc
    };
    let (same, outcome) =
        reconcile_privilege(&db, &changed, None, attome_core::changeset::Layer::Project)
            .await
            .unwrap();
    assert_eq!((same, outcome), (id, ReconcileOutcome::Updated));
    let (name, description): (String, Option<String>) =
        sqlx::query_as("SELECT name, description FROM privilege WHERE id = $1")
            .bind(id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!((name.as_str(), description), ("Custom v2", None));
}

#[tokio::test]
async fn reconcile_field_security_profile_members_and_retire_round_trip() {
    let db = skip_if_no_db!(test_db().await);
    let name = unique("rs_fsp");
    let member = |field: &str, can_read: bool| ProfileFieldDesc {
        entity: "account".into(),
        field: field.into(),
        can_read,
        can_update: false,
    };
    let desc = FieldSecurityProfileDesc {
        name: name.clone(),
        description: Some("p1".into()),
        fields: vec![member("ssn", true), member("salary", true)],
    };
    let (id, outcome) = reconcile_field_security_profile(&db, &desc, BUNDLE_PLATFORM, None)
        .await
        .unwrap();
    assert_eq!(outcome, ReconcileOutcome::Created);
    let members = |db: &DbPool, id: Uuid| {
        let db = db.clone();
        async move {
            sqlx::query_as::<_, (String, bool)>(
                "SELECT field_logicalname, can_read FROM field_security_profile_field \
                 WHERE profile_ref = $1 ORDER BY field_logicalname",
            )
            .bind(id)
            .fetch_all(&db)
            .await
            .unwrap()
        }
    };
    assert_eq!(
        members(&db, id).await,
        vec![("salary".to_owned(), true), ("ssn".to_owned(), true)]
    );
    let (same, outcome) = reconcile_field_security_profile(&db, &desc, BUNDLE_PLATFORM, None)
        .await
        .unwrap();
    assert_eq!((same, outcome), (id, ReconcileOutcome::Unchanged));

    // Admin marks; Seed skips; Bundle applies set semantics (extra member
    // removed, changed member updated) and clears the marker.
    let (_, outcome) = reconcile_field_security_profile(&db, &desc, ReconcilePolicy::Admin, None)
        .await
        .unwrap();
    assert_eq!(outcome, ReconcileOutcome::Updated);
    let narrowed = FieldSecurityProfileDesc {
        description: None,
        fields: vec![member("ssn", false)],
        ..desc.clone()
    };
    let (_, outcome) =
        reconcile_field_security_profile(&db, &narrowed, ReconcilePolicy::Seed, None)
            .await
            .unwrap();
    assert_eq!(outcome, ReconcileOutcome::SkippedCustomized);
    let (_, outcome) = reconcile_field_security_profile(&db, &narrowed, BUNDLE_PLATFORM, None)
        .await
        .unwrap();
    assert_eq!(outcome, ReconcileOutcome::Updated);
    assert_eq!(members(&db, id).await, vec![("ssn".to_owned(), false)]);
    let (customized, description): (bool, Option<String>) = sqlx::query_as(
        "SELECT is_customized, description FROM field_security_profile WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!((customized, description), (false, None));

    assert_eq!(
        retire_field_security_profile(&db, &name).await.unwrap(),
        ReconcileOutcome::Updated
    );
    assert_eq!(
        retire_field_security_profile(&db, &name).await.unwrap(),
        ReconcileOutcome::Unchanged
    );
    assert_eq!(
        reactivate_field_security_profile(&db, &name).await.unwrap(),
        ReconcileOutcome::Updated
    );
    assert_eq!(
        reactivate_field_security_profile(&db, &name).await.unwrap(),
        ReconcileOutcome::Unchanged
    );
    retire_field_security_profile(&db, &name).await.unwrap();
    let (again, outcome) = reconcile_field_security_profile(&db, &narrowed, BUNDLE_PLATFORM, None)
        .await
        .unwrap();
    assert_eq!((again, outcome), (id, ReconcileOutcome::Updated));
    assert_eq!(members(&db, id).await, vec![("ssn".to_owned(), false)]);
}
