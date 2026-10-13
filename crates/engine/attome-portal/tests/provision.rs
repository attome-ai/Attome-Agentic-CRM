//! Integration tests for `attome_portal::provision` (D-576, Phase 1), against a
//! real database.
//!
//! Each run gets its **own** empty database (`attome_testkit::empty_database`)
//! and applies every compiled migration to it with the real
//! `sqlx::migrate!` migrator, so these tests never depend on the shared
//! `attomedb_test` template being migrated to this branch's level (migration
//! 0482 is new here). The engine functions are driven directly on a
//! transaction, the same way the admin handlers drive them inside a
//! `SecurityTx`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-portal --test provision -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test drives engine functions on raw pool transactions"
)]

use attome_core::EngineModel;
use attome_db::DbPool;
use attome_portal::provision::{
    self, NewPortal, NewPortalUser, PortalSettingsPatch, PortalType, PortalUserStatus,
};
use attome_types::AppError;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::OnceCell;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../apps/attome/migrations");
const BUNDLE: &str = include_str!("../../../../platform-bundles/attome-portal.json");

/// URL of this binary's migrated and seeded database, created once.
static DB_URL: OnceCell<Option<String>> = OnceCell::const_new();

async fn prepare() -> Option<String> {
    let db = attome_testkit::empty_database("portal_provision").await?;
    let url = db.url().to_owned();
    // Kept for the process lifetime; `empty_database` reclaims a leftover
    // database of the same name on the next run.
    std::mem::forget(db);

    let pool = connect(&url).await;
    sqlx::query("CREATE SCHEMA IF NOT EXISTS attome_dev")
        .execute(&pool)
        .await
        .expect("create schema");
    MIGRATOR.run(&pool).await.expect("apply every migration");
    attome_security::seed::seed_for_tests(&pool)
        .await
        .expect("attome_security::seed::seed_for_tests");
    seed_portal_entities(&pool).await;
    pool.close().await;
    Some(url)
}

async fn connect(url: &str) -> DbPool {
    PgPoolOptions::new()
        .max_connections(4)
        // The one-time migration run applies ~480 files; don't let a busy
        // shared test cluster turn a slow acquire into a setup failure.
        .acquire_timeout(std::time::Duration::from_secs(180))
        .connect(url)
        .await
        .expect("connect to the test database")
}

/// A fresh pool per test (each `#[tokio::test]` has its own runtime), on the
/// database `prepare` built once.
async fn test_db() -> Option<DbPool> {
    let url = DB_URL.get_or_init(prepare).await.clone()?;
    Some(connect(&url).await)
}

/// Provisions the bundle's two entities the way `apply_platform_bundle` does
/// at boot (entities first, then attributes, so the self-bundle lookup
/// `webportal_ref` resolves). Same shape as `attome_service::seed::seed_for_tests`.
async fn seed_portal_entities(db: &DbPool) {
    let bundle: serde_json::Value = serde_json::from_str(BUNDLE).expect("bundle JSON");
    let entities = bundle["entities"].as_array().expect("entities");
    let mut ids = std::collections::HashMap::new();
    for e in entities {
        let name = e["logicalname"].as_str().unwrap();
        let id = attome_metadata::provision::ensure_entity(
            db,
            name,
            e["display_name"].as_str().unwrap(),
            e["primary_name_attribute"].as_str(),
            false,
        )
        .await
        .expect("ensure_entity");
        ids.insert(name.to_owned(), id);
    }
    for e in entities {
        let entity_id = ids[e["logicalname"].as_str().unwrap()];
        for a in e["attributes"].as_array().unwrap() {
            let lookup = match a["lookup_entity"].as_str() {
                Some(t) if ids.contains_key(t) => Some(ids[t]),
                Some(t) => Some(
                    sqlx::query_scalar::<_, Uuid>(
                        "SELECT id FROM entity_info WHERE logicalname = $1",
                    )
                    .bind(t)
                    .fetch_one(db)
                    .await
                    .expect("lookup target registered"),
                ),
                None => None,
            };
            attome_metadata::provision::ensure_attribute(
                db,
                entity_id,
                a["logicalname"].as_str().unwrap(),
                a["display_name"].as_str().unwrap(),
                a["field_type"].as_str().unwrap(),
                a["is_required"].as_bool().unwrap_or(false),
                a["is_sensitive"].as_bool().unwrap_or(false),
                a["is_sortable"].as_bool().unwrap_or(false),
                a["is_filterable"].as_bool().unwrap_or(false),
                lookup,
                a.get("options").cloned(),
            )
            .await
            .expect("ensure_attribute");
        }
    }
}

fn uniq(prefix: &str) -> String {
    format!("{prefix}-{}", &Uuid::new_v4().simple().to_string()[..10])
}

async fn new_portal(db: &DbPool, portal_type: PortalType) -> provision::PortalDetail {
    let mut tx = db.begin().await.unwrap();
    let p = provision::create_portal(
        &mut tx,
        Uuid::now_v7(),
        NewPortal {
            name: "Customers".into(),
            description: None,
            keyword: uniq("kw"),
            portal_type,
            is_enabled: true,
            owning_team_ref: None,
            mfa_policy: Default::default(),
        },
    )
    .await
    .expect("create_portal");
    tx.commit().await.unwrap();
    p
}

async fn new_user(
    db: &DbPool,
    portal: Uuid,
    email: &str,
) -> Result<provision::PortalUserDetail, AppError> {
    let mut tx = db.begin().await.unwrap();
    let r = provision::create_user(
        &mut tx,
        Uuid::now_v7(),
        portal,
        NewPortalUser {
            name: "Ada".into(),
            email: Some(email.into()),
            username: None,
        },
    )
    .await;
    if r.is_ok() {
        tx.commit().await.unwrap();
    }
    r
}

async fn epoch(db: &DbPool, user: Uuid) -> Option<i32> {
    sqlx::query_scalar("SELECT auth_epoch FROM webportal_credential WHERE webportal_user_id = $1")
        .bind(user)
        .fetch_optional(db)
        .await
        .unwrap()
}

#[test]
fn the_model_claims_exactly_the_bundle_entities() {
    let bundle: serde_json::Value = serde_json::from_str(BUNDLE).unwrap();
    let mut in_bundle: Vec<&str> = bundle["entities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["logicalname"].as_str().unwrap())
        .collect();
    in_bundle.sort_unstable();
    let mut claimed = attome_portal::PortalModel.owned_entities().to_vec();
    claimed.sort_unstable();
    assert_eq!(
        claimed, in_bundle,
        "D-383: every seeded entity must be licence-gated"
    );
    // Every guarded field must exist in the bundle, or the guard is decorative.
    for (entity, fields) in [
        ("webportal", attome_portal::guard::WEBPORTAL_PROTECTED),
        (
            "webportal_user",
            attome_portal::guard::WEBPORTAL_USER_PROTECTED,
        ),
    ] {
        let e = bundle["entities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["logicalname"] == entity)
            .unwrap();
        let mut required_and_protected = 0;
        for f in fields {
            let attr = e["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["logicalname"] == *f)
                .unwrap_or_else(|| panic!("{entity}.{f} missing from the bundle"));
            if attr["is_required"] == true {
                required_and_protected += 1;
            }
        }
        // A generic create must either omit a required field or send a refused
        // one, so at least one protected field has to be required.
        assert!(
            required_and_protected > 0,
            "{entity}: no protected field is required, so a generic create could succeed"
        );
    }
}

#[tokio::test]
async fn portal_keywords_are_normalized_unique_and_never_reserved() {
    let Some(db) = test_db().await else { return };
    let kw = uniq("Shop").to_uppercase();

    let mut tx = db.begin().await.unwrap();
    let p = provision::create_portal(
        &mut tx,
        Uuid::now_v7(),
        NewPortal {
            name: " Shop ".into(),
            description: Some("  ".into()),
            keyword: format!("  {kw} "),
            portal_type: PortalType::Mixed,
            is_enabled: false,
            owning_team_ref: None,
            mfa_policy: Default::default(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(p.keyword, kw.to_lowercase());
    assert_eq!(p.name, "Shop");
    assert_eq!(p.description, None);
    assert!(!p.is_enabled);

    // Same keyword, different case: conflict.
    let mut tx = db.begin().await.unwrap();
    let dup = provision::create_portal(
        &mut tx,
        Uuid::now_v7(),
        NewPortal {
            name: "Other".into(),
            description: None,
            keyword: kw.clone(),
            portal_type: PortalType::Authenticated,
            is_enabled: true,
            owning_team_ref: None,
            mfa_policy: Default::default(),
        },
    )
    .await;
    assert!(matches!(dup, Err(AppError::Conflict(_))), "{dup:?}");
    drop(tx);

    // The staff app's prefix can never be claimed.
    let mut tx = db.begin().await.unwrap();
    let reserved = provision::create_portal(
        &mut tx,
        Uuid::now_v7(),
        NewPortal {
            name: "Staff".into(),
            description: None,
            keyword: "xrm".into(),
            portal_type: PortalType::Authenticated,
            is_enabled: true,
            owning_team_ref: None,
            mfa_policy: Default::default(),
        },
    )
    .await;
    assert!(
        matches!(reserved, Err(AppError::Validation(_))),
        "{reserved:?}"
    );
}

#[tokio::test]
async fn owning_team_must_be_a_real_team() {
    let Some(db) = test_db().await else { return };
    let mut tx = db.begin().await.unwrap();
    let r = provision::create_portal(
        &mut tx,
        Uuid::now_v7(),
        NewPortal {
            name: "Partners".into(),
            description: None,
            keyword: uniq("partners"),
            portal_type: PortalType::Authenticated,
            is_enabled: true,
            owning_team_ref: Some(Uuid::now_v7()),
            mfa_policy: Default::default(),
        },
    )
    .await;
    assert!(matches!(r, Err(AppError::Validation(_))), "{r:?}");
}

#[tokio::test]
async fn provisioning_creates_the_profile_and_an_empty_credential_and_never_a_staff_user() {
    let Some(db) = test_db().await else { return };
    let portal = new_portal(&db, PortalType::Authenticated).await;
    let staff_before: i64 = sqlx::query_scalar("SELECT count(*) FROM user_account")
        .fetch_one(&db)
        .await
        .unwrap();

    let user = new_user(&db, portal.id, " Ada@Example.COM ").await.unwrap();
    assert_eq!(user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(user.status, PortalUserStatus::Invited);
    assert_eq!(user.webportal_id, portal.id);

    let (portal_of_cred, has_password, verified): (Uuid, bool, bool) = sqlx::query_as(
        "SELECT webportal_id, password_hash IS NOT NULL, email_verified \
         FROM webportal_credential WHERE webportal_user_id = $1",
    )
    .bind(user.id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(portal_of_cred, portal.id);
    assert!(!has_password && !verified);

    // D-576: a portal user is never a system user.
    let staff_after: i64 = sqlx::query_scalar("SELECT count(*) FROM user_account")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(staff_before, staff_after);
    let as_staff: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_account WHERE id = $1)")
            .bind(user.id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(!as_staff);
}

#[tokio::test]
async fn email_is_unique_per_portal_case_insensitively() {
    let Some(db) = test_db().await else { return };
    let a = new_portal(&db, PortalType::Authenticated).await;
    let b = new_portal(&db, PortalType::Mixed).await;
    let email = format!("{}@example.com", uniq("grace"));

    new_user(&db, a.id, &email).await.unwrap();
    let dup = new_user(&db, a.id, &email.to_uppercase()).await;
    assert!(matches!(dup, Err(AppError::Conflict(_))), "{dup:?}");
    // The same address in another portal is a separate account.
    new_user(&db, b.id, &email).await.unwrap();
}

async fn new_named_user(
    db: &DbPool,
    portal: Uuid,
    email: Option<&str>,
    username: Option<&str>,
) -> Result<provision::PortalUserDetail, AppError> {
    let mut tx = db.begin().await.unwrap();
    let r = provision::create_user(
        &mut tx,
        Uuid::now_v7(),
        portal,
        NewPortalUser {
            name: "Ada".into(),
            email: email.map(Into::into),
            username: username.map(Into::into),
        },
    )
    .await;
    if r.is_ok() {
        tx.commit().await.unwrap();
    }
    r
}

/// A username that fits the default rules (3-12 characters) and is unique
/// across test runs.
fn uniq_username() -> String {
    format!("u{}", &Uuid::new_v4().simple().to_string()[..10])
}

#[tokio::test]
async fn username_is_unique_per_portal_case_insensitively() {
    let Some(db) = test_db().await else { return };
    let a = new_portal(&db, PortalType::Authenticated).await;
    let b = new_portal(&db, PortalType::Mixed).await;
    let name = uniq_username();

    let user = new_named_user(&db, a.id, None, Some(&name)).await.unwrap();
    assert_eq!(user.username.as_deref(), Some(name.as_str()));
    assert_eq!(user.email, None);
    let dup = new_named_user(&db, a.id, None, Some(&name.to_uppercase())).await;
    assert!(matches!(dup, Err(AppError::Conflict(_))), "{dup:?}");
    // The same username in another portal is a separate account.
    new_named_user(&db, b.id, None, Some(&name)).await.unwrap();
    // Both identifiers on one account.
    let both = new_named_user(
        &db,
        a.id,
        Some(&format!("{}@example.com", uniq("both"))),
        Some(&uniq_username()),
    )
    .await
    .unwrap();
    assert!(both.email.is_some() && both.username.is_some());
}

#[tokio::test]
async fn a_user_needs_an_email_or_a_valid_username() {
    let Some(db) = test_db().await else { return };
    let portal = new_portal(&db, PortalType::Authenticated).await;
    let none = new_named_user(&db, portal.id, None, None).await;
    assert!(matches!(none, Err(AppError::Validation(_))), "{none:?}");
    let blank = new_named_user(&db, portal.id, Some("  "), Some(" ")).await;
    assert!(matches!(blank, Err(AppError::Validation(_))), "{blank:?}");
    for bad in ["ab", "bad!name", "1234", "_edge"] {
        let r = new_named_user(&db, portal.id, None, Some(bad)).await;
        assert!(matches!(r, Err(AppError::Validation(_))), "{bad:?}: {r:?}");
    }
}

#[tokio::test]
async fn the_login_username_is_unique_per_portal_in_the_database() {
    let Some(db) = test_db().await else { return };
    let portal = new_portal(&db, PortalType::Authenticated).await;
    let name = uniq_username().to_ascii_lowercase();
    let insert = |user: Uuid| {
        sqlx::query(
            "INSERT INTO webportal_credential \
               (webportal_user_id, webportal_id, login_username_lower) VALUES ($1, $2, $3)",
        )
        .bind(user)
        .bind(portal.id)
        .bind(name.clone())
    };
    insert(Uuid::now_v7()).execute(&db).await.unwrap();
    let err = insert(Uuid::now_v7()).execute(&db).await.unwrap_err();
    assert_eq!(
        err.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("23505"),
        "{err:?}"
    );
}

#[tokio::test]
async fn concurrent_creates_of_one_username_make_one_account() {
    let Some(db) = test_db().await else { return };
    let portal = new_portal(&db, PortalType::Authenticated).await;
    let name = uniq_username();
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let db = db.clone();
            let name = name.clone();
            tokio::spawn(async move {
                let mut tx = db.begin().await.unwrap();
                let r = provision::create_verified_account(
                    &mut tx,
                    portal.id,
                    "Racer",
                    None,
                    Some(&name),
                    None,
                )
                .await;
                if let Ok(Some(_)) = r {
                    tx.commit().await.unwrap();
                }
                r
            })
        })
        .collect();
    let mut created = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(Some(_)) => created += 1,
            // Lost the race: the name was taken, or the other request held
            // the lock; either way nothing was created.
            Ok(None) | Err(AppError::Conflict(_)) => {}
            Err(e) => panic!("unexpected: {e:?}"),
        }
    }
    assert_eq!(created, 1);
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webportal_credential \
         WHERE webportal_id = $1 AND login_username_lower = $2",
    )
    .bind(portal.id)
    .bind(name.to_ascii_lowercase())
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(rows, 1);
}

#[tokio::test]
async fn an_anonymous_portal_has_no_users() {
    let Some(db) = test_db().await else { return };
    let portal = new_portal(&db, PortalType::Anonymous).await;
    let r = new_user(&db, portal.id, "x@example.com").await;
    assert!(matches!(r, Err(AppError::Validation(_))), "{r:?}");
}

#[tokio::test]
async fn disabling_a_user_ends_their_sessions_and_enabling_restores_invited() {
    let Some(db) = test_db().await else { return };
    let portal = new_portal(&db, PortalType::Authenticated).await;
    let user = new_user(&db, portal.id, &format!("{}@example.com", uniq("u")))
        .await
        .unwrap();
    let actor = Uuid::now_v7();

    let mut tx = db.begin().await.unwrap();
    let disabled = provision::set_user_enabled(&mut tx, actor, portal.id, user.id, false)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(disabled.status, PortalUserStatus::Disabled);
    assert_eq!(epoch(&db, user.id).await, Some(1));

    // Idempotent: a second disable changes nothing, epoch included.
    let mut tx = db.begin().await.unwrap();
    provision::set_user_enabled(&mut tx, actor, portal.id, user.id, false)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(epoch(&db, user.id).await, Some(1));

    // No password yet, so enabling returns to `invited`, not `active`.
    let mut tx = db.begin().await.unwrap();
    let enabled = provision::set_user_enabled(&mut tx, actor, portal.id, user.id, true)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(enabled.status, PortalUserStatus::Invited);
}

#[tokio::test]
async fn a_user_is_not_reachable_through_another_portal() {
    let Some(db) = test_db().await else { return };
    let a = new_portal(&db, PortalType::Authenticated).await;
    let b = new_portal(&db, PortalType::Authenticated).await;
    let user = new_user(&db, a.id, &format!("{}@example.com", uniq("u")))
        .await
        .unwrap();

    let mut tx = db.begin().await.unwrap();
    let r = provision::set_user_enabled(&mut tx, Uuid::now_v7(), b.id, user.id, false).await;
    assert!(matches!(r, Err(AppError::NotFound)), "{r:?}");
    let r = provision::delete_user(&mut tx, Uuid::now_v7(), b.id, user.id).await;
    assert!(matches!(r, Err(AppError::NotFound)), "{r:?}");
}

#[tokio::test]
async fn deleting_a_user_soft_deletes_the_profile_and_removes_the_credential() {
    let Some(db) = test_db().await else { return };
    let portal = new_portal(&db, PortalType::Authenticated).await;
    let email = format!("{}@example.com", uniq("u"));
    let user = new_user(&db, portal.id, &email).await.unwrap();

    let mut tx = db.begin().await.unwrap();
    provision::delete_user(&mut tx, Uuid::now_v7(), portal.id, user.id)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let (is_active, status): (Option<bool>, String) =
        sqlx::query_as("SELECT is_active, status FROM webportal_user WHERE id = $1")
            .bind(user.id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(is_active, Some(false));
    assert_eq!(status, "disabled");
    assert_eq!(
        epoch(&db, user.id).await,
        None,
        "credential row must be gone"
    );

    // The address is free to be invited again.
    new_user(&db, portal.id, &email).await.unwrap();
}

#[tokio::test]
async fn portal_settings_check_row_version_and_revoke_sessions_when_access_ends() {
    let Some(db) = test_db().await else { return };
    let portal = new_portal(&db, PortalType::Authenticated).await;
    let other = new_portal(&db, PortalType::Authenticated).await;
    let user = new_user(&db, portal.id, &format!("{}@example.com", uniq("u")))
        .await
        .unwrap();
    let bystander = new_user(&db, other.id, &format!("{}@example.com", uniq("u")))
        .await
        .unwrap();
    let actor = Uuid::now_v7();

    let patch = |row_version, is_enabled, portal_type| PortalSettingsPatch {
        row_version,
        keyword: None,
        portal_type,
        is_enabled,
        owning_team_ref: None,
        mfa_policy: None,
    };

    // A stale row_version is refused.
    let mut tx = db.begin().await.unwrap();
    let stale = provision::update_portal_settings(
        &mut tx,
        actor,
        portal.id,
        patch(portal.row_version + 1, Some(false), None),
    )
    .await;
    assert!(matches!(stale, Err(AppError::VersionConflict)), "{stale:?}");
    drop(tx);

    // Disabling the portal revokes its users' sessions, and only theirs.
    let mut tx = db.begin().await.unwrap();
    let updated = provision::update_portal_settings(
        &mut tx,
        actor,
        portal.id,
        patch(portal.row_version, Some(false), None),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(!updated.is_enabled);
    assert_eq!(updated.row_version, portal.row_version + 1);
    assert_eq!(epoch(&db, user.id).await, Some(1));
    assert_eq!(epoch(&db, bystander.id).await, Some(0));

    // Turning a portal anonymous also ends its users' sessions.
    let mut tx = db.begin().await.unwrap();
    provision::update_portal_settings(
        &mut tx,
        actor,
        portal.id,
        patch(updated.row_version, None, Some(PortalType::Anonymous)),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(epoch(&db, user.id).await, Some(2));
}

#[tokio::test]
async fn a_keyword_change_is_checked_for_collisions() {
    let Some(db) = test_db().await else { return };
    let a = new_portal(&db, PortalType::Authenticated).await;
    let b = new_portal(&db, PortalType::Authenticated).await;

    let mut tx = db.begin().await.unwrap();
    let r = provision::update_portal_settings(
        &mut tx,
        Uuid::now_v7(),
        b.id,
        PortalSettingsPatch {
            row_version: b.row_version,
            keyword: Some(a.keyword.to_uppercase()),
            portal_type: None,
            is_enabled: None,
            owning_team_ref: None,
            mfa_policy: Default::default(),
        },
    )
    .await;
    assert!(matches!(r, Err(AppError::Conflict(_))), "{r:?}");
}

/// Migration 0482's grants, proven against the real roles (created by
/// migration 0042): the runtime role can do the credential DML Phase 2 needs,
/// and the read-only role that stored queries run under cannot read a hash.
#[tokio::test]
async fn credential_grants_allow_runtime_dml_and_deny_readonly() {
    let Some(db) = test_db().await else { return };
    let portal = new_portal(&db, PortalType::Authenticated).await;
    let user = new_user(&db, portal.id, &format!("{}@example.com", uniq("u")))
        .await
        .unwrap();

    let mut tx = db.begin().await.unwrap();
    sqlx::query("SET LOCAL ROLE attome_runtime")
        .execute(&mut *tx)
        .await
        .expect("attome_runtime exists");
    let updated = sqlx::query(
        "UPDATE webportal_credential SET password_hash = 'h', failed_login_count = 1 \
         WHERE webportal_user_id = $1",
    )
    .bind(user.id)
    .execute(&mut *tx)
    .await
    .expect("runtime may UPDATE credentials");
    assert_eq!(updated.rows_affected(), 1);
    let hash: String = sqlx::query_scalar(
        "SELECT password_hash FROM webportal_credential WHERE webportal_user_id = $1",
    )
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await
    .expect("runtime may SELECT credentials");
    assert_eq!(hash, "h");
    let other = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO webportal_credential (webportal_user_id, webportal_id) VALUES ($1, $2)",
    )
    .bind(other)
    .bind(portal.id)
    .execute(&mut *tx)
    .await
    .expect("runtime may INSERT credentials");
    sqlx::query("DELETE FROM webportal_credential WHERE webportal_user_id = $1")
        .bind(other)
        .execute(&mut *tx)
        .await
        .expect("runtime may DELETE credentials");
    tx.rollback().await.unwrap();

    let mut tx = db.begin().await.unwrap();
    sqlx::query("SET LOCAL ROLE attome_readonly")
        .execute(&mut *tx)
        .await
        .expect("attome_readonly exists");
    let denied = sqlx::query_scalar::<_, Option<String>>(
        "SELECT password_hash FROM webportal_credential LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await;
    let code = denied
        .expect_err("attome_readonly must not read credentials")
        .as_database_error()
        .and_then(|e| e.code().map(|c| c.into_owned()));
    assert_eq!(
        code.as_deref(),
        Some("42501"),
        "expected insufficient_privilege"
    );
}

// ── D-779: trusted server login state machine ─────────────────────────────────

mod trusted_login {
    use super::*;
    use attome_portal::policy::{AuthPolicy, UsernameRejected};
    use attome_portal::trusted::{TrustedOutcome, TrustedRequest, trusted_login};
    use chrono::{Duration, Utc};

    const PASSWORD: &str = "correct horse battery staple";

    fn policy() -> AuthPolicy {
        AuthPolicy {
            trusted_server_login: true,
            username_reserved: vec!["admin".into()],
            ..AuthPolicy::default()
        }
    }

    async fn run(
        db: &DbPool,
        portal: Uuid,
        login: &str,
        password: &str,
        create: bool,
        budget: Result<(), i64>,
        now: chrono::DateTime<Utc>,
    ) -> TrustedOutcome {
        let mut tx = db.begin().await.unwrap();
        let req = TrustedRequest {
            login,
            password,
            create_if_missing: create,
            creation_budget: budget,
            second_factor: None,
            now,
        };
        let out = trusted_login(&mut tx, portal, &policy(), req)
            .await
            .expect("trusted_login");
        tx.commit().await.unwrap();
        out
    }

    /// (trusted failure streak, web failure count, web lock set)
    async fn counters(db: &DbPool, user: Uuid) -> (i32, i32, bool) {
        sqlx::query_as::<_, (i32, i32, bool)>(
            "SELECT trusted_failed_count, COALESCE(failed_login_count, 0), locked_until IS NOT NULL \
             FROM webportal_credential WHERE webportal_user_id = $1",
        )
        .bind(user)
        .fetch_one(db)
        .await
        .unwrap()
    }

    async fn accounts(db: &DbPool, portal: Uuid) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM webportal_credential WHERE webportal_id = $1")
            .bind(portal)
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_free_username_is_created_and_then_signs_in() {
        let Some(db) = test_db().await else { return };
        let p = new_portal(&db, PortalType::Authenticated).await;
        let name = uniq_username();
        let now = Utc::now();

        // Without create_if_missing nothing is created.
        let out = run(&db, p.id, &name, PASSWORD, false, Ok(()), now).await;
        assert_eq!(out, TrustedOutcome::BadCredentials { user_id: None });
        assert_eq!(accounts(&db, p.id).await, 0);

        let TrustedOutcome::Created {
            user_id,
            auth_epoch,
        } = run(&db, p.id, &name, PASSWORD, true, Ok(()), now).await
        else {
            panic!("expected Created")
        };
        assert_eq!(auth_epoch, 0);
        // Any case; create_if_missing on an existing account just signs in.
        let out = run(&db, p.id, &name.to_uppercase(), PASSWORD, true, Ok(()), now).await;
        assert_eq!(
            out,
            TrustedOutcome::Ok {
                user_id,
                auth_epoch: 0
            }
        );
        let (email, username): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT email, username FROM webportal_user WHERE id = $1")
                .bind(user_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(email, None);
        assert_eq!(username.as_deref(), Some(name.as_str()));
    }

    #[tokio::test]
    async fn a_wrong_password_never_creates_or_changes_the_account_and_slows_it_down() {
        let Some(db) = test_db().await else { return };
        let p = new_portal(&db, PortalType::Authenticated).await;
        let name = uniq_username();
        let t0 = Utc::now();
        let TrustedOutcome::Created { user_id, .. } =
            run(&db, p.id, &name, PASSWORD, true, Ok(()), t0).await
        else {
            panic!("expected Created")
        };

        // Wrong password with create_if_missing: a failure, not a new account.
        let out = run(&db, p.id, &name, "wrong password!", true, Ok(()), t0).await;
        assert_eq!(
            out,
            TrustedOutcome::BadCredentials {
                user_id: Some(user_id)
            }
        );
        assert_eq!(accounts(&db, p.id).await, 1);

        // Inside the 1 s delay even the right password waits.
        let out = run(&db, p.id, &name, PASSWORD, false, Ok(()), t0).await;
        assert!(
            matches!(
                out,
                TrustedOutcome::RetryLater {
                    retry_after_secs: 1,
                    ..
                }
            ),
            "{out:?}"
        );
        // A second failure doubles it.
        let t1 = t0 + Duration::seconds(2);
        run(&db, p.id, &name, "wrong again!!", false, Ok(()), t1).await;
        let out = run(
            &db,
            p.id,
            &name,
            PASSWORD,
            false,
            Ok(()),
            t1 + Duration::seconds(1),
        )
        .await;
        assert!(matches!(out, TrustedOutcome::RetryLater { .. }), "{out:?}");
        // The web login's own lockout counters are untouched.
        assert_eq!(counters(&db, user_id).await, (2, 0, false));

        // After the delay the right password works and clears the streak.
        let out = run(
            &db,
            p.id,
            &name,
            PASSWORD,
            false,
            Ok(()),
            t1 + Duration::seconds(3),
        )
        .await;
        assert_eq!(
            out,
            TrustedOutcome::Ok {
                user_id,
                auth_epoch: 0
            }
        );
        assert_eq!(counters(&db, user_id).await.0, 0);
    }

    #[tokio::test]
    async fn refusals_follow_the_state_machine() {
        let Some(db) = test_db().await else { return };
        let p = new_portal(&db, PortalType::Authenticated).await;
        let now = Utc::now();

        // An unknown email is never created.
        let out = run(&db, p.id, "nobody@example.com", PASSWORD, true, Ok(()), now).await;
        assert_eq!(out, TrustedOutcome::BadCredentials { user_id: None });
        // Name rules and reserved names.
        let out = run(&db, p.id, "ab", PASSWORD, true, Ok(()), now).await;
        assert_eq!(
            out,
            TrustedOutcome::NameRejected(UsernameRejected::Length { min: 3, max: 12 })
        );
        let out = run(&db, p.id, "Admin", PASSWORD, true, Ok(()), now).await;
        assert_eq!(
            out,
            TrustedOutcome::NameRejected(UsernameRejected::NotAllowed)
        );
        // The address's creation budget.
        let out = run(&db, p.id, &uniq_username(), PASSWORD, true, Err(1800), now).await;
        assert_eq!(
            out,
            TrustedOutcome::CreationLimited {
                retry_after_secs: 1800
            }
        );
        // The platform password policy.
        let out = run(&db, p.id, &uniq_username(), "x", true, Ok(()), now).await;
        assert!(
            matches!(out, TrustedOutcome::PasswordRejected(_)),
            "{out:?}"
        );
        assert_eq!(accounts(&db, p.id).await, 0);

        // A disabled account.
        let name = uniq_username();
        let TrustedOutcome::Created { user_id, .. } =
            run(&db, p.id, &name, PASSWORD, true, Ok(()), now).await
        else {
            panic!("expected Created")
        };
        let mut tx = db.begin().await.unwrap();
        provision::set_user_enabled(&mut tx, Uuid::now_v7(), p.id, user_id, false)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let out = run(&db, p.id, &name, PASSWORD, false, Ok(()), now).await;
        assert_eq!(out, TrustedOutcome::Disabled { user_id });

        // An account with MFA can't sign in without a second factor.
        let name = uniq_username();
        let TrustedOutcome::Created { user_id, .. } =
            run(&db, p.id, &name, PASSWORD, true, Ok(()), now).await
        else {
            panic!("expected Created")
        };
        sqlx::query(
            "UPDATE webportal_credential SET mfa_enabled = TRUE WHERE webportal_user_id = $1",
        )
        .bind(user_id)
        .execute(&db)
        .await
        .unwrap();
        let out = run(&db, p.id, &name, PASSWORD, false, Ok(()), now).await;
        assert_eq!(out, TrustedOutcome::MfaRequired { user_id });
    }

    #[tokio::test]
    async fn concurrent_creates_of_one_name_make_one_account_and_the_rest_sign_in() {
        let Some(db) = test_db().await else { return };
        let p = new_portal(&db, PortalType::Authenticated).await;
        let name = uniq_username();
        let tasks: Vec<_> = (0..6)
            .map(|_| {
                let db = db.clone();
                let name = name.clone();
                let portal = p.id;
                tokio::spawn(async move {
                    let mut tx = db.begin().await.unwrap();
                    let req = TrustedRequest {
                        login: &name,
                        password: PASSWORD,
                        create_if_missing: true,
                        creation_budget: Ok(()),
                        second_factor: None,
                        now: Utc::now(),
                    };
                    let r = trusted_login(&mut tx, portal, &policy(), req).await;
                    if r.is_ok() {
                        tx.commit().await.unwrap();
                    }
                    r
                })
            })
            .collect();
        let mut created = 0;
        for t in tasks {
            match t.await.unwrap() {
                Ok(TrustedOutcome::Created { .. }) => created += 1,
                // Lost the race: signed in to the winner's account, or the
                // winner held the lock (the caller retries).
                Ok(TrustedOutcome::Ok { .. }) | Err(AppError::Conflict(_)) => {}
                other => panic!("unexpected: {other:?}"),
            }
        }
        assert_eq!(created, 1);
        assert_eq!(accounts(&db, p.id).await, 1);
    }
}
