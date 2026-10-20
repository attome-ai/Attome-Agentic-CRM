//! Against a real database (D-424/D-425's two load-bearing properties):
//!
//! 1. Credential round trip — a stored credential's plaintext is never
//!    readable back from `integration_credential` except through
//!    `credential::resolve` (decrypt), `meta()` never exposes it, and
//!    `rotate` supersedes rather than leaving two "active" rows.
//! 2. The privilege dependency `webhook::handle_webhook` relies on for its
//!    core security property: a per-system service principal's resolved
//!    `SecurityContext` reflects exactly the privileges granted to it in
//!    `user_account_mm_privilege` — nothing more. This is what makes
//!    "the service principal lacks `integration_event.create`, so the
//!    webhook write is correctly rejected" true; `webhook.rs` itself calls
//!    `state.base.security.resolve(..)` (the cached production resolver) and
//!    `SecurityContextExt::require`, both already covered by attome-security's
//!    own test suite — this file tests the one piece this crate adds:
//!    `system::service_principal_id` correctly round-trips the stored
//!    `text` reference, and the resolved context is exactly as privileged
//!    as the grant table says.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-integration --test service_principal_and_credential
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::KeyRing;
use attome_db::DbPool;
use attome_integration::credential;
use attome_integration::system::IntegrationSystem;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

fn test_ring() -> KeyRing {
    KeyRing::single("cc".repeat(32))
}

async fn seed_systemuser(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) \
         VALUES ($1, $2, 'Integration Test Principal', true)",
    )
    .bind(id)
    .bind(attome_testkit::unique_email("integration-principal"))
    .execute(db)
    .await
    .expect("seed systemuser");
    id
}

async fn grant_privilege(db: &DbPool, user_id: Uuid, entity: &str, action: &str) {
    // The key is shared by every test in the binary: insert it once and
    // read the id back either way.
    let key = format!("{entity}.{action}");
    let privilege_id: Uuid = sqlx::query_scalar(
        "INSERT INTO privilege (id, key, name, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $2, true, NOW(), 'project') \
         ON CONFLICT (key) DO UPDATE SET is_active = true \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(&key)
    .fetch_one(db)
    .await
    .expect("insert privilege");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("grant privilege");
}

fn stub_system(service_principal_ref: String) -> IntegrationSystem {
    IntegrationSystem {
        id: Uuid::now_v7(),
        name: "Test System".into(),
        kind: "rest".into(),
        base_url: "https://example.com".into(),
        auth_type: "hmac".into(),
        credential_ref: None,
        rate_limit: None,
        status: "active".into(),
        health_last_ok_at: None,
        health_last_error: None,
        service_principal_ref,
        config: None,
        row_version: 0,
    }
}

// ── Credential round trip (D-424) ───────────────────────────────────────────

#[tokio::test]
async fn a_stored_credential_decrypts_correctly_and_is_never_exposed_by_meta() {
    let db = skip_if_no_db!(test_db().await);
    let ring = test_ring();
    let system_id = Uuid::now_v7();
    let plaintext = "super-secret-webhook-key-0001";

    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    let credential_id = credential::store(&mut tx, &ring, system_id, plaintext)
        .await
        .expect("store credential");
    attome_db::tx::commit(tx).await.expect("commit");

    let resolved = credential::resolve(&db, &ring, Some(&credential_id.to_string()))
        .await
        .expect("resolve")
        .expect("credential must resolve");
    assert_eq!(
        resolved.with_value(str::to_owned),
        plaintext,
        "decrypted value must round-trip exactly"
    );
    assert!(
        !format!("{resolved:?}").contains(plaintext),
        "Z1-T10: a sealed credential never prints its value"
    );

    let meta = credential::meta(&db, &credential_id.to_string())
        .await
        .expect("meta")
        .expect("meta row must exist");
    assert_eq!(
        meta.secret_last4.as_deref(),
        Some(&plaintext[plaintext.len() - 4..])
    );

    // The whole point: `CredentialMeta` structurally has no plaintext/
    // encrypted field at all, so there is nothing to accidentally leak
    // through it — pinned here so a future field addition to that struct
    // gets caught by this assertion needing an update, not shipped silently.
    let json = serde_json::to_value(&meta).expect("serialize meta");
    let obj = json.as_object().expect("object");
    assert!(!obj.contains_key("secret_encrypted"));
    let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
    let expected: std::collections::BTreeSet<&str> =
        ["id", "secret_last4", "rotated_at", "created_at"]
            .into_iter()
            .collect();
    assert_eq!(keys, expected);
}

#[tokio::test]
async fn resolve_returns_none_for_an_unresolvable_or_absent_ref() {
    let db = skip_if_no_db!(test_db().await);
    let ring = test_ring();

    assert!(
        credential::resolve(&db, &ring, None)
            .await
            .expect("resolve")
            .is_none()
    );
    assert!(
        credential::resolve(&db, &ring, Some("not-a-uuid"))
            .await
            .expect("resolve")
            .is_none()
    );
    assert!(
        credential::resolve(&db, &ring, Some(&Uuid::now_v7().to_string()))
            .await
            .expect("resolve")
            .is_none(),
        "a well-formed but non-existent ref must resolve to None, not an error"
    );
}

#[tokio::test]
async fn rotate_supersedes_the_previous_credential_rather_than_leaving_two_active_rows() {
    let db = skip_if_no_db!(test_db().await);
    let ring = test_ring();
    let system_id = Uuid::now_v7();

    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    let first_id = credential::store(&mut tx, &ring, system_id, "first-secret-value")
        .await
        .expect("store first");
    attome_db::tx::commit(tx).await.expect("commit");

    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    let second_id = credential::rotate(&mut tx, &ring, system_id, "second-secret-value")
        .await
        .expect("rotate");
    attome_db::tx::commit(tx).await.expect("commit");

    assert_ne!(
        first_id, second_id,
        "rotation must mint a new row, not update in place"
    );

    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM integration_credential WHERE system_ref = $1 AND is_deleted = FALSE",
    )
    .bind(system_id)
    .fetch_one(&db)
    .await
    .expect("count active");
    assert_eq!(
        active, 1,
        "exactly one credential row must remain active after rotation"
    );

    assert!(
        credential::resolve(&db, &ring, Some(&first_id.to_string()))
            .await
            .expect("resolve")
            .is_none(),
        "the superseded credential must no longer resolve"
    );
    assert_eq!(
        credential::resolve(&db, &ring, Some(&second_id.to_string()))
            .await
            .expect("resolve")
            .expect("must resolve")
            .with_value(str::to_owned),
        "second-secret-value"
    );
}

// ── Service-principal resolution (D-425) ────────────────────────────────────

#[tokio::test]
async fn service_principal_id_round_trips_the_stored_reference() {
    let user_id = Uuid::now_v7();
    let system = stub_system(user_id.to_string());
    assert_eq!(
        attome_integration::system::service_principal_id(&system).unwrap(),
        user_id
    );
}

#[tokio::test]
async fn service_principal_id_fails_closed_on_a_malformed_reference() {
    let system = stub_system("not-a-uuid".into());
    assert!(attome_integration::system::service_principal_id(&system).is_err());
}

/// The property `webhook.rs` depends on: a service principal resolves with
/// exactly the privileges granted to it — none by default, and the grant
/// (not the caller's say-so) is what turns `require("integration_event",
/// "create")` from a rejection into a pass. `resolve_uncached` is the same
/// DB-truth resolution `EngineSecurityResolver`'s cache warms from — this test
/// exercises the ungated path directly rather than fighting the L1/L2 cache
/// in a short-lived test process.
#[tokio::test]
async fn a_service_principal_without_the_grant_is_rejected_and_with_it_is_accepted() {
    let db = skip_if_no_db!(test_db().await);
    let principal = seed_systemuser(&db).await;

    let ctx_before = attome_security::resolve_uncached(&db, principal)
        .await
        .expect("resolve before grant");
    assert!(
        !ctx_before.privileges.contains("integration_event.create"),
        "a freshly-created service principal must start with no privileges"
    );
    use attome_security::SecurityContextExt;
    assert!(
        ctx_before.require("integration_event", "create").is_err(),
        "no grant yet -> the write must be rejected"
    );

    grant_privilege(&db, principal, "integration_event", "create").await;

    let ctx_after = attome_security::resolve_uncached(&db, principal)
        .await
        .expect("resolve after grant");
    assert!(ctx_after.privileges.contains("integration_event.create"));
    assert!(
        ctx_after.require("integration_event", "create").is_ok(),
        "granted -> the write must be accepted"
    );

    // Never satisfied by a DIFFERENT entity's grant — an integration scoped
    // to write one event type must not implicitly gain another.
    assert!(
        ctx_after.require("user_account", "delete").is_err(),
        "an unrelated grant must not leak into an unrelated privilege check"
    );
}
