//! Integration tests for `attome_service::portal` — the self-service portal's
//! business logic (the HTTP bypass handlers live in `attome-api` and are
//! exercised by that crate's own tests). Covers the checklist's required
//! case directly: the public status lookup leaks nothing beyond status for
//! a wrong/valid token.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use attome_service::portal::{list_public_offerings, lookup_status};
use attome_service::token;
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

/// The pepper ring portal tokens hash with (attome-auth hardening 1.4, D-500).
fn test_ring() -> attome_auth::PepperRing {
    attome_auth::PepperRing::new(0, "attome-service-test-pepper-0123456789abcdef", &[])
}

async fn ensure_seeded(db: &DbPool) {
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    attome_project::seed::seed_for_tests(db)
        .await
        .expect("attome_project::seed::seed");
    attome_service::seed::seed_for_tests(db)
        .await
        .expect("attome_service::seed::seed");
}

async fn insert_offering(db: &DbPool, name: &str, is_public: bool, is_active: bool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_offering \
         (id, name, category, default_priority, fulfilment, is_public, is_active) \
         VALUES ($1, $2, 'it', 'medium', 'ticket', $3, $4)",
    )
    .bind(id)
    .bind(name)
    .bind(is_public)
    .bind(is_active)
    .execute(db)
    .await
    .expect("insert service_offering");
    id
}

/// Inserts a work request carrying a real portal token, returning
/// `(work_request_id, bearer)`.
async fn insert_work_request_with_token(db: &DbPool, title: &str, status: &str) -> (Uuid, String) {
    let issued = token::issue(&test_ring()).await.expect("token::issue");
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_work_request \
         (id, title, description, request_type, status, portal_public_id, portal_secret_hash) \
         VALUES ($1, $2, 'a test work request', 'it_request', $3, $4, $5)",
    )
    .bind(id)
    .bind(title)
    .bind(status)
    .bind(issued.public_id.to_string())
    .bind(&issued.secret_hash)
    .execute(db)
    .await
    .expect("insert service_work_request");
    (id, issued.bearer)
}

/// A work request created via plain generic CRUD, with no portal token at
/// all — must behave exactly like "no such token" for any bearer presented
/// against it, never a 500 or a different response shape.
async fn insert_work_request_without_token(db: &DbPool, title: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_work_request (id, title, description, request_type, status) \
         VALUES ($1, $2, 'no portal token on this one', 'it_request', 'new')",
    )
    .bind(id)
    .bind(title)
    .execute(db)
    .await
    .expect("insert service_work_request");
    id
}

#[tokio::test]
async fn a_valid_token_returns_status_and_nothing_else() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let (_id, bearer) = insert_work_request_with_token(&db, "Check my request", "new").await;

    let status = lookup_status(&db, &bearer, &test_ring())
        .await
        .expect("lookup_status")
        .expect("a valid token must resolve");
    assert_eq!(status.title, "Check my request");
    assert_eq!(status.status, "new");
    assert_eq!(status.resolved_entity_name, None);
}

#[tokio::test]
async fn a_wrong_secret_with_a_real_public_id_resolves_to_none() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let (_id, bearer) = insert_work_request_with_token(&db, "Real request", "new").await;
    let (public_id, _real_secret) = token::parse_bearer(&bearer).expect("parse_bearer");
    let forged = format!("{public_id}.wrong-secret-entirely");

    assert!(
        lookup_status(&db, &forged, &test_ring())
            .await
            .expect("lookup_status")
            .is_none(),
        "a wrong secret against a real public_id must not resolve"
    );
}

#[tokio::test]
async fn an_unknown_public_id_resolves_to_none() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let bearer = format!("{}.any-secret", Uuid::now_v7());
    assert!(
        lookup_status(&db, &bearer, &test_ring())
            .await
            .expect("lookup_status")
            .is_none()
    );
}

#[tokio::test]
async fn a_malformed_bearer_resolves_to_none_without_erroring() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    for malformed in ["no-dot-separator", "", "not-a-uuid.secret"] {
        assert!(
            lookup_status(&db, malformed, &test_ring())
                .await
                .expect("lookup_status must not error on malformed input")
                .is_none(),
            "{malformed:?} must resolve to None"
        );
    }
}

#[tokio::test]
async fn a_work_request_created_without_a_portal_token_never_resolves() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let _id = insert_work_request_without_token(&db, "No token on this one").await;
    // Presenting a well-formed but entirely unrelated bearer must still miss
    // — there is no secret_hash on this row for anything to verify against.
    let bearer = format!("{}.any-secret", Uuid::now_v7());
    assert!(
        lookup_status(&db, &bearer, &test_ring())
            .await
            .expect("lookup_status")
            .is_none()
    );
}

/// D-500: portal tokens are stored as peppered HMAC, and a work request whose
/// token was hashed any other way (here Argon2) does not resolve.
#[tokio::test]
async fn new_tokens_are_hmac_and_an_argon2_token_does_not_resolve() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let issued = token::issue(&test_ring()).await.expect("token::issue");
    assert!(
        issued.secret_hash.starts_with("hmac256"),
        "a new portal token must be stored as peppered HMAC, got {}",
        issued.secret_hash
    );

    let legacy_public_id = Uuid::now_v7();
    let legacy_secret = "legacy-argon2-portal-secret-0123456789";
    let legacy_hash = attome_auth::password::hash_password_async(
        attome_auth::NewPassword::platform_generated(legacy_secret),
    )
    .await
    .expect("hash");
    sqlx::query(
        "INSERT INTO service_work_request \
         (id, title, description, request_type, status, portal_public_id, portal_secret_hash) \
         VALUES ($1, 'Legacy token request', 'hashed before D-500', 'it_request', 'new', $2, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(legacy_public_id.to_string())
    .bind(&legacy_hash)
    .execute(&db)
    .await
    .expect("insert a work request with a legacy Argon2 token");

    let status = lookup_status(
        &db,
        &format!("{legacy_public_id}.{legacy_secret}"),
        &test_ring(),
    )
    .await;
    assert!(
        !matches!(status, Ok(Some(_))),
        "an Argon2 portal token must not resolve"
    );
}

#[tokio::test]
async fn the_public_offering_list_only_returns_public_active_offerings() {
    let db = skip_if_no_db!(test_db().await);
    ensure_seeded(&db).await;

    let public_active = insert_offering(&db, "Public Active Offering", true, true).await;
    insert_offering(&db, "Private Offering", false, true).await;
    insert_offering(&db, "Public Inactive Offering", true, false).await;

    let offerings = list_public_offerings(&db)
        .await
        .expect("list_public_offerings");
    let ids: Vec<Uuid> = offerings.iter().map(|o| o.id).collect();

    assert!(ids.contains(&public_active));
    assert_eq!(
        offerings.len(),
        1,
        "only the public, active offering must be listed, got: {offerings:?}"
    );
}
