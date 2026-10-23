//! S11-T1: the token endpoint's client directory over a real `s2s_client`
//! table: a client's live state, its key secrets (client_secret_basic) and
//! the one-use `jti` claim, then a token issued end to end.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@127.0.0.1:5555/attomedb_test"
//! cargo test -p attome-s2s --test oauth_directory -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::oauth_token::{self, ClientDirectory, Issuer, OAuthError, TokenRequest};
use attome_cache::Store;
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_s2s::crypto;
use attome_s2s::oauth_clients::PgClientDirectory;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn pool() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("connect DATABASE_URL"),
    )
}

/// An active client bound to a fresh service user, with one key; answers
/// its slug and the key's plain secret.
async fn client(db: &DbPool, ring: &KeyRing, scopes: &[&str]) -> (String, String, Uuid) {
    let user = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, email, user_name) VALUES ($1, $2, 'OAuth test')")
        .bind(user)
        .bind(format!("oauth-{user}@example.test"))
        .execute(db)
        .await
        .expect("insert service user");
    let id = Uuid::now_v7();
    let slug = format!("oauth-{id}");
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
    sqlx::query(
        "INSERT INTO s2s_client (id, name, client_id, status, service_user_ref, oauth_scopes)
         VALUES ($1, $2, $2, 'active', $3, $4)",
    )
    .bind(id)
    .bind(&slug)
    .bind(user)
    .bind(&scopes)
    .execute(db)
    .await
    .expect("insert client");
    let key_id = Uuid::now_v7();
    let secret = crypto::generate_secret();
    sqlx::query(
        "INSERT INTO s2s_client_key
             (id, client_ref, key_slot, public_id, secret_encrypted, secret_last4, status)
         VALUES ($1, $2, 'primary', $3, $4, $5, 'active')",
    )
    .bind(key_id)
    .bind(id)
    .bind(format!("pub-{key_id}"))
    .bind(crypto::encrypt_key_secret(ring, key_id, &secret).expect("encrypt"))
    .bind(&secret[secret.len() - 4..])
    .execute(db)
    .await
    .expect("insert key");
    (slug, secret, user)
}

fn ring() -> KeyRing {
    KeyRing::single("cc".repeat(32))
}

#[tokio::test]
async fn oauth_directory_reads_live_clients_and_secrets() {
    let db = skip_if_no_db!(pool().await);
    let ring = ring();
    let redis = Store::memory();
    let (slug, secret, user) = client(&db, &ring, &["records.read"]).await;
    let directory = PgClientDirectory {
        db: &db,
        redis: &redis,
        key_ring: &ring,
    };

    let found = directory.find(&slug).await.unwrap().expect("the client");
    assert!(found.active);
    assert_eq!(found.service_user_id, user);
    assert_eq!(found.scopes, vec!["records.read".to_owned()]);
    assert!(found.public_key_pem.is_none());
    assert!(directory.find("no-such-client").await.unwrap().is_none());

    assert!(directory.secret_matches(&slug, &secret).await.unwrap());
    assert!(
        !directory
            .secret_matches(&slug, &crypto::generate_secret())
            .await
            .unwrap()
    );

    assert!(directory.claim_jti(&slug, "j-1", 0).await.unwrap());
    assert!(
        !directory.claim_jti(&slug, "j-1", 0).await.unwrap(),
        "a jti is accepted once"
    );

    sqlx::query("UPDATE s2s_client SET status = 'suspended' WHERE client_id = $1")
        .bind(&slug)
        .execute(&db)
        .await
        .unwrap();
    assert!(!directory.find(&slug).await.unwrap().unwrap().active);
}

#[tokio::test]
async fn oauth_token_issued_with_a_key_secret() {
    let db = skip_if_no_db!(pool().await);
    let key_ring = ring();
    let jwt_ring = KeyRing::single("test-only-throwaway-secret-32-bytes-min".into());
    let redis = Store::memory();
    let (slug, secret, user) = client(&db, &key_ring, &["records.read", "records.write"]).await;
    let directory = PgClientDirectory {
        db: &db,
        redis: &redis,
        key_ring: &key_ring,
    };
    let at = Issuer {
        issuer: "attome-test",
        access_audience: "attome-test",
        token_audiences: &["attome-test"],
        ring: &jwt_ring,
        now: chrono::Utc::now().timestamp(),
    };
    let request = |secret: &str| TokenRequest {
        grant_type: "client_credentials".into(),
        scope: Some("records.read".into()),
        basic: Some((slug.clone(), secret.to_owned())),
        ..TokenRequest::default()
    };

    let issued = oauth_token::issue(&directory, &request(&secret), &at)
        .await
        .expect("a token");
    let claims = oauth_token::validate_access_token(
        &issued.access_token,
        &jwt_ring,
        "attome-test",
        "attome-test",
    )
    .unwrap();
    assert_eq!(claims.claims.sub, user);
    assert_eq!(claims.client_id, slug);
    assert_eq!(claims.scope, "records.read");

    assert_eq!(
        oauth_token::issue(&directory, &request("00ff"), &at).await,
        Err(OAuthError::InvalidClient)
    );
}
