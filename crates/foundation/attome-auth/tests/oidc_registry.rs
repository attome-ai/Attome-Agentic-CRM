//! Q1-T3: a provider an administrator adds on screen signs in through the same
//! registry as a configured one. A row sealed under
//! `oidc.client_secret_encryption_key` loads with its secret opened; one
//! sealed under another key, or with no key ring configured, is left out.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test: a failed setup step should panic with its message"
)]

use std::collections::HashMap;

use attome_auth::envelope::{RowBinding, encrypt_bound};
use attome_auth::oidc_registry::{CLIENT_SECRET_FIELD, OidcRegistry, ProviderSource};
use attome_config::{KeyRing, OidcProviderConfig};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

fn ring(byte: &str) -> KeyRing {
    KeyRing::single(byte.repeat(32))
}

/// Inserts a provider row whose client secret is sealed under `sealing`.
async fn insert_provider(db: &DbPool, key: &str, secret: &str, sealing: &KeyRing) -> Uuid {
    let id = Uuid::now_v7();
    let sealed = encrypt_bound(
        CLIENT_SECRET_FIELD,
        sealing,
        secret,
        RowBinding {
            table: "oidc_provider",
            column: "client_secret_enc",
            row_id: id,
        },
    )
    .expect("seal the client secret");
    sqlx::query(
        "INSERT INTO oidc_provider (id, key, display_name, issuer, client_id, client_secret_enc, scopes) \
         VALUES ($1, $2, 'On screen', 'https://idp.example', 'client', $3, ARRAY['openid','email'])",
    )
    .bind(id)
    .bind(key)
    .bind(sealed)
    .execute(db)
    .await
    .expect("insert a provider");
    id
}

fn unique_key(prefix: &str) -> String {
    format!("{prefix}-{}", &Uuid::now_v7().simple().to_string()[20..])
}

#[tokio::test]
async fn a_database_provider_signs_in_through_the_registry() {
    let db = skip_if_no_db!(pool().await);
    let right = ring("ab");
    let key = unique_key("screen");
    let id = insert_provider(&db, &key, "the-client-secret", &right).await;
    let wrong_key = unique_key("wrong");
    insert_provider(&db, &wrong_key, "other", &ring("cd")).await;

    let configured: HashMap<String, OidcProviderConfig> = HashMap::from([(
        "configured".to_owned(),
        serde_json::from_value(serde_json::json!({
            "display_name": "Configured", "issuer": "https://config.example",
            "client_id": "c", "client_secret": "configured-secret-value",
        }))
        .unwrap(),
    )]);
    let registry = OidcRegistry::from_config(&configured, &HashMap::new());
    assert!(registry.get(&key).is_none(), "configuration only until a reload");

    registry
        .reload(&db, &configured, &HashMap::new(), &right)
        .await
        .expect("reload");
    let entry = registry.get(&key).expect("the on-screen provider");
    assert_eq!(entry.source, ProviderSource::Database);
    assert_eq!(entry.id, Some(id));
    assert_eq!(entry.config.client_secret.expose(), "the-client-secret");
    assert!(registry.get("configured").is_some());
    assert!(
        registry.get(&wrong_key).is_none(),
        "a secret sealed under another key is left out"
    );

    registry
        .reload(&db, &configured, &HashMap::new(), &KeyRing::default())
        .await
        .expect("reload without a ring");
    assert!(
        registry.get(&key).is_none(),
        "with no key ring only configured providers sign in"
    );
    assert!(registry.get("configured").is_some());
}
