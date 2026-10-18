//! D-130's §6 rotate-then-rewrap scenario for `s2s.key_encryption_key`, run
//! live against a real Postgres: a client secret encrypted under key A must
//! still verify (decrypt + HMAC) after key B is added and made active, then
//! converge onto key B via the rewrap job, then keep verifying once key A is
//! retired from the ring entirely.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@127.0.0.1:5555/attomedb_test"
//! cargo test -p attome-s2s --test key_rotation -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::KeyRing;
use attome_db::DbPool;
use attome_s2s::crypto;
use attome_testkit::skip_if_no_db;
use hmac::Mac;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
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

/// Fetches the stored `secret_encrypted` for `key_id`, decrypts it under
/// `ring`, asserts it matches `expected_plain`, and proves an HMAC signed
/// with the decrypted secret verifies -- the actual thing an S2S request
/// depends on, not just "decrypt returns something." Returns the raw
/// still-encoded blob so the caller can inspect which key id it names.
async fn verify_current_row_hmac(
    db: &DbPool,
    key_id: Uuid,
    ring: &KeyRing,
    expected_plain: &str,
) -> String {
    let stored: String =
        sqlx::query_scalar("SELECT secret_encrypted FROM s2s_client_key WHERE id = $1")
            .bind(key_id)
            .fetch_one(db)
            .await
            .expect("fetch secret_encrypted");
    let decrypted = crypto::decrypt_key_secret(ring, key_id, &stored).expect("decrypt");
    assert_eq!(decrypted, expected_plain);

    let message =
        crypto::canonical_message("POST", "/api/v1/s2s/test", "body-hash", "123", "nonce-1");
    let secret_bytes = hex::decode(&decrypted).expect("secret must be hex");
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&secret_bytes)
        .expect("hmac accepts any key len");
    mac.update(&message);
    let sig = hex::encode(mac.finalize().into_bytes());
    assert!(crypto::verify_hmac(&decrypted, &message, &sig));
    stored
}

#[tokio::test]
async fn rotating_the_s2s_key_encryption_key_survives_rewrap_and_retirement() {
    let db = skip_if_no_db!(pool().await);
    let key_a = "aa".repeat(32);
    let key_b = "bb".repeat(32);
    let mut ring = KeyRing {
        keys: std::iter::once(("key-a".to_string(), key_a)).collect(),
        active_key_id: "key-a".to_string(),
    };

    let client_id = Uuid::now_v7();
    let plain_secret = crypto::generate_secret();
    let secret_encrypted = crypto::encrypt_secret(&ring, &plain_secret).expect("encrypt");

    sqlx::query(
        "INSERT INTO s2s_client (id, name, client_id, status)
         VALUES ($1, $2, $2, 'active')",
    )
    .bind(client_id)
    .bind(format!("key-rotation-test-{client_id}"))
    .execute(&db)
    .await
    .expect("insert test client");

    // Keyset cursor taken immediately BEFORE this test's key row is inserted.
    // `rewrap_secrets`' third argument is `after_id` (`WHERE id > $1`), not a
    // client filter: passing `None` scans every `s2s_client_key` row in
    // the database. That is correct for the maintenance job, but it made this
    // test pass only against a database no earlier run had touched — on a
    // rerun it picked up the previous run's rows, still wrapped under that
    // run's throwaway ring, and died with "s2s.key_encryption_key decryption
    // failed" (F-006/TODO-008). UUIDv7 is time-ordered, so `id > cursor`
    // scopes both passes below to the row this test owns.
    let cursor = Uuid::now_v7();
    let key_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO s2s_client_key
             (id, client_ref, key_slot, public_id, secret_encrypted, secret_last4, status)
         VALUES ($1, $2, 'primary', $3, $4, $5, 'active')",
    )
    .bind(key_id)
    .bind(client_id)
    .bind(format!("pub-{key_id}"))
    .bind(&secret_encrypted)
    .bind(&plain_secret[plain_secret.len() - 4..])
    .execute(&db)
    .await
    .expect("insert test client key");

    let stored_before = verify_current_row_hmac(&db, key_id, &ring, &plain_secret).await;
    assert_eq!(
        attome_auth::envelope::stored_key_id(&stored_before).as_deref(),
        Some("key-a")
    );

    // Add key B, flip active -- pre-rewrap, the row still names key A, which
    // the ring still holds.
    ring.keys.insert("key-b".to_string(), key_b);
    ring.active_key_id = "key-b".to_string();
    verify_current_row_hmac(&db, key_id, &ring, &plain_secret).await;

    // `batch_size` 1: with the cursor above, that is exactly this test's row,
    // so a suite running concurrently in another test binary cannot pull its
    // own differently-wrapped row into this batch.
    let progress = attome_s2s::rewrap::rewrap_secrets(&db, &ring, Some(cursor), 1)
        .await
        .expect("rewrap");
    assert_eq!(progress.rewrapped, 1);

    let stored_after = verify_current_row_hmac(&db, key_id, &ring, &plain_secret).await;
    assert_eq!(
        attome_auth::envelope::stored_key_id(&stored_after).as_deref(),
        Some("key-b")
    );

    // Idempotent second pass.
    let progress2 = attome_s2s::rewrap::rewrap_secrets(&db, &ring, Some(cursor), 1)
        .await
        .expect("rewrap again");
    assert_eq!(progress2.rewrapped, 0);

    // Retire key A -- HMAC verification must still succeed on key B alone.
    ring.keys.remove("key-a");
    verify_current_row_hmac(&db, key_id, &ring, &plain_secret).await;
}
