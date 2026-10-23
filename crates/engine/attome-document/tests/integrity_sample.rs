//! Z6-T3: the weekly file sample reads stored files back from a local-disk
//! store and finds the one whose contents changed and the one that is gone.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@127.0.0.1:5556/postgres"
//! cargo test -p attome-document --test integrity_sample
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_document::integrity::{IntegrityStats, SampleScope, sample_check};
use attome_testkit::skip_if_no_db;
use object_store::local::LocalFileSystem;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStoreExt, PutPayload};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn pool() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect DATABASE_URL"),
    )
}

/// A user every version row names as its uploader.
async fn uploader(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, email, user_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("integrity-{id}@example.test"))
        .bind(format!("integrity-{id}"))
        .execute(db)
        .await
        .expect("insert the uploader");
    id
}

/// Records a version of `key` with the size and hash of `recorded`.
async fn version(db: &DbPool, by: Uuid, key: &str, recorded: &[u8]) {
    sqlx::query(
        "INSERT INTO file_version
            (entity, record_id, field, version_no, object_key, size, hash,
             content_type, uploaded_by, scan_status, is_current)
         VALUES ('integrity_test', $1, 'attachment', 1, $2, $3, $4,
                 'text/plain', $5, 'clean', true)",
    )
    .bind(Uuid::now_v7())
    .bind(key)
    .bind(recorded.len() as i64)
    .bind(hex::encode(Sha256::digest(recorded)))
    .bind(by)
    .execute(db)
    .await
    .expect("insert a file version");
}

#[tokio::test]
async fn integrity_sample_finds_the_corrupted_and_the_missing_file() {
    let db = skip_if_no_db!(pool().await);
    let dir = std::env::temp_dir().join(format!("attome-integrity-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = LocalFileSystem::new_with_prefix(&dir).unwrap();
    let prefix = format!("integrity/{}/", Uuid::now_v7());
    let by = uploader(&db).await;

    let good = format!("{prefix}good.txt");
    let corrupted = format!("{prefix}corrupted.txt");
    let missing = format!("{prefix}missing.txt");
    store
        .put(
            &ObjectPath::parse(&good).unwrap(),
            PutPayload::from_static(b"the contract, signed"),
        )
        .await
        .unwrap();
    // Uploaded as one thing, damaged on disk since.
    store
        .put(
            &ObjectPath::parse(&corrupted).unwrap(),
            PutPayload::from_static(b"the contract, sigNed"),
        )
        .await
        .unwrap();
    version(&db, by, &good, b"the contract, signed").await;
    version(&db, by, &corrupted, b"the contract, signed").await;
    version(&db, by, &missing, b"an invoice").await;

    let scope = SampleScope {
        limit: 10,
        key_prefix: Some(prefix),
    };
    let stats = sample_check(&db, &store, &scope).await.unwrap();
    assert_eq!(
        stats,
        IntegrityStats {
            checked: 3,
            mismatched: 1,
            missing: 1,
        }
    );

    let none = SampleScope {
        limit: 0,
        key_prefix: None,
    };
    assert_eq!(
        sample_check(&db, &store, &none).await.unwrap(),
        IntegrityStats::default()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
