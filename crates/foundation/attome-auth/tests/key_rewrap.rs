//! Q18-T4: after a rotation in two domains, the rewrap job reseals every
//! row of each registered column under its ring's new key, records its
//! progress, resumes a run stopped part-way, and leaves a column whose
//! domain has no ring alone.
//!
//! Two throwaway tables stand in for registry columns (a bound text column
//! and a bytea column sealed against its row), in a throwaway database.
//!
//! ```powershell
//! cargo test -p attome-auth --test key_rewrap -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::HashMap;

use attome_auth::encrypted_columns::{EncryptedColumn, Sealing};
use attome_auth::envelope::{self, RowBinding};
use attome_auth::key_rewrap::rewrap_columns;
use attome_config::KeyRing;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use uuid::Uuid;

async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

fn ring(keys: &[(&str, &str)], active: &str) -> KeyRing {
    KeyRing {
        keys: keys
            .iter()
            .map(|(id, hex)| ((*id).to_owned(), (*hex).to_owned()))
            .collect::<HashMap<_, _>>(),
        active_key_id: active.to_owned(),
    }
}

const A_OLD: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const A_NEW: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const B_OLD: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const B_NEW: &str = "4444444444444444444444444444444444444444444444444444444444444444";

#[tokio::test]
async fn rewrap_all_converges_two_domains_and_resumes() {
    let db = skip_if_no_db!(pool().await);
    let suffix = Uuid::now_v7().simple().to_string();
    let text_table: &'static str = Box::leak(format!("rw_text_{suffix}").into_boxed_str());
    let bytes_table: &'static str = Box::leak(format!("rw_bytes_{suffix}").into_boxed_str());
    for sql in [
        format!("CREATE TABLE {text_table} (id uuid PRIMARY KEY, secret text)"),
        format!("CREATE TABLE {bytes_table} (id uuid PRIMARY KEY, secret bytea)"),
    ] {
        sqlx::query(&sql).execute(&db).await.unwrap();
    }
    let text_col = EncryptedColumn {
        table: text_table,
        column: "secret",
        domain: "alpha",
        key: "id",
        sealing: Sealing::Text,
    };
    let bytes_col = EncryptedColumn {
        table: bytes_table,
        column: "secret",
        domain: "beta",
        key: "id",
        sealing: Sealing::BytesPrefixedKey("rw/v1:"),
    };
    let unconfigured = EncryptedColumn {
        domain: "gamma",
        ..bytes_col
    };

    // Seven rows each, sealed under the old keys.
    let alpha_old = ring(&[("a1", A_OLD)], "a1");
    let beta_old = ring(&[("b1", B_OLD)], "b1");
    let mut ids = Vec::new();
    for i in 0..7 {
        let id = Uuid::now_v7();
        ids.push(id);
        let binding = RowBinding {
            table: text_table,
            column: "secret",
            row_id: id,
        };
        let text = envelope::encrypt_bound("t", &alpha_old, &format!("text-{i}"), binding).unwrap();
        let bytes = envelope::encrypt_bytes_with_aad(
            "b",
            &beta_old,
            format!("bytes-{i}").as_bytes(),
            format!("rw/v1:{id}").as_bytes(),
        )
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO {text_table} (id, secret) VALUES ($1, $2)"
        ))
        .bind(id)
        .bind(text)
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO {bytes_table} (id, secret) VALUES ($1, $2)"
        ))
        .bind(id)
        .bind(bytes)
        .execute(&db)
        .await
        .unwrap();
    }

    // Both domains rotate: the new key is active, the old one still held.
    let alpha = ring(&[("a1", A_OLD), ("a2", A_NEW)], "a2");
    let beta = ring(&[("b1", B_OLD), ("b2", B_NEW)], "b2");
    let rings = |domain: &str| match domain {
        "alpha" => Some(alpha.clone()),
        "beta" => Some(beta.clone()),
        _ => None,
    };

    // A run stopped after one batch of three (as a restart would leave it).
    sqlx::query(
        "INSERT INTO key_rewrap_progress (table_name, column_name, domain, last_key, scanned) \
         VALUES ($1, 'secret', 'alpha', $2, 3)",
    )
    .bind(text_table)
    .bind(ids[2].to_string())
    .execute(&db)
    .await
    .unwrap();

    let report = rewrap_columns(&db, &[text_col, bytes_col, unconfigured], rings, 3)
        .await
        .unwrap();
    assert_eq!(report.skipped, vec![unconfigured], "no ring, left alone");
    let (_, text_totals) = &report.columns[0];
    assert_eq!(text_totals.scanned, 4, "resumed after the third row");
    assert_eq!(text_totals.rewrapped, 4);
    let (_, bytes_totals) = &report.columns[1];
    assert_eq!(
        (
            bytes_totals.scanned,
            bytes_totals.rewrapped,
            bytes_totals.failed
        ),
        (7, 7, 0)
    );

    // The resumed run left the first three text rows under the old key; a
    // fresh run (the column finished) converges them too.
    let report = rewrap_columns(&db, &[text_col], rings, 3).await.unwrap();
    assert_eq!(report.columns[0].1.rewrapped, 3);

    for (i, id) in ids.iter().enumerate() {
        let text: String =
            sqlx::query_scalar(&format!("SELECT secret FROM {text_table} WHERE id = $1"))
                .bind(id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(envelope::stored_key_id(&text).as_deref(), Some("a2"));
        let binding = RowBinding {
            table: text_table,
            column: "secret",
            row_id: *id,
        };
        assert_eq!(
            envelope::decrypt_bound("t", &alpha, &text, binding)
                .unwrap()
                .into_exposed(),
            format!("text-{i}")
        );
        let bytes: Vec<u8> =
            sqlx::query_scalar(&format!("SELECT secret FROM {bytes_table} WHERE id = $1"))
                .bind(id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(envelope::stored_key_id_bytes(&bytes).as_deref(), Some("b2"));
        // The old keys can now leave the rings.
        let beta_new_only = ring(&[("b2", B_NEW)], "b2");
        assert_eq!(
            envelope::decrypt_bytes_with_aad(
                "b",
                &beta_new_only,
                &bytes,
                format!("rw/v1:{id}").as_bytes()
            )
            .unwrap(),
            format!("bytes-{i}").into_bytes()
        );
    }

    let finished: Vec<(String, bool)> = sqlx::query_as(
        "SELECT table_name, finished_at IS NOT NULL FROM key_rewrap_progress \
         WHERE table_name IN ($1, $2) ORDER BY table_name",
    )
    .bind(text_table)
    .bind(bytes_table)
    .fetch_all(&db)
    .await
    .unwrap();
    assert!(finished.iter().all(|(_, done)| *done), "{finished:?}");

    // Nothing left: a further run rewraps nothing.
    let report = rewrap_columns(&db, &[text_col, bytes_col], rings, 3)
        .await
        .unwrap();
    assert_eq!(report.totals().rewrapped, 0);

    for table in [text_table, bytes_table] {
        sqlx::query(&format!("DROP TABLE {table}"))
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM key_rewrap_progress WHERE table_name = $1")
            .bind(table)
            .execute(&db)
            .await
            .unwrap();
    }
}
