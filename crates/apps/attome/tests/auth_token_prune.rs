//! attome-auth plan BAU-13a/13b — the `PruneAuthTokens` job handler
//! (`attome::jobs::prune_auth_tokens`) removes single-use tokens whose
//! `expires_at` passed more than `AUTH_TOKEN_PRUNE_RETENTION_SECS` ago, and
//! keeps anything younger, used or not. The per-query safety (live refresh
//! families, racing redeems) is proven in attome-auth's own suites; this proves
//! the job drives every table with the right window.
//!
//! Requires a throwaway database (NEVER attome_dev); skips when unset.
//! Run: `cargo test -p server --test auth_token_prune -- --test-threads=1`

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use uuid::Uuid;

async fn seed_user(db: &sqlx::PgPool) -> (Uuid, String) {
    let id = Uuid::now_v7();
    let email = format!("auth-prune-test-{id}@example.invalid");
    sqlx::query(
        "INSERT INTO user_account (id, email, created_at, is_active) VALUES ($1, $2, now(), true)",
    )
    .bind(id)
    .bind(&email)
    .execute(db)
    .await
    .expect("seed test user");
    (id, email)
}

/// The throwaway clone, with the platform schema on the search path (the raw
/// testkit pool has only `public`).
async fn schema_pool() -> Option<sqlx::PgPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    sqlx::query("SET search_path TO attome_dev, public")
                        .execute(conn)
                        .await
                        .map(|_| ())
                })
            })
            .connect(&url)
            .await
            .expect("connect to the throwaway database"),
    )
}

#[tokio::test]
async fn the_job_prunes_every_single_use_table_past_retention_only() {
    let db = skip_if_no_db!(schema_pool().await);
    let (user_id, email) = seed_user(&db).await;
    let retention = attome::jobs::AUTH_TOKEN_PRUNE_RETENTION_SECS;
    const DAY: i64 = 86_400;
    // (expires_at offset from now in seconds, expected to survive)
    let cases: [(i64, bool); 3] = [(DAY, true), (-DAY, true), (-(retention + DAY), false)];

    let mut seeded = Vec::new();
    for table in [
        "password_reset_token",
        "email_verification_token",
        "invitation_token",
    ] {
        for (offset, survives) in cases {
            let id = Uuid::now_v7();
            let result = if table == "invitation_token" {
                sqlx::query(&format!(
                    "INSERT INTO {table} (id, email, invited_by_ref, public_id, secret_hash, expires_at)
                     VALUES ($1, $2, $3, $4, 'x', NOW() + make_interval(secs => $5::float8))"
                ))
                .bind(id)
                .bind(&email)
                .bind(user_id)
                .bind(Uuid::now_v7())
                .bind(offset)
                .execute(&db)
                .await
            } else {
                sqlx::query(&format!(
                    "INSERT INTO {table} (id, user_ref, public_id, secret_hash, expires_at)
                     VALUES ($1, $2, $3, 'x', NOW() + make_interval(secs => $4::float8))"
                ))
                .bind(id)
                .bind(user_id)
                .bind(Uuid::now_v7())
                .bind(offset)
                .execute(&db)
                .await
            };
            result.unwrap_or_else(|e| panic!("insert into {table}: {e}"));
            seeded.push((table, id, offset, survives));
        }
    }

    attome::jobs::prune_auth_tokens(&db)
        .await
        .expect("prune_auth_tokens");

    for (table, id, offset, survives) in seeded {
        let present: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM {table} WHERE id = $1)"
        ))
        .bind(id)
        .fetch_one(&db)
        .await
        .expect("look the row up");
        assert_eq!(
            present,
            survives,
            "{table}: a row expiring at now{offset:+}s must {} the prune",
            if survives { "survive" } else { "not survive" }
        );
    }
}
