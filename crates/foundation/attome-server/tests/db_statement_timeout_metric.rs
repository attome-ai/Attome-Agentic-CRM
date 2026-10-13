//! attome-db plan 3.1b — `build_layer_and_handle` installs attome-db's
//! statement-timeout hook, so a `57014` that reaches `attome_db::classify` shows
//! up as `db_statement_timeouts_total`.
//!
//! Its own test binary because the recorder and the hook are process-wide and
//! install once. Needs a live PostgreSQL through `DATABASE_URL` (a real `57014`
//! cannot be constructed by hand); skips when unset. Run:
//! `cargo test -p attome-server --test db_statement_timeout_metric`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_server::build_layer_and_handle;
use attome_types::AppError;
use sqlx::{Connection, PgConnection};

#[tokio::test]
async fn a_statement_timeout_increments_the_counter() {
    let Some(url) = attome_testkit::migrated_db_url() else {
        eprintln!("SKIP: set DATABASE_URL to a throwaway test database (NEVER attome_dev)");
        return;
    };
    let (_layer, handle) = build_layer_and_handle();

    let mut conn = PgConnection::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    sqlx::query("SET statement_timeout = '1ms'")
        .execute(&mut conn)
        .await
        .expect("set a 1ms statement_timeout");
    let err = sqlx::query("SELECT pg_sleep(0.1)")
        .execute(&mut conn)
        .await
        .expect_err("a 1ms statement_timeout must cancel a 100ms sleep");

    match attome_db::classify(err) {
        AppError::Internal(_) => {}
        other => panic!("SQLSTATE 57014 must stay a masked Internal, got {other:?}"),
    }

    let rendered = handle.render();
    assert!(
        rendered.contains("db_statement_timeouts_total 1"),
        "expected exactly one counted statement timeout, got:\n{rendered}"
    );
}
