//! Synchronizes the SELECT-only PostgreSQL role's login credential.
//!
//! Migration 0010 creates `attome_readonly` structurally with NOLOGIN. The
//! configured password is applied here at boot so credential material never
//! lives in checked-in migration SQL. This is intentionally idempotent: a
//! secret rotation is picked up on the next restart.
//!
//! D-094/D-097: `ALTER ROLE ... PASSWORD` is a utility statement, not
//! preparable DML, so PostgreSQL rejects a `$1` bind parameter in it
//! directly. The secret is instead bound through `set_config` (a normal,
//! parameterized `SELECT`) inside the same transaction, then the fixed
//! `ALTER ROLE` command reads it back via `current_setting` and lets
//! PostgreSQL's own `%L` quoting embed it — this is the one sanctioned
//! exception to "values always bound" (coding-guidelines.md §4), scoped
//! narrowly to this statement class. Every fallible step below constructs
//! its own static error message rather than forwarding the underlying
//! `sqlx::Error`'s `Display` — `AppError::internal` logs whatever it's given
//! via `tracing::error!`, and a `sqlx::Error` arising from this specific
//! transaction is the one place in the codebase where that log line could
//! end up adjacent to the secret; keeping the log line static removes that
//! risk without changing the shared `AppError::internal` helper.

use attome_config::AppConfig;
use attome_db::DbPool;
use attome_types::AppError;

/// Grants LOGIN and applies the configured password to `attome_readonly`.
pub async fn seed(db: &DbPool, config: &AppConfig) -> Result<(), AppError> {
    let Some(readonly) = &config.database.readonly else {
        // D-038's fail-closed check remains in main.rs/create_readonly_pool:
        // debug may omit this block, while non-debug environments cannot.
        return Ok(());
    };

    #[expect(
        clippy::disallowed_methods,
        reason = "boot-time role seed that deliberately replaces the driver error with a fixed message; not an HTTP path"
    )]
    let mut tx = db
        .begin()
        .await
        .map_err(|_| AppError::internal("readonly_role_seed: failed to open transaction"))?;

    sqlx::query("SELECT set_config('attome.readonly_password', $1, true)")
        .bind(readonly.password.expose())
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::internal("readonly_role_seed: failed to stage credential"))?;

    sqlx::query(
        r#"
        DO $$
        BEGIN
            EXECUTE format(
                'ALTER ROLE attome_readonly WITH LOGIN PASSWORD %L',
                current_setting('attome.readonly_password')
            );
        END
        $$;
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| AppError::internal("readonly_role_seed: failed to apply ALTER ROLE"))?;

    tx.commit()
        .await
        .map_err(|_| AppError::internal("readonly_role_seed: failed to commit"))?;

    tracing::info!("server: attome_readonly role credentials synced from config");
    Ok(())
}
