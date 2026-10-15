//! Synchronizes the login credentials of the two P-db-privilege-separation
//! (D-117) PostgreSQL roles: `attome_migrator` (DDL) and `attome_runtime`
//! (DML-only).
//!
//! Migration `0042_migrator_runtime_roles.sql` creates both structurally
//! with NOLOGIN. The configured password is applied here at boot, same
//! D-094 reasoning as `readonly_role_seed`: credential material never lives
//! in checked-in migration SQL, and a secret rotation is picked up on the
//! next restart. Both functions below no-op when their config block
//! (`database.migrator` / `database.runtime`) isn't set — each identity is
//! entirely optional, and an unconfigured deployment keeps using
//! `database.user`/`.password` for everything, exactly as before this
//! feature existed.
//!
//! D-094/D-097: `ALTER ROLE ... PASSWORD` is a utility statement, not
//! preparable DML, so PostgreSQL rejects a `$1` bind parameter in it
//! directly. The secret is instead bound through `set_config` (a normal,
//! parameterized `SELECT`) inside the same transaction, then the fixed
//! `ALTER ROLE` command reads it back via `current_setting` and lets
//! PostgreSQL's own `%L` quoting embed it. Every fallible step below
//! constructs its own static error message rather than forwarding the
//! underlying `sqlx::Error`'s `Display`, for the same reason
//! `readonly_role_seed` does — keeping the log line static removes any
//! chance of the secret ending up adjacent to it in `AppError::internal`'s
//! `tracing::error!` call.

use attome_config::AppConfig;
use attome_db::DbPool;
use attome_types::AppError;

/// Grants LOGIN and applies the configured password to `attome_migrator`.
/// Must run on the schema-bootstrap connection (`main.rs`'s `migration_db`,
/// `database.user`) — that's the only identity guaranteed to already have
/// sufficient privilege to `ALTER ROLE` a role it (or migration 0042) just
/// created, and it must run BEFORE `attome_db::create_migrator_pool` is ever
/// built, since that pool tries to log in as `attome_migrator` directly.
pub async fn seed_migrator(db: &DbPool, config: &AppConfig) -> Result<(), AppError> {
    let Some(migrator) = &config.database.migrator else {
        return Ok(());
    };

    #[expect(
        clippy::disallowed_methods,
        reason = "boot-time role seed that deliberately replaces the driver error with a fixed message; not an HTTP path"
    )]
    let mut tx = db
        .begin()
        .await
        .map_err(|_| AppError::internal("db_role_seed: failed to open transaction (migrator)"))?;

    sqlx::query("SELECT set_config('attome.migrator_password', $1, true)")
        .bind(migrator.password.expose())
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::internal("db_role_seed: failed to stage migrator credential"))?;

    sqlx::query(
        r#"
        DO $$
        BEGIN
            EXECUTE format(
                'ALTER ROLE attome_migrator WITH LOGIN PASSWORD %L',
                current_setting('attome.migrator_password')
            );
        END
        $$;
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| AppError::internal("db_role_seed: failed to apply ALTER ROLE (migrator)"))?;

    tx.commit()
        .await
        .map_err(|_| AppError::internal("db_role_seed: failed to commit (migrator)"))?;

    tracing::info!("server: attome_migrator role credentials synced from config");
    Ok(())
}

/// Grants LOGIN and applies the configured password to `attome_runtime`.
/// Same bootstrap-connection requirement as `seed_migrator` — must run
/// before `attome_db::create_pool` is built (that pool connects as
/// `attome_runtime` as soon as `database.runtime` is configured).
pub async fn seed_runtime(db: &DbPool, config: &AppConfig) -> Result<(), AppError> {
    let Some(runtime) = &config.database.runtime else {
        return Ok(());
    };

    #[expect(
        clippy::disallowed_methods,
        reason = "boot-time role seed that deliberately replaces the driver error with a fixed message; not an HTTP path"
    )]
    let mut tx = db
        .begin()
        .await
        .map_err(|_| AppError::internal("db_role_seed: failed to open transaction (runtime)"))?;

    sqlx::query("SELECT set_config('attome.runtime_password', $1, true)")
        .bind(runtime.password.expose())
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::internal("db_role_seed: failed to stage runtime credential"))?;

    sqlx::query(
        r#"
        DO $$
        BEGIN
            EXECUTE format(
                'ALTER ROLE attome_runtime WITH LOGIN PASSWORD %L',
                current_setting('attome.runtime_password')
            );
        END
        $$;
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| AppError::internal("db_role_seed: failed to apply ALTER ROLE (runtime)"))?;

    tx.commit()
        .await
        .map_err(|_| AppError::internal("db_role_seed: failed to commit (runtime)"))?;

    tracing::info!("server: attome_runtime role credentials synced from config");
    Ok(())
}
