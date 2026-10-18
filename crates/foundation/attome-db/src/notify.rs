//! Y8-T1: Postgres `LISTEN`, the doorbell that needs no Redis. A writer runs
//! `pg_notify(channel, payload)` inside its transaction, so the notice is
//! delivered only if the transaction commits; a node that listens hears it
//! on its own connection.
//!
//! `LISTEN` holds a session, so the listener connects to the
//! `database.direct_url` endpoint (never a transaction-mode pgbouncer) as the
//! runtime identity, exactly like [`crate::create_runtime_session`].

use attome_config::AppConfig;
use attome_types::AppError;
use sqlx::postgres::{PgListener, PgPoolOptions};

/// A listener on `channel`. `try_recv` answering `Ok(None)` means the
/// connection dropped and notices may have been missed.
pub async fn listen(config: &AppConfig, channel: &str) -> Result<PgListener, AppError> {
    let options = crate::runtime_session_options(
        config,
        attome_config::app_env().as_deref(),
        std::env::var("DATABASE_URL").ok().as_deref(),
    )
    .map_err(AppError::internal)?
    .application_name("attome-listener");
    // One connection, held by the listener for its life.
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .min_connections(0)
        .connect_lazy_with(options);
    let mut listener = PgListener::connect_with(&pool)
        .await
        .map_err(AppError::internal)?;
    listener.listen(channel).await.map_err(AppError::internal)?;
    Ok(listener)
}
