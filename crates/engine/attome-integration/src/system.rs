//! Shared `integration_system` row-loading — used by [`crate::admin`],
//! [`crate::webhook`], and [`crate::adapters`] alike, so all three read the
//! same shape off the provisioned entity table via direct SQL rather than
//! the generic entity-read path (this crate is already the entity's owner;
//! see `model.rs`).
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IntegrationSystem {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub base_url: String,
    pub auth_type: String,
    pub credential_ref: Option<String>,
    pub rate_limit: Option<f64>,
    pub status: String,
    pub health_last_ok_at: Option<DateTime<Utc>>,
    pub health_last_error: Option<String>,
    pub service_principal_ref: String,
    pub config: Option<String>,
    pub row_version: i64,
}

const SELECT_COLUMNS: &str = "id, name, kind, base_url, auth_type, credential_ref, \
     rate_limit::float8 AS rate_limit, status, health_last_ok_at, health_last_error, \
     service_principal_ref, config, row_version";

pub async fn load(db: &DbPool, id: Uuid) -> Result<Option<IntegrationSystem>, AppError> {
    // M53 Phase 1 (Omnichannel, D-474) fix: `integration_system` is a
    // runtime-provisioned entity table (`ensure_entity`, mutable — see
    // `seed.rs`'s doc comment), so its soft-delete flag is `is_active`
    // (`attome-metadata/src/provision/table.rs::ensure_is_active`), not
    // `is_deleted` — that column has never existed on this table. Found
    // live: the M53 web-chat channel lookup (`server::omnichannel::
    // load_channel_system`, which calls this function) failed every request
    // with "column is_deleted does not exist" against a freshly provisioned
    // database. `IS NOT FALSE` (not a bare `= true`) so a legacy/NULL value
    // never silently hides an otherwise-active row, matching every other
    // provisioned-entity query in this codebase (e.g.
    // `attome_service::seed::entity_id_by_logicalname`).
    sqlx::query_as(&format!(
        "SELECT {SELECT_COLUMNS} FROM integration_system WHERE id = $1 AND is_active IS NOT FALSE"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Parses `service_principal_ref` (stored as `text` — see `seed.rs`'s doc
/// comment for why it isn't a `lookup` attribute) into a `Uuid`. A stored
/// value that fails to parse is an internal-consistency bug (the field is
/// validated at write time in `admin.rs`), not a caller error.
pub fn service_principal_id(system: &IntegrationSystem) -> Result<Uuid, AppError> {
    Uuid::parse_str(&system.service_principal_ref).map_err(|_| {
        AppError::internal(format!(
            "integration_system {} has a non-UUID service_principal_ref",
            system.id
        ))
    })
}

pub async fn ensure_service_principal_exists(db: &DbPool, user_id: Uuid) -> Result<(), AppError> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_account WHERE id = $1)")
            .bind(user_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::Validation(
            "service_principal_ref does not reference an existing system user".into(),
        ));
    }
    Ok(())
}
