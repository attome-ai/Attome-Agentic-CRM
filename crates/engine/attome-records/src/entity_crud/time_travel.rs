//! A1-T10: time travel, opt-in per entity.
//!
//! An entity with time travel on keeps every earlier version of its records.
//! Before an update or a delete changes a row, the row as it stands (all of
//! it, `to_jsonb`) is copied into the entity's history table
//! (`<entity>__history`) in the writer's own transaction ([`capture`]), valid
//! from its `modified_at` (else `created_at`) until the moment of the write.
//! The table is provisioned when time travel is switched on and partitioned
//! by month on `valid_to`; the partition job ([`maintain`]) keeps
//! [`HISTORY_MONTHS_AHEAD`] months of partitions ahead and drops the months
//! past the entity's retention, except while a legal hold names the entity
//! or one of its records.
//!
//! **Reading.** `GET /api/v1/{entity}/{id}?as_of=<RFC 3339>` answers the
//! version valid at that moment, after the ordinary read check on the record
//! as it is now. The old row goes through the same projection as a live read
//! (`jsonb_populate_record` over the table's own row type), so field grants,
//! masking and the full-read log apply to old values exactly as to current
//! ones. A moment before the earliest kept version (before time travel was
//! on, or before the record existed) is 404.
//!
//! **Restoring.** `POST /api/v1/{entity}/{id}/restore-version` writes the
//! values of the version valid at `as_of` back through the ordinary update
//! (`If-Match` required), so rules, validation and audit run as for any
//! edit. Only values that differ from the current ones are written; computed
//! and encrypted fields, and fields the caller may not read or write, are
//! never restored (422 when named).
//!
//! **Settings.** `GET`/`PUT /api/v1/admin/time-travel/{entity}`, kept in
//! `entity_time_travel` (migration 0339) beside the entity rather than in
//! its metadata row, like the search settings. The history is not chained
//! into the audit chain: each change's audit event stays where it is.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::{AttrInfo, EngineState, quote_ident};
use attome_db::DbPool;
use attome_security::SecurityContextExt;
use attome_security::record_action::Update;
use attome_server::authz::{Authorized, Privilege, RecordScoped, area};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::HeaderMap,
};
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::{Postgres, Transaction};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::access::require_record_read;
use super::mutations::{RowSource, project_row, read_record_projection};
use super::resolve::resolve_entity;
use super::response::EntityRecordResponse;

/// Months of history partitions kept ahead of today.
pub const HISTORY_MONTHS_AHEAD: u32 = 12;

/// Storage parameters of a history partition: rows are only inserted.
const HISTORY_STORAGE_PARAMS: &str =
    "fillfactor = 100, autovacuum_vacuum_insert_scale_factor = 0.02";

/// The longest retention accepted, about 100 years.
pub const MAX_RETENTION_DAYS: i32 = 36_500;

/// `?as_of=` on a record read.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AsOfParam {
    /// A1-T10: read the version of the record valid at this moment (RFC 3339,
    /// UTC), on an entity with time travel on.
    #[serde(default)]
    pub as_of: Option<DateTime<Utc>>,
}

/// An entity's time-travel settings.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TimeTravelSettings {
    pub entity: String,
    /// Whether earlier versions are kept.
    pub enabled: bool,
    /// Days a version is kept after it was replaced; `None` keeps it for ever.
    pub retention_days: Option<i32>,
    /// `0` until the settings are first saved; send it as `If-Match`.
    pub row_version: i64,
}

/// The settings to save.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct TimeTravelBody {
    pub enabled: bool,
    /// 1 to 36,500; absent keeps versions for ever.
    #[serde(default)]
    pub retention_days: Option<i32>,
}

/// What to restore.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RestoreVersionBody {
    /// The moment whose version to restore (RFC 3339, UTC).
    pub as_of: DateTime<Utc>,
    /// Only these attributes; every restorable one when absent.
    #[serde(default)]
    pub attributes: Option<Vec<String>>,
}

/// Whether `entity` has time travel on.
pub async fn is_enabled<'e, E>(executor: E, entity: &str) -> Result<bool, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM entity_time_travel \
          WHERE entity_logicalname = $1 AND enabled)",
    )
    .bind(entity)
    .fetch_one(executor)
    .await
    .map_err(AppError::internal)
}

/// Copies the live row `record_id` of `entity` into its history table, valid
/// until now, when the entity has time travel on; nothing otherwise. Runs
/// in the writer's transaction, before the row changes, so a rolled-back
/// write leaves no version behind.
pub async fn capture(
    tx: &mut Transaction<'_, Postgres>,
    entity: &str,
    record_id: Uuid,
    changed_by: Option<Uuid>,
) -> Result<(), AppError> {
    if !is_enabled(&mut **tx, entity).await? {
        return Ok(());
    }
    let Some(history) = attome_metadata::provision::history_table_name(entity) else {
        return Ok(());
    };
    let sql = format!(
        "INSERT INTO {h} (id, valid_from, valid_to, row_version, changed_by, data) \
         SELECT t.id, COALESCE(t.modified_at, t.created_at, now()), now(), t.row_version, $2, \
                to_jsonb(t) \
           FROM {t} t WHERE t.id = $1 AND t.is_active = true",
        h = quote_ident(&history),
        t = quote_ident(entity)
    );
    sqlx::query(&attome_db::tag_dynamic("entity.time_travel", &sql))
        .bind(record_id)
        .bind(changed_by)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// The version of a record valid at a moment.
#[derive(Debug, Clone, PartialEq)]
enum Version {
    /// The live row is that version.
    Current,
    /// An earlier version, its whole row.
    Earlier(Value),
}

/// The version of `record_id` valid at `at`. 422 when the entity has no
/// time travel, 404 when the record is gone or no version is kept for `at`.
async fn version_at(
    db: &DbPool,
    entity: &str,
    record_id: Uuid,
    at: DateTime<Utc>,
) -> Result<Version, AppError> {
    if !is_enabled(db, entity).await? {
        return Err(AppError::Validation(format!(
            "time travel is not on for {entity}"
        )));
    }
    let history = attome_metadata::provision::history_table_name(entity)
        .ok_or_else(|| AppError::Validation(format!("time travel is not on for {entity}")))?;
    let current_from: Option<Option<DateTime<Utc>>> = sqlx::query_scalar(&attome_db::tag_dynamic(
        "entity.time_travel",
        &format!(
            "SELECT COALESCE(modified_at, created_at) FROM {t} WHERE id = $1 AND is_active = true",
            t = quote_ident(entity)
        ),
    ))
    .bind(record_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(current_from) = current_from else {
        return Err(AppError::NotFound);
    };
    if current_from.is_none_or(|from| from <= at) {
        return Ok(Version::Current);
    }
    let image: Option<Value> = sqlx::query_scalar(&attome_db::tag_dynamic(
        "entity.time_travel",
        &format!(
            "SELECT data FROM {h} WHERE id = $1 AND valid_from <= $2 AND valid_to > $2 \
              ORDER BY valid_to DESC LIMIT 1",
            h = quote_ident(&history)
        ),
    ))
    .bind(record_id)
    .bind(at)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    image.map(Version::Earlier).ok_or(AppError::NotFound)
}

/// The record as it stood at `at`, as `ctx` may see it. The caller has run
/// the ordinary read check on the record as it is now.
pub(super) async fn read_as_of(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    attrs: &[AttrInfo],
    record_id: Uuid,
    at: DateTime<Utc>,
) -> Result<EntityRecordResponse, AppError> {
    let surface = attome_security::field_gate::Surface::Interactive;
    match version_at(&state.base.db, entity_name, record_id, at).await? {
        Version::Current => {
            read_record_projection(
                state,
                ctx,
                entity_id,
                entity_name,
                attrs,
                record_id,
                surface,
            )
            .await
        }
        Version::Earlier(image) => {
            project_row(
                state,
                ctx,
                entity_id,
                entity_name,
                attrs,
                RowSource::Image(&image),
                surface,
            )
            .await
        }
    }
}

/// The values `image` holds that differ from `current`, for the attributes a
/// restore may write: not computed, not encrypted, and writable by the
/// caller (`may_write`). `wanted` narrows it to named attributes, each of
/// which must be one of the entity's and restorable. Pure.
pub fn restore_body(
    attrs: &[AttrInfo],
    image: &Value,
    current: &Value,
    wanted: Option<&[String]>,
    may_write: impl Fn(&AttrInfo) -> bool,
) -> Result<Map<String, Value>, AppError> {
    if let Some(names) = wanted {
        if names.is_empty() {
            return Err(AppError::Validation(
                "attributes, when given, names at least one".into(),
            ));
        }
        if let Some(unknown) = names
            .iter()
            .find(|n| !attrs.iter().any(|a| &a.logicalname == *n))
        {
            return Err(AppError::Validation(format!(
                "{unknown}: not an attribute of this entity"
            )));
        }
    }
    let mut body = Map::new();
    for attr in attrs {
        let named = wanted.is_some_and(|w| w.iter().any(|n| n == &attr.logicalname));
        if wanted.is_some() && !named {
            continue;
        }
        let restorable =
            !attr.is_computed() && crate::attr_crypto::mode_for(attr).is_none() && may_write(attr);
        if !restorable {
            if named {
                return Err(AppError::Validation(format!(
                    "{}: this field cannot be restored",
                    attr.logicalname
                )));
            }
            continue;
        }
        let then = image.get(&attr.logicalname).cloned().unwrap_or(Value::Null);
        let now = current
            .get(&attr.logicalname)
            .cloned()
            .unwrap_or(Value::Null);
        if then != now {
            body.insert(attr.logicalname.clone(), then);
        }
    }
    if body.is_empty() {
        return Err(AppError::Validation(
            "nothing to restore: the record already holds those values".into(),
        ));
    }
    Ok(body)
}

/// Whether `ctx` may write `attr` back: read it (a read-gated field needs
/// its read grant) and write it (a sensitive or write-restricted field needs
/// its write grant).
fn may_write(ctx: &SecurityContext, entity: &str, attr: &AttrInfo) -> bool {
    let readable = !attr.is_read_gated() || ctx.has_field_read_grant(entity, &attr.logicalname);
    let writable = !(attr.is_sensitive || attr.is_write_restricted)
        || ctx.has_field_write_grant(entity, &attr.logicalname);
    readable && writable
}

/// A1-T10: writes the values of the version valid at `body.as_of` back
/// through the ordinary update (`row_version` as `If-Match`).
pub async fn restore_version(
    state: &EngineState,
    ctx: &SecurityContext,
    acting_user: Uuid,
    entity_input: &str,
    record_id: Uuid,
    expected_version: i64,
    body: &RestoreVersionBody,
) -> Result<EntityRecordResponse, AppError> {
    let (entity_id, entity_name, attrs, _) = resolve_entity(state, entity_input).await?;
    ctx.require(&entity_name, "update")?;
    require_record_read(state, ctx, entity_id, &entity_name, record_id).await?;
    let image = match version_at(&state.base.db, &entity_name, record_id, body.as_of).await? {
        Version::Current => {
            return Err(AppError::Validation(
                "that is the record's current version".into(),
            ));
        }
        Version::Earlier(image) => image,
    };
    let current: Value = sqlx::query_scalar(&attome_db::tag_dynamic(
        "entity.time_travel",
        &format!(
            "SELECT to_jsonb(t) FROM {t} t WHERE t.id = $1 AND t.is_active = true",
            t = quote_ident(&entity_name)
        ),
    ))
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let values = restore_body(
        &attrs,
        &image,
        &current,
        body.attributes.as_deref(),
        |attr| may_write(ctx, &entity_name, attr),
    )?;
    super::update_record_for(
        state,
        ctx,
        acting_user,
        &entity_name,
        record_id,
        expected_version,
        Value::Object(values),
    )
    .await
}

/// The month a history partition named `<table>_pYYYY_MM` covers, as its
/// first day. Pure.
fn partition_month(table: &str, partition: &str) -> Option<(i32, u32)> {
    let rest = partition.strip_prefix(table)?.strip_prefix("_p")?;
    let (year, month) = rest.split_once('_')?;
    let year: i32 = year.parse().ok()?;
    let month: u32 = month.parse().ok()?;
    (1..=12).contains(&month).then_some((year, month))
}

/// The partitions of `table` holding only versions replaced more than
/// `retention_days` before `now`: a month's partition goes once its last
/// moment is that old. Pure.
pub fn expired_partitions(
    table: &str,
    partitions: &[String],
    now: DateTime<Utc>,
    retention_days: i32,
) -> Vec<String> {
    let cutoff = now - chrono::Duration::days(i64::from(retention_days));
    partitions
        .iter()
        .filter(|p| {
            partition_month(table, p).is_some_and(|(year, month)| {
                let (next_year, next_month) = if month == 12 {
                    (year + 1, 1)
                } else {
                    (year, month + 1)
                };
                (next_year, next_month) <= (cutoff.year(), cutoff.month())
            })
        })
        .cloned()
        .collect()
}

/// The partition job's step for time travel (on the migrator pool): for
/// every entity with time travel on, its history table exists, months ahead
/// are created, and months past its retention are detached and dropped,
/// unless a legal hold names the entity or one of its records.
pub async fn maintain(db_migrator: &DbPool) -> Result<(), AppError> {
    let entities: Vec<(String, Option<i32>)> = sqlx::query_as(
        "SELECT entity_logicalname, retention_days FROM entity_time_travel WHERE enabled",
    )
    .fetch_all(db_migrator)
    .await
    .map_err(AppError::internal)?;
    for (entity, retention_days) in entities {
        let Some(table) = attome_metadata::provision::history_table_name(&entity) else {
            continue;
        };
        // Provisioned when switched on; recreated here only if it went missing,
        // so a steady-state pass issues no DDL against the table.
        let exists: bool = sqlx::query_scalar("SELECT to_regclass(quote_ident($1)) IS NOT NULL")
            .bind(&table)
            .fetch_one(db_migrator)
            .await
            .map_err(AppError::internal)?;
        if !exists {
            attome_metadata::provision::provision_history_table(db_migrator, &entity).await?;
        }
        let created = attome_core::partition_maintenance::ensure_ahead_partitions(
            db_migrator,
            &table,
            "valid_to",
            HISTORY_STORAGE_PARAMS,
            HISTORY_MONTHS_AHEAD,
        )
        .await?;
        if created > 0 {
            tracing::info!(%entity, created, "time travel: history partitions created");
        }
        let Some(days) = retention_days else {
            continue;
        };
        let held: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM legal_hold \
              WHERE entity_logicalname = $1 AND released_at IS NULL)",
        )
        .bind(&entity)
        .fetch_one(db_migrator)
        .await
        .map_err(AppError::internal)?;
        if held {
            tracing::info!(%entity, "time travel: retention skipped while a legal hold is active");
            continue;
        }
        let partitions: Vec<String> = sqlx::query_scalar(
            "SELECT c.relname::text FROM pg_inherits i \
               JOIN pg_class c ON c.oid = i.inhrelid \
               JOIN pg_class p ON p.oid = i.inhparent \
              WHERE p.relname = $1 AND p.relnamespace = current_schema()::regnamespace",
        )
        .bind(&table)
        .fetch_all(db_migrator)
        .await
        .map_err(AppError::internal)?;
        for partition in expired_partitions(&table, &partitions, Utc::now(), days) {
            attome_core::partition_maintenance::detach_partition(db_migrator, &table, &partition)
                .await?;
            attome_core::partition_maintenance::drop_detached_partition(db_migrator, &partition)
                .await?;
            tracing::info!(%entity, %partition, "time travel: expired history dropped");
        }
    }
    Ok(())
}

async fn read_settings(db: &DbPool, entity: &str) -> Result<TimeTravelSettings, AppError> {
    let row: Option<(bool, Option<i32>, i64)> = sqlx::query_as(
        "SELECT enabled, retention_days, row_version FROM entity_time_travel \
          WHERE entity_logicalname = $1",
    )
    .bind(entity)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (enabled, retention_days, row_version) = row.unwrap_or((false, None, 0));
    Ok(TimeTravelSettings {
        entity: entity.to_owned(),
        enabled,
        retention_days,
        row_version,
    })
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(axum::http::header::IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match: \"<row_version>\" is required".into()))?
        .to_str()
        .map_err(|_| AppError::Validation("If-Match must be ASCII".into()))?;
    raw.trim()
        .trim_matches('"')
        .parse()
        .map_err(|_| AppError::Validation("If-Match must be a row_version".into()))
}

/// The checks a settings body passes. Pure.
pub fn check_body(entity: &str, body: &TimeTravelBody) -> Result<(), AppError> {
    if let Some(days) = body.retention_days
        && !(1..=MAX_RETENTION_DAYS).contains(&days)
    {
        return Err(AppError::Validation(format!(
            "retention_days must be between 1 and {MAX_RETENTION_DAYS}"
        )));
    }
    if body.enabled && attome_metadata::provision::history_table_name(entity).is_none() {
        return Err(AppError::Validation(format!(
            "time travel needs an entity name of at most {} characters",
            attome_metadata::provision::MAX_HISTORY_ENTITY_LEN
        )));
    }
    Ok(())
}

/// Read an entity's time-travel settings
///
/// Whether earlier versions of the entity's records are kept, and for how long.
#[utoipa::path(
    get,
    path = "/api/v1/admin/time-travel/{entity}",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name")),
    responses(
        (status = 200, description = "The settings; row_version 0 when never saved", body = TimeTravelSettings),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not change the data model", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_time_travel(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path(entity): Path<String>,
) -> Result<Json<TimeTravelSettings>, AppError> {
    if state.entities.load().get(&entity).is_none() {
        return Err(AppError::NotFound);
    }
    Ok(Json(read_settings(&state.base.db, &entity).await?))
}

/// Change an entity's time-travel settings
///
/// Switching time travel on creates the entity's history table and its partitions; from then on
/// every update and delete keeps the version it replaces. Switching it off keeps the versions
/// already kept. Send `If-Match` with the `row_version` read (`"0"` the first time).
#[utoipa::path(
    put,
    path = "/api/v1/admin/time-travel/{entity}",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name")),
    request_body = TimeTravelBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The saved settings", body = TimeTravelSettings),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not change the data model", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 409, description = "Stale row_version", body = ErrorResponse),
        (status = 422, description = "Missing If-Match, a retention out of range or an entity name too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn put_time_travel(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(entity): Path<String>,
    headers: HeaderMap,
    Json(body): Json<TimeTravelBody>,
) -> Result<Json<TimeTravelSettings>, AppError> {
    let expected = if_match(&headers)?;
    if state.entities.load().get(&entity).is_none() {
        return Err(AppError::NotFound);
    }
    check_body(&entity, &body)?;
    // The table and its partitions first, outside the settings transaction:
    // DDL runs on the migrator pool, and an update that starts keeping
    // versions must find somewhere to put them.
    if body.enabled {
        let table =
            attome_metadata::provision::provision_history_table(&state.base.db_migrator, &entity)
                .await?;
        attome_core::partition_maintenance::ensure_ahead_partitions(
            &state.base.db_migrator,
            &table,
            "valid_to",
            HISTORY_STORAGE_PARAMS,
            HISTORY_MONTHS_AHEAD,
        )
        .await?;
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let written = if expected == 0 {
        sqlx::query(
            "INSERT INTO entity_time_travel \
                (entity_logicalname, enabled, retention_days, row_version, updated_by) \
             VALUES ($1, $2, $3, 1, $4) ON CONFLICT (entity_logicalname) DO NOTHING",
        )
        .bind(&entity)
        .bind(body.enabled)
        .bind(body.retention_days)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
    } else {
        sqlx::query(
            "UPDATE entity_time_travel SET enabled = $2, retention_days = $3, updated_by = $4, \
                    updated_at = now(), row_version = row_version + 1 \
              WHERE entity_logicalname = $1 AND row_version = $5",
        )
        .bind(&entity)
        .bind(body.enabled)
        .bind(body.retention_days)
        .bind(ctx.user_id)
        .bind(expected)
        .execute(&mut *tx)
        .await
    }
    .map_err(AppError::internal)?
    .rows_affected();
    if written == 0 {
        return Err(AppError::VersionConflict);
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "entity_time_travel",
            None,
        )
        .named("entity.time_travel")
        .comment(format!(
            "time travel of {entity} {}",
            if body.enabled { "on" } else { "off" }
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(read_settings(&state.base.db, &entity).await?))
}

/// Restore an earlier version
///
/// A1-T10: writes back the values of the version of this record valid at `as_of` (an entity with
/// time travel on), through the ordinary update: `If-Match` is required and validation, rules and
/// audit run as for any edit. Only values that differ from the current ones are written; computed
/// and encrypted fields, and fields the caller may not read or write, are never restored.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/restore-version",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name"), ("id" = Uuid, Path, description = "The record")),
    request_body = RestoreVersionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The record with the earlier values restored", body = EntityRecordResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this record", body = ErrorResponse),
        (status = 404, description = "No such record, or no version of it kept for as_of", body = ErrorResponse),
        (status = 409, description = "The record changed since the If-Match version", body = ErrorResponse),
        (status = 422, description = "No If-Match, no time travel on the entity, as_of is the current version, nothing to restore, a field that cannot be restored, or the values fail validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn restore_version_route(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Extension(claims): Extension<attome_auth::SessionClaims>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<RestoreVersionBody>,
) -> Result<Json<EntityRecordResponse>, AppError> {
    let expected = super::row_version::expected_row_version(&headers)?;
    Ok(Json(
        restore_version(
            &state,
            &ctx,
            claims.sub,
            &entity_input,
            record_id,
            expected,
            &body,
        )
        .await?,
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_time_travel, put_time_travel, restore_version_route))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::{DataClassification, OnTargetDelete};

    fn attr(name: &str, field_type_int: i32) -> AttrInfo {
        AttrInfo {
            logicalname: name.into(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::default(),
            data_classification: DataClassification::default(),
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
            options: None,
        }
    }

    #[test]
    fn restore_body_writes_only_changed_restorable_values() {
        let attrs = vec![attr("name", 3), attr("stage", 7), attr("notes", 3)];
        let image = json!({"name": "Acme", "stage": "lead", "notes": "same", "id": "x"});
        let current = json!({"name": "Acme Ltd", "stage": "won", "notes": "same"});
        let body = restore_body(&attrs, &image, &current, None, |_| true).unwrap();
        assert_eq!(
            Value::Object(body),
            json!({"name": "Acme", "stage": "lead"})
        );
        // Narrowed to one field.
        let names = vec!["stage".to_owned()];
        let body = restore_body(&attrs, &image, &current, Some(&names), |_| true).unwrap();
        assert_eq!(Value::Object(body), json!({"stage": "lead"}));
        // A field the caller may not write is skipped, and refused when named.
        let body =
            restore_body(&attrs, &image, &current, None, |a| a.logicalname != "name").unwrap();
        assert_eq!(Value::Object(body), json!({"stage": "lead"}));
        let names = vec!["name".to_owned()];
        assert!(
            restore_body(&attrs, &image, &current, Some(&names), |a| a.logicalname
                != "name")
            .is_err()
        );
        // Unknown names and no difference are refused.
        let names = vec!["missing".to_owned()];
        assert!(restore_body(&attrs, &image, &current, Some(&names), |_| true).is_err());
        assert!(restore_body(&attrs, &current, &current, None, |_| true).is_err());
    }

    #[test]
    fn retention_drops_whole_months_past_the_cutoff() {
        let table = "deal__history";
        let partitions: Vec<String> = [
            "deal__history_p2026_01",
            "deal__history_p2026_02",
            "deal__history_p2026_03",
            "other_p2026_01",
        ]
        .iter()
        .map(|p| (*p).to_owned())
        .collect();
        let now = DateTime::parse_from_rfc3339("2026-04-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        // 30 days back is 2026-03-16: January and February have ended.
        assert_eq!(
            expired_partitions(table, &partitions, now, 30),
            vec!["deal__history_p2026_01", "deal__history_p2026_02"]
        );
        assert!(expired_partitions(table, &partitions, now, 365).is_empty());
        assert_eq!(partition_month(table, "deal__history_p2026_13"), None);
    }

    #[test]
    fn settings_body_checks() {
        let on = TimeTravelBody {
            enabled: true,
            retention_days: Some(90),
        };
        assert!(check_body("deal", &on).is_ok());
        let long = "x".repeat(attome_metadata::provision::MAX_HISTORY_ENTITY_LEN + 1);
        assert!(check_body(&long, &on).is_err());
        let bad = TimeTravelBody {
            enabled: false,
            retention_days: Some(0),
        };
        assert!(check_body("deal", &bad).is_err());
    }
}
