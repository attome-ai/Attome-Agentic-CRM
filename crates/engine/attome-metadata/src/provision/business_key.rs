//! Solution 7 Phase 2 (D-787 rule 7, D-791 rule 7; `SOLUTION-7-PHASE-2-DESIGN.md`
//! §2.3, §3.8, §5.2) — entity business keys.
//!
//! An entity declares `business_key` (1–4 attribute logical names, ordered)
//! and, for configuration-like tables, `is_reference_data` (which requires a
//! key; migration 0539's `ck_core_entity_info_reference_key`). Records of a
//! keyed entity are matched by that key, and only by it, when a changeset's
//! `upsert_record` is applied; generic writes to a reference-data entity are
//! recorded as `upsert_record` when a changeset is in play.
//!
//! - **Declaration** ([`declare_business_key_recorded`]): every key field is a
//!   live attribute of the entity, of type text, number, date, bool or lookup
//!   (the record-set rule), single-valued, named once; a lookup key field's
//!   target must itself declare a key (nested key references, D-534). A key
//!   is refused while live rows share a value of it
//!   ([`count_duplicate_keys`], the plan's `business_key_duplicates` block).
//!   The metadata row is written under the global metadata-write lock and the
//!   entity's provisioning lock, with the change log and the recorded
//!   `update_entity` (`changed: ["business_key", …]`) in the same
//!   transaction.
//! - **Enforcement** ([`ensure_business_key_index`]): a unique index
//!   `uxbk_<e40>_<h8>` over the key columns, `NULLS NOT DISTINCT`, partial on
//!   live rows, built `CONCURRENTLY` on one pinned migrator session — inline
//!   at or under [`BUSINESS_KEY_INDEX_INLINE_ROW_LIMIT`] rows, else as the
//!   durable `EngineJob::BuildBusinessKeyIndex` (dedup-keyed per entity).
//!   A new key builds its index first, then the replaced key's index is
//!   dropped; an INVALID index left by a failed build is dropped and rebuilt.
//!   The status is [`business_key_index_status`].
//! - **References** ([`BusinessKeyHook`]): a rename of a key field rewrites
//!   the declared key and renames the index; deleting a key field is blocked
//!   (`field_in_business_key`).
//!
//! `<h8>`: the design names "the first 8 hex of sha256(entity:fields)"; this
//! crate has no sha2 dependency, so it is the first 8 hex of a UUIDv5 (SHA-1
//! based) of the same string under a fixed namespace — deterministic and
//! collision-resistant for the purpose (one name per entity + key).

use attome_config::AppConfig;
use attome_core::changeset::RecordedOp;
use attome_core::changeset::errors;
use attome_core::changeset::field_hooks::{
    Blocker, FieldRef, FieldReferenceHook, HookFuture, HookOutcome, RefOwner, RefScan,
};
use attome_core::{FieldType, quote_ident};
use attome_db::{DbPool, PgConnection};
use attome_types::AppError;
use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use super::changeset::{self as cs, ObjectKind, RecordAs};
use super::identifiers::{is_multi_valued, valid_identifier};

/// A key has at most this many fields (migration 0539's CHECK).
pub const MAX_BUSINESS_KEY_FIELDS: usize = 4;

/// At or under this many rows the unique index is built inline (the size
/// gate every runtime DDL path uses); above it, as a durable job.
pub const BUSINESS_KEY_INDEX_INLINE_ROW_LIMIT: i64 = 10_000;

/// The physical unique index name prefix; every index this module owns
/// starts with it, and nothing else does.
pub const BUSINESS_KEY_INDEX_PREFIX: &str = "uxbk_";

/// The field types a key field may have: the record-set rule
/// (`bundle::record_sets::valid_key_field_type`) plus a single-valued choice,
/// whose stored code is one text value (a pack's stage keyed by pipeline and
/// stage, V2-D496). A multi-valued field is refused by [`check_key_fields`].
pub const KEY_FIELD_TYPES: &[&str] = &[
    "text",
    "number",
    "date",
    "date_time",
    "bool",
    "choice",
    "lookup",
];

/// How many characters of the entity name the index name keeps.
const INDEX_ENTITY_CHARS: usize = 40;

/// The fixed namespace of the `<h8>` hash. Never changes: changing it renames
/// every key index on the next sync.
const INDEX_NAME_NAMESPACE: Uuid = uuid::uuid!("3b1f6c2e-8d4a-4f0e-9a57-0c6d2e9b4a71");

/// `(logicalname, type, options, lookup_entity_ref, target_has_key)` of one
/// candidate key field.
type KeyFieldSqlRow = (
    Option<String>,
    Option<i32>,
    Option<Value>,
    Option<Uuid>,
    bool,
);

/// `(logicalname, business_key, is_reference_data, owner_layer, is_append_only)`.
type EntityKeyRow = (Option<String>, Option<Vec<String>>, bool, String, bool);

/// `entity_info` live-row predicate.
const LIVE_ENTITY: &str = "(is_active IS NULL OR is_active = true)";

/// An entity's declared business key and reference-data flag.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BusinessKey {
    /// The key fields in declared order; `None`: no key.
    pub fields: Option<Vec<String>>,
    pub is_reference_data: bool,
}

/// What [`declare_business_key_recorded`] did.
#[derive(Debug, Clone)]
pub struct DeclareOutcome {
    pub entity: String,
    pub before: BusinessKey,
    pub after: BusinessKey,
    /// `business_key` and/or `is_reference_data`; empty: nothing changed.
    pub changed: Vec<&'static str>,
}

impl DeclareOutcome {
    /// Whether the key columns changed (the unique index must follow).
    pub fn key_changed(&self) -> bool {
        self.before.fields != self.after.fields
    }
}

/// `uxbk_<e40>_<h8>`: `<e40>` is the entity name cut to 40 characters,
/// `<h8>` the first 8 hex of a hash of `entity:field1,field2,…` (module
/// doc). At most 54 bytes, under PostgreSQL's 63.
pub fn business_key_index_name(entity: &str, fields: &[String]) -> String {
    let e40: String = entity.chars().take(INDEX_ENTITY_CHARS).collect();
    let hash = Uuid::new_v5(
        &INDEX_NAME_NAMESPACE,
        format!("{entity}:{}", fields.join(",")).as_bytes(),
    )
    .simple()
    .to_string();
    format!("{BUSINESS_KEY_INDEX_PREFIX}{e40}_{}", &hash[..8])
}

/// Trims a requested key and checks its shape: 1–4 field names, valid
/// identifiers, none repeated. Order is kept (it is the index column order).
pub fn normalize_key(raw: &[String]) -> Result<Vec<String>, AppError> {
    let fields: Vec<String> = raw.iter().map(|f| f.trim().to_owned()).collect();
    if fields.is_empty() || fields.len() > MAX_BUSINESS_KEY_FIELDS {
        return Err(AppError::Validation(format!(
            "business_key_invalid: a business key names 1 to {MAX_BUSINESS_KEY_FIELDS} fields"
        )));
    }
    for (i, field) in fields.iter().enumerate() {
        if !valid_identifier(field) {
            return Err(AppError::Validation(format!(
                "business_key_invalid: {field:?} is not a field logical name"
            )));
        }
        if fields[..i].contains(field) {
            return Err(AppError::Validation(format!(
                "business_key_invalid: {field} is named twice"
            )));
        }
    }
    Ok(fields)
}

/// One candidate key field as the attribute table describes it.
#[derive(Debug, Clone)]
pub struct KeyFieldRow {
    pub name: String,
    /// `FieldType::as_str`.
    pub field_type: String,
    pub multi: bool,
    pub lookup_target: Option<Uuid>,
    /// The lookup target declares a business key.
    pub target_has_key: bool,
}

/// The declaration rules over the live attributes `found` (design §3.8):
/// every field exists, has a key type, is single-valued, and a lookup's
/// target declares a key (or is the entity itself, whose key this is).
pub fn check_key_fields(
    entity_id: Uuid,
    fields: &[String],
    found: &[KeyFieldRow],
) -> Result<(), String> {
    for field in fields {
        let Some(row) = found.iter().find(|r| &r.name == field) else {
            return Err(format!(
                "business_key_invalid: {field} is not a live field of this entity"
            ));
        };
        if !KEY_FIELD_TYPES.contains(&row.field_type.as_str()) {
            return Err(format!(
                "business_key_invalid: {field} (type {}) cannot be part of a business key; \
                 key fields are text, number, date, bool, choice or lookup",
                row.field_type
            ));
        }
        if row.multi {
            return Err(format!(
                "business_key_invalid: {field} holds several values and cannot be part of a \
                 business key"
            ));
        }
        if row.field_type == "lookup" {
            match row.lookup_target {
                None => {
                    return Err(format!(
                        "business_key_invalid: the lookup {field} records no target entity"
                    ));
                }
                Some(target) if target != entity_id && !row.target_has_key => {
                    return Err(format!(
                        "business_key_invalid: the lookup {field} targets an entity without a \
                         business key; declare the target's key first (nested key references)"
                    ));
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

/// The live attributes named by `fields`, with what the rules need.
async fn load_key_fields(
    db: &DbPool,
    entity_id: Uuid,
    fields: &[String],
) -> Result<Vec<KeyFieldRow>, AppError> {
    let rows: Vec<KeyFieldSqlRow> = sqlx::query_as(
        "SELECT a.logicalname, a.\"type\", a.options, a.lookup_entity_ref, \
                COALESCE(le.business_key IS NOT NULL, false) \
         FROM attribute_info a \
         LEFT JOIN entity_info le ON le.id = a.lookup_entity_ref \
         WHERE a.entity_ref = $1 AND a.logicalname = ANY($2) \
           AND (a.is_active IS NULL OR a.is_active = true)",
    )
    .bind(entity_id)
    .bind(fields)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(name, type_int, options, lookup_target, target_has_key)| {
            let name = name?;
            let field_type = type_int
                .and_then(FieldType::from_int)
                .map_or("unknown", |t| t.as_str())
                .to_owned();
            let multi = is_multi_valued(&field_type, options.as_ref());
            Some(KeyFieldRow {
                name,
                field_type,
                multi,
                lookup_target,
                target_has_key,
            })
        })
        .collect())
}

/// The declared key of a live entity; `None` when the entity is not live.
pub async fn read_business_key<'e>(
    exec: impl sqlx::PgExecutor<'e>,
    entity: &str,
) -> Result<Option<BusinessKey>, AppError> {
    let row: Option<(Option<Vec<String>>, bool)> = sqlx::query_as(&format!(
        "SELECT business_key, is_reference_data FROM entity_info \
         WHERE logicalname = $1 AND {LIVE_ENTITY}"
    ))
    .bind(entity)
    .fetch_optional(exec)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(|(fields, is_reference_data)| BusinessKey {
        fields,
        is_reference_data,
    }))
}

/// The live-row predicate of an entity table, or none for an append-only
/// one (no soft-delete lifecycle; `attome_core::live_row_predicate`).
fn live_rows(is_append_only: bool) -> &'static str {
    if is_append_only {
        ""
    } else {
        "WHERE (is_active IS NULL OR is_active = true)"
    }
}

/// How many distinct key values more than one live row shares (design §5.1:
/// a read-only transaction, 5 s statement timeout, bound-free SQL over
/// validated identifiers). `None` when the count timed out: the caller does
/// not block on it by itself (the index build then fails on a duplicate and
/// reports it).
pub async fn count_duplicate_keys(
    db: &DbPool,
    entity: &str,
    fields: &[String],
    is_append_only: bool,
) -> Result<Option<i64>, AppError> {
    if !valid_identifier(entity) || !fields.iter().all(|f| valid_identifier(f)) {
        return Err(AppError::internal(format!(
            "business key duplicate check: invalid identifier on {entity}"
        )));
    }
    let cols: Vec<String> = fields.iter().map(|f| quote_ident(f)).collect();
    let sql = format!(
        "SELECT count(*) FROM (SELECT 1 FROM {table} {live} GROUP BY {cols} \
         HAVING count(*) > 1) d",
        table = quote_ident(entity),
        live = live_rows(is_append_only),
        cols = cols.join(", "),
    );
    let mut tx = attome_db::tx::begin(db).await?;
    for stmt in [
        "SET TRANSACTION READ ONLY",
        "SET LOCAL statement_timeout = '5s'",
        "SET LOCAL lock_timeout = '1s'",
    ] {
        sqlx::query(stmt)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    }
    let counted = sqlx::query_scalar::<_, i64>(&sql).fetch_one(&mut *tx).await;
    match counted {
        Ok(count) => {
            attome_db::tx::commit(tx).await?;
            Ok(Some(count))
        }
        // 57014 query_canceled (statement_timeout), 55P03 lock_not_available.
        Err(e)
            if e.as_database_error()
                .and_then(|d| d.code())
                .is_some_and(|c| c.as_ref() == "57014" || c.as_ref() == "55P03") =>
        {
            tracing::warn!(
                entity = %entity,
                "business key duplicate check timed out; the index build will report duplicates"
            );
            Ok(None)
        }
        Err(e) => Err(AppError::internal(e)),
    }
}

/// Declares (or clears) an entity's business key and reference-data flag
/// (design §1 "Declare a business key"). Validates, refuses a key live rows
/// duplicate, writes the metadata row under the metadata-write and entity
/// provisioning locks with the change log and, when `rec` asks for one, the
/// recorded `update_entity` whose snapshot carries `business_key` and
/// `is_reference_data` and whose `changed` names them. Does **not** build
/// the unique index: the caller runs [`ensure_business_key_index`] after
/// commit when [`DeclareOutcome::key_changed`].
pub async fn declare_business_key_recorded(
    db: &DbPool,
    entity_id: Uuid,
    desired: &BusinessKey,
    rec: Option<RecordAs<'_>>,
) -> Result<DeclareOutcome, AppError> {
    cs::preflight(db, rec).await?;

    let row: Option<EntityKeyRow> = sqlx::query_as(&format!(
        "SELECT logicalname, business_key, is_reference_data, owner_layer, \
                    COALESCE(is_append_only, false) \
             FROM entity_info WHERE id = $1 AND {LIVE_ENTITY}"
    ))
    .bind(entity_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (logicalname, current_fields, current_reference, owner_layer, is_append_only) =
        row.ok_or(AppError::NotFound)?;
    let entity = logicalname
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::internal(format!("entity {entity_id} has no logicalname")))?;
    cs::check_owner(rec, &owner_layer)?;

    let before = BusinessKey {
        fields: current_fields,
        is_reference_data: current_reference,
    };
    let after = BusinessKey {
        fields: match &desired.fields {
            Some(fields) => Some(normalize_key(fields)?),
            None => None,
        },
        is_reference_data: desired.is_reference_data,
    };
    if after.is_reference_data && after.fields.is_none() {
        return Err(AppError::Validation(
            errors::BUSINESS_KEY_REQUIRED_FOR_REFERENCE_DATA.to_owned(),
        ));
    }
    let mut changed = Vec::new();
    cs::diff(&mut changed, "business_key", &before.fields, &after.fields);
    cs::diff(
        &mut changed,
        "is_reference_data",
        &before.is_reference_data,
        &after.is_reference_data,
    );
    if changed.is_empty() {
        return Ok(DeclareOutcome {
            entity,
            before,
            after,
            changed,
        });
    }

    if before.fields != after.fields
        && let Some(fields) = &after.fields
    {
        let found = load_key_fields(db, entity_id, fields).await?;
        check_key_fields(entity_id, fields, &found).map_err(AppError::Validation)?;
        if count_duplicate_keys(db, &entity, fields, is_append_only)
            .await?
            .is_some_and(|n| n > 0)
        {
            return Err(AppError::Conflict(errors::BUSINESS_KEY_DUPLICATES));
        }
    }

    let mut tx = attome_db::tx::begin(db).await?;
    // The same lock order as `reconcile_entity`: the global metadata-write
    // lock, then the entity's provisioning lock.
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-metadata/provision-entity:{entity}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "entity provisioning already in progress",
        ));
    }
    // Compare-and-set on the values read above: a concurrent declaration
    // between that read and this lock is a conflict, not a silent overwrite.
    let updated = sqlx::query(&format!(
        "UPDATE entity_info \
         SET business_key = $2, is_reference_data = $3, modified_at = NOW() \
         WHERE id = $1 AND {LIVE_ENTITY} \
           AND business_key IS NOT DISTINCT FROM $4 AND is_reference_data = $5"
    ))
    .bind(entity_id)
    .bind(&after.fields)
    .bind(after.is_reference_data)
    .bind(&before.fields)
    .bind(before.is_reference_data)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() != 1 {
        return Err(AppError::Conflict(
            "the entity's business key changed concurrently; reload and retry",
        ));
    }
    attome_core::append_change_log(&mut tx, entity_id, &entity, attome_core::ChangeKind::Upsert)
        .await?;
    if let Some(RecordAs {
        recording,
        op: Some(op),
    }) = rec
    {
        let mut snapshot = cs::snapshot(&mut tx, ObjectKind::Entity, entity_id).await?;
        if let Value::Object(map) = &mut snapshot {
            map.insert(
                "business_key".into(),
                serde_json::to_value(&after.fields).map_err(AppError::internal)?,
            );
            map.insert(
                "is_reference_data".into(),
                Value::Bool(after.is_reference_data),
            );
        }
        recording
            .record(
                &mut tx,
                RecordedOp {
                    op,
                    object_kind: ObjectKind::Entity.as_str(),
                    object_ref: Some(entity_id),
                    target: cs::entity_target(&entity),
                    snapshot,
                    changed: changed.clone(),
                },
            )
            .await?;
    }
    attome_db::tx::commit(tx).await?;
    tracing::info!(
        entity = %entity,
        business_key = ?after.fields,
        is_reference_data = after.is_reference_data,
        "provision: declared the entity's business key"
    );
    Ok(DeclareOutcome {
        entity,
        before,
        after,
        changed,
    })
}

/// How [`ensure_business_key_index`] brought the index in line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexSync {
    /// Built (or dropped) inline.
    Inline,
    /// Above the size gate: `EngineJob::BuildBusinessKeyIndex` is queued.
    Queued,
}

impl IndexSync {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Queued => "queued",
        }
    }
}

/// Brings the unique index in line with the entity's declared key: inline at
/// or under [`BUSINESS_KEY_INDEX_INLINE_ROW_LIMIT`] rows, else as the durable
/// job (dedup-keyed `business-key-index:<entity>`). Runs outside any
/// transaction (`CONCURRENTLY`).
pub async fn ensure_business_key_index(
    db: &DbPool,
    config: &AppConfig,
    entity: &str,
) -> Result<IndexSync, AppError> {
    if super::table_row_count_exceeds(db, entity, BUSINESS_KEY_INDEX_INLINE_ROW_LIMIT).await? {
        attome_jobs::enqueue_dedup(
            db,
            attome_core::jobs::EngineJob::BuildBusinessKeyIndex {
                entity_logicalname: entity.to_owned(),
            },
            &format!("business-key-index:{entity}"),
        )
        .await
        .map_err(AppError::internal)?;
        tracing::info!(entity = %entity, "business key index queued (above the size gate)");
        Ok(IndexSync::Queued)
    } else {
        sync_business_key_index(config, entity).await?;
        Ok(IndexSync::Inline)
    }
}

/// The job body and the inline path: one pinned migrator session (the
/// `sync_attribute_index` shape — `CONCURRENTLY` cannot run in a transaction
/// and the session advisory lock must stay on one backend).
pub async fn sync_business_key_index(config: &AppConfig, entity: &str) -> Result<(), AppError> {
    let _permit = super::attribute::ATTRIBUTE_INDEX_CONNECTION_LIMIT
        .acquire()
        .await
        .map_err(|_| AppError::internal("the index-build connection limiter is closed"))?;
    let mut conn = attome_db::UnpooledSession::new(
        attome_db::create_migrator_connection(config)
            .await
            .map_err(AppError::internal)?,
    );
    let lock_key = format!("attome-metadata/business-key-index:{entity}");
    let result = sync_business_key_index_on_connection(&mut conn, entity, &lock_key).await;
    let unlock = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_optional(&mut *conn)
        .await;
    match (&result, unlock) {
        (_, Ok(Some(true))) | (Err(_), Ok(_)) => {}
        (Ok(()), Ok(_)) => tracing::warn!(
            entity = %entity,
            "business key index advisory lock was not held at release; the session was not \
             pinned — check that database.direct_url bypasses any transaction-mode pgbouncer"
        ),
        (_, Err(e)) => tracing::warn!(
            error = %e,
            entity = %entity,
            "failed to release the business key index advisory lock"
        ),
    }
    let _ = conn.close().await;
    result
}

/// `(index name, valid)` of every `uxbk_` index on the entity's table.
async fn existing_key_indexes(
    conn: &mut PgConnection,
    entity: &str,
) -> Result<Vec<(String, bool)>, AppError> {
    sqlx::query_as(
        "SELECT c.relname::text, i.indisvalid \
         FROM pg_index i \
         JOIN pg_class c ON c.oid = i.indexrelid \
         JOIN pg_class t ON t.oid = i.indrelid \
         WHERE t.relname = $1 AND c.relname LIKE 'uxbk!_%' ESCAPE '!'",
    )
    .bind(entity)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)
}

async fn drop_index_concurrently(conn: &mut PgConnection, name: &str) -> Result<(), AppError> {
    sqlx::query(&format!(
        "DROP INDEX CONCURRENTLY IF EXISTS {}",
        quote_ident(name)
    ))
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, index = %name, "DROP INDEX CONCURRENTLY failed (business key)");
        AppError::internal(e)
    })?;
    Ok(())
}

/// Runs the synchronization on one direct session (see
/// [`sync_business_key_index`]); the declared key is re-read here, so a key
/// changed while a job was queued builds the newest one.
pub async fn sync_business_key_index_on_connection(
    conn: &mut PgConnection,
    entity: &str,
    lock_key: &str,
) -> Result<(), AppError> {
    if !valid_identifier(entity) {
        return Err(AppError::internal(format!(
            "business key index: invalid entity identifier {entity}"
        )));
    }
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(lock_key)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "business key index build already in progress",
        ));
    }

    let intent: Option<(Option<Vec<String>>, bool)> = sqlx::query_as(&format!(
        "SELECT business_key, COALESCE(is_append_only, false) FROM entity_info \
         WHERE logicalname = $1 AND {LIVE_ENTITY}"
    ))
    .bind(entity)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    // A retired entity needs no DDL: its table and index stay as they are.
    let Some((fields, is_append_only)) = intent else {
        return Ok(());
    };
    if let Some(fields) = &fields
        && !fields.iter().all(|f| valid_identifier(f))
    {
        return Err(AppError::internal(format!(
            "business key index: {entity} declares an invalid field name"
        )));
    }
    let desired = fields
        .as_deref()
        .map(|f| business_key_index_name(entity, f));

    if let Some(name) = &desired {
        let building: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_progress_create_index p \
             JOIN pg_class c ON c.oid = p.index_relid WHERE c.relname = $1)",
        )
        .bind(name)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        if building {
            return Err(AppError::Conflict(
                "business key index build already in progress",
            ));
        }
    }

    let existing = existing_key_indexes(conn, entity).await?;
    if let (Some(name), Some(fields)) = (&desired, &fields) {
        let present = existing.iter().find(|(n, _)| n == name);
        if let Some((_, false)) = present {
            drop_index_concurrently(conn, name).await?;
        }
        if !matches!(present, Some((_, true))) {
            let cols: Vec<String> = fields.iter().map(|f| quote_ident(f)).collect();
            let sql = format!(
                "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS {index} ON {table} ({cols}) \
                 NULLS NOT DISTINCT {live}",
                index = quote_ident(name),
                table = quote_ident(entity),
                cols = cols.join(", "),
                live = live_rows(is_append_only),
            );
            if let Err(e) = sqlx::query(&sql).execute(&mut *conn).await {
                let duplicate = e
                    .as_database_error()
                    .and_then(|d| d.code())
                    .is_some_and(|c| c.as_ref() == "23505");
                // A failed concurrent build leaves an INVALID index behind;
                // drop it now rather than on the next attempt.
                if let Err(drop_error) = drop_index_concurrently(conn, name).await {
                    tracing::warn!(error = ?drop_error, index = %name, "could not drop the failed business key index");
                }
                if duplicate {
                    tracing::warn!(entity = %entity, index = %name, "business key index refused: duplicate key values");
                    return Err(AppError::Conflict(errors::BUSINESS_KEY_DUPLICATES));
                }
                tracing::error!(error = %e, entity = %entity, index = %name, "CREATE UNIQUE INDEX CONCURRENTLY failed (business key)");
                return Err(AppError::internal(e));
            }
        }
    }
    // The replaced key's index (or every index when the key was cleared)
    // goes only after the new one is valid.
    for (name, _) in existing {
        if desired.as_deref() != Some(name.as_str()) {
            drop_index_concurrently(conn, &name).await?;
        }
    }
    tracing::info!(entity = %entity, index = ?desired, "business key index in line with the declared key");
    Ok(())
}

/// The state of the unique index that enforces a declared key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyIndexState {
    /// The entity declares no key.
    None,
    /// The key is declared; its index does not exist (yet).
    Missing,
    /// `CREATE INDEX CONCURRENTLY` is running.
    Building,
    /// A failed build left it INVALID; the next sync rebuilds it.
    Invalid,
    Valid,
}

impl KeyIndexState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Missing => "missing",
            Self::Building => "building",
            Self::Invalid => "invalid",
            Self::Valid => "valid",
        }
    }
}

/// The index status of a declared key (`index_name`, state).
pub async fn business_key_index_status(
    exec: &DbPool,
    entity: &str,
    fields: Option<&[String]>,
) -> Result<(Option<String>, KeyIndexState), AppError> {
    let Some(fields) = fields else {
        return Ok((None, KeyIndexState::None));
    };
    let name = business_key_index_name(entity, fields);
    let building: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_stat_progress_create_index p \
         JOIN pg_class c ON c.oid = p.index_relid WHERE c.relname = $1)",
    )
    .bind(&name)
    .fetch_one(exec)
    .await
    .map_err(AppError::internal)?;
    if building {
        return Ok((Some(name), KeyIndexState::Building));
    }
    let valid: Option<bool> = sqlx::query_scalar(
        "SELECT i.indisvalid FROM pg_index i \
         JOIN pg_class c ON c.oid = i.indexrelid \
         JOIN pg_class t ON t.oid = i.indrelid \
         WHERE c.relname = $1 AND t.relname = $2",
    )
    .bind(&name)
    .bind(entity)
    .fetch_optional(exec)
    .await
    .map_err(AppError::internal)?;
    let state = match valid {
        None => KeyIndexState::Missing,
        Some(false) => KeyIndexState::Invalid,
        Some(true) => KeyIndexState::Valid,
    };
    Ok((Some(name), state))
}

/// A lookup value of a reference record as a portable key reference,
/// `{"key": {field: value, …}}`, built from the target record's declared
/// business key (design §3.8 recorder rule). `Ok(None)`: the target record
/// is gone. `Err(Conflict(lookup_target_has_no_business_key))`: the target
/// entity declares no key, or its key itself holds a lookup (a key
/// reference carries scalars only, `record_sets::parse_key_reference`).
pub async fn key_reference_of(
    conn: &mut PgConnection,
    target_entity_id: Uuid,
    record_id: Uuid,
) -> Result<Option<Value>, AppError> {
    let target: Option<(Option<String>, Option<Vec<String>>)> =
        sqlx::query_as("SELECT logicalname, business_key FROM entity_info WHERE id = $1")
            .bind(target_entity_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    let Some((Some(entity), Some(fields))) = target else {
        return Err(AppError::Conflict(
            errors::LOOKUP_TARGET_HAS_NO_BUSINESS_KEY,
        ));
    };
    if !valid_identifier(&entity) || !fields.iter().all(|f| valid_identifier(f)) {
        return Err(AppError::internal(format!(
            "key reference: {entity} declares an invalid key"
        )));
    }
    let lookup_in_key: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM attribute_info a \
         WHERE a.entity_ref = $1 AND a.logicalname = ANY($2) AND a.lookup_entity_ref IS NOT NULL)",
    )
    .bind(target_entity_id)
    .bind(&fields)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if lookup_in_key {
        return Err(AppError::Conflict(
            errors::LOOKUP_TARGET_HAS_NO_BUSINESS_KEY,
        ));
    }
    let cols: Vec<String> = fields.iter().map(|f| quote_ident(f)).collect();
    let row: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT row_to_json(t) FROM (SELECT {cols} FROM {table} WHERE id = $1) t",
        cols = cols.join(", "),
        table = quote_ident(&entity),
    ))
    .bind(record_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(|values| {
        let mut key = Map::new();
        for field in &fields {
            key.insert(
                field.clone(),
                values.get(field).cloned().unwrap_or(Value::Null),
            );
        }
        let mut reference = Map::new();
        reference.insert("key".into(), Value::Object(key));
        Value::Object(reference)
    }))
}

/// The field reference hook of declared business keys (design §7.4): a key
/// field follows a rename (the declared key and the index name), and a
/// delete of a key field is blocked (`field_in_business_key`). The registry
/// of record (`attome-server/src/field_hooks.rs`) lists it.
#[derive(Debug)]
pub struct BusinessKeyHook;

impl BusinessKeyHook {
    async fn key_of(
        conn: &mut PgConnection,
        entity: &str,
    ) -> Result<Option<(Uuid, Vec<String>)>, AppError> {
        let row: Option<(Uuid, Option<Vec<String>>)> = sqlx::query_as(&format!(
            "SELECT id, business_key FROM entity_info \
             WHERE logicalname = $1 AND {LIVE_ENTITY}"
        ))
        .bind(entity)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        Ok(row.and_then(|(id, fields)| fields.map(|f| (id, f))))
    }
}

impl FieldReferenceHook for BusinessKeyHook {
    fn name(&self) -> &'static str {
        "business_key"
    }

    fn scan<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
        renaming: bool,
    ) -> HookFuture<'a, RefScan> {
        Box::pin(async move {
            let mut scan = RefScan::default();
            let Some((id, fields)) = Self::key_of(conn, entity).await? else {
                return Ok(scan);
            };
            if !fields.iter().any(|f| f == field) {
                return Ok(scan);
            }
            scan.refs.push(FieldRef {
                hook: "business_key",
                object_kind: "entity_business_key".into(),
                object_ref: Some(id),
                name: entity.to_owned(),
                owner: RefOwner::Ours,
            });
            if !renaming {
                scan.blockers.push(Blocker {
                    hook: "business_key",
                    object_kind: "entity_business_key".into(),
                    object_ref: Some(id),
                    name: entity.to_owned(),
                    reason: errors::FIELD_IN_BUSINESS_KEY.to_owned(),
                });
            }
            Ok(scan)
        })
    }

    fn rename<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        old: &'a str,
        new: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            let Some((id, fields)) = Self::key_of(conn, entity).await? else {
                return Ok(HookOutcome::default());
            };
            if !fields.iter().any(|f| f == old) {
                return Ok(HookOutcome::default());
            }
            let renamed: Vec<String> = fields
                .iter()
                .map(|f| if f == old { new.to_owned() } else { f.clone() })
                .collect();
            sqlx::query(
                "UPDATE entity_info SET business_key = $2, modified_at = NOW() \
                 WHERE id = $1",
            )
            .bind(id)
            .bind(&renamed)
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            // The index keeps its columns through the column rename; only its
            // name (which hashes the field names) follows. Transactional DDL,
            // inside the rename's own transaction.
            let from = business_key_index_name(entity, &fields);
            let to = business_key_index_name(entity, &renamed);
            sqlx::query(&format!(
                "ALTER INDEX IF EXISTS {} RENAME TO {}",
                quote_ident(&from),
                quote_ident(&to)
            ))
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            Ok(HookOutcome {
                touched: 1,
                ..HookOutcome::default()
            })
        })
    }

    fn remove<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            // `scan` blocked a delete of a key field; reaching here with the
            // field still in the key is a registry-order defect.
            if let Some((_, fields)) = Self::key_of(conn, entity).await?
                && fields.iter().any(|f| f == field)
            {
                return Err(AppError::Conflict(errors::FIELD_IN_BUSINESS_KEY));
            }
            Ok(HookOutcome::default())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_index_name_is_deterministic_bounded_and_key_specific() {
        let a = business_key_index_name("country", &names(&["code"]));
        assert_eq!(a, business_key_index_name("country", &names(&["code"])));
        assert!(a.starts_with("uxbk_country_"), "{a}");
        assert_eq!(a.len(), "uxbk_country_".len() + 8);
        assert_ne!(a, business_key_index_name("country", &names(&["name"])));
        assert_ne!(
            business_key_index_name("country", &names(&["code", "region"])),
            business_key_index_name("country", &names(&["region", "code"])),
            "column order is part of the key"
        );
        let long = "e".repeat(63);
        let name = business_key_index_name(&long, &names(&["code"]));
        assert!(name.len() <= 63, "{name}");
        assert!(name.starts_with(&format!("uxbk_{}_", "e".repeat(40))));
    }

    #[test]
    fn a_key_has_one_to_four_distinct_valid_fields() {
        assert_eq!(
            normalize_key(&names(&[" code ", "region"])).ok(),
            Some(names(&["code", "region"]))
        );
        for bad in [
            names(&[]),
            names(&["a", "b", "c", "d", "e"]),
            names(&["code", "code"]),
            names(&["Code"]),
            names(&["code;drop"]),
        ] {
            let Err(AppError::Validation(message)) = normalize_key(&bad) else {
                panic!("{bad:?} must be refused");
            };
            assert!(message.starts_with("business_key_invalid"), "{message}");
        }
    }

    fn field(name: &str, field_type: &str) -> KeyFieldRow {
        KeyFieldRow {
            name: name.into(),
            field_type: field_type.into(),
            multi: false,
            lookup_target: None,
            target_has_key: false,
        }
    }

    #[test]
    fn key_fields_follow_the_record_set_rule() {
        let me = Uuid::now_v7();
        let other = Uuid::now_v7();
        let found = [
            field("code", "text"),
            field("rank", "number"),
            field("tags", "choice"),
            KeyFieldRow {
                multi: true,
                ..field("colours", "choice")
            },
            field("photo", "file"),
            KeyFieldRow {
                multi: true,
                ..field("labels", "text")
            },
            KeyFieldRow {
                lookup_target: Some(other),
                ..field("region", "lookup")
            },
            KeyFieldRow {
                lookup_target: Some(other),
                target_has_key: true,
                ..field("parent", "lookup")
            },
            KeyFieldRow {
                lookup_target: Some(me),
                ..field("same", "lookup")
            },
        ];
        assert!(check_key_fields(me, &names(&["code", "rank"]), &found).is_ok());
        assert!(
            check_key_fields(me, &names(&["tags", "code"]), &found).is_ok(),
            "a single-valued choice keys by its code"
        );
        assert!(check_key_fields(me, &names(&["parent"]), &found).is_ok());
        assert!(
            check_key_fields(me, &names(&["same"]), &found).is_ok(),
            "a self lookup's key is the one being declared"
        );
        for bad in [
            "missing", // not a live field
            "colours", // multi-valued choice
            "photo",   // file
            "labels",  // multi-valued
            "region",  // lookup to an entity without a key
        ] {
            let message = check_key_fields(me, &names(&[bad]), &found)
                .err()
                .unwrap_or_else(|| panic!("{bad} must be refused"));
            assert!(message.starts_with("business_key_invalid"), "{message}");
        }
    }

    #[test]
    fn the_outcome_knows_when_the_index_must_follow() {
        let outcome = DeclareOutcome {
            entity: "country".into(),
            before: BusinessKey::default(),
            after: BusinessKey {
                fields: Some(names(&["code"])),
                is_reference_data: true,
            },
            changed: vec!["business_key", "is_reference_data"],
        };
        assert!(outcome.key_changed());
        let flag_only = DeclareOutcome {
            before: BusinessKey {
                fields: Some(names(&["code"])),
                is_reference_data: false,
            },
            ..outcome
        };
        assert!(!flag_only.key_changed());
    }

    #[test]
    fn live_rows_skip_append_only_tables() {
        assert_eq!(live_rows(true), "");
        assert!(live_rows(false).contains("is_active IS NULL OR is_active = true"));
    }
}
