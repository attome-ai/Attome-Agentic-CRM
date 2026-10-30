//! Entity/attribute metadata registration and attribute-index synchronization.

use attome_config::AppConfig;
use attome_db::{DbPool, PgConnection};
use attome_types::AppError;
use tokio::sync::Semaphore;
use uuid::Uuid;

use super::ddl::exec_ddl_locked;
use super::identifiers::{
    attribute_index_name, external_id_index_name, field_constraint_name, valid_identifier,
};

/// Caps how many `sync_attribute_index` calls in this process may hold a
/// direct migrator-role connection open at once. `create_migrator_connection`
/// (unlike `create_migrator_pool`) opens a brand-new physical connection per
/// call with no pool ceiling of its own — one attribute create/update takes
/// this cost as the price of a pinned `CONCURRENTLY` session (see the doc
/// comment below), but a bulk metadata import that creates many attributes
/// back-to-back, or a burst of `BuildAttributeIndex` jobs draining
/// concurrently under `config.jobs.worker_concurrency`, would otherwise open
/// one such connection per attribute with no limit — competing with
/// `db_migrator`'s own pooled connections for the migrator role's
/// server-side connection budget (P-db-privilege-separation / D-117) and, in
/// the worst case, exhausting it. This is a background/admin-operation path,
/// not request-latency-sensitive, so a queued build waiting briefly for a
/// permit is harmless; a fixed, conservative, process-local cap is
/// deliberately not wired to config — nobody should need to tune it per
/// deployment (same posture as `DDL_LOCK_TIMEOUT` above).
pub(super) static ATTRIBUTE_INDEX_CONNECTION_LIMIT: Semaphore = Semaphore::const_new(4);

/// Ceiling on `attribute_info` rows per entity — counts soft-deleted
/// attributes too, because `delete_attribute` leaves the physical column in
/// place (P-data-lifecycle owns the purge path) and Postgres's hard limit is
/// 1,600 physical columns per table. A1-T3 raised it from 500 to 1,000; the
/// physical guard [`MAX_COLUMN_SLOTS`] keeps the rest of the margin for the
/// columns PostgreSQL still counts after they are dropped. Deliberately not
/// config-tunable. P-provisioning-hardening item (e).
///
/// Lives here rather than in `attome-types` (BTY-10): it is a statement about
/// this engine's table and Postgres's column limit, not about the wire
/// vocabulary, and attome-types is consumed by crates that have no entities.
pub const MAIN_TABLE_ATTRIBUTE_LIMIT: i64 = 1000;

/// A1-T3: the most column slots a table may use before a new field is
/// refused. PostgreSQL counts every column a table ever had, dropped ones
/// included, toward its 1,600 limit, and frees them only when the table is
/// rebuilt; this keeps 100 in hand.
pub const MAX_COLUMN_SLOTS: i64 = 1500;

/// A1-T3: the column slots `table` uses: every column it has had, dropped
/// ones included.
pub async fn column_slots_used(db: &DbPool, table: &str) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_attribute a \
           JOIN pg_class c ON c.oid = a.attrelid \
          WHERE c.relname = $1 AND c.relnamespace = current_schema()::regnamespace \
            AND a.attnum > 0",
    )
    .bind(table)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// P1.11(h): one btree index serves sortable/filterable access on an
/// attribute AND (T2-1 / due-diligence finding 3.1) the FK existence and
/// cascade-delete/restrict checks `entity_mutation.rs` runs against every
/// Lookup column. `wanted` is the caller's business — `attome-server`'s
/// `admin/attribute.rs` computes it as `is_sortable || is_filterable ||
/// field_type == Lookup`, so a Lookup attribute is always indexed even when
/// an admin never opts into sort/filter. It runs either inline for small
/// tables or in the durable worker for larger tables. Both paths use one
/// direct Postgres session because `CONCURRENTLY` cannot run in a
/// transaction and a PgBouncer transaction-pooled connection cannot retain a
/// session advisory lock across the catalog check and DDL.
#[expect(
    clippy::expect_used,
    reason = "the semaphore is a static that is never closed"
)]
pub async fn sync_attribute_index(
    config: &AppConfig,
    entity_logicalname: &str,
    field_logicalname: &str,
    wanted: bool,
) -> Result<(), AppError> {
    // Held across the connection's whole lifetime (acquire through close),
    // not just the connect call — the goal is bounding concurrently-open
    // sessions, not connection-establishment throughput.
    let _permit = ATTRIBUTE_INDEX_CONNECTION_LIMIT
        .acquire()
        .await
        .expect("ATTRIBUTE_INDEX_CONNECTION_LIMIT is never closed");

    // P-db-privilege-separation / D-117: the migrator identity, not the
    // schema-bootstrap one — this runs from a live admin request or the
    // async index-build job, not `main.rs`'s migration sequence.
    let mut conn = attome_db::UnpooledSession::new(
        attome_db::create_migrator_connection(config)
            .await
            .map_err(AppError::internal)?,
    );
    let result = sync_attribute_index_on_connection(
        &mut conn,
        entity_logicalname,
        field_logicalname,
        wanted,
    )
    .await;
    let unlock = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!(
            "attome-metadata/attribute-index:{entity_logicalname}:{field_logicalname}"
        ))
        .fetch_optional(&mut *conn)
        .await;
    match (&result, unlock) {
        (_, Ok(Some(true))) => {}
        // A successful sync took the lock on this session, so failing to
        // release it means the statements did not all run on one backend —
        // the pinned-session invariant above broke (D-497), and the lock may
        // stay held until that backend closes, turning every later sync of
        // this field into a 409.
        (Ok(()), Ok(_)) => tracing::warn!(
            entity = %entity_logicalname,
            field = %field_logicalname,
            "attribute index advisory lock was not held at release; the session was not \
             pinned and the lock may be stranded until its backend closes — check that \
             database.direct_url bypasses any transaction-mode pgbouncer"
        ),
        (_, Err(e)) => tracing::warn!(
            error = %e,
            entity = %entity_logicalname,
            field = %field_logicalname,
            "failed to release the attribute index advisory lock"
        ),
        // Error paths can return before the lock was taken; `false` is
        // expected there.
        (Err(_), Ok(_)) => {}
    }
    let _ = conn.close().await;
    result
}

/// Runs the synchronization on one direct PostgreSQL session. The lock,
/// catalog probe, repair, and concurrent DDL intentionally share this exact
/// session; a transaction-pooled connection cannot provide that invariant.
pub async fn sync_attribute_index_on_connection(
    conn: &mut PgConnection,
    entity_logicalname: &str,
    field_logicalname: &str,
    wanted: bool,
) -> Result<(), AppError> {
    if !valid_identifier(entity_logicalname) || !valid_identifier(field_logicalname) {
        return Err(AppError::internal(format!(
            "invalid identifier: entity={entity_logicalname}, field={field_logicalname}"
        )));
    }

    let index_name = attribute_index_name(entity_logicalname, field_logicalname)?;
    let lock_key =
        format!("attome-metadata/attribute-index:{entity_logicalname}:{field_logicalname}");
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "attribute index build already in progress",
        ));
    }

    // A partitioned table (the audit detail store) cannot take a concurrent
    // index, and its own migrations index it; an attribute on it gets none.
    let partitioned: bool = sqlx::query_scalar(
        "SELECT COALESCE((SELECT relkind = 'p' FROM pg_class \
         WHERE oid = to_regclass(quote_ident($1))), false)",
    )
    .bind(entity_logicalname)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if partitioned {
        // A1-T6: a high-volume entity's fields are indexed like any other's,
        // but without CONCURRENTLY, which PostgreSQL refuses on a partitioned
        // table: the build holds writes to the table while it runs. The audit
        // family's own migrations index it, so it gets none here.
        if super::storage::storage_mode_of(&mut *conn, entity_logicalname)
            .await?
            .is_high_volume()
        {
            let sql = if wanted {
                format!(
                    "CREATE INDEX IF NOT EXISTS {i} ON {t} ({c}) WHERE is_active = TRUE",
                    i = attome_core::quote_ident(&index_name),
                    t = attome_core::quote_ident(entity_logicalname),
                    c = attome_core::quote_ident(field_logicalname)
                )
            } else {
                format!(
                    "DROP INDEX IF EXISTS {i}",
                    i = attome_core::quote_ident(&index_name)
                )
            };
            sqlx::query(&sql).execute(&mut *conn).await.map_err(|e| {
                tracing::error!(
                    error = %e, index = %index_name, entity = %entity_logicalname,
                    "attribute index sync failed on a high-volume entity"
                );
                AppError::internal(e)
            })?;
            return Ok(());
        }
        tracing::debug!(
            entity = %entity_logicalname,
            field = %field_logicalname,
            "attribute index skipped: the table is partitioned"
        );
        return Ok(());
    }

    let build_in_progress: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_stat_progress_create_index p JOIN pg_class c ON c.oid = p.index_relid WHERE c.relname = $1)",
    )
    .bind(&index_name)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if build_in_progress {
        return Err(AppError::Conflict(
            "attribute index build already in progress",
        ));
    }

    let invalid: Option<bool> = sqlx::query_scalar(
        "SELECT NOT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_class t ON t.oid = i.indrelid WHERE c.relname = $1 AND t.relname = $2",
    )
    .bind(&index_name)
    .bind(entity_logicalname)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if invalid == Some(true) {
        sqlx::query(&format!(
            r#"DROP INDEX CONCURRENTLY IF EXISTS "{index_name}""#
        ))
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }

    if wanted {
        // A2-T3: a geolocation column (`{lat, lng}` JSONB) is indexed as a
        // point, by GiST, so a `within_km` box prefilter can use it.
        let field_type: Option<i32> = sqlx::query_scalar(
            "SELECT a.type FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
             WHERE e.logicalname = $1 AND a.logicalname = $2",
        )
        .bind(entity_logicalname)
        .bind(field_logicalname)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)?
        .flatten();
        let key = if field_type == Some(attome_core::FieldType::Geolocation.to_int()) {
            format!(
                "USING gist ({})",
                attome_core::filter::geo_point_sql(&format!("\"{field_logicalname}\""))
            )
        } else {
            format!("(\"{field_logicalname}\")")
        };
        sqlx::query(&format!(
            r#"CREATE INDEX CONCURRENTLY IF NOT EXISTS "{index_name}" ON "{entity_logicalname}" {key} WHERE is_active = TRUE"#
        ))
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e, index = %index_name, entity = %entity_logicalname, field = %field_logicalname,
                "CREATE INDEX CONCURRENTLY failed during attribute index sync"
            );
            AppError::internal(e)
        })?;
    } else {
        sqlx::query(&format!(
            r#"DROP INDEX CONCURRENTLY IF EXISTS "{index_name}""#
        ))
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, index = %index_name, "DROP INDEX CONCURRENTLY failed during attribute index sync");
            AppError::internal(e)
        })?;
    }

    Ok(())
}

/// Y2-T3: the live lookup attributes (`type` 11) whose physical column has
/// no index leading with it, as `(entity, field)`. A lookup column is always
/// meant to be indexed (FK existence and cascade checks); one created before
/// that rule, or whose build failed, shows up here.
pub async fn lookup_columns_without_index(db: &DbPool) -> Result<Vec<(String, String)>, AppError> {
    sqlx::query_as(
        "SELECT e.logicalname::text, a.logicalname::text
           FROM attribute_info a
           JOIN entity_info e ON e.id = a.entity_ref
           JOIN pg_class t ON t.relname::text = e.logicalname::text
                          AND t.relnamespace = current_schema()::regnamespace
                          AND t.relkind = 'r'
           JOIN pg_attribute c ON c.attrelid = t.oid AND c.attname::text = a.logicalname::text
                              AND NOT c.attisdropped
          WHERE a.type = 11
            AND COALESCE(a.is_active, true) AND COALESCE(e.is_active, true)
            AND NOT EXISTS (SELECT 1 FROM pg_index i
                             WHERE i.indrelid = t.oid AND i.indkey[0] = c.attnum)
          ORDER BY 1, 2",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// AA4-T5: the live, filterable text attributes (`type` 3) whose table's
/// estimated row count (`pg_class.reltuples`) is at least `min_rows` and
/// whose column has no GIN index yet, as `(entity, field)`.
pub async fn trigram_index_candidates(
    db: &DbPool,
    min_rows: i64,
) -> Result<Vec<(String, String)>, AppError> {
    sqlx::query_as(
        "SELECT e.logicalname::text, a.logicalname::text
           FROM attribute_info a
           JOIN entity_info e ON e.id = a.entity_ref
           JOIN pg_class t ON t.relname::text = e.logicalname::text
                          AND t.relnamespace = current_schema()::regnamespace
                          AND t.relkind = 'r'
           JOIN pg_attribute c ON c.attrelid = t.oid AND c.attname::text = a.logicalname::text
                              AND NOT c.attisdropped
          WHERE a.type = 3
            AND COALESCE(a.is_filterable, false)
            AND COALESCE(a.is_active, true) AND COALESCE(e.is_active, true)
            AND t.reltuples >= $1
            AND NOT EXISTS (SELECT 1 FROM pg_index i
                              JOIN pg_class ic ON ic.oid = i.indexrelid
                              JOIN pg_am am ON am.oid = ic.relam
                             WHERE i.indrelid = t.oid AND i.indkey[0] = c.attnum
                               AND am.amname = 'gin')
          ORDER BY 1, 2",
    )
    .bind(min_rows as f64)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// AA4-T5: brings a text field's trigram index in line with what it should
/// have: built (`CONCURRENTLY`, partial on live rows) when the field is a
/// filterable text field and its table holds at least `min_rows` rows by
/// the planner's estimate; dropped when it is no longer a filterable text
/// field; left as it is when only the table is still small. Runs on one
/// direct migrator session under a session advisory lock, like
/// [`sync_attribute_index`], and only from the index-build job, never on a
/// request thread.
#[expect(
    clippy::expect_used,
    reason = "the semaphore is a static that is never closed"
)]
pub async fn sync_trigram_index(
    config: &AppConfig,
    entity_logicalname: &str,
    field_logicalname: &str,
    min_rows: i64,
) -> Result<(), AppError> {
    if !valid_identifier(entity_logicalname) || !valid_identifier(field_logicalname) {
        return Err(AppError::internal(format!(
            "invalid identifier: entity={entity_logicalname}, field={field_logicalname}"
        )));
    }
    let _permit = ATTRIBUTE_INDEX_CONNECTION_LIMIT
        .acquire()
        .await
        .expect("ATTRIBUTE_INDEX_CONNECTION_LIMIT is never closed");
    let mut conn = attome_db::UnpooledSession::new(
        attome_db::create_migrator_connection(config)
            .await
            .map_err(AppError::internal)?,
    );
    let result = sync_trigram_index_on_connection(
        &mut conn,
        entity_logicalname,
        field_logicalname,
        min_rows,
    )
    .await;
    let _ = conn.close().await;
    result
}

/// [`sync_trigram_index`] on one direct session the caller owns: the lock,
/// the checks and the concurrent DDL share it.
pub async fn sync_trigram_index_on_connection(
    conn: &mut PgConnection,
    entity_logicalname: &str,
    field_logicalname: &str,
    min_rows: i64,
) -> Result<(), AppError> {
    if !valid_identifier(entity_logicalname) || !valid_identifier(field_logicalname) {
        return Err(AppError::internal(format!(
            "invalid identifier: entity={entity_logicalname}, field={field_logicalname}"
        )));
    }
    let lock_key =
        format!("attome-metadata/trigram-index:{entity_logicalname}:{field_logicalname}");
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "trigram index build already in progress",
        ));
    }
    let result =
        sync_trigram_index_locked(conn, entity_logicalname, field_logicalname, min_rows).await;
    let _ = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_optional(&mut *conn)
        .await;
    result
}

async fn sync_trigram_index_locked(
    conn: &mut PgConnection,
    entity_logicalname: &str,
    field_logicalname: &str,
    min_rows: i64,
) -> Result<(), AppError> {
    let index_name = super::identifiers::trigram_index_name(entity_logicalname, field_logicalname)?;
    let field: Option<(i32, bool)> = sqlx::query_as(
        "SELECT a.type, COALESCE(a.is_filterable, false)
           FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref
          WHERE e.logicalname = $1 AND a.logicalname = $2
            AND COALESCE(a.is_active, true) AND COALESCE(e.is_active, true)",
    )
    .bind(entity_logicalname)
    .bind(field_logicalname)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let eligible = matches!(field, Some((3, true)));
    // (estimated rows, partitioned)
    let table: Option<(f32, bool)> = sqlx::query_as(
        "SELECT reltuples, relkind = 'p' FROM pg_class WHERE oid = to_regclass(quote_ident($1))",
    )
    .bind(entity_logicalname)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some((rows, partitioned)) = table else {
        return Ok(());
    };
    if partitioned {
        return Ok(());
    }
    if eligible && f64::from(rows) >= min_rows as f64 {
        sqlx::query(&format!(
            r#"CREATE INDEX CONCURRENTLY IF NOT EXISTS "{index_name}" ON "{entity_logicalname}" USING gin ("{field_logicalname}" gin_trgm_ops) WHERE is_active = TRUE"#
        ))
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, index = %index_name, "trigram index build failed");
            AppError::internal(e)
        })?;
        tracing::info!(index = %index_name, rows, "trigram index built");
    } else if !eligible {
        sqlx::query(&format!(
            r#"DROP INDEX CONCURRENTLY IF EXISTS "{index_name}""#
        ))
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

/// Y2-T3: builds the missing lookup-column indexes found by
/// [`lookup_columns_without_index`], each `CONCURRENTLY` (no write lock), at
/// most four at a time ([`ATTRIBUTE_INDEX_CONNECTION_LIMIT`]). A column whose
/// build is already running elsewhere is skipped. Returns how many were
/// built; a second run reports 0. Boot enqueues the same work as durable
/// `BuildAttributeIndex` jobs instead of calling this inline.
pub async fn backfill_lookup_indexes(config: &AppConfig, db: &DbPool) -> Result<u32, AppError> {
    let mut built = 0u32;
    for (entity, field) in lookup_columns_without_index(db).await? {
        match sync_attribute_index(config, &entity, &field, true).await {
            Ok(()) => built += 1,
            Err(AppError::Conflict(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(built)
}

/// A29-T1: how many values of a field more than one live record holds; an
/// external id cannot be declared on a field while this is above zero.
pub async fn count_duplicate_values(
    db: &DbPool,
    entity_logicalname: &str,
    field_logicalname: &str,
) -> Result<i64, AppError> {
    if !valid_identifier(entity_logicalname) || !valid_identifier(field_logicalname) {
        return Err(AppError::internal(format!(
            "invalid identifier: entity={entity_logicalname}, field={field_logicalname}"
        )));
    }
    sqlx::query_scalar(&format!(
        r#"SELECT count(*) FROM (SELECT 1 FROM "{entity_logicalname}"
            WHERE is_active = TRUE AND "{field_logicalname}" IS NOT NULL
            GROUP BY "{field_logicalname}" HAVING count(*) > 1) d"#
    ))
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// A29-T1, A3-T6: makes the unique index of an external-id or unique field
/// match its metadata. The attribute's `options.external_id.system` and
/// `options.unique` are re-read here, so a caller only says which field
/// changed: a live external-id or unique field gets a
/// unique index over its live records (`NULLS DISTINCT`: a record without the
/// id is fine), built `CONCURRENTLY` so writes go on meanwhile; any other
/// field has none. Live records that share a value fail the build: the
/// half-built index is dropped and the caller gets a validation error.
#[expect(
    clippy::expect_used,
    reason = "the semaphore is a static that is never closed"
)]
pub async fn sync_external_id_index(
    config: &AppConfig,
    entity_logicalname: &str,
    field_logicalname: &str,
) -> Result<(), AppError> {
    if !valid_identifier(entity_logicalname) || !valid_identifier(field_logicalname) {
        return Err(AppError::internal(format!(
            "invalid identifier: entity={entity_logicalname}, field={field_logicalname}"
        )));
    }
    let index_name = external_id_index_name(entity_logicalname, field_logicalname)?;
    let _permit = ATTRIBUTE_INDEX_CONNECTION_LIMIT
        .acquire()
        .await
        .expect("ATTRIBUTE_INDEX_CONNECTION_LIMIT is never closed");
    let mut conn = attome_db::UnpooledSession::new(
        attome_db::create_migrator_connection(config)
            .await
            .map_err(AppError::internal)?,
    );
    let lock_key =
        format!("attome-metadata/external-id-index:{entity_logicalname}:{field_logicalname}");
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        let _ = conn.close().await;
        return Err(AppError::Conflict(
            "external id index build already in progress",
        ));
    }
    let result = sync_external_id_index_on_connection(
        &mut conn,
        entity_logicalname,
        field_logicalname,
        &index_name,
    )
    .await;
    if let Err(e) = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_optional(&mut *conn)
        .await
    {
        tracing::warn!(
            error = %e,
            entity = %entity_logicalname,
            field = %field_logicalname,
            "failed to release the external id index advisory lock"
        );
    }
    let _ = conn.close().await;
    result
}

async fn sync_external_id_index_on_connection(
    conn: &mut PgConnection,
    entity_logicalname: &str,
    field_logicalname: &str,
    index_name: &str,
) -> Result<(), AppError> {
    let wanted: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
          WHERE e.logicalname = $1 AND a.logicalname = $2 \
            AND (e.is_active IS NULL OR e.is_active = true) \
            AND (a.is_active IS NULL OR a.is_active = true) \
            AND (COALESCE(a.options->'external_id'->>'system', '') <> '' \
                 OR a.options->'unique' = 'true'::jsonb))",
    )
    .bind(entity_logicalname)
    .bind(field_logicalname)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;

    let drop = format!(r#"DROP INDEX CONCURRENTLY IF EXISTS "{index_name}""#);
    // A build that failed earlier leaves an INVALID index behind.
    let invalid: Option<bool> = sqlx::query_scalar(
        "SELECT NOT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid \
         JOIN pg_class t ON t.oid = i.indrelid WHERE c.relname = $1 AND t.relname = $2",
    )
    .bind(index_name)
    .bind(entity_logicalname)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if invalid == Some(true) || !wanted {
        sqlx::query(&drop)
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    }
    if !wanted {
        return Ok(());
    }
    let created = sqlx::query(&format!(
        r#"CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "{index_name}" ON "{entity_logicalname}" ("{field_logicalname}") WHERE is_active = TRUE"#
    ))
    .execute(&mut *conn)
    .await;
    match created {
        Ok(_) => Ok(()),
        Err(e) => {
            let duplicate = attome_db::is_unique_violation(&e);
            if let Err(drop_error) = sqlx::query(&drop).execute(&mut *conn).await {
                tracing::warn!(error = %drop_error, index = %index_name, "dropping the failed external id index failed");
            }
            if duplicate {
                Err(AppError::Validation(format!(
                    "{field_logicalname}: live records share a value, so it cannot be unique; \
                     fix the duplicates first"
                )))
            } else {
                tracing::error!(
                    error = %e, index = %index_name, entity = %entity_logicalname, field = %field_logicalname,
                    "CREATE UNIQUE INDEX CONCURRENTLY failed for an external id"
                );
                Err(AppError::internal(e))
            }
        }
    }
}

/// A3-T6: how many rows a table may hold for a new field constraint to be
/// checked against them inline; a bigger table keeps it `NOT VALID`.
const FIELD_CONSTRAINT_VALIDATE_ROW_LIMIT: i64 = 10_000;

/// A3-T6: makes a field's database CHECK constraints match its settings: a
/// number range (`range`, inclusive bounds) and a strict required value.
/// Each is replaced, added `NOT VALID` (no scan, and every later write is
/// held to it), then validated against the existing rows when the table is
/// small; a bigger table keeps it `NOT VALID` rather than scan on the request
/// (guidelines §9). Existing rows that break a rule refuse the change, and
/// the constraint is removed again.
pub async fn sync_field_constraints(
    db: &DbPool,
    entity_logicalname: &str,
    field_logicalname: &str,
    range: Option<(Option<f64>, Option<f64>)>,
    strict_required: bool,
) -> Result<(), AppError> {
    if !valid_identifier(entity_logicalname) || !valid_identifier(field_logicalname) {
        return Err(AppError::internal(format!(
            "invalid identifier: entity={entity_logicalname}, field={field_logicalname}"
        )));
    }
    let table = attome_core::quote_ident(entity_logicalname);
    let column = attome_core::quote_ident(field_logicalname);
    let range_name = field_constraint_name(entity_logicalname, field_logicalname, "rng")?;
    let required_name = field_constraint_name(entity_logicalname, field_logicalname, "req")?;
    let mut wanted: Vec<(String, String)> = Vec::new();
    if let Some((min, max)) = range {
        let bounds: Vec<String> = [(min, ">="), (max, "<=")]
            .into_iter()
            .filter_map(|(bound, op)| {
                bound
                    .filter(|b| b.is_finite())
                    .map(|b| format!("{column} {op} {b}"))
            })
            .collect();
        if !bounds.is_empty() {
            wanted.push((range_name.clone(), bounds.join(" AND ")));
        }
    }
    if strict_required {
        wanted.push((required_name.clone(), format!("{column} IS NOT NULL")));
    }
    for name in [&range_name, &required_name] {
        exec_ddl_locked(
            db,
            &[],
            &format!(
                "ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {}",
                attome_core::quote_ident(name)
            ),
        )
        .await
        .map_err(AppError::internal)?;
    }
    if wanted.is_empty() {
        return Ok(());
    }
    let small =
        !table_row_count_exceeds(db, entity_logicalname, FIELD_CONSTRAINT_VALIDATE_ROW_LIMIT)
            .await?;
    for (name, check) in wanted {
        let quoted = attome_core::quote_ident(&name);
        exec_ddl_locked(
            db,
            &[],
            &format!("ALTER TABLE {table} ADD CONSTRAINT {quoted} CHECK ({check}) NOT VALID"),
        )
        .await
        .map_err(AppError::internal)?;
        if !small {
            tracing::info!(
                entity = %entity_logicalname, field = %field_logicalname, constraint = %name,
                "field constraint added NOT VALID: new writes are held to it, existing rows are not checked"
            );
            continue;
        }
        if let Err(e) = exec_ddl_locked(
            db,
            &[],
            &format!("ALTER TABLE {table} VALIDATE CONSTRAINT {quoted}"),
        )
        .await
        {
            let _ = exec_ddl_locked(
                db,
                &[],
                &format!("ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {quoted}"),
            )
            .await;
            tracing::info!(error = %e, constraint = %name, "existing rows break a new field constraint");
            return Err(AppError::Validation(format!(
                "{field_logicalname}: existing records break this rule ({check}); fix them first"
            )));
        }
    }
    Ok(())
}

/// Registers an entity in `entity_info` and ensures its physical
/// table exists (see `provision_table`). Returns the entity id.
///
/// Thin wrapper over [`super::reconcile_entity`] with
/// [`super::ReconcilePolicy::Seed`] (P-environment-promotion §5 step 18), so
/// every existing seed gets reconcile-or-skip for free without changing
/// shape: an existing, non-customized row whose display name /
/// `primary_name_attribute` / `is_append_only` differ from the call is
/// **updated** (it used to be left as it was — the old `ON CONFLICT … DO
/// UPDATE SET logicalname = EXCLUDED.logicalname` was a deliberate no-op);
/// a row an admin customized (`is_customized = true`) is skipped and logged;
/// an identical row costs one SELECT and no lock. The positional arguments
/// this signature lacks (`category`) are passed as `None`, which under
/// `Seed` means "not managed by this seed — leave as is"; `is_audited` is
/// passed as `false` (nothing in the workspace writes that column, so this
/// is a no-op in practice). `primary_name_attribute: None` likewise means
/// "leave as is", not "clear".
///
/// Steady-state hot path (every boot, every entity already registered and
/// unchanged): no global metadata-write lock, no per-entity lock, no log row
/// — only a genuinely new or drifted registration pays for any of those.
/// A *new* registration appends an `metadata_change_log` row (Plan
/// 1.14) in the same transaction; without it, an entity registered by an
/// engine seed never reaches `EntityMetaRegistry` on a node whose
/// `pre_warm_registry` served a pre-existing Redis snapshot.
pub async fn ensure_entity(
    db: &DbPool,
    logicalname: &str,
    display_name: &str,
    primary_name_attribute: Option<&str>,
    is_append_only: bool,
) -> Result<Uuid, AppError> {
    let desc = super::EntityDesc {
        logicalname: logicalname.to_owned(),
        display_name: display_name.to_owned(),
        primary_name_attribute: primary_name_attribute.map(str::to_owned),
        is_append_only,
        is_audited: false,
        category: None,
        storage_mode: Default::default(),
    };
    super::reconcile_entity(db, &desc, super::ReconcilePolicy::Seed)
        .await
        .map(|(id, _)| id)
}

/// Registers an attribute on an entity in `attribute_info` and
/// ensures the physical column exists (see `provision_column`). Returns the
/// attribute id. Index synchronization is intentionally owned by the admin
/// write/worker boundary so large-table requests can commit the metadata and
/// durable job together.
///
/// Thin wrapper over the reconcile primitive with
/// [`super::ReconcilePolicy::Seed`] — same reconcile-or-skip semantics as
/// `ensure_entity` above. `lookup_entity_ref: None` and `options: None` mean
/// "leave as is" on an existing row (and NULL on create); `max_length`,
/// `on_target_delete`, `data_classification`, and `purpose` are not in this
/// signature and are never touched by a seed. A field-type drift between the seed and
/// the registered row is logged at `warn` and left alone (D-055 — never
/// cast, and a boot must not fail over it; `reconcile_attribute` under
/// `Admin`/`Bundle` refuses it with `AppError::Validation`).
/// `is_required`/`max_length` stay metadata-only under `Seed`, exactly as
/// every seed has always behaved.
///
/// The four adjacent `bool`s are the one hazard in this signature — a
/// transposition compiles cleanly and silently flips a flag. It stays
/// positional for now because its ~125 call sites span every engine's seed
/// module and seven DB-backed test suites (MAINT-1, 2026-08-25); the
/// `ensure_attribute_with_index_job` variant that used to sit alongside it
/// was collapsed into this one once `admin/attribute.rs` stopped enqueueing
/// the index job atomically with the metadata write (its only non-`None`
/// caller — see the comment at that enqueue site).
#[allow(clippy::too_many_arguments)] // positional, matches every other provision.rs/seed call site already in this shape
pub async fn ensure_attribute(
    db: &DbPool,
    entity_id: Uuid,
    logicalname: &str,
    display_name: &str,
    field_type: &str,
    is_required: bool,
    is_sensitive: bool,
    is_sortable: bool,
    is_filterable: bool,
    lookup_entity_ref: Option<Uuid>,
    options: Option<serde_json::Value>,
) -> Result<Uuid, AppError> {
    let desc = super::AttributeDesc {
        logicalname: logicalname.to_owned(),
        display_name: display_name.to_owned(),
        field_type: field_type.to_owned(),
        is_required,
        is_sensitive,
        // Seed callers never manage D-507's flag: `None` under `Seed` leaves
        // an admin's or a bundle's setting alone.
        is_write_restricted: None,
        is_sortable,
        is_filterable,
        // Resolved uuid is passed straight through below; the logicalname
        // form is only for callers that start from a bundle/admin payload.
        lookup_entity: None,
        options,
        max_length: None,
        on_target_delete: None,
        data_classification: None,
        purpose: None,
    };
    super::reconcile::reconcile_attribute_with_lookup_ref(
        db,
        entity_id,
        &desc,
        lookup_entity_ref,
        super::ReconcilePolicy::Seed,
        None,
        None,
    )
    .await
    .map(|(id, _)| id)
}

/// Bounded, exact row-count probe shared by the index-build gate and
/// P-online-schema-change's `classify_schema_change` below. Stops once it
/// observes the threshold plus one row rather than relying on planner stats
/// (`pg_class.reltuples`, often `-1`/stale).
pub async fn table_row_count_exceeds(
    db: &DbPool,
    entity_logicalname: &str,
    threshold: i64,
) -> Result<bool, AppError> {
    if !valid_identifier(entity_logicalname) || threshold < 0 {
        return Err(AppError::Validation("invalid row-count probe".into()));
    }
    sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM \"{entity_logicalname}\" OFFSET {threshold})"
    ))
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Kept as a thin, named delegate (P-online-schema-change §4(a)) so the
/// async-index gate's call sites don't need to change even though the probe
/// itself is now shared with the schema-change classifier below.
pub async fn attribute_index_requires_async(
    db: &DbPool,
    entity_logicalname: &str,
    threshold: i64,
) -> Result<bool, AppError> {
    table_row_count_exceeds(db, entity_logicalname, threshold).await
}
