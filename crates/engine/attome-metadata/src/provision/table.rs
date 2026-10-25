//! Physical table/column provisioning for entities and attributes.

use attome_core::quote_ident;
use attome_db::DbPool;
use attome_types::AppError;

use super::ddl::{
    TableColumns, column_exists, exec_ddl_locked, existing_columns, is_concurrent_create_race,
};
use super::grants::grant_readonly_select;
use super::identifiers::{MAX_IDENTIFIER_LEN, pg_type_for, valid_identifier};

/// P-db-maintenance item (a) — storage-parameter defaults by table class.
/// Numbers are the plan's stated starting point, not yet measured against a
/// real load (step 1 of that plan is unrun — see DECISIONS.md); re-tune once
/// a seeded-volume measurement exists, don't treat these as a production SLA.
///
/// Mutable entity tables: `row_version` (D-037) bumps on every UPDATE, so a
/// lower fillfactor keeps room for HOT updates (no index-column change on an
/// ordinary edit) and a lower scale_factor triggers autovacuum earlier, before
/// dead-tuple accumulation gets expensive to catch up on.
const MUTABLE_STORAGE_PARAMS: &str =
    "fillfactor = 90, autovacuum_vacuum_scale_factor = 0.02, autovacuum_vacuum_cost_delay = 2";

/// Append-only entity tables (`is_append_only`, e.g. future audit-adjacent
/// entities provisioned through this generic path — the audit family itself
/// is migration-owned, see migrations/0026_audit_partitioning.sql): never
/// UPDATEd after insert, so fillfactor stays at 100 and autovacuum tunes off
/// insert volume instead of the update/delete-driven default.
const APPEND_ONLY_STORAGE_PARAMS: &str = "fillfactor = 100, autovacuum_vacuum_insert_scale_factor = 0.02, autovacuum_vacuum_scale_factor = 0.05, autovacuum_vacuum_cost_delay = 2";

/// Creates the physical table backing an entity, if no table by this name
/// exists at all. Idempotent and self-healing for entities whose
/// `entity_info` row was registered before a physical table existed.
///
/// Deliberately does NOT reshape a table that already exists under this name —
/// system entities (api_key, etc.) are provisioned by real migrations
/// with their own schema, which may not match the generic shape below. The
/// one exception is `row_version` (F027/D-037): the generic UPDATE path
/// increments it on every registered entity, so any table reachable through
/// entity_crud gets the column backfilled here, idempotently. Storage
/// parameters (P-db-maintenance item (a)) follow the same self-healing
/// pattern: applied on CREATE for new tables, backfilled via an idempotent
/// `ALTER TABLE ... SET` on every boot for tables provisioned before this
/// existed — deliberately not a one-off migration, since migrations can't
/// enumerate dynamically-provisioned entity table names (DDL ownership,
/// D-003) — only entity provisioning knows what tables exist.
///
/// P-provisioning-hardening item (c): every ALTER below runs through
/// `exec_ddl_locked` instead of directly on the pool, and the catalog
/// pre-check (`existing_columns`) skips an ALTER entirely once its column
/// is already present — after the first boot per node, a steady-state
/// reseed issues zero ALTER TABLE statements for row_version/modified_at/
/// modified_by. The pre-check is an *optimization*, NOT the correctness
/// mechanism: every ALTER still keeps IF NOT EXISTS, so the TOCTOU race
/// between two nodes booting concurrently stays handled by Postgres's own
/// idempotent DDL, exactly as before. Do not drop IF NOT EXISTS because
/// "the pre-check already handles it" — it doesn't, on its own.
///
/// C-20 extends the same pre-check to the four ALTERs that used to run
/// unconditionally every boot regardless of column existence (storage
/// parameters, and the `id`/`created_at`/`is_active` `SET DEFAULT`s):
/// `existing_columns` now also carries each column's stored default
/// expression and the table's `pg_class.reloptions`, so
/// `backfill_storage_params`/`backfill_system_columns`/`ensure_is_active`
/// skip the ALTER once the catalog already matches the desired value —
/// on a 133-entity deployment that was ~530 ACCESS EXCLUSIVE transactions
/// per node boot, now zero once every table's already correct.
///
/// The phases run in a fixed order — create, storage parameters, system
/// columns, `is_active`, partial indexes, the TIMESTAMPTZ backfill, the
/// read-only grant — and each is its own function below so the sequence
/// reads top-to-bottom here. Do not reorder them: `is_active`'s default and
/// the partial indexes assume the column phase has run.
pub(super) async fn provision_table(
    db: &DbPool,
    logicalname: &str,
    is_append_only: bool,
) -> Result<(), AppError> {
    if !valid_identifier(logicalname) {
        return Err(AppError::internal(format!(
            "invalid entity logicalname (lowercase/digits/underscore, max {MAX_IDENTIFIER_LEN} chars): {logicalname}"
        )));
    }

    let storage_params = if is_append_only {
        APPEND_ONLY_STORAGE_PARAMS
    } else {
        MUTABLE_STORAGE_PARAMS
    };

    if existing_columns(db, logicalname).await?.is_none() {
        create_table(db, logicalname, storage_params).await?;
    }

    // Re-read after a possible CREATE so every phase below (storage params,
    // row_version, modified_at/modified_by, is_active, and the TIMESTAMPTZ
    // backfill further down) sees the table's real current column set, not
    // the pre-CREATE `None` snapshot.
    let cols = existing_columns(db, logicalname).await?.ok_or_else(|| {
        AppError::internal(format!(
            "table {logicalname} missing immediately after provisioning"
        ))
    })?;

    let is_partitioned = is_partitioned_table(db, logicalname).await?;
    backfill_storage_params(db, logicalname, storage_params, &cols, is_partitioned).await?;
    backfill_system_columns(db, logicalname, &cols).await?;
    let has_is_active = ensure_is_active(db, logicalname, &cols, is_append_only).await?;
    if has_is_active && !is_partitioned {
        create_partial_indexes(db, logicalname).await?;
    }
    backfill_timestamptz(db, logicalname, &cols).await?;

    // P-stored-query-containment phase 1(a) / D-126: migration 0046 revoked
    // attome_readonly's blanket `SELECT ON ALL TABLES`/default-privileges
    // grant — this table (new or pre-existing) must be re-granted
    // explicitly, or it silently stops being reachable through
    // `/api/v1/query/execute` (D-036 routes every entity list through that
    // surface). Unconditional and idempotent, same reasoning as the
    // storage-parameter/id-default ALTERs above: a GRANT is metadata-only
    // and safe to re-run on every boot.
    grant_readonly_select(db, logicalname).await?;

    Ok(())
}

/// One locked, retried DDL statement against `logicalname`'s table, with
/// the failure logged under `what` before it is masked as `internal`. Every
/// provisioning ALTER that needs no session settings goes through here.
async fn ddl(db: &DbPool, logicalname: &str, what: &str, sql: &str) -> Result<(), AppError> {
    exec_ddl_locked(db, &[], sql).await.map_err(|e| {
        tracing::error!(error = %e, logicalname = %logicalname, "{what} failed during provisioning");
        AppError::internal(e)
    })
}

/// The generic entity-table shape. Matches the system-column convention used
/// across entity_info / attribute_info and read by
/// attome-server's generic entity_crud dispatcher (which soft-deletes via
/// `is_active`, not a separate flag). created_at gets a DB default because
/// entity_crud::create_record only inserts user-defined attribute columns,
/// never system columns itself. row_version is F027's optimistic-concurrency
/// counter (D-037).
async fn create_table(
    db: &DbPool,
    logicalname: &str,
    storage_params: &str,
) -> Result<(), AppError> {
    let sql = format!(
        r#"CREATE TABLE IF NOT EXISTS "{logicalname}" (
               id               UUID PRIMARY KEY DEFAULT uuidv7(),
               created_at        TIMESTAMPTZ DEFAULT NOW(),
               created_by        UUID,
               modified_at       TIMESTAMPTZ,
               modified_by       UUID,
               organization_ref UUID,
               is_active        BOOLEAN DEFAULT TRUE,
               row_version      BIGINT NOT NULL DEFAULT 0,
               owner_ref        UUID,
               owner_type       SMALLINT NOT NULL DEFAULT 0
           ) WITH ({storage_params})"#
    );
    // C-20: `provision_table` (this function's caller) now runs before any
    // serializing advisory lock, so two genuinely concurrent callers
    // creating the same brand-new entity can both reach this statement —
    // treat the loser's `duplicate_table` the same as if `IF NOT EXISTS`
    // had caught it locally (see `is_concurrent_create_race`).
    match exec_ddl_locked(db, &[], &sql).await {
        Ok(()) => Ok(()),
        Err(e) if is_concurrent_create_race(&e) => Ok(()),
        Err(e) => {
            tracing::error!(error = %e, logicalname = %logicalname, "CREATE TABLE failed during provisioning");
            Err(AppError::internal(e))
        }
    }
}

/// Postgres 18 rejects storage parameters on a partitioned table's parent
/// outright ("specify them for its leaf partitions instead"), and flatly
/// rejects `CREATE INDEX CONCURRENTLY` there too — found by actually running
/// this against attomedb_test: the audit family
/// (migrations/0026_audit_partitioning.sql) is migration-owned AND reachable
/// through this same provisioning path (`attome-audit/src/seed.rs` calls
/// `ensure_entity` for metadata registration even though the physical table
/// is migration-owned), so `provision_table` runs against an
/// already-partitioned table on every boot. The phases that cannot apply to
/// a partitioned parent skip it; migration 0026 already owns storage
/// parameters and indexes for its own partitions.
async fn is_partitioned_table(db: &DbPool, logicalname: &str) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM pg_class c
             JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = current_schema() AND c.relname = $1 AND c.relkind = 'p'
         )",
    )
    .bind(logicalname)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Parses a comma-separated `"key = value"` storage-parameter spec (the
/// shape `MUTABLE_STORAGE_PARAMS`/`APPEND_ONLY_STORAGE_PARAMS` are written
/// in) into normalized `(key, value)` pairs, for comparison against
/// Postgres's own `pg_class.reloptions` text shape (`"key=value"`, no
/// surrounding whitespace).
fn parse_storage_params(spec: &str) -> Vec<(String, String)> {
    spec.split(',')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// C-20: whether `current_reloptions` (as read from `pg_class.reloptions`)
/// already expresses exactly the same key/value pairs as `desired` — order
/// doesn't matter, but an extra or missing key does (a stale option left
/// over from an old code path must still trigger the ALTER).
fn storage_params_match(desired: &str, current_reloptions: &[String]) -> bool {
    let mut desired_pairs = parse_storage_params(desired);
    let mut current_pairs: Vec<(String, String)> = current_reloptions
        .iter()
        .filter_map(|opt| {
            let (k, v) = opt.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    desired_pairs.sort();
    current_pairs.sort();
    desired_pairs == current_pairs
}

/// P-db-maintenance item (a) backfill for tables provisioned before this
/// existed (or whose is_append_only flag changed) — a no-op if the CREATE
/// already set the same values. C-20: `existing_columns` now carries
/// `pg_class.reloptions` alongside the column map, so this skips the ALTER
/// entirely once the catalog already matches `storage_params` exactly
/// (`storage_params_match`) — before this, the ALTER ran unconditionally
/// every boot, ~530 ACCESS EXCLUSIVE transactions per node boot on a
/// 133-entity deployment. The catalog check is an optimization, not the
/// correctness mechanism: the ALTER itself still gains the
/// lock_timeout+retry safety from `exec_ddl_locked`, which is the actual
/// outage fix — a boot can be slow but can no longer wedge live traffic
/// indefinitely behind it. Skipped on a partitioned parent (see
/// `is_partitioned_table`).
async fn backfill_storage_params(
    db: &DbPool,
    logicalname: &str,
    storage_params: &str,
    cols: &TableColumns,
    is_partitioned: bool,
) -> Result<(), AppError> {
    if is_partitioned || storage_params_match(storage_params, &cols.reloptions) {
        return Ok(());
    }
    ddl(
        db,
        logicalname,
        "storage-parameter backfill ALTER",
        &format!(r#"ALTER TABLE "{logicalname}" SET ({storage_params})"#),
    )
    .await
}

/// The self-healing system-column backfills for a table that predates one
/// of the generic entity conventions — each skipped entirely once the
/// pre-check shows the column present (IF NOT EXISTS remains the
/// correctness backstop, not the skip mechanism — see `provision_table`).
async fn backfill_system_columns(
    db: &DbPool,
    logicalname: &str,
    cols: &TableColumns,
) -> Result<(), AppError> {
    // F027 backfill for tables created before row_version existed (including
    // migration-owned system entities like api_key).
    if !cols.contains_key("row_version") {
        ddl(
            db,
            logicalname,
            "row_version backfill ALTER",
            &format!(r#"ALTER TABLE "{logicalname}" ADD COLUMN IF NOT EXISTS row_version BIGINT NOT NULL DEFAULT 0"#),
        )
        .await?;
    }

    // Same backfill, for modified_at/modified_by — legacy core_* bootstrap tables
    // (core_job, organization, privilege) predate both columns, but
    // entity_crud's generic UPDATE unconditionally stamps `modified_at = NOW()`
    // on every row (D-005's entity-table convention), so any such table reached
    // through registration needs them before Update works.
    if !cols.contains_key("modified_at") {
        ddl(
            db,
            logicalname,
            "modified_at backfill ALTER",
            &format!(
                r#"ALTER TABLE "{logicalname}" ADD COLUMN IF NOT EXISTS modified_at TIMESTAMPTZ"#
            ),
        )
        .await?;
    }
    if !cols.contains_key("modified_by") {
        ddl(
            db,
            logicalname,
            "modified_by backfill ALTER",
            &format!(r#"ALTER TABLE "{logicalname}" ADD COLUMN IF NOT EXISTS modified_by UUID"#),
        )
        .await?;
    }

    // Same backfill, for created_at/created_by. The fresh CREATE TABLE emits
    // both, but a migration-owned table that predates the D-005 entity
    // convention has neither, and registration alone did not add them:
    // `entity_mutation::create_one` splices `created_by` into every INSERT
    // column list from the caller's context, and `select_columns` names both
    // in the RETURNING projection. So a registered legacy table missing them
    // named a column that does not exist, Postgres answered 42703, and the
    // client saw a bare 500 on every create. team (0051), plus
    // api_key, license, and user_account_mm_team, are
    // the live cases — organization/user_account happen to
    // carry both from 0000_core_bootstrap.sql, which is why generic create
    // worked there and nowhere else.
    if !cols.contains_key("created_at") {
        ddl(
            db,
            logicalname,
            "created_at backfill ALTER",
            &format!(
                r#"ALTER TABLE "{logicalname}" ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ"#
            ),
        )
        .await?;
    }

    // Added without a default above, then defaulted here — deliberately the
    // same two-step `is_active` uses (`ensure_is_active`), and for the same
    // reason. Adding the column WITH `DEFAULT NOW()` would stamp every
    // pre-existing row with the backfill's own timestamp, asserting a
    // creation time that never happened; leaving those rows NULL says
    // "unknown", which is true. `create_one` never binds created_at itself,
    // so new rows still need the default — and applying it unconditionally
    // also heals a legacy table that has the column with no default at all.
    // C-20: skipped once `pg_get_expr` already reports `now()` for this
    // column — Postgres's canonical text for `DEFAULT NOW()`.
    if cols.default_expr("created_at") != Some("now()") {
        ddl(
            db,
            logicalname,
            "created_at default backfill ALTER",
            &format!(r#"ALTER TABLE "{logicalname}" ALTER COLUMN created_at SET DEFAULT NOW()"#),
        )
        .await?;
    }

    if !cols.contains_key("created_by") {
        ddl(
            db,
            logicalname,
            "created_by backfill ALTER",
            &format!(r#"ALTER TABLE "{logicalname}" ADD COLUMN IF NOT EXISTS created_by UUID"#),
        )
        .await?;
    }

    // D-137 backfill for tables provisioned before owner_ref/owner_type
    // existed. Same self-healing pattern as row_version/modified_at/modified_by
    // above — this column is denormalized-and-synced from
    // `entity_mutation::create_one`/`attome_security::admin::reassign_owner`,
    // never consulted by `rls_predicate` (see `ALL_SYSTEM_COLS`'s doc
    // comment), so backfilling it onto an existing table is a pure additive,
    // zero-behavior-change column — nothing reads it yet for any pre-existing
    // row, exactly like `row_version`'s own backfill story (D-037).
    if !cols.contains_key("owner_ref") {
        ddl(
            db,
            logicalname,
            "owner_ref backfill ALTER",
            &format!(r#"ALTER TABLE "{logicalname}" ADD COLUMN IF NOT EXISTS owner_ref UUID"#),
        )
        .await?;
    }
    if !cols.contains_key("owner_type") {
        ddl(
            db,
            logicalname,
            "owner_type backfill ALTER",
            &format!(
                r#"ALTER TABLE "{logicalname}" ADD COLUMN IF NOT EXISTS owner_type SMALLINT NOT NULL DEFAULT 0"#
            ),
        )
        .await?;
    }
    // `attome_security::rls` names `organization_ref` in the BusinessUnit tier
    // for every non-admin read, so a registered migration-owned table without
    // it (role is one) answered every such read with 42703 and a
    // bare 500. Nullable and default-free, so a metadata-only ALTER; a NULL
    // org never matches the tier, leaving existing rows share-only.
    if !cols.contains_key("organization_ref") {
        ddl(
            db,
            logicalname,
            "organization_ref backfill ALTER",
            &format!(
                r#"ALTER TABLE "{logicalname}" ADD COLUMN IF NOT EXISTS organization_ref UUID"#
            ),
        )
        .await?;
    }

    // Some legacy core_* bootstrap tables declare `id UUID PRIMARY KEY` with no
    // column default (D-018 — by design, their existing call sites generate
    // Uuid::now_v7() explicitly in Rust). entity_crud::create_record never sets
    // id itself — it relies on the DB default, same as created_at — so a
    // registered legacy table needs one too. An explicit id in an INSERT always
    // overrides a column default, so this is a no-op for every pre-existing
    // caller. C-20: skipped once the catalog already reports `uuidv7()`.
    if cols.default_expr("id") != Some("uuidv7()") {
        ddl(
            db,
            logicalname,
            "id-default backfill ALTER",
            &format!(r#"ALTER TABLE "{logicalname}" ALTER COLUMN id SET DEFAULT uuidv7()"#),
        )
        .await?;
    }
    Ok(())
}

/// Mutable registered tables need is_active for generic CRUD. Append-only
/// tables (including partitioned audit tables) remain exempt because they
/// deliberately have no soft-delete lifecycle. Returns whether the table has
/// the column once this phase is done.
async fn ensure_is_active(
    db: &DbPool,
    logicalname: &str,
    cols: &TableColumns,
    is_append_only: bool,
) -> Result<bool, AppError> {
    let mut has_is_active = cols.contains_key("is_active");
    if !is_append_only && !has_is_active {
        // Mutable registered entities must satisfy the generic CRUD contract,
        // whose read/update/delete paths use is_active. DEFAULT TRUE makes
        // existing rows in legacy tables such as team immediately live.
        ddl(
            db,
            logicalname,
            "is_active backfill ALTER",
            &format!(
                r#"ALTER TABLE "{logicalname}" ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE"#
            ),
        )
        .await?;
        has_is_active = true;
    }

    // Column existence (above) is deliberately never forced — append-only
    // tables must not gain one. But a handful of legacy core_* bootstrap
    // tables (e.g. core_job) HAVE the column with no DEFAULT TRUE, unlike the
    // generic entity convention — entity_crud::create_record never sets
    // is_active itself, so an insert leaves it NULL, and every generic read
    // filters `WHERE is_active = true` (NULL never matches), silently hiding
    // every row created through the registered entity. Safe/idempotent to set
    // once the column is confirmed present. C-20: skipped once the catalog
    // already reports `true` — this still runs once right after the ADD
    // COLUMN branch above sets `has_is_active = true` without refreshing
    // `cols`, since that branch's own `DEFAULT TRUE` already makes the very
    // next boot's read skip it.
    if has_is_active && cols.default_expr("is_active") != Some("true") {
        ddl(
            db,
            logicalname,
            "is_active-default backfill ALTER",
            &format!(r#"ALTER TABLE "{logicalname}" ALTER COLUMN is_active SET DEFAULT TRUE"#),
        )
        .await?;
    }
    Ok(has_is_active)
}

/// The two `is_active`-filtered partial indexes every mutable entity table
/// carries. CONCURRENTLY cannot run inside a transaction at all, so these
/// stay direct pool calls, never routed through exec_ddl_locked — and it is
/// flatly rejected on a partitioned parent (there is no "concurrently" on a
/// virtual relation with no storage of its own — it would have to run
/// per-partition), so the caller skips this phase there; a partitioned table
/// that needs these indexes gets them explicitly in whatever migration
/// partitioned it (migration 0026 didn't for the audit family — the per-org
/// queries filter by organization_ref/entity_name, not is_active).
async fn create_partial_indexes(db: &DbPool, logicalname: &str) -> Result<(), AppError> {
    // C-20: same concurrent-create race as `create_table` (see
    // `is_concurrent_create_race`) — two racers provisioning the same
    // brand-new entity can both reach this statement now that it runs
    // before any serializing advisory lock.
    if let Err(e) = sqlx::query(&format!(
        r#"CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_{logicalname}_active" ON "{logicalname}" (id) WHERE is_active = TRUE"#
    ))
    .execute(db)
    .await
        && !is_concurrent_create_race(&e)
    {
        tracing::error!(error = %e, logicalname = %logicalname, "active-index CREATE failed during provisioning");
        return Err(AppError::internal(e));
    }

    // D-137: "my records"/pipeline-by-owner/queue-claim queries filter on
    // owner_ref directly (never through record_share — that table
    // has no per-owner index shape suited to this access pattern, only
    // record_id/principal_id lookups). Same CONCURRENTLY/partitioned-skip
    // reasoning as the active index just above.
    if let Err(e) = sqlx::query(&format!(
        r#"CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_{logicalname}_owner" ON "{logicalname}" (owner_ref) WHERE is_active = TRUE"#
    ))
    .execute(db)
    .await
        && !is_concurrent_create_race(&e)
    {
        tracing::error!(error = %e, logicalname = %logicalname, "owner-index CREATE failed during provisioning");
        return Err(AppError::internal(e));
    }
    Ok(())
}

/// P-provisioning-hardening item (d) / D-101: entity-half of the
/// TIMESTAMP -> TIMESTAMPTZ backfill. New tables are already TIMESTAMPTZ
/// (see `create_table`); this catches tables provisioned before that
/// convention landed. `SET LOCAL timezone = 'UTC'` inside the same
/// transaction as the ALTER makes PG 18 recognize the conversion as
/// binary-compatible (no table rewrite) — values already stored were
/// written by `NOW()` under UTC sessions (guidelines require it), so the
/// conversion is value-preserving. Reuses the `cols` map the caller fetched
/// — once converted, a column no longer matches `data_type == "timestamp
/// without time zone"` and this never fires again for it.
async fn backfill_timestamptz(
    db: &DbPool,
    logicalname: &str,
    cols: &TableColumns,
) -> Result<(), AppError> {
    for (column, info) in &cols.columns {
        if info.data_type == "timestamp without time zone" {
            let quoted_col = quote_ident(column);
            exec_ddl_locked(
                db,
                &["SET LOCAL timezone = 'UTC'"],
                &format!(r#"ALTER TABLE "{logicalname}" ALTER COLUMN {quoted_col} TYPE timestamptz"#),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, logicalname = %logicalname, column = %column, "TIMESTAMPTZ backfill ALTER failed during provisioning");
                AppError::internal(e)
            })?;
        }
    }
    Ok(())
}

/// Y2-T7: the column types whose values go to TOAST and are worth lz4.
fn compresses_with_lz4(pg_type: &str) -> bool {
    let upper = pg_type.trim().to_ascii_uppercase();
    upper.starts_with("TEXT") || upper.starts_with("JSONB")
}

/// Y2-T7: whether this server was built with lz4 (`default_toast_compression`
/// offers it). Asked once per process; a server without it gets a single
/// warning and pglz columns.
async fn lz4_available(db: &DbPool) -> bool {
    static AVAILABLE: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();
    // A failed probe is not cached: the next column asks again.
    let probe = AVAILABLE
        .get_or_try_init(|| async {
            let available = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM pg_settings \
                 WHERE name = 'default_toast_compression' AND 'lz4' = ANY(enumvals))",
            )
            .fetch_one(db)
            .await?;
            if !available {
                tracing::warn!(
                    "this PostgreSQL has no lz4; new text and JSON columns use the default compression"
                );
            }
            Ok::<bool, sqlx::Error>(available)
        })
        .await;
    probe.copied().unwrap_or(false)
}

/// A17-T1: the column a hierarchy lookup's tree path is stored in.
pub const HIERARCHY_PATH_COLUMN: &str = "hier_path";

/// A17-T1: the deepest tree the path backfill walks.
const HIERARCHY_BACKFILL_DEPTH: u32 = 100;

/// A17-T1: whether `options` flag a lookup as its entity's hierarchy
/// (`"hierarchy": true`). Only a lookup from an entity to itself is one.
pub fn is_hierarchy_lookup(options: Option<&serde_json::Value>) -> bool {
    options
        .and_then(|o| o.get("hierarchy"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// A17-T1: the stored tree path of `entity`'s hierarchy lookup `field`.
/// Each row's `hier_path` is its ancestors' ids and its own, joined by `/`
/// (`root/…/parent/id`), with a `text_pattern_ops` index so a subtree is one
/// prefix scan. Two triggers keep it right whichever path writes the row: a
/// row inserted, or whose parent changes, takes its parent's path plus its
/// id; a moved row's descendants are rewritten in one `UPDATE` by the old
/// prefix. Existing rows are filled once, when the triggers are first
/// created. Idempotent: a later reconcile finds the column and triggers and
/// does nothing.
pub(super) async fn ensure_hierarchy_path(
    db: &DbPool,
    entity_id: uuid::Uuid,
    entity: &str,
    field: &str,
) -> Result<(), AppError> {
    if !valid_identifier(entity) || !valid_identifier(field) {
        return Err(AppError::internal(format!(
            "invalid identifier for a hierarchy path: entity={entity}, field={field}"
        )));
    }
    let installed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t \
           JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid \
           JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = current_schema() AND c.relname = $1 \
            AND t.tgname = 'hier_path_move' AND NOT t.tgisinternal)",
    )
    .bind(entity)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if installed && column_exists(db, entity, HIERARCHY_PATH_COLUMN).await? {
        return Ok(());
    }
    let table = quote_ident(entity);
    let col = quote_ident(field);
    // Function and index names come from the entity id, so they stay unique
    // and under the identifier limit whatever the entity is called.
    let tag = entity_id.simple();
    let set_fn = format!("\"hier_{tag}_set\"");
    let move_fn = format!("\"hier_{tag}_move\"");
    let statements = [
        format!("ALTER TABLE {table} ADD COLUMN IF NOT EXISTS hier_path text"),
        format!(
            "CREATE INDEX IF NOT EXISTS \"hier_{tag}_idx\" ON {table} (hier_path text_pattern_ops)"
        ),
        format!(
            "CREATE OR REPLACE FUNCTION {set_fn}() RETURNS trigger LANGUAGE plpgsql AS $fn$ \
             BEGIN \
               IF TG_OP = 'INSERT' OR NEW.{col} IS DISTINCT FROM OLD.{col} OR NEW.hier_path IS NULL THEN \
                 IF NEW.{col} IS NULL THEN \
                   NEW.hier_path := NEW.id::text; \
                 ELSE \
                   NEW.hier_path := COALESCE( \
                     (SELECT p.hier_path FROM {table} p WHERE p.id = NEW.{col}), \
                     NEW.{col}::text) || '/' || NEW.id::text; \
                 END IF; \
               END IF; \
               RETURN NEW; \
             END $fn$"
        ),
        format!(
            "CREATE OR REPLACE FUNCTION {move_fn}() RETURNS trigger LANGUAGE plpgsql AS $fn$ \
             BEGIN \
               IF OLD.hier_path IS NOT NULL AND NEW.hier_path IS DISTINCT FROM OLD.hier_path THEN \
                 UPDATE {table} SET hier_path = NEW.hier_path || substr(hier_path, length(OLD.hier_path) + 1) \
                  WHERE hier_path LIKE OLD.hier_path || '/%'; \
               END IF; \
               RETURN NULL; \
             END $fn$"
        ),
        format!("DROP TRIGGER IF EXISTS hier_path_set ON {table}"),
        format!(
            "CREATE TRIGGER hier_path_set BEFORE INSERT OR UPDATE ON {table} \
             FOR EACH ROW EXECUTE FUNCTION {set_fn}()"
        ),
        format!("DROP TRIGGER IF EXISTS hier_path_move ON {table}"),
        // Only a change of the parent moves a subtree; the rewrite below
        // touches `hier_path` alone, so it never fires this again.
        format!(
            "CREATE TRIGGER hier_path_move AFTER UPDATE OF {col} ON {table} \
             FOR EACH ROW EXECUTE FUNCTION {move_fn}()"
        ),
        format!(
            "WITH RECURSIVE tree AS ( \
                 SELECT id, id::text AS path, 0 AS depth FROM {table} WHERE {col} IS NULL \
                 UNION ALL \
                 SELECT c.id, tree.path || '/' || c.id::text, tree.depth + 1 \
                   FROM {table} c JOIN tree ON c.{col} = tree.id \
                  WHERE tree.depth < {HIERARCHY_BACKFILL_DEPTH} \
             ) \
             UPDATE {table} e SET hier_path = tree.path FROM tree \
              WHERE e.id = tree.id AND e.hier_path IS DISTINCT FROM tree.path"
        ),
    ];
    for sql in &statements {
        exec_ddl_locked(db, &[], sql).await.map_err(|e| {
            tracing::error!(error = %e, %entity, %field, "hierarchy path provisioning failed");
            AppError::internal(e)
        })?;
    }
    tracing::info!(%entity, %field, "provision: hierarchy path installed");
    Ok(())
}

/// Adds the physical column backing an attribute, if it doesn't already exist.
/// Idempotent and self-healing, same rationale as `provision_table`.
/// `generated` (Y2-T11) is the SQL of a generated formula: the column is
/// then `GENERATED ALWAYS AS (<sql>) STORED`.
pub(super) async fn provision_column(
    db: &DbPool,
    entity_logicalname: &str,
    field_logicalname: &str,
    field_type: &str,
    is_multi: bool,
    generated: Option<&str>,
) -> Result<(), AppError> {
    if !valid_identifier(entity_logicalname) || !valid_identifier(field_logicalname) {
        return Err(AppError::internal(format!(
            "invalid identifier (lowercase/digits/underscore, max {MAX_IDENTIFIER_LEN} chars): entity={entity_logicalname}, field={field_logicalname}"
        )));
    }

    // P-provisioning-hardening item (c): skip the ALTER entirely once the
    // column already exists — same pre-check-is-an-optimization reasoning as
    // `provision_table` (IF NOT EXISTS below remains the TOCTOU-race
    // correctness backstop, not the skip mechanism).
    if column_exists(db, entity_logicalname, field_logicalname).await? {
        return Ok(());
    }

    let pg_type = pg_type_for(field_type, is_multi);
    // Y2-T7: new text and JSON columns compress with lz4 (faster than the
    // default pglz at a similar ratio). Existing columns are left alone;
    // their new values keep pglz.
    let compression = if compresses_with_lz4(pg_type) && lz4_available(db).await {
        " COMPRESSION lz4"
    } else {
        ""
    };
    let generated = generated
        .map(|sql| format!(" GENERATED ALWAYS AS ({sql}) STORED"))
        .unwrap_or_default();
    exec_ddl_locked(
        db,
        &[],
        &format!(
            r#"ALTER TABLE "{entity_logicalname}" ADD COLUMN IF NOT EXISTS "{field_logicalname}" {pg_type}{compression}{generated}"#,
        ),
    )
    .await
    .map_err(|e| {
        tracing::error!(
            error = %e, entity = %entity_logicalname, field = %field_logicalname,
            "ADD COLUMN failed during provisioning"
        );
        AppError::internal(e)
    })?;

    Ok(())
}

/// Permanently drops the physical table backing an entity, if it exists.
/// Irreversible — callers are responsible for removing/checking the
/// `entity_info`/`attribute_info` rows around this call.
///
/// C-20: routed through `exec_ddl_locked` like every other provisioning
/// statement — a bare pool call here had no `lock_timeout`, so a `DROP
/// TABLE` could queue indefinitely (and convoy every other query on the
/// table behind it) instead of retrying/erroring within the same bounded
/// budget the rest of this module already guarantees.
/// Boot sweep: adds the columns row-level security names
/// (`organization_ref`, `owner_ref`, `owner_type`) to every registered entity
/// table that lacks one. `provision_table` heals a table only when its entity
/// is reconciled, and an unchanged platform bundle is skipped at boot, so a
/// table registered before these backfills existed would otherwise keep
/// failing non-admin reads with 42703. One catalog query; DDL only for the
/// tables that need it, so an already-healed database pays one read.
pub async fn backfill_rls_columns(db: &DbPool) -> Result<(), AppError> {
    const COLUMNS: [(&str, &str); 3] = [
        ("organization_ref", "UUID"),
        ("owner_ref", "UUID"),
        ("owner_type", "SMALLINT NOT NULL DEFAULT 0"),
    ];
    let missing: Vec<(String, String)> = sqlx::query_as(
        "SELECT e.logicalname, want.col \
           FROM entity_info e \
           JOIN pg_catalog.pg_class c ON c.relname = e.logicalname AND c.relkind IN ('r', 'p') \
           JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace AND n.nspname = current_schema() \
          CROSS JOIN unnest($1::text[]) AS want(col) \
          WHERE (e.is_active IS NULL OR e.is_active = true) \
            AND NOT EXISTS ( \
                SELECT 1 FROM pg_catalog.pg_attribute a \
                 WHERE a.attrelid = c.oid AND a.attname = want.col \
                   AND a.attnum > 0 AND NOT a.attisdropped) \
          ORDER BY e.logicalname, want.col",
    )
    .bind(COLUMNS.iter().map(|(name, _)| *name).collect::<Vec<_>>())
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    for (logicalname, col) in missing {
        if !valid_identifier(&logicalname) {
            return Err(AppError::internal(format!(
                "invalid entity logicalname in rls column backfill: {logicalname}"
            )));
        }
        let (_, ty) = COLUMNS
            .iter()
            .find(|(name, _)| *name == col)
            .ok_or_else(|| AppError::internal(format!("unexpected column {col}")))?;
        tracing::info!(entity = %logicalname, column = %col, "provision: backfilling an RLS column");
        ddl(
            db,
            &logicalname,
            "rls column backfill ALTER",
            &format!(
                "ALTER TABLE {} ADD COLUMN IF NOT EXISTS {col} {ty}",
                quote_ident(&logicalname)
            ),
        )
        .await?;
    }
    Ok(())
}

pub async fn drop_table(db: &DbPool, logicalname: &str) -> Result<(), AppError> {
    if !valid_identifier(logicalname) {
        return Err(AppError::internal(format!(
            "invalid entity logicalname: {logicalname}"
        )));
    }

    exec_ddl_locked(
        db,
        &[],
        &format!(r#"DROP TABLE IF EXISTS "{logicalname}""#),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, logicalname = %logicalname, "DROP TABLE failed during entity deletion");
        AppError::internal(e)
    })?;

    Ok(())
}
