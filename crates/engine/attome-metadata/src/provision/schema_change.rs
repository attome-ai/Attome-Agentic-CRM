//! P-online-schema-change: classification and durable async execution for
//! `Expensive` schema changes (guidelines §9's callout about routing
//! schema-evolution DDL through a durable job).

use attome_core::quote_ident;
use attome_db::{DbPool, Tx};
use attome_types::AppError;
use uuid::Uuid;

use super::attribute::table_row_count_exceeds;
use super::ddl::exec_ddl_locked;
use super::identifiers::valid_identifier;

/// Which execution path a requested `evolve_attribute_schema` call should
/// take (P-online-schema-change §4(a)/Step 2). `needs_backfill` is `true`
/// exactly when `is_required` is being set to `true` — a genuinely new
/// requirement, so any pre-existing `NULL`s must be backfilled ahead of the
/// terminal `SET NOT NULL`. It is deliberately not conditioned on the
/// column's previous `required` value: re-affirming an already-required
/// column costs nothing extra (the backfill loop below finds zero `NULL`s
/// and returns immediately), and every caller already fully resolves
/// current+requested into one concrete `is_required` value before reaching
/// this point, so there is no "unchanged" case to special-case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeClassification {
    /// At/under the inline threshold, or no scan-bearing statement is
    /// requested at all (`DROP CONSTRAINT`/`DROP NOT NULL` are always
    /// metadata-only). Runs inline, synchronously, as today.
    Cheap,
    /// Over the inline threshold and at least one of `VALIDATE CONSTRAINT`/
    /// `SET NOT NULL` is requested. Must go through
    /// `apply_schema_change_plan` instead of an inline `evolve_attribute_schema`
    /// call.
    Expensive { needs_backfill: bool },
}

/// P-online-schema-change §4(a) Step 2 — decides whether a requested
/// `is_required`/`max_length` change on `entity_logicalname` can run inline
/// or must be queued as an `ApplySchemaChangePlan` job. Mirrors
/// `evolve_attribute_schema`'s own `needs_full_scan` computation exactly, so
/// the two never disagree about which statements actually scan.
pub async fn classify_schema_change(
    db: &DbPool,
    entity_logicalname: &str,
    inline_row_limit: i64,
    is_required: bool,
    max_length: Option<i32>,
) -> Result<ChangeClassification, AppError> {
    // D-788 (amends D-180): required is application-level — it never
    // installs `NOT NULL` and never backfills, so it never scans. Only a
    // `max_length` CHECK's `VALIDATE` does.
    let _ = is_required;
    let needs_full_scan = max_length.is_some();
    if !needs_full_scan {
        return Ok(ChangeClassification::Cheap);
    }
    if table_row_count_exceeds(db, entity_logicalname, inline_row_limit).await? {
        Ok(ChangeClassification::Expensive {
            needs_backfill: false,
        })
    } else {
        Ok(ChangeClassification::Cheap)
    }
}

/// Applies only lossless, independently retryable column-contract changes.
/// Metadata callers invoke this before publishing their metadata change, so a
/// failed validation leaves the prior contract visible to every node.
///
/// Callers are responsible for classifying the change first
/// (`classify_schema_change`) and only reaching this function on the `Cheap`
/// path, or from `apply_schema_change_plan`'s terminal phase once any
/// required backfill has already completed — this function itself no longer
/// gates on table size (P-online-schema-change Step 2/4; superseded the
/// interim "refuse outright" mitigation D-148 shipped, which is now the
/// `Expensive` classification's job-enqueue path instead of a dead end).
pub async fn evolve_attribute_schema(
    db: &DbPool,
    entity_logicalname: &str,
    field_logicalname: &str,
    field_type: &str,
    is_required: bool,
    max_length: Option<i32>,
    is_multi: bool,
) -> Result<(), AppError> {
    if !valid_identifier(entity_logicalname) || !valid_identifier(field_logicalname) {
        return Err(AppError::Validation("invalid schema identifier".into()));
    }
    if max_length.is_some_and(|n| n <= 0) {
        return Err(AppError::Validation(
            "max_length must be greater than zero".into(),
        ));
    }
    if max_length.is_some() && !matches!(field_type, "text" | "file") {
        return Err(AppError::Validation(
            "max_length only applies to text and file fields".into(),
        ));
    }
    // C-22: a multi-valued `file` field is a JSONB column (D-362), and
    // `char_length(jsonb)` below is undefined — Postgres would reject it and
    // this used to surface as an opaque `AppError::internal` deep inside a
    // DDL statement instead of a client-actionable 422. `choice` never
    // reaches here at all (blocked by the check above), so `file` is the only
    // field type this can actually fire for today.
    if max_length.is_some() && is_multi {
        return Err(AppError::Validation(
            "max_length does not apply to multi-valued fields".into(),
        ));
    }

    let table = quote_ident(entity_logicalname);
    let column = quote_ident(field_logicalname);
    let constraint = quote_ident(&format!(
        "ck_{entity_logicalname}_{field_logicalname}_length"
    ));

    // P-online-schema-change Step 1: every statement below routes through
    // `exec_ddl_locked` (SET LOCAL lock_timeout + bounded 55P03 retry) rather
    // than a bare `sqlx::query(...).execute(db)` — this call site was the one
    // provisioning ALTER that D-105's `exec_ddl_locked` hardening had missed
    // (every other ALTER in provision_table/provision_column already goes
    // through it). Error mapping is unchanged: a constraint/nullability
    // failure is still `AppError::Validation` (the admin needs to see it),
    // never masked as `AppError::internal`.
    if let Some(max) = max_length {
        exec_ddl_locked(
            db,
            &[],
            &format!("ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {constraint}"),
        )
        .await
        .map_err(AppError::internal)?;
        exec_ddl_locked(
            db,
            &[],
            &format!(
                "ALTER TABLE {table} ADD CONSTRAINT {constraint} CHECK (char_length({column}) <= {max}) NOT VALID"
            ),
        )
        .await
        .map_err(AppError::internal)?;
        exec_ddl_locked(
            db,
            &[],
            &format!("ALTER TABLE {table} VALIDATE CONSTRAINT {constraint}"),
        )
        .await
        .map_err(|e| {
            AppError::Validation(format!(
                "existing values violate max_length {max} for {field_logicalname}: {e}"
            ))
        })?;
    } else {
        exec_ddl_locked(
            db,
            &[],
            &format!("ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {constraint}"),
        )
        .await
        .map_err(AppError::internal)?;
    }

    // D-788 (amends D-180; SOLUTION-7-PHASE-2-DESIGN.md §3.6): required is
    // application-level. `is_required` stays a metadata property the generic
    // engine enforces on every write that touches the field; the column never
    // carries `NOT NULL`, and existing empty rows stay empty. A `NOT NULL`
    // installed before this rule is dropped here (catalog-only at any size).
    let _ = is_required;
    exec_ddl_locked(
        db,
        &[],
        &format!("ALTER TABLE {table} ALTER COLUMN {column} DROP NOT NULL"),
    )
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

// ── P-online-schema-change: async execution for `Expensive` schema changes ────
//
// Steps 3-5 of `document/detailed-plans/P-online-schema-change.md`. Reuses
// `exec_ddl_locked` (via `evolve_attribute_schema` itself, called once as
// this job's terminal phase) rather than `sync_attribute_index`'s dedicated-
// session/advisory-lock machinery — unlike `CREATE/DROP INDEX CONCURRENTLY`,
// every statement here runs fine inside an ordinary pooled transaction, so a
// plain row-CAS claim (mirroring `automation_staged_import_item`'s crash-recovery
// ledger, D-100) is simpler and no less correct than a session-scoped
// advisory lock.

/// How long a `claimed`/`backfilling`/`altering` row may sit without a
/// progress update before a second worker pass is allowed to reclaim it.
/// Generous relative to expected backfill/ALTER durations so a legitimately
/// slow run on a huge table is never falsely reclaimed mid-flight; short
/// enough that a genuinely crashed worker's row does not sit orphaned for a
/// full release cycle. Untuned, same caveat as the batch size above.
const SCHEMA_CHANGE_CLAIM_TIMEOUT: &str = "30 minutes";

/// A `schema_change_operation` row's fields needed to actually run the
/// plan. `entity_ref` is carried through only for the tracing span below —
/// every DDL/backfill statement addresses the table by logicalname, not by
/// id.
#[derive(sqlx::FromRow)]
struct SchemaChangePlanRow {
    id: Uuid,
    entity_ref: Uuid,
    attribute_ref: Uuid,
    entity_logicalname: String,
    field_logicalname: String,
    field_type: String,
    target_required: bool,
    target_max_length: Option<i32>,
    previous_required: bool,
    previous_max_length: Option<i32>,
    backfill_default: Option<serde_json::Value>,
    backfill_cursor: Option<Uuid>,
    /// C-22: whether the physical column is multi-valued (`TEXT[]`/`JSONB`,
    /// D-078/D-362) — carried on the ledger row itself rather than re-derived
    /// from `attribute_info.options` at apply time, matching this
    /// struct's existing "the ledger row IS the frozen intent" contract (see
    /// `apply_schema_change_plan`'s doc comment). Enforced at enqueue time
    /// (`queue_schema_change_plan_in_tx`) so a request this plan cannot
    /// support 422s immediately instead of surfacing as an internal error
    /// once the async job actually reaches Postgres.
    is_multi: bool,
}

/// Accepts only a JSON scalar (string/number/bool) as a backfill default —
/// multi-valued/choice defaults and structured (object/array) values are out
/// of scope for this plan's backfill phase (see
/// `document/detailed-plans/P-online-schema-change.md` §4's "generic rewrite
/// engine" non-goal). Called both at enqueue time (`admin.rs`, so a bad
/// default 422s immediately instead of failing hours later inside the async
/// job) and by `queue_schema_change_plan_in_tx` itself.
///
/// C-22: `is_multi` refuses outright rather than attempting the value —
/// `backfill_required_nulls`'s `$1::text::{pg_type}` cast is meaningless
/// against a `TEXT[]`/`JSONB` column (a scalar default can't populate an
/// array/object column), and used to reach Postgres and surface as an opaque
/// `AppError::internal` instead of a client-actionable 422.
pub fn validate_backfill_default(
    value: &serde_json::Value,
    is_multi: bool,
) -> Result<(), AppError> {
    if is_multi {
        return Err(AppError::Validation(
            "backfill default_value is not supported for multi-valued fields".into(),
        ));
    }
    scalar_json_as_text(value).map(|_| ())
}

fn scalar_json_as_text(value: &serde_json::Value) -> Result<String, AppError> {
    match value {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        _ => Err(AppError::Validation(
            "backfill default_value must be a string, number, or boolean".into(),
        )),
    }
}

/// The parameter set the three `queue_*` entry points below share verbatim.
///
/// Grouped into a struct rather than passed positionally (MAINT-1) because
/// the list carries two adjacent same-typed pairs — `target_required`/
/// `previous_required` (`bool`) and `target_max_length`/`previous_max_length`
/// (`Option<i32>`). Transposing target with previous compiles cleanly and
/// inverts the plan: the job would install the values it was meant to revert
/// to, and revert to the ones it was asked to install. Named fields make that
/// mistake unrepresentable at the call site, which is the whole reason these
/// eleven are worth a struct while a merely-long heterogeneous list is not.
pub struct SchemaChangePlanRequest<'a> {
    pub entity_id: Uuid,
    pub attribute_id: Uuid,
    pub entity_logicalname: &'a str,
    pub field_logicalname: &'a str,
    pub field_type: &'a str,
    pub target_required: bool,
    pub target_max_length: Option<i32>,
    pub previous_required: bool,
    pub previous_max_length: Option<i32>,
    pub backfill_default: Option<serde_json::Value>,
    /// C-22: whether the target column is multi-valued (`TEXT[]`/`JSONB`) —
    /// see `SchemaChangePlanRow`'s doc comment. Callers compute this the same
    /// way `reconcile.rs` does (`provision::is_multi_valued(field_type,
    /// options)`).
    pub is_multi: bool,
    pub created_by: Uuid,
}

impl std::fmt::Debug for SchemaChangePlanRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaChangePlanRequest")
            .finish_non_exhaustive()
    }
}

/// Inserts the ledger row and enqueues `ApplySchemaChangePlan` in the given
/// transaction — the caller decides whether that's a transaction it already
/// has open (`update_attribute`, alongside the metadata `UPDATE`, for true
/// same-commit atomicity) or a fresh one (`queue_schema_change_plan` below).
pub async fn queue_schema_change_plan_in_tx(
    tx: &mut Tx<'_>,
    req: SchemaChangePlanRequest<'_>,
) -> Result<Uuid, AppError> {
    // C-22: the same refusal `evolve_attribute_schema`/`backfill_required_nulls`
    // apply physically, checked here too so a request this plan can never
    // support 422s at enqueue time instead of failing hours later inside the
    // async job (and, for `create_attribute`/`update_attribute`'s callers,
    // before the metadata `UPDATE` a few lines above this call commits — the
    // whole transaction rolls back on this `Err`).
    if req.is_multi && req.target_max_length.is_some() {
        return Err(AppError::Validation(
            "max_length does not apply to multi-valued fields".into(),
        ));
    }
    if let Some(default_value) = &req.backfill_default {
        validate_backfill_default(default_value, req.is_multi)?;
    }

    let plan_id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO schema_change_operation
               (entity_ref, attribute_ref, entity_logicalname, field_logicalname, field_type,
                target_required, target_max_length, previous_required, previous_max_length,
                backfill_default, is_multi, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
           RETURNING id"#,
    )
    .bind(req.entity_id)
    .bind(req.attribute_id)
    .bind(req.entity_logicalname)
    .bind(req.field_logicalname)
    .bind(req.field_type)
    .bind(req.target_required)
    .bind(req.target_max_length)
    .bind(req.previous_required)
    .bind(req.previous_max_length)
    .bind(req.backfill_default)
    .bind(req.is_multi)
    .bind(req.created_by)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    attome_jobs::enqueue_in_tx(
        tx,
        attome_core::jobs::EngineJob::ApplySchemaChangePlan { plan_id },
    )
    .await
    .map_err(AppError::internal)?;

    Ok(plan_id)
}

/// Standalone-transaction wrapper for callers with no transaction of their
/// own already open. `create_attribute`'s metadata `INSERT`
/// (`ensure_attribute`) already commits before this can run —
/// `ensure_entity`/`ensure_attribute` must run outside the caller's own
/// transaction because `provision_column`'s index maintenance can require
/// `CREATE INDEX CONCURRENTLY`, which Postgres refuses inside a transaction
/// block at all (same constraint documented at `create_entity`'s call site
/// in `admin.rs`). This leaves the same narrow crash window `create_entity`
/// already tolerates between its own metadata commit and its change-log
/// commit — not a new hole this plan introduces.
pub async fn queue_schema_change_plan(
    db: &DbPool,
    req: SchemaChangePlanRequest<'_>,
) -> Result<Uuid, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let plan_id = queue_schema_change_plan_in_tx(&mut tx, req).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(plan_id)
}

/// The `Expensive` half of an attribute contract change (`is_required`/
/// `max_length`), shared by every caller that reconciles an attribute and
/// crosses the size gate (`ChangeClassification::Expensive`): the reconcile
/// primitive deliberately refuses to write the contract pair inline, so this
/// records the target `required`/`max_length` on the metadata row and queues
/// `ApplySchemaChangePlan` in one short transaction — metadata write lock,
/// the `UPDATE`, the queue insert, change log last. `previous_*` are what the
/// plan job reverts to on failure. Originally duplicated in
/// `attome-server/src/admin/attribute.rs` (the admin PATCH path) and
/// `attome-server/src/bundle/apply.rs` (the bundle engine's deferred-contract
/// path, P-environment-promotion §5 step 24 follow-up); generalized here so
/// there is exactly one implementation of "queue the contract change" the way
/// there is exactly one `reconcile_attribute`.
pub async fn queue_contract_change(
    db: &DbPool,
    req: SchemaChangePlanRequest<'_>,
) -> Result<(), AppError> {
    queue_contract_change_recorded(db, req, None).await
}

/// Solution 7 Phase 1 (design §1.1, §4.5) — [`queue_contract_change`] that
/// records `rec.op` (`add_field` / `update_field`) when the plan is queued:
/// the operation is the intent, the `ApplySchemaChangePlan` job records
/// nothing. The row's owner layer is checked under the lock too (the caller's
/// reconcile already checked it before its DDL). `None` is exactly
/// [`queue_contract_change`].
pub async fn queue_contract_change_recorded(
    db: &DbPool,
    req: SchemaChangePlanRequest<'_>,
    rec: Option<super::changeset::RecordAs<'_>>,
) -> Result<(), AppError> {
    use super::changeset;
    changeset::preflight(db, rec).await?;
    // All `Copy`, captured before `req` moves into the queue call below so
    // the change-log append and the recorded op can still name the field.
    let entity_id = req.entity_id;
    let attribute_id = req.attribute_id;
    let entity_logicalname = req.entity_logicalname;
    let field_logicalname = req.field_logicalname;
    let mut changed = Vec::new();
    changeset::diff(
        &mut changed,
        "required",
        &req.previous_required,
        &req.target_required,
    );
    changeset::diff(
        &mut changed,
        "max_length",
        &req.previous_max_length,
        &req.target_max_length,
    );
    let mut tx = attome_db::tx::begin(db).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    let owner_layer: Option<String> = sqlx::query_scalar(
        "UPDATE attribute_info SET required = $2, max_length = $3, modified_at = NOW() \
         WHERE id = $1 AND entity_ref = $4 \
         RETURNING owner_layer",
    )
    .bind(req.attribute_id)
    .bind(req.target_required)
    .bind(req.target_max_length)
    .bind(req.entity_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(owner_layer) = owner_layer else {
        return Err(AppError::NotFound);
    };
    changeset::check_owner(rec, &owner_layer)?;
    queue_schema_change_plan_in_tx(&mut tx, req).await?;
    attome_core::append_change_log(
        &mut tx,
        entity_id,
        entity_logicalname,
        attome_core::ChangeKind::Upsert,
    )
    .await?;
    changeset::record(
        &mut tx,
        rec,
        changeset::ObjectKind::Attribute,
        attribute_id,
        changeset::field_target(entity_logicalname, field_logicalname),
        changed,
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// Row-CAS claim (D-100's `automation_staged_import_item` pattern, not a session
/// advisory lock — see this section's top comment). `Ok(true)` iff this call
/// won the claim; `Ok(false)` means the row is gone, already terminal, or
/// held by a still-live claim, and the caller should simply return without
/// doing any work (apalis will not retry a job that returns `Ok(())`, so a
/// lost race here is not itself a failure — the worker that actually holds
/// the claim is the one making progress).
async fn claim_schema_change_plan(
    db: &DbPool,
    plan_id: Uuid,
    claimed_by: &str,
) -> Result<bool, AppError> {
    let rows_affected = sqlx::query(&format!(
        r#"UPDATE schema_change_operation
           SET status = 'claimed', claimed_by = $1, claimed_at = NOW(),
               row_version = row_version + 1, updated_at = NOW()
           WHERE id = $2 AND is_deleted = false
             AND (status = 'queued'
                  OR (status IN ('claimed', 'backfilling', 'altering')
                      AND claimed_at < NOW() - INTERVAL '{SCHEMA_CHANGE_CLAIM_TIMEOUT}'))"#
    ))
    .bind(claimed_by)
    .bind(plan_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(rows_affected == 1)
}

async fn apply_schema_change_plan_inner(
    db: &DbPool,
    plan: &SchemaChangePlanRow,
) -> Result<(), AppError> {
    tracing::info!(
        plan_id = %plan.id,
        entity_ref = %plan.entity_ref,
        entity = %plan.entity_logicalname,
        field = %plan.field_logicalname,
        "applying schema-change plan"
    );
    // D-788: required is application-level, so a plan never backfills (a
    // `backfill_default` on an older plan row is ignored); only the
    // `max_length` contract is installed below.
    if plan.backfill_default.is_some() || plan.backfill_cursor.is_some() {
        tracing::info!(
            plan_id = %plan.id,
            "schema-change plan: backfill_default ignored (D-788: required is application-level)"
        );
    }

    sqlx::query(
        "UPDATE schema_change_operation SET status = 'altering', updated_at = NOW() WHERE id = $1",
    )
    .bind(plan.id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;

    evolve_attribute_schema(
        db,
        &plan.entity_logicalname,
        &plan.field_logicalname,
        &plan.field_type,
        plan.target_required,
        plan.target_max_length,
        plan.is_multi,
    )
    .await
}

/// `attome_core::jobs::EngineJob::ApplySchemaChangePlan` handler
/// (`crates/server/src/jobs.rs`). A bare `plan_id` pointer, not a
/// desired-state snapshot (matching `BuildAttributeIndex`'s precedent) — but
/// unlike that job, this one does NOT re-read mutable intent before running:
/// the ledger row IS the frozen intent, committed atomically with the
/// metadata write that created it, and re-deriving it from
/// `attribute_info` would just read back what that same transaction
/// already wrote (see `queue_schema_change_plan_in_tx`'s doc comment).
///
/// On success, the ledger row moves to `succeeded` — `attribute_info`
/// already carries the target values (written when the plan was queued), so
/// there is nothing further to commit. On failure at any phase, the ledger
/// row moves to `failed` with `error_message`, and this function also
/// reverts `attribute_info.required`/`max_length` back to the plan's
/// `previous_required`/`previous_max_length` — mirroring
/// `create_attribute`'s existing compensating soft-delete for the create
/// case, "revert" rather than "delete" being the correct undo for an
/// update. A revert failure is logged at `tracing::error!` (best-effort — the
/// caller is already inside an error path) but never panics.
pub async fn apply_schema_change_plan(db: &DbPool, plan_id: Uuid) -> Result<(), AppError> {
    let claimed_by = format!("pid-{}:{}", std::process::id(), Uuid::now_v7());
    if !claim_schema_change_plan(db, plan_id, &claimed_by).await? {
        return Ok(());
    }

    let plan: Option<SchemaChangePlanRow> = sqlx::query_as(
        r#"SELECT id, entity_ref, attribute_ref, entity_logicalname, field_logicalname, field_type,
                  target_required, target_max_length, previous_required, previous_max_length,
                  backfill_default, backfill_cursor, is_multi
           FROM schema_change_operation WHERE id = $1"#,
    )
    .bind(plan_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(plan) = plan else {
        return Ok(());
    };

    match apply_schema_change_plan_inner(db, &plan).await {
        Ok(()) => {
            sqlx::query(
                "UPDATE schema_change_operation SET status = 'succeeded', updated_at = NOW(), row_version = row_version + 1 WHERE id = $1",
            )
            .bind(plan_id)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            Ok(())
        }
        Err(e) => {
            sqlx::query(
                "UPDATE schema_change_operation SET status = 'failed', error_message = $2, updated_at = NOW(), row_version = row_version + 1 WHERE id = $1",
            )
            .bind(plan_id)
            .bind(e.to_string())
            .execute(db)
            .await
            .map_err(AppError::internal)?;

            if let Err(revert_err) = sqlx::query(
                "UPDATE attribute_info SET required = $2, max_length = $3, modified_at = NOW() WHERE id = $1",
            )
            .bind(plan.attribute_ref)
            .bind(plan.previous_required)
            .bind(plan.previous_max_length)
            .execute(db)
            .await
            {
                tracing::error!(
                    error = %revert_err,
                    plan_id = %plan_id,
                    attribute_ref = %plan.attribute_ref,
                    "failed to revert attribute_info after a failed schema-change plan"
                );
            }

            Err(e)
        }
    }
}
