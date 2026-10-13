//! Default list-view/query seeding for a registered entity.

use attome_core::quote_ident;
use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// Registers a default list view for an entity in `sql_query` — the
/// stored-query engine `/api/v1/query/execute` reads from. Without a query
/// row here, the generic entity list page 404s (AppError::NotFound) even
/// though the entity itself is registered. Idempotent — a query already
/// existing for this entity_id is left untouched.
///
/// D-036: the seeded row's `required_privilege` is `{logicalname}.read` — the
/// same per-entity key `entity_crud.rs` checks (D-012) — so the entity list
/// is readable by exactly the users who may read the entity's records, not
/// admin-only. Admin-authored custom queries are unaffected (their NULL
/// `required_privilege` keeps the coarse admin-only default).
///
/// P-stored-query-containment addendum §11(a): unlike `query_admin.rs`'s
/// `create_query`/`update_query`, this INSERT never runs `lint_and_plan` —
/// `sql_query` lands in `sql_query` (and is therefore executable via
/// `/api/v1/query/execute`) without the publish-time relation lint ever
/// seeing it. That is accepted here, not closed, because every current
/// caller (`attome-notification`, `attome-s2s` x3, `attome-audit`, `server`'s
/// `apikey_seed`/`license_seed`/`admin.rs`'s entity-provisioning endpoint —
/// seven call sites total) passes a developer-authored or
/// `quote_ident`-templated literal, never admin/user input, so there is no
/// lint to bypass in the threat-model sense `query_admin.rs` cares about.
/// `reject_unsafe_default_query_sql` turns that "every caller happens to be
/// safe" assumption into an enforced invariant instead of an implicit one:
/// a caller that ever passes a join/union/multi-statement string fails the
/// boot loudly here, rather than silently landing a multi-table query that
/// only the readonly role's per-table grants (migration 0046) would have
/// contained. Deliberately *not* routed through the full `EXPLAIN`-based
/// `lint_and_plan` (that would add a round trip to every entity's boot-time
/// provisioning for zero real risk reduction given the caller shape above);
/// revisit only if a future caller's SQL grows real structural complexity.
pub async fn ensure_default_query(
    db: &DbPool,
    entity_id: Uuid,
    name: &str,
    sql_query: &str,
) -> Result<Uuid, AppError> {
    reject_unsafe_default_query_sql(sql_query)?;
    let existing_query_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM sql_query \
         WHERE entity_logical_name = $1 AND (is_active IS NULL OR is_active = true) \
         AND required_privilege IS NOT NULL \
         ORDER BY created_at ASC NULLS LAST, id LIMIT 1",
    )
    .bind(entity_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    // Solution 7 (D-785): the seeded query and view are side effects of the
    // entity, so they take the entity's own `owner_layer`.
    let (entity_logicalname, owner_layer): (String, String) =
        sqlx::query_as("SELECT logicalname, owner_layer FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;

    // sql_query.id has no column default (unlike entity_info/
    // attribute_info) — this table predates this provisioning module.
    let query_id = if let Some(id) = existing_query_id {
        id
    } else {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO sql_query \
             (id, sql_query, record_no, entity_logical_name, required_privilege, is_active, created_at, \
              owner_layer) \
             VALUES ($1, $2, $3, $4, $5, true, NOW(), $6)",
        )
        .bind(id)
        .bind(sql_query)
        .bind(name)
        .bind(entity_id)
        .bind(format!("{entity_logicalname}.read"))
        .bind(&owner_layer)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        id
    };

    let has_default_view: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM view WHERE entity_logical_name = $1 AND is_default = true AND is_active = true)",
    )
    .bind(entity_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    if !has_default_view {
        // D-429: `view`'s old single `(entity_logical_name, name)`
        // unique constraint became two scope-partitioned partial unique
        // indexes (personal views are unique per-owner, not entity-wide).
        // This insert never sets `scope` (defaults to `system`), so it must
        // name the matching partial index's predicate for Postgres to infer
        // it as the `ON CONFLICT` target at all.
        sqlx::query(
            "INSERT INTO view \
             (id, name, entity_logical_name, sql_query_ref, is_default, is_active, created_at, \
              owner_layer) \
             VALUES ($1, $2, $3, $4, true, true, NOW(), $5) \
             ON CONFLICT (entity_logical_name, name) WHERE scope IN ('system', 'shared') DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(name)
        .bind(entity_id)
        .bind(query_id)
        .bind(&owner_layer)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(query_id)
}

/// Seeds the pair of list views every runtime-created entity gets: an
/// **Active** view (the default the list page opens on) and an **Inactive**
/// companion showing the soft-deleted rows. Both are ordinary
/// `view` rows over ordinary `sql_query` rows, so the list
/// page's existing view picker (`ViewAdminService.listAvailable`) offers them
/// with no further wiring, and an admin can rename, re-column, or delete
/// either one afterwards.
///
/// Deliberately scoped to *runtime-created* entities (`admin::entity::
/// create_entity`) rather than folded into `ensure_default_query` itself:
/// the eight engine-seed call sites of that function pass hand-written SQL
/// whose live/deleted predicate is not uniform (`is_active = TRUE`,
/// `is_deleted = FALSE`, and two with no predicate at all), so there is no
/// sound generic way to derive their "inactive" counterpart. A provisioned
/// entity table, by contrast, always has `is_active` — `provision_table`
/// creates it — so the pair below is always well-formed.
///
/// Idempotent on both halves: `ensure_default_query` already no-ops on a
/// second call, and the Inactive view is matched by its `(entity, name)`
/// unique key.
pub async fn ensure_entity_list_views(
    db: &DbPool,
    entity_id: Uuid,
    entity_logicalname: &str,
    display_name: &str,
) -> Result<(), AppError> {
    ensure_default_query(
        db,
        entity_id,
        &active_view_name(display_name),
        &seeded_view_sql(entity_logicalname, None, true),
    )
    .await?;
    ensure_secondary_view(
        db,
        entity_id,
        entity_logicalname,
        &inactive_view_name(display_name),
        &seeded_view_sql(entity_logicalname, None, false),
    )
    .await?;
    Ok(())
}

/// View names are data, not identifiers — kept in one place so
/// `set_default_query_display_column` and any future backfill agree with
/// what `ensure_entity_list_views` actually wrote.
fn active_view_name(display_name: &str) -> String {
    format!("Active {display_name}")
}

fn inactive_view_name(display_name: &str) -> String {
    format!("Inactive {display_name}")
}

/// Registers a *non-default* view (plus its backing query row) for an entity.
///
/// Differs from `ensure_default_query` in exactly two ways, both required for
/// a second view to exist at all: it never reuses an unrelated existing query
/// row for the entity (that lookup is what makes `ensure_default_query`
/// idempotent, and it would hand the Inactive view the Active view's SQL),
/// and it writes `is_default = false` so the partial unique index
/// `uq_core_view_default_per_entity` (migration 0078) is not violated.
///
/// Same containment rules as `ensure_default_query`: single-table,
/// developer-authored SQL only, checked by `reject_unsafe_default_query_sql`,
/// and the same `{logicalname}.read` required privilege (D-036) so the view
/// is readable by exactly the users who may read the entity's records.
pub async fn ensure_secondary_view(
    db: &DbPool,
    entity_id: Uuid,
    entity_logicalname: &str,
    name: &str,
    sql_query: &str,
) -> Result<Uuid, AppError> {
    reject_unsafe_default_query_sql(sql_query)?;

    // Keyed on the view's own (entity, name) unique key rather than on the
    // query text: renaming the view is an admin's prerogative, but re-running
    // provisioning must not then mint a duplicate.
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT sql_query_ref FROM view \
         WHERE entity_logical_name = $1 AND name = $2",
    )
    .bind(entity_id)
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if let Some(query_id) = existing {
        return Ok(query_id);
    }

    // Solution 7 (D-785): the entity's own `owner_layer`, as in
    // `ensure_default_query`.
    let owner_layer: String =
        sqlx::query_scalar("SELECT owner_layer FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;

    let query_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query \
         (id, sql_query, record_no, entity_logical_name, required_privilege, is_active, created_at, \
          owner_layer) \
         VALUES ($1, $2, $3, $4, $5, true, NOW(), $6)",
    )
    .bind(query_id)
    .bind(sql_query)
    .bind(name)
    .bind(entity_id)
    .bind(format!("{entity_logicalname}.read"))
    .bind(&owner_layer)
    .execute(db)
    .await
    .map_err(AppError::internal)?;

    // D-429: see `ensure_default_query`'s identical comment above — this
    // insert also never sets `scope` (defaults to `system`).
    sqlx::query(
        "INSERT INTO view \
         (id, name, entity_logical_name, sql_query_ref, is_default, is_active, created_at, \
          owner_layer) \
         VALUES ($1, $2, $3, $4, false, true, NOW(), $5) \
         ON CONFLICT (entity_logical_name, name) WHERE scope IN ('system', 'shared') DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(name)
    .bind(entity_id)
    .bind(query_id)
    .bind(&owner_layer)
    .execute(db)
    .await
    .map_err(AppError::internal)?;

    Ok(query_id)
}

/// Rewrites an entity's seeded default query when — and only when — its
/// `sql_query` is still byte-identical to `previous_sql`, the literal a
/// previous release of the seed wrote.
///
/// `ensure_default_query` is insert-only by design: it leaves an existing row
/// untouched, so changing the literal in an engine seed governs fresh
/// databases and nothing else. That is correct for an admin-authored view (an
/// operator's edits must survive a redeploy) but leaves every already-seeded
/// deployment permanently on the old column list, which is exactly the drift
/// `user_account`'s seed comment describes. Matching on the exact prior
/// literal draws the line precisely: a row that still says what this crate
/// wrote is this crate's to correct on the next boot; a row an admin has
/// touched — through `/api/v1/admin/queries`, the API-first path that remains
/// the only way to author a *custom* view — no longer matches and is never
/// clobbered.
///
/// Scoped to the entity's seeded row the same way
/// `set_default_query_display_column` is (`required_privilege =
/// '{logicalname}.read'`, D-036), so an unrelated report query over the same
/// entity is out of reach even if its text somehow collided. Idempotent: the
/// second boot matches zero rows.
///
/// P-environment-promotion ownership rule on top of the literal match: a row
/// an admin touched through the query admin API (`is_customized = true`) is
/// never rewritten even if its SQL still happens to equal the old literal
/// (the admin may have edited another column of the same row) — the skip is
/// logged at `info` with the entity.
pub async fn resync_seeded_query_sql(
    db: &DbPool,
    entity_id: Uuid,
    entity_logicalname: &str,
    previous_sql: &str,
    new_sql: &str,
) -> Result<(), AppError> {
    reject_unsafe_default_query_sql(new_sql)?;
    let updated = sqlx::query(
        "UPDATE sql_query SET sql_query = $1 \
         WHERE entity_logical_name = $2 \
         AND required_privilege = $3 \
         AND (is_active IS NULL OR is_active = true) \
         AND sql_query = $4 \
         AND is_customized = false",
    )
    .bind(new_sql)
    .bind(entity_id)
    .bind(format!("{entity_logicalname}.read"))
    .bind(previous_sql)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if updated > 0 {
        tracing::info!(
            entity = entity_logicalname,
            rows = updated,
            "provision: resynced seeded list-view query to the current release's column list"
        );
        return Ok(());
    }
    // Zero rows is the normal steady state (already resynced, or never on the
    // old literal). Only then is it worth one more query to tell a customized
    // row apart, so the skip is reported rather than silent.
    let skipped: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sql_query \
         WHERE entity_logical_name = $1 \
         AND required_privilege = $2 \
         AND (is_active IS NULL OR is_active = true) \
         AND sql_query = $3 \
         AND is_customized = true",
    )
    .bind(entity_id)
    .bind(format!("{entity_logicalname}.read"))
    .bind(previous_sql)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if skipped > 0 {
        tracing::info!(
            entity = entity_logicalname,
            "provision: seed skipped a customized list-view query row (is_customized = true)"
        );
    }
    Ok(())
}

/// Rewrites an entity's seeded default query's `sql_query` text in place —
/// only ever called for the row `ensure_default_query` created (never an
/// admin-authored custom query; `is_report`/hand-edited rows are a separate
/// concern this never touches). `ensure_default_query` runs at entity-creation
/// time, before any attribute exists, so it can only ever produce
/// `SELECT id FROM ...` (D-036's "seeded default queries carry a read grant"
/// intent, undermined without this: the list page renders zero columns for
/// every entity until an admin hand-edits the query). Called once, when the
/// entity's `primary_name_attribute` attribute is itself created, so the
/// list view immediately has a real display column instead of only `id`.
/// A no-op if no default query row exists yet (caller's problem, not this
/// function's) — matches `ensure_default_query`'s own "idempotent, entity
/// row must already exist" contract. Also a no-op (logged at `info`) when the
/// query row is `is_customized` — an admin already authored its column list
/// through the query admin API, and this seed-time rewrite must not replace
/// it (P-environment-promotion's ownership rule).
pub async fn set_default_query_display_column(
    db: &DbPool,
    entity_id: Uuid,
    entity_logicalname: &str,
    display_attribute_logicalname: &str,
) -> Result<(), AppError> {
    let sql_query = default_display_query_sql(entity_logicalname, display_attribute_logicalname);
    reject_unsafe_default_query_sql(&sql_query)?;
    let updated = sqlx::query(
        "UPDATE sql_query q SET sql_query = $1 \
         FROM view v \
         WHERE v.sql_query_ref = q.id AND v.entity_logical_name = $2 \
         AND v.is_default = true AND v.is_active = true \
         AND (q.is_active IS NULL OR q.is_active = true) \
         AND q.required_privilege = $3 \
         AND q.is_customized = false",
    )
    .bind(&sql_query)
    .bind(entity_id)
    .bind(format!("{entity_logicalname}.read"))
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if updated == 0 {
        let skipped: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sql_query q \
             JOIN view v ON v.sql_query_ref = q.id \
             WHERE v.entity_logical_name = $1 \
             AND v.is_default = true AND v.is_active = true \
             AND (q.is_active IS NULL OR q.is_active = true) \
             AND q.required_privilege = $2 \
             AND q.is_customized = true",
        )
        .bind(entity_id)
        .bind(format!("{entity_logicalname}.read"))
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
        if skipped > 0 {
            tracing::info!(
                entity = entity_logicalname,
                "provision: seed skipped a customized default list-view query row (is_customized = true)"
            );
        }
    }

    // Same fix for the Inactive companion view `ensure_entity_list_views`
    // seeded, which is `is_default = false` and so invisible to the UPDATE
    // above. Matched on its exact pre-attribute SQL text rather than on the
    // view name (an admin may have renamed it) or on "any non-default view"
    // (that would clobber an admin's hand-authored second view): the only row
    // this can hit is one still carrying the id-only string this module
    // itself wrote.
    let inactive_before = seeded_view_sql(entity_logicalname, None, false);
    let inactive_after = seeded_view_sql(
        entity_logicalname,
        Some(display_attribute_logicalname),
        false,
    );
    reject_unsafe_default_query_sql(&inactive_after)?;
    sqlx::query(
        "UPDATE sql_query q SET sql_query = $1 \
         FROM view v \
         WHERE v.sql_query_ref = q.id AND v.entity_logical_name = $2 \
         AND v.is_default = false AND v.is_active = true \
         AND (q.is_active IS NULL OR q.is_active = true) \
         AND q.sql_query = $3 \
         AND q.is_customized = false",
    )
    .bind(&inactive_after)
    .bind(entity_id)
    .bind(&inactive_before)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The exact SQL text of a seeded list view, in its two variants (Active /
/// Inactive) and its two lifecycle stages (before the entity's
/// `primary_name_attribute` exists, and after — `display_attribute` None vs
/// Some). Single builder on purpose: `set_default_query_display_column`
/// upgrades a row by matching the string this produced at create time, so
/// the two call sites must agree character for character.
pub(super) fn seeded_view_sql(
    entity_logicalname: &str,
    display_attribute: Option<&str>,
    is_active_view: bool,
) -> String {
    let columns = match display_attribute {
        Some(attr) => format!("id, {}", quote_ident(attr)),
        None => "id".to_owned(),
    };
    format!(
        "SELECT {} FROM {} WHERE is_active = {}",
        columns,
        quote_ident(entity_logicalname),
        if is_active_view { "true" } else { "false" },
    )
}

/// Pure string-builder pulled out of `set_default_query_display_column` so
/// its exact template shape is unit-testable without a database connection —
/// P-stored-query-containment addendum §11(a)'s "add a unit test asserting
/// the generated SQL always matches a strict template regex" fix, applied to
/// the one call site here that actually generates SQL from parts (the other,
/// `ensure_default_query`, takes the whole string from its caller — see
/// `reject_unsafe_default_query_sql` for that one's invariant instead).
pub(super) fn default_display_query_sql(
    entity_logicalname: &str,
    display_attribute_logicalname: &str,
) -> String {
    seeded_view_sql(
        entity_logicalname,
        Some(display_attribute_logicalname),
        true,
    )
}

/// P-stored-query-containment addendum §11(a) — see `ensure_default_query`'s
/// doc comment for the full rationale. A cheap, dependency-free structural
/// check (no DB round trip, unlike `query_admin.rs::lint_and_plan`'s
/// `EXPLAIN`): rejects a second statement, a `JOIN`, a `UNION`, anything
/// other than exactly one `FROM` clause, or an `ORDER BY`. Every one of the
/// seven current `ensure_default_query` call sites (and
/// `default_display_query_sql` above) is a single-table
/// `SELECT <columns> FROM <table> WHERE ...` literal, so this never rejects
/// real traffic today — it exists to fail loudly the day a future call site's
/// SQL stops being that shape, instead of silently landing an unlinted
/// multi-table query in `sql_query`.
///
/// The `ORDER BY` half is D-350 (finding H-9 / TODO-008), and it is a
/// performance invariant rather than a containment one. `/api/v1/query/execute`
/// runs a stored query as `SELECT … FROM (<stored sql>) AS t <rls> ORDER BY …
/// LIMIT n`. PostgreSQL's subquery pull-up (`is_simple_subquery`) refuses any
/// subquery carrying a `sortClause`, so an inner `ORDER BY` pins the stored SQL
/// as its own plan node: the whole relation is materialised and sorted — every
/// selected column, spilling to disk once it outgrows `work_mem` — before the
/// outer `LIMIT` can take a page. The cost is proportional to the table, not to
/// the page, so on the append-only ledgers it grows with every row ever written
/// and eventually exceeds the 500 ms fast-read `statement_timeout`; three seeded
/// queries (`audit_header`, `s2s_access_log`, `license`) shipped
/// that way and the audit one was measured failing at ~15.6k rows. Unordered,
/// the subquery flattens into the outer query and the `LIMIT` terminates early
/// on an index. Ordering belongs to the caller (`order_by`/`order_dir` on
/// `query/execute`), which is applied outside the subquery where it can.
/// `pub` (not the `pub(super)` every other caller in this file gets) —
/// `attome_records::query_admin::reconcile_query` reuses this exact
/// structural check for a platform bundle's queries (`skip_containment_lint`,
/// see that function's doc comment): attome-records already depends on
/// this crate, so no new dependency edge, and this is the one existing
/// primitive for "developer-authored SQL trusted without the EXPLAIN lint."
pub fn reject_unsafe_default_query_sql(sql_query: &str) -> Result<(), AppError> {
    let upper = sql_query.to_ascii_uppercase();
    // `EXTRACT(field FROM source)` and `SUBSTRING(str FROM start [FOR len])`
    // are standard SQL functions that use the FROM keyword as part of their
    // own call syntax, not a table clause — each occurrence of either
    // function accounts for exactly one FROM that isn't a second table
    // reference. Without this, a legitimate single-table aggregate like
    // `SELECT AVG(EXTRACT(EPOCH FROM (a - b))) FROM one_table` counts two
    // " FROM "s and is wrongly rejected as multi-table (verified live,
    // 2026-09-02, attome-service's SLA mean-time-to-resolve seed).
    let from_in_function_syntax =
        upper.matches("EXTRACT(").count() + upper.matches("SUBSTRING(").count();
    let from_clauses = upper
        .matches(" FROM ")
        .count()
        .saturating_sub(from_in_function_syntax);
    if sql_query.contains(';')
        || upper.contains(" JOIN ")
        || upper.contains(" UNION ")
        || from_clauses != 1
    {
        return Err(AppError::internal(format!(
            "ensure_default_query/set_default_query_display_column: sql_query must be a single-table \
             SELECT with no JOIN/UNION/second statement — this bypasses query_admin.rs's publish-time \
             relation lint, so only a structurally simple, developer-authored literal is safe here: \
             {sql_query}"
        )));
    }
    if upper.contains(" ORDER BY ") {
        return Err(AppError::internal(format!(
            "ensure_default_query/set_default_query_display_column: sql_query must not carry its own \
             ORDER BY (D-350) — query/execute wraps it as a subquery, which PostgreSQL then cannot \
             flatten, so the sort runs over the whole relation before the outer LIMIT applies. Let the \
             caller's order_by/order_dir do the ordering outside the subquery: {sql_query}"
        )));
    }
    Ok(())
}
