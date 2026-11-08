//! `attome_readonly` SELECT grant maintenance — P-stored-query-containment
//! phase 1(a) / D-126.

use attome_core::credential_columns::CREDENTIAL_ENTITY_EXCLUDED_COLUMNS;
use attome_core::quote_ident;
use attome_db::DbPool;
use attome_types::AppError;

use super::ddl::{exec_ddl_locked, existing_columns};
use super::identifiers::valid_identifier;

/// Grants `attome_readonly` SELECT access to this entity table —
/// P-stored-query-containment phase 1(a) / D-126. Called unconditionally
/// from `provision_table` (CREATE TABLE time and every idempotent reseed)
/// and from `backfill_readonly_grants` (boot backfill for entities that
/// exist but whose owning seed doesn't run on every boot, e.g. an
/// admin-authored custom entity). `user_account`/`api_key` are
/// credential-bearing registered entities and get a column-level grant
/// instead, excluding `password_hash`/`secret_hash` — see
/// `CREDENTIAL_ENTITY_EXCLUDED_COLUMNS`. Routed through `exec_ddl_locked`
/// like every other provisioning statement (a GRANT takes a lock too, and
/// the retry/backoff behavior is the same regardless of statement kind).
pub async fn grant_readonly_select(db: &DbPool, logicalname: &str) -> Result<(), AppError> {
    if !valid_identifier(logicalname) {
        return Err(AppError::internal(format!(
            "invalid entity logicalname for readonly grant: {logicalname}"
        )));
    }

    // Y2-T13: a sensitive attribute is never readable by the BI role, so an
    // entity that has one takes the column-level grant like a credential
    // entity does.
    let mut excluded: Vec<String> = CREDENTIAL_ENTITY_EXCLUDED_COLUMNS
        .iter()
        .find(|(name, _)| *name == logicalname)
        .map(|(_, cols)| cols.iter().map(|c| (*c).to_owned()).collect())
        .unwrap_or_default();
    excluded.extend(sensitive_columns(db, logicalname).await?);

    if !excluded.is_empty() {
        grant_readonly_select_excluding_columns(db, logicalname, &excluded).await?;
    } else {
        exec_ddl_locked(
            db,
            &[],
            &format!(r#"GRANT SELECT ON "{logicalname}" TO attome_readonly"#),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, logicalname = %logicalname, "readonly SELECT grant failed during provisioning");
            AppError::internal(e)
        })?;
    }
    ensure_bi_row_policy(db, logicalname).await
}

/// Y2-T13: the physical columns of `logicalname` whose attribute is marked
/// sensitive (`attribute_info.is_sensitive`). Empty for a table with no
/// metadata row (a join table). Bound, never interpolated.
async fn sensitive_columns(db: &DbPool, logicalname: &str) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        "SELECT a.logicalname FROM attribute_info a \
           JOIN entity_info e ON e.id = a.entity_ref \
          WHERE e.logicalname = $1 AND a.is_sensitive \
            AND (a.is_active IS NULL OR a.is_active = true) \
            AND a.logicalname IS NOT NULL",
    )
    .bind(logicalname)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Y2-T13: every entity that has a sensitive attribute, in one query, for the
/// boot backfill.
async fn entities_with_sensitive_columns(
    db: &DbPool,
) -> Result<std::collections::HashSet<String>, AppError> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT e.logicalname FROM attribute_info a \
           JOIN entity_info e ON e.id = a.entity_ref \
          WHERE a.is_sensitive AND (a.is_active IS NULL OR a.is_active = true) \
            AND e.logicalname IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().collect())
}

/// The roles of the application, which keep reading and writing every row.
const APP_ROLES: &str = "attome_runtime, attome_migrator";

/// Y2-T13: the statement that gives `table` (already quoted) its row policies
/// and turns row-level security on. The application's roles get a permissive
/// policy for everything first, so there is no moment when they see no rows;
/// the read-only role gets one that shows the live rows the application's own
/// lists show (`is_active` NULL counts as live), or all rows for a table with
/// no `is_active` column. The table's owner bypasses row security and
/// superusers too, so the platform's own queries do not change. One `DO`
/// block, so the boot's many tables cost one round trip each. Pure.
pub fn bi_policy_statement(table: &str, has_is_active: bool) -> String {
    let live = if has_is_active {
        "is_active IS NULL OR is_active = true"
    } else {
        "true"
    };
    format!(
        "DO $policy$ BEGIN \
         DROP POLICY IF EXISTS app_all ON {table}; \
         CREATE POLICY app_all ON {table} AS PERMISSIVE FOR ALL TO {APP_ROLES} USING (true) WITH CHECK (true); \
         DROP POLICY IF EXISTS bi_read ON {table}; \
         CREATE POLICY bi_read ON {table} AS PERMISSIVE FOR SELECT TO attome_readonly USING ({live}); \
         ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; \
         END $policy$"
    )
}

/// Y2-T13: row-level security for the read-only (BI) role on one table, so
/// the database never shows it more than the application does. Skipped when
/// the table already has it (the policies are defined once). The application
/// roles' policy comes first and the daily `pg_dump` runs with
/// `--enable-row-security`, so neither the application nor the backup sees
/// fewer rows.
async fn ensure_bi_row_policy(db: &DbPool, logicalname: &str) -> Result<(), AppError> {
    let enabled: Option<bool> = sqlx::query_scalar(
        "SELECT c.relrowsecurity FROM pg_catalog.pg_class c \
           JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = current_schema() AND c.relname = $1",
    )
    .bind(logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if enabled != Some(false) {
        // Already on, or no such table (the grant above has failed first).
        return Ok(());
    }
    let has_is_active = existing_columns(db, logicalname)
        .await?
        .is_some_and(|cols| cols.columns.contains_key("is_active"));
    exec_ddl_locked(
        db,
        &[],
        &bi_policy_statement(&quote_ident(logicalname), has_is_active),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, logicalname = %logicalname, "readonly row policy failed during provisioning");
        AppError::internal(e)
    })
}

/// Column-level counterpart of `grant_readonly_select` for credential-bearing
/// entities. Re-reads the table's current column set on every call so a
/// column added after the entity was first provisioned (`provision_column`)
/// is picked up on the next boot backfill without a separate code path.
async fn grant_readonly_select_excluding_columns(
    db: &DbPool,
    logicalname: &str,
    excluded: &[String],
) -> Result<(), AppError> {
    let cols = existing_columns(db, logicalname).await?.ok_or_else(|| {
        AppError::internal(format!(
            "table {logicalname} missing when granting readonly select"
        ))
    })?;
    let allowed: Vec<String> = cols
        .columns
        .keys()
        .filter(|c| !excluded.contains(c))
        .map(|c| quote_ident(c))
        .collect();
    if allowed.is_empty() {
        return Ok(());
    }

    // A column privilege cannot narrow a table-wide one: a field made
    // sensitive after the table was granted whole is only withheld once the
    // table-wide grant is taken back (REVOKE on the table also takes back its
    // column grants), then the allowed columns are granted again.
    exec_ddl_locked(
        db,
        &[],
        &format!(r#"REVOKE SELECT ON "{logicalname}" FROM attome_readonly"#),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, logicalname = %logicalname, "readonly SELECT revoke failed during provisioning");
        AppError::internal(e)
    })?;
    exec_ddl_locked(
        db,
        &[],
        &format!(
            r#"GRANT SELECT ({}) ON "{logicalname}" TO attome_readonly"#,
            allowed.join(", ")
        ),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, logicalname = %logicalname, "readonly column-level SELECT grant failed during provisioning");
        AppError::internal(e)
    })
}

/// P-stored-query-containment phase 1(a) / D-126: boot backfill for entities
/// that already exist but whose owning seed function doesn't re-run
/// `ensure_entity`/`provision_table` on every boot (an admin-authored custom
/// entity, provisioned once via `attome-server/src/admin.rs` and never touched
/// again). Migration 0046 handles the one-time revoke + re-grant for
/// whatever's registered at migration time; this closes the gap for
/// anything registered afterward by a session that then never re-seeds it.
/// Idempotent — safe to call on every boot alongside the other seed steps.
pub async fn backfill_readonly_grants(db: &DbPool) -> Result<(), AppError> {
    let logicalnames: Vec<String> = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info \
         WHERE (is_active IS NULL OR is_active = true) \
           AND logicalname IS NOT NULL AND logicalname <> ''",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    // One `GRANT SELECT ON a, b, c` for every whole-table entity instead of one
    // statement each. The per-entity loop this replaces cost far more than its
    // statement count suggests: `exec_ddl_locked` wraps every call in its own
    // transaction with two `SET LOCAL`s, so each grant was ~5 round-trips, and
    // past 100 entities that is ~500 per boot re-granting what a previous boot
    // already granted. A GRANT naming many tables is still exactly the same
    // grant — this narrows nothing and widens nothing.
    //
    // Credential-bearing entities are deliberately NOT in the batch: they take
    // a column-level grant that must keep excluding `password_hash`/
    // `secret_hash`, and folding them into a whole-table GRANT would hand
    // `attome_readonly` the very columns `CREDENTIAL_ENTITY_EXCLUDED_COLUMNS`
    // exists to withhold.
    // Y2-T13: an entity with a sensitive attribute is column-granted too.
    let sensitive = entities_with_sensitive_columns(db).await?;
    let (credential, whole_table): (Vec<&String>, Vec<&String>) =
        logicalnames.iter().partition(|ln| {
            sensitive.contains(ln.as_str())
                || CREDENTIAL_ENTITY_EXCLUDED_COLUMNS
                    .iter()
                    .any(|(name, _)| *name == ln.as_str())
        });

    for logicalname in credential {
        grant_readonly_select(db, logicalname).await?;
    }

    // Rejected, not skipped: `grant_readonly_select` fails on an invalid
    // logicalname, and a batch that quietly dropped one would leave an entity
    // ungranted with nothing in the log saying so.
    let mut quoted: Vec<String> = Vec::with_capacity(whole_table.len());
    for logicalname in &whole_table {
        if !valid_identifier(logicalname) {
            return Err(AppError::internal(format!(
                "invalid entity logicalname for readonly grant: {logicalname}"
            )));
        }
        quoted.push(quote_ident(logicalname));
    }

    if quoted.is_empty() {
        return Ok(());
    }

    let batched = format!("GRANT SELECT ON {} TO attome_readonly", quoted.join(", "));
    if exec_ddl_locked(db, &[], &batched).await.is_ok() {
        // Y2-T13: the row policies, for each table that has none yet.
        for logicalname in &whole_table {
            ensure_bi_row_policy(db, logicalname).await?;
        }
        return Ok(());
    }

    // One bad table (dropped out from under its metadata row, say) fails the
    // whole batch and the error names the statement, not the culprit. Falling
    // back to the per-entity path costs a slow boot exactly once and restores
    // `grant_readonly_select`'s specific, logicalname-tagged error — the
    // diagnosability the batch would otherwise have taken away.
    tracing::warn!(
        tables = quoted.len(),
        "batched readonly SELECT grant failed — retrying per entity to identify the offender"
    );
    for logicalname in whole_table {
        grant_readonly_select(db, logicalname).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_statement_covers_the_app_roles_before_row_security_is_on() {
        let sql = bi_policy_statement(r#""account""#, true);
        let app = sql
            .find("app_all ON \"account\" AS PERMISSIVE FOR ALL")
            .unwrap();
        let on = sql.find("ENABLE ROW LEVEL SECURITY").unwrap();
        assert!(app < on, "the application's policy exists before RLS is on");
        assert!(sql.contains("TO attome_runtime, attome_migrator USING (true) WITH CHECK (true)"));
        assert!(sql.contains(
            "FOR SELECT TO attome_readonly USING (is_active IS NULL OR is_active = true)"
        ));
        let join = bi_policy_statement(r#""account_contact""#, false);
        assert!(join.contains("TO attome_readonly USING (true)"));
        assert!(!join.contains("is_active"));
    }
}
