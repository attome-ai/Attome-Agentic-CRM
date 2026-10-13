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

    if let Some(&(_, excluded)) = CREDENTIAL_ENTITY_EXCLUDED_COLUMNS
        .iter()
        .find(|(name, _)| *name == logicalname)
    {
        return grant_readonly_select_excluding_columns(db, logicalname, excluded).await;
    }

    exec_ddl_locked(
        db,
        &[],
        &format!(r#"GRANT SELECT ON "{logicalname}" TO attome_readonly"#),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, logicalname = %logicalname, "readonly SELECT grant failed during provisioning");
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
    excluded: &[&str],
) -> Result<(), AppError> {
    let cols = existing_columns(db, logicalname).await?.ok_or_else(|| {
        AppError::internal(format!(
            "table {logicalname} missing when granting readonly select"
        ))
    })?;
    let allowed: Vec<String> = cols
        .columns
        .keys()
        .filter(|c| !excluded.contains(&c.as_str()))
        .map(|c| quote_ident(c))
        .collect();
    if allowed.is_empty() {
        return Ok(());
    }

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
    let (credential, whole_table): (Vec<&String>, Vec<&String>) =
        logicalnames.iter().partition(|ln| {
            CREDENTIAL_ENTITY_EXCLUDED_COLUMNS
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
