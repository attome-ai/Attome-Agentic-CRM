//! Y2-T6: a single-value choice field's values held by the database as well:
//! `ck_<entity>_<field>_chc`, `CHECK (<col> IN (<literals>))` (a NULL passes,
//! as every CHECK lets it).
//!
//! Removing a choice value keeps the stored values in place (design §3.5: no
//! data step), so a check of the current choices alone would refuse every
//! later write to a record that still holds a removed value (a CHECK is
//! tested on every UPDATE of the row, whichever column changed). The check
//! therefore admits the current choices **plus every value the column still
//! holds** that is not one of them (V2-D1925). The generic engine refuses a
//! removed value on write; the database refuses anything that was never a
//! value of the column. Finding the kept values reads the column, so the
//! rebuild runs inline only at or under the size gate and through the
//! durable `SyncChoiceCheck` job above it.
//!
//! The check is rebuilt, never edited:
//!
//! * a change to the choices (add, remove, a type conversion) drops it in the
//!   change's own transaction ([`drop_choice_check_in_tx`], catalog only), so
//!   a value just added is never refused by the old check;
//! * after commit, [`request_choice_check`] rebuilds it from the committed
//!   choices: added `NOT VALID` (no scan), then `VALIDATE CONSTRAINT`.
//!
//! Left out: a multi-valued choice (`TEXT[]`, not in this task), and a field
//! that names an option set (its codes change when the set is published,
//! and a retired code stays stored; the set's publish path does not rebuild
//! field checks yet). Literals are quoted by the server (`quote_literal`);
//! no value is spliced into SQL by this process.

use attome_core::{FieldType, quote_ident};
use attome_db::DbPool;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgConnection;

use super::ddl::exec_ddl_locked;
use super::field_change::{choices_of, map_ddl_error};
use super::identifiers::{field_constraint_name, is_multi_valued, valid_identifier};

/// The rows a table may hold for its choice check to be rebuilt inline; a
/// bigger table rebuilds it through the `SyncChoiceCheck` job.
pub const CHOICE_CHECK_INLINE_ROW_LIMIT: i64 = 10_000;

/// More distinct kept values than this and the field keeps no check: a
/// column that loose is not a choice list worth holding in the catalog.
pub const MAX_KEPT_VALUES: i64 = 1_000;

/// The check's name for `entity.field` (`ck_<entity>_<field>_chc`, hashed
/// when longer than PostgreSQL's 63 bytes).
pub fn choice_check_name(entity: &str, field: &str) -> Result<String, AppError> {
    field_constraint_name(entity, field, "chc")
}

/// Whether a field with this type and options carries a choice check. Pure.
pub fn wants_choice_check(field_type: &str, options: Option<&Value>) -> bool {
    field_type == FieldType::Choice.as_str()
        && !is_multi_valued(field_type, options)
        && !options.is_some_and(|o| o.get("option_set").is_some())
        && !choices_of(options).is_empty()
}

/// The values the check admits: the choices in order, then the kept values
/// that are not choices, each once. Pure.
pub fn admitted_values(choices: &[String], kept: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(choices.len() + kept.len());
    for v in choices.iter().chain(kept) {
        if !out.contains(v) {
            out.push(v.clone());
        }
    }
    out
}

/// Drops `entity.field`'s choice check in the caller's transaction (the
/// caller set the DDL bounds). Catalog only, no scan.
pub async fn drop_choice_check_in_tx(
    conn: &mut PgConnection,
    entity: &str,
    field: &str,
) -> Result<(), AppError> {
    if !valid_identifier(entity) || !valid_identifier(field) {
        return Err(AppError::Validation("invalid schema identifier".into()));
    }
    sqlx::query(&format!(
        "ALTER TABLE {} DROP CONSTRAINT IF EXISTS {}",
        quote_ident(entity),
        quote_ident(&choice_check_name(entity, field)?)
    ))
    .execute(&mut *conn)
    .await
    .map_err(map_ddl_error)?;
    Ok(())
}

/// What rebuilding a field's check did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChoiceCheck {
    /// The check holds the admitted values and is valid.
    Valid,
    /// The table is over the size gate; the rebuild is queued.
    Queued,
    /// The field carries no check (not a single-value inline choice list,
    /// or too many kept values).
    None,
}

#[derive(sqlx::FromRow)]
struct FieldOptions {
    type_int: i32,
    options: Option<Value>,
}

/// The committed type and options of `entity.field`, `None` when the field
/// is gone or inactive.
async fn read_field(
    db: &DbPool,
    entity: &str,
    field: &str,
) -> Result<Option<(String, Option<Value>)>, AppError> {
    let row: Option<FieldOptions> = sqlx::query_as(
        r#"SELECT COALESCE(a."type", 3) AS type_int, a.options
           FROM attribute_info a
           JOIN entity_info e ON e.id = a.entity_ref
           WHERE e.logicalname = $1 AND a.logicalname = $2
             AND (a.is_active IS NULL OR a.is_active = true)"#,
    )
    .bind(entity)
    .bind(field)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(|r| {
        (
            FieldType::from_int(r.type_int)
                .unwrap_or(FieldType::Text)
                .as_str()
                .to_owned(),
            r.options,
        )
    }))
}

/// Rebuilds `entity.field`'s choice check now, whatever the table's size:
/// reads the kept values (a scan of the column), replaces the check
/// `NOT VALID`, validates it. The `SyncChoiceCheck` job and the inline path
/// of [`request_choice_check`] both end here.
pub async fn sync_choice_check(
    db: &DbPool,
    entity: &str,
    field: &str,
) -> Result<ChoiceCheck, AppError> {
    if !valid_identifier(entity) || !valid_identifier(field) {
        return Err(AppError::internal(format!(
            "invalid identifier for a choice check: {entity}.{field}"
        )));
    }
    let table = quote_ident(entity);
    let column = quote_ident(field);
    let name = quote_ident(&choice_check_name(entity, field)?);
    let drop_sql = format!("ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}");
    exec_ddl_locked(db, &[], &drop_sql)
        .await
        .map_err(AppError::internal)?;

    let Some((field_type, options)) = read_field(db, entity, field).await? else {
        return Ok(ChoiceCheck::None);
    };
    if !wants_choice_check(&field_type, options.as_ref()) {
        return Ok(ChoiceCheck::None);
    }
    let choices = choices_of(options.as_ref());

    // The values rows still hold that are no longer choices (bound, never
    // spliced). One more than the cap tells "too many" apart.
    let kept: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT DISTINCT {column}::text FROM {table} \
          WHERE {column} IS NOT NULL AND {column}::text <> ALL($1::text[]) \
          LIMIT {}",
        MAX_KEPT_VALUES + 1
    ))
    .bind(&choices)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if i64::try_from(kept.len()).unwrap_or(i64::MAX) > MAX_KEPT_VALUES {
        tracing::warn!(
            entity = %entity, field = %field, kept = kept.len(),
            "choice field holds too many values outside its choices; it keeps no database check"
        );
        return Ok(ChoiceCheck::None);
    }
    if !kept.is_empty() {
        tracing::info!(
            entity = %entity, field = %field, kept = kept.len(),
            "choice check also admits values records still hold"
        );
    }
    let admitted = admitted_values(&choices, &kept);
    // The server quotes every literal.
    let literals: String = sqlx::query_scalar(
        "SELECT string_agg(quote_literal(v), ', ' ORDER BY n) \
           FROM unnest($1::text[]) WITH ORDINALITY AS u(v, n)",
    )
    .bind(&admitted)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    exec_ddl_locked(
        db,
        &[],
        &format!(
            "ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({column}::text IN ({literals})) NOT VALID"
        ),
    )
    .await
    .map_err(AppError::internal)?;
    if let Err(e) = exec_ddl_locked(
        db,
        &[],
        &format!("ALTER TABLE {table} VALIDATE CONSTRAINT {name}"),
    )
    .await
    {
        // A value written between the read of kept values and the validate
        // (an older node, a raw write): leave no half-made check behind; a
        // later rebuild picks the value up as kept.
        let _ = exec_ddl_locked(db, &[], &drop_sql).await;
        tracing::warn!(
            entity = %entity, field = %field, error = %e,
            "choice check did not validate; the field keeps no database check until the next rebuild"
        );
        return Ok(ChoiceCheck::None);
    }
    Ok(ChoiceCheck::Valid)
}

/// Rebuilds `entity.field`'s choice check from its committed choices:
/// inline when the table holds at most `inline_row_limit` rows, else by
/// queueing `SyncChoiceCheck` (dedup-keyed on the field).
pub async fn request_choice_check(
    db: &DbPool,
    entity: &str,
    field: &str,
    inline_row_limit: i64,
) -> Result<ChoiceCheck, AppError> {
    if super::table_row_count_exceeds(db, entity, inline_row_limit).await? {
        attome_jobs::enqueue_dedup(
            db,
            attome_core::jobs::EngineJob::SyncChoiceCheck {
                entity_logicalname: entity.to_owned(),
                field_logicalname: field.to_owned(),
            },
            &format!("choice-check:{entity}.{field}"),
        )
        .await
        .map_err(AppError::internal)?;
        return Ok(ChoiceCheck::Queued);
    }
    sync_choice_check(db, entity, field).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_single_value_inline_choice_lists_are_checked() {
        let list = json!({ "choices": ["open", "won"] });
        assert!(wants_choice_check("choice", Some(&list)));
        assert!(!wants_choice_check("text", Some(&list)));
        let multi = json!({ "choices": ["a"], "multi": true });
        assert!(!wants_choice_check("choice", Some(&multi)));
        let set = json!({ "option_set": "stage", "choices": ["a"] });
        assert!(!wants_choice_check("choice", Some(&set)));
        assert!(!wants_choice_check(
            "choice",
            Some(&json!({ "choices": [] }))
        ));
        assert!(!wants_choice_check("choice", None));
    }

    #[test]
    fn admitted_values_keep_choice_order_then_kept_values_once() {
        let choices = vec!["open".to_owned(), "won".to_owned()];
        let kept = vec!["lost".to_owned(), "open".to_owned(), "lost".to_owned()];
        assert_eq!(
            admitted_values(&choices, &kept),
            vec!["open", "won", "lost"]
        );
        assert_eq!(admitted_values(&choices, &[]), choices);
    }

    #[test]
    fn check_names_fit_postgres() {
        assert_eq!(
            choice_check_name("deal", "stage").unwrap(),
            "ck_deal_stage_chc"
        );
        let long = choice_check_name(&"e".repeat(48), &"f".repeat(48)).unwrap();
        assert!(long.len() <= 63 && long.ends_with("_chc"));
    }
}
