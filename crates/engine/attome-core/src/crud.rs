//! Programmatic entity record operations — same logic as the HTTP handlers in
//! attome-server/entity_crud.rs but callable from other crates without going
//! through HTTP (e.g. attome-audit writing audit records at runtime).
//!
//! `resolve`/`append_only_insert`/`append_only_insert_many` take
//! `&mut PgConnection` (not `&DbPool`) so callers can run them inside an
//! existing `sqlx::Transaction` via `&mut *tx` — required by attome-audit's
//! chain-append transaction (P1.5a+d).
//!
//! **C-17 (M01 §7): scope boundary — read this before adding a caller.**
//! This module sits *below* `attome-records` in the dependency graph
//! (ARCH-1a-i), so it cannot call `entity_mutation::create_one` even if it
//! wanted to — that would be a reverse dependency edge. It is not a
//! general-purpose alternative to the engine's mutation path: no
//! validation, no field-write-grant check, no autovalue, no state-model
//! default, no rule evaluation, no creator-share grant, no audit event of
//! its own, and no change-feed emission. `resolve`/`append_only_insert`/
//! `append_only_insert_many` exist only so an **append-only infrastructure
//! entity** — today, exactly `audit_header`/`audit_detail` — can
//! write its own row from inside a transaction the caller already holds
//! open (the audit chain's actual need: the row being written *is* the
//! audit trail, so routing it back through the engine would try to
//! audit-log the audit log). Any caller that wants to create or update an
//! ordinary entity record from another crate belongs on
//! `attome_records::entity_mutation::create_one`/`update_one`, ideally via
//! `attome_records::mutation_ring::MutationRing::commit_mutation` so it
//! also gets the creator-share grant, audit event, cache invalidation, and
//! rw-pin every other mutation call site gets for free — not this module.

use crate::field_type::FieldType;
use crate::quote_ident;
use attome_types::AppError;
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

/// C-16 (M01 §7): was a hand-copied cast map that had already drifted from
/// `attome_core::FieldType`'s canonical one — it lacked the `choice`/
/// `file` multi-valued arms, so a multi-select or multi-file field inserted
/// through this module failed to cast. Now delegates to the shared codec, so
/// it cannot drift again.
fn sql_cast(attr: &AttrInfo) -> &'static str {
    let ft = FieldType::from_int(attr.field_type_int)
        .unwrap_or(FieldType::Text)
        .storage(attr.options.as_ref());
    ft.sql_cast(attr.options.as_ref().is_some_and(|o| ft.is_multi_valued(o)))
}

/// A multi-select `choice` binds as a Postgres `TEXT[]` literal (`{"a","b"}`);
/// a multi-`file` field stays JSON (bound `::jsonb`, so `Value`'s own
/// stringification is already the right text). Threading `attr` through (C-16,
/// M01 §7's other half of this module's drift — see `sql_cast`) is what a
/// single-arg `json_to_str` had no way to do, which is exactly why a
/// multi-select insert through this path never actually worked even once the
/// cast arm exists.
fn json_to_str(v: &Value, attr: &AttrInfo) -> Option<String> {
    let ft = FieldType::from_int(attr.field_type_int)
        .unwrap_or(FieldType::Text)
        .storage(attr.options.as_ref());
    let multi = attr.options.as_ref().is_some_and(|o| ft.is_multi_valued(o));
    match v {
        Value::Null => None,
        Value::Bool(b) => Some(if *b { "true" } else { "false" }.to_owned()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        Value::Array(_) if ft == FieldType::File && multi => Some(v.to_string()),
        Value::Array(items) => Some(pg_text_array_literal(items)),
        other => Some(other.to_string()),
    }
}

/// Postgres `TEXT[]` literal syntax (`{"a","b"}`), quoting/escaping each
/// element — same convention `attome_records::entity_mutation`'s copy
/// uses for the same case; kept local here (not shared) because it is a
/// plain array-formatting helper, not part of the int<->[`FieldType`] codec
/// C-16 unifies.
fn pg_text_array_literal(items: &[Value]) -> String {
    let mut out = String::from("{");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let s = match item {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        out.push('"');
        for c in s.chars() {
            if c == '"' || c == '\\' {
                out.push('\\');
            }
            out.push(c);
        }
        out.push('"');
    }
    out.push('}');
    out
}

#[derive(sqlx::FromRow)]
struct AttrInfo {
    logicalname: String,
    field_type_int: i32,
    /// `attome_field::ChoiceOptions.multi` / `FileOptions.multi` — needed by
    /// `sql_cast` so a multi-select/multi-file column casts correctly (C-16,
    /// M01 §7). Previously absent here, which is exactly why this module's
    /// cast had drifted from the canonical one.
    options: Option<Value>,
}

/// Resolves an entity by logicalname.
/// Returns `(entity_id, trusted_table_name, is_append_only)`.
/// `entity_name` is sourced from the DB and is safe to interpolate into SQL.
pub async fn resolve(
    conn: &mut PgConnection,
    logicalname: &str,
) -> Result<(Uuid, String, bool), AppError> {
    let row: Option<(Uuid, String, Option<bool>)> = sqlx::query_as(
        "SELECT id, COALESCE(logicalname, ''), is_append_only
         FROM entity_info
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_optional(conn)
    .await
    .map_err(AppError::internal)?;

    let (id, name, append_only) = row.ok_or(AppError::NotFound)?;
    Ok((id, name, append_only.unwrap_or(false)))
}

async fn fetch_attrs(conn: &mut PgConnection, entity_id: Uuid) -> Result<Vec<AttrInfo>, AppError> {
    sqlx::query_as(
        r#"SELECT COALESCE(logicalname, '')  AS logicalname,
                  COALESCE("type", 3)        AS field_type_int,
                  options
           FROM attribute_info
           WHERE entity_ref = $1
             AND (is_active IS NULL OR is_active = true)
             AND logicalname IS NOT NULL AND logicalname <> ''"#,
    )
    .bind(entity_id)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)
}

/// C-17 (M01 §7): a `data` key with no matching attribute logicalname used
/// to be silently dropped (the caller's `INSERT` would just have fewer
/// columns than the caller thought it wrote) — now it is a hard error, so a
/// stale or misspelled field name surfaces immediately instead of quietly
/// losing data.
fn reject_unknown_keys(
    logicalname: &str,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    let known: std::collections::HashSet<&str> =
        attrs.iter().map(|a| a.logicalname.as_str()).collect();
    if let Some(unknown) = obj.keys().find(|k| !known.contains(k.as_str())) {
        return Err(AppError::internal(format!(
            "entity {logicalname:?} has no attribute named {unknown:?} \
             (append_only_insert rejects unrecognised keys rather than dropping them)"
        )));
    }
    Ok(())
}

/// Inserts a record into an entity's physical table via the same dynamic-SQL
/// approach used by the generic HTTP handler. Returns the new record `id`.
///
/// Every `data` key must match a registered attribute logicalname — C-17
/// (M01 §7) turned the earlier silent-drop of an unrecognised key into an
/// error (see [`reject_unknown_keys`]).
///
/// Renamed from `insert` (C-17): see this module's doc comment for the scope
/// boundary the new name is meant to make obvious at every call site.
pub async fn append_only_insert(
    conn: &mut PgConnection,
    logicalname: &str,
    data: &Value,
) -> Result<Uuid, AppError> {
    let (entity_id, entity_name, _) = resolve(&mut *conn, logicalname).await?;
    let attrs = fetch_attrs(&mut *conn, entity_id).await?;

    let obj = data
        .as_object()
        .ok_or_else(|| AppError::internal("data must be a JSON object"))?;
    reject_unknown_keys(logicalname, &attrs, obj)?;

    let mut cols = Vec::new();
    let mut placeholders = Vec::new();
    let mut values: Vec<Option<String>> = Vec::new();
    let mut p = 1usize;

    for attr in &attrs {
        if let Some(val) = obj.get(&attr.logicalname) {
            cols.push(quote_ident(&attr.logicalname));
            placeholders.push(format!("${p}{}", sql_cast(attr)));
            values.push(json_to_str(val, attr));
            p += 1;
        }
    }

    if cols.is_empty() {
        return Err(AppError::internal(
            "data contained no fields matching registered attributes",
        ));
    }

    // entity_name is DB-sourced (trusted), not from user input; quoted (as
    // are the column names above) so a logicalname matching a reserved word
    // still parses.
    let table = quote_ident(&entity_name);
    let sql = format!(
        "INSERT INTO {table} ({cols}) VALUES ({phs}) RETURNING id",
        cols = cols.join(", "),
        phs = placeholders.join(", "),
    );

    let mut q = sqlx::query_scalar::<_, Uuid>(&sql);
    for v in &values {
        q = q.bind(v.clone());
    }

    q.fetch_one(conn).await.map_err(AppError::internal)
}

/// Inserts many rows into an entity's physical table as a single multi-row
/// `INSERT ... VALUES (...),(...)`. Resolves entity + attribute metadata
/// exactly once regardless of `rows.len()` — the fix for the N+1 that
/// `append_only_insert()` has when called once per row in a loop (P1.5d).
///
/// Every row must have the same shape (same set of recognised keys) — true
/// for all current callers (e.g. attome-audit's per-field detail rows, which are
/// built from the same `json!` template). Column set is taken from the first
/// row; a later row missing one of those keys binds SQL `NULL` for it. Every
/// row's keys are still checked against the registered attributes (C-17):
/// an unrecognised key on *any* row is rejected, not just one absent from the
/// first row's (silently narrower) column set.
///
/// Renamed from `insert_many` (C-17): see this module's doc comment for the
/// scope boundary the new name is meant to make obvious at every call site.
pub async fn append_only_insert_many(
    conn: &mut PgConnection,
    logicalname: &str,
    rows: &[Value],
) -> Result<(), AppError> {
    if rows.is_empty() {
        return Ok(());
    }

    let (entity_id, entity_name, _) = resolve(&mut *conn, logicalname).await?;
    let attrs = fetch_attrs(&mut *conn, entity_id).await?;

    let first_obj = rows[0]
        .as_object()
        .ok_or_else(|| AppError::internal("data must be a JSON object"))?;
    reject_unknown_keys(logicalname, &attrs, first_obj)?;

    let cols: Vec<&AttrInfo> = attrs
        .iter()
        .filter(|a| first_obj.contains_key(&a.logicalname))
        .collect();

    if cols.is_empty() {
        return Err(AppError::internal(
            "data contained no fields matching registered attributes",
        ));
    }

    let mut row_groups = Vec::with_capacity(rows.len());
    let mut values: Vec<Option<String>> = Vec::with_capacity(rows.len() * cols.len());
    let mut p = 1usize;

    for (i, row) in rows.iter().enumerate() {
        let obj = row
            .as_object()
            .ok_or_else(|| AppError::internal("data must be a JSON object"))?;
        if i > 0 {
            reject_unknown_keys(logicalname, &attrs, obj)?;
        }

        let mut placeholders = Vec::with_capacity(cols.len());
        for attr in &cols {
            placeholders.push(format!("${p}{}", sql_cast(attr)));
            values.push(
                obj.get(&attr.logicalname)
                    .and_then(|v| json_to_str(v, attr)),
            );
            p += 1;
        }
        row_groups.push(format!("({})", placeholders.join(", ")));
    }

    let col_names: Vec<String> = cols.iter().map(|a| quote_ident(&a.logicalname)).collect();

    // entity_name/col_names are DB-sourced (trusted), not from user input;
    // quoted so a logicalname matching a reserved word still parses.
    let table = quote_ident(&entity_name);
    let sql = format!(
        "INSERT INTO {table} ({cols}) VALUES {groups}",
        cols = col_names.join(", "),
        groups = row_groups.join(", "),
    );

    let mut q = sqlx::query(&sql);
    for v in &values {
        q = q.bind(v.clone());
    }

    q.execute(conn).await.map_err(AppError::internal)?;
    Ok(())
}
