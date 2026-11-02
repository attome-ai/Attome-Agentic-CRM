//! A26-T1: derived entities. A derived entity is the anchor entity's rows
//! that match a rule-language condition, under a name of its own: "open
//! deals over 100,000" over `deal`, say. It is read-only (V2-D1628 (1)):
//! every write path refuses it with 405, and its view carries SELECT-only
//! grants.
//!
//! - **Condition.** An `attome-rules` expression over the anchor's own,
//!   non-sensitive fields, translated by the formula-to-SQL translator
//!   ([`attome_core::rules_sql`]); lookups, paths and the clock are refused
//!   until a compiler for them exists.
//! - **Live** mode creates the view `xrm_dv_<name>`: the anchor's live rows
//!   matching the condition, every value a quoted literal.
//! - **Stored** mode also creates the membership table `xrm_dm_<name>`
//!   (`anchor_id`, `entered_at`, `reason`) that A26-T2 maintains, and its
//!   view is the anchor's live rows that are members.
//!
//! The definition is kept in `derived_entity` (migration 0381). The record
//! routes read a derived entity through its anchor's own query, with the
//! condition added, so the anchor's record-level security applies to every
//! member (`attome-records`' `derived_entity` hook).

use std::collections::HashMap;

use attome_core::{EntityMeta, live_row_predicate, quote_ident, select_columns};
use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

use super::ddl::exec_ddl_locked;
use super::identifiers::valid_identifier;

/// The prefix of a derived entity's view.
pub const VIEW_PREFIX: &str = "xrm_dv_";
/// The prefix of a stored derived entity's membership table.
pub const MEMBERSHIP_PREFIX: &str = "xrm_dm_";
/// PostgreSQL's identifier limit, in bytes.
const MAX_IDENT: usize = 63;

/// How a derived entity's members are found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedMode {
    /// The condition, evaluated at every read.
    Live,
    /// A membership table, maintained as records change (A26-T2).
    Stored,
}

impl DerivedMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Stored => "stored",
        }
    }

    /// The mode a stored or requested value names. Pure.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "live" => Some(Self::Live),
            "stored" => Some(Self::Stored),
            _ => None,
        }
    }
}

/// One derived entity's definition.
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedEntity {
    pub name: String,
    pub anchor: String,
    pub condition: String,
    pub mode: DerivedMode,
}

impl DerivedEntity {
    /// The view's name. Pure.
    pub fn view_name(&self) -> String {
        format!("{VIEW_PREFIX}{}", self.name)
    }

    /// The membership table's name. Pure.
    pub fn membership_name(&self) -> String {
        format!("{MEMBERSHIP_PREFIX}{}", self.name)
    }
}

/// The anchor's fields a condition may read: its own, non-sensitive ones.
/// Pure.
fn condition_fields(anchor: &EntityMeta) -> HashMap<String, attome_core::AttrInfo> {
    anchor
        .attrs
        .iter()
        .filter(|a| !a.is_read_gated())
        .map(|a| (a.logicalname.clone(), a.clone()))
        .collect()
}

/// Checks `def` against its anchor and answers the condition as a predicate
/// on the anchor aliased `a`, every value a literal. Refused when the name
/// is not an identifier (or too long once prefixed), names an existing
/// entity, or the condition does not parse or translate. Pure.
pub fn validate(
    def: &DerivedEntity,
    anchor: &EntityMeta,
    entity_exists: impl Fn(&str) -> bool,
) -> Result<String, AppError> {
    if !valid_identifier(&def.name)
        || !def.name.starts_with(|c: char| c.is_ascii_lowercase())
        || VIEW_PREFIX.len() + def.name.len() > MAX_IDENT
    {
        return Err(AppError::Validation(format!(
            "a derived entity's name must be a lower-case identifier of at most {} characters",
            MAX_IDENT - VIEW_PREFIX.len()
        )));
    }
    if entity_exists(&def.name) {
        return Err(AppError::Validation(format!(
            "{} is already an entity",
            def.name
        )));
    }
    predicate(def, anchor, "a")
}

/// `def`'s condition as a predicate on the anchor aliased `alias` (a literal
/// the calling code chooses), every value a quoted literal. Pure.
pub fn predicate(
    def: &DerivedEntity,
    anchor: &EntityMeta,
    alias: &str,
) -> Result<String, AppError> {
    if def.anchor != anchor.logicalname {
        return Err(AppError::internal(
            "derived entity checked against another anchor",
        ));
    }
    let expr = attome_rules::parse(&def.condition)
        .map_err(|e| AppError::Validation(format!("the condition does not parse: {e}")))?;
    attome_core::rules_sql::to_sql_inline(&expr, &condition_fields(anchor), alias).map_err(|e| {
        AppError::Validation(format!(
            "the condition must read only {}'s own fields: {e}",
            anchor.logicalname
        ))
    })
}

/// The predicate on the anchor aliased `alias` that keeps `def`'s members:
/// the condition (live) or presence in the membership table (stored).
/// Pure.
pub fn members_predicate(
    def: &DerivedEntity,
    anchor: &EntityMeta,
    alias: &str,
) -> Result<String, AppError> {
    match def.mode {
        DerivedMode::Live => predicate(def, anchor, alias),
        DerivedMode::Stored => Ok(format!(
            "{alias}.\"id\" IN (SELECT anchor_id FROM {})",
            quote_ident(&def.membership_name())
        )),
    }
}

/// The view's definition: the anchor's live rows (without sensitive
/// columns) matching `predicate` (live) or present in the membership table
/// (stored). Pure.
pub fn view_sql(def: &DerivedEntity, anchor: &EntityMeta, predicate: &str) -> String {
    let columns = select_columns(&anchor.attrs, false)
        .split(", ")
        .map(|c| format!("a.{c}"))
        .collect::<Vec<_>>()
        .join(", ");
    let live = live_row_predicate("a", anchor.is_append_only).unwrap_or_else(|| "TRUE".into());
    let from = quote_ident(&anchor.logicalname);
    match def.mode {
        DerivedMode::Live => format!(
            "CREATE VIEW {} AS SELECT {columns} FROM {from} a WHERE {live} AND {predicate}",
            quote_ident(&def.view_name())
        ),
        DerivedMode::Stored => format!(
            "CREATE VIEW {} AS SELECT {columns} FROM {from} a JOIN {} m ON m.anchor_id = a.id WHERE {live}",
            quote_ident(&def.view_name()),
            quote_ident(&def.membership_name())
        ),
    }
}

/// The membership table of a stored derived entity. Pure.
pub fn membership_sql(def: &DerivedEntity) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {} (anchor_id uuid PRIMARY KEY, \
         entered_at timestamptz NOT NULL DEFAULT now(), reason text)",
        quote_ident(&def.membership_name())
    )
}

/// The grants that make the view read-only: SELECT for the read-only role,
/// and no writes for the runtime role (whose default privileges would
/// otherwise grant them). Pure.
pub fn grant_sql(def: &DerivedEntity) -> [String; 2] {
    let view = quote_ident(&def.view_name());
    [
        format!("GRANT SELECT ON {view} TO attome_readonly"),
        format!("REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON {view} FROM attome_runtime"),
    ]
}

fn ddl_error(e: sqlx::Error) -> AppError {
    AppError::internal(format!("derived entity DDL failed: {e}"))
}

/// Creates or replaces `def`: checks it, (re)creates its view and, when
/// stored, its membership table, applies the grants, and saves the
/// definition. DDL runs on `migrator`, the definition on `db`.
pub async fn install(
    migrator: &DbPool,
    db: &DbPool,
    def: &DerivedEntity,
    anchor: &EntityMeta,
    entity_exists: impl Fn(&str) -> bool,
    actor: Uuid,
) -> Result<(), AppError> {
    let predicate = validate(def, anchor, entity_exists)?;
    let view = quote_ident(&def.view_name());
    exec_ddl_locked(migrator, &[], &format!("DROP VIEW IF EXISTS {view}"))
        .await
        .map_err(ddl_error)?;
    if def.mode == DerivedMode::Stored {
        exec_ddl_locked(migrator, &[], &membership_sql(def))
            .await
            .map_err(ddl_error)?;
        // The record list reads membership on the read-only query pool.
        exec_ddl_locked(
            migrator,
            &[],
            &format!(
                "GRANT SELECT ON {} TO attome_readonly",
                quote_ident(&def.membership_name())
            ),
        )
        .await
        .map_err(ddl_error)?;
    }
    exec_ddl_locked(migrator, &[], &view_sql(def, anchor, &predicate))
        .await
        .map_err(ddl_error)?;
    for grant in grant_sql(def) {
        exec_ddl_locked(migrator, &[], &grant)
            .await
            .map_err(ddl_error)?;
    }
    sqlx::query(
        "INSERT INTO derived_entity (name, anchor, condition, mode, created_by) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (name) DO UPDATE SET anchor = EXCLUDED.anchor, \
         condition = EXCLUDED.condition, mode = EXCLUDED.mode, updated_at = now()",
    )
    .bind(&def.name)
    .bind(&def.anchor)
    .bind(&def.condition)
    .bind(def.mode.as_str())
    .bind(actor)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The definition named `name`, if there is one.
pub async fn find(db: &DbPool, name: &str) -> Result<Option<DerivedEntity>, AppError> {
    let row: Option<(String, String, String, String)> =
        sqlx::query_as("SELECT name, anchor, condition, mode FROM derived_entity WHERE name = $1")
            .bind(name)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(row.map(|(name, anchor, condition, mode)| DerivedEntity {
        name,
        anchor,
        condition,
        mode: DerivedMode::parse(&mode).unwrap_or(DerivedMode::Live),
    }))
}

/// Every definition, by name.
pub async fn list(db: &DbPool) -> Result<Vec<DerivedEntity>, AppError> {
    let rows: Vec<(String, String, String, String)> =
        sqlx::query_as("SELECT name, anchor, condition, mode FROM derived_entity ORDER BY name")
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(name, anchor, condition, mode)| DerivedEntity {
            name,
            anchor,
            condition,
            mode: DerivedMode::parse(&mode).unwrap_or(DerivedMode::Live),
        })
        .collect())
}

/// Removes the derived entity `name`: its view, its membership table and
/// its definition. `false` when there was none.
pub async fn remove(migrator: &DbPool, db: &DbPool, name: &str) -> Result<bool, AppError> {
    let Some(def) = find(db, name).await? else {
        return Ok(false);
    };
    exec_ddl_locked(
        migrator,
        &[],
        &format!("DROP VIEW IF EXISTS {}", quote_ident(&def.view_name())),
    )
    .await
    .map_err(ddl_error)?;
    exec_ddl_locked(
        migrator,
        &[],
        &format!(
            "DROP TABLE IF EXISTS {}",
            quote_ident(&def.membership_name())
        ),
    )
    .await
    .map_err(ddl_error)?;
    sqlx::query("DELETE FROM derived_entity_pending WHERE name = $1")
        .bind(name)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    sqlx::query("DELETE FROM derived_entity WHERE name = $1")
        .bind(name)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(true)
}

// ── A26-T2: keeping stored membership current ─────────────────────────────

/// A change that would move more members than this at once is held for an
/// administrator (the surge guard).
pub const SURGE_LIMIT: usize = 10_000;
/// Anchors re-checked per statement when held changes are applied.
pub const RESUME_CHUNK: usize = 5_000;

/// Members entering and leaving, as anchor ids.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MembershipChange {
    pub enter: Vec<Uuid>,
    pub leave: Vec<Uuid>,
}

impl MembershipChange {
    /// How many members move.
    pub fn len(&self) -> usize {
        self.enter.len() + self.leave.len()
    }

    pub fn is_empty(&self) -> bool {
        self.enter.is_empty() && self.leave.is_empty()
    }
}

/// What makes `ids` right: those that match and are not members enter,
/// those that are members and no longer match leave. Pure.
pub fn membership_change(
    ids: &[Uuid],
    matching: &std::collections::HashSet<Uuid>,
    members: &std::collections::HashSet<Uuid>,
) -> MembershipChange {
    let mut seen = std::collections::HashSet::new();
    let mut change = MembershipChange::default();
    for id in ids.iter().filter(|id| seen.insert(**id)) {
        match (matching.contains(id), members.contains(id)) {
            (true, false) => change.enter.push(*id),
            (false, true) => change.leave.push(*id),
            _ => {}
        }
    }
    change
}

/// How [`reconcile`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciled {
    /// The change was applied (possibly empty).
    Applied(MembershipChange),
    /// The change was larger than the limit and nothing was written.
    Surge(usize),
}

/// Re-checks the anchors `ids` against stored `def` and makes its
/// membership right, in one transaction: members entering and leaving, and
/// a history row each with `reason`. With `limit`, a change moving more
/// members than it writes nothing and answers [`Reconciled::Surge`]. An id
/// that is not a live anchor matching the condition is not a member.
pub async fn reconcile(
    db: &DbPool,
    def: &DerivedEntity,
    anchor: &EntityMeta,
    ids: &[Uuid],
    reason: &str,
    limit: Option<usize>,
) -> Result<Reconciled, AppError> {
    if def.mode != DerivedMode::Stored || ids.is_empty() {
        return Ok(Reconciled::Applied(MembershipChange::default()));
    }
    let condition = predicate(def, anchor, "a")?;
    let live = live_row_predicate("a", anchor.is_append_only).unwrap_or_else(|| "TRUE".into());
    let table = quote_ident(&def.membership_name());
    let mut tx = attome_db::tx::begin(db).await?;
    // The membership rows of these anchors, locked so two ticks cannot
    // decide on the same member at once.
    let members: std::collections::HashSet<Uuid> = sqlx::query_scalar(&format!(
        "SELECT anchor_id FROM {table} WHERE anchor_id = ANY($1) FOR UPDATE"
    ))
    .bind(ids)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let matching: std::collections::HashSet<Uuid> = sqlx::query_scalar(&format!(
        "SELECT a.\"id\" FROM {} a WHERE a.\"id\" = ANY($1) AND {live} AND {condition}",
        quote_ident(&anchor.logicalname)
    ))
    .bind(ids)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let change = membership_change(ids, &matching, &members);
    if let Some(limit) = limit
        && change.len() > limit
    {
        return Ok(Reconciled::Surge(change.len()));
    }
    if !change.enter.is_empty() {
        sqlx::query(&format!(
            "INSERT INTO {table} (anchor_id, reason) SELECT unnest($1::uuid[]), $2 \
             ON CONFLICT (anchor_id) DO NOTHING"
        ))
        .bind(&change.enter)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    if !change.leave.is_empty() {
        sqlx::query(&format!("DELETE FROM {table} WHERE anchor_id = ANY($1)"))
            .bind(&change.leave)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    }
    for (kind, list) in [("enter", &change.enter), ("leave", &change.leave)] {
        if list.is_empty() {
            continue;
        }
        sqlx::query(
            "INSERT INTO derived_entity_history (name, anchor_id, change, reason) \
             SELECT $1, unnest($2::uuid[]), $3, $4",
        )
        .bind(&def.name)
        .bind(list)
        .bind(kind)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(Reconciled::Applied(change))
}

/// A26-T3: anchors re-checked per range in a full refresh.
pub const REFRESH_RANGE: i64 = 5_000;

/// A26-T3: a full refresh of stored `def`: every anchor row re-checked in
/// id ranges of [`REFRESH_RANGE`] (each range its own short transaction,
/// through [`reconcile`]), then every member whose anchor row no longer
/// exists removed. No surge limit: it runs after an administrator saved the
/// definition, or nightly to heal drift. Idempotent, so a refresh stopped
/// part-way is simply run again.
pub async fn refresh(
    db: &DbPool,
    def: &DerivedEntity,
    anchor: &EntityMeta,
) -> Result<MembershipChange, AppError> {
    let mut total = MembershipChange::default();
    if def.mode != DerivedMode::Stored {
        return Ok(total);
    }
    let mut add = |reconciled: Reconciled| {
        if let Reconciled::Applied(change) = reconciled {
            total.enter.extend(change.enter);
            total.leave.extend(change.leave);
        }
    };
    let from = quote_ident(&anchor.logicalname);
    let mut after = Uuid::nil();
    loop {
        let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
            "SELECT \"id\" FROM {from} WHERE \"id\" > $1 ORDER BY \"id\" LIMIT $2"
        ))
        .bind(after)
        .bind(REFRESH_RANGE)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = ids.last().copied() else {
            break;
        };
        add(reconcile(db, def, anchor, &ids, "refresh", None).await?);
        after = last;
    }
    // Members whose anchor row is gone (a hard delete).
    let table = quote_ident(&def.membership_name());
    loop {
        let gone: Vec<Uuid> = sqlx::query_scalar(&format!(
            "SELECT m.anchor_id FROM {table} m \
              WHERE NOT EXISTS (SELECT 1 FROM {from} a WHERE a.\"id\" = m.anchor_id) \
              LIMIT $1"
        ))
        .bind(REFRESH_RANGE)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        if gone.is_empty() {
            break;
        }
        add(reconcile(db, def, anchor, &gone, "the record no longer exists", None).await?);
    }
    Ok(total)
}

// ── A26-T4: preview, explain, trend ───────────────────────────────────────

/// How long a preview or explanation may run.
const READ_TIMEOUT: &str = "SET LOCAL statement_timeout = '30s'";
/// Members a preview shows.
pub const PREVIEW_SAMPLE: i64 = 20;
/// The most weeks a trend covers.
pub const MAX_TREND_WEEKS: i64 = 104;

/// The parts of a condition joined by `and` at its top, in order: each is
/// explained on its own. Pure.
pub fn condition_parts(expr: &attome_rules::Expr) -> Vec<&attome_rules::Expr> {
    match expr {
        attome_rules::Expr::Binary {
            op: attome_rules::BinaryOp::And,
            lhs,
            rhs,
        } => {
            let mut parts = condition_parts(lhs);
            parts.extend(condition_parts(rhs));
            parts
        }
        other => vec![other],
    }
}

/// The anchor's own fields `expr` reads, in name order. Pure.
pub fn fields_read(expr: &attome_rules::Expr) -> std::collections::BTreeSet<String> {
    fn walk(expr: &attome_rules::Expr, out: &mut std::collections::BTreeSet<String>) {
        use attome_rules::Expr;
        match expr {
            Expr::FieldRef(field) if field.hop.is_none() => {
                out.insert(field.base.clone());
            }
            Expr::ListLit(items) | Expr::Call { args: items, .. } => {
                items.iter().for_each(|e| walk(e, out));
            }
            Expr::Unary { expr, .. } => walk(expr, out),
            Expr::Binary { lhs, rhs, .. } => {
                walk(lhs, out);
                walk(rhs, out);
            }
            Expr::Lambda { body, .. } => walk(body, out),
            _ => {}
        }
    }
    let mut out = std::collections::BTreeSet::new();
    walk(expr, &mut out);
    out
}

/// One member of a preview.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SampleMember {
    pub id: Uuid,
    /// The anchor's primary name, when it has a readable one.
    pub name: Option<String>,
}

/// What publishing `def` would do.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Preview {
    /// Live anchor rows matching the condition now.
    pub matching: i64,
    /// Of those, the ones not members of the current version (all of them
    /// when there is none, or it reads another anchor).
    pub entering: i64,
    /// Members of the current version that would no longer match; `None`
    /// when there is no current version on this anchor.
    pub leaving: Option<i64>,
    pub sample: Vec<SampleMember>,
}

/// Counts what `def` selects now and, against `current` (the saved version
/// of the same name, if any), how many would enter and leave; with up to
/// [`PREVIEW_SAMPLE`] members. Reads only, under a 30-second limit.
pub async fn preview(
    db: &DbPool,
    def: &DerivedEntity,
    anchor: &EntityMeta,
    current: Option<&DerivedEntity>,
) -> Result<Preview, AppError> {
    let new = predicate(def, anchor, "a")?;
    let old = match current {
        Some(cur) if cur.anchor == def.anchor => Some(members_predicate(cur, anchor, "a")?),
        _ => None,
    };
    let live = live_row_predicate("a", anchor.is_append_only).unwrap_or_else(|| "TRUE".into());
    let from = quote_ident(&anchor.logicalname);
    let new_holds = format!("COALESCE(({new}), false)");
    let old_holds = old
        .as_ref()
        .map(|o| format!("COALESCE(({o}), false)"))
        .unwrap_or_else(|| "false".into());
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query(READ_TIMEOUT)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let (matching, entering, leaving): (i64, i64, i64) = sqlx::query_as(&format!(
        "SELECT count(*) FILTER (WHERE {new_holds}), \
                count(*) FILTER (WHERE {new_holds} AND NOT {old_holds}), \
                count(*) FILTER (WHERE {old_holds} AND NOT {new_holds}) \
           FROM {from} a WHERE {live}"
    ))
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let name_column = anchor
        .primary_name_attribute
        .as_deref()
        .filter(|p| condition_fields(anchor).contains_key(*p))
        .map(|p| format!("a.{}::text", quote_ident(p)))
        .unwrap_or_else(|| "NULL::text".into());
    let sample: Vec<(Uuid, Option<String>)> = sqlx::query_as(&format!(
        "SELECT a.\"id\", {name_column} FROM {from} a \
          WHERE {live} AND {new_holds} ORDER BY a.\"id\" LIMIT $1"
    ))
    .bind(PREVIEW_SAMPLE)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(Preview {
        matching,
        entering,
        leaving: old.is_some().then_some(leaving),
        sample: sample
            .into_iter()
            .map(|(id, name)| SampleMember { id, name })
            .collect(),
    })
}

/// One part of a condition, explained for one record.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct PartExplained {
    /// The part as written (`amount > 100000`).
    pub part: String,
    /// Whether it holds; `None` when it cannot be decided (a field is
    /// empty, so the comparison is unknown, which counts as not holding).
    pub holds: Option<bool>,
    /// The record's value of each field the part reads.
    pub values: serde_json::Map<String, serde_json::Value>,
}

/// Why a record is, or is not, a member.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Explanation {
    pub record_id: Uuid,
    /// Whether it is a member now (stored: in the membership table).
    pub member: bool,
    /// Whether the record is live (a deleted record is never a member).
    pub live: bool,
    /// Whether the whole condition holds now (for a stored entity, the
    /// membership may lag it by a few seconds).
    pub matches: bool,
    pub parts: Vec<PartExplained>,
}

/// Explains `def` for the anchor record `record_id`: each top-level part
/// of the condition with whether it holds and the record's values of the
/// fields it reads. `None` when the anchor has no such record.
pub async fn explain(
    db: &DbPool,
    def: &DerivedEntity,
    anchor: &EntityMeta,
    record_id: Uuid,
) -> Result<Option<Explanation>, AppError> {
    let expr = attome_rules::parse(&def.condition)
        .map_err(|e| AppError::Validation(format!("the condition does not parse: {e}")))?;
    let fields = condition_fields(anchor);
    let parts = condition_parts(&expr);
    let mut part_sql = Vec::with_capacity(parts.len());
    for part in &parts {
        let sql = attome_core::rules_sql::to_sql_inline(part, &fields, "a")
            .map_err(|e| AppError::Validation(e.to_string()))?;
        part_sql.push(format!("({sql})"));
    }
    let read: std::collections::BTreeSet<String> = parts
        .iter()
        .flat_map(|p| fields_read(p))
        .filter(|f| fields.contains_key(f))
        .collect();
    let values_sql = if read.is_empty() {
        "'{}'::jsonb".to_owned()
    } else {
        format!(
            "jsonb_build_object({})",
            read.iter()
                .map(|f| format!("'{f}', a.{}", quote_ident(f)))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let live = live_row_predicate("a", anchor.is_append_only).unwrap_or_else(|| "TRUE".into());
    let member_sql = match def.mode {
        DerivedMode::Live => format!(
            "({live}) AND COALESCE(({}), false)",
            predicate(def, anchor, "a")?
        ),
        DerivedMode::Stored => format!(
            "EXISTS (SELECT 1 FROM {} m WHERE m.anchor_id = a.\"id\")",
            quote_ident(&def.membership_name())
        ),
    };
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query(READ_TIMEOUT)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let row: Option<(bool, bool, bool, serde_json::Value, serde_json::Value)> =
        sqlx::query_as(&format!(
            "SELECT {member_sql}, ({live}), COALESCE(({}), false), jsonb_build_array({}), {values_sql} \
               FROM {} a WHERE a.\"id\" = $1",
            predicate(def, anchor, "a")?,
            part_sql.join(", "),
            quote_ident(&anchor.logicalname),
        ))
        .bind(record_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    let Some((member, live, matches, holds, values)) = row else {
        return Ok(None);
    };
    let holds = holds.as_array().cloned().unwrap_or_default();
    let values = values.as_object().cloned().unwrap_or_default();
    Ok(Some(Explanation {
        record_id,
        member,
        live,
        matches: live && matches,
        parts: parts
            .iter()
            .enumerate()
            .map(|(i, part)| PartExplained {
                part: part.to_string(),
                holds: holds.get(i).and_then(serde_json::Value::as_bool),
                values: fields_read(part)
                    .into_iter()
                    .filter_map(|f| values.get(&f).cloned().map(|v| (f, v)))
                    .collect(),
            })
            .collect(),
    }))
}

/// One week of a membership trend.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct WeekCount {
    /// The Monday the week starts on (UTC).
    pub week: chrono::NaiveDate,
    pub entered: i64,
    pub left: i64,
    /// Members at the end of the week.
    pub members: i64,
}

/// The members at the end of each week, oldest first, from today's count
/// and each week's entries and exits: a week's end is today's count less
/// what every later week added. Pure.
pub fn week_series(current: i64, weeks: &[(chrono::NaiveDate, i64, i64)]) -> Vec<WeekCount> {
    let mut members = current;
    let mut out: Vec<WeekCount> = Vec::with_capacity(weeks.len());
    for (week, entered, left) in weeks.iter().rev() {
        out.push(WeekCount {
            week: *week,
            entered: *entered,
            left: *left,
            members,
        });
        members -= entered - left;
    }
    out.reverse();
    out
}

/// Weekly membership of stored `def` over the last `weeks` weeks (this one
/// included, at most [`MAX_TREND_WEEKS`]), from its history; a week with no
/// change is listed with zero. A live derived entity keeps no history, so
/// its trend is this week's count alone.
pub async fn trend(
    db: &DbPool,
    def: &DerivedEntity,
    anchor: &EntityMeta,
    weeks: i64,
) -> Result<Vec<WeekCount>, AppError> {
    let weeks = weeks.clamp(1, MAX_TREND_WEEKS);
    let this_week: chrono::NaiveDate = sqlx::query_scalar("SELECT date_trunc('week', now())::date")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if def.mode == DerivedMode::Live {
        let preview = preview(db, def, anchor, None).await?;
        return Ok(vec![WeekCount {
            week: this_week,
            entered: 0,
            left: 0,
            members: preview.matching,
        }]);
    }
    let current: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM {}",
        quote_ident(&def.membership_name())
    ))
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<(chrono::NaiveDate, i64, i64)> = sqlx::query_as(
        "SELECT date_trunc('week', at)::date AS week, \
                count(*) FILTER (WHERE change = 'enter'), \
                count(*) FILTER (WHERE change = 'leave') \
           FROM derived_entity_history \
          WHERE name = $1 AND at >= date_trunc('week', now()) - ($2 - 1) * interval '1 week' \
          GROUP BY 1 ORDER BY 1",
    )
    .bind(&def.name)
    .bind(weeks)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let by_week: std::collections::HashMap<chrono::NaiveDate, (i64, i64)> =
        rows.into_iter().map(|(w, e, l)| (w, (e, l))).collect();
    let all: Vec<(chrono::NaiveDate, i64, i64)> = (0..weeks)
        .rev()
        .map(|back| {
            let week = this_week - chrono::Duration::weeks(back);
            let (entered, left) = by_week.get(&week).copied().unwrap_or((0, 0));
            (week, entered, left)
        })
        .collect();
    Ok(week_series(current, &all))
}

/// A26-T5: the ids of `def`'s current members, live anchor rows, in id
/// order, at most `limit + 1` (so a caller can tell there were more).
pub async fn member_ids(
    db: &DbPool,
    def: &DerivedEntity,
    anchor: &EntityMeta,
    limit: i64,
) -> Result<Vec<Uuid>, AppError> {
    let members = members_predicate(def, anchor, "a")?;
    let live = live_row_predicate("a", anchor.is_append_only).unwrap_or_else(|| "TRUE".into());
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query(READ_TIMEOUT)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let ids = sqlx::query_scalar(&format!(
        "SELECT a.\"id\" FROM {} a WHERE {live} AND COALESCE(({members}), false) \
          ORDER BY a.\"id\" LIMIT $1",
        quote_ident(&anchor.logicalname)
    ))
    .bind(limit + 1)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(ids)
}

/// The names of the paused definitions.
pub async fn paused(db: &DbPool) -> Result<std::collections::HashSet<String>, AppError> {
    Ok(
        sqlx::query_scalar("SELECT name FROM derived_entity WHERE paused_at IS NOT NULL")
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .collect(),
    )
}

/// Pauses `name` (the surge guard) and holds `ids` for when it resumes.
/// `true` when this paused it (it was running).
pub async fn pause(db: &DbPool, name: &str, ids: &[Uuid], reason: &str) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let paused = sqlx::query(
        "UPDATE derived_entity SET paused_at = now(), pause_reason = $2 \
          WHERE name = $1 AND paused_at IS NULL",
    )
    .bind(name)
    .bind(reason)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected()
        == 1;
    hold_in(&mut tx, name, ids).await?;
    attome_db::tx::commit(tx).await?;
    Ok(paused)
}

/// Holds `ids` of paused `name` for when it resumes.
pub async fn hold(db: &DbPool, name: &str, ids: &[Uuid]) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    hold_in(&mut tx, name, ids).await?;
    attome_db::tx::commit(tx).await
}

async fn hold_in(tx: &mut attome_db::Tx<'_>, name: &str, ids: &[Uuid]) -> Result<(), AppError> {
    if ids.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO derived_entity_pending (name, anchor_id) SELECT $1, unnest($2::uuid[]) \
         ON CONFLICT DO NOTHING",
    )
    .bind(name)
    .bind(ids)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Resumes paused `def`: applies every held change, [`RESUME_CHUNK`]
/// anchors at a time with no surge limit (an administrator approved it),
/// then clears the pause. `None` when it was not paused.
pub async fn resume(
    db: &DbPool,
    def: &DerivedEntity,
    anchor: &EntityMeta,
) -> Result<Option<MembershipChange>, AppError> {
    let was_paused: Option<bool> =
        sqlx::query_scalar("SELECT paused_at IS NOT NULL FROM derived_entity WHERE name = $1")
            .bind(&def.name)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    if was_paused != Some(true) {
        return Ok(None);
    }
    let mut total = MembershipChange::default();
    loop {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT anchor_id FROM derived_entity_pending WHERE name = $1 \
              ORDER BY anchor_id LIMIT $2",
        )
        .bind(&def.name)
        .bind(RESUME_CHUNK as i64)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        if ids.is_empty() {
            break;
        }
        if let Reconciled::Applied(change) =
            reconcile(db, def, anchor, &ids, "resumed after a surge", None).await?
        {
            total.enter.extend(change.enter);
            total.leave.extend(change.leave);
        }
        sqlx::query("DELETE FROM derived_entity_pending WHERE name = $1 AND anchor_id = ANY($2)")
            .bind(&def.name)
            .bind(&ids)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
    }
    sqlx::query("UPDATE derived_entity SET paused_at = NULL, pause_reason = NULL WHERE name = $1")
        .bind(&def.name)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(Some(total))
}

#[cfg(test)]
mod derived_entity_tests {
    use super::*;
    use attome_core::{AttrInfo, DataClassification, FieldType, OnTargetDelete};

    fn attr(name: &str, ty: FieldType, sensitive: bool) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int: FieldType::to_int(&ty),
            is_required: false,
            max_length: None,
            is_sensitive: sensitive,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::default(),
            data_classification: DataClassification::default(),
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
            options: None,
        }
    }

    fn deal() -> EntityMeta {
        EntityMeta {
            entity_id: Uuid::nil(),
            logicalname: "deal".into(),
            attrs: vec![
                attr("amount", FieldType::Number, false),
                attr("stage", FieldType::Text, false),
                attr("margin", FieldType::Number, true),
            ],
            is_append_only: false,
            primary_name_attribute: None,
        }
    }

    fn def(condition: &str, mode: DerivedMode) -> DerivedEntity {
        DerivedEntity {
            name: "big_open_deal".into(),
            anchor: "deal".into(),
            condition: condition.into(),
            mode,
        }
    }

    #[test]
    fn derived_entity_live_view_selects_matching_live_rows() {
        let d = def("amount > 100000 and stage == \"open\"", DerivedMode::Live);
        let predicate = validate(&d, &deal(), |_| false).unwrap();
        let sql = view_sql(&d, &deal(), &predicate);
        assert!(
            sql.starts_with("CREATE VIEW \"xrm_dv_big_open_deal\" AS SELECT a."),
            "{sql}"
        );
        assert!(
            sql.contains("FROM \"deal\" a WHERE (a.is_active IS NULL OR a.is_active = true) AND "),
            "{sql}"
        );
        assert!(sql.contains("'100000'::numeric"), "{sql}");
        assert!(!sql.contains('$'), "{sql}");
        // Sensitive columns stay out of the view.
        assert!(!sql.contains("\"margin\""), "{sql}");
    }

    #[test]
    fn derived_entity_stored_has_membership_table() {
        let d = def("amount > 1", DerivedMode::Stored);
        let predicate = validate(&d, &deal(), |_| false).unwrap();
        assert!(
            view_sql(&d, &deal(), &predicate)
                .contains("JOIN \"xrm_dm_big_open_deal\" m ON m.anchor_id = a.id")
        );
        let table = membership_sql(&d);
        assert!(
            table.contains("\"xrm_dm_big_open_deal\" (anchor_id uuid PRIMARY KEY"),
            "{table}"
        );
        assert!(table.contains("entered_at timestamptz") && table.contains("reason text"));
    }

    #[test]
    fn derived_entity_members_predicate_by_mode() {
        let live = def("amount > 5", DerivedMode::Live);
        let text = members_predicate(&live, &deal(), "t").unwrap();
        assert!(
            text.contains("t.\"amount\"") && text.contains("'5'::numeric"),
            "{text}"
        );
        let stored = def("amount > 5", DerivedMode::Stored);
        assert_eq!(
            members_predicate(&stored, &deal(), "t").unwrap(),
            "t.\"id\" IN (SELECT anchor_id FROM \"xrm_dm_big_open_deal\")"
        );
    }

    #[test]
    fn derived_incremental_enter_and_leave() {
        let ids: Vec<Uuid> = (0..4).map(|_| Uuid::now_v7()).collect();
        // 0 matches and is new, 1 matches and is a member, 2 no longer
        // matches, 3 neither.
        let matching = [ids[0], ids[1]].into_iter().collect();
        let members = [ids[1], ids[2]].into_iter().collect();
        let mut repeated = ids.clone();
        repeated.push(ids[0]);
        let change = membership_change(&repeated, &matching, &members);
        assert_eq!(change.enter, vec![ids[0]]);
        assert_eq!(change.leave, vec![ids[2]]);
        assert_eq!(change.len(), 2);
        assert!(membership_change(&[], &matching, &members).is_empty());
    }

    #[test]
    fn derived_explain_splits_the_condition_into_parts() {
        let expr = attome_rules::parse("amount > 100 and stage == \"open\" and (a or b)").unwrap();
        let parts = condition_parts(&expr);
        assert_eq!(parts.len(), 3);
        assert_eq!(
            fields_read(parts[0]).into_iter().collect::<Vec<_>>(),
            vec!["amount".to_owned()]
        );
        assert_eq!(fields_read(parts[2]).len(), 2);
        let single = attome_rules::parse("amount > 1").unwrap();
        assert_eq!(condition_parts(&single).len(), 1);
    }

    #[test]
    fn derived_trend_counts_back_from_today() {
        let day = |d: u32| chrono::NaiveDate::from_ymd_opt(2026, 10, d).unwrap();
        let series = week_series(10, &[(day(5), 4, 0), (day(12), 0, 0), (day(19), 3, 1)]);
        let members: Vec<i64> = series.iter().map(|w| w.members).collect();
        // Today 10; the last week added 2, so 8 before it; the week
        // before changed nothing; the first added 4.
        assert_eq!(members, vec![8, 8, 10]);
        assert_eq!(series[0].entered, 4);
    }

    #[test]
    fn derived_entity_view_is_select_only() {
        let [grant, revoke] = grant_sql(&def("amount > 1", DerivedMode::Live));
        assert_eq!(
            grant,
            "GRANT SELECT ON \"xrm_dv_big_open_deal\" TO attome_readonly"
        );
        assert!(revoke.starts_with("REVOKE INSERT, UPDATE, DELETE, TRUNCATE"));
    }

    #[test]
    fn derived_entity_refuses_bad_definitions() {
        let anchor = deal();
        // A lookup path, the clock and a sensitive field are not the
        // anchor's own readable fields.
        for condition in [
            "owner_ref.name == \"x\"",
            "today() > amount",
            "margin > 1",
            "amount >",
        ] {
            assert!(
                validate(&def(condition, DerivedMode::Live), &anchor, |_| false).is_err(),
                "{condition}"
            );
        }
        let mut bad = def("amount > 1", DerivedMode::Live);
        bad.name = "Bad Name".into();
        assert!(validate(&bad, &anchor, |_| false).is_err());
        bad.name = "x".repeat(60);
        assert!(validate(&bad, &anchor, |_| false).is_err());
        assert!(
            validate(&def("amount > 1", DerivedMode::Live), &anchor, |n| n
                == "big_open_deal")
            .is_err()
        );
        assert_eq!(DerivedMode::parse("stored"), Some(DerivedMode::Stored));
        assert_eq!(DerivedMode::parse("other"), None);
    }
}
