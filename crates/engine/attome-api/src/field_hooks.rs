//! Solution 7 Phase 2 (D-788; `SOLUTION-7-PHASE-2-DESIGN.md` §7.4) — the
//! reference hooks a field rename or delete runs, and the registry of record.
//!
//! Each hook covers one name-keyed store. `scan` lists the references and the
//! blockers; `rename` rewrites them; `remove` removes a deleted field's
//! consequence references and adjusts or removes customer objects (which
//! never block; each yields a release-report draft). "Customer object" means
//! `owner_layer = 'customer'`, or a personal/shared view (user-owned data).
//!
//! Registered here (the crate that sees every engine):
//!
//! | hook | store | delete |
//! |---|---|---|
//! | `views` | `view.table_definition`, `view_metadata` (every scope) | ours block; customer adjusted/removed |
//! | `stored_queries` | `sql_query.sql_query` (+ `table_definition`) | ours block; customer deactivated |
//! | `labels` | `metadata_label` `e.f`, `e.f.*` | soft-deleted |
//! | `business_rules` | `rule` conditions, expressions, `target_field`; `rule_policy` fields and expressions (`business_rule_hooks.rs`, D-789 §8) | visibility/requirement styling removed; other ours block; customer policies deleted, rule turned off or removed |
//! | `state` | `state_model.state_field`, transition guards | `state_field` blocks; guards: ours block, customer removed |
//! | `workflows` | trigger/condition node configs of workflows triggered on the entity | ours block; customer deactivated |
//! | `field_security` | profile fields, role bulk fields, grant conditions | profile/bulk entries deleted; our grant condition blocks (Topic 15 #3); a customer one is decided by the executor ([`customer_grant_conditions`]): revoked in the delete's transaction when the grant, its conditions and the change are all the customer layer, otherwise it blocks (Topic 16, security review M3) |
//! | `portal` | `webportal_grant_condition` (field, `@portal_user.<field>`), `webportal_grant_field`, `webportal_entity.portal_user_field` | conditions and the owner field block; grant-field entries deleted (security review M2) |
//! | `record_baseline` | `record_baseline.field_logicalname` (`attome_core::release_report`, design §9.1) | rows deleted (a rename moves them) |
//! | `lineage` | `metadata_reference.to_attribute` | deleted |
//!
//! Not covered yet (engine lanes, design P2-D): dashboards' widget configs,
//! report definitions, content/docgen merge tokens,
//! match/survivorship rules, data-tool mappings, approval-policy expressions,
//! prediction features. Rules of *other* entities that reach this field
//! through a `lookup.field` hop are not rewritten either.
//!
//! The SQL rewriting of stored queries is token based: an identifier is
//! rewritten when it provably belongs to the entity (qualified by the
//! entity's table or alias, or bare in a query whose only table is the
//! entity); a bare name in a multi-table query is ambiguous (design §15 Q2).

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use attome_core::changeset::Layer;
use attome_core::changeset::field_hooks::{
    Blocker, CacheTouch, FieldHooks, FieldRef, FieldReferenceHook, HookFuture, HookOutcome,
    LineageHook, RefOwner, RefScan, ReportItemDraft,
};
use attome_metadata::provision::field_change::{expression_names, rewrite_expression};
use attome_types::AppError;
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

/// The registered hook names, in run order (the coverage test pins it).
pub const REGISTERED: &[&str] = &[
    "business_key",
    "views",
    "stored_queries",
    "labels",
    "business_rules",
    "state",
    "workflows",
    "field_security",
    "portal",
    "record_baseline",
    "lineage",
];

/// The registry of record.
pub fn registry() -> &'static FieldHooks {
    static REGISTRY: OnceLock<FieldHooks> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let hooks: Vec<Box<dyn FieldReferenceHook>> = vec![
            Box::new(attome_metadata::provision::BusinessKeyHook),
            Box::new(ViewsHook),
            Box::new(StoredQueriesHook),
            Box::new(LabelsHook),
            Box::new(crate::business_rule_hooks::BusinessRulesHook),
            Box::new(StateHook),
            Box::new(WorkflowsHook),
            Box::new(FieldSecurityHook),
            Box::new(PortalHook),
            Box::new(attome_core::release_report::RecordBaselineHook),
            Box::new(LineageHook),
        ];
        FieldHooks::new(hooks)
    })
}

fn owner_of(owner_layer: &str) -> RefOwner {
    if attome_model::Layer::from_stored(owner_layer) == Some(attome_model::Layer::Customer) {
        RefOwner::Customer
    } else {
        RefOwner::Ours
    }
}

fn draft(
    kind: &'static str,
    entity: &str,
    field: &str,
    object_kind: &str,
    object_ref: Uuid,
    detail: Value,
) -> ReportItemDraft {
    ReportItemDraft {
        kind,
        entity: entity.to_owned(),
        field: Some(field.to_owned()),
        object_kind: Some(object_kind.to_owned()),
        object_ref: Some(object_ref),
        detail,
    }
}

fn internal(e: sqlx::Error) -> AppError {
    AppError::internal(e)
}

// ── views ───────────────────────────────────────────────────────────────────

/// `view_metadata` keys that hold one field name. The `bool` says whether
/// the view kind cannot work without it (a customer view losing it is
/// deactivated rather than adjusted).
const VIEW_FIELD_KEYS: &[(&str, bool)] = &[
    ("state_field", true),
    ("start_field", true),
    ("end_field", false),
    ("color_field", false),
    ("x_field", true),
    ("group_by_field", false),
];

fn column_entries(table_definition: &mut Value) -> Option<&mut Vec<Value>> {
    match table_definition {
        Value::Array(items) => Some(items),
        Value::Object(map) => map.get_mut("columns").and_then(Value::as_array_mut),
        _ => None,
    }
}

fn column_name(entry: &Value) -> Option<&str> {
    ["name", "logicalName", "logical_name"]
        .iter()
        .find_map(|k| entry.get(*k).and_then(Value::as_str))
}

/// Whether the view's JSON names `field`.
fn view_names(table_definition: &Value, metadata: &Value, field: &str) -> bool {
    let mut td = table_definition.clone();
    let in_columns = column_entries(&mut td)
        .is_some_and(|cols| cols.iter().any(|c| column_name(c) == Some(field)));
    let in_keys = VIEW_FIELD_KEYS
        .iter()
        .any(|(k, _)| metadata.get(*k).and_then(Value::as_str) == Some(field));
    let in_lists = ["y_fields", "filters"].iter().any(|list| {
        metadata
            .get(*list)
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|i| i.get("field").and_then(Value::as_str) == Some(field))
            })
    });
    in_columns || in_keys || in_lists
}

fn rename_in_view(table_definition: &mut Value, metadata: &mut Value, old: &str, new: &str) {
    if let Some(cols) = column_entries(table_definition) {
        for c in cols.iter_mut() {
            for k in ["name", "logicalName", "logical_name"] {
                if c.get(k).and_then(Value::as_str) == Some(old)
                    && let Some(map) = c.as_object_mut()
                {
                    map.insert(k.to_owned(), json!(new));
                }
            }
        }
    }
    if let Some(map) = metadata.as_object_mut() {
        for (k, _) in VIEW_FIELD_KEYS {
            if map.get(*k).and_then(Value::as_str) == Some(old) {
                map.insert((*k).to_owned(), json!(new));
            }
        }
        for list in ["y_fields", "filters"] {
            if let Some(items) = map.get_mut(list).and_then(Value::as_array_mut) {
                for i in items.iter_mut() {
                    if i.get("field").and_then(Value::as_str) == Some(old)
                        && let Some(m) = i.as_object_mut()
                    {
                        m.insert("field".into(), json!(new));
                    }
                }
            }
        }
    }
}

/// Removes `field` from the view; `true` when the view can no longer work
/// (a required key lost, or no chart series left).
fn remove_from_view(table_definition: &mut Value, metadata: &mut Value, field: &str) -> bool {
    if let Some(cols) = column_entries(table_definition) {
        cols.retain(|c| column_name(c) != Some(field));
    }
    let mut broken = false;
    if let Some(map) = metadata.as_object_mut() {
        for (k, required) in VIEW_FIELD_KEYS {
            if map.get(*k).and_then(Value::as_str) == Some(field) {
                map.insert((*k).to_owned(), Value::Null);
                broken |= *required;
            }
        }
        for list in ["y_fields", "filters"] {
            if let Some(items) = map.get_mut(list).and_then(Value::as_array_mut) {
                let before = items.len();
                items.retain(|i| i.get("field").and_then(Value::as_str) != Some(field));
                if list == "y_fields" && before > 0 && items.is_empty() {
                    broken = true;
                }
            }
        }
    }
    broken
}

#[derive(sqlx::FromRow)]
struct ViewRow {
    id: Uuid,
    name: String,
    scope: String,
    owner_layer: String,
    table_definition: Value,
    view_metadata: Value,
}

impl ViewRow {
    fn owner(&self) -> RefOwner {
        if matches!(self.scope.as_str(), "personal" | "shared") {
            RefOwner::Customer
        } else {
            owner_of(&self.owner_layer)
        }
    }
}

async fn entity_views(conn: &mut PgConnection, entity: &str) -> Result<Vec<ViewRow>, AppError> {
    sqlx::query_as(
        "SELECT v.id, v.name, v.scope, v.owner_layer, \
                COALESCE(v.table_definition, '[]'::jsonb) AS table_definition, \
                COALESCE(v.view_metadata, '{}'::jsonb) AS view_metadata \
         FROM view v JOIN entity_info e ON e.id = v.entity_logical_name \
         WHERE e.logicalname = $1 AND v.is_active = true",
    )
    .bind(entity)
    .fetch_all(&mut *conn)
    .await
    .map_err(internal)
}

async fn write_view(
    conn: &mut PgConnection,
    id: Uuid,
    table_definition: &Value,
    metadata: &Value,
    active: bool,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE view SET table_definition = $2, view_metadata = $3, is_active = $4 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(table_definition)
    .bind(metadata)
    .bind(active)
    .execute(&mut *conn)
    .await
    .map_err(internal)?;
    Ok(())
}

struct ViewsHook;

impl FieldReferenceHook for ViewsHook {
    fn name(&self) -> &'static str {
        "views"
    }

    fn scan<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
        renaming: bool,
    ) -> HookFuture<'a, RefScan> {
        Box::pin(async move {
            let mut out = RefScan::default();
            for v in entity_views(conn, entity).await? {
                if !view_names(&v.table_definition, &v.view_metadata, field) {
                    continue;
                }
                let owner = v.owner();
                if !renaming && owner == RefOwner::Ours {
                    out.blockers.push(Blocker {
                        hook: "views",
                        object_kind: "view".into(),
                        object_ref: Some(v.id),
                        name: v.name.clone(),
                        reason: "field_referenced: a view of ours shows or filters on the field; \
                                 remove it from the view in the same changeset first"
                            .into(),
                    });
                }
                out.refs.push(FieldRef {
                    hook: "views",
                    object_kind: format!("view:{}", v.scope),
                    object_ref: Some(v.id),
                    name: v.name,
                    owner,
                });
            }
            Ok(out)
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
            let mut out = HookOutcome::default();
            for mut v in entity_views(conn, entity).await? {
                if !view_names(&v.table_definition, &v.view_metadata, old) {
                    continue;
                }
                rename_in_view(&mut v.table_definition, &mut v.view_metadata, old, new);
                write_view(conn, v.id, &v.table_definition, &v.view_metadata, true).await?;
                out.touched += 1;
                if v.owner() == RefOwner::Customer {
                    out.report.push(draft(
                        "customer_object_adjusted",
                        entity,
                        old,
                        "view",
                        v.id,
                        json!({ "name": v.name, "change": "renamed_reference", "to": new }),
                    ));
                }
            }
            if out.touched > 0 {
                out.caches.push(CacheTouch::Views);
            }
            Ok(out)
        })
    }

    fn remove<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            let mut out = HookOutcome::default();
            for mut v in entity_views(conn, entity).await? {
                if v.owner() != RefOwner::Customer
                    || !view_names(&v.table_definition, &v.view_metadata, field)
                {
                    continue;
                }
                let broken = remove_from_view(&mut v.table_definition, &mut v.view_metadata, field);
                write_view(conn, v.id, &v.table_definition, &v.view_metadata, !broken).await?;
                out.touched += 1;
                out.report.push(draft(
                    if broken {
                        "customer_object_removed"
                    } else {
                        "customer_object_adjusted"
                    },
                    entity,
                    field,
                    "view",
                    v.id,
                    json!({
                        "name": v.name,
                        "scope": v.scope,
                        "change": if broken { "deactivated: the view cannot work without the field" }
                                  else { "column, filter or series removed" },
                    }),
                ));
            }
            Ok(out)
        })
    }
}

// ── stored queries (SQL) ────────────────────────────────────────────────────

/// One SQL token: identifiers (bare or quoted), punctuation, and opaque
/// spans (strings, comments, whitespace) that are never rewritten.
#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident { text: String, quoted: bool },
    Punct(char),
    Opaque(String),
}

impl Tok {
    fn src(&self) -> String {
        match self {
            Tok::Ident { text, quoted: true } => format!("\"{}\"", text.replace('"', "\"\"")),
            Tok::Ident { text, .. } => text.clone(),
            Tok::Punct(c) => c.to_string(),
            Tok::Opaque(s) => s.clone(),
        }
    }

    fn ident(&self) -> Option<(&str, bool)> {
        match self {
            Tok::Ident { text, quoted } => Some((text, *quoted)),
            _ => None,
        }
    }

    fn keyword(&self) -> Option<String> {
        match self {
            Tok::Ident {
                text,
                quoted: false,
            } => Some(text.to_ascii_lowercase()),
            _ => None,
        }
    }
}

fn tokenize(sql: &str) -> Vec<Tok> {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            let start = i;
            i += 1;
            while i < chars.len() {
                if chars[i] == '\'' {
                    if chars.get(i + 1) == Some(&'\'') {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push(Tok::Opaque(
                chars[start..i.min(chars.len())].iter().collect(),
            ));
        } else if c == '"' {
            let mut text = String::new();
            i += 1;
            while i < chars.len() {
                if chars[i] == '"' {
                    if chars.get(i + 1) == Some(&'"') {
                        text.push('"');
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                text.push(chars[i]);
                i += 1;
            }
            out.push(Tok::Ident { text, quoted: true });
        } else if c == '-' && chars.get(i + 1) == Some(&'-') {
            let start = i;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            out.push(Tok::Opaque(chars[start..i].iter().collect()));
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            let start = i;
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            out.push(Tok::Opaque(chars[start..i].iter().collect()));
        } else if c.is_whitespace() {
            let start = i;
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
            out.push(Tok::Opaque(chars[start..i].iter().collect()));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '$')
            {
                i += 1;
            }
            out.push(Tok::Ident {
                text: chars[start..i].iter().collect(),
                quoted: false,
            });
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                i += 1;
            }
            out.push(Tok::Opaque(chars[start..i].iter().collect()));
        } else {
            out.push(Tok::Punct(c));
            i += 1;
        }
    }
    out
}

const NOT_ALIAS: &[&str] = &[
    "where",
    "join",
    "on",
    "left",
    "right",
    "inner",
    "outer",
    "full",
    "cross",
    "group",
    "order",
    "limit",
    "union",
    "using",
    "having",
    "window",
    "offset",
    "fetch",
    "for",
    "natural",
    "lateral",
    "set",
    "returning",
    "and",
    "or",
    "except",
    "intersect",
    "as",
    "select",
    "from",
    "tablesample",
];

/// What a query's SQL says about `entity.field`.
#[derive(Debug, Default, PartialEq)]
struct SqlRefs {
    /// Indexes (into the token list) of identifiers that are the field.
    rewrite: Vec<usize>,
    /// A bare `field` in a query that reads the entity and other tables.
    ambiguous: bool,
}

fn analyze_sql(tokens: &[Tok], entity: &str, field: &str) -> SqlRefs {
    // Significant tokens (whitespace/comments/strings dropped), with their
    // index in the full list.
    let sig: Vec<(usize, &Tok)> = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| !matches!(t, Tok::Opaque(_)))
        .collect();
    let mut aliases: HashMap<String, String> = HashMap::new();
    let mut tables: HashSet<String> = HashSet::new();
    let mut table_positions: HashSet<usize> = HashSet::new();
    let mut j = 0;
    while j < sig.len() {
        let kw = sig[j].1.keyword();
        if matches!(kw.as_deref(), Some("from" | "join")) {
            let mut k = j + 1;
            loop {
                // Skip `ONLY` / `LATERAL`; a subquery starts with `(`.
                while k < sig.len()
                    && matches!(sig[k].1.keyword().as_deref(), Some("only" | "lateral"))
                {
                    k += 1;
                }
                let Some((_, Tok::Ident { text, .. })) = sig.get(k).map(|(i, t)| (*i, *t)) else {
                    break;
                };
                let mut name = text.to_ascii_lowercase();
                table_positions.insert(sig[k].0);
                // schema.table
                if matches!(sig.get(k + 1).map(|s| s.1), Some(Tok::Punct('.')))
                    && let Some((i2, Tok::Ident { text: t2, .. })) =
                        sig.get(k + 2).map(|(i, t)| (*i, *t))
                {
                    name = t2.to_ascii_lowercase();
                    table_positions.insert(i2);
                    k += 2;
                }
                tables.insert(name.clone());
                aliases.insert(name.clone(), name.clone());
                k += 1;
                if matches!(
                    sig.get(k).and_then(|s| s.1.keyword()).as_deref(),
                    Some("as")
                ) {
                    k += 1;
                }
                if let Some((ia, t)) = sig.get(k).map(|(i, t)| (*i, *t))
                    && let Some((alias, _)) = t.ident()
                    && !NOT_ALIAS.contains(&alias.to_ascii_lowercase().as_str())
                {
                    aliases.insert(alias.to_ascii_lowercase(), name.clone());
                    table_positions.insert(ia);
                    k += 1;
                }
                if matches!(sig.get(k).map(|s| s.1), Some(Tok::Punct(',')))
                    && kw.as_deref() == Some("from")
                {
                    k += 1;
                    continue;
                }
                break;
            }
            j = k;
            continue;
        }
        j += 1;
    }
    let entity_lc = entity.to_ascii_lowercase();
    let only_entity = tables.len() == 1 && tables.contains(&entity_lc);
    let reads_entity = tables.contains(&entity_lc);
    let mut out = SqlRefs::default();
    for (n, (idx, tok)) in sig.iter().enumerate() {
        let Some((text, quoted)) = tok.ident() else {
            continue;
        };
        let matches_field = if quoted {
            text == field
        } else {
            text.eq_ignore_ascii_case(field)
        };
        if !matches_field || table_positions.contains(idx) {
            continue;
        }
        let prev = n.checked_sub(1).and_then(|p| sig.get(p)).map(|s| s.1);
        let next = sig.get(n + 1).map(|s| s.1);
        if matches!(prev.and_then(Tok::keyword).as_deref(), Some("as")) {
            continue; // an output alias
        }
        if matches!(next, Some(Tok::Punct('(') | Tok::Punct('.'))) {
            continue; // a function name, or a qualifier itself
        }
        if matches!(prev, Some(Tok::Punct('.'))) {
            let qualifier = n
                .checked_sub(2)
                .and_then(|p| sig.get(p))
                .and_then(|s| s.1.ident())
                .map(|(q, _)| q.to_ascii_lowercase());
            if qualifier
                .and_then(|q| aliases.get(&q))
                .is_some_and(|t| *t == entity_lc)
            {
                out.rewrite.push(*idx);
            }
            continue;
        }
        if only_entity {
            out.rewrite.push(*idx);
        } else if reads_entity {
            out.ambiguous = true;
        }
    }
    out
}

fn rewrite_sql(tokens: &[Tok], positions: &[usize], new: &str) -> String {
    tokens
        .iter()
        .enumerate()
        .map(|(i, t)| {
            if positions.contains(&i) {
                format!("\"{}\"", new.replace('"', "\"\""))
            } else {
                t.src()
            }
        })
        .collect()
}

#[derive(sqlx::FromRow)]
struct QueryRow {
    id: Uuid,
    record_no: Option<String>,
    sql_query: Option<String>,
    table_definition: Option<String>,
    owner_layer: String,
}

async fn candidate_queries(
    conn: &mut PgConnection,
    field: &str,
) -> Result<Vec<QueryRow>, AppError> {
    sqlx::query_as(
        "SELECT id, record_no, sql_query, table_definition, owner_layer FROM sql_query \
         WHERE COALESCE(is_active, true) = true AND strpos(lower(sql_query), lower($1)) > 0",
    )
    .bind(field)
    .fetch_all(&mut *conn)
    .await
    .map_err(internal)
}

struct StoredQueriesHook;

impl FieldReferenceHook for StoredQueriesHook {
    fn name(&self) -> &'static str {
        "stored_queries"
    }

    fn scan<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
        renaming: bool,
    ) -> HookFuture<'a, RefScan> {
        Box::pin(async move {
            let mut out = RefScan::default();
            for q in candidate_queries(conn, field).await? {
                let tokens = tokenize(q.sql_query.as_deref().unwrap_or(""));
                let refs = analyze_sql(&tokens, entity, field);
                if refs.rewrite.is_empty() && !refs.ambiguous {
                    continue;
                }
                let owner = owner_of(&q.owner_layer);
                let name = q.record_no.clone().unwrap_or_default();
                if owner == RefOwner::Ours && (!renaming || refs.ambiguous) {
                    out.blockers.push(Blocker {
                        hook: "stored_queries",
                        object_kind: "stored_query".into(),
                        object_ref: Some(q.id),
                        name: name.clone(),
                        reason: if renaming {
                            "rename_blocked_by_reference: the query names the field where it \
                             cannot be told apart from another table's column; qualify it \
                             (table.field) first"
                                .into()
                        } else {
                            "field_referenced: a stored query of ours reads the field; change \
                             the query in the same changeset first"
                                .into()
                        },
                    });
                }
                out.refs.push(FieldRef {
                    hook: "stored_queries",
                    object_kind: "stored_query".into(),
                    object_ref: Some(q.id),
                    name,
                    owner,
                });
            }
            Ok(out)
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
            let mut out = HookOutcome::default();
            for q in candidate_queries(conn, old).await? {
                let sql = q.sql_query.clone().unwrap_or_default();
                let tokens = tokenize(&sql);
                let refs = analyze_sql(&tokens, entity, old);
                if refs.rewrite.is_empty() && !refs.ambiguous {
                    continue;
                }
                let name = q.record_no.clone().unwrap_or_default();
                if refs.ambiguous {
                    // Ours was refused by `scan`; a customer query is marked
                    // invalid (deactivated) and reported.
                    sqlx::query(
                        "UPDATE sql_query SET is_active = false, \
                         row_version = row_version + 1 WHERE id = $1",
                    )
                    .bind(q.id)
                    .execute(&mut *conn)
                    .await
                    .map_err(internal)?;
                    out.report.push(draft(
                        "customer_object_adjusted",
                        entity,
                        old,
                        "stored_query",
                        q.id,
                        json!({ "name": name, "change": "deactivated: ambiguous reference to the renamed field" }),
                    ));
                    out.touched += 1;
                    continue;
                }
                let rewritten = rewrite_sql(&tokens, &refs.rewrite, new);
                let table_definition = q.table_definition.as_deref().map(|td| {
                    match serde_json::from_str::<Value>(td) {
                        Ok(mut v) => {
                            let mut empty = json!({});
                            rename_in_view(&mut v, &mut empty, old, new);
                            v.to_string()
                        }
                        Err(_) => td.to_owned(),
                    }
                });
                sqlx::query(
                    "UPDATE sql_query SET sql_query = $2, table_definition = $3, \
                     row_version = row_version + 1 WHERE id = $1",
                )
                .bind(q.id)
                .bind(&rewritten)
                .bind(table_definition)
                .execute(&mut *conn)
                .await
                .map_err(internal)?;
                out.touched += 1;
                if owner_of(&q.owner_layer) == RefOwner::Customer {
                    out.report.push(draft(
                        "customer_object_adjusted",
                        entity,
                        old,
                        "stored_query",
                        q.id,
                        json!({ "name": name, "change": "renamed_reference", "to": new }),
                    ));
                }
            }
            Ok(out)
        })
    }

    fn remove<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            let mut out = HookOutcome::default();
            for q in candidate_queries(conn, field).await? {
                if owner_of(&q.owner_layer) != RefOwner::Customer {
                    continue;
                }
                let tokens = tokenize(q.sql_query.as_deref().unwrap_or(""));
                let refs = analyze_sql(&tokens, entity, field);
                if refs.rewrite.is_empty() && !refs.ambiguous {
                    continue;
                }
                sqlx::query(
                    "UPDATE sql_query SET is_active = false, \
                     row_version = row_version + 1 WHERE id = $1",
                )
                .bind(q.id)
                .execute(&mut *conn)
                .await
                .map_err(internal)?;
                out.touched += 1;
                out.report.push(draft(
                    "customer_object_adjusted",
                    entity,
                    field,
                    "stored_query",
                    q.id,
                    json!({ "name": q.record_no, "change": "deactivated: reads the deleted field" }),
                ));
            }
            Ok(out)
        })
    }
}

// ── labels ──────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct LabelRow {
    id: Uuid,
    object_kind: String,
    object_ref: String,
    locale: String,
}

async fn field_labels(
    conn: &mut PgConnection,
    entity: &str,
    field: &str,
) -> Result<Vec<LabelRow>, AppError> {
    let exact = format!("{entity}.{field}");
    let prefix = format!("{entity}.{field}.");
    sqlx::query_as(
        "SELECT id, object_kind, object_ref, locale FROM metadata_label \
         WHERE is_deleted = false AND ( \
             (object_kind = 'attribute' AND object_ref = $1) \
          OR (object_kind = 'choice_option' AND left(object_ref, char_length($2)) = $2))",
    )
    .bind(&exact)
    .bind(&prefix)
    .fetch_all(&mut *conn)
    .await
    .map_err(internal)
}

async fn label_change_log(
    conn: &mut PgConnection,
    kind: &str,
    object_ref: &str,
    locale: &str,
    is_delete: bool,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO metadata_label_change_log (object_kind, object_ref, locale, change_kind) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(kind)
    .bind(object_ref)
    .bind(locale)
    .bind(if is_delete { "delete" } else { "upsert" })
    .execute(&mut *conn)
    .await
    .map_err(internal)?;
    Ok(())
}

struct LabelsHook;

impl FieldReferenceHook for LabelsHook {
    fn name(&self) -> &'static str {
        "labels"
    }

    fn scan<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
        _renaming: bool,
    ) -> HookFuture<'a, RefScan> {
        Box::pin(async move {
            Ok(RefScan {
                refs: field_labels(conn, entity, field)
                    .await?
                    .into_iter()
                    .map(|l| FieldRef {
                        hook: "labels",
                        object_kind: format!("label:{}", l.object_kind),
                        object_ref: Some(l.id),
                        name: format!("{} ({})", l.object_ref, l.locale),
                        owner: RefOwner::Ours,
                    })
                    .collect(),
                blockers: Vec::new(),
            })
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
            let mut out = HookOutcome::default();
            let old_base = format!("{entity}.{old}");
            let new_base = format!("{entity}.{new}");
            for l in field_labels(conn, entity, old).await? {
                let new_ref = format!("{new_base}{}", &l.object_ref[old_base.len()..]);
                sqlx::query(
                    "UPDATE metadata_label SET object_ref = $2, \
                     row_version = row_version + 1, updated_at = NOW() WHERE id = $1",
                )
                .bind(l.id)
                .bind(&new_ref)
                .execute(&mut *conn)
                .await
                .map_err(internal)?;
                label_change_log(conn, &l.object_kind, &l.object_ref, &l.locale, true).await?;
                label_change_log(conn, &l.object_kind, &new_ref, &l.locale, false).await?;
                out.touched += 1;
            }
            if out.touched > 0 {
                out.caches.push(CacheTouch::Labels);
            }
            Ok(out)
        })
    }

    fn remove<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            let mut out = HookOutcome::default();
            for l in field_labels(conn, entity, field).await? {
                sqlx::query(
                    "UPDATE metadata_label SET is_deleted = true, \
                     row_version = row_version + 1, updated_at = NOW() WHERE id = $1",
                )
                .bind(l.id)
                .execute(&mut *conn)
                .await
                .map_err(internal)?;
                label_change_log(conn, &l.object_kind, &l.object_ref, &l.locale, true).await?;
                out.touched += 1;
            }
            if out.touched > 0 {
                out.caches.push(CacheTouch::Labels);
            }
            Ok(out)
        })
    }
}

// ── business rules: `crate::business_rule_hooks` (D-789 §8) ─────────────────

// ── state models ────────────────────────────────────────────────────────────

struct StateHook;

#[derive(sqlx::FromRow)]
struct GuardRow {
    id: Uuid,
    from_state: String,
    to_state: String,
    guard_expression: Option<String>,
    owner_layer: String,
}

async fn entity_guards(conn: &mut PgConnection, entity: &str) -> Result<Vec<GuardRow>, AppError> {
    sqlx::query_as(
        "SELECT t.id, t.from_state, t.to_state, t.guard_expression, t.owner_layer \
         FROM state_transition t JOIN state_model m ON m.id = t.model_ref \
         WHERE m.entity_logicalname = $1 AND m.is_deleted = false AND t.is_deleted = false \
           AND t.guard_expression IS NOT NULL",
    )
    .bind(entity)
    .fetch_all(&mut *conn)
    .await
    .map_err(internal)
}

impl FieldReferenceHook for StateHook {
    fn name(&self) -> &'static str {
        "state"
    }

    fn scan<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
        renaming: bool,
    ) -> HookFuture<'a, RefScan> {
        Box::pin(async move {
            let mut out = RefScan::default();
            let models: Vec<(Uuid, String, String)> = sqlx::query_as(
                "SELECT id, name, owner_layer FROM state_model \
                 WHERE entity_logicalname = $1 AND state_field = $2 AND is_deleted = false",
            )
            .bind(entity)
            .bind(field)
            .fetch_all(&mut *conn)
            .await
            .map_err(internal)?;
            for (id, name, layer) in models {
                if !renaming {
                    out.blockers.push(Blocker {
                        hook: "state",
                        object_kind: "state_model".into(),
                        object_ref: Some(id),
                        name: name.clone(),
                        reason: "field_in_use: the field is the entity's status field".into(),
                    });
                }
                out.refs.push(FieldRef {
                    hook: "state",
                    object_kind: "state_model".into(),
                    object_ref: Some(id),
                    name,
                    owner: owner_of(&layer),
                });
            }
            for g in entity_guards(conn, entity).await? {
                if !g
                    .guard_expression
                    .as_deref()
                    .is_some_and(|e| expression_names(e, field))
                {
                    continue;
                }
                let owner = owner_of(&g.owner_layer);
                let name = format!("{}->{}", g.from_state, g.to_state);
                if !renaming && owner == RefOwner::Ours {
                    out.blockers.push(Blocker {
                        hook: "state",
                        object_kind: "state_transition".into(),
                        object_ref: Some(g.id),
                        name: name.clone(),
                        reason: "field_referenced: a status change's guard reads the field".into(),
                    });
                }
                out.refs.push(FieldRef {
                    hook: "state",
                    object_kind: "state_transition".into(),
                    object_ref: Some(g.id),
                    name,
                    owner,
                });
            }
            Ok(out)
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
            let mut out = HookOutcome::default();
            let n = sqlx::query(
                "UPDATE state_model SET state_field = $3, row_version = row_version + 1 \
                 WHERE entity_logicalname = $1 AND state_field = $2 AND is_deleted = false",
            )
            .bind(entity)
            .bind(old)
            .bind(new)
            .execute(&mut *conn)
            .await
            .map_err(internal)?
            .rows_affected();
            out.touched += n;
            for g in entity_guards(conn, entity).await? {
                let Some(expr) = g.guard_expression.as_deref() else {
                    continue;
                };
                if !expression_names(expr, old) {
                    continue;
                }
                sqlx::query(
                    "UPDATE state_transition SET guard_expression = $2, \
                     row_version = row_version + 1 WHERE id = $1",
                )
                .bind(g.id)
                .bind(rewrite_expression(expr, old, new))
                .execute(&mut *conn)
                .await
                .map_err(internal)?;
                out.touched += 1;
            }
            if out.touched > 0 {
                out.caches.push(CacheTouch::StateModels);
            }
            Ok(out)
        })
    }

    fn remove<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            let mut out = HookOutcome::default();
            for g in entity_guards(conn, entity).await? {
                if owner_of(&g.owner_layer) != RefOwner::Customer
                    || !g
                        .guard_expression
                        .as_deref()
                        .is_some_and(|e| expression_names(e, field))
                {
                    continue;
                }
                sqlx::query(
                    "UPDATE state_transition SET is_deleted = true, \
                     row_version = row_version + 1 WHERE id = $1",
                )
                .bind(g.id)
                .execute(&mut *conn)
                .await
                .map_err(internal)?;
                out.touched += 1;
                out.report.push(draft(
                    "customer_object_removed",
                    entity,
                    field,
                    "state_transition",
                    g.id,
                    json!({ "name": format!("{}->{}", g.from_state, g.to_state),
                            "change": "removed: its guard read the deleted field" }),
                ));
            }
            if out.touched > 0 {
                out.caches.push(CacheTouch::StateModels);
            }
            Ok(out)
        })
    }
}

// ── workflows ───────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct WorkflowVersionRow {
    version_id: Uuid,
    definition_id: Uuid,
    name: String,
    owner_layer: String,
    graph: Value,
}

/// Draft and published versions of workflows with a trigger on `entity`
/// (their condition nodes read that record: the static record context).
async fn entity_workflows(
    conn: &mut PgConnection,
    entity: &str,
) -> Result<Vec<WorkflowVersionRow>, AppError> {
    sqlx::query_as(
        "SELECT v.id AS version_id, d.id AS definition_id, d.name, d.owner_layer, v.graph \
         FROM workflow_definition_version v \
         JOIN workflow_definition d ON d.id = v.definition_id \
         WHERE d.is_deleted = false AND v.status IN ('draft', 'published') \
           AND EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(v.graph->'nodes', '[]'::jsonb)) n \
                       WHERE n->>'type' = 'trigger' AND n->'config'->>'entity_logicalname' = $1)",
    )
    .bind(entity)
    .fetch_all(&mut *conn)
    .await
    .map_err(internal)
}

fn node_field_matches(value: &str, field: &str) -> bool {
    value == field
        || value
            .strip_prefix(field)
            .is_some_and(|rest| rest.starts_with('.'))
        || value.strip_prefix("record.").is_some_and(|v| {
            v == field || v.strip_prefix(field).is_some_and(|r| r.starts_with('.'))
        })
}

fn graph_names(graph: &Value, field: &str) -> bool {
    graph
        .get("nodes")
        .and_then(Value::as_array)
        .is_some_and(|nodes| {
            nodes.iter().any(|n| {
                let config = n.get("config");
                config
                    .and_then(|c| c.get("field"))
                    .and_then(Value::as_str)
                    .is_some_and(|f| node_field_matches(f, field))
                    || config
                        .and_then(|c| c.get("expression"))
                        .and_then(Value::as_str)
                        .is_some_and(|e| expression_names(e, field))
            })
        })
}

fn rename_in_graph(graph: &mut Value, old: &str, new: &str) {
    let Some(nodes) = graph.get_mut("nodes").and_then(Value::as_array_mut) else {
        return;
    };
    for n in nodes {
        let Some(config) = n.get_mut("config").and_then(Value::as_object_mut) else {
            continue;
        };
        if let Some(f) = config
            .get("field")
            .and_then(Value::as_str)
            .map(str::to_owned)
            && node_field_matches(&f, old)
        {
            let renamed = if let Some(rest) = f.strip_prefix("record.") {
                format!("record.{new}{}", &rest[old.len()..])
            } else {
                format!("{new}{}", &f[old.len()..])
            };
            config.insert("field".into(), json!(renamed));
        }
        if let Some(e) = config
            .get("expression")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            config.insert("expression".into(), json!(rewrite_expression(&e, old, new)));
        }
    }
}

struct WorkflowsHook;

impl FieldReferenceHook for WorkflowsHook {
    fn name(&self) -> &'static str {
        "workflows"
    }

    fn scan<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
        renaming: bool,
    ) -> HookFuture<'a, RefScan> {
        Box::pin(async move {
            let mut out = RefScan::default();
            for w in entity_workflows(conn, entity).await? {
                if !graph_names(&w.graph, field) {
                    continue;
                }
                let owner = owner_of(&w.owner_layer);
                if !renaming && owner == RefOwner::Ours {
                    out.blockers.push(Blocker {
                        hook: "workflows",
                        object_kind: "workflow".into(),
                        object_ref: Some(w.definition_id),
                        name: w.name.clone(),
                        reason: "field_referenced: a workflow of ours reads the field; change it \
                                 in the same changeset first"
                            .into(),
                    });
                }
                out.refs.push(FieldRef {
                    hook: "workflows",
                    object_kind: "workflow_version".into(),
                    object_ref: Some(w.version_id),
                    name: w.name,
                    owner,
                });
            }
            Ok(out)
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
            let mut out = HookOutcome::default();
            for mut w in entity_workflows(conn, entity).await? {
                if !graph_names(&w.graph, old) {
                    continue;
                }
                rename_in_graph(&mut w.graph, old, new);
                sqlx::query(
                    "UPDATE workflow_definition_version SET graph = $2, \
                     row_version = row_version + 1 WHERE id = $1",
                )
                .bind(w.version_id)
                .bind(&w.graph)
                .execute(&mut *conn)
                .await
                .map_err(internal)?;
                // The published version's derived trigger index carries the
                // trigger expression too (rebuilt at publish).
                let rows: Vec<(Uuid, Value)> = sqlx::query_as(
                    "SELECT id, condition FROM workflow_trigger_index \
                     WHERE definition_version_id = $1 AND condition ? 'expression'",
                )
                .bind(w.version_id)
                .fetch_all(&mut *conn)
                .await
                .map_err(internal)?;
                for (id, mut condition) in rows {
                    if let Some(e) = condition.get("expression").and_then(Value::as_str) {
                        let rewritten = rewrite_expression(e, old, new);
                        condition["expression"] = json!(rewritten);
                        sqlx::query(
                            "UPDATE workflow_trigger_index SET condition = $2 WHERE id = $1",
                        )
                        .bind(id)
                        .bind(&condition)
                        .execute(&mut *conn)
                        .await
                        .map_err(internal)?;
                    }
                }
                out.touched += 1;
                if owner_of(&w.owner_layer) == RefOwner::Customer {
                    out.report.push(draft(
                        "customer_object_adjusted",
                        entity,
                        old,
                        "workflow",
                        w.definition_id,
                        json!({ "name": w.name, "change": "renamed_reference", "to": new }),
                    ));
                }
            }
            Ok(out)
        })
    }

    fn remove<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            let mut out = HookOutcome::default();
            let mut done: HashSet<Uuid> = HashSet::new();
            for w in entity_workflows(conn, entity).await? {
                if owner_of(&w.owner_layer) != RefOwner::Customer
                    || !graph_names(&w.graph, field)
                    || !done.insert(w.definition_id)
                {
                    continue;
                }
                sqlx::query(
                    "UPDATE workflow_definition SET is_active = false, \
                     row_version = row_version + 1 WHERE id = $1",
                )
                .bind(w.definition_id)
                .execute(&mut *conn)
                .await
                .map_err(internal)?;
                out.touched += 1;
                out.report.push(draft(
                    "customer_object_adjusted",
                    entity,
                    field,
                    "workflow",
                    w.definition_id,
                    json!({ "name": w.name, "change": "deactivated: a node read the deleted field" }),
                ));
            }
            Ok(out)
        })
    }
}

// ── field security ──────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct ConditionRow {
    id: Uuid,
    role_ref: Uuid,
    privilege_key: String,
    owner_layer: String,
}

async fn grant_conditions(
    conn: &mut PgConnection,
    entity: &str,
    field: &str,
) -> Result<Vec<ConditionRow>, AppError> {
    sqlx::query_as(
        "SELECT c.id, rp.role_ref, p.key AS privilege_key, c.owner_layer \
         FROM role_privilege_condition c \
         JOIN role_mm_privilege rp ON rp.id = c.role_privilege_ref \
         JOIN privilege p ON p.id = rp.privilege_ref \
         WHERE c.is_deleted = false AND rp.is_deleted = false \
           AND c.field_logicalname = $2 AND split_part(p.key, '.', 1) = $1",
    )
    .bind(entity)
    .bind(field)
    .fetch_all(&mut *conn)
    .await
    .map_err(internal)
}

struct FieldSecurityHook;

impl FieldReferenceHook for FieldSecurityHook {
    fn name(&self) -> &'static str {
        "field_security"
    }

    fn scan<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
        renaming: bool,
    ) -> HookFuture<'a, RefScan> {
        Box::pin(async move {
            let mut out = RefScan::default();
            let profiles: Vec<(Uuid, Uuid)> = sqlx::query_as(
                "SELECT id, profile_ref FROM field_security_profile_field \
                 WHERE entity_logicalname = $1 AND field_logicalname = $2",
            )
            .bind(entity)
            .bind(field)
            .fetch_all(&mut *conn)
            .await
            .map_err(internal)?;
            for (id, profile) in profiles {
                out.refs.push(FieldRef {
                    hook: "field_security",
                    object_kind: "field_security_profile_field".into(),
                    object_ref: Some(id),
                    name: profile.to_string(),
                    owner: RefOwner::Ours,
                });
            }
            let bulk: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT role_ref FROM role_bulk_field \
                 WHERE entity_logicalname = $1 AND attribute_logicalname = $2",
            )
            .bind(entity)
            .bind(field)
            .fetch_all(&mut *conn)
            .await
            .map_err(internal)?;
            for (role,) in bulk {
                out.refs.push(FieldRef {
                    hook: "field_security",
                    object_kind: "role_bulk_field".into(),
                    object_ref: Some(role),
                    name: role.to_string(),
                    owner: RefOwner::Ours,
                });
            }
            for c in grant_conditions(conn, entity, field).await? {
                let owner = owner_of(&c.owner_layer);
                // Topic 15 #3: our grant condition blocks the delete —
                // removing a condition would widen access.
                if !renaming && owner == RefOwner::Ours {
                    out.blockers.push(Blocker {
                        hook: "field_security",
                        object_kind: "role_grant_condition".into(),
                        object_ref: Some(c.id),
                        name: c.privilege_key.clone(),
                        reason: "field_referenced: a role grant condition of ours uses the field; \
                                 removing it would widen access, so change the grant first"
                            .into(),
                    });
                }
                out.refs.push(FieldRef {
                    hook: "field_security",
                    object_kind: "role_grant_condition".into(),
                    object_ref: Some(c.id),
                    name: c.privilege_key,
                    owner,
                });
            }
            Ok(out)
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
            let mut out = HookOutcome::default();
            let profiles: Vec<(Uuid,)> = sqlx::query_as(
                "UPDATE field_security_profile_field SET field_logicalname = $3, \
                 row_version = row_version + 1 \
                 WHERE entity_logicalname = $1 AND field_logicalname = $2 RETURNING profile_ref",
            )
            .bind(entity)
            .bind(old)
            .bind(new)
            .fetch_all(&mut *conn)
            .await
            .map_err(internal)?;
            let roles: Vec<(Uuid,)> = sqlx::query_as(
                "UPDATE role_bulk_field SET attribute_logicalname = $3 \
                 WHERE entity_logicalname = $1 AND attribute_logicalname = $2 RETURNING role_ref",
            )
            .bind(entity)
            .bind(old)
            .bind(new)
            .fetch_all(&mut *conn)
            .await
            .map_err(internal)?;
            let conditions = grant_conditions(conn, entity, old).await?;
            for c in &conditions {
                sqlx::query(
                    "UPDATE role_privilege_condition SET field_logicalname = $2, \
                     row_version = row_version + 1 WHERE id = $1",
                )
                .bind(c.id)
                .bind(new)
                .execute(&mut *conn)
                .await
                .map_err(internal)?;
            }
            out.touched = (profiles.len() + roles.len() + conditions.len()) as u64;
            for (p,) in profiles {
                push_unique(&mut out.caches, CacheTouch::SecurityProfile(p));
            }
            for role in roles
                .iter()
                .map(|(r,)| *r)
                .chain(conditions.iter().map(|c| c.role_ref))
            {
                push_unique(&mut out.caches, CacheTouch::SecurityRole(role));
            }
            Ok(out)
        })
    }

    fn remove<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            let mut out = HookOutcome::default();
            let profiles: Vec<(Uuid,)> = sqlx::query_as(
                "DELETE FROM field_security_profile_field \
                 WHERE entity_logicalname = $1 AND field_logicalname = $2 RETURNING profile_ref",
            )
            .bind(entity)
            .bind(field)
            .fetch_all(&mut *conn)
            .await
            .map_err(internal)?;
            let roles: Vec<(Uuid,)> = sqlx::query_as(
                "DELETE FROM role_bulk_field \
                 WHERE entity_logicalname = $1 AND attribute_logicalname = $2 RETURNING role_ref",
            )
            .bind(entity)
            .bind(field)
            .fetch_all(&mut *conn)
            .await
            .map_err(internal)?;
            out.touched = (profiles.len() + roles.len()) as u64;
            for (p,) in profiles {
                push_unique(&mut out.caches, CacheTouch::SecurityProfile(p));
            }
            for (r,) in roles {
                push_unique(&mut out.caches, CacheTouch::SecurityRole(r));
            }
            // Grant conditions are not handled here: whether a customer
            // condition's grant may be revoked depends on the layer of the
            // change and needs its actor for the security event, so the
            // executor decides ([`customer_grant_conditions`]) and revokes
            // ([`revoke_customer_grants`]) in the delete's transaction.
            Ok(out)
        })
    }
}

/// A customer grant a customer-layer field delete revokes (security review
/// M3): the grant, every live condition of it and the change are all the
/// customer layer.
#[derive(Debug, Clone)]
pub(crate) struct RevocableGrant {
    pub grant_id: Uuid,
    pub role_ref: Uuid,
    pub role_name: String,
    pub privilege_key: String,
}

#[derive(sqlx::FromRow)]
struct CustomerConditionRow {
    grant_id: Uuid,
    role_ref: Uuid,
    role_name: String,
    privilege_key: String,
    grant_layer: String,
    all_customer: bool,
}

/// Whether a customer condition's grant may be revoked by a delete made in
/// `change_layer`: only when the change, the grant and every live condition
/// of the grant are the customer layer (Topic 16: a delete touches rows of
/// its own layer only). Pure, for the unit test.
pub(crate) fn customer_grant_revocable(
    change_layer: Option<Layer>,
    grant_layer: &str,
    all_conditions_customer: bool,
) -> bool {
    change_layer == Some(Layer::Customer) && grant_layer == "customer" && all_conditions_customer
}

/// The customer-layer grant conditions naming `entity.field` (our own
/// conditions are blockers of the `field_security` hook's scan). Each is
/// either revocable ([`customer_grant_revocable`]) or a blocker that names
/// the grant. The grant rows are locked `FOR UPDATE`: the caller revokes
/// them in the same transaction.
pub(crate) async fn customer_grant_conditions(
    conn: &mut PgConnection,
    entity: &str,
    field: &str,
    change_layer: Option<Layer>,
) -> Result<(Vec<Blocker>, Vec<RevocableGrant>), AppError> {
    let rows: Vec<CustomerConditionRow> = sqlx::query_as(
        "SELECT DISTINCT rp.id AS grant_id, rp.role_ref, r.name AS role_name, \
                p.key AS privilege_key, rp.owner_layer AS grant_layer, \
                NOT EXISTS (SELECT 1 FROM role_privilege_condition c2 \
                            WHERE c2.role_privilege_ref = rp.id AND c2.is_deleted = false \
                              AND c2.owner_layer <> 'customer') AS all_customer \
         FROM role_privilege_condition c \
         JOIN role_mm_privilege rp ON rp.id = c.role_privilege_ref \
         JOIN role r ON r.id = rp.role_ref \
         JOIN privilege p ON p.id = rp.privilege_ref \
         WHERE c.is_deleted = false AND rp.is_deleted = false AND c.owner_layer = 'customer' \
           AND c.field_logicalname = $2 AND split_part(p.key, '.', 1) = $1",
    )
    .bind(entity)
    .bind(field)
    .fetch_all(&mut *conn)
    .await
    .map_err(internal)?;
    let mut blockers = Vec::new();
    let mut revocable = Vec::new();
    for r in rows {
        if customer_grant_revocable(change_layer, &r.grant_layer, r.all_customer) {
            revocable.push(RevocableGrant {
                grant_id: r.grant_id,
                role_ref: r.role_ref,
                role_name: r.role_name,
                privilege_key: r.privilege_key,
            });
        } else {
            blockers.push(Blocker {
                hook: "field_security",
                object_kind: "role_grant".into(),
                object_ref: Some(r.grant_id),
                name: format!("{} on role {}", r.privilege_key, r.role_name),
                reason: format!(
                    "field_referenced: a customer grant condition on grant {} of role {} \
                     ({}-layer grant) uses the field; a {} change may not revoke it, so change \
                     or remove the grant's condition first",
                    r.privilege_key,
                    r.role_name,
                    r.grant_layer,
                    change_layer.map_or("dry-run", Layer::as_str)
                ),
            });
        }
    }
    Ok((blockers, revocable))
}

/// Revokes `grants` (every condition, then the grant row; the role is marked
/// customized so a boot seed leaves it alone) in the delete's transaction,
/// each with its `Access`/`Revoke` security event written in that same
/// transaction (security review M3, L2). Access narrows, never widens.
pub(crate) async fn revoke_customer_grants(
    tx: &mut attome_db::Tx<'_>,
    audit: &attome_audit::AuditService<'_>,
    entity: &str,
    field: &str,
    grants: &[RevocableGrant],
    actor: Uuid,
) -> Result<HookOutcome, AppError> {
    let mut out = HookOutcome::default();
    for g in grants {
        sqlx::query(
            "UPDATE role_privilege_condition SET is_deleted = true, \
             row_version = row_version + 1 WHERE role_privilege_ref = $1 AND is_deleted = false",
        )
        .bind(g.grant_id)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
        let revoked = sqlx::query(
            "UPDATE role_mm_privilege SET is_deleted = true, \
             row_version = row_version + 1, updated_at = NOW() \
             WHERE id = $1 AND is_deleted = false AND owner_layer = 'customer'",
        )
        .bind(g.grant_id)
        .execute(&mut **tx)
        .await
        .map_err(internal)?
        .rows_affected();
        if revoked != 1 {
            return Err(AppError::Conflict(
                "a role grant changed concurrently with the field delete; retry",
            ));
        }
        sqlx::query(
            "UPDATE role SET is_customized = true, updated_at = NOW() \
             WHERE id = $1 AND is_customized = false",
        )
        .bind(g.role_ref)
        .execute(&mut **tx)
        .await
        .map_err(internal)?;
        attome_audit::security::write_security_event(
            tx,
            audit,
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Access,
                attome_audit::AuditOperation::Revoke,
                actor,
                "role_mm_privilege",
                Some(g.grant_id),
            )
            .named("role_grant.revoked_by_field_delete")
            .comment(format!(
                "grant {} of role {} revoked: its condition named the deleted field {entity}.{field}",
                g.privilege_key, g.role_name
            )),
        )
        .await?;
        out.touched += 1;
        push_unique(&mut out.caches, CacheTouch::SecurityRole(g.role_ref));
        out.report.push(draft(
            "customer_object_adjusted",
            entity,
            field,
            "role_grant",
            g.grant_id,
            json!({ "privilege": g.privilege_key, "role": g.role_name,
                    "change": "grant revoked: its condition named the deleted field" }),
        ));
    }
    Ok(out)
}

// ── portal (attome-portal, migration 0485) ─────────────────────────────────────

/// The portal user entity a `value_ref` (`@portal_user.<field>`) reads.
const PORTAL_USER_ENTITY: &str = "webportal_user";

/// `@portal_user.<field>`.
fn portal_value_ref(field: &str) -> String {
    format!("@portal_user.{field}")
}

/// The portal's field-name references (security review M2): grant
/// conditions (`webportal_grant_condition.field_logicalname` of a grant
/// on the entity, and `value_ref = @portal_user.<field>` when the entity is
/// the portal user), grant field profiles (`webportal_grant_field`) and
/// the per-portal owner field (`webportal_entity.portal_user_field`).
/// A rename rewrites every one. A delete is blocked while a condition, a
/// `value_ref` or the owner field names the field — the same rule as our own
/// grant conditions, since removing a row scope would widen access and a
/// stale name would re-bind to a later field of the same name (D-788 allows
/// reuse) — and removes the grant-field entries (an allow-list entry going
/// away only narrows access).
struct PortalHook;

async fn portal_condition_refs(
    conn: &mut PgConnection,
    entity: &str,
    field: &str,
) -> Result<Vec<(Uuid, Uuid)>, AppError> {
    sqlx::query_as(
        "SELECT c.id, c.grant_id FROM webportal_grant_condition c \
         JOIN webportal_grant g ON g.id = c.grant_id \
         WHERE (g.entity_logicalname = $1 AND c.field_logicalname = $2) \
            OR ($1 = $3 AND c.value_ref = $4)",
    )
    .bind(entity)
    .bind(field)
    .bind(PORTAL_USER_ENTITY)
    .bind(portal_value_ref(field))
    .fetch_all(&mut *conn)
    .await
    .map_err(internal)
}

impl FieldReferenceHook for PortalHook {
    fn name(&self) -> &'static str {
        "portal"
    }

    fn scan<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
        renaming: bool,
    ) -> HookFuture<'a, RefScan> {
        Box::pin(async move {
            let mut out = RefScan::default();
            for (id, grant) in portal_condition_refs(conn, entity, field).await? {
                if !renaming {
                    out.blockers.push(Blocker {
                        hook: "portal",
                        object_kind: "portal_grant_condition".into(),
                        object_ref: Some(id),
                        name: grant.to_string(),
                        reason: "field_referenced: a portal grant condition uses the field; \
                                 removing it would widen portal access, so change the portal \
                                 grant first"
                            .into(),
                    });
                }
                out.refs.push(FieldRef {
                    hook: "portal",
                    object_kind: "portal_grant_condition".into(),
                    object_ref: Some(id),
                    name: grant.to_string(),
                    owner: RefOwner::Ours,
                });
            }
            let owners: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT webportal_id FROM webportal_entity \
                 WHERE entity_logicalname = $1 AND portal_user_field = $2",
            )
            .bind(entity)
            .bind(field)
            .fetch_all(&mut *conn)
            .await
            .map_err(internal)?;
            for (portal,) in owners {
                if !renaming {
                    out.blockers.push(Blocker {
                        hook: "portal",
                        object_kind: "portal_entity".into(),
                        object_ref: Some(portal),
                        name: portal.to_string(),
                        reason: "field_referenced: a portal records its users in this field; \
                                 change the portal's entity setting first"
                            .into(),
                    });
                }
                out.refs.push(FieldRef {
                    hook: "portal",
                    object_kind: "portal_entity".into(),
                    object_ref: Some(portal),
                    name: portal.to_string(),
                    owner: RefOwner::Ours,
                });
            }
            let fields: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT f.grant_id FROM webportal_grant_field f \
                 JOIN webportal_grant g ON g.id = f.grant_id \
                 WHERE g.entity_logicalname = $1 AND f.field_logicalname = $2",
            )
            .bind(entity)
            .bind(field)
            .fetch_all(&mut *conn)
            .await
            .map_err(internal)?;
            for (grant,) in fields {
                out.refs.push(FieldRef {
                    hook: "portal",
                    object_kind: "portal_grant_field".into(),
                    object_ref: Some(grant),
                    name: grant.to_string(),
                    owner: RefOwner::Ours,
                });
            }
            Ok(out)
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
            let conditions = sqlx::query(
                "UPDATE webportal_grant_condition c SET field_logicalname = $3 \
                 FROM webportal_grant g \
                 WHERE g.id = c.grant_id AND g.entity_logicalname = $1 \
                   AND c.field_logicalname = $2",
            )
            .bind(entity)
            .bind(old)
            .bind(new)
            .execute(&mut *conn)
            .await
            .map_err(internal)?
            .rows_affected();
            let value_refs = if entity == PORTAL_USER_ENTITY {
                sqlx::query(
                    "UPDATE webportal_grant_condition SET value_ref = $2 WHERE value_ref = $1",
                )
                .bind(portal_value_ref(old))
                .bind(portal_value_ref(new))
                .execute(&mut *conn)
                .await
                .map_err(internal)?
                .rows_affected()
            } else {
                0
            };
            let fields = sqlx::query(
                "UPDATE webportal_grant_field f SET field_logicalname = $3 \
                 FROM webportal_grant g \
                 WHERE g.id = f.grant_id AND g.entity_logicalname = $1 \
                   AND f.field_logicalname = $2",
            )
            .bind(entity)
            .bind(old)
            .bind(new)
            .execute(&mut *conn)
            .await
            .map_err(internal)?
            .rows_affected();
            let owners = sqlx::query(
                "UPDATE webportal_entity SET portal_user_field = $3 \
                 WHERE entity_logicalname = $1 AND portal_user_field = $2",
            )
            .bind(entity)
            .bind(old)
            .bind(new)
            .execute(&mut *conn)
            .await
            .map_err(internal)?
            .rows_affected();
            // The portal's plan templates are keyed by the metadata snapshot
            // (`attome_portal::context::PlanTemplate::built_against`); the
            // rename's metadata doorbell swaps the snapshot, so they rebuild
            // from these rows.
            Ok(HookOutcome {
                touched: conditions + value_refs + fields + owners,
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
            // Conditions, value_refs and the owner field blocked the delete
            // in `scan`; only the field-profile entries remain.
            let removed = sqlx::query(
                "DELETE FROM webportal_grant_field f USING webportal_grant g \
                 WHERE g.id = f.grant_id AND g.entity_logicalname = $1 \
                   AND f.field_logicalname = $2",
            )
            .bind(entity)
            .bind(field)
            .execute(&mut *conn)
            .await
            .map_err(internal)?
            .rows_affected();
            Ok(HookOutcome {
                touched: removed,
                ..HookOutcome::default()
            })
        })
    }
}

fn push_unique(caches: &mut Vec<CacheTouch>, touch: CacheTouch) {
    if !caches.contains(&touch) {
        caches.push(touch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_matches_its_declared_set() {
        assert_eq!(registry().names(), REGISTERED);
        assert!(REGISTERED.contains(&"portal"), "security review M2");
    }

    #[test]
    fn a_field_delete_revokes_only_grants_of_its_own_customer_layer() {
        // Security review M3 / Topic 16: every row customer, change customer.
        assert!(customer_grant_revocable(
            Some(Layer::Customer),
            "customer",
            true
        ));
        // A customer condition narrowing a platform grant: block, never
        // soft-delete the platform grant.
        assert!(!customer_grant_revocable(
            Some(Layer::Customer),
            "platform",
            true
        ));
        // Another condition of the grant is ours: block.
        assert!(!customer_grant_revocable(
            Some(Layer::Customer),
            "customer",
            false
        ));
        // Our layer deleting the field: a customer grant blocks it.
        for layer in [Layer::Platform, Layer::Product, Layer::Project] {
            assert!(!customer_grant_revocable(Some(layer), "customer", true));
        }
        // Unknown layer (a dry run without a changeset): conservative.
        assert!(!customer_grant_revocable(None, "customer", true));
    }

    #[test]
    fn portal_value_refs_name_the_portal_user_field() {
        assert_eq!(portal_value_ref("company_ref"), "@portal_user.company_ref");
    }

    fn refs(sql: &str, entity: &str, field: &str) -> (Vec<String>, bool) {
        let tokens = tokenize(sql);
        let r = analyze_sql(&tokens, entity, field);
        (
            r.rewrite.iter().map(|i| tokens[*i].src()).collect(),
            r.ambiguous,
        )
    }

    #[test]
    fn single_table_queries_rewrite_every_bare_reference() {
        let (hits, ambiguous) = refs(
            "SELECT id, amount, \"amount\" AS a FROM invoice WHERE amount > 0 -- amount\n ORDER BY amount",
            "invoice",
            "amount",
        );
        assert_eq!(hits.len(), 4);
        assert!(!ambiguous);
        let tokens = tokenize("SELECT amount FROM invoice WHERE note = 'amount'");
        let r = analyze_sql(&tokens, "invoice", "amount");
        assert_eq!(
            rewrite_sql(&tokens, &r.rewrite, "total"),
            "SELECT \"total\" FROM invoice WHERE note = 'amount'"
        );
    }

    #[test]
    fn joins_rewrite_only_qualified_references_and_flag_bare_ones() {
        let (hits, ambiguous) = refs(
            "SELECT i.amount, c.amount FROM invoice i JOIN contract AS c ON c.id = i.contract_ref",
            "invoice",
            "amount",
        );
        assert_eq!(hits, vec!["amount"]);
        assert!(!ambiguous);
        let (_, ambiguous) = refs(
            "SELECT amount FROM invoice i JOIN contract c ON c.id = i.contract_ref",
            "invoice",
            "amount",
        );
        assert!(ambiguous);
        let (hits, ambiguous) = refs("SELECT amount FROM contract", "invoice", "amount");
        assert!(hits.is_empty() && !ambiguous);
        let (hits, _) = refs(
            "SELECT sum(amount) AS amount FROM invoice",
            "invoice",
            "amount",
        );
        assert_eq!(hits.len(), 1, "the alias after AS is not the field");
    }

    #[test]
    fn view_json_follows_a_rename_and_loses_a_deleted_field() {
        let mut td = json!([{ "name": "amount" }, { "name": "name" }]);
        let mut md = json!({ "filters": [{ "field": "amount", "op": "gt", "value": 1 }],
                             "color_field": "amount" });
        assert!(view_names(&td, &md, "amount"));
        rename_in_view(&mut td, &mut md, "amount", "total");
        assert_eq!(td[0]["name"], "total");
        assert_eq!(md["filters"][0]["field"], "total");
        assert_eq!(md["color_field"], "total");
        let broken = remove_from_view(&mut td, &mut md, "total");
        assert!(!broken);
        assert_eq!(td.as_array().map(Vec::len), Some(1));
        assert!(md["color_field"].is_null());
        let mut kanban = json!({ "state_field": "status" });
        assert!(remove_from_view(&mut json!([]), &mut kanban, "status"));
    }

    #[test]
    fn workflow_condition_fields_follow_a_rename() {
        let mut g = json!({ "nodes": [
            { "id": "t", "type": "trigger", "config": { "entity_logicalname": "invoice",
              "expression": "amount > 5" } },
            { "id": "c", "type": "condition", "config": { "field": "record.amount", "op": "gt" } }
        ]});
        assert!(graph_names(&g, "amount"));
        rename_in_graph(&mut g, "amount", "total");
        assert_eq!(g["nodes"][0]["config"]["expression"], "total > 5");
        assert_eq!(g["nodes"][1]["config"]["field"], "record.total");
        assert!(!graph_names(&g, "amount"));
    }
}
