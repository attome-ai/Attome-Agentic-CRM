//! M01-core C-05: lookup/polymorphic-reference display-name resolution,
//! honouring the *target* entity's own RLS.
//!
//! Three call sites resolve a lookup or polymorphic-reference field's
//! display name the same way — batch the ids by distinct target entity, run
//! one `WHERE id = ANY($1)` against that target's table, read back
//! `primary_name_attribute` — but none of them applied the target entity's
//! own record-level predicate before this fix:
//! `entity_crud::response::resolve_lookup_meta` (single-record reads),
//! `query_exec::attach_lookup_display_names` (list/grid reads), and
//! `attome_document::documents_tree::resolve_record_display_names` (the
//! Documents browser's polymorphic `entity_name`/`record_id` grouping). A
//! caller could read another team's record's name — sometimes its whole
//! `primary_name_attribute` value, e.g. a customer's legal name — merely by
//! having a lookup field that pointed at it, with no read grant on the
//! target entity at all.
//!
//! This module is the one place that batch now goes through:
//! [`resolve_visible`] resolves the caller's own `(target_entity_id, Read)`
//! access level once per target entity and splices `attome_security::rls_predicate`
//! into the same `WHERE id = ANY($1)` query, so an id the predicate excludes
//! simply isn't in the returned map — indistinguishable from an id that
//! doesn't exist at all. Callers render anything missing from the map as
//! `{id, name: null, exists: false}` (additive field, D-077/D-140's existing
//! `{exists, is_active, name}` shape).

use std::collections::HashMap;

use attome_core::{EngineState, quote_ident};
use attome_security::RecordAction;
use attome_server::security::SecurityContext;
use uuid::Uuid;

/// One target row's resolved visibility + display name. Absent from
/// [`resolve_visible`]'s returned map for an id that either doesn't exist at
/// all, or exists but this caller's RLS on the target entity excludes it —
/// deliberately the same outcome for both: telling the two apart would let a
/// caller probe for a record's existence through a lookup field it has no
/// read grant on.
pub struct ResolvedLookup {
    /// Whether the referenced record row still exists at all — always
    /// `true` for an entry present in the map (an invisible/missing id is
    /// simply not in the map; see the module doc comment).
    pub exists: bool,
    /// Whether it exists *and* is live (not soft-deleted/deactivated).
    pub is_active: bool,
    /// The target's `primary_name_attribute` value, when it declares one.
    pub name: Option<String>,
}

impl std::fmt::Debug for ResolvedLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedLookup").finish_non_exhaustive()
    }
}

/// Batches `ids` — every value one lookup/polymorphic-reference field on a
/// row (or a page of rows) is pointing at, for a single distinct
/// `target_entity_id` — into one `WHERE id = ANY($1)` query against that
/// target's table, with the caller's own `(target_entity_id, Read)`
/// `attome_security::rls_predicate` spliced in.
///
/// Resolves `access_level` once per call (callers already batch by distinct
/// target entity, so this is "once per target entity" as the fix requires,
/// not once per row/field). Returns an empty map — never an error — for an
/// unknown `target_entity_id` or a query failure: display-name resolution is
/// a data-hygiene concern, not this read's authorization boundary (that
/// boundary is whatever already gated the *caller's own* row read, upstream
/// of this), so a failure here must degrade to "no name," not fail the
/// request.
pub async fn resolve_visible(
    state: &EngineState,
    ctx: &SecurityContext,
    target_entity_id: Uuid,
    ids: &[Uuid],
) -> HashMap<Uuid, ResolvedLookup> {
    if ids.is_empty() {
        return HashMap::new();
    }

    let cached = {
        let registry = state.entities.load();
        registry
            .get_by_id(target_entity_id)
            .map(|m| (m.logicalname.clone(), m.primary_name_attribute.clone()))
    };
    // A target entity created moments ago can still be missing from this
    // node's registry; read its name from `entity_info` rather than report
    // every record of it as missing.
    let found = match cached {
        Some(found) => Some(found),
        None => sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT logicalname, primary_name_attribute FROM entity_info \
             WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(target_entity_id)
        .fetch_optional(&state.base.db)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "lookup-name target entity unreadable");
            None
        }),
    };
    let Some((target_table, name_attr)) = found else {
        return HashMap::new();
    };

    let access_level = match attome_security::resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        target_entity_id,
        &target_table,
        RecordAction::Read,
    )
    .await
    {
        Ok(level) => level,
        Err(e) => {
            tracing::warn!(
                error = %e, target_entity = %target_table,
                "lookup-name access-level resolution failed, omitting this target's ids"
            );
            return HashMap::new();
        }
    };

    // `table_alias: ""` — the query below is a bare `FROM {table}`, no
    // alias, so the predicate's `id`/`is_active` references must stay
    // unqualified too (see `rls_predicate`'s doc comment on `table_alias`).
    let pred = attome_security::rls_predicate(
        ctx,
        target_entity_id,
        "",
        access_level,
        RecordAction::Read.share_capability(),
        2,
    );

    let target_table_q = quote_ident(&target_table);
    let name_expr = match &name_attr {
        Some(col) => format!("{}::text", quote_ident(col)),
        None => "NULL::text".to_owned(),
    };
    let predicate = pred.as_ref().map_or("", |p| p.sql.as_str());
    let sql = format!(
        "SELECT id, (is_active IS NULL OR is_active = TRUE) AS is_live, {name_expr} AS display_name \
         FROM {target_table_q} WHERE id = ANY($1) {predicate}"
    );

    let mut query = sqlx::query_as::<_, (Uuid, bool, Option<String>)>(&sql).bind(ids);
    if let Some(p) = &pred {
        query = query
            .bind(p.binds.entity_ref)
            .bind(p.binds.caller_id)
            .bind(&p.binds.team_ids)
            .bind(p.binds.capability)
            .bind(&p.binds.accessible_org_ids)
            .bind(&p.binds.subordinate_user_ids);
    }

    match query.fetch_all(&state.base.db).await {
        Ok(rows) => rows
            .into_iter()
            .map(|(id, is_active, name)| {
                (
                    id,
                    ResolvedLookup {
                        exists: true,
                        is_active,
                        name,
                    },
                )
            })
            .collect(),
        Err(e) => {
            tracing::warn!(
                error = %e, target_entity = %target_table,
                "lookup-name resolution failed, omitting this target's ids"
            );
            HashMap::new()
        }
    }
}
