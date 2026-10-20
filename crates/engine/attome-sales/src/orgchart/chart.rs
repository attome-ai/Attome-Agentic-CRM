//! D23-T5: an account's org chart. One query reads the account's contacts
//! (or every account's in its group) with the caller's row-level predicate
//! applied, so only readable contacts take part; the tree is then built in
//! memory along `reports_to`. A contact whose manager is missing or not
//! readable is listed as unplaced, never shown under someone else.
//!
//! Branches deeper than [`VISIBLE_LEVELS`] are collapsed to a child count
//! unless their node is named in `expand`; a call reads at most
//! [`PAGE_LIMIT`] contacts (by id) and answers a cursor for the rest.
//!
//! Contacts have no Arabic name attribute yet, so a node carries
//! `full_name` only (its department has both languages).

use std::collections::{HashMap, HashSet};

use attome_core::EngineState;
use attome_security::{
    RecordAction, SecurityContextExt, bind_rls_predicate_as, resolve_entity_access_level,
    resolve_owner_visible, rls_predicate_with_conditions,
};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// Levels shown below a root before a branch collapses.
pub const VISIBLE_LEVELS: usize = 3;
/// Contacts read per call.
pub const PAGE_LIMIT: i64 = 500;
/// Accounts a group walk follows.
const MAX_GROUP_ACCOUNTS: i64 = 200;

/// One contact as the chart reads it.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct ContactRow {
    pub id: Uuid,
    pub full_name: Option<String>,
    pub job_title: Option<String>,
    pub department: Option<String>,
    pub department_ar: Option<String>,
    pub reports_to: Option<Uuid>,
    pub dotted_line_ref: Option<Uuid>,
    pub is_former_employee: Option<bool>,
    pub account_ref: Option<Uuid>,
}

/// One person on the chart.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct OrgNode {
    pub id: Uuid,
    pub full_name: Option<String>,
    pub job_title: Option<String>,
    pub department: Option<String>,
    pub department_ar: Option<String>,
    /// The company the person works at (several in a group chart).
    pub account_id: Option<Uuid>,
    pub dotted_line_id: Option<Uuid>,
    pub is_former_employee: bool,
    #[schema(no_recursion)]
    pub children: Vec<OrgNode>,
    /// When the branch is collapsed: how many people report to this one.
    pub collapsed_children: Option<usize>,
}

/// A company in a group chart.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct ChartCompany {
    pub id: Uuid,
    pub name: Option<String>,
}

/// An account's chart.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct OrgChart {
    pub roots: Vec<OrgNode>,
    /// Readable contacts whose manager is missing or not readable.
    pub unplaced: Vec<OrgNode>,
    /// The companies the chart covers (one unless it is a group chart).
    pub companies: Vec<ChartCompany>,
    /// More contacts follow: pass this as `cursor`.
    pub next_cursor: Option<Uuid>,
}

fn node(row: &ContactRow) -> OrgNode {
    OrgNode {
        id: row.id,
        full_name: row.full_name.clone(),
        job_title: row.job_title.clone(),
        department: row.department.clone(),
        department_ar: row.department_ar.clone(),
        account_id: row.account_ref,
        dotted_line_id: row.dotted_line_ref,
        is_former_employee: row.is_former_employee == Some(true),
        children: Vec::new(),
        collapsed_children: None,
    }
}

/// The tree from the readable contacts: roots (no manager), and unplaced
/// subtrees (a manager that is not among `rows`), each shown
/// [`VISIBLE_LEVELS`] deep unless a node is in `expand`. A loop in the
/// data never repeats a person. Pure.
pub fn build_tree(rows: &[ContactRow], expand: &HashSet<Uuid>) -> (Vec<OrgNode>, Vec<OrgNode>) {
    let by_id: HashMap<Uuid, &ContactRow> = rows.iter().map(|r| (r.id, r)).collect();
    let mut reports: HashMap<Uuid, Vec<&ContactRow>> = HashMap::new();
    for r in rows {
        if let Some(m) = r.reports_to.filter(|m| *m != r.id && by_id.contains_key(m)) {
            reports.entry(m).or_default().push(r);
        }
    }
    fn grow(
        row: &ContactRow,
        levels: usize,
        reports: &HashMap<Uuid, Vec<&ContactRow>>,
        expand: &HashSet<Uuid>,
        seen: &mut HashSet<Uuid>,
    ) -> OrgNode {
        let mut out = node(row);
        let below = reports.get(&row.id).map(Vec::as_slice).unwrap_or_default();
        if below.is_empty() {
            return out;
        }
        let levels = if expand.contains(&row.id) {
            VISIBLE_LEVELS
        } else {
            levels
        };
        if levels == 0 {
            out.collapsed_children = Some(below.len());
            return out;
        }
        for child in below {
            if seen.insert(child.id) {
                out.children
                    .push(grow(child, levels - 1, reports, expand, seen));
            }
        }
        out
    }
    let mut seen = HashSet::new();
    let mut roots = Vec::new();
    let mut unplaced = Vec::new();
    for r in rows {
        let placed_under = r.reports_to.filter(|m| *m != r.id);
        match placed_under {
            None => {
                if seen.insert(r.id) {
                    roots.push(grow(r, VISIBLE_LEVELS, &reports, expand, &mut seen));
                }
            }
            Some(m) if !by_id.contains_key(&m) => {
                if seen.insert(r.id) {
                    unplaced.push(grow(r, VISIBLE_LEVELS, &reports, expand, &mut seen));
                }
            }
            Some(_) => {}
        }
    }
    // Anyone left is in a loop with no way in: show them as unplaced.
    for r in rows {
        if seen.insert(r.id) {
            unplaced.push(grow(r, VISIBLE_LEVELS, &reports, expand, &mut seen));
        }
    }
    (roots, unplaced)
}

/// The accounts a chart covers: the account, or its whole group.
async fn accounts(
    state: &EngineState,
    account: Uuid,
    include_group: bool,
) -> Result<Vec<Uuid>, AppError> {
    if !include_group {
        return Ok(vec![account]);
    }
    let root = super::group_root(state, account).await?;
    sqlx::query_scalar(
        "WITH RECURSIVE g(id, depth) AS ( \
            SELECT id, 0 FROM account WHERE id = $1 AND (is_active IS NULL OR is_active = true) \
            UNION ALL \
            SELECT a.id, g.depth + 1 FROM account a JOIN g ON a.parent_account_ref = g.id \
             WHERE g.depth < 20 AND (a.is_active IS NULL OR a.is_active = true) \
         ) SELECT DISTINCT id FROM g LIMIT $2",
    )
    .bind(root)
    .bind(MAX_GROUP_ACCOUNTS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

const CHART_SELECT: &str = "SELECT t.id, t.full_name, t.job_title, t.department, t.department_ar, \
     t.reports_to, t.dotted_line_ref, t.is_former_employee, t.account_ref \
     FROM contact t \
     WHERE t.account_ref = ANY($1) AND (t.is_active IS NULL OR t.is_active = true) \
       AND ($2::uuid IS NULL OR t.id > $2)";

/// The account's chart as `ctx` may read it; see the module doc.
pub async fn account_chart(
    state: &EngineState,
    ctx: &SecurityContext,
    account: Uuid,
    include_group: bool,
    expand: &HashSet<Uuid>,
    cursor: Option<Uuid>,
) -> Result<OrgChart, AppError> {
    ctx.require("contact", "read")?;
    // The account itself must be readable.
    attome_records::entity_crud::read_record(state, ctx, "account", account).await?;
    let account_ids = accounts(state, account, include_group).await?;

    let (entity_id, entity_name, attrs, _) =
        attome_records::entity_crud::resolve_entity(state, "contact").await?;
    let access_level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        &entity_name,
        RecordAction::Read,
    )
    .await?;
    let owner_visible = resolve_owner_visible(
        &state.base.db,
        ctx.user_id,
        entity_id,
        &entity_name,
        RecordAction::Read,
    )
    .await?;
    let privilege_key = format!("{entity_name}.read");
    let rls = rls_predicate_with_conditions(
        ctx,
        entity_id,
        "t",
        access_level,
        RecordAction::Read.share_capability(),
        &privilege_key,
        &attrs,
        owner_visible,
        4,
    );
    let mut sql = String::from(CHART_SELECT);
    if let Some(pred) = &rls {
        sql.push(' ');
        sql.push_str(&pred.sql);
    }
    sql.push_str(" ORDER BY t.id LIMIT $3");
    let sql = attome_db::tag_dynamic("sales.org_chart", &sql);
    let mut q = sqlx::query_as::<_, ContactRow>(&sql)
        .bind(&account_ids)
        .bind(cursor)
        .bind(PAGE_LIMIT + 1);
    if let Some(pred) = &rls {
        if let Some(tb) = &pred.tier_binds {
            q = bind_rls_predicate_as(q, tb);
        }
        for bind in &pred.condition_binds {
            q = q.bind(bind);
        }
    }
    let pool = state.base.read_pool(ctx.user_id).await;
    let mut rows: Vec<ContactRow> = q.fetch_all(pool).await.map_err(AppError::internal)?;
    let next_cursor = if rows.len() as i64 > PAGE_LIMIT {
        rows.truncate(PAGE_LIMIT as usize);
        rows.last().map(|r| r.id)
    } else {
        None
    };
    let (roots, unplaced) = build_tree(&rows, expand);

    let mut companies = Vec::new();
    let mut named: HashSet<Uuid> = HashSet::new();
    for id in std::iter::once(account).chain(rows.iter().filter_map(|r| r.account_ref)) {
        if !named.insert(id) {
            continue;
        }
        if let Ok(record) =
            attome_records::entity_crud::read_record(state, ctx, "account", id).await
        {
            companies.push(ChartCompany {
                id,
                name: record
                    .data()
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
            });
        }
    }
    Ok(OrgChart {
        roots,
        unplaced,
        companies,
        next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(n: u128, manager: Option<u128>, account: u128) -> ContactRow {
        ContactRow {
            id: Uuid::from_u128(n),
            full_name: Some(format!("P{n}")),
            job_title: None,
            department: None,
            department_ar: None,
            reports_to: manager.map(Uuid::from_u128),
            dotted_line_ref: None,
            is_former_employee: None,
            account_ref: Some(Uuid::from_u128(account)),
        }
    }

    #[test]
    fn chart_hides_unreadable_contacts() {
        // 2 reports to 1; 3 reports to 9, whom the caller cannot read.
        let rows = vec![
            row(1, None, 100),
            row(2, Some(1), 100),
            row(3, Some(9), 100),
        ];
        let (roots, unplaced) = build_tree(&rows, &HashSet::new());
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].children[0].id, Uuid::from_u128(2));
        assert_eq!(unplaced.len(), 1);
        assert_eq!(unplaced[0].id, Uuid::from_u128(3));
        let all = |nodes: &[OrgNode]| nodes.iter().any(|n| n.id == Uuid::from_u128(9));
        assert!(
            !all(&roots) && !all(&unplaced),
            "the unreadable manager never appears"
        );
    }

    #[test]
    fn group_chart_marks_company() {
        let rows = vec![row(1, None, 100), row(2, Some(1), 200)];
        let (roots, _) = build_tree(&rows, &HashSet::new());
        assert_eq!(roots[0].account_id, Some(Uuid::from_u128(100)));
        assert_eq!(roots[0].children[0].account_id, Some(Uuid::from_u128(200)));
    }

    #[test]
    fn deep_branches_collapse_unless_expanded() {
        // A chain 1 <- 2 <- 3 <- 4 <- 5.
        let rows: Vec<ContactRow> = (1..=5)
            .map(|n| row(n, (n > 1).then(|| n - 1), 100))
            .collect();
        let (roots, _) = build_tree(&rows, &HashSet::new());
        let level3 = &roots[0].children[0].children[0].children[0];
        assert_eq!(level3.id, Uuid::from_u128(4));
        assert_eq!(level3.collapsed_children, Some(1));
        assert!(level3.children.is_empty());
        let expanded = HashSet::from([Uuid::from_u128(4)]);
        let (roots, _) = build_tree(&rows, &expanded);
        let level3 = &roots[0].children[0].children[0].children[0];
        assert_eq!(level3.children[0].id, Uuid::from_u128(5));
    }

    #[test]
    fn a_loop_is_shown_once_as_unplaced() {
        let rows = vec![row(1, Some(2), 100), row(2, Some(1), 100)];
        let (roots, unplaced) = build_tree(&rows, &HashSet::new());
        assert!(roots.is_empty());
        let count = unplaced.len() + unplaced.iter().map(|n| n.children.len()).sum::<usize>();
        assert_eq!(count, 2);
    }
}
