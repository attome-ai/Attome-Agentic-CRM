//! D23 org charts: buying committees and relationship maps.
//!
//! D23-T4: who a contact reports to. `contact.reports_to` (the solid line)
//! and `contact.dotted_line_ref` (the dotted line) are engine-managed: the
//! generic record API refuses them, and they change only through
//! `PUT /api/v1/sales/contacts/{id}/manager`, which checks that
//!
//! - the caller may update the contact and read the manager;
//! - the manager works at the contact's account, or at an account in the
//!   same group (the two accounts share the top of their
//!   `parent_account_ref` chain);
//! - the line forms no loop (the manager does not report, along the same
//!   kind of line, to the contact);
//!
//! and then writes through the records engine (`MutationMode::EngineManaged`),
//! so the row version, validation, audit and the change feed apply. The
//! answer names the previous manager, so the client undoes a change by
//! setting that one back.

/// D23-T5: the chart of an account or its group.
pub mod chart;
/// D23-T7: the buying committee and its coverage gaps.
pub mod committee;
/// D23-T8: people who leave.
pub mod movers;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, header::IF_MATCH},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

/// The longest chain walked, of accounts or of managers.
pub const MAX_DEPTH: usize = 32;

/// The two kinds of reporting line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManagerLine {
    Solid,
    Dotted,
}

impl ManagerLine {
    /// The contact field that holds this line.
    pub fn field(self) -> &'static str {
        match self {
            Self::Solid => "reports_to",
            Self::Dotted => "dotted_line_ref",
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesSetManagerBody {
    /// The new manager, or `null` to clear the line.
    pub manager_id: Option<Uuid>,
    /// `solid` (the default) or `dotted`.
    #[serde(default = "solid")]
    pub line: ManagerLine,
}

fn solid() -> ManagerLine {
    ManagerLine::Solid
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesManagerSet {
    pub contact_id: Uuid,
    pub line: ManagerLine,
    pub manager_id: Option<Uuid>,
    /// The manager before this change: set it back to undo.
    pub previous_manager_id: Option<Uuid>,
    pub row_version: i64,
}

/// A lookup's id from a record read. Pure.
fn lookup(data: &Value, field: &str) -> Option<Uuid> {
    match data.get(field)? {
        Value::String(s) => s.parse().ok(),
        Value::Object(o) => o.get("id")?.as_str()?.parse().ok(),
        _ => None,
    }
}

/// Whether setting `manager` over `contact` closes a loop, given each
/// contact's current manager on the same line (`manager_of`). Walks at most
/// [`MAX_DEPTH`] steps; a chain longer than that counts as a loop, so a bad
/// chain is refused rather than followed forever. Pure.
pub fn makes_loop(contact: Uuid, manager: Uuid, manager_of: impl Fn(Uuid) -> Option<Uuid>) -> bool {
    let mut current = Some(manager);
    for _ in 0..MAX_DEPTH {
        match current {
            None => return false,
            Some(id) if id == contact => return true,
            Some(id) => current = manager_of(id),
        }
    }
    current.is_some()
}

/// The top of an account's `parent_account_ref` chain (its group's root).
async fn group_root(state: &EngineState, account: Uuid) -> Result<Uuid, AppError> {
    let mut current = account;
    for _ in 0..MAX_DEPTH {
        let parent: Option<Option<Uuid>> = sqlx::query_scalar(
            "SELECT parent_account_ref FROM account \
              WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(current)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        match parent.flatten() {
            Some(next) if next != current => current = next,
            _ => return Ok(current),
        }
    }
    Ok(current)
}

/// The managers along `line` above `start`, for the loop check.
async fn chain(
    state: &EngineState,
    line: ManagerLine,
    start: Uuid,
) -> Result<Vec<(Uuid, Option<Uuid>)>, AppError> {
    let sql = match line {
        ManagerLine::Solid => "SELECT reports_to FROM contact WHERE id = $1",
        ManagerLine::Dotted => "SELECT dotted_line_ref FROM contact WHERE id = $1",
    };
    let mut out = Vec::new();
    let mut current = Some(start);
    while let Some(id) = current {
        if out.len() >= MAX_DEPTH || out.iter().any(|(seen, _)| *seen == id) {
            break;
        }
        let next: Option<Option<Uuid>> = sqlx::query_scalar(sql)
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        let next = next.flatten();
        out.push((id, next));
        current = next;
    }
    Ok(out)
}

/// Sets or clears one of a contact's reporting lines.
pub async fn set_manager(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    contact: Uuid,
    manager: Option<Uuid>,
    line: ManagerLine,
    if_match: i64,
) -> Result<SalesManagerSet, AppError> {
    ctx.require("contact", "update")?;
    let record = attome_records::entity_crud::read_record(state, ctx, "contact", contact).await?;
    let previous = lookup(record.data(), line.field());
    if let Some(manager) = manager {
        if manager == contact {
            return Err(AppError::Validation(
                "a contact cannot report to themselves".into(),
            ));
        }
        let boss = attome_records::entity_crud::read_record(state, ctx, "contact", manager).await?;
        let related = match (
            lookup(record.data(), "account_ref"),
            lookup(boss.data(), "account_ref"),
        ) {
            (Some(a), Some(b)) => {
                a == b || group_root(state, a).await? == group_root(state, b).await?
            }
            _ => false,
        };
        if !related {
            return Err(AppError::Validation(
                "the manager must work at the contact's account or in its group".into(),
            ));
        }
        let above = chain(state, line, manager).await?;
        let manager_of = |id: Uuid| above.iter().find(|(c, _)| *c == id).and_then(|(_, m)| *m);
        if makes_loop(contact, manager, manager_of) {
            return Err(AppError::Validation(
                "this manager already reports to the contact: the line would form a loop".into(),
            ));
        }
    }

    let (entity_id, _, attrs, _) =
        attome_records::entity_crud::resolve_entity(state, "contact").await?;
    let mut patch = Map::new();
    patch.insert(
        line.field().to_owned(),
        manager.map_or(Value::Null, |m| Value::String(m.to_string())),
    );
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = attome_records::entity_mutation::update_one_as(
        &mut tx,
        state,
        attome_records::entity_mutation::Principal::Staff(ctx),
        "contact",
        entity_id,
        contact,
        &attrs,
        &patch,
        Some(ctx.user_id),
        if_match,
        attome_records::entity_mutation::MutationMode::EngineManaged,
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "contact",
            contact,
            attome_audit::AuditOperation::Update,
            "sales.manager_set",
            ctx.user_id,
        )
        .comment(format!(
            "{}: {} -> {}",
            line.field(),
            previous.map_or_else(|| "none".to_owned(), |p| p.to_string()),
            manager.map_or_else(|| "none".to_owned(), |m| m.to_string()),
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    let row_version = result
        .new_row
        .as_ref()
        .and_then(|r| r.get("row_version"))
        .and_then(Value::as_i64)
        .unwrap_or(if_match + 1);
    Ok(SalesManagerSet {
        contact_id: contact,
        line,
        manager_id: manager,
        previous_manager_id: previous,
        row_version,
    })
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers.get(IF_MATCH).ok_or_else(|| {
        AppError::Validation("If-Match: \"<row_version>\" is required to change a manager".into())
    })?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

/// Sets who a contact reports to.
///
/// Sets or clears the contact's solid or dotted reporting line. The manager
/// must work at the contact's account or at an account in its group, and the
/// line may not form a loop. Send the contact's `row_version` in `If-Match`.
/// The answer names the previous manager, so setting it back undoes the
/// change.
#[utoipa::path(
    put,
    path = "/api/v1/sales/contacts/{id}/manager",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The contact"),
        ("If-Match" = String, Header, description = "The contact's row_version"),
    ),
    request_body = SalesSetManagerBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The line is set", body = SalesManagerSet),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update the contact", body = ErrorResponse),
        (status = 404, description = "No such contact or manager the caller may read", body = ErrorResponse),
        (status = 409, description = "The contact changed since it was read", body = ErrorResponse),
        (status = 422, description = "Unrelated account, a loop, or a missing If-Match", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn put_sales_contact_manager(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(contact): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<SalesSetManagerBody>,
) -> Result<Json<SalesManagerSet>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        set_manager(&state, &ctx, contact, body.manager_id, body.line, expected).await?,
    ))
}

/// Records that a contact left their company.
///
/// Marks the contact a former employee as of `left_on` (keeping the record
/// and its history) and lists the contacts who reported to them, for a new
/// manager. With `new_account_id`, also creates the person's contact at
/// that account (duplicate rules apply) and links the two with a `moved_to`
/// relationship. Send the contact's `row_version` in `If-Match`.
#[utoipa::path(
    post,
    path = "/api/v1/sales/contacts/{id}/left",
    operation_id = "post_sales_contact_left",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The contact who left"),
        ("If-Match" = String, Header, description = "The contact's row_version"),
    ),
    request_body = movers::SalesContactLeftBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Recorded; the reports to reassign are listed", body = movers::SalesContactLeft),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update the contact", body = ErrorResponse),
        (status = 404, description = "No such contact or account the caller may read", body = ErrorResponse),
        (status = 409, description = "The contact changed since it was read, or the new contact looks like a duplicate", body = ErrorResponse),
        (status = 422, description = "A missing If-Match or an invalid field", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_sales_contact_left(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(contact): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<movers::SalesContactLeftBody>,
) -> Result<Json<movers::SalesContactLeft>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        movers::mark_left(
            &state,
            &ctx,
            contact,
            body.left_on,
            body.new_account_id,
            expected,
        )
        .await?,
    ))
}

/// The org chart's options.
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SalesOrgChartQuery {
    /// The whole group: every account sharing the top of the parent chain.
    #[serde(default)]
    pub group: bool,
    /// Comma-separated contact ids whose collapsed branches to open.
    pub expand: Option<String>,
    /// The `next_cursor` of the previous call.
    pub cursor: Option<Uuid>,
}

/// An account's org chart.
///
/// The account's contacts (or its group's) that the caller may read, by
/// who they report to; a contact whose manager is missing or unreadable is
/// listed as unplaced. Branches deeper than three levels are collapsed to a
/// count unless named in `expand`; at most 500 contacts a call, the rest
/// through `cursor`.
#[utoipa::path(
    get,
    path = "/api/v1/sales/accounts/{id}/org-chart",
    operation_id = "get_sales_org_chart",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The account"),
        SalesOrgChartQuery,
    ),
    responses(
        (status = 200, description = "The chart", body = chart::OrgChart),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not read contacts", body = ErrorResponse),
        (status = 404, description = "No such account the caller may read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_sales_org_chart(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(account): Path<Uuid>,
    axum::extract::Query(q): axum::extract::Query<SalesOrgChartQuery>,
) -> Result<Json<chart::OrgChart>, AppError> {
    let expand: std::collections::HashSet<Uuid> = q
        .expand
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| Uuid::parse_str(s.trim()).ok())
        .take(200)
        .collect();
    Ok(Json(
        chart::account_chart(&state, &ctx, account, q.group, &expand, q.cursor).await?,
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        put_sales_contact_manager,
        post_sales_contact_left,
        get_sales_org_chart
    ),
    components(schemas(
        movers::SalesContactLeftBody,
        movers::SalesContactLeft,
        chart::OrgChart,
        chart::OrgNode,
        chart::ChartCompany
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> [Uuid; 4] {
        [
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        ]
    }

    #[test]
    fn a_chain_that_reaches_the_contact_is_a_loop() {
        let [a, b, c, d] = ids();
        // b -> c -> a: making b a's manager closes a -> b -> c -> a.
        let up = move |id: Uuid| match id {
            x if x == b => Some(c),
            x if x == c => Some(a),
            _ => None,
        };
        assert!(makes_loop(a, b, up));
        // d has no manager: no loop.
        assert!(!makes_loop(a, d, |_| None));
    }

    #[test]
    fn an_endless_chain_is_refused() {
        let [a, b, c, _] = ids();
        // b <-> c, never reaching a: refused once the walk runs out.
        let up = move |id: Uuid| if id == b { Some(c) } else { Some(b) };
        assert!(makes_loop(a, b, up));
    }

    #[test]
    fn lines_name_their_fields() {
        assert_eq!(ManagerLine::Solid.field(), "reports_to");
        assert_eq!(ManagerLine::Dotted.field(), "dotted_line_ref");
    }
}
