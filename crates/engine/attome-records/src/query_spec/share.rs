//! Saved queries shared with roles and teams (roadmap A14-T2). An
//! administrator shares a stored query with a role or a team, to `read` (run
//! it by id through `POST /api/v1/query/run`) or to `edit` (also change its
//! QuerySpec and parameters through `PATCH /api/v1/admin/queries/{id}/spec`).
//! A share admits the caller in place of the query's `required_privilege`;
//! it never widens what the query returns, because a saved QuerySpec is
//! compiled with the caller's own record and field security inside the SQL.
//!
//! The shares live in `sql_query_share` (migration 0275). They name this
//! deployment's roles and teams, so they are deployment state and never
//! travel in a changeset.

use std::collections::BTreeSet;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use super::saved::ParamDecl;

/// The most shares one query holds.
pub const MAX_SHARES: usize = 100;

/// What a share lets its holders do; `edit` includes `read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = QueryShareAccess)]
pub enum ShareAccess {
    Read,
    Edit,
}

impl ShareAccess {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Edit => "edit",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "edit" => Some(Self::Edit),
            _ => None,
        }
    }
}

/// Who a share is with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = QuerySharePrincipal)]
pub enum SharePrincipal {
    Role,
    Team,
}

impl SharePrincipal {
    fn code(self) -> i16 {
        match self {
            Self::Role => 0,
            Self::Team => 1,
        }
    }

    fn from_code(code: i16) -> Option<Self> {
        match code {
            0 => Some(Self::Role),
            1 => Some(Self::Team),
            _ => None,
        }
    }
}

/// One share of a stored query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryShare {
    pub principal_type: SharePrincipal,
    pub principal_id: Uuid,
    pub access: ShareAccess,
}

/// The whole share list of a query; it replaces the stored one.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PutQuerySharesBody {
    pub shares: Vec<QueryShare>,
}

/// A query's shares.
#[derive(Debug, Serialize, ToSchema)]
pub struct QuerySharesResponse {
    pub query_id: Uuid,
    pub shares: Vec<QueryShare>,
}

/// A stored query shared with the caller.
#[derive(Debug, Serialize, ToSchema)]
pub struct SharedQuery {
    pub id: Uuid,
    pub name: String,
    /// The most any of the caller's shares allows.
    pub access: ShareAccess,
    /// Whether it holds a QuerySpec, so `query/run` can run it by id.
    pub runnable: bool,
    pub parameters: Vec<ParamDecl>,
}

/// The caller's role and team ids, for matching shares.
fn principals(ctx: &SecurityContext) -> (Vec<Uuid>, Vec<Uuid>) {
    (
        ctx.role_ids.clone().unwrap_or_default(),
        ctx.team_ids.clone(),
    )
}

/// The predicate matching a share `s` to the role ids bound at `roles` and
/// the team ids bound at `teams` (placeholders such as `$2`).
fn share_match(roles: &str, teams: &str) -> String {
    format!(
        "((s.principal_type = 0 AND s.principal_id = ANY({roles}::uuid[])) \
         OR (s.principal_type = 1 AND s.principal_id = ANY({teams}::uuid[])))"
    )
}

/// The most `ctx` may do with stored query `query_id` through a share of one
/// of its roles or teams; `None` when no share reaches it.
pub async fn access_for(
    db: &DbPool,
    query_id: Uuid,
    ctx: &SecurityContext,
) -> Result<Option<ShareAccess>, AppError> {
    let (roles, teams) = principals(ctx);
    if roles.is_empty() && teams.is_empty() {
        return Ok(None);
    }
    let rows: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT s.access FROM sql_query_share s WHERE s.query_id = $1 AND {}",
        share_match("$2", "$3")
    ))
    .bind(query_id)
    .bind(&roles)
    .bind(&teams)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.iter().filter_map(|a| ShareAccess::parse(a.as_str())).max())
}

async fn query_is_live(db: &DbPool, query_id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sql_query \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(query_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

async fn load_shares(db: &DbPool, query_id: Uuid) -> Result<Vec<QueryShare>, AppError> {
    let rows: Vec<(i16, Uuid, String)> = sqlx::query_as(
        "SELECT principal_type, principal_id, access FROM sql_query_share \
          WHERE query_id = $1 ORDER BY principal_type, principal_id",
    )
    .bind(query_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    rows.into_iter()
        .map(|(kind, principal_id, access)| {
            Ok(QueryShare {
                principal_type: SharePrincipal::from_code(kind).ok_or_else(|| {
                    AppError::internal(format!("sql_query_share principal_type {kind}"))
                })?,
                principal_id,
                access: ShareAccess::parse(&access).ok_or_else(|| {
                    AppError::internal(format!("sql_query_share access {access}"))
                })?,
            })
        })
        .collect()
}

/// Checks a share list: within the cap and each principal at most once.
fn validate_shares(shares: &[QueryShare]) -> Result<(), AppError> {
    if shares.len() > MAX_SHARES {
        return Err(AppError::Validation(format!(
            "a query is shared with at most {MAX_SHARES} roles and teams"
        )));
    }
    let mut seen = BTreeSet::new();
    for share in shares {
        if !seen.insert((share.principal_type, share.principal_id)) {
            return Err(AppError::Validation(format!(
                "{} is listed twice",
                share.principal_id
            )));
        }
    }
    Ok(())
}

/// List a stored query's shares
///
/// A14-T2: the roles and teams a stored query is shared with. Administrators
/// only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/query-shares/{id}",
    tag = "admin",
    operation_id = "list_query_shares",
    params(("id" = Uuid, Path, description = "The stored query")),
    responses(
        (status = 200, description = "The query's shares", body = QuerySharesResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such stored query", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn list_query_shares(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(query_id): Path<Uuid>,
) -> Result<Json<QuerySharesResponse>, AppError> {
    if !query_is_live(&state.base.db, query_id).await? {
        return Err(AppError::NotFound);
    }
    Ok(Json(QuerySharesResponse {
        query_id,
        shares: load_shares(&state.base.db, query_id).await?,
    }))
}

/// Replace a stored query's shares
///
/// A14-T2: shares a stored query with roles and teams, to read (run it by id)
/// or to edit (also change its QuerySpec and parameters). The list replaces
/// the stored one; an empty list stops sharing. Administrators only; audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/query-shares/{id}",
    tag = "admin",
    operation_id = "put_query_shares",
    params(("id" = Uuid, Path, description = "The stored query")),
    request_body = PutQuerySharesBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The query's shares as stored", body = QuerySharesResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such stored query", body = ErrorResponse),
        (status = 422, description = "Too many shares, a principal listed twice, or a role or team that does not exist", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn put_query_shares(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(query_id): Path<Uuid>,
    Json(body): Json<PutQuerySharesBody>,
) -> Result<Json<QuerySharesResponse>, AppError> {
    validate_shares(&body.shares)?;
    let event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Update,
        ctx.user_id,
        "sql_query_share",
        Some(query_id),
    )
    .named("query.shares_set")
    .comment(format!("{} share(s)", body.shares.len()));
    let mut stx = SecurityTx::begin(&state, event).await?;

    // The query row lock serialises two replacements of the same list, and
    // finding no row is the 404.
    let locked: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sql_query \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(query_id)
    .fetch_optional(&mut *stx)
    .await
    .map_err(AppError::internal)?;
    if locked.is_none() {
        return Err(AppError::NotFound);
    }

    for share in &body.shares {
        let table = match share.principal_type {
            SharePrincipal::Role => "role",
            SharePrincipal::Team => "team",
        };
        let exists: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM {table} WHERE id = $1 AND is_deleted = false)"
        ))
        .bind(share.principal_id)
        .fetch_one(&mut *stx)
        .await
        .map_err(AppError::internal)?;
        if !exists {
            return Err(AppError::Validation(format!(
                "no {table} {}",
                share.principal_id
            )));
        }
    }

    sqlx::query("DELETE FROM sql_query_share WHERE query_id = $1")
        .bind(query_id)
        .execute(&mut *stx)
        .await
        .map_err(AppError::internal)?;
    for share in &body.shares {
        sqlx::query(
            "INSERT INTO sql_query_share \
                 (query_id, principal_type, principal_id, access, granted_by) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(query_id)
        .bind(share.principal_type.code())
        .bind(share.principal_id)
        .bind(share.access.as_str())
        .bind(ctx.user_id)
        .execute(&mut *stx)
        .await
        .map_err(AppError::internal)?;
    }
    stx.commit().await?;

    Ok(Json(QuerySharesResponse {
        query_id,
        shares: load_shares(&state.base.db, query_id).await?,
    }))
}

#[derive(sqlx::FromRow)]
struct SharedRow {
    id: Uuid,
    record_no: Option<String>,
    parameters: Option<Value>,
    runnable: bool,
    can_edit: bool,
}

/// List the stored queries shared with me
///
/// A14-T2: every live stored query shared with one of the caller's roles or
/// teams, with the access the shares give and the parameters a run takes.
#[utoipa::path(
    get,
    path = "/api/v1/queries/shared",
    tag = "query",
    operation_id = "list_shared_queries",
    params(OnePageQuery),
    responses(
        (status = 200, description = "The queries shared with the caller", body = PaginatedResponse<SharedQuery>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn list_shared_queries(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SharedQuery>>, AppError> {
    let window = query.window();
    let (roles, teams) = principals(&ctx);
    let live = "(q.is_active IS NULL OR q.is_active = true)";
    let matched = share_match("$1", "$2");
    let rows: Vec<SharedRow> = sqlx::query_as(&format!(
        "SELECT q.id, q.record_no, q.parameters, q.query_spec IS NOT NULL AS runnable, \
                bool_or(s.access = 'edit') AS can_edit \
           FROM sql_query_share s JOIN sql_query q ON q.id = s.query_id \
          WHERE {live} AND {matched} \
          GROUP BY q.id, q.record_no, q.parameters, q.query_spec \
          ORDER BY q.record_no NULLS LAST, q.id \
          LIMIT $3 OFFSET $4"
    ))
    .bind(&roles)
    .bind(&teams)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(DISTINCT q.id) \
           FROM sql_query_share s JOIN sql_query q ON q.id = s.query_id \
          WHERE {live} AND {matched}"
    ))
    .bind(&roles)
    .bind(&teams)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|r| {
            let parameters: Vec<ParamDecl> = match r.parameters {
                Some(p) => serde_json::from_value(p).map_err(|e| {
                    AppError::internal(format!("stored parameters of {}: {e}", r.id))
                })?,
                None => Vec::new(),
            };
            Ok(SharedQuery {
                id: r.id,
                name: r
                    .record_no
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "Unnamed Query".into()),
                access: if r.can_edit {
                    ShareAccess::Edit
                } else {
                    ShareAccess::Read
                },
                runnable: r.runnable,
                parameters,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/query-shares/{id}",
            get(list_query_shares).put(put_query_shares),
        )
        .route("/api/v1/queries/shared", get(list_shared_queries))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn share(kind: SharePrincipal, id: Uuid, access: ShareAccess) -> QueryShare {
        QueryShare {
            principal_type: kind,
            principal_id: id,
            access,
        }
    }

    #[test]
    fn a_principal_is_listed_once() {
        let role = Uuid::now_v7();
        let ok = [
            share(SharePrincipal::Role, role, ShareAccess::Read),
            share(SharePrincipal::Team, role, ShareAccess::Edit),
        ];
        assert!(
            validate_shares(&ok).is_ok(),
            "a role and a team are distinct"
        );
        let twice = [
            share(SharePrincipal::Role, role, ShareAccess::Read),
            share(SharePrincipal::Role, role, ShareAccess::Edit),
        ];
        assert!(validate_shares(&twice).is_err());
        let many: Vec<_> = (0..=MAX_SHARES)
            .map(|_| share(SharePrincipal::Team, Uuid::now_v7(), ShareAccess::Read))
            .collect();
        assert!(validate_shares(&many).is_err());
    }

    #[test]
    fn edit_is_the_wider_access() {
        assert!(ShareAccess::Edit > ShareAccess::Read);
        for access in [ShareAccess::Read, ShareAccess::Edit] {
            assert_eq!(ShareAccess::parse(access.as_str()), Some(access));
        }
        for kind in [SharePrincipal::Role, SharePrincipal::Team] {
            assert_eq!(SharePrincipal::from_code(kind.code()), Some(kind));
        }
        let body: PutQuerySharesBody = serde_json::from_value(json!({"shares": [
            {"principal_type": "team", "principal_id": Uuid::nil(), "access": "edit"}
        ]}))
        .unwrap();
        assert_eq!(body.shares[0].access, ShareAccess::Edit);
    }
}
