//! The accountability report's coverage, scorecard and evidence (roadmap
//! L3-T6), read only, for compliance administrators:
//!
//! - `GET /api/v1/admin/governance/coverage`: where accountability has gaps:
//!   live entities in no domain, domains with no owner (L3-T2's `owner`
//!   role), personal attributes on entities whose domain has no policy,
//!   policies with nothing enforcing them, and stewards whose domains have
//!   items overdue in the steward inbox (L3-T3, older than
//!   `steward_inbox::OVERDUE_DAYS`).
//! - `GET /api/v1/admin/governance/domains/{id}/scorecard`: one domain's L2
//!   quality (the newest score per entity and dimension, averaged), its open
//!   and overdue inbox items, its policy exceptions and its policy coverage.
//! - `GET /api/v1/admin/governance/evidence`: the roles, policies with their
//!   enforcements, exceptions and governed-change approvals, as one JSON
//!   document for an audit (R10).
//!
//! Each list is capped at [`MAX_ROWS`]; `truncated` says when a list was cut.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::steward_inbox::{OVERDUE_DAYS, providers};

/// The most rows one list carries.
pub const MAX_ROWS: i64 = 500;

/// A domain named in a report.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct DomainRef {
    pub id: Uuid,
    pub name: String,
}

/// A personal attribute whose domain has no policy.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct UncoveredAttribute {
    pub entity: String,
    pub attribute: String,
    /// `personal` or `sensitive_special_category`.
    pub classification: String,
}

/// A policy nothing enforces.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct UnenforcedPolicy {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub name: String,
}

/// A steward with overdue inbox items in their domains.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct OverdueSteward {
    pub user_id: Uuid,
    pub overdue_items: i64,
}

/// Where accountability has gaps.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Coverage {
    pub entities_without_domain: Vec<String>,
    pub domains_without_owner: Vec<DomainRef>,
    pub personal_attributes_without_policy: Vec<UncoveredAttribute>,
    pub policies_without_enforcement: Vec<UnenforcedPolicy>,
    pub stewards_with_overdue_items: Vec<OverdueSteward>,
    /// True when a list was cut at [`MAX_ROWS`].
    pub truncated: bool,
}

fn cut<T>(mut rows: Vec<T>, truncated: &mut bool) -> Vec<T> {
    if rows.len() > usize::try_from(MAX_ROWS).unwrap_or(usize::MAX) {
        rows.truncate(usize::try_from(MAX_ROWS).unwrap_or(usize::MAX));
        *truncated = true;
    }
    rows
}

/// The inbox items of the domain `$1` names, as one `SELECT` (L3-T3's
/// providers over the domain's entities), or `None` when no provider has
/// rows. Pure.
fn domain_items_sql() -> Option<String> {
    let all = providers();
    let selects: Vec<&str> = all.iter().filter_map(|p| p.select()).collect();
    (!selects.is_empty()).then(|| selects.join(" UNION ALL "))
}

/// The entities of domain `domain`.
async fn domain_entities(db: &sqlx::PgPool, domain: Uuid) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        "SELECT logicalname FROM entity_info \
          WHERE domain_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY logicalname",
    )
    .bind(domain)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Accountability coverage and gaps
///
/// L3-T6: live entities in no domain, domains with no owner, personal attributes whose domain has no
/// policy, policies nothing enforces, and stewards with inbox items overdue by more than two days.
/// Each list holds at most 500 rows (`truncated` says when one was cut). Compliance administrators.
#[utoipa::path(
    get,
    path = "/api/v1/admin/governance/coverage",
    operation_id = "get_governance_coverage",
    tag = "admin",
    responses(
        (status = 200, description = "Success", body = Coverage),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn coverage(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Compliance>>,
) -> Result<Json<Coverage>, AppError> {
    let db = &state.base.db;
    let mut truncated = false;
    let entities_without_domain: Vec<String> = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info \
          WHERE domain_ref IS NULL AND (is_active IS NULL OR is_active = true) \
          ORDER BY logicalname LIMIT $1",
    )
    .bind(MAX_ROWS + 1)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let domains_without_owner: Vec<DomainRef> = sqlx::query_as(
        "SELECT d.id, d.name FROM data_domain d \
          WHERE d.is_deleted = false \
            AND NOT EXISTS (SELECT 1 FROM governance_role r \
                             WHERE r.domain_ref = d.id AND r.role = 'owner') \
          ORDER BY d.name LIMIT $1",
    )
    .bind(MAX_ROWS + 1)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let personal_attributes_without_policy: Vec<UncoveredAttribute> = sqlx::query_as(
        "SELECT e.logicalname AS entity, a.logicalname AS attribute, \
                a.data_classification::text AS classification \
           FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
          WHERE a.data_classification IN ('personal', 'sensitive_special_category') \
            AND (a.is_active IS NULL OR a.is_active = true) \
            AND (e.is_active IS NULL OR e.is_active = true) \
            AND NOT EXISTS (SELECT 1 FROM governance_policy p WHERE p.domain_ref = e.domain_ref) \
          ORDER BY e.logicalname, a.logicalname LIMIT $1",
    )
    .bind(MAX_ROWS + 1)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let policies_without_enforcement: Vec<UnenforcedPolicy> = sqlx::query_as(
        "SELECT p.id, p.domain_ref AS domain_id, p.name_en AS name FROM governance_policy p \
          WHERE NOT EXISTS (SELECT 1 FROM governance_policy_enforcement f \
                             WHERE f.policy_id = p.id) \
          ORDER BY p.name_en, p.id LIMIT $1",
    )
    .bind(MAX_ROWS + 1)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let stewards_with_overdue_items: Vec<OverdueSteward> = match domain_items_sql() {
        Some(items) => sqlx::query_as(&format!(
            "WITH overdue AS ( \
                 SELECT i.entity FROM ({items}) i \
                  WHERE i.due_at < now() - make_interval(days => $2::int)) \
             SELECT d.steward_ref AS user_id, count(*) AS overdue_items \
               FROM overdue o JOIN entity_info e ON e.logicalname = o.entity \
               JOIN data_domain d ON d.id = e.domain_ref \
              WHERE d.is_deleted = false AND d.steward_ref IS NOT NULL \
              GROUP BY d.steward_ref ORDER BY overdue_items DESC, d.steward_ref LIMIT $3",
        ))
        .bind(
            sqlx::query_scalar::<_, String>(
                "SELECT logicalname FROM entity_info WHERE domain_ref IS NOT NULL",
            )
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?,
        )
        .bind(OVERDUE_DAYS)
        .bind(MAX_ROWS + 1)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?,
        None => Vec::new(),
    };
    Ok(Json(Coverage {
        entities_without_domain: cut(entities_without_domain, &mut truncated),
        domains_without_owner: cut(domains_without_owner, &mut truncated),
        personal_attributes_without_policy: cut(personal_attributes_without_policy, &mut truncated),
        policies_without_enforcement: cut(policies_without_enforcement, &mut truncated),
        stewards_with_overdue_items: cut(stewards_with_overdue_items, &mut truncated),
        truncated,
    }))
}

/// One entity's newest quality score in a dimension.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct QualityLine {
    pub entity: String,
    pub dimension: String,
    /// 0 to 100.
    pub score: f64,
    pub computed_at: DateTime<Utc>,
}

/// One domain's scorecard.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Scorecard {
    pub domain: DomainRef,
    /// L2: the newest score per entity and dimension.
    pub quality: Vec<QualityLine>,
    /// Their average; none while no entity of the domain has been scored.
    pub quality_average: Option<f64>,
    /// Steward inbox items open in the domain, and how many are overdue.
    pub open_items: i64,
    pub overdue_items: i64,
    /// Policy exceptions requested or approved and not expired.
    pub open_exceptions: i64,
    pub policies: i64,
    /// Policies with at least one enforcement.
    pub enforced_policies: i64,
}

/// A data domain's scorecard
///
/// L3-T6: the domain's L2 quality (the newest score per entity and dimension, and their average), its
/// open and overdue steward inbox items, its open policy exceptions and how many of its policies are
/// enforced. Compliance administrators.
#[utoipa::path(
    get,
    path = "/api/v1/admin/governance/domains/{id}/scorecard",
    operation_id = "get_governance_domain_scorecard",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The domain")),
    responses(
        (status = 200, description = "Success", body = Scorecard),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such domain", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn scorecard(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Scorecard>, AppError> {
    let db = &state.base.db;
    let domain: DomainRef =
        sqlx::query_as("SELECT id, name FROM data_domain WHERE id = $1 AND is_deleted = false")
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?;
    let entities = domain_entities(db, id).await?;
    let quality: Vec<QualityLine> = sqlx::query_as(
        "SELECT DISTINCT ON (entity_logicalname, dimension) \
                entity_logicalname AS entity, dimension, score::float8 AS score, computed_at \
           FROM quality_score WHERE entity_logicalname = ANY($1) \
          ORDER BY entity_logicalname, dimension, computed_at DESC",
    )
    .bind(&entities)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let quality_average = (!quality.is_empty()).then(|| {
        quality.iter().map(|q| q.score).sum::<f64>()
            / f64::from(u32::try_from(quality.len()).unwrap_or(u32::MAX))
    });
    let (open_items, overdue_items): (i64, i64) = match domain_items_sql() {
        Some(items) => sqlx::query_as(&format!(
            "SELECT count(*), count(*) FILTER (WHERE due_at < now() - make_interval(days => $2::int)) \
               FROM ({items}) i",
        ))
        .bind(&entities)
        .bind(OVERDUE_DAYS)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?,
        None => (0, 0),
    };
    let (policies, enforced_policies, open_exceptions): (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), \
                count(*) FILTER (WHERE EXISTS (SELECT 1 FROM governance_policy_enforcement f \
                                                WHERE f.policy_id = p.id)), \
                (SELECT count(*) FROM governance_policy_exception x \
                   JOIN governance_policy q ON q.id = x.policy_id \
                  WHERE q.domain_ref = $1 AND x.status IN ('requested', 'approved') \
                    AND (x.expires_at IS NULL OR x.expires_at > now())) \
           FROM governance_policy p WHERE p.domain_ref = $1",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(Scorecard {
        domain,
        quality,
        quality_average,
        open_items,
        overdue_items,
        open_exceptions,
        policies,
        enforced_policies,
    }))
}

/// The governance evidence for an audit.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Evidence {
    pub generated_at: DateTime<Utc>,
    /// `{domain_id, domain, user_id, role}`.
    #[schema(value_type = Vec<Object>)]
    pub roles: Vec<Value>,
    /// `{id, domain_id, name_en, name_ar, version, enforcements: [{kind, target_ref}]}`.
    #[schema(value_type = Vec<Object>)]
    pub policies: Vec<Value>,
    /// `{id, policy_id, target_ref, reason, status, approved_by, expires_at}`.
    #[schema(value_type = Vec<Object>)]
    pub exceptions: Vec<Value>,
    /// Governed-change approval requests: `{id, status, requested_by, requested_at}`.
    #[schema(value_type = Vec<Object>)]
    pub approvals: Vec<Value>,
}

/// Governance evidence
///
/// L3-T6: the governance roles, the policies with their enforcements, the policy exceptions and the
/// governed-change approval requests, as one JSON document for an audit (R10). Compliance
/// administrators.
#[utoipa::path(
    get,
    path = "/api/v1/admin/governance/evidence",
    operation_id = "get_governance_evidence",
    tag = "admin",
    responses(
        (status = 200, description = "Success", body = Evidence),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn evidence(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Compliance>>,
) -> Result<Json<Evidence>, AppError> {
    let db = &state.base.db;
    let rows = |sql: &'static str| async move {
        sqlx::query_scalar::<_, Value>(sql)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)
    };
    let roles = rows(
        "SELECT jsonb_build_object('domain_id', d.id, 'domain', d.name, 'user_id', r.user_id, \
                'role', r.role) \
           FROM governance_role r JOIN data_domain d ON d.id = r.domain_ref \
          WHERE d.is_deleted = false ORDER BY d.name, r.role, r.user_id LIMIT 5000",
    )
    .await?;
    let policies = rows(
        "SELECT jsonb_build_object('id', p.id, 'domain_id', p.domain_ref, 'name_en', p.name_en, \
                'name_ar', p.name_ar, 'version', p.version, 'enforcements', \
                COALESCE((SELECT jsonb_agg(jsonb_build_object('kind', f.kind, 'target_ref', f.target_ref) \
                                           ORDER BY f.kind, f.target_ref) \
                            FROM governance_policy_enforcement f WHERE f.policy_id = p.id), '[]'::jsonb)) \
           FROM governance_policy p ORDER BY p.name_en, p.id LIMIT 5000",
    )
    .await?;
    let exceptions = rows(
        "SELECT jsonb_build_object('id', x.id, 'policy_id', x.policy_id, 'target_ref', x.target_ref, \
                'reason', x.reason, 'status', x.status, 'approved_by', x.approved_by, \
                'expires_at', x.expires_at) \
           FROM governance_policy_exception x ORDER BY x.id LIMIT 5000",
    )
    .await?;
    let approvals = rows(
        "SELECT jsonb_build_object('id', a.id, 'status', a.status, 'requested_by', a.requested_by, \
                'requested_at', a.requested_at) \
           FROM approval_request a WHERE a.action_type LIKE 'governance%' \
          ORDER BY a.requested_at DESC LIMIT 5000",
    )
    .await?;
    Ok(Json(Evidence {
        generated_at: Utc::now(),
        roles,
        policies,
        exceptions,
        approvals,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/governance/coverage", get(coverage))
        .route(
            "/api/v1/admin/governance/domains/{id}/scorecard",
            get(scorecard),
        )
        .route("/api/v1/admin/governance/evidence", get(evidence))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(coverage, scorecard, evidence))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_past_the_cap_is_cut_and_says_so() {
        let mut truncated = false;
        let rows: Vec<i64> = (0..=MAX_ROWS).collect();
        let cut_rows = cut(rows, &mut truncated);
        assert_eq!(
            cut_rows.len(),
            usize::try_from(MAX_ROWS).expect("a small cap")
        );
        assert!(truncated);
        let mut fine = false;
        assert_eq!(cut(vec![1, 2], &mut fine).len(), 2);
        assert!(!fine);
        assert!(domain_items_sql().is_some_and(|s| s.contains("UNION ALL")));
    }
}
