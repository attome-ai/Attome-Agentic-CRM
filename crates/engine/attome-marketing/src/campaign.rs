//! E1-T3: a campaign's members from a marketing list, and its members by
//! status.
//!
//! - `POST /api/v1/marketing/campaigns/{id}/members/from-list` queues the
//!   `campaign_members_from_list` job for one list. The job works out the
//!   list's people as the person who asked (`segment::evaluate`, so their
//!   record access applies), keeps at most [`MAX_MEMBERS`], skips people
//!   already members, and for a campaign whose type is a marketing type
//!   ([`CONSENT_TYPES`]) skips people without a current `granted` consent
//!   for the purpose. Each member is created through the generic record
//!   path (`create_record_for`) with status `targeted`, so validation,
//!   audit and the change feed apply. A retry adds only who is still
//!   missing.
//! - `GET /api/v1/marketing/campaigns/{id}/members/summary` counts the
//!   campaign's live members by status.
//!
//! Campaigns and members are the marketing package's entities (`campaign`,
//! `campaign_member`); without them both routes answer 404.

use std::collections::{BTreeMap, HashSet};

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The job that adds a list's people to a campaign.
pub const MEMBERS_JOB: &str = "campaign_members_from_list";
/// Most people one request adds.
pub const MAX_MEMBERS: usize = 50_000;
/// Campaign types that reach people with marketing, so need their consent.
pub const CONSENT_TYPES: &[&str] = &["email", "social", "advertising", "content"];
/// The status a new member starts in.
pub const FIRST_STATUS: &str = "targeted";

/// Whether adding people to a campaign of this type needs their consent.
pub fn needs_consent(campaign_type: Option<&str>) -> bool {
    campaign_type.is_some_and(|t| CONSENT_TYPES.contains(&t))
}

/// What one run adds, in id order, and what it skips. Pure.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MemberPlan {
    pub add: Vec<Uuid>,
    /// Already members of the campaign.
    pub skipped_existing: usize,
    /// No current consent for the purpose.
    pub skipped_no_consent: usize,
    /// Past [`MAX_MEMBERS`].
    pub skipped_over_limit: usize,
}

/// Plans a run: `consenting` is `None` when the campaign needs no consent.
pub fn plan_members(
    people: &HashSet<Uuid>,
    existing: &HashSet<Uuid>,
    consenting: Option<&HashSet<Uuid>>,
) -> MemberPlan {
    let mut ordered: Vec<Uuid> = people.iter().copied().collect();
    ordered.sort();
    let mut plan = MemberPlan::default();
    for id in ordered {
        if existing.contains(&id) {
            plan.skipped_existing += 1;
        } else if consenting.is_some_and(|c| !c.contains(&id)) {
            plan.skipped_no_consent += 1;
        } else if plan.add.len() >= MAX_MEMBERS {
            plan.skipped_over_limit += 1;
        } else {
            plan.add.push(id);
        }
    }
    plan
}

/// A campaign's members by status.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MemberSummary {
    pub total: i64,
    /// Count per status; a member without one counts under `none`.
    pub by_status: BTreeMap<String, i64>,
}

/// Rolls status counts up. Pure.
pub fn summarize(rows: Vec<(Option<String>, i64)>) -> MemberSummary {
    let mut summary = MemberSummary::default();
    for (status, count) in rows {
        summary.total += count;
        *summary
            .by_status
            .entry(status.unwrap_or_else(|| "none".to_owned()))
            .or_default() += count;
    }
    summary
}

fn package_installed(state: &EngineState) -> bool {
    let entities = state.entities.load();
    entities.get("campaign").is_some() && entities.get("campaign_member").is_some()
}

/// The campaign's type, when the caller may read the campaign.
async fn campaign_type(
    state: &EngineState,
    ctx: &SecurityContext,
    campaign: Uuid,
) -> Result<Option<String>, AppError> {
    if !package_installed(state)
        || !attome_records::entity_crud::referenced_record_visible(state, ctx, "campaign", campaign)
            .await?
    {
        return Err(AppError::NotFound);
    }
    sqlx::query_scalar(
        "SELECT campaign_type::text FROM campaign \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(campaign)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// The member lookup for a list's people: contacts or leads only.
async fn person_field(state: &EngineState, list: Uuid) -> Result<&'static str, AppError> {
    let target: String = sqlx::query_scalar(
        "SELECT COALESCE(target_entity, 'contact') FROM marketing_list \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(list)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    match target.as_str() {
        "contact" => Ok("contact_ref"),
        "lead" => Ok("lead_ref"),
        _ => Err(AppError::Validation(
            "campaign members are contacts or leads; this list holds other records".into(),
        )),
    }
}

/// Adding a list to a campaign.
#[derive(Debug, Deserialize, ToSchema)]
pub struct FromListBody {
    /// The marketing list whose people become members.
    pub list_id: Uuid,
    /// The consent purpose; required for an email, social, advertising or
    /// content campaign.
    #[serde(default)]
    pub purpose: Option<String>,
}

/// The queued job.
#[derive(Debug, Serialize, ToSchema)]
pub struct FromListQueued {
    pub campaign_id: Uuid,
    pub list_id: Uuid,
    /// Whether people without consent for the purpose are skipped.
    pub consent_checked: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobPayload {
    campaign: Uuid,
    list: Uuid,
    purpose: Option<String>,
    user: Uuid,
}

/// Checks the request and queues the job.
pub async fn queue_from_list(
    state: &EngineState,
    ctx: &SecurityContext,
    campaign: Uuid,
    body: &FromListBody,
) -> Result<FromListQueued, AppError> {
    ctx.require("campaign_member", "create")?;
    let kind = campaign_type(state, ctx, campaign).await?;
    if !attome_records::entity_crud::referenced_record_visible(
        state,
        ctx,
        "marketing_list",
        body.list_id,
    )
    .await?
    {
        return Err(AppError::NotFound);
    }
    person_field(state, body.list_id).await?;
    let purpose = body
        .purpose
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned);
    let consent_checked = needs_consent(kind.as_deref());
    if consent_checked && purpose.is_none() {
        return Err(AppError::Validation(
            "a consent purpose is required for this campaign type".into(),
        ));
    }
    let payload = JobPayload {
        campaign,
        list: body.list_id,
        purpose,
        user: ctx.user_id,
    };
    let job = attome_core::jobs::JOB_TYPES
        .job(MEMBERS_JOB, &json!(payload))
        .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(FromListQueued {
        campaign_id: campaign,
        list_id: body.list_id,
        consent_checked,
    })
}

/// The job: adds the list's people as the person who asked.
pub async fn run_from_list(
    state: &EngineState,
    payload: serde_json::Value,
) -> Result<MemberPlan, AppError> {
    let JobPayload {
        campaign,
        list,
        purpose,
        user,
    } = serde_json::from_value(payload).map_err(AppError::internal)?;
    let ctx = state.base.security.resolve(user).await?;
    ctx.require("campaign_member", "create")?;
    let kind = campaign_type(state, &ctx, campaign).await?;
    let field = person_field(state, list).await?;
    let entity = if field == "lead_ref" {
        "lead"
    } else {
        "contact"
    };
    let people = crate::segment::evaluate(state, &ctx, list, Vec::new()).await?;
    let ids: Vec<Uuid> = people.iter().copied().collect();

    let existing: HashSet<Uuid> = sqlx::query_scalar::<_, Uuid>(&format!(
        "SELECT {field} FROM campaign_member \
          WHERE campaign_ref = $1 AND {field} IS NOT NULL \
            AND (is_active IS NULL OR is_active = true)"
    ))
    .bind(campaign)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();

    let consenting: Option<HashSet<Uuid>> = if needs_consent(kind.as_deref()) {
        let purpose = purpose.ok_or_else(|| {
            AppError::Validation("a consent purpose is required for this campaign type".into())
        })?;
        Some(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT DISTINCT subject_id FROM consent_current \
                  WHERE subject_entity = $1 AND subject_id = ANY($2) \
                    AND purpose_key = $3 AND status = 'granted'",
            )
            .bind(entity)
            .bind(&ids)
            .bind(&purpose)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .collect(),
        )
    } else {
        None
    };

    let plan = plan_members(&people, &existing, consenting.as_ref());
    for person in &plan.add {
        attome_records::entity_crud::create_record_for(
            state,
            &ctx,
            user,
            "campaign_member",
            json!({ "campaign_ref": campaign, (field): person, "status": FIRST_STATUS }),
        )
        .await?;
    }
    tracing::info!(
        %campaign,
        %list,
        added = plan.add.len(),
        skipped_existing = plan.skipped_existing,
        skipped_no_consent = plan.skipped_no_consent,
        skipped_over_limit = plan.skipped_over_limit,
        "campaign members added from a list"
    );
    Ok(plan)
}

/// E8-T7: adds one person (a contact or a lead) to a campaign as `targeted`,
/// as `ctx`; `false` when they already are a member. A journey step calls
/// it, so no consent is checked here: messages check consent when they send.
pub async fn add_person(
    state: &EngineState,
    ctx: &SecurityContext,
    campaign: Uuid,
    person: Uuid,
) -> Result<bool, AppError> {
    ctx.require("campaign_member", "create")?;
    campaign_type(state, ctx, campaign).await?;
    let is_contact: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM contact WHERE id = $1 \
            AND (is_active IS NULL OR is_active = true))",
    )
    .bind(person)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let field = if is_contact {
        "contact_ref"
    } else {
        "lead_ref"
    };
    let existing: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM campaign_member WHERE campaign_ref = $1 AND {field} = $2 \
            AND (is_active IS NULL OR is_active = true))"
    ))
    .bind(campaign)
    .bind(person)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if existing {
        return Ok(false);
    }
    attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "campaign_member",
        json!({ "campaign_ref": campaign, (field): person, "status": FIRST_STATUS }),
    )
    .await?;
    Ok(true)
}

/// The campaign's live members by status.
pub async fn member_summary(
    state: &EngineState,
    ctx: &SecurityContext,
    campaign: Uuid,
) -> Result<MemberSummary, AppError> {
    ctx.require("campaign_member", "read")?;
    campaign_type(state, ctx, campaign).await?;
    let rows: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT status::text, count(*) FROM campaign_member \
          WHERE campaign_ref = $1 AND (is_active IS NULL OR is_active = true) \
          GROUP BY 1",
    )
    .bind(campaign)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(summarize(rows))
}

// ── Routes ───────────────────────────────────────────────────────────────────

/// `campaign_member.create`: adding members.
#[derive(Debug)]
pub struct MemberCreate;

impl PrivilegeKey for MemberCreate {
    const KEY: &'static str = "campaign_member.create";
}

/// `campaign_member.read`: counting members.
#[derive(Debug)]
pub struct MemberRead;

impl PrivilegeKey for MemberRead {
    const KEY: &'static str = "campaign_member.read";
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/campaigns/{id}/members/from-list",
    operation_id = "add_campaign_members_from_list",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The campaign")),
    request_body = FromListBody,
    responses(
        (status = 202, description = "The members are being added", body = FromListQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks campaign_member.create", body = ErrorResponse),
        (status = 404, description = "No such campaign or list, or the marketing package is not installed", body = ErrorResponse),
        (status = 422, description = "The list holds neither contacts nor leads, or the campaign type needs a consent purpose", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
/// Add a list's people to a campaign.
///
/// In the background: people already members are skipped, and for an
/// email, social, advertising or content campaign, so are people without a
/// current consent for the purpose. Each member is created as `targeted`.
async fn post_from_list(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MemberCreate>>,
    Path(campaign): Path<Uuid>,
    Json(body): Json<FromListBody>,
) -> Result<(StatusCode, Json<FromListQueued>), AppError> {
    let queued = queue_from_list(&state, &ctx, campaign, &body).await?;
    Ok((StatusCode::ACCEPTED, Json(queued)))
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/campaigns/{id}/members/summary",
    operation_id = "campaign_member_summary",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The campaign")),
    responses(
        (status = 200, description = "Members by status", body = MemberSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks campaign_member.read", body = ErrorResponse),
        (status = 404, description = "No such campaign, or the marketing package is not installed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// A campaign's members by status.
async fn get_summary(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MemberRead>>,
    Path(campaign): Path<Uuid>,
) -> Result<Json<MemberSummary>, AppError> {
    member_summary(&state, &ctx, campaign).await.map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/marketing/campaigns/{id}/members/from-list",
            post(post_from_list),
        )
        .route(
            "/api/v1/marketing/campaigns/{id}/members/summary",
            get(get_summary),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_from_list, get_summary),
    components(schemas(FromListBody, FromListQueued, MemberSummary, MemberPlan))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: usize) -> Vec<Uuid> {
        let mut v: Vec<Uuid> = (0..n).map(|_| Uuid::now_v7()).collect();
        v.sort();
        v
    }

    #[test]
    fn campaign_members_consent_only_for_marketing_types() {
        assert!(needs_consent(Some("email")));
        assert!(needs_consent(Some("advertising")));
        assert!(!needs_consent(Some("event")));
        assert!(!needs_consent(Some("webinar")));
        assert!(!needs_consent(None));
    }

    #[test]
    fn campaign_members_skip_existing_and_non_consented() {
        let p = ids(4);
        let people: HashSet<Uuid> = p.iter().copied().collect();
        let existing: HashSet<Uuid> = [p[0]].into();
        let consenting: HashSet<Uuid> = [p[0], p[1], p[3]].into();
        let plan = plan_members(&people, &existing, Some(&consenting));
        assert_eq!(plan.add, vec![p[1], p[3]]);
        assert_eq!(plan.skipped_existing, 1);
        assert_eq!(plan.skipped_no_consent, 1);
        assert_eq!(plan.skipped_over_limit, 0);

        // Without a consent check everyone missing is added.
        let plan = plan_members(&people, &existing, None);
        assert_eq!(plan.add, vec![p[1], p[2], p[3]]);
        assert_eq!(plan.skipped_no_consent, 0);
    }

    #[test]
    fn campaign_members_rerun_adds_nothing() {
        let p = ids(3);
        let people: HashSet<Uuid> = p.iter().copied().collect();
        let plan = plan_members(&people, &people, None);
        assert!(plan.add.is_empty());
        assert_eq!(plan.skipped_existing, 3);
    }

    #[test]
    fn campaign_members_summary_by_status() {
        let s = summarize(vec![
            (Some("targeted".into()), 5),
            (Some("responded".into()), 2),
            (None, 1),
        ]);
        assert_eq!(s.total, 8);
        assert_eq!(s.by_status["targeted"], 5);
        assert_eq!(s.by_status["responded"], 2);
        assert_eq!(s.by_status["none"], 1);
    }
}
