//! F9-T3: deal registration — conflicts, decisions and lapse.
//!
//! A partner registers a deal as a `deal_registration` record (partner pack),
//! through the partner portal's create form (AC11-T2) or any record write;
//! it starts `submitted`.
//!
//! - **Intake** ([`intake_tick`], every minute): each `submitted`
//!   registration not yet checked is compared with the open opportunities on
//!   the same customer account and with the other live registrations
//!   (submitted, in conflict or approved) for the same customer — the same
//!   account, or the same name once Arabic spelling is folded
//!   ([`same_customer`]) — and the same product when both name one
//!   ([`find_conflicts`]). With any, it becomes `conflict` and
//!   `conflict_summary` names them; either way `checked_at` is set and the
//!   partner account's partner manager is told.
//! - **Decision** (`POST /api/v1/partner/registrations/{id}/decision`): a
//!   person with update access on the registration approves or rejects it.
//!   API keys and S2S clients are refused, so an agent or integration never
//!   decides. Approval runs under the customer's lock
//!   (`attome-partner/registration:{customer}`), refuses while another
//!   partner holds live protection for the same customer and product, sets
//!   `protection_ends_on` from the partner's tier (`protection_days`, else
//!   [`DEFAULT_PROTECTION_DAYS`]), and links the opportunity named or creates
//!   one on the customer account, naming the partner in
//!   `opportunity.partner_account_ref` — the field a partner portal role
//!   scopes opportunity reads by (partners reach deals through the portal,
//!   not through staff shares). A rejection keeps its reason.
//! - **Lapse** ([`lapse_tick`], daily): an approved registration whose
//!   protection has ended becomes `lapsed`, in batches of [`BATCH`], and its
//!   opportunity stops naming the partner unless the deal was won.
//!
//! Each decision and lapse writes a business event with the change.

use attome_audit::{AuditOperation, BusinessEvent, write_business_event_in_tx};
use attome_core::EngineState;
use attome_core::match_normalize::normalize_ar;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::support::{installed, lock, notify, partner_manager, person_only, require};

/// The registered intake job (every minute).
pub const INTAKE_JOB: &str = "partner_registration_intake";
/// The registered lapse job (daily).
pub const LAPSE_JOB: &str = "partner_registration_lapse";
/// Rows a tick handles per batch.
pub const BATCH: i64 = 500;
/// Protection when the partner has no tier, or its tier names none.
pub const DEFAULT_PROTECTION_DAYS: i64 = 90;
/// The most conflicts a registration lists.
const MAX_CONFLICTS: usize = 20;
const ENTITY: &str = "deal_registration";

/// What a registration conflicts with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Conflict {
    /// An open opportunity on the same customer account.
    Opportunity { id: Uuid, name: Option<String> },
    /// Another partner's live registration for the same customer.
    Registration {
        id: Uuid,
        status: String,
        customer_name: Option<String>,
    },
}

impl Conflict {
    /// One line for `conflict_summary`. Pure.
    pub fn line(&self) -> String {
        match self {
            Self::Opportunity { id, name } => {
                format!(
                    "open opportunity {} ({id})",
                    name.as_deref().unwrap_or("unnamed")
                )
            }
            Self::Registration {
                id,
                status,
                customer_name,
            } => format!(
                "{status} registration for {} ({id})",
                customer_name.as_deref().unwrap_or("the same customer")
            ),
        }
    }
}

/// Whether two customer names are the same customer once Arabic spelling,
/// diacritics, digits, case and spacing are folded. Blank names never
/// match. Pure.
pub fn same_customer(a: &str, b: &str) -> bool {
    let (a, b) = (normalize_ar(a), normalize_ar(b));
    !a.is_empty() && a == b
}

/// Whether two registrations are for the same product: either names none,
/// or both name the same one. Pure.
pub fn same_product(a: Option<Uuid>, b: Option<Uuid>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

/// The parts of a registration conflicts are found from.
#[derive(Debug, Clone, Default)]
pub struct Registration {
    pub id: Uuid,
    pub status: String,
    pub partner_account: Option<Uuid>,
    pub customer_account: Option<Uuid>,
    pub customer_name: Option<String>,
    pub product: Option<Uuid>,
    pub amount: Option<Value>,
    pub expected_close: Option<Value>,
    pub opportunity: Option<Uuid>,
}

fn uuid_of(row: &Value, field: &str) -> Option<Uuid> {
    row.get(field)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
}

impl Registration {
    /// From the record's JSON row. Pure.
    pub fn from_row(row: &Value) -> Option<Self> {
        Some(Self {
            id: uuid_of(row, "id")?,
            status: row
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("submitted")
                .to_owned(),
            partner_account: uuid_of(row, "partner_account_ref"),
            customer_account: uuid_of(row, "customer_account_ref"),
            customer_name: row
                .get("customer_name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            product: uuid_of(row, "product_ref"),
            amount: row.get("amount").filter(|v| !v.is_null()).cloned(),
            expected_close: row.get("expected_close").filter(|v| !v.is_null()).cloned(),
            opportunity: uuid_of(row, "opportunity_ref"),
        })
    }

    /// The key the customer's lock is taken on: the account, else the
    /// folded name. Pure.
    pub fn customer_key(&self) -> String {
        match self.customer_account {
            Some(account) => format!("account:{account}"),
            None => format!(
                "name:{}",
                normalize_ar(self.customer_name.as_deref().unwrap_or_default())
            ),
        }
    }
}

async fn read(db: &attome_db::DbPool, id: Uuid) -> Result<Option<Registration>, AppError> {
    let row: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(r) FROM deal_registration r \
          WHERE r.id = $1 AND (r.is_active IS NULL OR r.is_active = true)",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.as_ref().and_then(Registration::from_row))
}

/// Every conflict `registration` has: open opportunities on the same
/// customer account, and other partners' live registrations for the same
/// customer and product. At most [`MAX_CONFLICTS`].
pub async fn find_conflicts(
    conn: &mut sqlx::PgConnection,
    registration: &Registration,
) -> Result<Vec<Conflict>, AppError> {
    let mut out = Vec::new();
    if let Some(account) = registration.customer_account {
        let open: Vec<(Uuid, Option<String>)> = sqlx::query_as(
            "SELECT id, name FROM opportunity \
              WHERE account_ref = $1 AND (is_active IS NULL OR is_active = true) \
                AND (stage IS NULL OR stage NOT IN ('closed_won', 'closed_lost')) \
              ORDER BY id LIMIT 20",
        )
        .bind(account)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        out.extend(
            open.into_iter()
                .map(|(id, name)| Conflict::Opportunity { id, name }),
        );
    }
    // Candidates by account or product; the name fold runs here, in Rust.
    let others: Vec<(
        Uuid,
        String,
        Option<Uuid>,
        Option<String>,
        Option<Uuid>,
        Option<Uuid>,
    )> = sqlx::query_as(
        "SELECT id, status, customer_account_ref, customer_name, product_ref, partner_account_ref \
               FROM deal_registration \
              WHERE id <> $1 AND (is_active IS NULL OR is_active = true) \
                AND status IN ('submitted', 'conflict', 'approved') \
                AND (customer_account_ref = $2 OR $3::uuid IS NULL OR product_ref IS NULL \
                     OR product_ref = $3) \
              ORDER BY id LIMIT 500",
    )
    .bind(registration.id)
    .bind(registration.customer_account)
    .bind(registration.product)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    for (id, status, account, name, product, partner) in others {
        // The same partner registering twice is a duplicate, not a conflict.
        if partner.is_some() && partner == registration.partner_account {
            continue;
        }
        let same_account = account.is_some() && account == registration.customer_account;
        let same_name = match (&name, &registration.customer_name) {
            (Some(a), Some(b)) => same_customer(a, b),
            _ => false,
        };
        if (same_account || same_name) && same_product(product, registration.product) {
            out.push(Conflict::Registration {
                id,
                status,
                customer_name: name,
            });
        }
    }
    out.truncate(MAX_CONFLICTS);
    Ok(out)
}

/// `conflict_summary` for `conflicts`, one per line. Pure.
pub fn summary(conflicts: &[Conflict]) -> Option<String> {
    (!conflicts.is_empty()).then(|| {
        conflicts
            .iter()
            .map(Conflict::line)
            .collect::<Vec<_>>()
            .join("\n")
    })
}

async fn tell_manager(state: &EngineState, registration: &Registration, conflicts: &[Conflict]) {
    let Some(manager) = partner_manager(state, registration.partner_account).await else {
        return;
    };
    let customer = registration
        .customer_name
        .as_deref()
        .unwrap_or("a customer");
    let subject = if conflicts.is_empty() {
        format!("A partner registered a deal for {customer}")
    } else {
        format!("A partner registered a deal for {customer}, with conflicts")
    };
    notify(
        state,
        manager,
        subject,
        summary(conflicts).unwrap_or_else(|| "No conflicts found.".to_owned()),
        format!("/xrm/entity/{ENTITY}/{}", registration.id),
    )
    .await;
}

/// The intake job: checks new registrations for conflicts. Answers how many
/// were checked.
pub async fn intake_tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    if !installed(db, ENTITY, "checked_at").await? {
        return Ok(0);
    }
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(r) FROM deal_registration r \
          WHERE r.status = 'submitted' AND r.checked_at IS NULL \
            AND (r.is_active IS NULL OR r.is_active = true) \
          ORDER BY r.id LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut checked = 0;
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    for registration in rows.iter().filter_map(Registration::from_row) {
        let conflicts = find_conflicts(&mut conn, &registration).await?;
        let status = if conflicts.is_empty() {
            "submitted"
        } else {
            "conflict"
        };
        // Claimed once: a registration changed or checked meanwhile is left.
        let done = sqlx::query(
            "UPDATE deal_registration SET status = $2, conflict_summary = $3, checked_at = now(), \
                    modified_at = now(), row_version = row_version + 1 \
              WHERE id = $1 AND status = 'submitted' AND checked_at IS NULL",
        )
        .bind(registration.id)
        .bind(status)
        .bind(summary(&conflicts))
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        if done.rows_affected() == 1 {
            checked += 1;
            tell_manager(state, &registration, &conflicts).await;
        }
    }
    Ok(checked)
}

/// The lapse job: approved registrations past their protection become
/// `lapsed`. Answers how many lapsed.
pub async fn lapse_tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    if !installed(db, ENTITY, "checked_at").await? {
        return Ok(0);
    }
    let mut lapsed = 0;
    loop {
        let mut tx = attome_db::tx::begin(db).await?;
        let rows: Vec<(Uuid, Option<Uuid>, Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
            "UPDATE deal_registration r SET status = 'lapsed', modified_at = now(), \
                    row_version = r.row_version + 1 \
              WHERE r.id IN (SELECT id FROM deal_registration \
                              WHERE status = 'approved' AND protection_ends_on < now() \
                                AND (is_active IS NULL OR is_active = true) \
                              ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED) \
              RETURNING r.id, r.opportunity_ref, r.partner_account_ref, r.decided_by",
        )
        .bind(BATCH)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if rows.is_empty() {
            tx.commit().await.map_err(AppError::internal)?;
            break;
        }
        for (id, opportunity, partner, decided_by) in &rows {
            // The partner keeps a won deal; an open or lost one no longer names it.
            if let (Some(opportunity), Some(partner)) = (opportunity, partner) {
                sqlx::query(
                    "UPDATE opportunity SET partner_account_ref = NULL, modified_at = now(), \
                            row_version = row_version + 1 \
                      WHERE id = $1 AND partner_account_ref = $2 \
                        AND (stage IS NULL OR stage <> 'closed_won')",
                )
                .bind(opportunity)
                .bind(partner)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            }
            write_business_event_in_tx(
                &mut tx,
                &attome_audit::audit_service(state),
                BusinessEvent::new(
                    ENTITY,
                    *id,
                    AuditOperation::Update,
                    "partner.registration_lapsed",
                    decided_by.unwrap_or(Uuid::nil()),
                )
                .comment("protection ended"),
            )
            .await?;
        }
        tx.commit().await.map_err(AppError::internal)?;
        lapsed += rows.len() as u64;
    }
    Ok(lapsed)
}

/// A decision on a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Reject,
}

/// `POST /api/v1/partner/registrations/{id}/decision`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DecisionBody {
    pub decision: Decision,
    /// Approve: link this opportunity instead of creating one.
    #[serde(default)]
    pub opportunity_id: Option<Uuid>,
    /// Required to reject; kept on the registration either way.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The registration after a decision.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Decided {
    pub id: Uuid,
    /// `approved` or `rejected`.
    pub status: String,
    pub opportunity_id: Option<Uuid>,
    /// When the partner's protection ends (approved only).
    pub protection_ends_on: Option<chrono::DateTime<chrono::Utc>>,
}

/// The registration's conflicts, found now.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Conflicts {
    pub id: Uuid,
    pub conflicts: Vec<Conflict>,
}

/// Days of protection the partner's tier gives.
async fn protection_days(
    tx: &mut attome_db::Tx<'_>,
    partner: Option<Uuid>,
) -> Result<i64, AppError> {
    let Some(partner) = partner else {
        return Ok(DEFAULT_PROTECTION_DAYS);
    };
    let days: Option<Option<i64>> = sqlx::query_scalar(
        "SELECT (t.protection_days)::bigint FROM account a \
           JOIN partner_tier t ON t.id = a.partner_tier_ref WHERE a.id = $1",
    )
    .bind(partner)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(days
        .flatten()
        .filter(|d| *d > 0)
        .unwrap_or(DEFAULT_PROTECTION_DAYS))
}

/// Approves or rejects a registration as `ctx` (see the module doc).
pub async fn decide(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    body: DecisionBody,
) -> Result<Decided, AppError> {
    // A person decides: never an API key, an S2S client or an agent.
    person_only(ctx)?;
    require(state, ctx, ENTITY, id, RecordAction::Update).await?;
    let registration = read(&state.base.db, id).await?.ok_or(AppError::NotFound)?;
    if !matches!(registration.status.as_str(), "submitted" | "conflict") {
        return Err(AppError::Conflict("the registration is already decided"));
    }
    let reason = body
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(str::to_owned);
    let audit = attome_audit::audit_service(state);
    if body.decision == Decision::Reject {
        let reason =
            reason.ok_or_else(|| AppError::Validation("a rejection needs a reason".into()))?;
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let done = sqlx::query(
            "UPDATE deal_registration SET status = 'rejected', decision_reason = $2, \
                    decided_by = $3, modified_by = $3, modified_at = now(), \
                    row_version = row_version + 1 \
              WHERE id = $1 AND status IN ('submitted', 'conflict')",
        )
        .bind(id)
        .bind(&reason)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if done.rows_affected() != 1 {
            return Err(AppError::Conflict("the registration is already decided"));
        }
        write_business_event_in_tx(
            &mut tx,
            &audit,
            BusinessEvent::new(
                ENTITY,
                id,
                AuditOperation::Update,
                "partner.registration_rejected",
                ctx.user_id,
            )
            .comment(reason),
        )
        .await?;
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(Decided {
            id,
            status: "rejected".into(),
            opportunity_id: None,
            protection_ends_on: None,
        });
    }

    if let Some(opportunity) = body.opportunity_id {
        require(state, ctx, "opportunity", opportunity, RecordAction::Update).await?;
    } else if registration.customer_account.is_none() {
        return Err(AppError::Validation(
            "set the registration's customer account, or name the opportunity to link".into(),
        ));
    }

    // The claim: under the customer's lock, no other partner may hold live
    // protection for the same customer and product.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(
        &mut tx,
        format!(
            "attome-partner/registration:{}",
            registration.customer_key()
        ),
    )
    .await?;
    let held = find_conflicts(&mut tx, &registration)
        .await?
        .into_iter()
        .any(|c| matches!(&c, Conflict::Registration { status, .. } if status == "approved"));
    if held {
        return Err(AppError::Conflict(
            "another partner holds protection for this customer",
        ));
    }
    let days = protection_days(&mut tx, registration.partner_account).await?;
    let ends: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "UPDATE deal_registration SET status = 'approved', \
                protection_ends_on = now() + make_interval(days => $2::int), \
                decision_reason = $3, decided_by = $4, modified_by = $4, modified_at = now(), \
                row_version = row_version + 1 \
          WHERE id = $1 AND status IN ('submitted', 'conflict') RETURNING protection_ends_on",
    )
    .bind(id)
    .bind(i32::try_from(days).unwrap_or(90))
    .bind(&reason)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::Conflict("the registration is already decided"))?;
    tx.commit().await.map_err(AppError::internal)?;

    // The opportunity, through the record engine as the person deciding.
    let opportunity = match link_opportunity(state, ctx, &registration, body.opportunity_id).await {
        Ok(opportunity) => opportunity,
        Err(error) => {
            // Undo the claim so the registration can be decided again.
            let undo = sqlx::query(
                "UPDATE deal_registration SET status = $2, protection_ends_on = NULL, \
                        decided_by = NULL, modified_at = now(), row_version = row_version + 1 \
                  WHERE id = $1 AND status = 'approved' AND opportunity_ref IS NULL",
            )
            .bind(id)
            .bind(&registration.status)
            .execute(&state.base.db)
            .await;
            if let Err(undo) = undo {
                tracing::error!(registration = %id, %undo, "deal registration: approval not undone");
            }
            return Err(error);
        }
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "UPDATE deal_registration SET opportunity_ref = $2, modified_at = now(), \
                row_version = row_version + 1 WHERE id = $1",
    )
    .bind(id)
    .bind(opportunity)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_business_event_in_tx(
        &mut tx,
        &audit,
        BusinessEvent::new(
            ENTITY,
            id,
            AuditOperation::Update,
            "partner.registration_approved",
            ctx.user_id,
        )
        .comment(format!(
            "opportunity {opportunity}, protected for {days} days"
        )),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Decided {
        id,
        status: "approved".into(),
        opportunity_id: Some(opportunity),
        protection_ends_on: Some(ends),
    })
}

/// Names the partner on `existing`, or creates the customer's opportunity
/// from the registration.
async fn link_opportunity(
    state: &EngineState,
    ctx: &SecurityContext,
    registration: &Registration,
    existing: Option<Uuid>,
) -> Result<Uuid, AppError> {
    let partner = registration.partner_account.map(|p| p.to_string());
    if let Some(opportunity) = existing {
        let version: i64 = sqlx::query_scalar("SELECT row_version FROM opportunity WHERE id = $1")
            .bind(opportunity)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?;
        attome_records::entity_crud::update_record_for(
            state,
            ctx,
            ctx.user_id,
            "opportunity",
            opportunity,
            version,
            json!({ "partner_account_ref": partner }),
        )
        .await?;
        return Ok(opportunity);
    }
    let mut values = Map::new();
    let customer = registration
        .customer_name
        .clone()
        .unwrap_or_else(|| "Partner deal".to_owned());
    values.insert("name".into(), json!(format!("{customer} (registered)")));
    values.insert(
        "account_ref".into(),
        json!(registration.customer_account.map(|a| a.to_string())),
    );
    values.insert("stage".into(), json!("prospecting"));
    values.insert("partner_account_ref".into(), json!(partner));
    if let Some(amount) = &registration.amount {
        values.insert("amount".into(), amount.clone());
    }
    if let Some(close) = &registration.expected_close {
        values.insert("close_date".into(), close.clone());
    }
    attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "opportunity",
        Value::Object(values),
    )
    .await
    .map(|(id, _)| id)
}

/// A deal registration's conflicts
///
/// F9-T3: the open opportunities and other partners' live registrations this registration
/// conflicts with, found now. Needs read access on the registration.
#[utoipa::path(
    get,
    path = "/api/v1/partner/registrations/{id}/conflicts",
    operation_id = "partner_registration_conflicts",
    tag = "partner",
    params(("id" = Uuid, Path, description = "The deal registration")),
    responses(
        (status = 200, description = "The conflicts", body = Conflicts),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such registration the caller may read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_conflicts(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<Conflicts>, AppError> {
    require(&state, &ctx, ENTITY, id, RecordAction::Read).await?;
    let registration = read(&state.base.db, id).await?.ok_or(AppError::NotFound)?;
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let conflicts = find_conflicts(&mut conn, &registration).await?;
    Ok(Json(Conflicts { id, conflicts }))
}

/// Decide a deal registration
///
/// F9-T3: approve (link the opportunity named, or create one on the customer account, naming the
/// partner, with protection from the partner's tier) or reject (with a reason). A person with
/// update access on the registration decides; API keys and S2S clients are refused. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/partner/registrations/{id}/decision",
    operation_id = "partner_registration_decide",
    tag = "partner",
    params(("id" = Uuid, Path, description = "The deal registration")),
    request_body = DecisionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Decided", body = Decided),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not a person, or no update access", body = ErrorResponse),
        (status = 404, description = "No such registration the caller may read", body = ErrorResponse),
        (status = 409, description = "Already decided, or another partner holds protection", body = ErrorResponse),
        (status = 422, description = "A rejection without a reason, or no customer account to create the opportunity on", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(crate) async fn post_decision(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<DecisionBody>,
) -> Result<Json<Decided>, AppError> {
    decide(&state, &ctx, id, body).await.map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/partner/registrations/{id}/conflicts",
            get(get_conflicts),
        )
        .route(
            "/api/v1/partner/registrations/{id}/decision",
            post(post_decision),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_conflicts, post_decision),
    components(schemas(Conflict, Conflicts, Decision, DecisionBody, Decided))
)]
pub(crate) struct RegistrationApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arabic_name_variants_conflict() {
        assert!(same_customer("أحمد للتجارة", "احمد للتجارة"));
        assert!(same_customer("مؤسسة  الإبداع", "مؤسسه الابداع"));
        assert!(same_customer("Acme Trading", "acme  trading"));
        assert!(!same_customer("", " "));
        assert!(!same_customer("Acme", "Apex"));
    }

    #[test]
    fn different_product_no_conflict() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        assert!(!same_product(Some(a), Some(b)));
        assert!(same_product(Some(a), Some(a)));
        assert!(same_product(None, Some(b)));
    }

    #[test]
    fn a_registration_reads_from_its_row_and_keys_its_customer() {
        let account = Uuid::now_v7();
        let row = json!({ "id": Uuid::now_v7(), "status": "conflict", "customer_account_ref": account,
                          "customer_name": "أحمد", "amount": 1500, "expected_close": null });
        let r = Registration::from_row(&row).expect("a registration");
        assert_eq!(r.status, "conflict");
        assert_eq!(r.customer_key(), format!("account:{account}"));
        assert_eq!(r.amount, Some(json!(1500)));
        assert_eq!(r.expected_close, None);
        let by_name = Registration {
            customer_name: Some("أحمد".into()),
            ..Registration::default()
        };
        assert_eq!(
            by_name.customer_key(),
            format!("name:{}", normalize_ar("احمد"))
        );
        let conflicts = [Conflict::Opportunity {
            id: Uuid::nil(),
            name: Some("Big deal".into()),
        }];
        assert_eq!(
            summary(&conflicts).as_deref(),
            Some("open opportunity Big deal (00000000-0000-0000-0000-000000000000)")
        );
        assert_eq!(summary(&[]), None);
    }
}
