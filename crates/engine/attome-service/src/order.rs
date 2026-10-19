//! G3-T2: cart orders.
//!
//! An order is one work request (G2) with one `service_request_item` per
//! line. Each item whose offering `requires_approval` waits for its own
//! approval (Z10, action [`ACTION_SERVICE_ORDER_ITEM`]); an approved item,
//! or one that needs none, starts its fulfilment: the offering's
//! `fulfilment_plan` becomes `service_fulfilment_task` records, opened one
//! after another (`sequential`) or all at once (`parallel`). The ticket
//! sweep ([`advance_orders`]) opens the next task of a sequential plan when
//! the open one is done, marks an item fulfilled when all its tasks are, and
//! rejected when its approval was refused, withdrawn or expired.
//!
//! An order guide (`service_order_guide`) asks shared questions and adds its
//! offerings to the order, each line carrying the answers.

use attome_core::EngineState;
use attome_db::DbPool;
use attome_records::entity_mutation::{CreateStamp, MutationMode, Principal, create_one_as};
use attome_records::mutation_ring::MutationActor;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::WorkRequestCreate;
use crate::intake::{IntakeEntity, audit_entity_write};

/// The approval action an order item waits on.
pub const ACTION_SERVICE_ORDER_ITEM: &str = "service.order_item";
/// Most lines one order has.
pub const MAX_LINES: usize = 20;
/// Most tasks one fulfilment plan has.
pub const MAX_TASKS: usize = 20;
/// Most questions one order guide asks.
pub const MAX_QUESTIONS: usize = 20;

const ITEM: &str = "service_request_item";
const TASK: &str = "service_fulfilment_task";

/// How an offering's fulfilment tasks run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanMode {
    #[default]
    Sequential,
    Parallel,
}

impl PlanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequential => "sequential",
            Self::Parallel => "parallel",
        }
    }
}

/// One planned task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedTask {
    pub title: String,
}

/// An offering's fulfilment plan (`service_offering.fulfilment_plan`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FulfilmentPlan {
    #[serde(default)]
    pub mode: PlanMode,
    #[serde(default)]
    pub tasks: Vec<PlannedTask>,
}

/// An offering's plan, checked: at most [`MAX_TASKS`] tasks, each titled.
/// An empty or missing plan has no tasks. Pure.
pub fn parse_plan(raw: Option<&str>) -> Result<FulfilmentPlan, String> {
    let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(FulfilmentPlan::default());
    };
    let plan: FulfilmentPlan =
        serde_json::from_str(raw).map_err(|e| format!("fulfilment_plan is not valid: {e}"))?;
    if plan.tasks.len() > MAX_TASKS {
        return Err(format!("a fulfilment plan has at most {MAX_TASKS} tasks"));
    }
    if plan.tasks.iter().any(|t| t.title.trim().is_empty()) {
        return Err("every fulfilment task has a title".into());
    }
    Ok(plan)
}

/// The status each planned task starts in: the first open and the rest
/// pending for a sequential plan, all open for a parallel one. Pure.
pub fn initial_statuses(plan: &FulfilmentPlan) -> Vec<&'static str> {
    (0..plan.tasks.len())
        .map(|i| match plan.mode {
            PlanMode::Parallel => "open",
            PlanMode::Sequential if i == 0 => "open",
            PlanMode::Sequential => "pending",
        })
        .collect()
}

/// For a sequential item's tasks (sequence, status): the task to open next,
/// when none is open and one is pending. Pure.
pub fn next_to_open(tasks: &[(i64, String)]) -> Option<i64> {
    if tasks.iter().any(|(_, s)| s == "open") {
        return None;
    }
    tasks
        .iter()
        .filter(|(_, s)| s == "pending")
        .map(|(seq, _)| *seq)
        .min()
}

/// Whether an item's tasks are all finished. Pure.
pub fn all_finished(tasks: &[(i64, String)]) -> bool {
    tasks.iter().all(|(_, s)| s == "done" || s == "cancelled")
}

/// One question of an order guide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuideQuestion {
    pub key: String,
    pub label: String,
    #[serde(default)]
    pub required: bool,
}

/// An order guide's questions, checked. Pure.
pub fn parse_questions(raw: Option<&str>) -> Result<Vec<GuideQuestion>, String> {
    let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(Vec::new());
    };
    let questions: Vec<GuideQuestion> =
        serde_json::from_str(raw).map_err(|e| format!("questions are not valid: {e}"))?;
    if questions.len() > MAX_QUESTIONS {
        return Err(format!("a guide asks at most {MAX_QUESTIONS} questions"));
    }
    if let Some(bad) = questions
        .iter()
        .find(|q| q.key.is_empty() || !q.key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    {
        return Err(format!("question key `{}` is not a name", bad.key));
    }
    Ok(questions)
}

/// The required questions `answers` leaves empty. Pure.
pub fn unanswered<'a>(
    questions: &'a [GuideQuestion],
    answers: &Map<String, Value>,
) -> Vec<&'a str> {
    questions
        .iter()
        .filter(|q| q.required)
        .filter(|q| match answers.get(&q.key) {
            None | Some(Value::Null) => true,
            Some(Value::String(s)) => s.trim().is_empty(),
            Some(_) => false,
        })
        .map(|q| q.key.as_str())
        .collect()
}

/// One line of an order.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct OrderLine {
    pub offering_id: Uuid,
    #[serde(default = "one")]
    pub quantity: i64,
    /// Answers for this line's offering.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub answers: Map<String, Value>,
}

fn one() -> i64 {
    1
}

/// `POST /api/v1/service-orders`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PlaceOrderRequest {
    /// Who the order is for.
    pub requester_id: Uuid,
    /// The order's title; "Order of N items" when unset.
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub lines: Vec<OrderLine>,
    /// An order guide whose offerings join the order with `guide_answers`.
    #[serde(default)]
    pub guide_id: Option<Uuid>,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub guide_answers: Map<String, Value>,
}

/// One placed item.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PlacedItem {
    pub id: Uuid,
    pub offering_id: Uuid,
    /// `awaiting_approval`, `fulfilling` or `fulfilled`.
    pub status: String,
    pub approval_request_id: Option<Uuid>,
}

/// What an order placed.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrderPlaced {
    pub work_request_id: Uuid,
    pub reference: Option<String>,
    pub items: Vec<PlacedItem>,
}

#[derive(Debug, sqlx::FromRow)]
struct GuideRow {
    questions: Option<String>,
    offering_ids: Option<String>,
}

/// The lines an order guide adds, each carrying the shared answers.
async fn guide_lines(
    db: &DbPool,
    guide_id: Uuid,
    answers: &Map<String, Value>,
) -> Result<Vec<OrderLine>, AppError> {
    let guide: Option<GuideRow> = sqlx::query_as(
        "SELECT questions, offering_ids FROM service_order_guide \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(guide_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let guide = guide.ok_or_else(|| AppError::Validation("no such order guide".into()))?;
    let questions = parse_questions(guide.questions.as_deref()).map_err(AppError::Validation)?;
    let missing = unanswered(&questions, answers);
    if !missing.is_empty() {
        return Err(AppError::Validation(format!(
            "the order guide needs answers to: {}",
            missing.join(", ")
        )));
    }
    let offerings: Vec<Uuid> = serde_json::from_str(guide.offering_ids.as_deref().unwrap_or("[]"))
        .map_err(|e| {
            AppError::Validation(format!("the order guide's offering_ids are not valid: {e}"))
        })?;
    Ok(offerings
        .into_iter()
        .map(|offering_id| OrderLine {
            offering_id,
            quantity: 1,
            answers: answers.clone(),
        })
        .collect())
}

/// Places an order: one work request (through the offering path, filed on
/// the first line's offering) and one item per line, then each item's
/// approval or fulfilment.
pub async fn place_order(
    state: &EngineState,
    ctx: &SecurityContext,
    body: PlaceOrderRequest,
    ring: &attome_auth::PepperRing,
) -> Result<OrderPlaced, AppError> {
    let mut lines = body.lines;
    if let Some(guide_id) = body.guide_id {
        lines.extend(guide_lines(&state.base.db, guide_id, &body.guide_answers).await?);
    }
    if lines.is_empty() || lines.len() > MAX_LINES {
        return Err(AppError::Validation(format!(
            "an order has 1 to {MAX_LINES} lines"
        )));
    }
    if lines.iter().any(|l| !(1..=1000).contains(&l.quantity)) {
        return Err(AppError::Validation(
            "a line's quantity is 1 to 1000".into(),
        ));
    }
    ctx.require_key(&format!("{ITEM}.create"))?;
    ctx.require_key(&format!("{TASK}.create"))?;

    let title = body
        .title
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| format!("Order of {} items", lines.len()));
    let request = crate::offering::create_work_request_from_offering(
        state,
        ctx,
        lines[0].offering_id,
        crate::offering::CreateWorkRequestFromOfferingRequest {
            title,
            description: None,
            request_type: "custom".to_owned(),
            requester_id: body.requester_id,
            channel: None,
        },
        ring,
    )
    .await?;

    let item_entity = IntakeEntity::resolve(state, ITEM).await?;
    let actor = MutationActor::fetch(state, ctx.user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut created = Vec::with_capacity(lines.len());
    for line in &lines {
        let mut item = Map::new();
        item.insert(
            "work_request_ref".into(),
            Value::String(request.work_request_id.to_string()),
        );
        item.insert(
            "offering_ref".into(),
            Value::String(line.offering_id.to_string()),
        );
        item.insert("quantity".into(), Value::from(line.quantity));
        item.insert("status".into(), Value::String("awaiting_approval".into()));
        item.insert(
            "answers".into(),
            Value::String(Value::Object(line.answers.clone()).to_string()),
        );
        let result = create_one_as(
            &mut tx,
            state,
            Principal::Staff(ctx),
            &item_entity.name,
            &item_entity.attrs,
            &item,
            CreateStamp::staff(ctx.user_id, actor.org_ref),
            MutationMode::Strict,
        )
        .await?;
        audit_entity_write(
            &mut tx,
            state,
            &actor,
            &item_entity,
            &result,
            attome_audit::AuditOperation::Create,
            &item,
            "service_order.place",
        )
        .await?;
        created.push((result.record_id, line.offering_id));
    }
    attome_db::tx::commit(tx).await?;

    let mut items = Vec::with_capacity(created.len());
    for (item_id, offering_id) in created {
        let requires_approval: Option<bool> = sqlx::query_scalar(
            "SELECT coalesce(requires_approval, false) FROM service_offering WHERE id = $1",
        )
        .bind(offering_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if requires_approval == Some(true) {
            let approval = attome_audit::approval::gate_required(
                state,
                ACTION_SERVICE_ORDER_ITEM,
                json!({ "item_id": item_id }),
                ctx.user_id,
                true,
            )
            .await?;
            let approval_id = approval.map(|a| a.id);
            sqlx::query("UPDATE service_request_item SET approval_request_id = $2 WHERE id = $1")
                .bind(item_id)
                .bind(approval_id.map(|a| a.to_string()))
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            items.push(PlacedItem {
                id: item_id,
                offering_id,
                status: "awaiting_approval".into(),
                approval_request_id: approval_id,
            });
        } else {
            let status = start_fulfilment(&state.base.db, item_id).await?;
            items.push(PlacedItem {
                id: item_id,
                offering_id,
                status,
                approval_request_id: None,
            });
        }
    }
    Ok(OrderPlaced {
        work_request_id: request.work_request_id,
        reference: request.reference,
        items,
    })
}

/// Starts an item's fulfilment (it needed no approval, or was approved):
/// its offering's plan becomes tasks. Idempotent: an item already past
/// `awaiting_approval` is left alone. Returns the item's status.
pub async fn start_fulfilment(db: &DbPool, item_id: Uuid) -> Result<String, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT i.status, o.fulfilment_plan FROM service_request_item i \
           JOIN service_offering o ON o.id = i.offering_ref \
          WHERE i.id = $1 FOR UPDATE OF i",
    )
    .bind(item_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (status, plan) = row.ok_or(AppError::NotFound)?;
    if status != "awaiting_approval" {
        return Ok(status);
    }
    let plan = parse_plan(plan.as_deref()).map_err(AppError::Validation)?;
    let statuses = initial_statuses(&plan);
    for (index, (task, task_status)) in plan.tasks.iter().zip(statuses).enumerate() {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO service_fulfilment_task (id, item_ref, title, sequence, status) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(item_id)
        .bind(task.title.trim())
        .bind(i64::try_from(index + 1).unwrap_or(i64::MAX))
        .bind(task_status)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_core::change_feed::emit_tx(&mut tx, TASK, id, attome_core::ChangeOperation::Create)
            .await?;
    }
    let next = if plan.tasks.is_empty() {
        "fulfilled"
    } else {
        "fulfilling"
    };
    sqlx::query("UPDATE service_request_item SET status = $2, fulfilment_mode = $3 WHERE id = $1")
        .bind(item_id)
        .bind(next)
        .bind(plan.mode.as_str())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    attome_core::change_feed::emit_tx(&mut tx, ITEM, item_id, attome_core::ChangeOperation::Update)
        .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(next.to_owned())
}

/// The ticket sweep's order step: rejects items whose approval was refused,
/// withdrawn or expired; opens the next task of a sequential plan; marks
/// items fulfilled once all their tasks are. Returns how many items moved.
pub async fn advance_orders(db: &DbPool) -> Result<u64, AppError> {
    let provisioned: bool =
        sqlx::query_scalar("SELECT to_regclass('service_request_item') IS NOT NULL")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if !provisioned {
        return Ok(0);
    }
    let mut moved = sqlx::query(
        "UPDATE service_request_item i SET status = 'rejected' \
          WHERE i.status = 'awaiting_approval' AND i.approval_request_id IS NOT NULL \
            AND EXISTS (SELECT 1 FROM approval_request a \
                         WHERE a.id::text = i.approval_request_id \
                           AND a.status IN ('rejected', 'expired', 'cancelled'))",
    )
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    let fulfilling: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, fulfilment_mode FROM service_request_item \
          WHERE status = 'fulfilling' AND (is_active IS NULL OR is_active = true) LIMIT 500",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (item_id, mode) in fulfilling {
        let tasks: Vec<(i64, String)> = sqlx::query_as(
            "SELECT sequence::bigint, coalesce(status, 'pending') FROM service_fulfilment_task \
              WHERE item_ref = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(item_id)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        if all_finished(&tasks) {
            sqlx::query(
                "UPDATE service_request_item SET status = 'fulfilled' \
                  WHERE id = $1 AND status = 'fulfilling'",
            )
            .bind(item_id)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            moved += 1;
            continue;
        }
        if mode.as_deref() != Some(PlanMode::Parallel.as_str())
            && let Some(sequence) = next_to_open(&tasks)
        {
            sqlx::query(
                "UPDATE service_fulfilment_task SET status = 'open' \
                  WHERE item_ref = $1 AND sequence = $2 AND status = 'pending'",
            )
            .bind(item_id)
            .bind(sequence)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        }
    }
    Ok(moved)
}

/// Places a cart order (G3-T2).
///
/// One work request with one item per line (and per offering of an order
/// guide, each carrying the guide's answers). An item whose offering
/// requires approval waits for it; the others start their fulfilment tasks
/// at once.
#[utoipa::path(
    post,
    path = "/api/v1/service-orders",
    tag = "service",
    request_body = PlaceOrderRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create),
    ])))),
    responses(
        (status = 201, description = "The order and its items", body = OrderPlaced),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "The first line's offering is not active", body = ErrorResponse),
        (status = 422, description = "No lines or too many, a bad quantity, or an unanswered guide question", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn place_order_route(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<WorkRequestCreate>>,
    Json(body): Json<PlaceOrderRequest>,
) -> Result<(StatusCode, Json<OrderPlaced>), AppError> {
    let ring = state.base.pepper_ring();
    let placed = place_order(&state, &ctx, body, &ring).await?;
    Ok((StatusCode::CREATED, Json(placed)))
}

// ── G3-T3: catalog, my orders and cancel ────────────────────────────────────

/// Most offerings one catalog search answers.
pub const CATALOG_LIMIT: i64 = 100;
/// Most orders one listing answers.
pub const ORDERS_LIMIT: i64 = 50;

/// Text folded for matching in Arabic and English: lower case, the alef and
/// teh marbuta forms people type interchangeably made one. Pure.
pub fn fold_search(text: &str) -> String {
    text.trim()
        .to_lowercase()
        .chars()
        .map(|c| match c {
            'أ' | 'إ' | 'آ' => 'ا',
            'ة' => 'ه',
            'ى' => 'ي',
            other => other,
        })
        .collect()
}

/// `GET /api/v1/service-catalog`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CatalogQuery {
    /// Words to look for in the name, description and category.
    pub q: Option<String>,
    /// Only offerings in this catalog category.
    pub category_ref: Option<Uuid>,
}

/// One offering in the catalog.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct CatalogOffering {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub category_ref: Option<Uuid>,
    pub category_name: Option<String>,
    pub default_priority: Option<String>,
    pub requires_approval: bool,
}

/// The active offerings matching `q`, by name. Only active offerings are
/// ever listed; a caller without `service_offering.read` gets none.
pub async fn search_catalog(
    db: &DbPool,
    query: &CatalogQuery,
) -> Result<Vec<CatalogOffering>, AppError> {
    let pattern = query
        .q
        .as_deref()
        .map(fold_search)
        .filter(|q| !q.is_empty())
        .map(|q| {
            format!(
                "%{}%",
                q.replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            )
        });
    sqlx::query_as(
        "SELECT o.id, o.name, o.description, o.category::text AS category, o.category_ref, \
                c.name AS category_name, o.default_priority::text AS default_priority, \
                coalesce(o.requires_approval, false) AS requires_approval \
           FROM service_offering o \
           LEFT JOIN service_category c ON c.id = o.category_ref \
          WHERE (o.is_active IS NULL OR o.is_active = true) \
            AND ($2::uuid IS NULL OR o.category_ref = $2) \
            AND ($1::text IS NULL OR translate(lower(concat_ws(' ', o.name, o.description, \
                     o.category::text, c.name)), 'أإآةى', 'اااهي') LIKE $1) \
          ORDER BY o.name LIMIT $3",
    )
    .bind(pattern)
    .bind(query.category_ref)
    .bind(CATALOG_LIMIT)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// The service catalog (G3-T3): active offerings, searched in Arabic or
/// English across name, description and category.
#[utoipa::path(
    get,
    path = "/api/v1/service-catalog",
    tag = "service",
    params(CatalogQuery),
    responses(
        (status = 200, description = "Matching offerings, by name", body = PaginatedResponse<CatalogOffering>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn catalog_route(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<crate::auth::OfferingRead>>,
    axum::extract::Query(query): axum::extract::Query<CatalogQuery>,
) -> Result<Json<PaginatedResponse<CatalogOffering>>, AppError> {
    let items = search_catalog(&state.base.db, &query).await?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, CATALOG_LIMIT)))
}

/// One item of an order, as its owner sees it.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct OrderItemView {
    pub id: Uuid,
    pub offering_id: Uuid,
    pub offering_name: Option<String>,
    pub quantity: Option<f64>,
    pub status: String,
}

/// One order, as its owner sees it.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrderView {
    pub work_request_id: Uuid,
    pub title: String,
    pub reference: Option<String>,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    pub items: Vec<OrderItemView>,
}

/// The caller's orders, newest first: ones placed for them or by them.
pub async fn my_orders(db: &DbPool, user_id: Uuid) -> Result<Vec<OrderView>, AppError> {
    let orders: Vec<(
        Uuid,
        String,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as(
        "SELECT w.id, w.title, w.reference, w.created_at FROM service_work_request w \
              WHERE (w.requester_id = $1 OR w.created_by = $1) \
                AND (w.is_active IS NULL OR w.is_active = true) \
                AND EXISTS (SELECT 1 FROM service_request_item i WHERE i.work_request_ref = w.id) \
              ORDER BY w.created_at DESC LIMIT $2",
    )
    .bind(user_id)
    .bind(ORDERS_LIMIT)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let ids: Vec<Uuid> = orders.iter().map(|o| o.0).collect();
    let items: Vec<(Uuid, OrderItemView)> = sqlx::query_as::<
        _,
        (Uuid, Uuid, Uuid, Option<String>, Option<f64>, String),
    >(
        "SELECT i.work_request_ref, i.id, i.offering_ref, o.name, i.quantity::double precision, \
                coalesce(i.status, 'awaiting_approval') \
           FROM service_request_item i LEFT JOIN service_offering o ON o.id = i.offering_ref \
          WHERE i.work_request_ref = ANY($1) AND (i.is_active IS NULL OR i.is_active = true) \
          ORDER BY i.created_at, i.id",
    )
    .bind(&ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .map(
        |(order, id, offering_id, offering_name, quantity, status)| {
            (
                order,
                OrderItemView {
                    id,
                    offering_id,
                    offering_name,
                    quantity,
                    status,
                },
            )
        },
    )
    .collect();
    let mut views: Vec<OrderView> = orders
        .into_iter()
        .map(|(id, title, reference, created_at)| OrderView {
            work_request_id: id,
            title,
            reference,
            created_at,
            items: Vec::new(),
        })
        .collect();
    for (order, item) in items {
        if let Some(view) = views.iter_mut().find(|v| v.work_request_id == order) {
            view.items.push(item);
        }
    }
    Ok(views)
}

/// The caller's orders and where each item stands (G3-T3).
#[utoipa::path(
    get,
    path = "/api/v1/service-orders/mine",
    tag = "service",
    responses(
        (status = 200, description = "The caller's orders, newest first", body = PaginatedResponse<OrderView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn my_orders_route(
    State(state): State<EngineState>,
    ctx: Authorized<attome_server::authz::SelfService>,
) -> Result<Json<PaginatedResponse<OrderView>>, AppError> {
    let items = my_orders(&state.base.db, ctx.user_id).await?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, ORDERS_LIMIT)))
}

/// Whether an item in `status` can still be cancelled. Pure.
pub fn cancellable(status: &str) -> bool {
    matches!(status, "awaiting_approval" | "fulfilling")
}

/// Cancels an order item (G3-T3): its unfinished tasks are cancelled too,
/// and an approval it waits for no longer starts anything. Only the person
/// the order is for, the one who placed it, or an administrator may.
pub async fn cancel_item(
    state: &EngineState,
    ctx: &SecurityContext,
    item_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<(String, Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT coalesce(i.status, ''), w.requester_id, w.created_by \
           FROM service_request_item i JOIN service_work_request w ON w.id = i.work_request_ref \
          WHERE i.id = $1 AND (i.is_active IS NULL OR i.is_active = true) FOR UPDATE OF i",
    )
    .bind(item_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (status, requester, creator) = row.ok_or(AppError::NotFound)?;
    let owner = Some(ctx.user_id) == requester || Some(ctx.user_id) == creator;
    if !owner && !ctx.is_admin {
        return Err(AppError::NotFound);
    }
    if !cancellable(&status) {
        return Err(AppError::Conflict("this item can no longer be cancelled"));
    }
    sqlx::query("UPDATE service_request_item SET status = 'cancelled' WHERE id = $1")
        .bind(item_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE service_fulfilment_task SET status = 'cancelled' \
          WHERE item_ref = $1 AND status IN ('pending', 'open')",
    )
    .bind(item_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_core::change_feed::emit_tx(&mut tx, ITEM, item_id, attome_core::ChangeOperation::Update)
        .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            ITEM,
            item_id,
            attome_audit::AuditOperation::Update,
            "service_order.cancel_item",
            ctx.user_id,
        )
        .comment(format!("cancelled while {status}")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// Cancels an order item (G3-T3).
///
/// Allowed while it waits for approval or is being fulfilled; its open and
/// pending tasks are cancelled with it. Only the person the order is for, the
/// one who placed it, or an administrator may; anyone else gets 404.
#[utoipa::path(
    post,
    path = "/api/v1/service-orders/items/{id}/cancel",
    tag = "service",
    params(("id" = Uuid, Path, description = "The order item's id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update),
    ])))),
    responses(
        (status = 204, description = "Cancelled"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such item, or not one the caller may cancel", body = ErrorResponse),
        (status = 409, description = "The item is fulfilled, rejected or cancelled already", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn cancel_item_route(
    State(state): State<EngineState>,
    ctx: Authorized<attome_server::authz::SelfService>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
) -> Result<StatusCode, AppError> {
    cancel_item(&state, &ctx, item_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod catalog_browse {
    use super::*;

    #[test]
    fn catalog_search_folds_arabic_letter_forms_and_case() {
        assert_eq!(fold_search(" Laptop "), "laptop");
        assert_eq!(fold_search("إجازة"), "اجازه");
        assert_eq!(fold_search("أجازه"), fold_search("اجازة"));
    }

    #[test]
    fn catalog_items_cancel_only_before_they_finish() {
        assert!(cancellable("awaiting_approval"));
        assert!(cancellable("fulfilling"));
        assert!(!cancellable("fulfilled"));
        assert!(!cancellable("rejected"));
        assert!(!cancellable("cancelled"));
    }
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/service-orders", post(place_order_route))
        .route("/api/v1/service-catalog", axum::routing::get(catalog_route))
        .route(
            "/api/v1/service-orders/mine",
            axum::routing::get(my_orders_route),
        )
        .route(
            "/api/v1/service-orders/items/{id}/cancel",
            post(cancel_item_route),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(place_order_route, catalog_route, my_orders_route, cancel_item_route))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod catalog_order {
    use super::*;

    #[test]
    fn catalog_order_plans_open_in_order_or_together() {
        let plan = parse_plan(Some(
            r#"{"mode": "sequential", "tasks": [{"title": "Order"}, {"title": "Configure"}, {"title": "Deliver"}]}"#,
        ))
        .unwrap_or_default();
        assert_eq!(initial_statuses(&plan), vec!["open", "pending", "pending"]);
        let parallel = parse_plan(Some(
            r#"{"mode": "parallel", "tasks": [{"title": "A"}, {"title": "B"}]}"#,
        ))
        .unwrap_or_default();
        assert_eq!(initial_statuses(&parallel), vec!["open", "open"]);
        assert_eq!(parse_plan(None), Ok(FulfilmentPlan::default()));
        assert!(parse_plan(Some(r#"{"tasks": [{"title": " "}]}"#)).is_err());
        assert!(parse_plan(Some(r#"{"mode": "random"}"#)).is_err());
    }

    #[test]
    fn catalog_order_opens_the_next_task_when_the_open_one_is_done() {
        let tasks = |s: &[&str]| -> Vec<(i64, String)> {
            s.iter()
                .enumerate()
                .map(|(i, st)| (i64::try_from(i + 1).unwrap_or(0), (*st).to_owned()))
                .collect()
        };
        assert_eq!(next_to_open(&tasks(&["open", "pending"])), None);
        assert_eq!(
            next_to_open(&tasks(&["done", "pending", "pending"])),
            Some(2)
        );
        assert_eq!(next_to_open(&tasks(&["done", "done"])), None);
        assert!(all_finished(&tasks(&["done", "cancelled"])));
        assert!(!all_finished(&tasks(&["done", "open"])));
    }

    #[test]
    fn catalog_order_guides_require_their_questions() {
        let questions = parse_questions(Some(
            r#"[{"key": "start_date", "label": "Start date", "required": true},
                {"key": "notes", "label": "Notes"}]"#,
        ))
        .unwrap_or_default();
        let mut answers = Map::new();
        assert_eq!(unanswered(&questions, &answers), vec!["start_date"]);
        answers.insert("start_date".into(), json!("2026-11-01"));
        assert!(unanswered(&questions, &answers).is_empty());
        assert!(parse_questions(Some(r#"[{"key": "bad key", "label": "x"}]"#)).is_err());
    }
}
