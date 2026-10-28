//! I10-T1: an asset's warranty as an entitlement. A warranty is an
//! `entitlement` with `source = warranty` on the asset (field-service pack
//! 0003, with its `warranty_term`); the asset's `warranty_expires_on`
//! (asset-management pack) is the latest end of its active warranty
//! entitlements.
//!
//! Filling that date for assets that predate their entitlements is a
//! one-time job run only after a person confirms it:
//! `POST /api/v1/service/warranty-backfill/preview` counts the assets whose
//! date would change (and shows a few), and `POST
//! /api/v1/service/warranty-backfill` with `confirm: true` queues the job,
//! which writes each change through the record engine as the person who
//! confirmed (record rules, validation, audit), 500 assets a batch.
//!
//! I10-T2: **coverage per line** is [`crate::work_order::split`]: a
//! warranty covers part, service (labour) and travel lines by its term's
//! three percentages, so a covered work order line is not billed. **Expiry
//! reminders**: the nightly `warranty_expiry_reminder` job tells each
//! active warranty entitlement's owner (else its creator) once, [`LEAD_DAYS`]
//! days before it ends. The job claims the entitlement by writing the end
//! date into `expiry_reminded_on` before it notifies, so a second run in a
//! night finds nothing, and a warranty extended to a new end date is
//! reminded again for that date.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "warranty_backfill";
/// Assets written per batch.
pub const BATCH: i64 = 500;
/// Changes the preview lists.
const SAMPLE: i64 = 20;
/// I10-T2: the expiry reminder job.
pub const REMINDER_JOB: &str = "warranty_expiry_reminder";
/// Days before a warranty ends that its owner is told.
pub const LEAD_DAYS: i64 = 30;

/// `asset.update`: who may run the backfill.
#[derive(Debug)]
pub struct AssetUpdate;

impl PrivilegeKey for AssetUpdate {
    const KEY: &'static str = "asset.update";
}

/// An asset's warranty end: the latest end of its active warranty
/// entitlements, `None` with none. Pure.
pub fn warranty_expiry(ends: &[(Option<NaiveDate>, Option<String>)]) -> Option<NaiveDate> {
    ends.iter()
        .filter(|(_, status)| status.as_deref().is_none_or(|s| s == "active"))
        .filter_map(|(end, _)| *end)
        .max()
}

/// The assets' warranty ends, from their active warranty entitlements.
const WARRANTY_ENDS: &str = "WITH w AS ( \
        SELECT e.asset_ref AS asset, max(e.period_end::date) AS ends \
          FROM entitlement e \
         WHERE e.source::text = 'warranty' AND e.asset_ref IS NOT NULL \
           AND COALESCE(e.status::text, 'active') = 'active' \
           AND (e.is_active IS NULL OR e.is_active = true) \
         GROUP BY e.asset_ref) ";

/// The assets whose date would change, with the new date, a page after
/// `$1`. Constants only: nothing is interpolated.
const CHANGES_SQL: &str = "SELECT a.id AS asset_id, a.warranty_expires_on::date AS \"current\", \
            w.ends AS \"new\" \
       FROM asset a JOIN w ON w.asset = a.id \
      WHERE (a.is_active IS NULL OR a.is_active = true) \
        AND a.warranty_expires_on::date IS DISTINCT FROM w.ends \
        AND a.id > $1 \
      ORDER BY a.id LIMIT $2";

/// How many assets would change.
const COUNT_SQL: &str = "SELECT COUNT(*) FROM asset a JOIN w ON w.asset = a.id \
      WHERE (a.is_active IS NULL OR a.is_active = true) \
        AND a.warranty_expires_on::date IS DISTINCT FROM w.ends";

/// The asset and entitlement entities must both be installed.
fn installed(state: &EngineState) -> Result<(), AppError> {
    let registry = state.entities.load();
    if registry.get("asset").is_some() && registry.get("entitlement").is_some() {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// One asset's change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, sqlx::FromRow)]
pub struct WarrantyChange {
    pub asset_id: Uuid,
    pub current: Option<NaiveDate>,
    pub new: Option<NaiveDate>,
}

/// What the backfill would do.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WarrantyPreview {
    pub assets_to_change: i64,
    pub sample: Vec<WarrantyChange>,
}

/// Counts and samples the changes.
pub async fn preview(state: &EngineState) -> Result<WarrantyPreview, AppError> {
    installed(state)?;
    let count: i64 = sqlx::query_scalar(&[WARRANTY_ENDS, COUNT_SQL].concat())
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let sample: Vec<WarrantyChange> = sqlx::query_as(&[WARRANTY_ENDS, CHANGES_SQL].concat())
        .bind(Uuid::nil())
        .bind(SAMPLE)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(WarrantyPreview {
        assets_to_change: count,
        sample,
    })
}

/// The job's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillJob {
    pub user_id: Uuid,
}

/// The job: writes every change as `ctx`, a batch at a time. Returns the
/// assets written.
pub async fn run(state: &EngineState, ctx: &SecurityContext) -> Result<u64, AppError> {
    installed(state)?;
    let sql = [WARRANTY_ENDS, CHANGES_SQL].concat();
    let mut after = Uuid::nil();
    let mut written = 0;
    loop {
        let batch: Vec<WarrantyChange> = sqlx::query_as(&sql)
            .bind(after)
            .bind(BATCH)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        let Some(last) = batch.last().map(|c| c.asset_id) else {
            break;
        };
        for change in &batch {
            let record = match attome_records::entity_crud::read_record(
                state,
                ctx,
                "asset",
                change.asset_id,
            )
            .await
            {
                Ok(r) => r,
                // An asset the person may not read is left as it is.
                Err(AppError::NotFound | AppError::Forbidden) => continue,
                Err(e) => return Err(e),
            };
            attome_records::entity_crud::update_record_for(
                state,
                ctx,
                ctx.user_id,
                "asset",
                change.asset_id,
                record.row_version(),
                json!({ "warranty_expires_on": change.new.map(|d| d.to_string()) }),
            )
            .await?;
            written += 1;
        }
        after = last;
        if (batch.len() as i64) < BATCH {
            break;
        }
    }
    Ok(written)
}

/// Preview the warranty date backfill
///
/// Counts the assets whose warranty expiry date would change from their active warranty entitlements,
/// and shows a few. Writes nothing.
#[utoipa::path(
    post,
    path = "/api/v1/service/warranty-backfill/preview",
    operation_id = "post_warranty_backfill_preview",
    tag = "service",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "counts the assets the backfill would change; writes nothing",
    )))),
    responses(
        (status = 200, description = "What the backfill would change", body = WarrantyPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks asset.update", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
// Previews the warranty date backfill.
async fn post_preview(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<AssetUpdate>>,
) -> Result<Json<WarrantyPreview>, AppError> {
    Ok(Json(preview(&state).await?))
}

/// The confirmation.
#[derive(Debug, Deserialize, ToSchema)]
pub struct WarrantyBackfillBody {
    /// Must be `true`: the person has seen the preview.
    pub confirm: bool,
}

/// Backfill warranty dates
///
/// With `confirm: true`, queues the job that writes each asset's warranty expiry date through the
/// record engine as the person who confirmed, 500 assets a batch. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/service/warranty-backfill",
    operation_id = "post_warranty_backfill",
    tag = "service",
    request_body = WarrantyBackfillBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 202, description = "The backfill is queued"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks asset.update", body = ErrorResponse),
        (status = 422, description = "Not confirmed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
// Runs the warranty date backfill once confirmed.
async fn post_backfill(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<AssetUpdate>>,
    Json(body): Json<WarrantyBackfillBody>,
) -> Result<StatusCode, AppError> {
    installed(&state)?;
    if !body.confirm {
        return Err(AppError::Validation(
            "confirm: preview the backfill, then send confirm: true".into(),
        ));
    }
    let job = attome_core::jobs::JOB_TYPES
        .job(
            JOB,
            &BackfillJob {
                user_id: ctx.user_id,
            },
        )
        .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "asset",
            Uuid::nil(),
            attome_audit::AuditOperation::Update,
            "warranty.backfill_requested",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::ACCEPTED)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/service/warranty-backfill/preview",
            post(post_preview),
        )
        .route("/api/v1/service/warranty-backfill", post(post_backfill))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_preview, post_backfill),
    components(schemas(WarrantyChange, WarrantyPreview, WarrantyBackfillBody))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

/// Whether a warranty ending on `end` is due its reminder on `today`: it
/// ends within [`LEAD_DAYS`] and has not ended, and was not already
/// reminded for this end date. Pure; the claim query below applies the
/// same rule.
pub fn reminder_due(end: NaiveDate, reminded_for: Option<NaiveDate>, today: NaiveDate) -> bool {
    let until = today
        .checked_add_signed(chrono::Duration::days(LEAD_DAYS))
        .unwrap_or(today);
    end >= today && end <= until && reminded_for != Some(end)
}

/// `(entitlement, name, end, asset, recipient)`.
type ClaimedWarranty = (Uuid, Option<String>, NaiveDate, Option<Uuid>, Option<Uuid>);

/// One night's reminders. Answers how many were sent. A deployment without
/// the field-service columns on `entitlement` does nothing.
pub async fn remind_expiring(state: &EngineState, today: NaiveDate) -> Result<u64, AppError> {
    let db = &state.base.db;
    let ready: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = 'entitlement' \
            AND column_name = 'expiry_reminded_on')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !ready {
        return Ok(0);
    }
    let until = today
        .checked_add_signed(chrono::Duration::days(LEAD_DAYS))
        .unwrap_or(today);
    let mut sent = 0;
    loop {
        // Claimed before anyone is told: a second run finds nothing.
        let claimed: Vec<ClaimedWarranty> = sqlx::query_as(
            "WITH due AS ( \
               SELECT id FROM entitlement \
                WHERE source::text = 'warranty' \
                  AND COALESCE(status::text, 'active') = 'active' \
                  AND (is_active IS NULL OR is_active = true) \
                  AND period_end::date BETWEEN $1 AND $2 \
                  AND expiry_reminded_on::date IS DISTINCT FROM period_end::date \
                ORDER BY id LIMIT $3 FOR UPDATE SKIP LOCKED) \
             UPDATE entitlement e SET expiry_reminded_on = e.period_end::date \
               FROM due WHERE e.id = due.id \
             RETURNING e.id, e.name, e.period_end::date, e.asset_ref, \
                       COALESCE(e.owner_ref, e.created_by)",
        )
        .bind(today)
        .bind(until)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let n = claimed.len() as i64;
        for (id, name, end, _asset, recipient) in claimed {
            let Some(user) = recipient else { continue };
            let name = name.unwrap_or_else(|| "A warranty".to_owned());
            let req = attome_notification::dispatch::DispatchRequest {
                template_key: None,
                locale: "en".to_string(),
                recipient_user_ref: Some(user),
                is_global: false,
                organization_ref: None,
                channels: None,
                subject: Some(format!("{name} ends on {end}")),
                body_html: None,
                body_text: Some(format!(
                    "The warranty {name} ends on {end}. Work after that date is billed."
                )),
                route: Some(format!("/xrm/entity/entitlement/{id}")),
                variables: std::collections::HashMap::new(),
                priority: "normal".to_string(),
                escalate_after_minutes: None,
                escalate_channels: None,
            };
            // The claim already stands: a failed send is logged, not retried.
            match attome_notification::dispatch::create_dispatch(
                db,
                &state.base.config.notification,
                req,
            )
            .await
            {
                Ok(_) => sent += 1,
                Err(error) => {
                    tracing::warn!(entitlement = %id, %user, %error, "warranty expiry reminder failed");
                }
            }
        }
        if n < BATCH {
            break;
        }
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(m: u32) -> Option<NaiveDate> {
        NaiveDate::from_ymd_opt(2027, m, 1)
    }

    #[test]
    fn the_latest_active_warranty_wins() {
        let ends = vec![
            (d(3), Some("active".to_owned())),
            (d(9), Some("expired".to_owned())),
            (d(6), None),
            (None, Some("active".to_owned())),
        ];
        assert_eq!(warranty_expiry(&ends), d(6));
        assert_eq!(warranty_expiry(&[]), None);
    }
}

#[cfg(test)]
mod warranty_coverage {
    use super::*;
    use crate::work_order::{Cover, Line, LineKind, split};

    fn day(m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2027, m, d).expect("a real date")
    }

    fn line(n: u128, kind: LineKind, amount: f64) -> Line {
        Line {
            id: Uuid::from_u128(n),
            kind,
            quantity: 1.0,
            amount,
        }
    }

    #[test]
    fn each_line_kind_is_covered_by_its_own_percent() {
        let lines = [
            line(1, LineKind::Part, 100.0),
            line(2, LineKind::Service, 200.0),
            line(3, LineKind::Travel, 50.0),
        ];
        let out = split(
            &lines,
            Cover::Warranty {
                parts_pct: 100.0,
                labour_pct: 100.0,
                travel_pct: 40.0,
            },
        );
        assert_eq!(out[0].billable_amount, 0.0, "a covered part is not billed");
        assert_eq!(out[1].billable_amount, 0.0, "covered labour is not billed");
        assert_eq!(out[2].covered_pct, 40.0);
        assert_eq!(out[2].billable_amount, 30.0);
    }

    #[test]
    fn contracts_never_cover_travel() {
        let lines = [line(1, LineKind::Travel, 80.0)];
        assert_eq!(
            split(&lines, Cover::Hours { remaining: 10.0 })[0].billable_amount,
            80.0
        );
        assert_eq!(
            split(&lines, Cover::Cases { available: true })[0].billable_amount,
            80.0
        );
    }

    #[test]
    fn line_kinds_parse_with_parts_as_the_fallback() {
        assert_eq!(LineKind::parse(Some("travel")), LineKind::Travel);
        assert_eq!(LineKind::parse(Some("service")), LineKind::Service);
        assert_eq!(LineKind::parse(Some("part")), LineKind::Part);
        assert_eq!(LineKind::parse(None), LineKind::Part);
    }

    #[test]
    fn a_reminder_is_due_thirty_days_out_once_per_end_date() {
        let today = day(3, 1);
        assert!(reminder_due(day(3, 31), None, today), "30 days out");
        assert!(
            !reminder_due(day(4, 1), None, today),
            "31 days out is too early"
        );
        assert!(reminder_due(day(3, 1), None, today), "ends today");
        assert!(!reminder_due(day(2, 28), None, today), "already ended");
        assert!(
            !reminder_due(day(3, 20), Some(day(3, 20)), today),
            "already reminded"
        );
        assert!(
            reminder_due(day(3, 25), Some(day(3, 20)), today),
            "extended to a new end date: reminded again"
        );
    }
}
