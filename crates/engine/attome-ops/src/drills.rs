//! AB4-T6: drill evidence kept in the deployment (`ops_drill_run`,
//! migration 0266).
//!
//! - `POST /api/v1/ops/drills/evidence` (`ops.drill.run`) takes an
//!   `attome-evidence/v1` report as `attome drill` signed it, checks the
//!   signature against `config.ops.drill_public_keys` (422 when it does not
//!   hold or no key is configured) and stores it once: the SHA-256 of the
//!   evidence's canonical bytes is unique, so a replay answers 200 with the
//!   stored id. A new row commits with its Configuration event
//!   (`ops.drill_evidence_recorded`, the SHA-256 in its comment), which puts
//!   the hash in the audit chain.
//! - `GET /api/v1/ops/drills` pages the history, newest first, optionally of
//!   one kind, without the raw evidence; `GET /api/v1/ops/drills/{id}`
//!   answers the signed evidence itself. Both need `ops.read`, which the
//!   Auditor role holds.
//!
//! There is no delete or update route, and the table refuses both: an update
//! always, a delete within 400 days of the upload. v2 has no drill reports
//! from before the signed format, so there is no legacy upload.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::evidence::{self, EvidenceKind, SignedEvidence};
use crate::upgrades::OpsRead;

/// `ops.drill.run`: who runs drills and records their evidence.
#[derive(Debug)]
pub struct OpsDrillRun;

impl PrivilegeKey for OpsDrillRun {
    const KEY: &'static str = "ops.drill.run";
}

const COLUMNS: &str = "id, kind, started_at, finished_at, overall_ok, restore_ok, provenance_ok, \
     rpo_seconds, rto_seconds, data_size_bytes, platform_version, key_id, sha256, uploaded_by, \
     created_at";

/// One recorded drill, without its evidence.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct DrillRun {
    pub id: Uuid,
    /// `restore`, `failover`, `chaos`, `upgrade`, `secrets`, `recovery` or
    /// `drain`.
    pub kind: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub overall_ok: bool,
    pub restore_ok: bool,
    pub provenance_ok: bool,
    pub rpo_seconds: Option<f64>,
    pub rto_seconds: Option<f64>,
    pub data_size_bytes: Option<i64>,
    pub platform_version: String,
    /// The signing key's id.
    pub key_id: String,
    /// The SHA-256 of the evidence's canonical bytes, as the audit event
    /// records it.
    pub sha256: String,
    pub uploaded_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// An upload's outcome.
#[derive(Debug, Serialize, ToSchema)]
pub struct EvidenceRecorded {
    pub id: Uuid,
    pub sha256: String,
    /// False when this evidence was already stored.
    pub created: bool,
}

/// The history's filter.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DrillFilter {
    /// Only drills of this kind.
    #[serde(default)]
    pub kind: Option<String>,
}

/// A kind's stored name. Pure.
pub fn kind_name(kind: EvidenceKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The SHA-256 the row is keyed by: of the evidence's canonical bytes, so
/// the same evidence hashes the same however its file was formatted. Pure.
pub fn evidence_sha256(signed: &SignedEvidence) -> Result<String, AppError> {
    let bytes = signed
        .evidence
        .canonical_bytes()
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Checks `signed` against the configured keys. Pure but for the config.
pub fn check_signature(signed: &SignedEvidence, configured: &[String]) -> Result<(), AppError> {
    if signed.evidence.schema != evidence::SCHEMA {
        return Err(AppError::Validation(format!(
            "the evidence is not {}",
            evidence::SCHEMA
        )));
    }
    if configured.is_empty() {
        return Err(AppError::Validation(
            "no drill public key is configured (ops.drill_public_keys)".into(),
        ));
    }
    let trusted = configured
        .iter()
        .map(String::as_str)
        .map(evidence::verifying_key)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AppError::internal(e.to_string()))?;
    evidence::verify(signed, &trusted).map_err(|e| AppError::Validation(e.to_string()))
}

/// Record a drill's evidence
///
/// AB4-T6: the signed `attome-evidence/v1` report `attome drill` wrote. The
/// signature must hold against `ops.drill_public_keys`. Stored once: a
/// replay answers 200 with the stored id. Needs `ops.drill.run`. Audited
/// with the evidence's SHA-256.
#[utoipa::path(
    post,
    path = "/api/v1/ops/drills/evidence",
    tag = "ops",
    operation_id = "record_ops_drill_evidence",
    request_body = SignedEvidence,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Stored", body = EvidenceRecorded),
        (status = 200, description = "Already stored; the stored id", body = EvidenceRecorded),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.drill.run", body = ErrorResponse),
        (status = 422, description = "Not attome-evidence/v1, a signature that does not hold, or no configured key", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn record_evidence(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsDrillRun>>,
    Json(signed): Json<SignedEvidence>,
) -> Result<(StatusCode, Json<EvidenceRecorded>), AppError> {
    check_signature(&signed, &state.base.config.ops.drill_public_keys)?;
    let sha256 = evidence_sha256(&signed)?;
    let e = &signed.evidence;
    let stored = serde_json::to_value(&signed).map_err(AppError::internal)?;
    let size = e
        .data_size_bytes
        .map(|b| i64::try_from(b).unwrap_or(i64::MAX));
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO ops_drill_run (id, kind, started_at, finished_at, overall_ok, restore_ok, \
                provenance_ok, rpo_seconds, rto_seconds, data_size_bytes, platform_version, \
                key_id, sha256, evidence, uploaded_by) \
         VALUES (uuidv7(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
         ON CONFLICT (sha256) DO NOTHING RETURNING id",
    )
    .bind(kind_name(e.kind))
    .bind(e.started_at)
    .bind(e.finished_at)
    .bind(e.overall_ok)
    .bind(e.restore_ok)
    .bind(e.provenance_ok)
    .bind(e.rpo_seconds)
    .bind(e.rto_seconds)
    .bind(size)
    .bind(&e.platform_version)
    .bind(&signed.key_id)
    .bind(&sha256)
    .bind(&stored)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(id) = inserted else {
        drop(tx);
        let id: Uuid = sqlx::query_scalar("SELECT id FROM ops_drill_run WHERE sha256 = $1")
            .bind(&sha256)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        return Ok((
            StatusCode::OK,
            Json(EvidenceRecorded {
                id,
                sha256,
                created: false,
            }),
        ));
    };
    // AB4-T7: the upload moves its kind's schedule on.
    crate::drill_schedules::advance(&mut tx, &kind_name(e.kind), id).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "ops_drill_run",
            Some(id),
        )
        .named("ops.drill_evidence_recorded".to_owned())
        .comment(format!(
            "{} drill evidence sha256 {sha256} (key {}, overall_ok {})",
            kind_name(e.kind),
            signed.key_id,
            e.overall_ok
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    // AB4-T9: this node's freshness answers are now out of date.
    crate::freshness::invalidate();
    Ok((
        StatusCode::CREATED,
        Json(EvidenceRecorded {
            id,
            sha256,
            created: true,
        }),
    ))
}

/// List drills
///
/// AB4-T6: recorded drills, newest first, without their evidence;
/// optionally of one kind. Needs `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/drills",
    tag = "ops",
    operation_id = "list_ops_drills",
    params(DrillFilter, OnePageQuery),
    responses(
        (status = 200, description = "One page of drills", body = PaginatedResponse<DrillRun>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
        (status = 422, description = "An unknown kind", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_drills(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsRead>>,
    Query(filter): Query<DrillFilter>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<DrillRun>>, AppError> {
    let kind = match filter.kind.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(k) => {
            let parsed: EvidenceKind = serde_json::from_value(serde_json::Value::from(k))
                .map_err(|_| AppError::Validation(format!("unknown drill kind `{k}`")))?;
            Some(kind_name(parsed))
        }
    };
    let w = page.window();
    let items: Vec<DrillRun> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ops_drill_run WHERE ($1::text IS NULL OR kind = $1) \
          ORDER BY finished_at DESC, id DESC LIMIT $2 OFFSET $3"
    ))
    .bind(&kind)
    .bind(w.page_size)
    .bind(w.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ops_drill_run WHERE ($1::text IS NULL OR kind = $1)",
    )
    .bind(&kind)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        w.page,
        w.page_size,
    )))
}

/// Get a drill's evidence
///
/// AB4-T6: the signed evidence as it was uploaded, for an auditor to verify
/// with `attome drill verify`. Needs `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/drills/{id}",
    tag = "ops",
    operation_id = "get_ops_drill",
    params(("id" = Uuid, Path, description = "The drill")),
    responses(
        (status = 200, description = "The signed evidence", body = SignedEvidence),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
        (status = 404, description = "No such drill", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_drill(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsRead>>,
    Path(id): Path<Uuid>,
) -> Result<Json<SignedEvidence>, AppError> {
    let stored: serde_json::Value =
        sqlx::query_scalar("SELECT evidence FROM ops_drill_run WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?;
    serde_json::from_value(stored)
        .map(Json)
        .map_err(AppError::internal)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ops/drills/evidence", post(record_evidence))
        .route("/api/v1/ops/drills", get(list_drills))
        .route("/api/v1/ops/drills/{id}", get(get_drill))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(record_evidence, list_drills, get_drill),
    components(schemas(
        DrillRun,
        EvidenceRecorded,
        SignedEvidence,
        evidence::Evidence,
        evidence::EvidenceKind,
        evidence::Check,
        evidence::CheckResult
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use evidence::SigningKey;

    fn signed(key: &SigningKey) -> SignedEvidence {
        let at = Utc::now();
        let mut e = evidence::Evidence {
            schema: evidence::SCHEMA.into(),
            kind: EvidenceKind::Restore,
            drill_id: Uuid::now_v7(),
            started_at: at,
            finished_at: at,
            platform_version: "2.0.0".into(),
            image_digest: None,
            deployment_id: None,
            checks: Vec::new(),
            rpo_seconds: None,
            rto_seconds: Some(30.0),
            data_size_bytes: Some(1024),
            restore_ok: true,
            provenance_ok: true,
            overall_ok: false,
            extra: serde_json::Map::new(),
        };
        e.compute_overall();
        evidence::sign(&e, key).unwrap()
    }

    #[test]
    fn only_signatures_by_a_configured_key_are_accepted() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let other = SigningKey::from_bytes(&[6u8; 32]);
        let report = signed(&key);
        let configured = vec![evidence::public_key_base64(&key)];
        assert!(check_signature(&report, &configured).is_ok());
        assert!(check_signature(&report, &[evidence::public_key_base64(&other)]).is_err());
        assert!(check_signature(&report, &[]).is_err());

        let mut altered = report.clone();
        altered.evidence.rto_seconds = Some(1.0);
        assert!(check_signature(&altered, &configured).is_err());

        let mut wrong_schema = report;
        wrong_schema.evidence.schema = "attome-evidence/v0".into();
        assert!(check_signature(&wrong_schema, &configured).is_err());
    }

    #[test]
    fn the_hash_ignores_formatting_but_not_content() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let report = signed(&key);
        let reread: SignedEvidence =
            serde_json::from_str(&serde_json::to_string_pretty(&report).unwrap()).unwrap();
        assert_eq!(
            evidence_sha256(&report).unwrap(),
            evidence_sha256(&reread).unwrap()
        );
        let mut changed = report.clone();
        changed.evidence.platform_version = "2.0.1".into();
        assert_ne!(
            evidence_sha256(&report).unwrap(),
            evidence_sha256(&changed).unwrap()
        );
        assert_eq!(kind_name(EvidenceKind::Restore), "restore");
    }
}
