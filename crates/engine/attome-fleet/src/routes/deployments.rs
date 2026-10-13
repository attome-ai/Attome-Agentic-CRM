//! F1 — the deployment registry, its credentials, sync and drift (design
//! §6.1), the per-deployment action log, and the changeset files a publish
//! can choose from (§6.4).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_audit::{AuditOperation, AuditOutcome};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};

use super::{HumanSession, record, require_step_up, version_conflict_if_none};
use crate::changesets::{self, ChangesetFile};
use crate::client::{CustomerClient, RemoteError, S2sCredential, normalize_base_url};
use crate::crypto::{self, RolloutSecret};
use crate::error::{ConsoleError, ConsoleResult};
use crate::poll;
use crate::runtime::FleetState;
use crate::store::{self, ActionRow, ActionWrite, DeploymentFields, DeploymentRow, ObservationRow};

const ENTITY: &str = "fleet_deployment";
const ENVIRONMENTS: [&str; 3] = ["dev", "test", "prod"];
const RINGS: [&str; 3] = ["canary", "early", "broad"];
const MAX_LABEL: usize = 200;
const MAX_IDENT: usize = 200;
/// The dedup key (and schedule name) of `EngineJob::FleetPoll`.
pub const FLEET_POLL_KEY: &str = "fleet-poll";

// ── Wire types ──────────────────────────────────────────────────────────────

/// The latest probe of a deployment.
#[derive(Debug, Serialize, ToSchema)]
pub struct ObservationView {
    pub application_version: Option<String>,
    pub git_revision: Option<String>,
    pub schema_version: Option<i64>,
    pub schema_dirty: Option<bool>,
    pub configuration_version: Option<String>,
    pub ready: Option<bool>,
    pub open_items: Option<i32>,
    pub last_report_id: Option<Uuid>,
    pub last_release_at: Option<DateTime<Utc>>,
    /// `[{layer, scope, changeset_id, seq, status}]`.
    #[schema(value_type = Option<Object>)]
    pub ledger_head: Option<Value>,
    pub pending_approvals: Option<i32>,
    /// `timeout`, `tls`, `connect_failed`, `auth_refused`, `not_ready`, … or none.
    pub error_code: Option<String>,
    pub observed_at: DateTime<Utc>,
}

impl From<&ObservationRow> for ObservationView {
    fn from(row: &ObservationRow) -> Self {
        Self {
            application_version: row.application_version.clone(),
            git_revision: row.git_revision.clone(),
            schema_version: row.schema_version,
            schema_dirty: row.schema_dirty,
            configuration_version: row.configuration_version.clone(),
            ready: row.ready,
            open_items: row.open_items,
            last_report_id: row.last_report_id,
            last_release_at: row.last_release_at,
            ledger_head: row.ledger_head.clone(),
            pending_approvals: row.pending_approvals,
            error_code: row.error_code.clone(),
            observed_at: row.observed_at,
        }
    }
}

/// Drift against the console's own build (the source the developer runs is
/// the release the fleet converges to), with D-261's three outcomes: an axis
/// confirmed equal, confirmed different (`fields`), or not observable
/// (`unconfirmed`: the image digest, which no process can report, and the
/// configuration hash, which differs per project by design).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct DriftView {
    /// `never_observed`, `schema_dirty`, `in_sync` or `diverged`.
    pub status: String,
    /// `schema_version`, `application_version`.
    pub fields: Vec<String>,
    pub unconfirmed: Vec<String>,
}

/// One registered deployment. Never carries the secret: `secret_last4` and
/// `secret_rotated_at` only.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeploymentView {
    pub id: Uuid,
    pub project_code: String,
    pub label: String,
    /// `dev`, `test` or `prod`.
    pub environment: String,
    /// `canary`, `early` or `broad` — the wave a publish puts it in.
    pub ring: String,
    pub base_url: String,
    pub maintenance_window: Option<String>,
    pub is_active: bool,
    pub has_credential: bool,
    pub s2s_client_id: Option<String>,
    pub s2s_key_id: Option<String>,
    pub secret_last4: Option<String>,
    pub secret_rotated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
    pub observation: Option<ObservationView>,
    pub drift: DriftView,
}

/// The console's own release, the drift reference.
#[derive(Debug, Clone)]
pub struct ConsoleRelease {
    pub application_version: &'static str,
    pub schema_version: Option<i64>,
}

impl ConsoleRelease {
    pub async fn read(state: &FleetState) -> Self {
        let schema_version = match attome_db::schema_state(&state.xrm.base.db).await {
            Ok(schema) => schema.applied_max_version,
            Err(e) => {
                tracing::warn!(error = %e, "fleet: could not read the console's own schema version");
                None
            }
        };
        Self {
            application_version: env!("CARGO_PKG_VERSION"),
            schema_version,
        }
    }
}

pub fn drift(observation: Option<&ObservationRow>, console: &ConsoleRelease) -> DriftView {
    let mut unconfirmed = vec!["image_digest".to_owned(), "config_hash".to_owned()];
    let Some(observation) =
        observation.filter(|o| o.application_version.is_some() || o.schema_version.is_some())
    else {
        return DriftView {
            status: "never_observed".into(),
            fields: Vec::new(),
            unconfirmed,
        };
    };
    if observation.schema_dirty == Some(true) {
        return DriftView {
            status: "schema_dirty".into(),
            fields: Vec::new(),
            unconfirmed,
        };
    }
    let mut fields: Vec<String> = Vec::new();
    match (observation.schema_version, console.schema_version) {
        (Some(seen), Some(expected)) if seen != expected => fields.push("schema_version".into()),
        (Some(_), Some(_)) => {}
        _ => unconfirmed.push("schema_version".into()),
    }
    match observation.application_version.as_deref() {
        Some(seen) if seen != console.application_version => {
            fields.push("application_version".into())
        }
        Some(_) => {}
        None => unconfirmed.push("application_version".into()),
    }
    DriftView {
        status: if fields.is_empty() {
            "in_sync"
        } else {
            "diverged"
        }
        .into(),
        fields,
        unconfirmed,
    }
}

fn view(
    row: DeploymentRow,
    observation: Option<&ObservationRow>,
    console: &ConsoleRelease,
) -> DeploymentView {
    DeploymentView {
        has_credential: row.has_credential(),
        drift: drift(observation, console),
        observation: observation.map(ObservationView::from),
        id: row.id,
        project_code: row.project_code,
        label: row.label,
        environment: row.environment,
        ring: row.ring,
        base_url: row.base_url,
        maintenance_window: row.maintenance_window,
        is_active: row.is_active,
        s2s_client_id: row.s2s_client_id,
        s2s_key_id: row.s2s_key_id,
        secret_last4: row.secret_last4,
        secret_rotated_at: row.secret_rotated_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
        row_version: row.row_version,
    }
}

async fn view_one(state: &FleetState, row: DeploymentRow) -> Result<DeploymentView, AppError> {
    let observations = store::observations_for(&state.xrm.base.db, &[row.id]).await?;
    let console = ConsoleRelease::read(state).await;
    Ok(view(row, observations.first(), &console))
}

/// The rollout S2S credential, as the customer's S2S admin screen showed it.
/// Never logged, never returned (only `secret_last4`).
#[derive(Deserialize, ToSchema)]
pub struct CredentialBody {
    pub s2s_client_id: String,
    pub s2s_key_id: String,
    pub secret: String,
}

impl std::fmt::Debug for CredentialBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialBody").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct RegisterDeploymentBody {
    /// The customer's project code (Topic 15 #10), e.g. `BMD`.
    pub project_code: String,
    pub label: String,
    /// `dev`, `test` or `prod` (default `prod`).
    #[serde(default)]
    pub environment: Option<String>,
    /// `canary`, `early` or `broad` (default `broad`).
    #[serde(default)]
    pub ring: Option<String>,
    /// `https://host[:port]`, or `http://` for a loopback host.
    pub base_url: String,
    #[serde(default)]
    pub maintenance_window: Option<String>,
    /// Optional now; requires a fresh step-up when present.
    #[serde(default)]
    pub credential: Option<CredentialBody>,
}

impl std::fmt::Debug for RegisterDeploymentBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterDeploymentBody")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateDeploymentBody {
    /// The `row_version` the edit was made against.
    pub row_version: i64,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub ring: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    /// An empty string clears it.
    #[serde(default)]
    pub maintenance_window: Option<String>,
    #[serde(default)]
    pub is_active: Option<bool>,
}

impl std::fmt::Debug for UpdateDeploymentBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateDeploymentBody")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct SetCredentialBody {
    pub row_version: i64,
    #[serde(flatten)]
    pub credential: CredentialBody,
    /// Make one signed call with the new credential before storing it
    /// (default true): a refused credential is not stored.
    #[serde(default = "default_true")]
    pub verify: bool,
}

impl std::fmt::Debug for SetCredentialBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetCredentialBody").finish_non_exhaustive()
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DeploymentFilter {
    /// Include deactivated deployments.
    #[serde(default)]
    pub include_inactive: bool,
}

/// `POST /api/v1/fleet/sync` (202).
#[derive(Debug, Serialize, ToSchema)]
pub struct SyncQueued {
    /// `false` when a sync of the whole fleet is already queued or running.
    pub queued: bool,
}

/// One console action (append-only log).
#[derive(Debug, Serialize, ToSchema)]
pub struct ActionView {
    pub id: Uuid,
    pub actor_ref: Uuid,
    pub deployment_ref: Option<Uuid>,
    pub rollout_ref: Option<Uuid>,
    pub action: String,
    pub remote_method: Option<String>,
    pub remote_path: Option<String>,
    pub remote_status: Option<i32>,
    /// `ok`, `refused` or `failed`.
    pub outcome: String,
    #[schema(value_type = Object)]
    pub detail: Value,
    pub created_at: DateTime<Utc>,
}

impl From<ActionRow> for ActionView {
    fn from(row: ActionRow) -> Self {
        Self {
            id: row.id,
            actor_ref: row.actor_ref,
            deployment_ref: row.deployment_ref,
            rollout_ref: row.rollout_ref,
            action: row.action,
            remote_method: row.remote_method,
            remote_path: row.remote_path,
            remote_status: row.remote_status,
            outcome: row.outcome,
            detail: row.detail,
            created_at: row.created_at,
        }
    }
}

// ── Validation ──────────────────────────────────────────────────────────────

fn one_of(field: &str, value: &str, allowed: &[&str]) -> Result<String, AppError> {
    let value = value.trim().to_ascii_lowercase();
    if allowed.contains(&value.as_str()) {
        Ok(value)
    } else {
        Err(AppError::Validation(format!(
            "{field}: must be one of {allowed:?}"
        )))
    }
}

pub fn project_code(raw: &str) -> Result<String, AppError> {
    let value = raw.trim();
    if (2..=10).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric()) {
        Ok(value.to_ascii_uppercase())
    } else {
        Err(AppError::Validation(
            "project_code: 2-10 letters or digits, e.g. BMD".into(),
        ))
    }
}

fn text(field: &str, raw: &str, max: usize) -> Result<String, AppError> {
    let value = raw.trim();
    if value.is_empty() || value.chars().count() > max {
        return Err(AppError::Validation(format!(
            "{field}: required, at most {max} characters"
        )));
    }
    Ok(value.to_owned())
}

fn identifier(field: &str, raw: &str) -> Result<String, AppError> {
    let value = raw.trim();
    if value.is_empty() || value.len() > MAX_IDENT || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(AppError::Validation(format!(
            "{field}: required, printable characters without spaces, at most {MAX_IDENT}"
        )));
    }
    Ok(value.to_owned())
}

fn window(raw: Option<&str>) -> Result<Option<String>, AppError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(value) => text("maintenance_window", value, MAX_LABEL).map(Some),
    }
}

struct ParsedCredential {
    client_id: String,
    key_id: String,
    secret: RolloutSecret,
}

fn parse_credential(body: &CredentialBody) -> Result<ParsedCredential, AppError> {
    Ok(ParsedCredential {
        client_id: identifier("s2s_client_id", &body.s2s_client_id)?,
        key_id: identifier("s2s_key_id", &body.s2s_key_id)?,
        secret: RolloutSecret::parse(&body.secret)?,
    })
}

/// One signed call with a candidate credential (design §4.2 rotation step:
/// "confirm one signed probe works"). A refusal is a 422 and nothing is
/// stored; an unreachable customer is a 502.
async fn verify_credential(
    state: &FleetState,
    base_url: &str,
    credential: &ParsedCredential,
    correlation: Uuid,
) -> ConsoleResult<()> {
    let client = CustomerClient::new(
        state.runtime.http.clone(),
        base_url,
        Some(S2sCredential {
            client_id: credential.client_id.clone(),
            key_id: credential.key_id.clone(),
            secret: credential.secret.clone(),
        }),
    );
    match client.rollout_status(Some(correlation)).await {
        Ok(_) => Ok(()),
        Err(RemoteError::NotFound) => client
            .report_summary(Some(correlation))
            .await
            .map(|_| ())
            .map_err(refused_or_remote),
        Err(e) => Err(refused_or_remote(e)),
    }
}

fn refused_or_remote(error: RemoteError) -> ConsoleError {
    match error {
        RemoteError::AuthRefused { .. } => ConsoleError::Local(AppError::Validation(
            "credential_refused: the customer server refused a call signed with this \
             credential (wrong client, key or secret, a disallowed address, or no \
             metadata.rollout privilege)"
                .into(),
        )),
        other => ConsoleError::Remote(other),
    }
}

async fn load(state: &FleetState, id: Uuid) -> Result<DeploymentRow, AppError> {
    store::get_deployment(&state.xrm.base.db, id)
        .await?
        .ok_or(AppError::NotFound)
}

fn local_action(
    actor: Uuid,
    deployment: Option<Uuid>,
    action: &'static str,
    detail: Value,
) -> ActionWrite {
    ActionWrite {
        id: Uuid::now_v7(),
        actor_ref: actor,
        deployment_ref: deployment,
        rollout_ref: None,
        action,
        remote_method: None,
        remote_path: None,
        remote_status: None,
        outcome: "ok",
        detail,
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/fleet/deployments",
    tag = "fleet",
    params(DeploymentFilter, OnePageQuery),
    responses(
        (status = 200, description = "Registered deployments with their latest probe and drift", body = PaginatedResponse<DeploymentView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn list_deployments(
    State(state): State<FleetState>,
    _ctx: Authorized<Admin>,
    _session: HumanSession,
    Query(filter): Query<DeploymentFilter>,
    Query(paging): Query<OnePageQuery>,
) -> ConsoleResult<Json<PaginatedResponse<DeploymentView>>> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let (rows, total) = store::list_deployments(
        &state.xrm.base.db,
        filter.include_inactive,
        page_size,
        offset,
    )
    .await?;
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let observations = store::observations_for(&state.xrm.base.db, &ids).await?;
    let console = ConsoleRelease::read(&state).await;
    let items = rows
        .into_iter()
        .map(|row| {
            let observation = observations.iter().find(|o| o.deployment_ref == row.id);
            view(row, observation, &console)
        })
        .collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/deployments",
    tag = "fleet",
    request_body = RegisterDeploymentBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Registered", body = DeploymentView),
        (status = 401, description = "Missing credentials, or `reauth_required` when a credential is included without a fresh step-up", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 409, description = "fleet_deployment_exists: this project code and environment are registered", body = ErrorResponse),
        (status = 422, description = "A field fails validation, or credential_refused", body = ErrorResponse),
        (status = 502, description = "fleet_remote_error: the credential check could not reach the customer", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn register_deployment(
    State(state): State<FleetState>,
    ctx: Authorized<Admin>,
    session: HumanSession,
    Json(body): Json<RegisterDeploymentBody>,
) -> ConsoleResult<(StatusCode, Json<DeploymentView>)> {
    let fields = DeploymentFields {
        project_code: project_code(&body.project_code)?,
        label: text("label", &body.label, MAX_LABEL)?,
        environment: one_of(
            "environment",
            body.environment.as_deref().unwrap_or("prod"),
            &ENVIRONMENTS,
        )?,
        ring: one_of("ring", body.ring.as_deref().unwrap_or("broad"), &RINGS)?,
        base_url: normalize_base_url(&body.base_url)?,
        maintenance_window: window(body.maintenance_window.as_deref())?,
        is_active: true,
    };
    let credential = body.credential.as_ref().map(parse_credential).transpose()?;
    let id = Uuid::now_v7();
    let mut action = local_action(
        ctx.user_id,
        Some(id),
        "register",
        json!({ "credential": credential.is_some() }),
    );
    let sealed = match &credential {
        Some(credential) => {
            require_step_up(&state, session, ctx.user_id).await?;
            verify_credential(&state, &fields.base_url, credential, action.id).await?;
            Some(crypto::seal(state.runtime.ring(), id, &credential.secret)?)
        }
        None => None,
    };
    let category = if credential.is_some() {
        MandatoryCategory::Credential
    } else {
        MandatoryCategory::Configuration
    };
    let mut stx = SecurityTx::begin(
        &state.xrm,
        SecurityEvent::new(
            category,
            AuditOperation::Create,
            ctx.user_id,
            ENTITY,
            Some(id),
        )
        .named("fleet.deployment.register"),
    )
    .await?;
    let mut row = store::insert_deployment(&mut stx, id, &fields).await?;
    if let (Some(credential), Some(sealed)) = (&credential, &sealed) {
        row = version_conflict_if_none(
            store::set_credential(
                &mut stx,
                id,
                row.row_version,
                &credential.client_id,
                &credential.key_id,
                sealed,
                &credential.secret.last4(),
            )
            .await?,
        )?;
        action.detail["verified"] = Value::Bool(true);
    }
    store::insert_action(&mut stx, &action).await?;
    stx.commit().await?;
    Ok((StatusCode::CREATED, Json(view_one(&state, row).await?)))
}

#[utoipa::path(
    get,
    path = "/api/v1/fleet/deployments/{id}",
    tag = "fleet",
    params(("id" = Uuid, Path, description = "Deployment id")),
    responses(
        (status = 200, description = "The deployment with its latest probe and drift", body = DeploymentView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such deployment", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn get_deployment(
    State(state): State<FleetState>,
    _ctx: Authorized<Admin>,
    _session: HumanSession,
    Path(id): Path<Uuid>,
) -> ConsoleResult<Json<DeploymentView>> {
    let row = load(&state, id).await?;
    Ok(Json(view_one(&state, row).await?))
}

#[utoipa::path(
    patch,
    path = "/api/v1/fleet/deployments/{id}",
    tag = "fleet",
    params(("id" = Uuid, Path, description = "Deployment id")),
    request_body = UpdateDeploymentBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Updated", body = DeploymentView),
        (status = 401, description = "Missing credentials, or `reauth_required` when base_url moves a deployment that holds a credential without a fresh step-up", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such deployment", body = ErrorResponse),
        (status = 409, description = "version_conflict, or fleet_deployment_exists", body = ErrorResponse),
        (status = 422, description = "A field fails validation, or credential_refused at the new base_url", body = ErrorResponse),
        (status = 502, description = "fleet_remote_error: the new base_url could not be reached", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn update_deployment(
    State(state): State<FleetState>,
    ctx: Authorized<Admin>,
    session: HumanSession,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateDeploymentBody>,
) -> ConsoleResult<Json<DeploymentView>> {
    let current = load(&state, id).await?;
    let fields = DeploymentFields {
        project_code: current.project_code.clone(),
        label: match &body.label {
            Some(label) => text("label", label, MAX_LABEL)?,
            None => current.label.clone(),
        },
        environment: match &body.environment {
            Some(value) => one_of("environment", value, &ENVIRONMENTS)?,
            None => current.environment.clone(),
        },
        ring: match &body.ring {
            Some(value) => one_of("ring", value, &RINGS)?,
            None => current.ring.clone(),
        },
        base_url: match &body.base_url {
            Some(value) => normalize_base_url(value)?,
            None => current.base_url.clone(),
        },
        maintenance_window: match &body.maintenance_window {
            Some(value) => window(Some(value))?,
            None => current.maintenance_window.clone(),
        },
        is_active: body.is_active.unwrap_or(current.is_active),
    };
    // Moving a deployment that holds a credential redirects signed traffic:
    // that is a credential change (design §2.5), so it needs a fresh step-up
    // and one signed call to the new address with the stored credential.
    if fields.base_url != current.base_url && current.has_credential() {
        require_step_up(&state, session, ctx.user_id).await?;
        let moved = DeploymentRow {
            base_url: fields.base_url.clone(),
            ..current.clone()
        };
        let client = state.runtime.customer(&state.xrm.base.db, &moved).await?;
        let correlation = Some(Uuid::now_v7());
        match client.rollout_status(correlation).await {
            Ok(_) => {}
            Err(RemoteError::NotFound) => {
                client
                    .report_summary(correlation)
                    .await
                    .map_err(refused_or_remote)?;
            }
            Err(e) => return Err(refused_or_remote(e)),
        }
    }
    let name = if current.is_active && !fields.is_active {
        "deactivate"
    } else {
        "update"
    };
    let action = local_action(
        ctx.user_id,
        Some(id),
        name,
        json!({ "base_url_changed": fields.base_url != current.base_url }),
    );
    let mut stx = SecurityTx::begin(
        &state.xrm,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            ENTITY,
            Some(id),
        )
        .named("fleet.deployment.update"),
    )
    .await?;
    let row = version_conflict_if_none(
        store::update_deployment(&mut stx, id, body.row_version, &fields).await?,
    )?;
    store::insert_action(&mut stx, &action).await?;
    stx.commit().await?;
    Ok(Json(view_one(&state, row).await?))
}

#[utoipa::path(
    put,
    path = "/api/v1/fleet/deployments/{id}/credential",
    tag = "fleet",
    params(("id" = Uuid, Path, description = "Deployment id")),
    request_body = SetCredentialBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Credential, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Stored (encrypted); only secret_last4 is ever shown", body = DeploymentView),
        (status = 401, description = "Missing credentials, or `reauth_required` without a fresh step-up", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such deployment", body = ErrorResponse),
        (status = 409, description = "version_conflict", body = ErrorResponse),
        (status = 422, description = "A field fails validation, or credential_refused", body = ErrorResponse),
        (status = 502, description = "fleet_remote_error: the check could not reach the customer", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn set_credential(
    State(state): State<FleetState>,
    ctx: Authorized<Admin>,
    session: HumanSession,
    Path(id): Path<Uuid>,
    Json(body): Json<SetCredentialBody>,
) -> ConsoleResult<Json<DeploymentView>> {
    let current = load(&state, id).await?;
    let credential = parse_credential(&body.credential)?;
    require_step_up(&state, session, ctx.user_id).await?;
    let action = local_action(
        ctx.user_id,
        Some(id),
        "rotate_secret",
        json!({ "verified": body.verify, "had_credential": current.has_credential() }),
    );
    if body.verify {
        verify_credential(&state, &current.base_url, &credential, action.id).await?;
    }
    let sealed = crypto::seal(state.runtime.ring(), id, &credential.secret)?;
    let mut stx = SecurityTx::begin(
        &state.xrm,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Update,
            ctx.user_id,
            ENTITY,
            Some(id),
        )
        .named("fleet.credential.set"),
    )
    .await?;
    let row = version_conflict_if_none(
        store::set_credential(
            &mut stx,
            id,
            body.row_version,
            &credential.client_id,
            &credential.key_id,
            &sealed,
            &credential.secret.last4(),
        )
        .await?,
    )?;
    store::insert_action(&mut stx, &action).await?;
    stx.commit().await?;
    Ok(Json(view_one(&state, row).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/deployments/{id}/sync",
    tag = "fleet",
    params(("id" = Uuid, Path, description = "Deployment id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Probed now; a failed probe is recorded as observation.error_code", body = DeploymentView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such deployment", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn sync_deployment(
    State(state): State<FleetState>,
    ctx: Authorized<Admin>,
    _session: HumanSession,
    Path(id): Path<Uuid>,
) -> ConsoleResult<Json<DeploymentView>> {
    let row = load(&state, id).await?;
    let mut action = local_action(ctx.user_id, Some(id), "sync", json!({}));
    let (observation, probe) =
        poll::sync_one(&state.xrm, &state.runtime, &row, Some(action.id)).await?;
    action.remote_method = Some("GET");
    action.remote_path = Some(crate::client::paths::ROLLOUT_STATUS.to_owned());
    action.remote_status = probe.error.as_ref().and_then(RemoteError::status);
    let mut event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Update,
        ctx.user_id,
        ENTITY,
        Some(id),
    )
    .named("fleet.deployment.sync");
    if let Some(error) = &probe.error {
        action.outcome = if matches!(error, RemoteError::AuthRefused { .. }) {
            "refused"
        } else {
            "failed"
        };
        action.detail = json!({ "error": error.code() });
        event = event.outcome(AuditOutcome::Failed);
    }
    record(&state, event, &action).await?;
    let console = ConsoleRelease::read(&state).await;
    Ok(Json(view(row, Some(&observation), &console)))
}

#[utoipa::path(
    post,
    path = "/api/v1/fleet/sync",
    tag = "fleet",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 202, description = "A sync of every active deployment is queued (FleetPoll)", body = SyncQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn sync_all(
    State(state): State<FleetState>,
    ctx: Authorized<Admin>,
    _session: HumanSession,
) -> ConsoleResult<(StatusCode, Json<SyncQueued>)> {
    let action = local_action(ctx.user_id, None, "sync_all", json!({}));
    let mut stx = SecurityTx::begin(
        &state.xrm,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            ENTITY,
            None,
        )
        .named("fleet.sync_all"),
    )
    .await?;
    let queued = attome_jobs::enqueue_in_tx_dedup(
        stx.tx(),
        attome_core::jobs::EngineJob::FleetPoll,
        FLEET_POLL_KEY,
    )
    .await
    .map_err(AppError::internal)?;
    store::insert_action(&mut stx, &action).await?;
    stx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(SyncQueued { queued })))
}

#[utoipa::path(
    get,
    path = "/api/v1/fleet/deployments/{id}/actions",
    tag = "fleet",
    params(("id" = Uuid, Path, description = "Deployment id"), OnePageQuery),
    responses(
        (status = 200, description = "The console's actions on this deployment, newest first", body = PaginatedResponse<ActionView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 404, description = "No such deployment", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn list_actions(
    State(state): State<FleetState>,
    _ctx: Authorized<Admin>,
    _session: HumanSession,
    Path(id): Path<Uuid>,
    Query(paging): Query<OnePageQuery>,
) -> ConsoleResult<Json<PaginatedResponse<ActionView>>> {
    load(&state, id).await?;
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let (rows, total) = store::list_actions(&state.xrm.base.db, id, page_size, offset).await?;
    Ok(Json(PaginatedResponse::new(
        rows.into_iter().map(ActionView::from).collect(),
        total,
        page,
        page_size,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/fleet/changesets",
    tag = "fleet",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Closed changeset files under fleet.changesets_dir, platform first, by seq", body = PaginatedResponse<ChangesetFile>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not system.admin, not a cookie session, or not a loopback peer", body = ErrorResponse),
        (status = 422, description = "fleet.changesets_dir does not exist", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn list_changesets(
    State(state): State<FleetState>,
    _ctx: Authorized<Admin>,
    _session: HumanSession,
    Query(paging): Query<OnePageQuery>,
) -> ConsoleResult<Json<PaginatedResponse<ChangesetFile>>> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let files = changesets::list(state.runtime.changesets_dir.clone()).await?;
    let total = files.len() as i64;
    let items = files
        .into_iter()
        .skip(usize::try_from(offset).unwrap_or(0))
        .take(usize::try_from(page_size).unwrap_or(0))
        .collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

pub fn routes() -> Router<FleetState> {
    Router::new()
        .route(
            "/api/v1/fleet/deployments",
            get(list_deployments).post(register_deployment),
        )
        .route(
            "/api/v1/fleet/deployments/{id}",
            get(get_deployment).patch(update_deployment),
        )
        .route(
            "/api/v1/fleet/deployments/{id}/credential",
            put(set_credential),
        )
        .route("/api/v1/fleet/deployments/{id}/sync", post(sync_deployment))
        .route("/api/v1/fleet/deployments/{id}/actions", get(list_actions))
        .route("/api/v1/fleet/sync", post(sync_all))
        .route("/api/v1/fleet/changesets", get(list_changesets))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_deployments,
    register_deployment,
    get_deployment,
    update_deployment,
    set_credential,
    sync_deployment,
    sync_all,
    list_actions,
    list_changesets
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn console(schema: Option<i64>) -> ConsoleRelease {
        ConsoleRelease {
            application_version: "4.0.1",
            schema_version: schema,
        }
    }

    fn observed(app: &str, schema: i64) -> ObservationRow {
        ObservationRow {
            application_version: Some(app.into()),
            schema_version: Some(schema),
            schema_dirty: Some(false),
            ..ObservationRow::default()
        }
    }

    #[test]
    fn drift_confirms_diverges_or_cannot_confirm() {
        assert_eq!(drift(None, &console(Some(543))).status, "never_observed");
        let same = drift(Some(&observed("4.0.1", 543)), &console(Some(543)));
        assert_eq!(same.status, "in_sync");
        assert_eq!(same.unconfirmed, ["image_digest", "config_hash"]);
        let behind = drift(Some(&observed("4.0.0", 540)), &console(Some(543)));
        assert_eq!(behind.status, "diverged");
        assert_eq!(behind.fields, ["schema_version", "application_version"]);
        let unknown = drift(Some(&observed("4.0.1", 543)), &console(None));
        assert_eq!(unknown.status, "in_sync");
        assert!(unknown.unconfirmed.contains(&"schema_version".to_string()));
        let dirty = ObservationRow {
            schema_dirty: Some(true),
            ..observed("4.0.1", 543)
        };
        assert_eq!(
            drift(Some(&dirty), &console(Some(543))).status,
            "schema_dirty"
        );
    }

    #[test]
    fn registry_fields_are_validated_and_normalized() {
        assert_eq!(project_code(" bmd ").unwrap(), "BMD");
        assert!(project_code("B").is_err());
        assert!(project_code("BMD-1").is_err());
        assert_eq!(one_of("ring", "Canary", &RINGS).unwrap(), "canary");
        assert!(one_of("environment", "staging", &ENVIRONMENTS).is_err());
        assert_eq!(window(Some("  ")).unwrap(), None);
        assert!(identifier("s2s_key_id", "has space").is_err());
        assert!(text("label", "", MAX_LABEL).is_err());
    }

    #[test]
    fn a_pasted_credential_is_parsed_without_echoing_the_secret() {
        let body = CredentialBody {
            s2s_client_id: "rollout-bmd".into(),
            s2s_key_id: "key-1".into(),
            secret: "nothex".into(),
        };
        let Err(AppError::Validation(message)) = parse_credential(&body) else {
            panic!("a non-hex secret must be refused");
        };
        assert!(!message.contains("nothex"));
    }
}
