//! N12-T1: the admin API's entity and field create paths as the agent's
//! build tools (`attome_ai::actions::schema_build`), installed when the
//! engine system is built.
//!
//! Each write records into a changeset as the admin route's does. In a
//! workspace's own process (T5-T3) that is the workspace's changeset, so a
//! building agent working in a workspace drafts there; on live it is the
//! caller's open changeset, or an automatic one, per the deployment's
//! changeset mode.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use attome_ai::actions::schema_build::{self, SchemaBuilder};
use attome_core::EngineState;
use attome_core::changeset::{Recording, RequestContext};
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::admin::{CreateAttributeBody, CreateEntityBody, create_entity_core};

/// The workspace this process serves, when it is a workspace's own process.
static CURRENT: OnceLock<Uuid> = OnceLock::new();

/// Marks this process as workspace `id`'s own (`attome serve --workspace`).
pub fn serve_workspace(id: Uuid) -> bool {
    CURRENT.set(id).is_ok()
}

/// The workspace this process serves, if any.
pub fn current_workspace() -> Option<Uuid> {
    CURRENT.get().copied()
}

/// Installs the build tools' create paths.
pub fn install() -> bool {
    schema_build::install(Arc::new(ApiSchemaBuilder))
}

/// The recording a build tool's write goes into: the workspace's changeset in
/// a workspace's process, else the deployment's rule for an admin write.
async fn recording(state: &EngineState, user: Uuid, tool: &str) -> Result<Recording, AppError> {
    let changesets = &state.base.config.metadata.changesets;
    let header = match current_workspace() {
        Some(workspace) => {
            let changeset: Option<Uuid> = sqlx::query_scalar(
                "SELECT changeset_ref FROM develop_workspace WHERE id = $1 AND status = 'open'",
            )
            .bind(workspace)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .flatten();
            Some(changeset.ok_or(AppError::Conflict(
                "this workspace is not open, or records no changeset",
            ))?)
        }
        None => None,
    };
    Ok(Recording::for_request(RequestContext {
        header,
        actor: Some(user),
        actor_label: format!("user:{user}"),
        request_id: None,
        route: format!("AGENT {tool}"),
        mode: changesets.effective_mode(&state.base.config.app.deployment_profile),
        auto_layer: changesets.auto_layer,
        break_glass: false,
    }))
}

/// The entity `reference` names: an id, or a logical name.
async fn entity_id(state: &EngineState, reference: &str) -> Result<Uuid, AppError> {
    if let Ok(id) = Uuid::parse_str(reference) {
        return Ok(id);
    }
    sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
        .bind(reference.trim().to_lowercase())
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

#[derive(Debug)]
struct ApiSchemaBuilder;

impl SchemaBuilder for ApiSchemaBuilder {
    fn create_entity<'a>(
        &'a self,
        state: &'a EngineState,
        user: Uuid,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let body: CreateEntityBody = serde_json::from_value(args.clone())
                .map_err(|e| AppError::Validation(format!("invalid entity: {e}")))?;
            let recording = recording(state, user, schema_build::ENTITY_CREATE).await?;
            recording.preflight(&state.base.db_migrator).await?;
            let meta = create_entity_core(state, user, &recording, body).await?;
            serde_json::to_value(meta).map_err(AppError::internal)
        })
    }

    fn create_attribute<'a>(
        &'a self,
        state: &'a EngineState,
        user: Uuid,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let reference = args["entity"]
                .as_str()
                .ok_or_else(|| AppError::Validation("entity: the entity's name or id".into()))?;
            let entity = entity_id(state, reference).await?;
            let mut fields = args.clone();
            if let Value::Object(map) = &mut fields {
                map.remove("entity");
            }
            let body: CreateAttributeBody = serde_json::from_value(fields.clone())
                .map_err(|e| AppError::Validation(format!("invalid field: {e}")))?;
            let recording = recording(state, user, schema_build::ATTRIBUTE_CREATE).await?;
            recording.preflight(&state.base.db_migrator).await?;
            // The field route's own gate: a schema change may need a second
            // administrator's approval first.
            if let Some(request) = crate::approval_admin::gate(
                state,
                crate::admin::ACTION_SCHEMA_CHANGE,
                serde_json::json!({ "op": "create", "entity_id": entity, "body": fields }),
                user,
            )
            .await?
            {
                return Ok(serde_json::json!({
                    "approval_pending": true,
                    "approval_request_id": request.id,
                }));
            }
            let response = crate::admin::do_create_attribute_recorded(
                state,
                entity,
                user,
                body,
                Some(&recording),
            )
            .await?;
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .map_err(AppError::internal)?;
            let mut answer: Value = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).map_err(AppError::internal)?
            };
            if let Value::Object(map) = &mut answer {
                map.insert("status".into(), Value::from(status.as_u16()));
            }
            Ok(answer)
        })
    }
}
