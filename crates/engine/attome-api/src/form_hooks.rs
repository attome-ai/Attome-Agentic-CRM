//! A12-T4: form hooks. While a person works in a record form, the form asks
//! the server to run the entity's published extensions on its state: when
//! the form opens (`load`, extensions declaring `form_load`), when a value
//! changes (`change`, `form_change`), and before it saves (`before_save`:
//! the write pipeline's own `before_validation` and `before_save` hooks, run
//! ahead of the save so the person sees a refusal or a filled value first).
//! Customer code runs on the server only (no client WebAssembly for it), in
//! the same runtime, limits and grants as the write hooks; nothing is saved
//! here, and the save still runs every write hook itself.

use attome_core::EngineState;
use attome_core::record_hooks::HookOutcome;
use attome_extension::{HookInput, HookPoint};
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

/// A form event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FormEvent {
    Load,
    Change,
    BeforeSave,
}

impl FormEvent {
    /// The hook points the event runs, in order.
    fn points(self) -> &'static [HookPoint] {
        match self {
            Self::Load => &[HookPoint::FormLoad],
            Self::Change => &[HookPoint::FormChange],
            Self::BeforeSave => &[HookPoint::BeforeValidation, HookPoint::BeforeSave],
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Load => "load",
            Self::Change => "change",
            Self::BeforeSave => "before_save",
        }
    }
}

const EVENTS: [FormEvent; 3] = [FormEvent::Load, FormEvent::Change, FormEvent::BeforeSave];

/// The form events with at least one extension on `entity`. Pure over the
/// snapshot.
fn watched(entity: &str) -> Vec<&'static str> {
    EVENTS
        .iter()
        .filter(|event| {
            event
                .points()
                .iter()
                .any(|point| crate::extension_hooks::watches(entity, *point))
        })
        .map(|event| event.name())
        .collect()
}

/// Body of `POST /api/v1/{entity}/form-hooks`.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct FormHookBody {
    event: FormEvent,
    /// The record the form shows; absent for a new one.
    #[serde(default)]
    record_id: Option<Uuid>,
    /// The form's values now.
    #[schema(value_type = Object)]
    values: Map<String, Value>,
    /// The record's values as loaded, when there is one.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    previous: Option<Map<String, Value>>,
}

/// What the extensions answered.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct FormHookAnswer {
    /// Values the extensions set, for the form to fill in.
    #[schema(value_type = Object)]
    changes: Map<String, Value>,
    /// A refusal, in English; the form shows it (on `before_save`, instead
    /// of saving).
    rejection: Option<String>,
    /// The refusal in each language the extension wrote it in.
    #[schema(value_type = Object)]
    rejection_translations: std::collections::BTreeMap<String, String>,
    /// The form events with an extension on this entity, so the form calls
    /// only those.
    events: Vec<&'static str>,
}

/// Run form hooks
///
/// A12-T4: runs the entity's published extensions on the form's state for one event: `load`
/// (`form_load` hooks), `change` (`form_change`) or `before_save` (the write pipeline's
/// `before_validation` and `before_save` hooks, ahead of the save). Each extension sees only the
/// attributes its grants let it read and may set only those it may write; its changes carry to the
/// next. Nothing is saved; a refusal comes back as `rejection`. Every call is logged as the
/// extension's run. Needs read access to the entity's records.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/form-hooks",
    operation_id = "run_form_hooks",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name")),
    request_body = FormHookBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::DryRun, None, "runs the entity's extensions on the form's unsaved values and returns their answer; nothing is saved (the save runs the write hooks again under its own audit)")))),
    responses(
        (status = 200, description = "The extensions' answer", body = FormHookAnswer),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not read the entity's records", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "An extension failed", body = ErrorResponse),
        (status = 503, description = "An extension on this entity could not be loaded", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn run_form_hooks(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(entity): Path<String>,
    Json(body): Json<FormHookBody>,
) -> Result<Json<FormHookAnswer>, AppError> {
    if state.entities.load().get(&entity).is_none() {
        return Err(AppError::NotFound);
    }
    ctx.require(&entity, "read")?;
    let mut answer = FormHookAnswer {
        changes: Map::new(),
        rejection: None,
        rejection_translations: std::collections::BTreeMap::new(),
        events: watched(&entity),
    };
    if !answer.events.contains(&body.event.name()) {
        return Ok(Json(answer));
    }
    let mut values = body.values;
    for point in body.event.points() {
        let input = HookInput {
            stage: *point,
            entity: entity.clone(),
            record_id: body.record_id.map(|id| id.to_string()),
            is_create: body.record_id.is_none(),
            values: values.clone(),
            previous: body.previous.clone(),
            actor: Some(ctx.user_id.to_string()),
        };
        match crate::extension_hooks::run_point(&state, input).await? {
            HookOutcome::Continue => {}
            HookOutcome::Change(set) => {
                values.extend(set.clone());
                answer.changes.extend(set);
            }
            HookOutcome::Reject(rejection) => {
                answer.rejection = Some(rejection.message);
                answer.rejection_translations = rejection.translations;
                break;
            }
        }
    }
    Ok(Json(answer))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/{entity}/form-hooks", post(run_form_hooks))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(run_form_hooks))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn form_events_run_their_hook_points() {
        assert_eq!(FormEvent::Load.points(), &[HookPoint::FormLoad]);
        assert_eq!(FormEvent::Change.points(), &[HookPoint::FormChange]);
        assert_eq!(
            FormEvent::BeforeSave.points(),
            &[HookPoint::BeforeValidation, HookPoint::BeforeSave]
        );
        let event: FormEvent = serde_json::from_value(json!("before_save")).unwrap();
        assert_eq!(event, FormEvent::BeforeSave);
        assert!(watched("no_such_entity_for_form_hooks").is_empty());
    }
}
