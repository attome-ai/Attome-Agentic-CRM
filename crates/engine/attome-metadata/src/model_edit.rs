//! The registered metadata kinds and the one edit path (roadmap Y1-T9,
//! Y1-T14): the admin API's `POST .../commands` and the agents' generated
//! `model.<kind>.edit` tools both save drafts through [`edit`], so a person
//! and an agent change metadata the same way. Each caller checks that the
//! actor is an administrator and writes its own audit event in the same
//! transaction.

use std::sync::{Arc, OnceLock};

use attome_db::{DbPool, Tx};
use attome_model::commands::{self, Command};
use attome_model::store::{self, DraftSaved, ObjectSpec};
use attome_model::{Kind, KindRegistry, Layer, ObjectId};
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// The kinds every engine registers: forms and agents (stored in the model)
/// and the adapters over their own tables.
fn registered_kinds() -> Vec<Arc<dyn Kind>> {
    let mut kinds: Vec<Arc<dyn Kind>> = vec![
        Arc::new(attome_model::kinds::FormKind),
        Arc::new(attome_model::kinds::AgentKind),
        Arc::new(attome_model::kinds::NavigationKind),
        Arc::new(attome_model::kinds::OptionSetKind),
        Arc::new(attome_model::kinds::EvalSuiteKind),
        Arc::new(attome_model::kinds::PromptOverrideKind),
        Arc::new(attome_model::kinds::ReplyTemplateKind),
        Arc::new(attome_model::kinds::TourKind),
        Arc::new(attome_model::kinds::EnvironmentVariableKind),
        Arc::new(attome_model::kinds::RecordTypeKind),
        Arc::new(attome_model::kinds::FlowTemplateKind),
        Arc::new(attome_model::kinds::ComponentKind),
    ];
    for adapter in crate::kinds::ADAPTER_KINDS {
        kinds.push(Arc::new(adapter));
    }
    kinds
}

/// The process-wide kind registry.
pub fn registry() -> &'static KindRegistry {
    static KINDS: OnceLock<KindRegistry> = OnceLock::new();
    KINDS.get_or_init(|| {
        let mut registry = KindRegistry::default();
        for kind in registered_kinds() {
            if let Err(error) = registry.register(kind) {
                tracing::error!(%error, "metadata kind registered twice; the second is ignored");
            }
        }
        registry
    })
}

/// What [`edit`] saved.
#[derive(Debug, Clone)]
pub struct Edited {
    /// The object's name (its existing one, or the one given for a new
    /// object).
    pub name: String,
    pub commands: usize,
    pub saved: DraftSaved,
}

/// One edit, as the admin API and the agent tools receive it.
#[derive(Debug, Clone)]
pub struct EditRequest {
    pub id: Uuid,
    /// The content hash the commands were made against; empty for a new
    /// object.
    pub base_hash: String,
    /// Required when the object does not exist yet.
    pub name: Option<String>,
    /// `add`/`remove`/`move`/`set` commands as raw JSON, parsed here.
    pub commands: Vec<Value>,
}

/// Applies an edit to the object's draft, creating the object on its first
/// edit, inside the caller's transaction.
pub async fn edit(
    db: &DbPool,
    tx: &mut Tx<'_>,
    kind: &dyn Kind,
    request: EditRequest,
    actor: Option<Uuid>,
) -> Result<Edited, AppError> {
    let EditRequest {
        id,
        base_hash,
        name,
        commands,
    } = request;
    let parsed: Vec<Command> = commands
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()
        .map_err(|error| AppError::Validation(format!("a command is malformed: {error}")))?;
    let name = match store::read(db, id, None).await {
        Ok(existing) if existing.kind != kind.name().as_str() => return Err(AppError::NotFound),
        Ok(existing) => existing.name,
        Err(AppError::NotFound) => name.ok_or_else(|| {
            AppError::Validation("name is required for an object that does not exist yet".into())
        })?,
        Err(other) => return Err(other),
    };
    let object = ObjectSpec {
        id: ObjectId(id),
        name: name.clone(),
        app: "customer".to_owned(),
        layer: Layer::Customer,
    };
    let saved =
        commands::apply_commands(tx, registry(), kind, &object, &base_hash, &parsed, actor).await?;
    Ok(Edited {
        name,
        commands: parsed.len(),
        saved,
    })
}
