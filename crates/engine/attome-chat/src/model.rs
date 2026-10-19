//! `EngineModel` registration: mounted only when the `chat` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_CHAT, ModuleId};
use axum::Router;

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct ChatModel;

impl EngineModel for ChatModel {
    fn name(&self) -> &'static str {
        "attome-chat"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_CHAT
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        // Channels and messages are infrastructure tables, not entities.
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::channels::routes()
    }
}
