//! C5 (chatbot plan) — the seam through which an engine that cannot depend on
//! `attome-workflow` starts a published workflow.
//!
//! `attome-workflow` depends on `attome-ai` (its AI nodes dispatch AI actions), so
//! `attome-ai`'s `workflow.start` action cannot call `attome-workflow` directly
//! without a dependency cycle. The inversion follows the
//! [`crate::my_work::MyWorkProvider`] precedent: the trait lives here, the
//! owning engine implements it, and the composition root registers the one
//! implementation on the `EngineSystem` builder, which freezes it onto
//! [`crate::EngineState::workflow_starter`].
//!
//! **One start path, not two.** `attome-workflow`'s implementation is the same
//! function its `POST /api/v1/workflow/instances` handler calls — the
//! published/active/not-deleted definition lookup and the instance creation —
//! so an agent-started instance and a hand-started one cannot drift apart.
//!
//! **What the trait does not do: authorize.** It is "declaration, not
//! enforcement", the posture `my_work.rs` documents. The caller owns the
//! boundary the HTTP route enforces with `Authorized<Admin>` and the licence
//! gate enforces with `MODULE_WORKFLOW`; `attome-ai`'s executor checks both
//! before calling [`WorkflowStarter::start`].

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use uuid::Uuid;

use crate::state::EngineState;

/// What to start, and on whose behalf.
#[derive(Debug, Clone)]
pub struct WorkflowStartRequest {
    /// The workflow definition's logical name; its **published, active,
    /// not-deleted** version is started, or the start is refused.
    pub definition_logicalname: String,
    /// The human the instance is started by — recorded on the instance
    /// exactly as the manual-start route records its caller.
    pub started_by: Uuid,
    pub correlation_entity_id: Option<Uuid>,
    pub context: serde_json::Value,
}

/// The future [`WorkflowStarter::start`] returns — the same manually boxed
/// shape [`crate::my_work::MyWorkFuture`] uses (this workspace does not use
/// `async_trait`).
pub type WorkflowStartFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Uuid, AppError>> + Send + 'a>>;

/// Implemented once, by `attome-workflow`. Returns the new instance's id.
pub trait WorkflowStarter: Send + Sync + 'static {
    fn start<'a>(
        &'a self,
        state: &'a EngineState,
        request: WorkflowStartRequest,
    ) -> WorkflowStartFuture<'a>;
}
