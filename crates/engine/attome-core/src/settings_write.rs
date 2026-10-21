//! U10-T2: the seam an engine below `attome-api` writes a deployment setting
//! through. The settings API owns the write (its validation against the
//! registry, the boot-time-only refusal, the per-key lock, the change log,
//! the audit event); `attome-api` registers that one implementation on the
//! `EngineSystem` builder, so the settings agent tool writes exactly as
//! `PUT /api/v1/admin/settings/{key}` does. `None` on a bare state: a write
//! through the seam then answers as unavailable, never as a silent no-op.

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::state::EngineState;

/// The written setting as the admin API answers it.
pub type SettingWriteFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Value, AppError>> + Send + 'a>>;

/// Implemented once, by `attome-api`.
pub trait SettingsWriter: Send + Sync + 'static {
    /// Sets the deployment value of `key` as `actor`.
    fn write_deployment<'a>(
        &'a self,
        state: &'a EngineState,
        actor: Uuid,
        key: &'a str,
        value: Value,
    ) -> SettingWriteFuture<'a>;
}
