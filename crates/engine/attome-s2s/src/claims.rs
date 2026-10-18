use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Attached to Axum request extensions for authenticated S2S calls.
/// Handlers can extract this to distinguish S2S callers from human users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S2SClaims {
    pub client_db_id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub key_db_id: Uuid,
    pub key_slot: String,
    /// The `user_account` the client acts as — the principal every
    /// downstream authz check and audit row is attributed to. Always present:
    /// `s2s_authn` rejects a client whose stored `service_user_ref` is NULL
    /// rather than substituting a placeholder (B9).
    pub service_user_id: Uuid,
    pub correlation_id: Option<String>,
    /// S1-T10: the user this request acts as (`x-attome-act-as`, for a client
    /// granted `can_act_as_user`); downstream checks and audit rows run as
    /// it, and the access log keeps both it and the client.
    #[serde(default)]
    pub acted_as_user_id: Option<Uuid>,
}
