use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Category of the audit event.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditCategory {
    Entity = 0,
    Security = 1,
    BusinessEvent = 2,
    Attachment = 3,
    Relationship = 4,
    // D-541 rule 1 (audit gate G3) — appended; never renumber (I9).
    /// Passwords, API keys, S2S clients/keys/secrets, MFA factors, sessions
    /// and refresh tokens.
    Credential = 5,
    /// Roles, role grants, user-roles, teams, positions, organizations, field
    /// security, shares, access reviews.
    Access = 6,
    /// Views, sidebar, queries, non-`Entity` metadata, audit policy, system
    /// settings.
    Configuration = 7,
    /// Licence import, activation and module changes.
    License = 8,
    /// Agent-executed actions and AI configuration with governance effect.
    Ai = 9,
}

/// Operation performed. Variants 0–8 are entity ops; 9–14 security; 15–20 business events.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOperation {
    // Entity
    Create = 0,
    Update = 1,
    SoftDelete = 2,
    HardDelete = 3,
    Restore = 4,
    Merge = 5,
    Clone = 6,
    Import = 7,
    Export = 8,
    // Security
    Login = 9,
    Logout = 10,
    FailedLogin = 11,
    PermissionChange = 12,
    RoleChange = 13,
    OwnerChange = 14,
    // Business events
    Approved = 15,
    Rejected = 16,
    Submitted = 17,
    Cancelled = 18,
    Closed = 19,
    Activated = 20,
    /// D-107 — a record's `audit_erasure_key` was destroyed (crypto-shredding).
    /// Appended here rather than inserted into the numbered ranges above so
    /// no existing stored value's discriminant changes.
    Erasure = 21,
    /// An administrator force-cleared a user's MFA enrollment for lost-device
    /// recovery. Appended to preserve every previously persisted discriminant.
    MfaReset = 22,
    /// An administrator disabled/re-enabled a `user_account` row
    /// (P-account-state-enforcement, audit finding #2). Two variants rather
    /// than one + a boolean field, matching this enum's existing shape (e.g.
    /// `Approved`/`Rejected`) — appended to preserve every previously
    /// persisted discriminant.
    AccountDisabled = 23,
    AccountEnabled = 24,
    /// P-file-upload-pipeline — a finalized upload session's async
    /// malware/content-disarm scan reached a terminal result (`clean` or
    /// `rejected`). Distinct from the ordinary `Update` event
    /// `entity_crud.rs` writes when the promoted key is later PATCHed onto
    /// the record's column — this is the evidence trail for the scan
    /// itself. Appended to preserve every previously persisted discriminant.
    FileScanned = 25,
    /// D-421 / M10 (Approval & Governance) — a plan-bearing approval
    /// request's current step fired its `on_timeout: escalate` policy (a
    /// notification went to that step's eligible approvers; the request
    /// itself is still `pending`, unlike `Approved`/`Rejected`, which is
    /// what an `on_timeout: auto_approve`/`auto_reject` sweep writes
    /// instead — see `attome_audit::approval::apply_and_audit_step_timeout`).
    /// Appended to preserve every previously persisted discriminant.
    Escalated = 26,
    /// D-442 / M58 Phase 1 (Digital Signature, internal sign-off) — a
    /// `approval_grant` decision's non-repudiation digest was
    /// computed and stored (`approval_grant.signature`), recorded
    /// here as its OWN event (in addition to the `Approved`/`Rejected` event
    /// `decide_approval` already writes for the same decision) so the
    /// existing hash chain + epoch seal + external anchor mechanisms cover
    /// its existence/ordering the same way they cover every other event —
    /// see `attome_audit::signoff`. Appended to preserve every previously
    /// persisted discriminant.
    DecisionDigest = 27,
    // D-541 rule 2 (audit gate G3) — appended; never renumber (I9).
    /// A role, privilege or share was granted.
    Grant = 28,
    /// A role, share or API key was revoked; an S2S key was disabled.
    Revoke = 29,
    /// An API key, S2S secret, signing key or recovery-code set was rotated.
    Rotate = 30,
    /// The audit trail was read or searched; a restricted value was revealed.
    View = 31,
    /// An evidence or audit export file was downloaded.
    Download = 32,
    /// A setting changed where Create/Update/SoftDelete do not fit.
    ConfigChange = 33,
    /// An approved action or an AI agent action was executed.
    Execute = 34,
    /// A password reset was requested or confirmed (`outcome` distinguishes).
    PasswordReset = 35,
    /// An administrator revoked sessions, or refresh-token reuse revoked a family.
    SessionRevoked = 36,
    /// Self-service MFA enrolment confirmed.
    MfaEnrolled = 37,
    /// Self-service MFA disabled (the admin path keeps `MfaReset`).
    MfaDisabled = 38,
    /// Bulk parent event: accepted (plan 3.10).
    BulkAccepted = 39,
    /// Bulk parent event: terminal state (plan 3.10).
    BulkCompleted = 40,
    /// Late evidence attachment (plan 7.4).
    Attached = 41,
}

/// D-541 rule 3: the `audit_header.outcome` column (hash v2 field 25).
/// NULL — `None` at the call site — means not applicable.
#[repr(i16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    Succeeded = 0,
    Failed = 1,
    PartiallyFailed = 2,
    Cancelled = 3,
}

/// D-541 rule 3: the outcome and count columns of `audit_header` (hash v2
/// fields 25-29), plus the AI governance columns of contract C19 (fields 23
/// and 24). Carried beside an [`AuditEvent`] rather than on it, so the
/// event's many existing struct literals stay unchanged; every field is
/// `None` (a NULL column) unless the writer sets it. Travels in the ingest
/// payload, so the chainer path keeps every field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventExtras {
    /// C19: the provider model id an AI action ran under (hash v2 field 23).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_model_id: Option<String>,
    /// C19: the approval request an AI action was executed under (field 24).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_ref: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<AuditOutcome>,
    /// Set only on `BulkAccepted`/`BulkCompleted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_count: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_count: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_count: Option<i32>,
    /// Set only on coalesced events (D-541 rule 6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence_count: Option<i32>,
}

impl EventExtras {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    pub fn outcome_i16(&self) -> Option<i16> {
        self.outcome.map(|o| o as i16)
    }
}

/// Where the operation originated.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditSource {
    WebForm = 0,
    Api = 1,
    Mobile = 2,
    Import = 3,
    Workflow = 4,
    Plugin = 5,
    BackgroundJob = 6,
    Integration = 7,
    MigrationTool = 8,
}

/// Snapshot of the acting user — denormalized so audit reads never need joins.
/// Users can rename themselves; storing here preserves the name at the time of the event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditUserContext {
    pub user_id: Uuid,
    pub user_name: String,
    pub user_display_name: String,
    pub user_email: String,
    pub user_job_ref: Option<Uuid>,
    pub user_job_name: Option<String>,
}

/// Context captured from the inbound HTTP request.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditRequestContext {
    pub ip_address: Option<String>,
    pub browser: Option<String>,
    /// 0 = Desktop, 1 = Tablet, 2 = Mobile
    pub device_type: Option<i32>,
}

/// One changed field within an audit event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditFieldChange {
    pub field_name: String,
    pub display_name: Option<String>,
    /// Maps to the data_type column (0=Text, 1=Number, 3=DateTime, 4=Bool, 5=Lookup, 6=OptionSet…)
    pub data_type: Option<i32>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub old_display_value: Option<String>,
    pub new_display_value: Option<String>,
    pub old_lookup_entity: Option<String>,
    pub old_lookup_name: Option<String>,
    pub new_lookup_entity: Option<String>,
    pub new_lookup_name: Option<String>,
    /// When true the value is masked before storage.
    pub is_sensitive: bool,
}

/// Full audit event — one per business operation.
/// Pass to `AuditService::write` to persist header + details + optional snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub organization_ref: Uuid,
    pub category: AuditCategory,
    pub entity_name: Option<String>,
    pub record_id: Option<Uuid>,
    pub operation: AuditOperation,
    pub version_before: Option<i64>,
    pub version_after: Option<i64>,
    pub user_context: AuditUserContext,
    pub changed_on: DateTime<Utc>,
    pub source: AuditSource,
    pub request_context: AuditRequestContext,
    pub correlation_id: Option<Uuid>,
    pub batch_id: Option<Uuid>,
    /// Business event label (populated when category = BusinessEvent).
    pub event_name: Option<String>,
    pub event_comment: Option<String>,
    /// Field-level changes (empty for security/business-event categories).
    pub changed_fields: Vec<AuditFieldChange>,
    /// When Some, also writes a audit_snapshot row.
    pub snapshot_json: Option<serde_json::Value>,
}

impl AuditCategory {
    /// The snake_case name `x-audit` annotations use (D-542 rule 1).
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Entity => "entity",
            Self::Security => "security",
            Self::BusinessEvent => "business_event",
            Self::Attachment => "attachment",
            Self::Relationship => "relationship",
            Self::Credential => "credential",
            Self::Access => "access",
            Self::Configuration => "configuration",
            Self::License => "license",
            Self::Ai => "ai",
        }
    }
}

impl AuditOperation {
    /// The snake_case name `x-audit` annotations use (D-542 rule 1).
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::SoftDelete => "soft_delete",
            Self::HardDelete => "hard_delete",
            Self::Restore => "restore",
            Self::Merge => "merge",
            Self::Clone => "clone",
            Self::Import => "import",
            Self::Export => "export",
            Self::Login => "login",
            Self::Logout => "logout",
            Self::FailedLogin => "failed_login",
            Self::PermissionChange => "permission_change",
            Self::RoleChange => "role_change",
            Self::OwnerChange => "owner_change",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Submitted => "submitted",
            Self::Cancelled => "cancelled",
            Self::Closed => "closed",
            Self::Activated => "activated",
            Self::Erasure => "erasure",
            Self::MfaReset => "mfa_reset",
            Self::AccountDisabled => "account_disabled",
            Self::AccountEnabled => "account_enabled",
            Self::FileScanned => "file_scanned",
            Self::Escalated => "escalated",
            Self::DecisionDigest => "decision_digest",
            Self::Grant => "grant",
            Self::Revoke => "revoke",
            Self::Rotate => "rotate",
            Self::View => "view",
            Self::Download => "download",
            Self::ConfigChange => "config_change",
            Self::Execute => "execute",
            Self::PasswordReset => "password_reset",
            Self::SessionRevoked => "session_revoked",
            Self::MfaEnrolled => "mfa_enrolled",
            Self::MfaDisabled => "mfa_disabled",
            Self::BulkAccepted => "bulk_accepted",
            Self::BulkCompleted => "bulk_completed",
            Self::Attached => "attached",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn categories() -> Vec<(AuditCategory, i32)> {
        use AuditCategory as C;
        vec![
            (C::Entity, 0),
            (C::Security, 1),
            (C::BusinessEvent, 2),
            (C::Attachment, 3),
            (C::Relationship, 4),
            (C::Credential, 5),
            (C::Access, 6),
            (C::Configuration, 7),
            (C::License, 8),
            (C::Ai, 9),
        ]
    }

    fn operations() -> Vec<(AuditOperation, i32)> {
        use AuditOperation as O;
        vec![
            (O::Create, 0),
            (O::Update, 1),
            (O::SoftDelete, 2),
            (O::HardDelete, 3),
            (O::Restore, 4),
            (O::Merge, 5),
            (O::Clone, 6),
            (O::Import, 7),
            (O::Export, 8),
            (O::Login, 9),
            (O::Logout, 10),
            (O::FailedLogin, 11),
            (O::PermissionChange, 12),
            (O::RoleChange, 13),
            (O::OwnerChange, 14),
            (O::Approved, 15),
            (O::Rejected, 16),
            (O::Submitted, 17),
            (O::Cancelled, 18),
            (O::Closed, 19),
            (O::Activated, 20),
            (O::Erasure, 21),
            (O::MfaReset, 22),
            (O::AccountDisabled, 23),
            (O::AccountEnabled, 24),
            (O::FileScanned, 25),
            (O::Escalated, 26),
            (O::DecisionDigest, 27),
            (O::Grant, 28),
            (O::Revoke, 29),
            (O::Rotate, 30),
            (O::View, 31),
            (O::Download, 32),
            (O::ConfigChange, 33),
            (O::Execute, 34),
            (O::PasswordReset, 35),
            (O::SessionRevoked, 36),
            (O::MfaEnrolled, 37),
            (O::MfaDisabled, 38),
            (O::BulkAccepted, 39),
            (O::BulkCompleted, 40),
            (O::Attached, 41),
        ]
    }

    /// D-541: every stored discriminant is fixed forever (I9). A reorder, an
    /// insertion or a renumbering fails here before it can reach a row.
    #[test]
    fn discriminants_are_pinned() {
        for (variant, value) in categories() {
            assert_eq!(variant as i32, value, "AuditCategory::{variant:?}");
        }
        for (variant, value) in operations() {
            assert_eq!(variant as i32, value, "AuditOperation::{variant:?}");
        }

        use AuditSource as S;
        let sources = [
            (S::WebForm, 0),
            (S::Api, 1),
            (S::Mobile, 2),
            (S::Import, 3),
            (S::Workflow, 4),
            (S::Plugin, 5),
            (S::BackgroundJob, 6),
            (S::Integration, 7),
            (S::MigrationTool, 8),
        ];
        for (variant, value) in sources {
            assert_eq!(variant as i32, value, "AuditSource::{variant:?}");
        }

        use AuditOutcome as R;
        for (variant, value) in [
            (R::Succeeded, 0),
            (R::Failed, 1),
            (R::PartiallyFailed, 2),
            (R::Cancelled, 3),
        ] {
            assert_eq!(variant as i16, value, "AuditOutcome::{variant:?}");
        }
    }

    /// The wire names are the snake_case of the variant names.
    #[test]
    fn wire_names_are_the_snake_case_variant_names() {
        fn snake(name: &str) -> String {
            let mut out = String::new();
            let chars: Vec<char> = name.chars().collect();
            for (i, c) in chars.iter().enumerate() {
                if c.is_ascii_uppercase() && i > 0 {
                    out.push('_');
                }
                out.push(c.to_ascii_lowercase());
            }
            out
        }
        for (c, _) in categories() {
            assert_eq!(c.wire_name(), snake(&format!("{c:?}")));
        }
        for (o, _) in operations() {
            assert_eq!(o.wire_name(), snake(&format!("{o:?}")));
        }
    }
}
