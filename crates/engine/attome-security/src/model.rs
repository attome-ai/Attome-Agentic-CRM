use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_CORE, ModuleId};
use axum::Router;

/// Registered for D-010's "every engine has a license module bit" bookkeeping
/// and so `attome_security::seed::seed` keeps running from the same startup
/// sequence as other engines — but this model mounts NO routes through the
/// `ModelRegistry`/license filter.
///
/// Why: unlike report/AI/automation (genuinely licensable premium engines),
/// authorization is core platform safety. The `authz` middleware that
/// resolves `SecurityContext` is already wired directly in `system.rs`,
/// unconditional of license (correct — unlicensing `core` must never
/// disable the gate itself, that would make the license switch a privilege-
/// escalation vector). The admin HTTP surface (`admin::routes()` — whoami,
/// privilege grants) follows the same reasoning for a second reason: an
/// expired/degraded license must not lock admins out of managing who has
/// `system.admin` — that's the mechanism you'd need to recover from a bad
/// license state in the first place. So `admin::routes()` is merged directly
/// into `attome-server`'s always-on `authed` router (`system.rs`), exactly like
/// `admin.rs`/`s2s_admin.rs`/`license_admin.rs`, not gated here.
#[derive(Debug)]
pub struct SecurityModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for SecurityModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-security"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_CORE
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new()
    }

    /// D-535: an API key is minted only by `POST /api/v1/auth/api-keys`, behind
    /// D-510's step-up guard. The generic entity engine therefore refuses to
    /// create, change or restore `api_key` rows for every caller.
    fn engine_owned_entities(&self) -> &'static [&'static str] {
        &["api_key"]
    }

    /// D-786 follow-up M2: no generic create or update may give a user row an
    /// address in the reserved service-principal domain. (Changing the email
    /// of an existing service principal needs the current row, so
    /// `entity_mutation::update_one_as` calls
    /// `accounts::guard_service_principal_email_change` for that half.)
    fn record_validators(&self) -> &'static [(&'static str, attome_core::model::RecordValidator)] {
        &[("user_account", crate::accounts::validate_systemuser_record)]
    }
}
