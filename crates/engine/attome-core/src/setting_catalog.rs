//! The closed catalogue of registered [`SettingDescriptor`]s (M02 §5, D-412).
//!
//! Mirrors `attome-ai`'s `actions/mod.rs::all()` — a hand-written `Vec`, not
//! distributed registration, so the set of valid keys is a code review, not a
//! runtime surprise. Add a new setting by adding it to `core_settings()` (or a
//! new `fn` grouped by owning concern, pushed into `all()` below) — never by
//! constructing a row directly, and never by inventing a key at write time
//! (`attome-server::settings_admin` rejects anything `registry().get(key)` can't
//! find).
//!
//! Two groups today:
//! - `core_settings()` — real, runtime-editable examples covering all three
//!   scopes, so the resolution-order test (`setting_store.rs`) has something
//!   genuine to resolve against.
//! - `reserved_boot_time_examples()` — a single illustrative descriptor
//!   proving the boot-time-only guard actually rejects a write (M02 §6's
//!   required test). It is deliberately not wired to any real `auth.*`
//!   config value — see its own doc comment.

use serde_json::json;

use crate::setting_descriptor::{SettingDescriptor, SettingScope};

pub(crate) fn all() -> Vec<SettingDescriptor> {
    let mut all = core_settings();
    all.extend(personal_settings());
    all.extend(reserved_boot_time_examples());
    all.extend(feature_flag_settings());
    all.extend(action_settings());
    all.extend(ai_settings());
    all.extend(omnichannel_settings());
    all.extend(ops_settings());
    all.extend(commission_settings());
    all.extend(billing_settings());
    all.extend(records_settings());
    all
}

/// B5-T3: record settings.
fn records_settings() -> Vec<SettingDescriptor> {
    vec![SettingDescriptor::new(
        "records.bulk_edit_approval_count",
        "A bulk edit changing more records than this waits on an approval before it runs; \
         0 never asks.",
        || json!({"type": "integer", "minimum": 0}),
        &[SettingScope::Deployment],
        false,
        || json!(0),
    )]
}

/// F4: billing settings.
fn billing_settings() -> Vec<SettingDescriptor> {
    vec![SettingDescriptor::new(
        "billing.seller_country",
        "The deployment's own country, as an ISO 3166 two-letter code: the seller \
         side of VAT on every invoice line.",
        || json!({"type": "string", "pattern": "^[A-Z]{2}$"}),
        &[SettingScope::Deployment],
        false,
        || json!("SA"),
    )]
}

/// F10: commission settings.
fn commission_settings() -> Vec<SettingDescriptor> {
    vec![SettingDescriptor::new(
        "commission.adjustment_approval_amount",
        "Manual commission adjustments larger than this (either way, in the \
         deployment's base currency) are written only after an approval.",
        || json!({"type": "number", "minimum": 0}),
        &[SettingScope::Deployment],
        false,
        || json!(1000),
    )]
}

/// AB5-T6: operating switches.
fn ops_settings() -> Vec<SettingDescriptor> {
    vec![SettingDescriptor::new(
        "ops.read_only",
        "Read-only mode: while true, every write answers 503 `read_only`; reading, \
         signing in and this switch keep working. Every server follows it within \
         the read-only refresh interval.",
        || json!({"type": "boolean"}),
        &[SettingScope::Deployment],
        false,
        || json!(false),
    )]
}

fn core_settings() -> Vec<SettingDescriptor> {
    vec![
        SettingDescriptor::new(
            "core.locale",
            "Preferred BCP-47 locale tag used for date/number formatting and \
             (future) localized content. Inheritable at every scope: a user's \
             own choice wins, then their organization's, then the \
             deployment-wide default, then \"en-US\".",
            || {
                json!({
                    "type": "string",
                    "pattern": "^[a-z]{2}(-[A-Z]{2})?$",
                })
            },
            &[
                SettingScope::User,
                SettingScope::Organization,
                SettingScope::Deployment,
            ],
            false,
            || json!("en-US"),
        ),
        SettingDescriptor::new(
            "core.list_page_size",
            "Default page size for admin list views. Deployment- or \
             organization-scoped only — deliberately not user-overridable in \
             this first slice, so a single descriptor still demonstrates a \
             narrower `allowed_scopes` set than core.locale's.",
            || {
                json!({
                    "type": "integer",
                    "minimum": 10,
                    "maximum": 200,
                })
            },
            &[SettingScope::Organization, SettingScope::Deployment],
            false,
            || json!(25),
        ),
        SettingDescriptor::new(
            "core.dark_mode_default",
            "Deployment-wide default for whether new users start in dark \
             mode. A user's own theme preference (client-local today, see \
             sidebar-preferences.service.ts) always wins if set; this is only \
             the fallback shown before they ever choose.",
            || json!({"type": "boolean"}),
            &[SettingScope::Deployment],
            false,
            || json!(false),
        ),
    ]
}

/// Every scope a personal setting may be stored at: the person's own choice
/// wins, then their organization's, then the deployment's, then the code
/// default (B11-T1). `SettingScope` has no role level; an organization is the
/// group default.
const PERSONAL: &[SettingScope] = &[
    SettingScope::User,
    SettingScope::Organization,
    SettingScope::Deployment,
];

/// B11-T1 / AG1-T7: how one person sees the product. The web app applies them
/// at once, and server rendering (exports, emails) reads the same values.
/// `core.locale` above is the language.
fn personal_settings() -> Vec<SettingDescriptor> {
    vec![
        SettingDescriptor::new(
            "core.time_zone",
            "IANA time zone dates and times are shown in, e.g. Asia/Riyadh.",
            || {
                json!({
                    "type": "string",
                    "pattern": "^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$",
                    "maxLength": 64,
                })
            },
            PERSONAL,
            false,
            || json!("UTC"),
        ),
        SettingDescriptor::new(
            "core.calendar",
            "Calendar dates are shown in: gregorian, hijri (Umm al-Qura), or \
             both. A date attribute's own display_calendar option wins.",
            || json!({"type": "string", "enum": ["gregorian", "hijri", "both"]}),
            PERSONAL,
            false,
            || json!("gregorian"),
        ),
        SettingDescriptor::new(
            "core.digits",
            "Digits numbers and dates are written with: latn (0-9) or arab \
             (Arabic-Indic).",
            || json!({"type": "string", "enum": ["latn", "arab"]}),
            PERSONAL,
            false,
            || json!("latn"),
        ),
        SettingDescriptor::new(
            "core.date_format",
            "Order of day, month and year in a short date: dmy, mdy or ymd.",
            || json!({"type": "string", "enum": ["dmy", "mdy", "ymd"]}),
            PERSONAL,
            false,
            || json!("dmy"),
        ),
        SettingDescriptor::new(
            "core.start_page",
            "The page opened after signing in, as an app route starting with /.",
            || json!({"type": "string", "pattern": "^/[^\\s]*$", "maxLength": 200}),
            PERSONAL,
            false,
            || json!("/"),
        ),
        SettingDescriptor::new(
            "core.theme",
            "Colour theme: light, dark, or auto (follow the device).",
            || json!({"type": "string", "enum": ["light", "dark", "auto"]}),
            PERSONAL,
            false,
            || json!("auto"),
        ),
        SettingDescriptor::new(
            "core.text_size",
            "Text size: normal or large.",
            || json!({"type": "string", "enum": ["normal", "large"]}),
            PERSONAL,
            false,
            || json!("normal"),
        ),
        SettingDescriptor::new(
            "core.reduced_motion",
            "Turn off animations and transitions.",
            || json!({"type": "boolean"}),
            PERSONAL,
            false,
            || json!(false),
        ),
        SettingDescriptor::new(
            "core.simple_mode",
            "Simple mode (AK6-T2): hide advanced actions such as duplicating, sharing \
             and changesets, for people who only need the everyday ones.",
            || json!({"type": "boolean"}),
            PERSONAL,
            false,
            || json!(false),
        ),
    ]
}

/// A single illustrative descriptor in a reserved namespace, existing only to
/// prove `SettingRegistry::new`'s boot-time-only assertion and the write
/// handler's 422 both actually fire (M02 §6). Deliberately NOT wired to the
/// real `config.auth` section — `attome-config`'s session TTL stays the sole
/// source of truth for that value; registering it here as `boot_time_only`
/// only demonstrates the guard, it does not expose or shadow the real config.
fn reserved_boot_time_examples() -> Vec<SettingDescriptor> {
    vec![SettingDescriptor::new(
        "auth.session_ttl_minutes",
        "Illustrative only. Session lifetime is boot-time config \
         (`config.json`'s auth section, D-038) precisely because a malformed \
         value must fail the process at boot rather than take effect quietly \
         mid-flight. This descriptor is registered solely so the runtime \
         settings API has a real key to reject a write against — it does not \
         read or influence the actual session TTL.",
        || json!({"type": "integer"}),
        &[SettingScope::Deployment],
        true,
        || serde_json::Value::Null,
    )]
}

/// One `SettingDescriptor` per registered [`crate::feature_flag_descriptor::FeatureFlag`]
/// (M95, D-430) — the storage half of the flag catalogue in
/// `feature_flag_catalog.rs`. `FeatureFlagRegistry::new()` asserts every flag
/// there has a matching entry here, so the two lists can't silently drift
/// apart.
///
/// Each descriptor is deliberately `Deployment`-scope only: per-user/role
/// targeting and the progressive-rollout percentage live *inside* the stored
/// JSON value (`feature_flag_store::FeatureFlagPolicy`), not as additional
/// `setting` rows at other scopes — `SettingScope` has no `Role`
/// variant and adding one (plus the DB `CHECK` it would need) is out of
/// scope for a change that rides entirely on the existing store. The schema
/// only pins the top-level shape (`validate_against_schema`'s minimal
/// subset has no nested-property support); `features_admin`'s write handler
/// does the deeper structural/dependency validation before ever calling the
/// shared `write_setting` path.
fn feature_flag_settings() -> Vec<SettingDescriptor> {
    let scan = |key: &'static str, description: &'static str| {
        SettingDescriptor::new(
            key,
            description,
            || json!({"type": "object"}),
            &[SettingScope::Deployment],
            false,
            || json!({"deployment": false}),
        )
    };
    vec![
        scan(
            "feature.scan.enabled",
            "Stored policy value for the scan.enabled feature flag (B16-T9), same shape as \
             feature.core.beta_ui.",
        ),
        scan(
            "feature.scan.actions_enabled",
            "Stored policy value for the scan.actions_enabled feature flag (B16-T9).",
        ),
        scan(
            "feature.scan.continuous_enabled",
            "Stored policy value for the scan.continuous_enabled feature flag (B16-T9).",
        ),
        scan(
            "feature.content.seo_audit",
            "Stored policy value for the content.seo_audit feature flag (E13-T2).",
        ),
        scan(
            "feature.content.seo_clusters",
            "Stored policy value for the content.seo_clusters feature flag (E13-T2).",
        ),
        scan(
            "feature.content.search_console",
            "Stored policy value for the content.search_console feature flag (E13-T2).",
        ),
        scan(
            "feature.content.instant_indexing",
            "Stored policy value for the content.instant_indexing feature flag (E13-T2).",
        ),
        scan(
            "feature.content.seo_arabic_paths",
            "Stored policy value for the content.seo_arabic_paths feature flag (E13-T2).",
        ),
        scan(
            "feature.content.seo_agent",
            "Stored policy value for the content.seo_agent feature flag (E13-T2).",
        ),
        scan(
            "feature.marketing.tracking",
            "Stored policy value for the marketing.tracking feature flag (E14-T1).",
        ),
        scan(
            "feature.marketing.tracking_external_sites",
            "Stored policy value for the marketing.tracking_external_sites feature flag (E14-T1).",
        ),
        scan(
            "feature.marketing.tracking_identify",
            "Stored policy value for the marketing.tracking_identify feature flag (E14-T1).",
        ),
        scan(
            "feature.marketing.tracking_company",
            "Stored policy value for the marketing.tracking_company feature flag (E14-T1).",
        ),
        scan(
            "feature.marketing.tracking_custom_events",
            "Stored policy value for the marketing.tracking_custom_events feature flag (E14-T1).",
        ),
        scan(
            "feature.marketing.tracking_alerts",
            "Stored policy value for the marketing.tracking_alerts feature flag (E14-T1).",
        ),
        scan(
            "feature.sales.opportunity_lines",
            "Stored policy value for the sales.opportunity_lines feature flag (D6-T13).",
        ),
        scan(
            "feature.sales.recurring_lines",
            "Stored policy value for the sales.recurring_lines feature flag (D6-T13).",
        ),
        scan(
            "feature.sales.schedules",
            "Stored policy value for the sales.schedules feature flag (D6-T13).",
        ),
        scan(
            "feature.sales.quote_sync",
            "Stored policy value for the sales.quote_sync feature flag (D6-T13).",
        ),
        scan(
            "feature.sales.product_suggestions",
            "Stored policy value for the sales.product_suggestions feature flag (D6-T13).",
        ),
        scan(
            "feature.sales.deal_teams",
            "Stored policy value for the sales.deal_teams feature flag (D7-T10).",
        ),
        scan(
            "feature.sales.splits",
            "Stored policy value for the sales.splits feature flag (D7-T10).",
        ),
        scan(
            "feature.sales.line_splits",
            "Stored policy value for the sales.line_splits feature flag (D7-T10).",
        ),
        scan(
            "feature.sales.partner_members",
            "Stored policy value for the sales.partner_members feature flag (D7-T10).",
        ),
        scan(
            "feature.sales.team_suggestions",
            "Stored policy value for the sales.team_suggestions feature flag (D7-T10).",
        ),
        SettingDescriptor::new(
            "feature.core.beta_ui",
            "Stored policy value for the core.beta_ui feature flag (M95, D-430): \
             {deployment: bool, user_overrides: {\"<user_id>\": bool}, \
             role_overrides: {\"<privilege_key>\": bool}, percentage: 0-100}.",
            || json!({"type": "object"}),
            &[SettingScope::Deployment],
            false,
            || json!({"deployment": false}),
        ),
        SettingDescriptor::new(
            "feature.core.beta_ui_advanced_panels",
            "Stored policy value for the core.beta_ui_advanced_panels feature \
             flag (M95, D-430) — same shape as feature.core.beta_ui.",
            || json!({"type": "object"}),
            &[SettingScope::Deployment],
            false,
            || json!({"deployment": false}),
        ),
        SettingDescriptor::new(
            "feature.project.gantt_v2_preview",
            "Stored policy value for the project.gantt_v2_preview feature flag \
             (M95, D-430) — same shape as feature.core.beta_ui. Gated on \
             MODULE_PROJECT: this flag can never evaluate true for a \
             deployment whose licence doesn't hold that module, regardless of \
             this stored value.",
            || json!({"type": "object"}),
            &[SettingScope::Deployment],
            false,
            || json!({"deployment": false}),
        ),
    ]
}

/// M98 Phase 1 (`record.update_field`, D-448) — the deployment-configured
/// allow-list of `(entity, field)` pairs the action may write. The action's
/// `RiskTier::Reversible` descriptor gates *whether* a caller may reach the
/// action at all; this setting gates *what it may touch* once reached — a
/// second, narrower boundary the static descriptor cannot express because it
/// has no notion of `args`. `attome-ai`'s executor resolves this at
/// `Deployment` scope only (no per-user override — an admin, not each agent
/// session's owner, decides the blast radius) and refuses any `(entity,
/// field)` pair not listed, for every caller, not only an agent — the action
/// is scoped by descriptor to this set, full stop.
///
/// Shape: `{"<entity_logicalname>": ["<field_logicalname>", ...], ...}`.
/// Default `{}` — nothing is writable until an admin opts fields in, the
/// same fail-closed posture `feature.*`'s `{"deployment": false}` default
/// uses. The minimal schema validator has no nested-property support (see
/// `setting_store.rs`'s header), so — same trade-off `feature_flag_settings`
/// already accepts — only the top-level `object` shape is schema-checked;
/// `attome-ai`'s executor is the one place that actually walks the map.
fn action_settings() -> Vec<SettingDescriptor> {
    vec![
        SettingDescriptor::new(
            "ai.record_update_field_allowlist",
            "Deployment-wide allow-list of entity/field pairs the \
             record.update_field AI action may write: \
             {\"<entity>\": [\"<field>\", ...]}. A pair not listed here is \
             refused regardless of caller, risk ceiling, or approval — this is \
             the action's own scope, not a privilege check.",
            || json!({"type": "object"}),
            &[SettingScope::Deployment],
            false,
            || json!({}),
        ),
        mcp_entity_admission(),
    ]
}

/// MCP entity admission (plan item M3.4, `mcp-excellence-10-10.md`; owner
/// decision 2026-09-28, a runtime setting rather than an entity metadata
/// flag). Which entities an **external agent on the MCP surface** may reach
/// through the `record.*` tools, and with which verbs.
///
/// Shape: `{"<entity_logicalname>": ["read" | "create" | "update" | "delete", ...]}`.
/// Default `{}` — **nothing is admitted** (default-deny, invariant MI-3): an
/// MCP `record.*` call on an entity not listed, or with a verb not listed, is
/// refused darkly. Admission only narrows: the caller's own privileges and
/// record-level security still apply on top. `attome-ai` also refuses a
/// code-owned set of security, identity, audit and licence entities even when
/// this setting names them (`attome_ai::mcp::admission`).
///
/// Deployment scope only, same reasoning as the allow-list above: an admin,
/// not each session owner, decides what an external agent may touch. Only the
/// top-level `object` shape is schema-checked (the minimal validator has no
/// nested support); `attome-ai` is the one place that walks the map, and an
/// unrecognised verb there admits nothing.
fn mcp_entity_admission() -> SettingDescriptor {
    SettingDescriptor::new(
        "ai.mcp_entity_admission",
        "Entities an external MCP agent may reach through the record.* tools, \
         and with which verbs: {\"<entity>\": [\"read\", \"create\", \
         \"update\", \"delete\"]}. Default {} admits nothing. Security, \
         identity, audit and licence entities are refused even if listed. \
         The caller's own privileges still apply.",
        || json!({"type": "object"}),
        &[SettingScope::Deployment],
        false,
        || json!({}),
    )
}

/// M35 (AI Memory, D-451). Deployment-scope only — memory retention is a
/// deployment-wide policy question, not a per-user preference, matching
/// `core.dark_mode_default`'s own reasoning for the same scope restriction.
/// Read by `attome-compliance::retention::propose_retention_actions` (via
/// `SettingsSnapshot::resolve`, `user_id`/`organization_ref` both `None`)
/// exactly like every other runtime-editable setting — no separate config
/// table, per M02/D-412.
fn ai_settings() -> Vec<SettingDescriptor> {
    vec![SettingDescriptor::new(
        "ai.memory_retention_days",
        "How many days a memory row (`memory`, M35) is kept after \
         creation before the retention sweep proposes it for deletion. \
         Applies uniformly across every scope_kind in v1. A deployment that \
         wants to keep memory indefinitely should set a very large value \
         rather than relying on an unset default — this key always has an \
         effective value (the code default below).",
        || {
            json!({
                "type": "integer",
                "minimum": 1,
                "maximum": 3650,
            })
        },
        &[SettingScope::Deployment],
        false,
        || json!(365),
    )]
}

/// M53 Phase 1 (Omnichannel, web chat only, D-474). Deployment-scope only —
/// same "policy question, not a per-user preference" reasoning
/// `ai_settings` above already gives for its own single-scope setting. Read
/// by `attome_server::omnichannel_public` via `SettingsSnapshot::resolve`
/// (`user_id`/`organization_ref` both `None`), same established pattern as
/// every other runtime-editable setting.
///
/// Genuine conditional routing (which queue a given request goes to, by
/// content/category) needs M45 rule authoring, which does not exist yet
/// (`attome_service::routing`'s own doc comment documents the identical gap for
/// M70) — `web_chat_default_queue_ref` is deliberately the simple,
/// hardcoded-but-admin-configurable stand-in the module plan calls for: every
/// new web-chat handoff routes to this one queue, full stop, until M45 Phase
/// 2 ships a real rule table.
fn omnichannel_settings() -> Vec<SettingDescriptor> {
    vec![
        SettingDescriptor::new(
            "omnichannel.web_chat_default_queue_ref",
            "The `service_work_queue.id` every new web-chat handoff's work \
             request is routed to (`work_queue_ref`). Empty string (the \
             default) means no default queue is configured — a handoff still \
             creates the work request, just with no queue set, exactly as if \
             an admin had not configured M84 queue routing for this channel \
             at all.",
            || json!({"type": "string"}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
        SettingDescriptor::new(
            "omnichannel.web_chat_offline_message",
            "Fixed auto-reply text shown to a web-chat visitor when \
             `web_chat_calendar_ref` is configured and the current instant \
             falls outside that calendar's business hours (`attome-calendar`, \
             D-404). Not M45-conditional — a single fixed message for v1, \
             same scope cut every other module this session has taken for a \
             genuine M45 gap.",
            || json!({"type": "string"}),
            &[SettingScope::Deployment],
            false,
            || {
                json!(
                    "Our team is currently offline. We've received your \
                     message and will follow up as soon as we're back."
                )
            },
        ),
        SettingDescriptor::new(
            "omnichannel.web_chat_calendar_ref",
            "Optional `calendar.id` (D-404/M83) whose business \
             hours gate the web chat widget. Empty string (the default) \
             means no business-hours check applies — the widget behaves as \
             if it were always open, the same opt-in-by-configuration \
             posture `service_sla_policy.calendar_ref`/`service_work_queue.calendar_ref` \
             already establish. Plain string, not a `lookup` — calendars are \
             a dedicated admin object, not a generic XRM entity (see either \
             of those two attributes' own doc comments).",
            || json!({"type": "string"}),
            &[SettingScope::Deployment],
            false,
            || json!(""),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B11-T1: every personal setting is the person's to set, its default
    /// passes its own schema, and a value outside it is refused.
    #[test]
    fn personal_settings_resolve_with_defaults() {
        use crate::setting_store::validate_against_schema;
        let personal = personal_settings();
        assert!(personal.iter().any(|d| d.key == "core.calendar"));
        for d in &personal {
            assert!(d.allows_scope(SettingScope::User), "{}", d.key);
            assert!(d.allows_scope(SettingScope::Deployment), "{}", d.key);
            validate_against_schema(&(d.default)(), &(d.schema)())
                .unwrap_or_else(|e| panic!("{}: default fails its schema: {e}", d.key));
        }
        let schema = |key: &str| (personal.iter().find(|d| d.key == key).unwrap().schema)();
        assert!(validate_against_schema(&json!("hijri"), &schema("core.calendar")).is_ok());
        assert!(validate_against_schema(&json!("julian"), &schema("core.calendar")).is_err());
        assert!(validate_against_schema(&json!("Asia/Riyadh"), &schema("core.time_zone")).is_ok());
        assert!(validate_against_schema(&json!("no zone"), &schema("core.time_zone")).is_err());
        assert!(
            validate_against_schema(&json!("/xrm/dashboard"), &schema("core.start_page")).is_ok()
        );
        assert!(validate_against_schema(&json!("https://x"), &schema("core.start_page")).is_err());
    }

    /// MCP entity admission is default-deny (plan item M3.4): the code
    /// default admits nothing, and only an admin's deployment-scope row can
    /// change that — no per-user or per-organization override.
    #[test]
    fn mcp_entity_admission_defaults_to_nothing_admitted_at_deployment_scope_only() {
        let descriptor = all()
            .into_iter()
            .find(|d| d.key == "ai.mcp_entity_admission")
            .expect("ai.mcp_entity_admission must be registered");
        assert_eq!((descriptor.default)(), json!({}));
        assert_eq!(descriptor.allowed_scopes, &[SettingScope::Deployment]);
        assert!(!descriptor.boot_time_only);
        assert_eq!((descriptor.schema)(), json!({"type": "object"}));
    }
}
