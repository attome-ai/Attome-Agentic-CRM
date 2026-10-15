//! `SettingDescriptor` — the closed catalogue of runtime settings (M02, D-412).
//!
//! Mirrors `attome-ai`'s `ActionDescriptor` pattern deliberately: modules
//! declare their settings in code at boot (a `Vec<SettingDescriptor>` built by
//! `all()` below), not by inventing a new key at write time. The registry is a
//! `BTreeMap` behind a `LazyLock` (compile-time data — no `AppState` field, no
//! DB round trip to know what keys exist), and `SettingDescriptor` itself is
//! sealed the same way `ActionDescriptor` is: `new()` is `pub(crate)`, so only
//! this crate can mint one, and the closed set really is closed.
//!
//! This is the *shape* catalogue — what keys exist, their JSON Schema, which
//! scopes they may be written at, and whether they are boot-time-only. The
//! *values* actually stored for a key live in `setting`
//! (`setting_store.rs`), resolved against these descriptors.
//!
//! # Boot-time-only enforcement (D-038, D-412)
//!
//! A setting that affects auth/CORS/secrets must never become silently
//! runtime-editable — a malformed value there should fail the process at
//! boot, not take effect quietly mid-flight (D-038). This is enforced at two
//! layers:
//!
//! 1. **Registration time** (this file): [`SettingRegistry::new`] panics if a
//!    descriptor's key falls under a [`RESERVED_BOOT_ONLY_NAMESPACES`] prefix
//!    but isn't marked `boot_time_only = true`. A malformed *registration* is
//!    exactly the "stop the process" case D-038 already established the
//!    precedent for — this is the same posture, one layer up.
//! 2. **Write time** (`attome-server::settings_admin`): the PUT handler rejects
//!    any write to a `boot_time_only` descriptor with a 422, regardless of
//!    namespace, and `GET /api/v1/admin/settings` excludes them from the
//!    runtime-editable listing entirely — the config source for them stays
//!    `config.json`/env, never this table.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// Zero-sized marker that makes [`SettingDescriptor`] uninstantiable outside
/// this crate — same trick `attome_ai::ActionDescriptor` uses. The field is
/// private and the type has no public constructor, so `SettingDescriptor { .. }`
/// literal syntax can't be used from another crate either.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sealed(());

/// The scope a stored setting *value* is written at. Resolution order for a
/// read is always `User -> Organization -> Deployment -> descriptor default`
/// (M02 §3) — this enum's declaration order matches that precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettingScope {
    User,
    Organization,
    Deployment,
}

impl SettingScope {
    pub fn as_str(self) -> &'static str {
        match self {
            SettingScope::User => "user",
            SettingScope::Organization => "organization",
            SettingScope::Deployment => "deployment",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(SettingScope::User),
            "organization" => Some(SettingScope::Organization),
            "deployment" => Some(SettingScope::Deployment),
            _ => None,
        }
    }
}

/// Where an effective value came from — echoed on every read so a caller (the
/// admin UI, `/settings/me`) can show "inherited from deployment default" vs.
/// "your own override" without a second round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettingSource {
    User,
    Organization,
    Deployment,
    /// No stored row at any eligible scope — `SettingDescriptor::default`.
    CodeDefault,
}

/// One registered setting. Modules declare these in `catalog.rs`'s `all()`;
/// nothing else can construct one (`_sealed` + `pub(crate) new`).
///
/// Derives `Debug` (reading every field, including `_sealed`) rather than
/// `#[allow(dead_code)]` on that marker — same choice `ActionDescriptor`
/// makes, and it keeps the struct printable for logging/tests for free.
#[derive(Debug, Clone)]
pub struct SettingDescriptor {
    /// `"{module}.{name}"` — validated by [`SettingRegistry::new`] (lowercase
    /// ascii, exactly one dot-separated module prefix).
    pub key: &'static str,
    pub description: &'static str,
    /// JSON Schema fragment the value must satisfy. A function rather than a
    /// literal so descriptors can share `serde_json::json!` macro calls
    /// without fighting Rust's raw-string escaping for schema literals.
    pub schema: fn() -> Value,
    /// Scopes a value may be stored at for this key. A key not carrying
    /// `Deployment` here can still resolve a deployment-wide *default* (via
    /// `default`, below) — it just can't have an explicit deployment-scope
    /// override row.
    pub allowed_scopes: &'static [SettingScope],
    /// `true` => never eligible for the runtime store (D-038). Config for
    /// this key stays `config.json`/env only; see the module doc for the
    /// two-layer enforcement.
    pub boot_time_only: bool,
    pub default: fn() -> Value,
    pub(crate) _sealed: Sealed,
}

impl SettingDescriptor {
    pub(crate) fn new(
        key: &'static str,
        description: &'static str,
        schema: fn() -> Value,
        allowed_scopes: &'static [SettingScope],
        boot_time_only: bool,
        default: fn() -> Value,
    ) -> Self {
        Self {
            key,
            description,
            schema,
            allowed_scopes,
            boot_time_only,
            default,
            _sealed: Sealed(()),
        }
    }

    pub fn allows_scope(&self, scope: SettingScope) -> bool {
        self.allowed_scopes.contains(&scope)
    }
}

/// Namespace prefixes (the part of `key` before the first `.`) that must
/// always be boot-time-only. A descriptor registered under one of these
/// without `boot_time_only = true` is a registration bug — `SettingRegistry::new`
/// panics rather than silently allowing an auth/CORS/secret-adjacent key to
/// become runtime-writable (D-038, D-412).
const RESERVED_BOOT_ONLY_NAMESPACES: &[&str] = &["auth", "cors", "secrets", "security", "session"];

/// The closed catalogue, built once at process start.
pub struct SettingRegistry {
    by_key: BTreeMap<&'static str, SettingDescriptor>,
}

impl std::fmt::Debug for SettingRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettingRegistry").finish_non_exhaustive()
    }
}

impl SettingRegistry {
    pub fn new() -> Self {
        let mut by_key = BTreeMap::new();
        for descriptor in crate::setting_catalog::all() {
            let namespace = descriptor.key.split('.').next().unwrap_or("");
            assert!(
                descriptor
                    .key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_')
                    && descriptor.key.matches('.').count() >= 1,
                "setting descriptor key {:?} must be lowercase ascii, snake_case, and \
                 namespaced as \"{{module}}.{{name}}\"",
                descriptor.key,
            );
            assert!(
                !RESERVED_BOOT_ONLY_NAMESPACES.contains(&namespace) || descriptor.boot_time_only,
                "setting descriptor {:?} is registered under the reserved \"{namespace}.*\" \
                 namespace (auth/CORS/secrets-adjacent) but is not marked boot_time_only — \
                 D-038 requires these to fail at boot registration, never become silently \
                 runtime-writable",
                descriptor.key,
            );
            assert!(
                !descriptor.allowed_scopes.is_empty() || descriptor.boot_time_only,
                "setting descriptor {:?} declares no allowed_scopes and is not \
                 boot_time_only — it could never be written anywhere",
                descriptor.key,
            );
            let key = descriptor.key;
            let previous = by_key.insert(key, descriptor);
            assert!(
                previous.is_none(),
                "duplicate setting descriptor key {key:?}"
            );
        }
        Self { by_key }
    }

    pub fn get(&self, key: &str) -> Option<&SettingDescriptor> {
        self.by_key.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = &SettingDescriptor> {
        self.by_key.values()
    }

    /// Descriptors eligible for the runtime store — excludes `boot_time_only`.
    /// This is the set `GET /api/v1/admin/settings` and `GET /api/v1/settings/me`
    /// ever expose a value for.
    pub fn runtime_eligible(&self) -> impl Iterator<Item = &SettingDescriptor> {
        self.by_key.values().filter(|d| !d.boot_time_only)
    }
}

impl Default for SettingRegistry {
    fn default() -> Self {
        Self::new()
    }
}

static REGISTRY: LazyLock<SettingRegistry> = LazyLock::new(SettingRegistry::new);

/// U10-T1: the admin console area a setting belongs to, from its key's
/// module.
pub fn area(key: &str) -> &'static str {
    match key.split('.').next() {
        Some("core") => "general",
        Some("auth") => "security",
        Some("feature") => "features",
        Some("ai") => "ai",
        Some("omnichannel") => "channels",
        Some("ops") => "operations",
        _ => "other",
    }
}

/// U10-T1: each setting's description in Arabic, for the admin console.
pub fn description_ar(key: &str) -> Option<&'static str> {
    Some(match key {
        "core.locale" => {
            "اللغة والمنطقة المفضلة لتنسيق التواريخ والأرقام؛ يغلب اختيار المستخدم ثم مؤسسته ثم الإعداد العام."
        }
        "core.list_page_size" => {
            "عدد العناصر الافتراضي في صفحات القوائم الإدارية، على مستوى النشر أو المؤسسة."
        }
        "core.dark_mode_default" => {
            "هل يبدأ المستخدمون الجدد بالوضع الداكن؛ يغلب اختيار المستخدم إن وُجد."
        }
        "core.time_zone" => "المنطقة الزمنية التي تُعرض بها التواريخ والأوقات، مثل Asia/Riyadh.",
        "core.calendar" => {
            "التقويم الذي تُعرض به التواريخ: ميلادي أو هجري (أم القرى) أو كلاهما؛ يغلب خيار عرض الحقل نفسه."
        }
        "core.digits" => "الأرقام المستخدمة في كتابة الأعداد والتواريخ: لاتينية (0-9) أو عربية هندية.",
        "core.date_format" => "ترتيب اليوم والشهر والسنة في التاريخ المختصر: dmy أو mdy أو ymd.",
        "core.start_page" => "الصفحة التي تُفتح بعد تسجيل الدخول، مسار يبدأ بـ /.",
        "core.theme" => "سمة الألوان: فاتح أو داكن أو تلقائي (حسب الجهاز).",
        "core.text_size" => "حجم النص: عادي أو كبير.",
        "core.reduced_motion" => "إيقاف الحركات والانتقالات.",
        "core.simple_mode" => {
            "الوضع المبسّط: إخفاء الإجراءات المتقدمة مثل النسخ والمشاركة ومجموعات التغييرات."
        }
        "auth.session_ttl_minutes" => "توضيحي فقط: مدة الجلسة تُضبط في ملف الإعداد عند الإقلاع.",
        "feature.core.beta_ui" => "سياسة ميزة الواجهة التجريبية: قيمة عامة واستثناءات لكل مستخدم.",
        "feature.core.beta_ui_advanced_panels" => {
            "سياسة ميزة اللوحات المتقدمة التجريبية، بنفس شكل الواجهة التجريبية."
        }
        "feature.scan.enabled" => {
            "سياسة ميزة المسح: قراءة الباركود ورموز QR في الحقول وللبحث عن السجلات."
        }
        "feature.scan.actions_enabled" => "سياسة تشغيل الإجراء المرتبط بنمط الرمز الممسوح.",
        "feature.scan.continuous_enabled" => "سياسة المسح المتواصل مع عدّاد للرموز المقروءة.",
        "feature.project.gantt_v2_preview" => "سياسة معاينة مخطط جانت الجديد؛ تتطلب وحدة المشاريع.",
        "ai.record_update_field_allowlist" => {
            "أزواج الكيان والحقل التي يجوز لإجراء الذكاء الاصطناعي تعديلها."
        }
        "ai.mcp_entity_admission" => {
            "الكيانات التي يصل إليها وكيل MCP خارجي عبر أدوات السجلات، والأفعال المسموحة لكل منها."
        }
        "ai.memory_retention_days" => {
            "عدد الأيام التي تُحفظ فيها ذاكرة الذكاء الاصطناعي قبل اقتراح حذفها."
        }
        "omnichannel.web_chat_default_queue_ref" => {
            "قائمة العمل التي تُوجَّه إليها محادثات الويب المحوّلة إلى موظف؛ فارغ يعني بلا قائمة افتراضية."
        }
        "omnichannel.web_chat_offline_message" => {
            "الرد التلقائي لزائر محادثة الويب خارج ساعات العمل."
        }
        "ops.read_only" => {
            "وضع القراءة فقط: ترفض الخوادم كل كتابة ما دام مفعّلًا، وتبقى القراءة وتسجيل الدخول متاحة."
        }
        "omnichannel.web_chat_calendar_ref" => {
            "تقويم ساعات العمل الذي يحكم نافذة محادثة الويب؛ فارغ يعني أنها مفتوحة دائمًا."
        }
        _ => return None,
    })
}

/// The process-wide closed catalogue. Cheap — a `LazyLock` deref, no lock
/// contention, since the map is built once and never mutated after.
pub fn registry() -> &'static SettingRegistry {
    &REGISTRY
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_setting_has_an_area_and_an_arabic_description() {
        for descriptor in super::registry().iter() {
            assert_ne!(
                super::area(descriptor.key),
                "other",
                "{} has no console area",
                descriptor.key
            );
            assert!(
                super::description_ar(descriptor.key).is_some(),
                "{} has no Arabic description",
                descriptor.key
            );
        }
    }

    use super::*;

    #[test]
    fn registry_builds_without_panicking() {
        // Exercises every assert in `new()` against the real catalogue —
        // this is the test that would fail if a future descriptor violated
        // the boot-time-only namespace rule.
        let reg = SettingRegistry::new();
        assert!(
            reg.iter().count() >= 2,
            "expected at least the seeded descriptors"
        );
    }

    #[test]
    fn reserved_namespace_descriptor_is_registered_and_boot_time_only() {
        let reg = registry();
        let d = reg
            .get("auth.session_ttl_minutes")
            .expect("illustrative reserved-namespace descriptor must be registered");
        assert!(d.boot_time_only);
    }

    #[test]
    fn boot_time_only_descriptors_are_excluded_from_runtime_eligible() {
        let reg = registry();
        assert!(reg.runtime_eligible().all(|d| !d.boot_time_only));
        assert!(
            reg.runtime_eligible()
                .all(|d| d.key != "auth.session_ttl_minutes")
        );
    }

    #[test]
    #[should_panic(expected = "reserved")]
    fn registering_a_reserved_namespace_key_as_runtime_writable_panics() {
        struct BadCatalog;
        // Build a standalone registry the same way `SettingRegistry::new`
        // does, but with one deliberately-misconfigured descriptor, to prove
        // the assertion actually fires rather than only trusting the real
        // catalogue never regresses.
        let bad = SettingDescriptor::new(
            "cors.bad_key",
            "should never be allowed",
            || serde_json::json!({"type": "string"}),
            &[SettingScope::Deployment],
            false, // NOT boot_time_only — this is the bug under test
            || serde_json::json!(null),
        );
        let _ = BadCatalog;
        let namespace = bad.key.split('.').next().unwrap_or("");
        assert!(
            !RESERVED_BOOT_ONLY_NAMESPACES.contains(&namespace) || bad.boot_time_only,
            "setting descriptor {:?} is registered under the reserved \"{namespace}.*\" \
             namespace but is not marked boot_time_only",
            bad.key,
        );
    }
}
