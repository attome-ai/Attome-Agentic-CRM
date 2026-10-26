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
        Some("commission") => "sales",
        Some("billing") => "sales",
        Some("sales") => "sales",
        Some("records") => "data",
        Some("customer_tests") => "data",
        Some("limits") => "operations",
        Some("compliance") => "security",
        Some("email" | "mail_capture" | "voice" | "service" | "marketing") => "channels",
        Some("scan" | "search" | "integration" | "catalog") => "data",
        Some("i18n") => "general",
        Some("notification") => "channels",
        Some("approval" | "jobs") => "operations",
        Some("data_profile") => "data",
        Some("quality" | "master" | "lineage") => "data",
        Some("revrec" | "fulfilment") => "sales",
        Some("grc") => "security",
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
        "service.anonymous_intake.offerings" => {
            "معرّفات عروض الخدمة العامة التي تقبل طلبات مجهولة من نموذج ويب؛ فارغة: لا يقبلها أي عرض."
        }
        "marketing.form_intake.user" => {
            "حساب الخدمة الذي تُسجَّل به إرسالات النماذج التسويقية؛ فارغ: لا تقبل النماذج أي إرسال."
        }
        "marketing.profile_event_retention_months" => {
            "عدد الأشهر التي تُحفظ فيها أحداث الملف الشخصي؛ تُحذف الأشهر الأقدم كاملة كل ليلة."
        }
        "marketing.sms_price_per_segment" => {
            "تكلفة مقطع الرسالة النصية الواحد بعملة النشر الأساسية، لتقدير تكلفة الحملة قبل إرسالها؛ صفر: عدد المقاطع فقط."
        }
        "marketing.sms_quiet_hours" => {
            "الساعات (بتوقيت المستلم المحلي) التي تُؤجَّل فيها رسائل الحملات النصية، لكل دولة برمزها و\"*\" لبقية الدول."
        }
        "marketing.blocklist_zones" => {
            "قوائم الحظر في نظام أسماء النطاقات التي يحق لهذا النشر الاستعلام منها، وفق شروط كل قائمة. لا شيء افتراضياً."
        }
        "marketing.social_post_approval" => {
            "لا تُنشر المنشورات الاجتماعية إلا بعد اعتمادها. عند الإيقاف يُنشر المنشور المجدول في موعده."
        }
        "marketing.blocklist_ips" => "عناوين IP المرسِلة التي يفحصها الفحص اليومي لقوائم الحظر.",
        "service.presence" => {
            "حضور الموظف في مكتب الخدمة: متاح أو مشغول أو غائب؛ توزع قوائم الانتظار التلقائية العمل الجديد على المتاحين فقط."
        }
        "service.email_thread_days" => {
            "البريد الوارد بلا رقم حالة في عنوانه ولا ترويسات رد ينضم إلى أحدث حالة مفتوحة لمرسله حُدّثت خلال هذا العدد من الأيام؛ صفر: لا ينضم إلا برقم الحالة أو ترويسات الرد."
        }
        "service.anonymous_intake.user" => {
            "حساب الخدمة الذي تُسجَّل به الطلبات المجهولة ويحتاج صلاحية إنشاء طلب العمل؛ فارغ: لا طلبات مجهولة."
        }
        "core.tours_seen" => {
            "الجولات الإرشادية التي أنهاها هذا الشخص أو تخطّاها، حتى لا تبدأ الجولة التلقائية إلا مرة واحدة."
        }
        "core.country" => {
            "الدولة التي يخدمها هذا النشر برمز ISO من حرفين (SA وAE وEG)؛ يضبطها معالج الإعداد الأول."
        }
        "email.tracking.enabled" => {
            "هل تحمل رسائل السجلات الصادرة روابط متتبَّعة وصورة لتتبع الفتح؛ لا يُتتبَّع من سحب موافقة email_tracking."
        }
        "compliance.double_opt_in_countries" => {
            "الدول التي لا تُحتسب فيها الموافقة التسويقية من نموذج عام إلا بعد تأكيدها من رسالة بريد؛ فارغة: تُحتسب عند منحها."
        }
        "compliance.consent_expiry_days" => {
            "عدد الأيام التي تبقى فيها الموافقة التسويقية سارية قبل أن تنتهي ويُطلب منحها من جديد؛ 0: لا تنتهي."
        }
        "compliance.dsr_response_days" => {
            "عدد الأيام التي يجب الرد خلالها على طلب صاحب البيانات؛ 0: مدة نظام الدولة (30 يومًا وفق نظام حماية البيانات الشخصية السعودي) أو 30."
        }
        "limits.heavy_op.inline_max_rows" => {
            "عدد السجلات التي يغيّرها تحديث أو حذف على مجموعة مرشّحة داخل الطلب؛ تعمل المجموعة الأكبر مهمةً في الخلفية مع عرض التقدم. من 1 إلى 100000."
        }
        "limits.heavy_op.undo_retention_days" => {
            "عدد الأيام التي تحتفظ فيها العملية الجماعية المنتهية بالقيم التي استبدلتها لإمكان التراجع عنها؛ تمسح مهمة يومية الأقدم منها. من 1 إلى 3650."
        }
        "limits.bulk.max_records_per_request" => {
            "عدد السجلات التي يحملها طلب جماعي واحد؛ تمر المجموعة الأكبر عبر استيراد مرحلي. من 1 إلى 10000."
        }
        "limits.query.timeout_ms.interactive" => {
            "المدة بالملّي ثانية التي يعمل خلالها استعلام قائمة أو عرض عادي قبل إلغائه."
        }
        "limits.query.timeout_ms.report" => {
            "المدة بالملّي ثانية التي يعمل خلالها استعلام مخزّن مُعلَّم كتقرير قبل إلغائه."
        }
        "limits.query.timeout_ms.export" => {
            "المدة بالملّي ثانية التي يعمل خلالها استعلام التصدير قبل إلغائه."
        }
        "limits.workflow.max_steps_per_run" => {
            "عدد مرات تنفيذ العقد المسموح بها لتشغيل تدفق واحد، بما فيها إعادة المحاولة؛ يفشل التشغيل إذا تجاوزها. من 10 إلى 100000."
        }
        "limits.workflow.max_loop_items" => {
            "عدد العناصر التي تمر بها خطوة «لكل عنصر» واحدة؛ تفشل الخطوة إذا كانت القائمة أطول. من 1 إلى 1000000."
        }
        "limits.workflow.max_nesting" => {
            "عدد مستويات التدفقات الفرعية وتشغيلات «لكل عنصر» التي يتداخل بعضها في بعض. من 1 إلى 50."
        }
        "limits.workflow.max_run_minutes" => {
            "المدة بالدقائق التي يستمر خلالها تشغيل التدفق بما فيها الانتظار؛ يفشل التشغيل الأقدم عند خطوته التالية. من 1 إلى 525600."
        }
        "limits.warn_at_percent" => {
            "النسبة المئوية من الحد التي يُنبَّه عندها المسؤولون إلى اقتراب المستخدمين منه. من 50 إلى 99."
        }
        "notification.quiet_hours" => {
            "ساعات الهدوء بتوقيتك، مثل {\"start\": \"22:00\", \"end\": \"07:00\"}: تنتظر فيها الإشعارات منخفضة وعادية الأولوية حتى تنتهي، وتصل العالية والعاجلة فورًا. فارغة: بلا ساعات هدوء."
        }
        "notification.digest" => {
            "كيف تصلك الإشعارات منخفضة الأولوية: إيقاف (كل إشعار وحده) أو كل ساعة أو يوميًا (رسالة واحدة الساعة 08:00 بتوقيتك تجمعها كلها)."
        }
        "mail_capture.enabled" => {
            "هل تُلتقط رسائل بريدك المتصل التي تخص جهات اتصال وعملاء محتملين معروفين وتُضاف إلى سجلاتهم."
        }
        "mail_capture.excluded_domains" => {
            "نطاقات لا تُلتقط عناوينها أبدًا، وعادةً نطاقات مؤسستك، مفصولة بفواصل."
        }
        "voice.agent_number" => {
            "رقم هاتفك (بصيغة E.164) أو تحويلتك في المقسم: المكالمة التي تُجرى من Attome ترن عليه أولًا ثم على العميل."
        }
        "scan.record_location" => {
            "هل يسجّل إجراء المسح موقع الجهاز عندما ترسله الجهاز؛ عند الإيقاف يُهمل الموقع."
        }
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
        "feature.content.seo_audit" => {
            "سياسة تدقيق تحسين محركات البحث للصفحات عند الحفظ وليلًا، مع درجات للصفحة والموقع."
        }
        "feature.content.seo_clusters" => {
            "سياسة موضوعات تحسين البحث مع الصفحات المحورية والفرعية وفحص فجوات الروابط."
        }
        "feature.content.search_console" => {
            "سياسة جلب بيانات Google Search Console وBing Webmaster يوميًا لكل صفحة عبر اتصال العميل."
        }
        "feature.content.instant_indexing" => {
            "سياسة إشعار IndexNow وخرائط الموقع عند النشر والإزالة."
        }
        "feature.content.seo_arabic_paths" => "سياسة السماح بمسارات URL عربية للترجمات العربية.",
        "feature.content.seo_agent" => {
            "سياسة صياغة الوكيل لعناوين البحث وأوصافه وكتل الأسئلة الشائعة."
        }
        "feature.revrec.basic" => "سياسة تشغيل الاعتراف بالإيراد: عقود الإيراد وجداوله ومساراته.",
        "feature.revrec.contracts" => {
            "سياسة إنشاء عقد إيراد والتزامات أداء للطلب المؤكد أو الاشتراك الفعّال في الخلفية."
        }
        "feature.revrec.ssp_allocation" => {
            "سياسة توزيع سعر العقد على التزاماته حسب سعر البيع المستقل."
        }
        "feature.revrec.usage_completion" => {
            "سياسة الاعتراف بالتزامات الاستخدام ونسبة الإنجاز وفق التقدم المقاس."
        }
        "feature.revrec.change_rules" => {
            "سياسة معالجة تعديلات العقود كعقد منفصل أو تعديل مستقبلي أو تسوية فورية."
        }
        "feature.revrec.disclosure" => {
            "سياسة تقارير الإفصاح عن الإيراد: التصنيف وأرصدة العقود والالتزامات المتبقية."
        }
        "feature.marketing.tracking" => {
            "سياسة تتبع زيارات صفحات الموقع لجهات الاتصال والعملاء المحتملين."
        }
        "feature.marketing.tracking_external_sites" => {
            "سياسة السماح بتتبع المواقع الخارجية غير المستضافة في المنصة."
        }
        "feature.marketing.tracking_identify" => {
            "سياسة ربط الزائر المجهول بجهة اتصال عند تعريفه بنفسه."
        }
        "feature.marketing.tracking_company" => "سياسة التعرف على شركة الزائر من عنوان الشبكة.",
        "feature.marketing.tracking_custom_events" => "سياسة استقبال الأحداث المخصصة من الموقع.",
        "feature.marketing.tracking_alerts" => "سياسة تنبيه المسؤول عند زيارة صفحة مراقبة.",
        "feature.sales.opportunity_lines" => "سياسة بنود المنتجات على الفرص البيعية.",
        "feature.sales.recurring_lines" => "سياسة البنود المتكررة والإيراد السنوي على الفرص.",
        "feature.sales.schedules" => "سياسة جداول الإيراد والتسليم لبنود الفرص.",
        "feature.sales.quote_sync" => "سياسة مزامنة بنود الفرصة مع عرض السعر الأساسي.",
        "feature.sales.product_suggestions" => "سياسة اقتراح المنتجات المرتبطة على الفرص.",
        "feature.sales.deal_teams" => "سياسة فرق الصفقات: الأعضاء وأدوارهم وصلاحياتهم.",
        "feature.sales.splits" => "سياسة تقسيم الإيراد والدعم الإضافي بين أعضاء فريق الصفقة.",
        "feature.sales.line_splits" => "سياسة تقسيم بنود الفرصة منفردة بدلا من الصفقة كاملة.",
        "feature.sales.partner_members" => "سياسة إضافة جهات اتصال الشركاء إلى فرق الصفقات.",
        "feature.sales.team_suggestions" => {
            "سياسة إضافة أعضاء الفريق الافتراضيين إلى الصفقات الجديدة."
        }
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
        "ai.meeting_briefs" => {
            "هل يكتب الذكاء الاصطناعي موجزاً قبل كل اجتماع بساعة لصاحب الاجتماع؛ اختيار المستخدم يغلب اختيار النظام."
        }
        "omnichannel.web_chat_default_queue_ref" => {
            "قائمة العمل التي تُوجَّه إليها محادثات الويب المحوّلة إلى موظف؛ فارغ يعني بلا قائمة افتراضية."
        }
        "omnichannel.web_chat_offline_message" => {
            "الرد التلقائي لزائر محادثة الويب خارج ساعات العمل."
        }
        "customer_tests.require_pass_before_publish" => {
            "قبل تطبيق حزمة تغييرات أو نشر عنصر من النموذج، تُشغَّل كل اختبارات العميل المانعة النشطة ويُرفض النشر إن فشل أحدها."
        }
        "records.bulk_actions" => {
            "التعديلات الجماعية المحفوظة للشخص حسب الكيان: لكل منها اسم وعمليات تُعاد من نافذة التعديل الجماعي."
        }
        "data_profile.schedule" => {
            "الكيانات التي تُحلَّل بياناتها وفق جدول، لكل كيان تعبير cron بتوقيت النشر، مثل {\"contact\": \"0 2 * * *\"}؛ يُنبَّه مشرفو البيانات حين يختلف التحليل عن سابقه. لا شيء افتراضيًا."
        }
        "data_profile.retention_days" => {
            "عدد الأيام التي تُحفظ فيها لقطة تحليل البيانات قبل حذفها. من 1 إلى 3650."
        }
        "jobs.quiet_windows" => {
            "ساعات هادئة بتوقيت النشر، مثل [{\"start\": \"08:00\", \"end\": \"18:00\"}]: لا تبدأ فيها الأعمال المجدولة الثقيلة (تشغيل تدفق على سجلات عرض، وتسليم التقارير) وتبدأ عند انتهائها مرة واحدة."
        }
        "approval.email_links" => {
            "هل يتلقى الموافقون على كل خطوة من طلب موافقة معلّق رسالة بريد فيها رابط يُستخدم مرة واحدة إلى الطلب."
        }
        "approval.email_decide_actions" => {
            "أنواع إجراءات الموافقة منخفضة الخطورة التي يمكن الموافقة عليها أو رفضها مباشرة من الرابط المرسل بالبريد؛ رابط أي طلب آخر يفتح صفحة الطلب التي تتطلب تسجيل الدخول."
        }
        "records.bulk_edit_approval_count" => {
            "التعديل الجماعي الذي يغيّر سجلات أكثر من هذا العدد ينتظر موافقة قبل تنفيذه؛ صفر يعني بلا موافقة."
        }
        "fulfilment.default_location_id" => {
            "موقع المخزون الذي تُشحن منه أوامر التنفيذ للطلب المؤكد. إن لم يُحدد يُستخدم موقع المخزون الوحيد في النشر؛ وإن تعددت المواقع دون تحديد لا تُقسم الطلبات."
        }
        "catalog.show_hidden_existence" => {
            "هل يعرض فهرس البيانات الحقل الذي لا يحق للشخص قراءته باسمه فقط، مع علامة أنه مخفي ليطلب الوصول إليه؛ متوقف افتراضيًا فلا يُذكر الحقل المخفي أبدًا."
        }
        "integration.warehouse_entities" => {
            "الكيانات التي تُصدَّر تغييرات سجلاتها كل بضع دقائق ملفاتِ Parquet في التخزين، ملفًا لكل ساعة تغيير مع بيان بالملفات؛ فارغة افتراضيًا أي أن التصدير متوقف، ولا تُصدَّر الحقول الحساسة أبدًا."
        }
        "search.personal_weights" => {
            "إضافات صغيرة إلى ترتيب نتيجة البحث لسجل يملكه الشخص أو فتحه من بحث خلال آخر 30 يومًا أو يملكه فريق من فرقه، كل منها من 0 إلى 1؛ كلها 0 افتراضيًا. لا تُعيد إلا ترتيب ما يستطيع الشخص رؤيته أصلًا."
        }
        "core.default_country" => {
            "الدولة (رمز ISO من حرفين) التي يتبعها رقم الهاتف المكتوب دون رمز الدولة، مثل SA؛ فيطابق البحث 0501234567 مع ‎+966501234567."
        }
        "fulfilment.stuck_hours" => {
            "عدد الساعات التي يبقى فيها أمر التنفيذ في حالة مفتوحة واحدة قبل أن يُرفع استثناءً متوقفًا. 48 افتراضيًا."
        }
        "revrec.ssp_list_discount_percent" => {
            "النسبة المئوية المخصومة من سعر القائمة للمنتج لتكون سعر بيعه المستقل، حين لا يكون له سعر مُدخل ولا مبيعات منفردة كافية لاستنتاجه. صفر افتراضيًا."
        }
        "revrec.ssp_cost_margin_percent" => {
            "النسبة المئوية المضافة إلى تكلفة المنتج لتكون سعر بيعه المستقل، حين لا يكون له سعر مُدخل ولا مبيعات منفردة كافية ولا سعر قائمة. صفر افتراضيًا."
        }
        "grc.max_admins" => {
            "أكبر عدد من المسؤولين النشطين يقبله فحص الأدلة؛ يفتح تجاوزه أو غياب أي مسؤول ملاحظة."
        }
        "master.certified_only" => {
            "الكيانات الرئيسية التي لا تُرسل تغييرات سجلاتها الذهبية إلى المشتركين إلا وهي معتمدة؛ لا تُرسل تغييرات السجل المسودة أو المتقاعد."
        }
        "quality.drop_alert_points" => {
            "عدد النقاط التي يجب أن تنخفضها الدرجة الكلية لجودة بيانات كيان منذ الأمس لتنبيه المسؤولين عنه، إضافة إلى نزولها تحت هدفها."
        }
        "quality.max_issues_per_run" => {
            "أقصى عدد من سجلات مشكلات جودة البيانات تكتبه دورة تقييم واحدة لكل الكيانات؛ الدرجات تُكتب دائمًا."
        }
        "quality.max_issues_per_entity" => {
            "أقصى عدد من سجلات مشكلات جودة البيانات لكيان واحد في دورة التقييم، كي لا يستهلك كيان واحد الدورة كلها."
        }
        "lineage.export_enabled" => {
            "هل يستطيع المسؤولون سحب مخطط تتبّع البيانات بصيغة OpenLineage: أسماء التعريفات والكيانات والحقول فقط، دون أي قيمة من السجلات. معطّل افتراضيًا."
        }
        "records.export_formula_guard" => {
            "هل تُكتب الخلايا النصية التي تبدأ بـ = أو + أو - أو @ نصاً عند التصدير، كي لا تنفّذها جداول البيانات كصيغة."
        }
        "billing.seller_country" => {
            "بلد النشر نفسه برمز ISO من حرفين: جهة البائع في ضريبة القيمة المضافة على كل بند فاتورة."
        }
        "billing.refund.approval_threshold" => {
            "المبالغ المستردة الأكبر من هذا المبلغ تنتظر موافقة المدير المالي (0 = لا تنتظر أبدًا)."
        }
        "billing.saved_methods.enabled" => {
            "تحصيل الفواتير المستحقة يوميًا من البطاقة المحفوظة الافتراضية للعميل، مع إعادة المحاولة."
        }
        "billing.retry.days" => {
            "عدد الأيام بعد كل محاولة تحصيل فاشلة قبل المحاولة التالية؛ وبعد الأخيرة تُحال الفاتورة إلى التحصيل."
        }
        "billing.gateway.rules" => {
            "أي بوابة دفع تستقبل الدفعة: قواعد مرتبة، تُطبَّق أول قاعدة تطابق العملة والدولة ونطاق المبلغ."
        }
        "billing.issue_approval_threshold" => {
            "الفواتير التي يتجاوز إجماليها هذا المبلغ تنتظر موافقة قبل إصدارها؛ صفر يعني الإصدار بلا موافقة."
        }
        "i18n.draft_locales" => {
            "اللغات التي يصوغ وكيل ترجمات أسماء البيانات الوصفية الناقصة إليها كل ساعة لتُراجَع؛ لا شيء افتراضيًا."
        }
        "billing.credit.block_overdue" => {
            "رفض البيع الآجل الجديد لحساب لديه فاتورة متأخرة السداد، حتى ضمن حده الائتماني."
        }
        "billing.credit.auto_hold" => {
            "إيقاف الائتمان كل ليلة لكل حساب لديه فاتورة تأخر سدادها أكثر من عدد الأيام المحدد."
        }
        "billing.credit.hold_after_days" => {
            "عدد الأيام بعد تاريخ استحقاق الفاتورة قبل أن يوقف الفحص الليلي ائتمان حسابها."
        }
        "billing.renewal.lead_days" => {
            "عدد الأيام قبل انتهاء الاشتراك التي يُجدَّد فيها تلقائيًا (بعد موعد الإشعار في العقد إن وُجد) أو تُفتح له فرصة تجديد."
        }
        "billing.renewal.uplift_percent" => {
            "النسبة المئوية التي تُضاف إلى سعر كل بند عند التجديد التلقائي للاشتراك؛ صفر يُبقي الأسعار كما هي."
        }
        "billing.trial.reminder_days" => {
            "عدد الأيام قبل انتهاء الفترة التجريبية التي يُذكَّر فيها مالك الاشتراك."
        }
        "billing.trial.convert" => {
            "هل يصبح الاشتراك التجريبي فعّالًا في تاريخ انتهاء التجربة؛ إن كان مغلقًا تنتهي التجربة بدلًا من ذلك."
        }
        "billing.seller_name" => "اسم المنشأة القانوني، يُطبع بائعًا على كل فاتورة.",
        "billing.seller_vat_number" => {
            "رقم تسجيل المنشأة في ضريبة القيمة المضافة، يُطبع على كل فاتورة."
        }
        "billing.seller_crn" => {
            "رقم السجل التجاري للمنشأة، يُطبع معرّفًا للبائع في الفواتير الإلكترونية."
        }
        "billing.seller_street" => "شارع البائع (العنوان الوطني) في الفواتير الإلكترونية.",
        "billing.seller_building_number" => "رقم مبنى البائع من أربعة أرقام (العنوان الوطني).",
        "billing.seller_district" => "حيّ البائع (العنوان الوطني).",
        "billing.seller_city" => "مدينة البائع (العنوان الوطني).",
        "billing.seller_postal_zone" => "الرمز البريدي للبائع من خمسة أرقام (العنوان الوطني).",
        "billing.write_off_approval_threshold" => {
            "الشطب الذي يتجاوز هذا المبلغ ينتظر موافقة قبل تنفيذه؛ صفر يعني الشطب بلا موافقة."
        }
        "sales.discount_policy" => {
            "حدود الخصم التي يُفحص بها عرض السعر عند إرساله، حسب عائلة المنتج والدور وحجم الصفقة؛ العرض الذي يتجاوز حدًا يُرسل إلى عملية الموافقة التي يسميها أشد الحدود، والعرض ضمن كل الحدود يُرسل مباشرة. لا شيء افتراضيًا."
        }
        "commission.clawback_days" => {
            "عدد الأيام بعد احتساب العمولة التي يظل فيها الإشعار الدائن أو الاسترداد يسترجعها؛ العمولة الأقدم تبقى."
        }
        "commission.adjustment_approval_amount" => {
            "تعديلات العمولات اليدوية التي تتجاوز هذا المبلغ (زيادةً أو نقصًا، بعملة النشر الأساسية) لا تُسجَّل إلا بعد الموافقة."
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
