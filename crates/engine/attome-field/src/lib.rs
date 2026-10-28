use attome_core::FieldType;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};

/// A2-T2: built-in text formats.
pub mod formats;

// ── Field options (stored as `options` JSONB on attribute_info,
// migration 0029) ─────────────────────────────────────────────────────────

/// Optional presentation hints for a single `choice` value — a colored pill
/// and/or icon in the grid instead of plain text. Purely cosmetic: never
/// consulted by `validate`/`validate_choice`, which only check membership in
/// `choices`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ChoiceStyle {
    pub color: Option<String>,
    pub icon: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ChoiceOptions {
    /// Allowed string values for this field.
    pub choices: Vec<String>,
    /// Whether the field accepts multiple selected values.
    pub multi: bool,
    /// Per-value display styling, keyed by the choice string. Absent/empty
    /// means "no decoration" — the grid falls back to plain text.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub choice_styles: HashMap<String, ChoiceStyle>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FileOptions {
    /// Whether the field accepts multiple uploaded files (stored as a JSON
    /// array of object-key strings) instead of a single one.
    pub multi: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct LookupOptions {
    /// The entity this field points to.
    pub target_entity_id: Option<uuid::Uuid>,
    /// Field on the target entity to display (default: "name").
    pub display_field: Option<String>,
    /// A17-T1: this lookup from the entity to itself is its hierarchy; each
    /// row keeps its tree path, so subtree reads are one prefix scan.
    #[serde(default)]
    pub hierarchy: bool,
}

/// Range enforcement for `Number`/`Currency` fields. Either bound may be
/// omitted; omitting both makes the field unbounded (today's implicit
/// behavior). `Currency` reuses this struct rather than defining its own —
/// a currency field is a plain NUMERIC amount in the system base (USD,
/// always 1:1); it carries no currency-code option because there is nothing
/// server-side to store per field (display conversion to a viewer's
/// preferred currency is entirely an Angular concern against a static rate
/// table, never persisted or validated here).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NumberOptions {
    /// Inclusive lower bound. `None` means no lower bound.
    pub min: Option<f64>,
    /// Inclusive upper bound. `None` means no upper bound.
    pub max: Option<f64>,
}

/// AG1-T7 — how a `Date` field is shown: `gregorian`, `hijri` or `both`.
/// Absent means the viewing person's own calendar preference. Display only:
/// the stored value is always the Gregorian date.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DateOptions {
    pub display_calendar: Option<String>,
}

/// The `display_calendar` values a `Date` field accepts.
pub const DISPLAY_CALENDARS: &[&str] = &["gregorian", "hijri", "both"];

/// F012 — format enforcement for `Text` fields (phone/ID/IBAN-style masks).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TextOptions {
    /// A regex a value must fully match (anchored at both ends regardless of
    /// whether the caller wrote `^`/`$`) to be accepted. `None`/absent means
    /// no format constraint — plain shape-only Text validation.
    pub pattern: Option<String>,
    /// Human-readable description of the expected format, e.g. "IBAN" — for
    /// error messages and (later) the Angular field editor; never itself
    /// interpreted as a pattern.
    pub mask_description: Option<String>,
    /// C-29 (M01 §7) — the HTML `<input>` type/keyboard hint the generic
    /// record form should use for this text field: one of "text" | "email"
    /// | "tel" | "url". `None`/absent means the client falls back to its own
    /// name-based heuristic (`field-input.component.ts::textType()`) — this
    /// is additive metadata, not a required migration, since every existing
    /// text field's `options` (or lack of one) already round-trips through
    /// this same JSONB column (migration 0029); nothing needs backfilling
    /// for the fallback to keep working exactly as before. Never itself
    /// validated against `pattern` — a deployment wanting both sets both.
    pub text_type: Option<String>,
    /// A2-T2: a built-in format ([`formats::FORMATS`]: email, phone, url,
    /// iban, Gulf identity numbers, percent, duration) every write must
    /// match, after normalising. Checked alongside `pattern` when both are
    /// set.
    #[serde(default)]
    pub format: Option<String>,
}

/// The only values `TextOptions.text_type` may hold — validated at write
/// time by [`validate_options`] so a typo doesn't silently reach the client
/// as an unrecognized hint (`field-input.component.ts` already falls back to
/// plain `text` for anything it doesn't recognize, but the admin API should
/// still reject it rather than accept silently-inert metadata).
const VALID_TEXT_TYPES: [&str; 4] = ["text", "email", "tel", "url"];

/// Shared by `Icon`/`Color` field-value validation (`validate`) and
/// `choice_styles` validation (`validate_choice_styles`) — a `color` value is
/// always a 6-digit hex string, whether it's a standalone field or a
/// per-choice style.
#[expect(
    clippy::expect_used,
    reason = "a literal regex that is known to compile"
)]
static HEX_COLOR_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^#[0-9a-fA-F]{6}$").expect("static regex is valid"));
/// Shared by `Icon`/`Color` field-value validation (`validate`) and
/// `choice_styles` validation — an `icon` value is a CSS glyph-class name
/// (e.g. `la-robot`), whether it's a standalone field or a per-choice style.
#[expect(
    clippy::expect_used,
    reason = "a literal regex that is known to compile"
)]
static ICON_CLASS_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-zA-Z0-9 _-]{1,64}$").expect("static regex is valid"));

// ── Normalisation (A3-T2) ─────────────────────────────────────────────────────

/// Arabic-Indic (U+0660..9) and Eastern Arabic-Indic (U+06F0..9) digits as
/// Western digits, and the Arabic decimal separator (U+066B) as `.`.
pub fn western_digits(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{0660}'..='\u{0669}' => char::from(b'0' + (c as u32 - 0x0660) as u8),
            '\u{06F0}'..='\u{06F9}' => char::from(b'0' + (c as u32 - 0x06F0) as u8),
            '\u{066B}' => '.',
            '\u{066C}' => ',',
            c => c,
        })
        .collect()
}

/// A phone number in E.164's shape as far as the input allows: Western
/// digits, separators (spaces, dashes, dots, brackets) dropped, a leading
/// `00` written as `+`. A number without a country code keeps its digits;
/// no country is guessed.
pub fn phone_e164(text: &str) -> String {
    let digits = western_digits(text);
    let trimmed = digits.trim();
    let plus = trimmed.starts_with('+');
    let mut out: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    if plus {
        out.insert(0, '+');
    } else if let Some(rest) = out.strip_prefix("00") {
        out = format!("+{rest}");
    }
    out
}

/// The value as it should be stored, before validation (A3-T2), or `None`
/// when it is already in shape. Text is trimmed; a `tel` field becomes
/// E.164-shaped; an `email` field is lower-cased; a masked field (an ID, an
/// IBAN) and a number sent as text get Western digits. Free text keeps its
/// own digits: rewriting what a person wrote is not normalisation.
pub fn normalize(field_type: &FieldType, value: &Value, options: Option<&Value>) -> Option<Value> {
    // A2-T3: a point object keeps only its `lat` and `lng`.
    if *field_type == FieldType::Geolocation && value.is_object() {
        let shaped = geolocation_of(value)?;
        return (shaped != *value).then_some(shaped);
    }
    let text = value.as_str()?;
    let changed = match field_type {
        FieldType::Text => {
            let opts = options
                .and_then(|o| serde_json::from_value::<TextOptions>(o.clone()).ok())
                .unwrap_or_default();
            if let Some(format) = opts.format.as_deref().filter(|f| formats::is_format(f)) {
                let shaped = Value::String(formats::normalize(format, text));
                return (shaped != *value).then_some(shaped);
            }
            match opts.text_type.as_deref() {
                Some("tel") => Value::String(phone_e164(text)),
                Some("email") => Value::String(text.trim().to_lowercase()),
                _ if opts.pattern.as_deref().is_some_and(|p| !p.is_empty()) => {
                    Value::String(western_digits(text.trim()))
                }
                _ => Value::String(text.trim().to_owned()),
            }
        }
        FieldType::Number | FieldType::Currency => {
            let western = western_digits(text.trim()).replace(',', "");
            Value::Number(
                western
                    .parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)?,
            )
        }
        FieldType::Choice => Value::String(text.trim().to_owned()),
        // A2-T3: `"lat,lng"` is stored as `{"lat": .., "lng": ..}`.
        FieldType::Geolocation => geolocation_of(value)?,
        _ => return None,
    };
    (changed != *value).then_some(changed)
}

// ── Validation ────────────────────────────────────────────────────────────────

/// A2-T1: whether `s` is a time of day, `HH:MM` or `HH:MM:SS`. Pure.
pub fn time_ok(s: &str) -> bool {
    chrono::NaiveTime::parse_from_str(s, "%H:%M:%S").is_ok()
        || chrono::NaiveTime::parse_from_str(s, "%H:%M").is_ok()
}

/// A2-T3: a point as it is stored, `{"lat": .., "lng": ..}`, from that
/// object or from `"lat,lng"` text (Arabic digits allowed); `None` when the
/// value is neither or a coordinate is out of range. Pure.
pub fn geolocation_of(value: &Value) -> Option<Value> {
    let (lat, lng) = match value {
        Value::Object(map) => (
            map.get("lat").and_then(Value::as_f64)?,
            map.get("lng").and_then(Value::as_f64)?,
        ),
        Value::String(s) => {
            let western = western_digits(s);
            let (lat, lng) = western.split_once(',')?;
            (
                lat.trim().parse::<f64>().ok()?,
                lng.trim().parse::<f64>().ok()?,
            )
        }
        _ => return None,
    };
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lng) {
        return None;
    }
    Some(serde_json::json!({ "lat": lat, "lng": lng }))
}

/// Validates that `value` is an acceptable JSON representation for `field_type`.
/// Pass `options` (the `options` JSONB from entity_fields) for Choice/Lookup checks.
pub fn validate(
    field_type: &FieldType,
    value: &Value,
    options: Option<&Value>,
) -> Result<(), AppError> {
    match field_type {
        FieldType::Text => {
            let s = value.as_str().ok_or_else(|| type_err("text", value))?;
            if let Some(opts_val) = options
                && let Ok(opts) = serde_json::from_value::<TextOptions>(opts_val.clone())
            {
                validate_text_mask(s, &opts)?;
                if let Some(format) = opts.format.as_deref() {
                    formats::check(format, s).map_err(AppError::Validation)?;
                }
            }
        }
        FieldType::Number | FieldType::Currency => {
            let n = value
                .as_f64()
                .ok_or_else(|| type_err(field_type.as_str(), value))?;
            if let Some(opts_val) = options
                && let Ok(opts) = serde_json::from_value::<NumberOptions>(opts_val.clone())
            {
                validate_number_bounds(n, &opts)?;
            }
        }
        // A2-T1: a time of day, `HH:MM` or `HH:MM:SS`.
        FieldType::Time => {
            let s = value
                .as_str()
                .ok_or_else(|| type_err("time (HH:MM or HH:MM:SS)", value))?;
            if !time_ok(s) {
                return Err(AppError::Validation(format!(
                    "time value must be HH:MM or HH:MM:SS, got: {s}"
                )));
            }
        }
        // A2-T1: a day is only `YYYY-MM-DD`, so it never shifts across zones.
        FieldType::Date => {
            let s = value
                .as_str()
                .ok_or_else(|| type_err("date (YYYY-MM-DD)", value))?;
            chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| {
                AppError::Validation(format!("date value must be YYYY-MM-DD, got: {s}"))
            })?;
        }
        FieldType::DateTime => {
            let s = value
                .as_str()
                .ok_or_else(|| type_err("date (ISO 8601 string)", value))?;
            chrono::DateTime::parse_from_rfc3339(s)
                .or_else(|_| {
                    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
                        .map(|_| chrono::DateTime::default())
                })
                .map_err(|_| {
                    AppError::Validation(format!(
                        "date value must be ISO 8601 (YYYY-MM-DD or RFC 3339), got: {s}"
                    ))
                })?;
        }
        FieldType::Bool => {
            if !value.is_boolean() {
                return Err(type_err("bool", value));
            }
        }
        FieldType::Choice => {
            if let Some(opts_val) = options
                && let Ok(opts) = serde_json::from_value::<ChoiceOptions>(opts_val.clone())
                && !opts.choices.is_empty()
            {
                validate_choice(value, &opts)?;
            }
        }
        FieldType::Lookup => {
            let s = value
                .as_str()
                .ok_or_else(|| type_err("lookup (UUID string)", value))?;
            uuid::Uuid::parse_str(s).map_err(|_| {
                AppError::Validation(format!("lookup value must be a valid UUID, got: {s}"))
            })?;
        }
        // B-R6 (D-604): a formula's value is computed on every write by the
        // entity engine and merged in *after* this validator runs, so any
        // value reaching here was written by a client — refused outright.
        FieldType::Formula => {
            return Err(AppError::Validation(
                "is a formula field; its value is computed and cannot be written".into(),
            ));
        }
        // B-R7 (D-605): any string; the entity engine sanitizes it against
        // the rich-text allow-list before it is stored.
        FieldType::RichText => {
            if !value.is_string() {
                return Err(type_err("rich_text (HTML string)", value));
            }
        }
        FieldType::File | FieldType::Image => {
            let is_multi = options
                .and_then(|o| serde_json::from_value::<FileOptions>(o.clone()).ok())
                .map(|o| o.multi)
                .unwrap_or(false);
            if is_multi {
                validate_multi_file(value)?;
            } else if !value.is_string() {
                return Err(type_err("file (object key string)", value));
            }
        }
        FieldType::Icon => {
            let s = value.as_str().ok_or_else(|| type_err("icon", value))?;
            if !ICON_CLASS_RE.is_match(s) {
                return Err(AppError::Validation(format!(
                    "icon value must be 1-64 chars of letters, digits, spaces, '-', '_', got: {s}"
                )));
            }
        }
        FieldType::Color => {
            let s = value.as_str().ok_or_else(|| type_err("color", value))?;
            if !HEX_COLOR_RE.is_match(s) {
                return Err(AppError::Validation(format!(
                    "color value must be a 6-digit hex color (e.g. #22c55e), got: {s}"
                )));
            }
        }
        // A2-T3: a point with lat in -90..90 and lng in -180..180.
        FieldType::Geolocation => {
            if geolocation_of(value).is_none() {
                return Err(AppError::Validation(format!(
                    "geolocation value must be {{\"lat\": .., \"lng\": ..}} or \"lat,lng\" \
                     with lat in -90..90 and lng in -180..180, got: {value}"
                )));
            }
        }
        // A2-T3: any JSON document; with `options.schema`, one that matches it.
        FieldType::Json => {
            if let Some(schema) = options.and_then(|o| o.get("schema")) {
                attome_core::setting_store::validate_against_schema(value, schema)
                    .map_err(|reason| AppError::Validation(format!("json value {reason}")))?;
            }
        }
    }
    Ok(())
}

fn validate_number_bounds(n: f64, opts: &NumberOptions) -> Result<(), AppError> {
    if let Some(min) = opts.min
        && n < min
    {
        return Err(AppError::Validation(format!(
            "value {n} is below the minimum allowed ({min})"
        )));
    }
    if let Some(max) = opts.max
        && n > max
    {
        return Err(AppError::Validation(format!(
            "value {n} is above the maximum allowed ({max})"
        )));
    }
    Ok(())
}

fn validate_choice(value: &Value, opts: &ChoiceOptions) -> Result<(), AppError> {
    if opts.multi {
        let items = value.as_array().ok_or_else(|| {
            AppError::Validation("multi-select choice field expects a JSON array".to_owned())
        })?;
        for item in items {
            let s = item.as_str().ok_or_else(|| {
                AppError::Validation("each choice item must be a string".to_owned())
            })?;
            if !opts.choices.contains(&s.to_owned()) {
                return Err(AppError::Validation(format!(
                    "'{s}' is not a valid choice; allowed: {:?}",
                    opts.choices
                )));
            }
        }
    } else {
        let s = value.as_str().ok_or_else(|| {
            AppError::Validation("single-select choice field expects a string".to_owned())
        })?;
        if !opts.choices.contains(&s.to_owned()) {
            return Err(AppError::Validation(format!(
                "'{s}' is not a valid choice; allowed: {:?}",
                opts.choices
            )));
        }
    }
    Ok(())
}

/// Validates `choice_styles` against the sibling `choices` list — called
/// from `validate_options` at write time (never from `validate`, which
/// governs record values, not presentation). Rejects a style entry for a
/// value that isn't an allowed choice, and rejects malformed `color`/`icon`
/// strings before they're persisted and later interpolated into a CSS
/// custom property / class attribute on the frontend.
fn validate_choice_styles(opts: &ChoiceOptions) -> Result<(), AppError> {
    for (value, style) in &opts.choice_styles {
        if !opts.choices.contains(value) {
            return Err(AppError::Validation(format!(
                "choice_styles has an entry for '{value}', which is not in choices: {:?}",
                opts.choices
            )));
        }
        if let Some(color) = style.color.as_deref()
            && !HEX_COLOR_RE.is_match(color)
        {
            return Err(AppError::Validation(format!(
                "choice_styles['{value}'].color must be a 6-digit hex color (e.g. #22c55e), got: {color}"
            )));
        }
        if let Some(icon) = style.icon.as_deref()
            && !ICON_CLASS_RE.is_match(icon)
        {
            return Err(AppError::Validation(format!(
                "choice_styles['{value}'].icon must be 1-64 chars of letters, digits, spaces, '-', '_', got: {icon}"
            )));
        }
    }
    Ok(())
}

/// A multi-file field stores a JSON array of object-key strings — mirrors
/// `validate_choice`'s multi arm, minus the allow-list check (a `choice`
/// field validates against a fixed option set; a `file` reference is only
/// ever checked against `upload_session` at the mutation layer,
/// which `attome-field` — a pure, DB-free crate — cannot reach).
fn validate_multi_file(value: &Value) -> Result<(), AppError> {
    let items = value
        .as_array()
        .ok_or_else(|| AppError::Validation("multi-file field expects a JSON array".to_owned()))?;
    for item in items {
        if !item.is_string() {
            return Err(type_err("file (object key string)", item));
        }
    }
    Ok(())
}

/// A predicate over a text value, as [`format_matcher`] returns it.
pub type FormatMatcher = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// L6-T3: a checker of an attribute's declared format (`options.pattern`,
/// the same anchored full match writes are held to), for profiling; `None`
/// without a pattern or with one that does not compile.
pub fn format_matcher(options: Option<&Value>) -> Option<FormatMatcher> {
    let pattern = options?
        .get("pattern")?
        .as_str()
        .filter(|p| !p.is_empty())?;
    let re = compiled_pattern(pattern).ok()?;
    Some(Box::new(move |s: &str| re.is_match(s)))
}

/// F012: `pattern` is always anchored full-match, even if the caller didn't
/// write `^`/`$` themselves — a mask describes the whole field's shape, not a
/// substring, so an unanchored `\d{3}` would wrongly accept "abc123def".
fn validate_text_mask(s: &str, opts: &TextOptions) -> Result<(), AppError> {
    let Some(pattern) = opts.pattern.as_deref().filter(|p| !p.is_empty()) else {
        return Ok(());
    };
    let re = compiled_pattern(pattern)?;
    if !re.is_match(s) {
        let desc = opts.mask_description.as_deref().unwrap_or(pattern);
        return Err(AppError::Validation(format!(
            "'{s}' does not match the required format ({desc})"
        )));
    }
    Ok(())
}

/// Upper bound on distinct mask patterns held by [`MASK_CACHE`]. Patterns are
/// admin-authored metadata, so the real population is a handful per deployment;
/// the cap only stops a pathological metadata set from growing the map without
/// limit.
const MASK_CACHE_MAX: usize = 512;

/// Bounded, process-local cache of compiled mask regexes, keyed by the raw
/// `pattern` string exactly as written in the field's `options` blob.
///
/// Before this existed, [`compiled_pattern`] allocated a `String` and ran
/// `regex::Regex::new` on **every** call — and `validate_text_mask` calls it on
/// every record create and update for every masked text field, i.e. on the hot
/// write path (PLATFORM-REVIEW-2026-08-24 §4 / PERF-1).
///
/// Per coding-guidelines §5, the cache contract:
///
/// - **Source of truth:** `TextOptions.pattern` inside the `options` JSONB on
///   `attribute_info` (migration 0029). This cache never answers
///   *which* pattern a field has — only what a given pattern string compiles to.
/// - **Key shape:** the raw, pre-anchoring pattern string. Anchoring is a pure
///   function of the key, so key and value are 1:1.
/// - **TTL / invalidation:** none, and none is needed. The cache is
///   content-addressed: a compiled `Regex` is a pure function of its pattern, so
///   an entry cannot go stale. An admin editing a field's mask produces a
///   *different* key; the previous entry becomes unused, never wrong. That is
///   why a process-local map needs no cross-node pub/sub invalidation here — it
///   is not shared mutable state whose correctness depends on every node
///   agreeing on a value.
/// - **Failure behavior:** an invalid pattern returns `AppError::Validation` and
///   is never inserted, so a bad pattern costs one failed compile per call
///   rather than poisoning the cache. `validate_options` rejects such patterns
///   at admin-write time anyway, so this path is close to unreachable.
/// - **Cold start:** empty; the first write per pattern compiles it. Two threads
///   racing on the same missing key both compile and both insert the same value,
///   which is wasteful once and never incorrect.
static MASK_CACHE: LazyLock<RwLock<HashMap<String, Arc<regex::Regex>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Anchors `pattern` at both ends unless already anchored — shared by
/// `validate_text_mask` (checking a value) and `validate_options` (checking
/// the pattern itself compiles before it's ever persisted). The compiled result
/// is memoized in [`MASK_CACHE`]; see that item for the cache contract.
fn compiled_pattern(pattern: &str) -> Result<Arc<regex::Regex>, AppError> {
    // Hit path: one read lock and one hash lookup, no allocation, no compile.
    if let Some(re) = read_mask_cache().get(pattern) {
        return Ok(Arc::clone(re));
    }

    // Z11-T15: the rule language's `matches` compile, so a mask is the same
    // full match (`^(?:pattern)$`, which also anchors every alternative of
    // `a|b`) under the same size limits.
    let re = Arc::new(
        attome_rules::full_match_regex(pattern)
            .map_err(|e| AppError::Validation(format!("invalid mask pattern '{pattern}': {e}")))?,
    );

    let mut cache = write_mask_cache();
    if cache.len() >= MASK_CACHE_MAX && !cache.contains_key(pattern) {
        // Drop everything rather than evict by LRU: recompiling is microseconds,
        // the map rebuilds itself from the next writes, and reaching the cap at
        // all means the metadata is pathological rather than merely busy.
        cache.clear();
    }
    cache.insert(pattern.to_owned(), Arc::clone(&re));
    Ok(re)
}

// A panic while a `MASK_CACHE` guard is held cannot leave the map logically
// inconsistent — the only mutations are `clear`/`insert` of a value that is a
// pure function of its key — so poisoning is recovered rather than propagated.
// Doing otherwise would turn one unrelated panic into a permanently failing
// validation path for every masked field in the process.
fn read_mask_cache() -> std::sync::RwLockReadGuard<'static, HashMap<String, Arc<regex::Regex>>> {
    MASK_CACHE.read().unwrap_or_else(|e| e.into_inner())
}

fn write_mask_cache() -> std::sync::RwLockWriteGuard<'static, HashMap<String, Arc<regex::Regex>>> {
    MASK_CACHE.write().unwrap_or_else(|e| e.into_inner())
}

/// Validates that an `options` JSONB blob is well-formed for `field_type` —
/// called by the admin attribute create/update handlers BEFORE persisting,
/// so a malformed pattern or option shape is rejected at write time rather
/// than silently accepted and only discovered the first time a record write
/// runs `validate` against it. Every field type accepts an absent/empty
/// options blob (no-op); only a *present* blob is shape-checked.
pub fn validate_options(field_type: &FieldType, options: &Value) -> Result<(), AppError> {
    validate_default(field_type, options)?;
    if let Some(scan) = options.get("scan") {
        validate_scan(field_type, scan)?;
    }
    if let Some(external_id) = options.get("external_id") {
        validate_external_id(field_type, external_id)?;
    }
    if let Some(unique) = options.get("unique") {
        validate_unique(field_type, unique)?;
    }
    if options.get("strict").is_some_and(|s| !s.is_boolean()) {
        return Err(AppError::Validation("strict: true or false".into()));
    }
    if options.get("create_only").is_some_and(|s| !s.is_boolean()) {
        return Err(AppError::Validation("create_only: true or false".into()));
    }
    if let Some(counter) = options.get("counts_changes") {
        validate_change_counter(field_type, counter)?;
    }
    if let Some(stamp) = options.get("stamps_changes") {
        validate_change_stamp(field_type, stamp)?;
    }
    if let Some(editable_by) = options.get("editable_by")
        && !matches!(editable_by.as_str(), Some("everyone" | "integrations_only"))
    {
        return Err(AppError::Validation(
            "editable_by: everyone or integrations_only".into(),
        ));
    }
    // The default, the scan settings and the external id are checked above;
    // each type's own shape below.
    let stripped;
    let options = match options.as_object() {
        Some(map)
            if map.contains_key("default")
                || map.contains_key("scan")
                || map.contains_key("external_id")
                || map.contains_key("unique")
                || map.contains_key("strict")
                || map.contains_key("create_only")
                || map.contains_key("counts_changes")
                || map.contains_key("stamps_changes")
                || map.contains_key("editable_by") =>
        {
            let mut map = map.clone();
            map.remove("default");
            map.remove("scan");
            map.remove("external_id");
            map.remove("unique");
            map.remove("strict");
            map.remove("create_only");
            map.remove("counts_changes");
            map.remove("stamps_changes");
            map.remove("editable_by");
            if map.is_empty() {
                // Only a default or scan settings: nothing else to check.
                return Ok(());
            }
            stripped = Value::Object(map);
            &stripped
        }
        _ => options,
    };
    match field_type {
        FieldType::Choice => {
            let opts = serde_json::from_value::<ChoiceOptions>(options.clone())
                .map_err(|e| AppError::Validation(format!("invalid choice options: {e}")))?;
            validate_choice_styles(&opts)?;
        }
        FieldType::Text => {
            let opts = serde_json::from_value::<TextOptions>(options.clone())
                .map_err(|e| AppError::Validation(format!("invalid text options: {e}")))?;
            if let Some(pattern) = opts.pattern.as_deref().filter(|p| !p.is_empty()) {
                compiled_pattern(pattern)?;
            }
            if let Some(format) = opts.format.as_deref()
                && !formats::is_format(format)
            {
                return Err(AppError::Validation(format!(
                    "format '{format}' is not one of {}",
                    formats::FORMATS.join("|")
                )));
            }
            if let Some(text_type) = opts.text_type.as_deref()
                && !VALID_TEXT_TYPES.contains(&text_type)
            {
                return Err(AppError::Validation(format!(
                    "text_type '{text_type}' is not one of {}",
                    VALID_TEXT_TYPES.join("|")
                )));
            }
        }
        FieldType::Lookup => {
            serde_json::from_value::<LookupOptions>(options.clone())
                .map_err(|e| AppError::Validation(format!("invalid lookup options: {e}")))?;
        }
        FieldType::File | FieldType::Image => {
            serde_json::from_value::<FileOptions>(options.clone())
                .map_err(|e| AppError::Validation(format!("invalid file options: {e}")))?;
        }
        // B-R6 (D-604): the shape only; the expression is compiled against
        // the entity's fields by `attome-metadata`'s reconcile before the field
        // is saved (`attome_core::formula::compile_formula`).
        FieldType::Formula => {
            attome_core::formula::parse_options(Some(options))?;
        }
        FieldType::Date | FieldType::DateTime => {
            let opts = serde_json::from_value::<DateOptions>(options.clone())
                .map_err(|e| AppError::Validation(format!("invalid date options: {e}")))?;
            if let Some(calendar) = opts.display_calendar.as_deref()
                && !DISPLAY_CALENDARS.contains(&calendar)
            {
                return Err(AppError::Validation(format!(
                    "display_calendar '{calendar}' is not one of {}",
                    DISPLAY_CALENDARS.join("|")
                )));
            }
        }
        // A2-T3: a json field's only option is its JSON Schema, an object.
        FieldType::Json => {
            if let Some(obj) = options.as_object() {
                if let Some(key) = obj.keys().find(|k| *k != "schema") {
                    return Err(AppError::Validation(format!(
                        "json fields accept only a `schema` option, not `{key}`"
                    )));
                }
                if obj.get("schema").is_some_and(|s| !s.is_object()) {
                    return Err(AppError::Validation(
                        "json option `schema` must be a JSON Schema object".into(),
                    ));
                }
            }
        }
        FieldType::Number | FieldType::Currency => {
            let opts = serde_json::from_value::<NumberOptions>(options.clone())
                .map_err(|e| AppError::Validation(format!("invalid number options: {e}")))?;
            if let (Some(min), Some(max)) = (opts.min, opts.max)
                && min > max
            {
                return Err(AppError::Validation(format!(
                    "number options min ({min}) must not exceed max ({max})"
                )));
            }
        }
        _ => {
            return Err(AppError::Validation(format!(
                "{field_type} fields do not accept an `options` configuration"
            )));
        }
    }
    Ok(())
}

/// B16-T3: the code formats a scan-enabled field reads.
pub const SCAN_FORMATS: &[&str] = &[
    "ean_13",
    "ean_8",
    "upc_a",
    "upc_e",
    "code_128",
    "code_39",
    "qr_code",
    "data_matrix",
    "pdf417",
];

/// B16-T3: `options.scan` — a field filled by scanning a code.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanOptions {
    #[serde(default = "scan_enabled_default")]
    pub enabled: bool,
    /// The formats read; at least one of [`SCAN_FORMATS`].
    pub formats: Vec<String>,
    /// The field a GS1 code's batch (AI 10) fills.
    #[serde(default)]
    pub gs1_batch_attribute: Option<String>,
    /// The field a GS1 code's expiry date (AI 17) fills.
    #[serde(default)]
    pub gs1_expiry_attribute: Option<String>,
    /// What a code matching no record does: `reject` or `offer_create`.
    #[serde(default = "scan_on_unknown_default")]
    pub on_unknown: String,
}

fn scan_enabled_default() -> bool {
    true
}

fn scan_on_unknown_default() -> String {
    "reject".to_owned()
}

/// B16-T3: a scan setting is for a text, number or lookup field, names known
/// formats, says `reject` or `offer_create` for an unknown code, and names
/// its GS1 target fields by logical name. That those fields exist on the
/// entity is checked where the entity is known.
fn validate_scan(field_type: &FieldType, scan: &Value) -> Result<(), AppError> {
    if !matches!(
        field_type,
        FieldType::Text | FieldType::Number | FieldType::Lookup
    ) {
        return Err(AppError::Validation(format!(
            "scan: a {field_type} field cannot be filled by scanning; use a text, number or lookup field"
        )));
    }
    let scan: ScanOptions = serde_json::from_value(scan.clone())
        .map_err(|e| AppError::Validation(format!("scan: {e}")))?;
    if scan.formats.is_empty() {
        return Err(AppError::Validation(
            "scan.formats: name at least one format".into(),
        ));
    }
    if let Some(unknown) = scan
        .formats
        .iter()
        .find(|f| !SCAN_FORMATS.contains(&f.as_str()))
    {
        return Err(AppError::Validation(format!(
            "scan.formats: '{unknown}' is not one of {}",
            SCAN_FORMATS.join("|")
        )));
    }
    if !matches!(scan.on_unknown.as_str(), "reject" | "offer_create") {
        return Err(AppError::Validation(
            "scan.on_unknown: reject or offer_create".into(),
        ));
    }
    for (key, name) in [
        ("gs1_batch_attribute", &scan.gs1_batch_attribute),
        ("gs1_expiry_attribute", &scan.gs1_expiry_attribute),
    ] {
        if let Some(name) = name
            && !(!name.is_empty()
                && name.len() <= 64
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
        {
            return Err(AppError::Validation(format!(
                "scan.{key}: '{name}' is not a field logical name"
            )));
        }
    }
    Ok(())
}

/// The longest external system name.
pub const EXTERNAL_ID_SYSTEM_MAX: usize = 64;

/// A29-T1: the system an external-id field holds ids for, from
/// `options.external_id.system`; `None` for an ordinary field. An entity may
/// have several external-id fields, one per system or more.
pub fn external_id_system(options: Option<&Value>) -> Option<&str> {
    options?
        .get("external_id")?
        .get("system")?
        .as_str()
        .filter(|s| !s.is_empty())
}

/// A3-T6: whether a field's value is unique among the entity's live
/// records: `options.unique: true`, or an external id (always unique).
pub fn is_unique(options: Option<&Value>) -> bool {
    external_id_system(options).is_some()
        || options
            .and_then(|o| o.get("unique"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

/// A29-T4: a field only integrations may write
/// (`options.editable_by: "integrations_only"`), such as an external id an
/// outside system owns: a person signed in to the app cannot change it.
pub fn integrations_only(options: Option<&Value>) -> bool {
    options
        .and_then(|o| o.get("editable_by"))
        .and_then(Value::as_str)
        == Some("integrations_only")
}

/// Which changes of the watched field a change counter counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountedChange {
    /// Any change to a different value (empty counts as a value).
    Any,
    /// A move to a later date or time, or a higher number.
    Later,
    /// A move to an earlier date or time, or a lower number.
    Earlier,
}

/// D5-T1: a number field that counts how often another field of the same
/// record changed (`options.counts_changes: {"field": "close_date",
/// "when": "later"}`), such as how many times a deal's close date was pushed
/// out. The engine adds one on every update that makes such a change; a
/// first value set where there was none is not counted.
pub fn change_counter(options: Option<&Value>) -> Option<(&str, CountedChange)> {
    let counter = options?.get("counts_changes")?;
    let field = counter.get("field")?.as_str()?;
    let when = match counter.get("when").and_then(Value::as_str).unwrap_or("any") {
        "later" => CountedChange::Later,
        "earlier" => CountedChange::Earlier,
        _ => CountedChange::Any,
    };
    Some((field, when))
}

/// D5-T2: a date field that holds when another field of the same record last
/// changed (`options.stamps_changes: {"field": "stage"}`), such as when a deal
/// entered its current stage. The engine sets it on create when the watched
/// field is given, and on every update that changes it.
pub fn change_stamp(options: Option<&Value>) -> Option<&str> {
    options?
        .get("stamps_changes")?
        .get("field")?
        .as_str()
        .filter(|f| !f.trim().is_empty())
}

fn validate_change_stamp(field_type: &FieldType, stamp: &Value) -> Result<(), AppError> {
    if !field_type.is_temporal() {
        return Err(AppError::Validation(
            "stamps_changes: only a date field can hold when a field changed".into(),
        ));
    }
    if stamp
        .get("field")
        .and_then(Value::as_str)
        .is_none_or(|f| f.trim().is_empty())
    {
        return Err(AppError::Validation(
            "stamps_changes: {\"field\": name}".into(),
        ));
    }
    Ok(())
}

fn validate_change_counter(field_type: &FieldType, counter: &Value) -> Result<(), AppError> {
    if *field_type != FieldType::Number {
        return Err(AppError::Validation(
            "counts_changes: only a number field can count changes".into(),
        ));
    }
    let field_ok = counter
        .get("field")
        .and_then(Value::as_str)
        .is_some_and(|f| !f.trim().is_empty());
    let when_ok = counter
        .get("when")
        .is_none_or(|w| matches!(w.as_str(), Some("any" | "later" | "earlier")));
    if !field_ok || !when_ok {
        return Err(AppError::Validation(
            "counts_changes: {\"field\": name, \"when\": any | later | earlier}".into(),
        ));
    }
    Ok(())
}

/// D5-T1: whether moving `old` to `new` is a change `when` counts. Numbers
/// compare as numbers, dates and times as instants (a bare date is its
/// midnight UTC), anything else as text. A first value (no `old`) is never
/// counted.
pub fn counts_as_change(old: Option<&Value>, new: Option<&Value>, when: CountedChange) -> bool {
    let old = old.filter(|v| !v.is_null());
    let Some(old) = old else {
        return false;
    };
    let new = new.filter(|v| !v.is_null());
    let Some(new) = new else {
        return when == CountedChange::Any;
    };
    let ordering = match (old.as_f64(), new.as_f64()) {
        (Some(a), Some(b)) => a.partial_cmp(&b),
        _ => match (as_instant(old), as_instant(new)) {
            (Some(a), Some(b)) => Some(a.cmp(&b)),
            _ => {
                let (a, b) = (value_text(old), value_text(new));
                Some(a.cmp(&b))
            }
        },
    };
    match (when, ordering) {
        (CountedChange::Any, Some(o)) => o != std::cmp::Ordering::Equal,
        (CountedChange::Later, Some(o)) => o == std::cmp::Ordering::Less,
        (CountedChange::Earlier, Some(o)) => o == std::cmp::Ordering::Greater,
        (_, None) => false,
    }
}

fn as_instant(value: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    let text = value.as_str()?.trim();
    if let Ok(at) = chrono::DateTime::parse_from_rfc3339(text) {
        return Some(at.with_timezone(&chrono::Utc));
    }
    if let Ok(at) = chrono::DateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f%#z") {
        return Some(at.with_timezone(&chrono::Utc));
    }
    let date = chrono::NaiveDate::parse_from_str(text.get(..10)?, "%Y-%m-%d").ok()?;
    Some(date.and_hms_opt(0, 0, 0)?.and_utc())
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Q15-T4: a field set when the record is created and never changed after
/// (`options.create_only: true`); an update that names it is refused.
pub fn create_only(options: Option<&Value>) -> bool {
    options
        .and_then(|o| o.get("create_only"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// A3-T6: a required field with `options.strict: true` is also refused
/// empty by the database (a CHECK constraint), not only by the engine.
pub fn strict_required(is_required: bool, options: Option<&Value>) -> bool {
    is_required
        && options
            .and_then(|o| o.get("strict"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

/// A3-T6: a number or currency field's `min`/`max`, which the database also
/// holds the column to (a CHECK constraint); `None` for other types or when
/// neither bound is set.
pub fn number_range(
    field_type: &str,
    options: Option<&Value>,
) -> Option<(Option<f64>, Option<f64>)> {
    if !matches!(field_type, "number" | "currency") {
        return None;
    }
    let options = options?;
    let bound = |key: &str| {
        options
            .get(key)
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite())
    };
    let (min, max) = (bound("min"), bound("max"));
    (min.is_some() || max.is_some()).then_some((min, max))
}

/// A3-T6: `options.unique` is a boolean on a text, number, date or lookup
/// field (a unique lookup makes the relationship one to one).
fn validate_unique(field_type: &FieldType, unique: &Value) -> Result<(), AppError> {
    if !unique.is_boolean() {
        return Err(AppError::Validation("unique: true or false".into()));
    }
    if unique == &Value::Bool(true)
        && !matches!(
            field_type,
            FieldType::Text
                | FieldType::Number
                | FieldType::Date
                | FieldType::DateTime
                | FieldType::Lookup
        )
    {
        return Err(AppError::Validation(format!(
            "unique: a {field_type} field cannot be unique; use a text, number, date or lookup field"
        )));
    }
    Ok(())
}

/// A29-T1: `options.external_id` is `{"system": "<name>"}` on a text or
/// number field: the id another system knows the record by. The name is
/// lowercase letters, digits, `_` or `-`, at most [`EXTERNAL_ID_SYSTEM_MAX`].
/// The value is unique among the entity's live records (a unique index).
fn validate_external_id(field_type: &FieldType, external_id: &Value) -> Result<(), AppError> {
    if !matches!(field_type, FieldType::Text | FieldType::Number) {
        return Err(AppError::Validation(format!(
            "external_id: a {field_type} field cannot hold an external id; use a text or number field"
        )));
    }
    let Some(map) = external_id.as_object() else {
        return Err(AppError::Validation(
            "external_id: expected {\"system\": \"<name>\"}".into(),
        ));
    };
    if let Some(unknown) = map.keys().find(|k| k.as_str() != "system") {
        return Err(AppError::Validation(format!(
            "external_id: unknown setting '{unknown}'"
        )));
    }
    let system = map.get("system").and_then(Value::as_str).unwrap_or("");
    if system.is_empty()
        || system.len() > EXTERNAL_ID_SYSTEM_MAX
        || !system
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return Err(AppError::Validation(format!(
            "external_id.system: 1 to {EXTERNAL_ID_SYSTEM_MAX} lowercase letters, digits, _ or -"
        )));
    }
    Ok(())
}

/// A28-T1: `options.default`, when present, is `{"kind": "fixed", "value":
/// <a value of the field's type>}`, `{"kind": "today"}` or `{"kind": "now"}`
/// (date fields), or `{"kind": "current_user"}` (lookup fields).
fn validate_default(field_type: &FieldType, options: &Value) -> Result<(), AppError> {
    let Some(default) = options.get("default") else {
        return Ok(());
    };
    let kind = default.get("kind").and_then(Value::as_str).unwrap_or("");
    match (kind, field_type) {
        ("fixed", _) => {
            let value = default
                .get("value")
                .ok_or_else(|| AppError::Validation("a fixed default needs a value".into()))?;
            validate(field_type, value, None).map_err(|_| {
                AppError::Validation(format!("the default value is not a valid {field_type}"))
            })
        }
        ("today" | "now", FieldType::Date | FieldType::DateTime) => Ok(()),
        ("current_user", FieldType::Lookup) => Ok(()),
        _ => Err(AppError::Validation(format!(
            "default kind '{kind}' does not apply to a {field_type} field"
        ))),
    }
}

fn type_err(expected: &str, got: &Value) -> AppError {
    AppError::Validation(format!("expected {expected}, got: {got}"))
}

// ── Tests (P1.8 pure-logic units; `validate` is wired into `entity_crud.rs`'s
// create/update path since 2026-07-13, audit #12) ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A2-T2: a text field with a format refuses a value that does not
    /// match it, after Arabic digits and separators are normalised.
    #[test]
    fn a_format_is_enforced_after_normalising() {
        let iban = json!({ "format": "iban" });
        let stored = normalize(
            &FieldType::Text,
            &json!("sa03 8000 0000 6080 1016 7519"),
            Some(&iban),
        )
        .expect("spaces dropped and upper-cased");
        assert_eq!(stored, json!("SA0380000000608010167519"));
        assert!(validate(&FieldType::Text, &stored, Some(&iban)).is_ok());
        let err = validate(
            &FieldType::Text,
            &json!("SA0380000000608010167518"),
            Some(&iban),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not a valid IBAN"), "{err}");

        let id = json!({ "format": "saudi_national_id" });
        let stored = normalize(&FieldType::Text, &json!("١٠٠٠٠٠٠٠٠٨"), Some(&id)).expect("digits");
        assert!(validate(&FieldType::Text, &stored, Some(&id)).is_ok());

        assert!(validate_options(&FieldType::Text, &json!({ "format": "iban" })).is_ok());
        assert!(validate_options(&FieldType::Text, &json!({ "format": "colour" })).is_err());
    }

    /// A29-T1: a text or number field can hold an external id.
    #[test]
    fn external_id_option_accepted_and_read() {
        let options = serde_json::json!({ "external_id": { "system": "sap" } });
        validate_options(&FieldType::Text, &options).unwrap();
        validate_options(&FieldType::Number, &options).unwrap();
        assert_eq!(external_id_system(Some(&options)), Some("sap"));
        assert_eq!(external_id_system(Some(&serde_json::json!({}))), None);
        assert_eq!(external_id_system(None), None);
        // Next to a text field's own settings.
        validate_options(
            &FieldType::Text,
            &serde_json::json!({ "external_id": { "system": "legacy-crm" }, "text_type": "email" }),
        )
        .unwrap();
    }

    /// A3-T6: `unique` on the types that can hold a unique index.
    #[test]
    fn unique_attribute_option() {
        let unique = serde_json::json!({ "unique": true });
        for field_type in [
            FieldType::Text,
            FieldType::Number,
            FieldType::Date,
            FieldType::Lookup,
        ] {
            validate_options(&field_type, &unique).unwrap();
        }
        assert!(validate_options(&FieldType::Bool, &unique).is_err());
        assert!(
            validate_options(&FieldType::Text, &serde_json::json!({ "unique": "yes" })).is_err()
        );
        validate_options(&FieldType::Bool, &serde_json::json!({ "unique": false })).unwrap();
        assert!(is_unique(Some(&unique)));
        assert!(is_unique(Some(
            &serde_json::json!({ "external_id": { "system": "sap" } })
        )));
        assert!(!is_unique(Some(&serde_json::json!({ "unique": false }))));
        assert!(!is_unique(None));
    }

    /// D5-T1: a change counter counts the moves its `when` names, never a
    /// first value, and only a number field may count.
    #[test]
    fn change_counter_counts_the_named_moves() {
        use serde_json::json;
        let later = json!({"counts_changes": {"field": "close_date", "when": "later"}});
        assert_eq!(
            change_counter(Some(&later)),
            Some(("close_date", CountedChange::Later))
        );
        let (a, b) = (json!("2026-10-01"), json!("2026-11-01T00:00:00+00:00"));
        assert!(counts_as_change(Some(&a), Some(&b), CountedChange::Later));
        assert!(!counts_as_change(Some(&b), Some(&a), CountedChange::Later));
        assert!(counts_as_change(Some(&b), Some(&a), CountedChange::Earlier));
        assert!(!counts_as_change(None, Some(&b), CountedChange::Any));
        assert!(!counts_as_change(
            Some(&json!("2026-10-01T00:00:00+00:00")),
            Some(&json!("2026-10-01")),
            CountedChange::Any
        ));
        assert!(counts_as_change(
            Some(&json!(3)),
            Some(&json!(5)),
            CountedChange::Later
        ));
        assert!(counts_as_change(
            Some(&json!("x")),
            None,
            CountedChange::Any
        ));
        assert!(validate_options(&FieldType::Number, &later).is_ok());
        assert!(validate_options(&FieldType::Text, &later).is_err());
        assert!(
            validate_options(
                &FieldType::Number,
                &json!({"counts_changes": {"field": "close_date", "when": "sideways"}})
            )
            .is_err()
        );
    }

    /// D5-T2: only a date field may stamp changes, and it must name a field.
    #[test]
    fn change_stamp_option() {
        use serde_json::json;
        let stamp = json!({"stamps_changes": {"field": "stage"}});
        assert_eq!(change_stamp(Some(&stamp)), Some("stage"));
        assert!(validate_options(&FieldType::Date, &stamp).is_ok());
        assert!(validate_options(&FieldType::Number, &stamp).is_err());
        assert!(validate_options(&FieldType::Date, &json!({"stamps_changes": {}})).is_err());
        assert_eq!(change_stamp(None), None);
    }

    /// A29-T4: `editable_by` locks a field to integrations.
    #[test]
    fn external_id_lock_option() {
        let locked = serde_json::json!({ "external_id": { "system": "sap" }, "editable_by": "integrations_only" });
        validate_options(&FieldType::Text, &locked).unwrap();
        assert!(integrations_only(Some(&locked)));
        assert!(!integrations_only(Some(
            &serde_json::json!({ "editable_by": "everyone" })
        )));
        assert!(!integrations_only(None));
        assert!(
            validate_options(
                &FieldType::Text,
                &serde_json::json!({ "editable_by": "admins" })
            )
            .is_err()
        );
    }

    /// A3-T6: the database-held range and strict required.
    #[test]
    fn unique_attribute_range_and_strict() {
        let options = serde_json::json!({ "min": 0, "max": 100 });
        assert_eq!(
            number_range("number", Some(&options)),
            Some((Some(0.0), Some(100.0)))
        );
        assert_eq!(number_range("text", Some(&options)), None);
        assert_eq!(number_range("number", Some(&serde_json::json!({}))), None);
        let strict = serde_json::json!({ "strict": true });
        assert!(strict_required(true, Some(&strict)));
        assert!(!strict_required(false, Some(&strict)));
        assert!(!strict_required(true, None));
        validate_options(&FieldType::Text, &strict).unwrap();
        assert!(validate_options(&FieldType::Text, &serde_json::json!({ "strict": 1 })).is_err());
    }

    #[test]
    fn external_id_option_refused_when_malformed() {
        for (field_type, options) in [
            (
                FieldType::Date,
                serde_json::json!({ "external_id": { "system": "sap" } }),
            ),
            (FieldType::Text, serde_json::json!({ "external_id": "sap" })),
            (FieldType::Text, serde_json::json!({ "external_id": {} })),
            (
                FieldType::Text,
                serde_json::json!({ "external_id": { "system": "SAP" } }),
            ),
            (
                FieldType::Text,
                serde_json::json!({ "external_id": { "system": "sap", "x": 1 } }),
            ),
        ] {
            assert!(
                validate_options(&field_type, &options).is_err(),
                "{options}"
            );
        }
    }

    /// B16-T3: a text field can be scanned.
    #[test]
    fn scan_options_accepted_on_text() {
        let options = serde_json::json!({
            "scan": {
                "formats": ["ean_13", "qr_code"],
                "gs1_batch_attribute": "batch_no",
                "on_unknown": "offer_create"
            }
        });
        assert!(validate_options(&FieldType::Text, &options).is_ok());
        let with_pattern =
            serde_json::json!({ "pattern": "[0-9]+", "scan": { "formats": ["code_128"] } });
        assert!(validate_options(&FieldType::Text, &with_pattern).is_ok());
    }

    #[test]
    fn scan_options_rejected_on_bool() {
        let options = serde_json::json!({ "scan": { "formats": ["ean_13"] } });
        let err = validate_options(&FieldType::Bool, &options).unwrap_err();
        assert!(err.to_string().contains("scan"), "{err}");
    }

    #[test]
    fn scan_options_unknown_format_422() {
        for scan in [
            serde_json::json!({ "formats": ["morse"] }),
            serde_json::json!({ "formats": [] }),
            serde_json::json!({ "formats": ["ean_13"], "on_unknown": "ignore" }),
            serde_json::json!({ "formats": ["ean_13"], "gs1_expiry_attribute": "Bad Name" }),
            serde_json::json!({ "formats": ["ean_13"], "extra": true }),
        ] {
            let options = serde_json::json!({ "scan": scan });
            assert!(
                matches!(
                    validate_options(&FieldType::Text, &options),
                    Err(AppError::Validation(_))
                ),
                "{options}"
            );
        }
    }

    #[test]
    fn normalize_trims_and_rewrites_digits_where_the_field_says_so() {
        let tel = serde_json::json!({ "text_type": "tel" });
        assert_eq!(
            normalize(
                &FieldType::Text,
                &serde_json::json!(" ٠٠٩٦٦ ٥٠-١٢٣-٤٥٦٧ "),
                Some(&tel)
            ),
            Some(serde_json::json!("+966501234567"))
        );
        assert_eq!(phone_e164("+966 (50) 123.4567"), "+966501234567");
        assert_eq!(
            phone_e164("0501234567"),
            "0501234567",
            "no country is guessed"
        );
        let email = serde_json::json!({ "text_type": "email" });
        assert_eq!(
            normalize(
                &FieldType::Text,
                &serde_json::json!(" Ada@Example.COM "),
                Some(&email)
            ),
            Some(serde_json::json!("ada@example.com"))
        );
        let masked = serde_json::json!({ "pattern": "[0-9]{10}" });
        assert_eq!(
            normalize(
                &FieldType::Text,
                &serde_json::json!("١٠١٠٢٠٣٠٤٠"),
                Some(&masked)
            ),
            Some(serde_json::json!("1010203040"))
        );
        // Free text keeps its own digits; only the ends are trimmed.
        assert_eq!(
            normalize(&FieldType::Text, &serde_json::json!(" الطابق ٣ "), None),
            Some(serde_json::json!("الطابق ٣"))
        );
        assert_eq!(
            normalize(&FieldType::Text, &serde_json::json!("ok"), None),
            None
        );
        // A number sent as Arabic text becomes a number.
        assert_eq!(
            normalize(&FieldType::Number, &serde_json::json!("١٬٢٥٠٫٥"), None),
            Some(serde_json::json!(1250.5))
        );
        assert_eq!(
            normalize(&FieldType::Number, &serde_json::json!(3), None),
            None
        );
    }
    use serde_json::json;

    #[test]
    fn formula_values_are_never_writable() {
        let err = validate(&FieldType::Formula, &json!(42), None).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
        assert!(validate(&FieldType::Formula, &json!("x"), None).is_err());
    }

    #[test]
    fn formula_options_need_expression_and_result_type() {
        assert!(
            validate_options(
                &FieldType::Formula,
                &json!({"expression": "a + 1", "result_type": "number"})
            )
            .is_ok()
        );
        assert!(validate_options(&FieldType::Formula, &json!({"expression": "a"})).is_err());
        assert!(
            validate_options(
                &FieldType::Formula,
                &json!({"expression": "a", "result_type": "choice"})
            )
            .is_err()
        );
    }

    #[test]
    fn rich_text_accepts_strings_only() {
        assert!(validate(&FieldType::RichText, &json!("<p>x</p>"), None).is_ok());
        assert!(validate(&FieldType::RichText, &json!(1), None).is_err());
        assert!(validate_options(&FieldType::RichText, &json!({"x": 1})).is_err());
    }

    #[test]
    fn image_validates_like_file() {
        assert!(validate(&FieldType::Image, &json!("e/1/f/k-a.png"), None).is_ok());
        assert!(validate(&FieldType::Image, &json!(1), None).is_err());
        let multi = json!({"multi": true});
        assert!(validate(&FieldType::Image, &json!(["a", "b"]), Some(&multi)).is_ok());
        assert!(validate_options(&FieldType::Image, &multi).is_ok());
    }

    #[test]
    fn text_accepts_string_rejects_number() {
        assert!(validate(&FieldType::Text, &json!("hello"), None).is_ok());
        assert!(validate(&FieldType::Text, &json!(42), None).is_err());
    }

    #[test]
    fn number_accepts_number_rejects_string() {
        assert!(validate(&FieldType::Number, &json!(42), None).is_ok());
        assert!(validate(&FieldType::Number, &json!(42.5), None).is_ok());
        assert!(validate(&FieldType::Number, &json!("42"), None).is_err());
    }

    #[test]
    fn number_bounds_enforce_min_and_max() {
        let opts = json!({ "min": 0, "max": 100 });
        assert!(validate(&FieldType::Number, &json!(50), Some(&opts)).is_ok());
        assert!(validate(&FieldType::Number, &json!(0), Some(&opts)).is_ok());
        assert!(validate(&FieldType::Number, &json!(100), Some(&opts)).is_ok());
        assert!(validate(&FieldType::Number, &json!(-1), Some(&opts)).is_err());
        assert!(validate(&FieldType::Number, &json!(101), Some(&opts)).is_err());
    }

    #[test]
    fn number_bounds_allow_one_sided_ranges() {
        let min_only = json!({ "min": 0 });
        assert!(validate(&FieldType::Number, &json!(1_000_000), Some(&min_only)).is_ok());
        assert!(validate(&FieldType::Number, &json!(-1), Some(&min_only)).is_err());

        let max_only = json!({ "max": 10 });
        assert!(validate(&FieldType::Number, &json!(-1_000_000), Some(&max_only)).is_ok());
        assert!(validate(&FieldType::Number, &json!(11), Some(&max_only)).is_err());
    }

    #[test]
    fn number_with_no_options_is_unbounded() {
        assert!(validate(&FieldType::Number, &json!(f64::MAX), None).is_ok());
        assert!(validate(&FieldType::Number, &json!(-1_000_000_000_i64), None).is_ok());
    }

    #[test]
    fn currency_accepts_number_rejects_string() {
        // A currency field is a plain NUMERIC amount in the system base
        // (USD) — validation is identical to `Number`; only the client's
        // rendering (amount + the viewer's preferred-currency symbol,
        // converted against a static rate table) differs.
        assert!(validate(&FieldType::Currency, &json!(19.99), None).is_ok());
        assert!(validate(&FieldType::Currency, &json!("19.99"), None).is_err());
    }

    #[test]
    fn currency_bounds_enforce_min_and_max() {
        let opts = json!({ "min": 0 });
        assert!(validate(&FieldType::Currency, &json!(0.002), Some(&opts)).is_ok());
        assert!(validate(&FieldType::Currency, &json!(-0.01), Some(&opts)).is_err());
    }

    #[test]
    fn validate_options_accepts_well_formed_currency_bounds() {
        assert!(validate_options(&FieldType::Currency, &json!({ "min": 0 })).is_ok());
        assert!(validate_options(&FieldType::Currency, &json!({})).is_ok());
    }

    #[test]
    fn validate_options_rejects_number_min_greater_than_max() {
        let err =
            validate_options(&FieldType::Number, &json!({ "min": 10, "max": 5 })).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn validate_options_accepts_well_formed_number_bounds() {
        assert!(validate_options(&FieldType::Number, &json!({ "min": 0, "max": 100 })).is_ok());
        assert!(validate_options(&FieldType::Number, &json!({})).is_ok());
    }

    #[test]
    fn bool_accepts_bool_rejects_string() {
        assert!(validate(&FieldType::Bool, &json!(true), None).is_ok());
        assert!(validate(&FieldType::Bool, &json!("true"), None).is_err());
    }

    #[test]
    fn date_accepts_rfc3339_and_plain_date_rejects_garbage() {
        assert!(validate(&FieldType::Time, &json!("08:30"), None).is_ok());
        assert!(validate(&FieldType::Time, &json!("23:59:59"), None).is_ok());
        assert!(validate(&FieldType::Time, &json!("24:00"), None).is_err());
        assert!(validate(&FieldType::Time, &json!("8.30"), None).is_err());
        // A2-T1: a day takes no time part; a moment takes either.
        assert!(validate(&FieldType::Date, &json!("2026-07-06T12:00:00Z"), None).is_err());
        assert!(validate(&FieldType::Date, &json!("2026-07-06"), None).is_ok());
        assert!(validate(&FieldType::DateTime, &json!("2026-07-06T12:00:00Z"), None).is_ok());
        assert!(
            validate(
                &FieldType::DateTime,
                &json!("2026-07-06T12:00:00+03:00"),
                None
            )
            .is_ok()
        );
        assert!(validate(&FieldType::DateTime, &json!("2026-07-06"), None).is_ok());
        assert!(validate(&FieldType::Date, &json!("not-a-date"), None).is_err());
        assert!(validate(&FieldType::Date, &json!(20260706), None).is_err());
    }

    #[test]
    fn lookup_accepts_uuid_string_rejects_non_uuid() {
        assert!(
            validate(
                &FieldType::Lookup,
                &json!("550e8400-e29b-41d4-a716-446655440000"),
                None
            )
            .is_ok()
        );
        assert!(validate(&FieldType::Lookup, &json!("not-a-uuid"), None).is_err());
        assert!(validate(&FieldType::Lookup, &json!(123), None).is_err());
    }

    #[test]
    fn file_accepts_string_key_rejects_object() {
        assert!(validate(&FieldType::File, &json!("s3://bucket/key.pdf"), None).is_ok());
        assert!(validate(&FieldType::File, &json!({"key": "x"}), None).is_err());
    }

    #[test]
    fn multi_file_accepts_string_array_rejects_scalar_and_non_string_items() {
        let opts = json!({"multi": true});
        assert!(validate(&FieldType::File, &json!(["a", "b"]), Some(&opts)).is_ok());
        assert!(validate(&FieldType::File, &json!([]), Some(&opts)).is_ok());
        // A single-file-shaped value is not a valid multi-file value — the
        // column is JSONB expecting an array, not a bare string.
        assert!(validate(&FieldType::File, &json!("a"), Some(&opts)).is_err());
        assert!(validate(&FieldType::File, &json!(["a", 1]), Some(&opts)).is_err());
    }

    #[test]
    fn single_file_options_multi_false_still_expects_a_bare_string() {
        let opts = json!({"multi": false});
        assert!(validate(&FieldType::File, &json!("a"), Some(&opts)).is_ok());
        assert!(validate(&FieldType::File, &json!(["a"]), Some(&opts)).is_err());
    }

    #[test]
    fn validate_options_accepts_well_formed_file_multi_flag() {
        assert!(validate_options(&FieldType::File, &json!({"multi": true})).is_ok());
        assert!(validate_options(&FieldType::File, &json!({"multi": false})).is_ok());
        assert!(validate_options(&FieldType::File, &json!({"multi": "yes"})).is_err());
    }

    #[test]
    fn choice_single_select_enforces_allowed_list() {
        let opts = json!({ "choices": ["red", "green", "blue"], "multi": false });
        assert!(validate(&FieldType::Choice, &json!("green"), Some(&opts)).is_ok());
        assert!(validate(&FieldType::Choice, &json!("purple"), Some(&opts)).is_err());
        // Array where a single string is expected must be rejected, not coerced.
        assert!(validate(&FieldType::Choice, &json!(["green"]), Some(&opts)).is_err());
    }

    #[test]
    fn choice_multi_select_enforces_allowed_list_per_item() {
        let opts = json!({ "choices": ["red", "green", "blue"], "multi": true });
        assert!(validate(&FieldType::Choice, &json!(["red", "blue"]), Some(&opts)).is_ok());
        assert!(validate(&FieldType::Choice, &json!(["red", "purple"]), Some(&opts)).is_err());
        // Bare string where an array is expected must be rejected, not coerced.
        assert!(validate(&FieldType::Choice, &json!("red"), Some(&opts)).is_err());
    }

    #[test]
    fn choice_with_no_options_or_empty_choices_is_a_no_op() {
        // No `options` at all — nothing to validate against, so anything passes.
        assert!(validate(&FieldType::Choice, &json!("anything"), None).is_ok());
        // `choices` present but empty — same no-op behavior (see `validate`'s
        // `if !opts.choices.is_empty()` guard).
        let opts = json!({ "choices": [], "multi": false });
        assert!(validate(&FieldType::Choice, &json!("anything"), Some(&opts)).is_ok());
    }

    #[test]
    fn text_mask_enforces_pattern_and_reports_description() {
        let opts = json!({ "pattern": "[0-9]{3}-[0-9]{4}", "mask_description": "phone" });
        assert!(validate(&FieldType::Text, &json!("555-1234"), Some(&opts)).is_ok());
        let err = validate(&FieldType::Text, &json!("not-a-phone"), Some(&opts)).unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("phone")));
    }

    #[test]
    fn text_mask_is_full_match_not_substring() {
        // An unanchored pattern would wrongly accept this via a partial match.
        let opts = json!({ "pattern": "[0-9]{3}" });
        assert!(validate(&FieldType::Text, &json!("123"), Some(&opts)).is_ok());
        assert!(validate(&FieldType::Text, &json!("abc123def"), Some(&opts)).is_err());
    }

    #[test]
    fn text_with_no_pattern_or_no_options_is_a_no_op() {
        assert!(validate(&FieldType::Text, &json!("anything"), None).is_ok());
        let opts = json!({ "pattern": null });
        assert!(validate(&FieldType::Text, &json!("anything"), Some(&opts)).is_ok());
    }

    /// PERF-1 (PLATFORM-REVIEW-2026-08-24 §4): `validate_text_mask` runs on
    /// every record write for every masked text field, so the mask regex must
    /// be compiled once per pattern, not once per call.
    ///
    /// The three assertions live in one test on purpose. `MASK_CACHE` is a
    /// process-wide static and `cargo test` runs this module's tests in
    /// parallel, so a separate bound test could `clear()` the map between the
    /// two `compiled_pattern` calls of a separate identity test and fail it
    /// spuriously. Sequencing them here — identity first, then the fill that
    /// may clear — removes that race entirely.
    #[test]
    fn pattern_validation_uses_base_rules() {
        // The same full match as a rule's `matches`: every alternative is
        // anchored, and an already-anchored pattern still works.
        let alt = compiled_pattern("ab|cd").expect("valid pattern");
        assert!(alt.is_match("ab") && alt.is_match("cd"));
        assert!(!alt.is_match("abx") && !alt.is_match("xcd"));
        let anchored = compiled_pattern(r"^[0-9]+$").expect("valid pattern");
        assert!(anchored.is_match("123") && !anchored.is_match("12a"));
        let opts = TextOptions {
            pattern: Some("[A-Z]{2}".to_owned()),
            ..TextOptions::default()
        };
        assert!(validate_text_mask("AB", &opts).is_ok());
        let err = validate_text_mask("ABC", &opts).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the required format"),
            "{err}"
        );
    }

    #[test]
    fn mask_regex_is_compiled_once_bounded_and_not_cached_when_invalid() {
        // Same pattern twice hands back the *same* compiled regex, not a copy.
        let first = compiled_pattern(r"[0-9]{3}-[0-9]{4}").expect("valid pattern");
        let second = compiled_pattern(r"[0-9]{3}-[0-9]{4}").expect("valid pattern");
        assert!(
            Arc::ptr_eq(&first, &second),
            "a repeated pattern must be served from MASK_CACHE, not recompiled"
        );

        // Caching must not change behavior: still anchored, still a full match.
        assert!(first.is_match("123-4567"));
        assert!(!first.is_match("x123-4567x"));

        // A different pattern is a different key, hence a different regex.
        let other = compiled_pattern(r"[0-9]{3}").expect("valid pattern");
        assert!(!Arc::ptr_eq(&first, &other));

        // An invalid pattern errors and is never inserted, so it cannot poison
        // the cache for the next caller.
        assert!(compiled_pattern("[unterminated").is_err());
        assert!(!read_mask_cache().contains_key("[unterminated"));

        // The map stays bounded: filling past the cap clears rather than grows.
        for i in 0..=MASK_CACHE_MAX {
            compiled_pattern(&format!("bound-probe-{i}")).expect("valid pattern");
        }
        assert!(read_mask_cache().len() <= MASK_CACHE_MAX);
    }

    #[test]
    fn validate_options_accepts_well_formed_choice_and_text() {
        assert!(
            validate_options(
                &FieldType::Choice,
                &json!({ "choices": ["a", "b"], "multi": true })
            )
            .is_ok()
        );
        assert!(
            validate_options(&FieldType::Text, &json!({ "pattern": "[0-9]{3}-[0-9]{4}" })).is_ok()
        );
    }

    #[test]
    fn defaults_are_checked_against_the_field_type() {
        assert!(
            validate_options(
                &FieldType::Number,
                &json!({"default": {"kind": "fixed", "value": 5}})
            )
            .is_ok()
        );
        assert!(
            validate_options(
                &FieldType::Number,
                &json!({"default": {"kind": "fixed", "value": "x"}})
            )
            .is_err()
        );
        assert!(validate_options(&FieldType::Date, &json!({"default": {"kind": "today"}})).is_ok());
        assert!(
            validate_options(
                &FieldType::Date,
                &json!({"default": {"kind": "today"}, "display_calendar": "hijri"})
            )
            .is_ok()
        );
        assert!(
            validate_options(&FieldType::Text, &json!({"default": {"kind": "today"}})).is_err()
        );
        assert!(
            validate_options(
                &FieldType::Lookup,
                &json!({"default": {"kind": "current_user"}})
            )
            .is_ok()
        );
        assert!(
            validate_options(&FieldType::Text, &json!({"default": {"kind": "fixed"}})).is_err()
        );
    }

    #[test]
    fn a_default_alone_is_valid_for_any_field_type() {
        let options = json!({"default": {"kind": "fixed", "value": true}});
        assert!(validate_options(&FieldType::Bool, &options).is_ok());
    }

    #[test]
    fn date_display_calendar_option_accepts_hijri() {
        for calendar in ["gregorian", "hijri", "both"] {
            assert!(
                validate_options(&FieldType::Date, &json!({ "display_calendar": calendar }))
                    .is_ok(),
                "{calendar}"
            );
        }
        assert!(validate_options(&FieldType::Date, &json!({})).is_ok());
    }

    #[test]
    fn date_display_calendar_rejects_unknown() {
        assert!(
            validate_options(&FieldType::Date, &json!({ "display_calendar": "julian" })).is_err()
        );
        assert!(validate_options(&FieldType::Date, &json!({ "pattern": "x" })).is_err());
    }

    #[test]
    fn validate_options_rejects_invalid_regex_and_wrong_field_types() {
        let err =
            validate_options(&FieldType::Text, &json!({ "pattern": "[unterminated" })).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));

        // Bool doesn't accept an options config at all today.
        assert!(validate_options(&FieldType::Bool, &json!({ "pattern": "x" })).is_err());
    }

    // C-29 (M01 §7) — `text_type`: an additive `TextOptions` field, not a
    // new column (migration 0029's `options` JSONB already round-trips this
    // for every text field), so field-input.component.ts can be told the
    // input mode instead of guessing it from the field's name.
    #[test]
    fn validate_options_accepts_well_formed_text_type() {
        for text_type in VALID_TEXT_TYPES {
            assert!(
                validate_options(&FieldType::Text, &json!({ "text_type": text_type })).is_ok(),
                "{text_type} should be accepted"
            );
        }
        // Absent altogether stays valid — the client's name heuristic keeps
        // covering every field created before this option existed.
        assert!(validate_options(&FieldType::Text, &json!({})).is_ok());
    }

    #[test]
    fn validate_options_rejects_unknown_text_type() {
        let err =
            validate_options(&FieldType::Text, &json!({ "text_type": "password" })).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn validate_options_accepts_well_formed_choice_styles() {
        let opts = json!({
            "choices": ["Inbound", "Outbound"],
            "multi": false,
            "choice_styles": {
                "Inbound": { "color": "#ef4444", "icon": "las la-arrow-down" },
                "Outbound": { "color": "#22c55e", "icon": "las la-arrow-up" },
            }
        });
        assert!(validate_options(&FieldType::Choice, &opts).is_ok());
    }

    #[test]
    fn validate_options_rejects_choice_style_for_unknown_value() {
        let opts = json!({
            "choices": ["Inbound", "Outbound"],
            "multi": false,
            "choice_styles": { "Sideways": { "color": "#ef4444" } }
        });
        let err = validate_options(&FieldType::Choice, &opts).unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("Sideways")));
    }

    #[test]
    fn validate_options_rejects_malformed_choice_style_color_and_icon() {
        let bad_color = json!({
            "choices": ["Sent"],
            "multi": false,
            "choice_styles": { "Sent": { "color": "green" } }
        });
        assert!(validate_options(&FieldType::Choice, &bad_color).is_err());

        let bad_icon = json!({
            "choices": ["Sent"],
            "multi": false,
            "choice_styles": { "Sent": { "icon": "<script>" } }
        });
        assert!(validate_options(&FieldType::Choice, &bad_icon).is_err());
    }

    #[test]
    fn choice_options_round_trips_without_choice_styles() {
        // Existing rows in `attribute_info.options` have no
        // `choice_styles` key at all — must still deserialize cleanly.
        let opts: ChoiceOptions =
            serde_json::from_value(json!({ "choices": ["a", "b"], "multi": false })).unwrap();
        assert!(opts.choice_styles.is_empty());
    }
}
