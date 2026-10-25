use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A field's type. Y2-T1: `Date` is a calendar day (`DATE`) and `DateTime`
/// a moment (`TIMESTAMPTZ`); attributes made before the split hold a
/// `TIMESTAMPTZ` column and are relabelled `date_time` (Y2-T2).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Text,
    Number,
    Currency,
    Date,
    Bool,
    Choice,
    Lookup,
    File,
    Icon,
    Color,
    Formula,
    RichText,
    Image,
    DateTime,
}

/// Every variant, in declaration order. The one list callers iterate — the
/// bundle vocabulary ([`FieldType::NAMES`]), the admin/reconcile validator,
/// and the round-trip tests below all derive from it.
pub const ALL_FIELD_TYPES: [FieldType; 14] = [
    FieldType::Text,
    FieldType::Number,
    FieldType::Currency,
    FieldType::Date,
    FieldType::Bool,
    FieldType::Choice,
    FieldType::Lookup,
    FieldType::File,
    FieldType::Icon,
    FieldType::Color,
    FieldType::Formula,
    FieldType::RichText,
    FieldType::Image,
    FieldType::DateTime,
];

/// The storage types a `formula` field (B-R6, D-604) may declare as its
/// `options.result_type` — the scalar types `attome-rules` can produce and a
/// native column can hold.
pub const FORMULA_RESULT_TYPES: &[&str] =
    &["text", "number", "currency", "date", "date_time", "bool"];

impl FieldType {
    /// The wire names of every variant ([`ALL_FIELD_TYPES`]'s `as_str`), the
    /// single field-type vocabulary the admin API, reconcile and the bundle
    /// planner accept. A test below keeps the two in lockstep.
    pub const NAMES: &'static [&'static str] = &[
        "text",
        "number",
        "currency",
        "date",
        "bool",
        "choice",
        "lookup",
        "file",
        "icon",
        "color",
        "formula",
        "rich_text",
        "image",
        "date_time",
    ];

    /// Whether `name` is one of [`Self::NAMES`] — the one field-type
    /// validator (was two hand-copied `valid_field_type` lists, in
    /// `attome-server/src/admin/attribute.rs` and `attome-metadata`'s reconcile).
    pub fn is_valid_name(name: &str) -> bool {
        Self::NAMES.contains(&name)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Number => "number",
            Self::Date => "date",
            Self::Bool => "bool",
            Self::Choice => "choice",
            Self::Lookup => "lookup",
            Self::File => "file",
            Self::Icon => "icon",
            Self::Color => "color",
            Self::Currency => "currency",
            Self::Formula => "formula",
            Self::RichText => "rich_text",
            Self::Image => "image",
            Self::DateTime => "date_time",
        }
    }

    /// Y2-T1: whether the field holds a day or a moment (`date` or
    /// `date_time`): what a date bucket, range binding or date feature needs.
    pub fn is_temporal(&self) -> bool {
        matches!(self, Self::Date | Self::DateTime)
    }

    /// The reverse of [`Self::to_int`] — `attribute_info."type"`
    /// (`INTEGER`) -> the variant it names. C-16 (M01 §7): this is the single
    /// place that owns the "legacy alias" ranges every hand-copied
    /// `int_to_type`/`field_type_of` used to repeat — `1|4|9|10` are
    /// reserved numeric subtypes (integer/percent/duration/…) that only `1`
    /// is actually written today; `2` is no longer one of them — it is now
    /// `Currency`'s own canonical code (a plain NUMERIC amount; the platform
    /// carries no exchange-rate/conversion state server-side — display
    /// conversion to a viewer's preferred currency happens entirely in
    /// Angular against a static rate table, USD is always the 1:1 system
    /// base). `7|8` and `12|13` are the "canonical/reserved-alias" pair for
    /// `choice`/`file` (multi-ness itself is carried on `options.multi`, see
    /// [`Self::is_multi_valued`], not by which of the pair is stored —
    /// D-078/D-362). Any value outside all of these (including the canonical
    /// `3`) is `Text`, matching every prior copy's `_ => text` default
    /// exactly — so this never panics or rejects a live row, only a
    /// genuinely-corrupt or not-yet-recognised code falls through to the same
    /// safe default the callers already relied on.
    pub fn from_int(i: i32) -> Option<Self> {
        Some(match i {
            1 | 4 | 9 | 10 => Self::Number,
            2 => Self::Currency,
            5 => Self::Date,
            6 => Self::Bool,
            7 | 8 => Self::Choice,
            11 => Self::Lookup,
            12 | 13 => Self::File,
            14 => Self::Icon,
            15 => Self::Color,
            16 => Self::Formula,
            17 => Self::RichText,
            18 => Self::Image,
            19 => Self::DateTime,
            _ => Self::Text,
        })
    }

    /// The canonical `attribute_info."type"` value written for this
    /// variant — the single value the write path (`ensure_attribute`) ever
    /// emits per variant (the "legacy alias" ints [`Self::from_int`] also
    /// accepts on read are not produced here).
    pub fn to_int(&self) -> i32 {
        match self {
            Self::Text => 3,
            Self::Number => 1,
            Self::Currency => 2,
            Self::Date => 5,
            Self::Bool => 6,
            Self::Choice => 7,
            Self::Lookup => 11,
            Self::File => 12,
            Self::Icon => 14,
            Self::Color => 15,
            Self::Formula => 16,
            Self::RichText => 17,
            Self::Image => 18,
            Self::DateTime => 19,
        }
    }

    /// The type a field *behaves as* for everything below its metadata —
    /// its physical column, bind casts, filter casts, rule evaluation and
    /// storage-level checks such as "is this a file key column". Three
    /// variants are metadata over another type's storage:
    ///
    /// - `Formula` (B-R6, D-604) is stored in a native column of its
    ///   declared `options.result_type` (`text` when absent or unknown — the
    ///   same safe default `from_int` uses);
    /// - `RichText` (B-R7, D-605) is a `TEXT` column holding sanitized HTML;
    /// - `Image` is a `File` column (D-144 end to end), restricted to image
    ///   content types at upload.
    ///
    /// Every other variant is its own storage type.
    pub fn storage(&self, options: Option<&Value>) -> FieldType {
        match self {
            Self::Formula => options
                .and_then(|o| o.get("result_type"))
                .and_then(Value::as_str)
                .filter(|t| FORMULA_RESULT_TYPES.contains(t))
                .and_then(|t| Self::try_from(t).ok())
                .unwrap_or(Self::Text),
            Self::RichText => Self::Text,
            Self::Image => Self::File,
            other => other.clone(),
        }
    }

    /// Like [`Self::storage`], but keeps `RichText`/`Image` as themselves —
    /// only a `Formula` resolves to its result type. This is the type a
    /// *reader* of the value cares about (a list column's `data_type`, a
    /// filter's operator set): a formula column reads exactly like a column
    /// of its result type, while a rich-text or image column still needs its
    /// own presentation.
    pub fn presentation(&self, options: Option<&Value>) -> FieldType {
        match self {
            Self::Formula => self.storage(options),
            other => other.clone(),
        }
    }

    /// The PostgreSQL column type provisioned for this field type — D-078
    /// (`choice`) / D-362 (`file`): `multi` picks the array/JSONB shape;
    /// `options.multi` (see [`Self::is_multi_valued`]) is what decides it at
    /// the caller, never a second field-type code.
    pub fn pg_type(&self, multi: bool) -> &'static str {
        match self {
            Self::Number => "NUMERIC",
            Self::Currency => "NUMERIC",
            Self::Date => "DATE",
            Self::DateTime => "TIMESTAMPTZ",
            Self::Bool => "BOOLEAN",
            Self::Choice if multi => "TEXT[]",
            Self::Choice => "TEXT",
            Self::Lookup => "UUID",
            Self::File if multi => "JSONB",
            Self::File => "TEXT",
            Self::Text => "TEXT",
            Self::Icon => "TEXT",
            Self::Color => "TEXT",
            // Metadata over another type's storage — see [`Self::storage`].
            // A caller provisioning a column resolves `storage(options)`
            // first; these arms answer for the options-less default.
            Self::Formula => "TEXT",
            Self::RichText => "TEXT",
            Self::Image if multi => "JSONB",
            Self::Image => "TEXT",
        }
    }

    /// The bind-placeholder cast suffix (e.g. `"::numeric"`) a dynamic-SQL
    /// caller appends after `$N` so a text-encoded bind lands as this
    /// field's [`Self::pg_type`]. Empty when the column is already `TEXT`
    /// (single `choice`/`file`, and `Text` itself) — a plain text bind needs
    /// no cast to reach a `TEXT` column.
    pub fn sql_cast(&self, multi: bool) -> &'static str {
        match self {
            Self::Number => "::numeric",
            Self::Currency => "::numeric",
            Self::Date => "::date",
            Self::DateTime => "::timestamptz",
            Self::Bool => "::boolean",
            Self::Lookup => "::uuid",
            Self::Choice if multi => "::text[]",
            Self::File | Self::Image if multi => "::jsonb",
            _ => "",
        }
    }

    /// Reads `options.multi` (`attome_field::ChoiceOptions.multi` /
    /// `FileOptions.multi`) — the one flag both options structs carry.
    /// Always `false` for a variant that has no multi-valued storage shape
    /// (`Text`, `Number`, `Date`, `Bool`, `Lookup`), regardless of what a
    /// stray `options.multi` might say, so a caller never needs its own
    /// `field_type == "choice" || field_type == "file"` guard first.
    pub fn is_multi_valued(&self, options: &Value) -> bool {
        matches!(self, Self::Choice | Self::File | Self::Image)
            && options
                .get("multi")
                .and_then(Value::as_bool)
                .unwrap_or(false)
    }
}

impl std::fmt::Display for FieldType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for FieldType {
    type Error = String;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "text" => Ok(Self::Text),
            "number" => Ok(Self::Number),
            "currency" => Ok(Self::Currency),
            "date" => Ok(Self::Date),
            "bool" => Ok(Self::Bool),
            "choice" => Ok(Self::Choice),
            "lookup" => Ok(Self::Lookup),
            "file" => Ok(Self::File),
            "icon" => Ok(Self::Icon),
            "color" => Ok(Self::Color),
            "formula" => Ok(Self::Formula),
            "rich_text" => Ok(Self::RichText),
            "image" => Ok(Self::Image),
            "date_time" => Ok(Self::DateTime),
            other => Err(format!("unknown field type: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [FieldType; 14] = ALL_FIELD_TYPES;

    #[test]
    fn names_match_every_variant_in_order() {
        let from_variants: Vec<&str> = ALL.iter().map(FieldType::as_str).collect();
        assert_eq!(from_variants, FieldType::NAMES);
        for name in FieldType::NAMES {
            assert_eq!(FieldType::try_from(*name).map(|t| t.as_str()), Ok(*name));
            assert!(FieldType::is_valid_name(name));
        }
        assert!(!FieldType::is_valid_name("html"));
    }

    #[test]
    fn new_types_use_codes_16_to_18() {
        assert_eq!(FieldType::Formula.to_int(), 16);
        assert_eq!(FieldType::RichText.to_int(), 17);
        assert_eq!(FieldType::Image.to_int(), 18);
        assert_eq!(FieldType::DateTime.to_int(), 19);
    }

    #[test]
    fn date_is_date_and_date_time_is_timestamptz() {
        assert_eq!(FieldType::Date.pg_type(false), "DATE");
        assert_eq!(FieldType::Date.sql_cast(false), "::date");
        assert_eq!(FieldType::DateTime.pg_type(false), "TIMESTAMPTZ");
        assert_eq!(FieldType::DateTime.sql_cast(false), "::timestamptz");
        assert_eq!(FieldType::try_from("date_time"), Ok(FieldType::DateTime));
        assert!(FieldType::Date.is_temporal() && FieldType::DateTime.is_temporal());
        assert!(!FieldType::Text.is_temporal());
    }

    #[test]
    fn storage_resolves_formula_rich_text_and_image() {
        let num = serde_json::json!({"expression": "a + 1", "result_type": "number"});
        let date = serde_json::json!({"expression": "now()", "result_type": "date"});
        let bogus = serde_json::json!({"expression": "x", "result_type": "lookup"});
        assert_eq!(FieldType::Formula.storage(Some(&num)), FieldType::Number);
        assert_eq!(FieldType::Formula.storage(Some(&date)), FieldType::Date);
        assert_eq!(FieldType::Formula.storage(Some(&bogus)), FieldType::Text);
        assert_eq!(FieldType::Formula.storage(None), FieldType::Text);
        assert_eq!(FieldType::RichText.storage(None), FieldType::Text);
        assert_eq!(FieldType::Image.storage(None), FieldType::File);
        assert_eq!(FieldType::Choice.storage(None), FieldType::Choice);
        // presentation keeps rich_text/image, resolves formula
        assert_eq!(
            FieldType::Formula.presentation(Some(&num)),
            FieldType::Number
        );
        assert_eq!(FieldType::RichText.presentation(None), FieldType::RichText);
        assert_eq!(FieldType::Image.presentation(None), FieldType::Image);
        // the resolved storage's pg type is a real native column type
        assert_eq!(
            FieldType::Formula.storage(Some(&num)).pg_type(false),
            "NUMERIC"
        );
        assert_eq!(
            FieldType::Formula.storage(Some(&date)).pg_type(false),
            "DATE"
        );
        let moment = serde_json::json!({"expression": "now()", "result_type": "date_time"});
        assert_eq!(
            FieldType::Formula.storage(Some(&moment)).pg_type(false),
            "TIMESTAMPTZ"
        );
    }

    #[test]
    fn image_multi_is_jsonb_like_file() {
        let multi = serde_json::json!({"multi": true});
        assert!(FieldType::Image.is_multi_valued(&multi));
        assert_eq!(FieldType::Image.pg_type(true), "JSONB");
        assert_eq!(FieldType::Image.sql_cast(true), "::jsonb");
    }

    /// C-16 proof: `from_int(to_int(t)) == t` for every variant.
    #[test]
    fn from_int_to_int_round_trips_for_every_variant() {
        for t in ALL {
            assert_eq!(FieldType::from_int(t.to_int()), Some(t.clone()), "{t:?}");
        }
    }

    /// C-16 proof: `sql_cast` agrees with `pg_type` for both `multi` values —
    /// a non-empty cast suffix always names the same Postgres type
    /// `pg_type` returns, and an empty cast is only ever paired with `TEXT`
    /// (the one column type a plain, uncast text bind can always reach).
    #[test]
    fn sql_cast_agrees_with_pg_type_for_both_multi_values() {
        for t in ALL {
            for multi in [false, true] {
                let want_type = t.pg_type(multi);
                let cast = t.sql_cast(multi);
                if cast.is_empty() {
                    assert_eq!(
                        want_type, "TEXT",
                        "{t:?} multi={multi}: empty cast must pair with TEXT, got {want_type}"
                    );
                } else {
                    let cast_type = cast.trim_start_matches("::").to_uppercase();
                    assert_eq!(
                        cast_type, want_type,
                        "{t:?} multi={multi}: cast {cast} implies {cast_type}, pg_type says {want_type}"
                    );
                }
            }
        }
    }

    #[test]
    fn from_int_accepts_the_legacy_numeric_aliases() {
        for i in [1, 4, 9, 10] {
            assert_eq!(FieldType::from_int(i), Some(FieldType::Number));
        }
        assert_eq!(FieldType::from_int(2), Some(FieldType::Currency));
        assert_eq!(FieldType::from_int(7), Some(FieldType::Choice));
        assert_eq!(FieldType::from_int(8), Some(FieldType::Choice));
        assert_eq!(FieldType::from_int(12), Some(FieldType::File));
        assert_eq!(FieldType::from_int(13), Some(FieldType::File));
    }

    #[test]
    fn from_int_defaults_unknown_codes_to_text() {
        assert_eq!(FieldType::from_int(3), Some(FieldType::Text));
        assert_eq!(FieldType::from_int(999), Some(FieldType::Text));
        assert_eq!(FieldType::from_int(0), Some(FieldType::Text));
    }

    #[test]
    fn is_multi_valued_reads_options_multi_and_gates_by_type() {
        let multi = serde_json::json!({"multi": true});
        let single = serde_json::json!({"multi": false});
        let empty = serde_json::Value::Null;

        assert!(FieldType::Choice.is_multi_valued(&multi));
        assert!(!FieldType::Choice.is_multi_valued(&single));
        assert!(!FieldType::Choice.is_multi_valued(&empty));
        assert!(FieldType::File.is_multi_valued(&multi));
        assert!(!FieldType::File.is_multi_valued(&empty));

        // Non-multi-capable variants never report multi, even if handed the
        // same JSON shape a choice/file field would.
        assert!(!FieldType::Text.is_multi_valued(&multi));
        assert!(!FieldType::Number.is_multi_valued(&multi));
        assert!(!FieldType::Lookup.is_multi_valued(&multi));
    }
}
