//! Z11-T12: the language's built-in functions as data, for an editor's
//! completion and an agent's prompt. [`catalog`] lists every built-in a
//! language version accepts, with its parameters, result type, an English and
//! an Arabic description and an example; [`GRAMMAR_NOTES`] describes the rest
//! of the language. The `catalog_covers_every_builtin` test compiles each
//! example, so an entry cannot name a function the compiler does not know.

use crate::LanguageVersion;
use crate::version::function_version;

/// One built-in function. Types are the language's type names (`number`,
/// `text`, `bool`, `date`, `list<number>`, `any`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionSpec {
    pub name: &'static str,
    /// `(name, type)` in call order; a name ending in `...` repeats.
    pub params: &'static [(&'static str, &'static str)],
    pub returns: &'static str,
    pub description_en: &'static str,
    pub description_ar: &'static str,
    pub example: &'static str,
    /// The version that added it.
    pub since: LanguageVersion,
}

const fn f(
    name: &'static str,
    params: &'static [(&'static str, &'static str)],
    returns: &'static str,
    description_en: &'static str,
    description_ar: &'static str,
    example: &'static str,
) -> FunctionSpec {
    FunctionSpec {
        name,
        params,
        returns,
        description_en,
        description_ar,
        example,
        // Filled from the version table by `catalog`.
        since: LanguageVersion::V1,
    }
}

const FUNCTIONS: &[FunctionSpec] = &[
    f(
        "if",
        &[("condition", "bool"), ("then", "any"), ("else", "any")],
        "any",
        "The second argument when the condition is true, otherwise the third.",
        "يعيد الوسيط الثاني إذا تحقق الشرط، وإلا يعيد الوسيط الثالث.",
        r#"if(amount > 1000, "large", "small")"#,
    ),
    f(
        "coalesce",
        &[("value...", "any")],
        "any",
        "The first argument that is not null.",
        "أول وسيط ليست قيمته فارغة.",
        "coalesce(discount, 0)",
    ),
    f(
        "is_null",
        &[("value", "any")],
        "bool",
        "Whether the value is null (empty).",
        "هل القيمة فارغة.",
        "is_null(closed_on)",
    ),
    f(
        "len",
        &[("value", "text or list")],
        "number",
        "The number of characters in a text, or of items in a list.",
        "عدد أحرف النص أو عدد عناصر القائمة.",
        "len(name)",
    ),
    f(
        "lower",
        &[("text", "text")],
        "text",
        "The text in lower case.",
        "النص بأحرف صغيرة.",
        "lower(name)",
    ),
    f(
        "upper",
        &[("text", "text")],
        "text",
        "The text in upper case.",
        "النص بأحرف كبيرة.",
        "upper(name)",
    ),
    f(
        "trim",
        &[("text", "text")],
        "text",
        "The text without leading and trailing white space.",
        "النص بعد حذف المسافات من بدايته ونهايته.",
        "trim(name)",
    ),
    f(
        "contains",
        &[("in", "text or list"), ("value", "any")],
        "bool",
        "Whether a text contains another text, or a list contains a value.",
        "هل يحتوي النص على نص آخر، أو تحتوي القائمة على قيمة.",
        r#"contains(name, "Ltd")"#,
    ),
    f(
        "startswith",
        &[("text", "text"), ("prefix", "text")],
        "bool",
        "Whether the text starts with the prefix.",
        "هل يبدأ النص بالبادئة.",
        r#"startswith(name, "Al")"#,
    ),
    f(
        "endswith",
        &[("text", "text"), ("suffix", "text")],
        "bool",
        "Whether the text ends with the suffix.",
        "هل ينتهي النص باللاحقة.",
        r#"endswith(email, ".sa")"#,
    ),
    f(
        "date_add",
        &[("date", "date"), ("amount", "number"), ("unit", "text")],
        "date",
        "The date moved by an amount of minutes, hours, days, months or years.",
        "التاريخ بعد إضافة عدد من الدقائق أو الساعات أو الأيام أو الأشهر أو السنوات.",
        r#"date_add(closed_on, 30, "days")"#,
    ),
    f(
        "date_diff",
        &[("from", "date"), ("to", "date"), ("unit", "text")],
        "number",
        "The first date minus the second, in seconds, minutes, hours, days, months or years.",
        "الفرق بين التاريخين بالثواني أو الدقائق أو الساعات أو الأيام أو الأشهر أو السنوات.",
        r#"date_diff(today(), closed_on, "days")"#,
    ),
    f(
        "today",
        &[],
        "date",
        "The start of today in the deployment's time zone.",
        "بداية اليوم الحالي بحسب المنطقة الزمنية للنظام.",
        "today()",
    ),
    f(
        "now",
        &[],
        "date",
        "The current date and time.",
        "التاريخ والوقت الحاليان.",
        "now()",
    ),
    f(
        "round",
        &[("number", "number"), ("digits", "number")],
        "number",
        "The number rounded to a number of decimal places (0 when left out).",
        "العدد مقرّبًا إلى عدد من المنازل العشرية (صفر إذا لم يُحدَّد).",
        "round(amount * 0.15, 2)",
    ),
    f(
        "min",
        &[("number...", "number or list<number>")],
        "number",
        "The smallest of the numbers, or of a list of numbers.",
        "أصغر الأعداد، أو أصغر عدد في القائمة.",
        "min(amount, 5000)",
    ),
    f(
        "max",
        &[("number...", "number or list<number>")],
        "number",
        "The largest of the numbers, or of a list of numbers.",
        "أكبر الأعداد، أو أكبر عدد في القائمة.",
        "max(amount, 0)",
    ),
    f(
        "in",
        &[("value", "any"), ("candidate...", "any or list")],
        "bool",
        "Whether the value equals one of the candidates.",
        "هل تساوي القيمة إحدى القيم المرشحة.",
        r#"in(status, "open", "pending")"#,
    ),
    f(
        "flag",
        &[("name", "text")],
        "bool",
        "Whether the named customer flag is on.",
        "هل العلامة المسماة مفعّلة لهذا العميل.",
        r#"flag("new_pricing")"#,
    ),
    f(
        "prev",
        &[("field", "field")],
        "any",
        "The field's value before this write.",
        "قيمة الحقل قبل هذا التعديل.",
        "prev(amount) < amount",
    ),
    f(
        "changed",
        &[("field", "field")],
        "bool",
        "Whether this write changes the field.",
        "هل يغيّر هذا التعديل قيمة الحقل.",
        "changed(status)",
    ),
    f(
        "normalize_ar",
        &[("text", "text")],
        "text",
        "Arabic text with diacritics and tatweel removed and alef, yaa and taa marbuta forms unified, for comparing names.",
        "النص العربي بعد حذف التشكيل والتطويل وتوحيد أشكال الألف والياء والتاء المربوطة، لمقارنة الأسماء.",
        r#"normalize_ar(name) == normalize_ar("أحمد")"#,
    ),
    f(
        "concat",
        &[("text...", "text")],
        "text",
        "The texts joined together.",
        "النصوص موصولة ببعضها.",
        r#"concat(name, " - ", status)"#,
    ),
    f(
        "substr",
        &[("text", "text"), ("start", "number"), ("length", "number")],
        "text",
        "Part of the text: length characters from start (the first character is 0).",
        "جزء من النص: عدد من الأحرف يبدأ من موضع معيّن (أول حرف موضعه صفر).",
        "substr(name, 0, 3)",
    ),
    f(
        "replace",
        &[("text", "text"), ("find", "text"), ("with", "text")],
        "text",
        "The text with every occurrence of find replaced.",
        "النص بعد استبدال كل مواضع النص المطلوب.",
        r#"replace(phone, " ", "")"#,
    ),
    f(
        "abs",
        &[("number", "number")],
        "number",
        "The number without its sign.",
        "القيمة المطلقة للعدد.",
        "abs(amount)",
    ),
    f(
        "floor",
        &[("number", "number")],
        "number",
        "The number rounded down to a whole number.",
        "العدد مقرّبًا إلى الأسفل لأقرب عدد صحيح.",
        "floor(amount)",
    ),
    f(
        "ceil",
        &[("number", "number")],
        "number",
        "The number rounded up to a whole number.",
        "العدد مقرّبًا إلى الأعلى لأقرب عدد صحيح.",
        "ceil(amount)",
    ),
    f(
        "power",
        &[("base", "number"), ("exponent", "number")],
        "number",
        "The base raised to the exponent.",
        "الأساس مرفوعًا إلى الأس.",
        "power(1.05, 3)",
    ),
    f(
        "clamp",
        &[("number", "number"), ("low", "number"), ("high", "number")],
        "number",
        "The number kept between low and high.",
        "العدد محصورًا بين الحد الأدنى والحد الأعلى.",
        "clamp(amount, 0, 100)",
    ),
    f(
        "round_currency",
        &[("amount", "number"), ("currency", "text")],
        "number",
        "The amount rounded to the currency's minor units (SAR 2, KWD 3).",
        "المبلغ مقرّبًا إلى الوحدات الصغرى للعملة (الريال منزلتان والدينار الكويتي ثلاث).",
        r#"round_currency(amount * 1.15, "SAR")"#,
    ),
    f(
        "convert",
        &[("amount", "number"), ("from", "text"), ("to", "text")],
        "number",
        "The amount converted between currencies at the deployment's rates.",
        "المبلغ محوّلًا بين العملات بأسعار الصرف المعتمدة في النظام.",
        r#"convert(amount, "USD", "SAR")"#,
    ),
    f(
        "minor_units",
        &[("currency", "text")],
        "number",
        "How many decimal places the currency has.",
        "عدد المنازل العشرية للعملة.",
        r#"minor_units("KWD")"#,
    ),
    f(
        "matches",
        &[("text", "text"), ("pattern", "text literal")],
        "bool",
        "Whether the whole text matches the regular expression, written as a literal.",
        "هل يطابق النص كاملًا التعبير النمطي المكتوب حرفيًا.",
        r#"matches(phone, "05[0-9]{8}")"#,
    ),
    f(
        "hijri_year",
        &[("date", "date")],
        "number",
        "The Hijri (Umm al-Qura) year of the date.",
        "السنة الهجرية (أم القرى) للتاريخ.",
        "hijri_year(today())",
    ),
    f(
        "hijri_month",
        &[("date", "date")],
        "number",
        "The Hijri (Umm al-Qura) month of the date, 1 to 12.",
        "الشهر الهجري (أم القرى) للتاريخ، من 1 إلى 12.",
        "hijri_month(today()) == 9",
    ),
    f(
        "hijri_day",
        &[("date", "date")],
        "number",
        "The day of the Hijri (Umm al-Qura) month.",
        "اليوم من الشهر الهجري (أم القرى).",
        "hijri_day(today())",
    ),
    f(
        "hijri_date",
        &[("year", "number"), ("month", "number"), ("day", "number")],
        "date",
        "The date of a Hijri (Umm al-Qura) year, month and day.",
        "التاريخ الموافق لسنة وشهر ويوم هجري (أم القرى).",
        "hijri_date(1448, 9, 1)",
    ),
    f(
        "add_workdays",
        &[("date", "date"), ("days", "number")],
        "date",
        "The date moved by working days of the deployment's calendar.",
        "التاريخ بعد إضافة أيام عمل بحسب تقويم العمل في النظام.",
        "add_workdays(today(), 5)",
    ),
    f(
        "workdays_between",
        &[("from", "date"), ("to", "date")],
        "number",
        "The working days between two dates on the deployment's calendar.",
        "عدد أيام العمل بين تاريخين بحسب تقويم العمل في النظام.",
        "workdays_between(closed_on, today())",
    ),
    f(
        "is_working",
        &[("date", "date")],
        "bool",
        "Whether the moment is within working hours of the deployment's calendar.",
        "هل اللحظة ضمن ساعات العمل بحسب تقويم العمل في النظام.",
        "is_working(now())",
    ),
    f(
        "to_zone",
        &[("date", "date"), ("zone", "text")],
        "date",
        "The same moment, read in a time zone such as Asia/Riyadh.",
        "اللحظة نفسها مقروءة في منطقة زمنية مثل Asia/Riyadh.",
        r#"to_zone(now(), "Asia/Riyadh")"#,
    ),
    f(
        "sum",
        &[("list", "list<number>")],
        "number",
        "The total of a list of numbers.",
        "مجموع قائمة من الأعداد.",
        "sum(map(lines, l => l.amount))",
    ),
    f(
        "avg",
        &[("list", "list<number>")],
        "number",
        "The average of a list of numbers.",
        "متوسط قائمة من الأعداد.",
        "avg(map(lines, l => l.amount))",
    ),
    f(
        "count",
        &[("list", "list")],
        "number",
        "The number of items in a list.",
        "عدد عناصر القائمة.",
        "count(lines)",
    ),
    f(
        "first",
        &[("list", "list")],
        "any",
        "The first item of a list, or null when it is empty.",
        "أول عنصر في القائمة، أو قيمة فارغة إذا كانت القائمة فارغة.",
        "first(map(lines, l => l.amount))",
    ),
    f(
        "any",
        &[("list", "list"), ("condition", "x => bool")],
        "bool",
        "Whether the condition holds for at least one item.",
        "هل يتحقق الشرط لعنصر واحد على الأقل.",
        "any(lines, l => l.amount > 1000)",
    ),
    f(
        "all",
        &[("list", "list"), ("condition", "x => bool")],
        "bool",
        "Whether the condition holds for every item.",
        "هل يتحقق الشرط لكل العناصر.",
        "all(lines, l => l.amount > 0)",
    ),
    f(
        "filter",
        &[("list", "list"), ("condition", "x => bool")],
        "list",
        "The items for which the condition holds.",
        "العناصر التي يتحقق لها الشرط.",
        "count(filter(lines, l => l.amount > 1000))",
    ),
    f(
        "map",
        &[("list", "list"), ("value", "x => any")],
        "list",
        "Each item turned into a value.",
        "قائمة بقيمة محسوبة لكل عنصر.",
        "map(lines, l => l.amount * 2)",
    ),
];

/// The rest of the language, for an editor's help and an agent's prompt.
pub const GRAMMAR_NOTES: &[&str] = &[
    "Literals: numbers (12, 3.5), text in double quotes (\"open\"), true, false, null, and lists ([1, 2, 3]).",
    "A field of the record is its logical name (amount); a field of a looked-up record is lookup.field (account.name).",
    "Comparisons: == != < <= > >=. Equality treats null as a value: null == null is true.",
    "Arithmetic: + - * / %. + also joins two texts.",
    "Logic: and, or, not. The untaken side of and, or and if is not evaluated.",
    "Lambdas: x => expression, only as the second argument of any, all, filter and map; x.field reads a field of a related item.",
    "Environment values: env.<name> reads a deployment environment variable.",
    "A null operand to an operator other than == and != is an error; guard it with is_null or coalesce.",
];

/// Every built-in `version` accepts, in catalog order.
pub fn catalog(version: LanguageVersion) -> Vec<FunctionSpec> {
    FUNCTIONS
        .iter()
        .map(|spec| FunctionSpec {
            since: function_version(spec.name),
            ..*spec
        })
        .filter(|spec| spec.since <= version)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Budgets, RulesError, Schema, Type, compile_versioned};

    fn schema() -> Schema {
        Schema::new()
            .with_field("amount", Type::Number)
            .with_field("discount", Type::Number)
            .with_field("name", Type::Text)
            .with_field("email", Type::Text)
            .with_field("phone", Type::Text)
            .with_field("status", Type::Text)
            .with_field("closed_on", Type::Date)
            .with_related_list("lines", vec![("amount".to_owned(), Type::Number)])
    }

    #[test]
    fn catalog_covers_every_builtin() {
        let all = catalog(LanguageVersion::V2);
        assert_eq!(all.len(), FUNCTIONS.len());
        for spec in &all {
            compile_versioned(
                spec.example,
                &schema(),
                LanguageVersion::V2,
                Budgets::default(),
            )
            .unwrap_or_else(|e| panic!("{}: {} does not compile: {e}", spec.name, spec.example));
            assert!(spec.example.contains(spec.name), "{}", spec.name);
            assert!(!spec.description_ar.is_empty(), "{}", spec.name);
        }
        // A name the catalog does not list is not a built-in.
        assert!(matches!(
            compile_versioned("nope()", &schema(), LanguageVersion::V2, Budgets::default()),
            Err(RulesError::UnknownFunction(_))
        ));
    }

    #[test]
    fn v1_catalog_leaves_out_v2_functions() {
        let v1 = catalog(LanguageVersion::V1);
        assert!(v1.iter().any(|s| s.name == "date_add"));
        assert!(!v1.iter().any(|s| s.name == "normalize_ar"));
        assert!(v1.iter().all(|s| s.since == LanguageVersion::V1));
        let v2 = catalog(LanguageVersion::V2);
        let normalize = v2.iter().find(|s| s.name == "normalize_ar").unwrap();
        assert_eq!(normalize.since, LanguageVersion::V2);
    }
}
