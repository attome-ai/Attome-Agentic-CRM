//! Auto Value — admin-configured, system-generated field values.
//!
//! An *auto value rule* binds a target entity + attribute to a format string
//! and a counter, so that creating a record fills that field automatically
//! (`AVG-0001-26-08-07`) instead of asking a user to invent an identifier.
//! This is the platform's autonumber primitive: invoice numbers, case
//! references, employee IDs.
//!
//! # Where the pieces live
//!
//! * The rule table `autovalue` is a *metadata-defined entity*, not
//!   a migration-owned infra table — `seed()` below registers it through the
//!   ordinary provision API, so `provision_table` creates the physical table
//!   and every admin surface (list, form, view, per-entity privileges) comes
//!   from the generic metadata-driven pages for free. That is the D-003 DDL
//!   ownership split applied literally: migrations own infrastructure,
//!   runtime provisioning owns entity tables, and this *is* an entity table.
//! * [`AutoValue`] is the "auto value class" that processes a rule: it owns
//!   format parsing, sequence allocation, and rendering.
//! * [`generate_for_create`] is the single entry point the create path calls;
//!   `attome-server`'s `entity_mutation::create_one` invokes it so ordinary
//!   create, upsert, and bulk import all go through the same allocation.
//!
//! # Format language
//!
//! Literal text passes through untouched. `{{` and `}}` are literal braces.
//! Everything inside a single `{...}` is a token:
//!
//! | Token                  | Meaning                                    |
//! |------------------------|--------------------------------------------|
//! | `{DDDD}`, `{####}`     | the sequence number, zero-padded to width  |
//! | `{SEQ}`, `{SEQ:4}`     | the same, named explicitly                 |
//! | `{YY-MM-DD}`, `{YYYY}` | the current local date/time, by pattern    |
//! | `{LUHN}`, `{MOD11}`    | a check digit over the sequence (A4-T4)    |
//! | `{hyyyy}`, `{hmm}`, `{hdd}` | the Umm al-Qura Hijri year, month, day (AG1-T5) |
//!
//! The `D`-vs-day ambiguity in the motivating example `AVG-{DDDD}-{YY-MM-DD}`
//! is resolved structurally, not by guessing: a token made of *nothing but*
//! `D`/`#` is the sequence (width = its length), and any other token is a
//! date pattern in which `DD` means day-of-month. So `{DDDD}` numbers the
//! record and `{YY-MM-DD}` dates it, which is what that example reads as.
//! Inside a date pattern the recognised units are `YYYY YY MM DD HH mm ss`
//! (`MM` month vs `mm` minute follow the usual case convention); anything
//! else in the pattern is literal.
//!
//! # Concurrency
//!
//! Allocation is a single `UPDATE ... RETURNING` against the rule row, run on
//! the *caller's* transaction. That is deliberate on both counts:
//!
//! * Same transaction as the INSERT, so a create that fails afterwards rolls
//!   the number back rather than burning it.
//! * Row-locked rather than a PostgreSQL sequence, so numbering is gap-free —
//!   which is the entire point of a customer-visible invoice number. The
//!   price is that concurrent creates against the *same rule* serialize on
//!   that row for the remainder of the transaction. That is the correct
//!   trade for identifier numbering; a rule is per entity+field, so unrelated
//!   entities never contend with each other.

use attome_core::AttrInfo;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Datelike, FixedOffset, Timelike};
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

/// Logicalname of the rule entity. Renders at `/xrm/core/autovalue/list` and
/// `/xrm/core/autovalue/form?id=…` — the Angular shell maps
/// `xrm_{module}_{entity}` to that path by replacing underscores with `/`.
pub const AUTOVALUE_ENTITY: &str = "autovalue";

/// When a rule's counter restarts. Stored as the `reset_scope` choice column.
///
/// The counter restarts at `initial_value` whenever the *scope key* for the
/// current instant differs from the one recorded on the rule — so a `Yearly`
/// rule's first create of 2027 gets `initial_value` again. Storing the last
/// key on the rule row keeps this to one column pair instead of a separate
/// per-period counter table, and it resets correctly even if a whole period
/// passes with no records created.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ResetScope {
    /// One monotonic sequence for the life of the rule.
    #[default]
    Never,
    Yearly,
    Monthly,
    Daily,
}

impl ResetScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Yearly => "yearly",
            Self::Monthly => "monthly",
            Self::Daily => "daily",
        }
    }

    /// Unrecognised/NULL values fall back to `Never` rather than failing the
    /// create: a malformed rule should keep issuing numbers monotonically,
    /// not block every insert into the entity it is attached to.
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.unwrap_or("").trim().to_ascii_lowercase().as_str() {
            "yearly" => Self::Yearly,
            "monthly" => Self::Monthly,
            "daily" => Self::Daily,
            _ => Self::Never,
        }
    }

    /// The period key for `now`. Equal keys mean "same period, keep counting".
    pub fn scope_key(self, now: DateTime<FixedOffset>) -> String {
        match self {
            Self::Never => String::new(),
            Self::Yearly => format!("{:04}", now.year()),
            Self::Monthly => format!("{:04}-{:02}", now.year(), now.month()),
            Self::Daily => format!("{:04}-{:02}-{:02}", now.year(), now.month(), now.day()),
        }
    }
}

/// One auto value rule, as loaded from `autovalue`.
///
/// This is the "auto value class": given an allocated sequence number and a
/// clock it produces the final field value, and it knows how to allocate that
/// number transactionally. Formatting ([`AutoValue::render`]) is pure and
/// unit-tested without a database; only [`AutoValue::allocate`] touches one.
#[derive(Clone, Debug)]
pub struct AutoValue {
    pub id: Uuid,
    /// Target entity — "ref to the table".
    pub entity_logicalname: String,
    /// Target attribute on that entity — "the field".
    pub attribute_logicalname: String,
    /// The formula, e.g. `AVG-{DDDD}-{YY-MM-DD}`.
    pub format: String,
    /// Where the counter starts, and where it restarts on a scope rollover.
    pub initial_value: i64,
    pub reset_scope: ResetScope,
}

impl AutoValue {
    /// Renders this rule's format with `seq` and `now`. Pure — no I/O.
    pub fn render(&self, seq: i64, now: DateTime<FixedOffset>) -> String {
        render_format(&self.format, seq, now)
    }

    /// Claims the next sequence number for this rule and returns the rendered
    /// value, on the caller's transaction.
    ///
    /// The CASE reads the rule's *old* `scope_key` (SET expressions always
    /// see the pre-UPDATE row), which is what makes the period rollover a
    /// single statement: restart at `initial_value` when the period changed,
    /// otherwise continue from `next_value`. `RETURNING next_value - 1` hands
    /// back the number this call just consumed, since the column has already
    /// been advanced past it.
    ///
    /// `COALESCE` guards the columns rather than trusting them: `next_value`
    /// is NULL on a rule an admin created without filling the counter in, and
    /// NULL would otherwise poison the whole arithmetic chain.
    ///
    /// `row_version` is bumped so an admin editing the rule through the
    /// generic form still gets a proper `If-Match` conflict (D-037) instead
    /// of silently overwriting a counter that moved underneath them.
    ///
    /// Returns `None` when the rule no longer matches — deactivated or
    /// deleted between [`load_rules`] and this statement. That is a real race
    /// (the admin form and the create path are different requests), and the
    /// caller treats it as "this rule no longer applies" rather than an
    /// error: an admin turning a rule off must not start failing every create
    /// on the entity it was attached to.
    pub async fn allocate(
        &self,
        conn: &mut PgConnection,
        now: DateTime<FixedOffset>,
    ) -> Result<Option<String>, AppError> {
        let scope_key = self.reset_scope.scope_key(now);
        let seq: Option<i64> = sqlx::query_scalar(
            "UPDATE autovalue \
                SET next_value = (CASE WHEN scope_key IS DISTINCT FROM $2 \
                                       THEN COALESCE(initial_value, 1) \
                                       ELSE COALESCE(next_value, initial_value, 1) END) + 1, \
                    scope_key   = $2, \
                    row_version = COALESCE(row_version, 0) + 1, \
                    modified_at  = NOW() \
              WHERE id = $1 AND is_active = TRUE \
          RETURNING (next_value - 1)::bigint",
        )
        .bind(self.id)
        .bind(&scope_key)
        .fetch_optional(conn)
        .await
        .map_err(AppError::internal)?;

        Ok(seq.map(|seq| self.render(seq, now)))
    }
}

// ── Format rendering ─────────────────────────────────────────────────────────

/// Expands `{...}` tokens in `format`. See the module docs for the language.
/// Pure, infallible, and total: an unterminated `{` is emitted literally
/// rather than erroring, because a rule is applied on the create path and a
/// typo in a format must not make an entity un-creatable.
fn render_format(format: &str, seq: i64, now: DateTime<FixedOffset>) -> String {
    let mut out = String::with_capacity(format.len() + 8);
    let mut chars = format.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut token = String::new();
                let mut closed = false;
                for tc in chars.by_ref() {
                    if tc == '}' {
                        closed = true;
                        break;
                    }
                    token.push(tc);
                }
                if closed {
                    out.push_str(&render_token(&token, seq, now));
                } else {
                    // Unterminated — emit what we consumed, verbatim.
                    out.push('{');
                    out.push_str(&token);
                }
            }
            other => out.push(other),
        }
    }

    out
}

/// Resolves one token's meaning. Sequence tokens win over date patterns, and
/// the test for "is this a sequence" is structural (`D`/`#` only, or a `SEQ`
/// prefix) so that `{DDDD}` and `{YY-MM-DD}` can coexist in one format — see
/// the module docs.
fn render_token(token: &str, seq: i64, now: DateTime<FixedOffset>) -> String {
    let trimmed = token.trim();

    if !trimmed.is_empty() && trimmed.chars().all(|c| c == 'D' || c == '#') {
        return pad(seq, trimmed.chars().count());
    }

    if let Some(rest) = trimmed
        .strip_prefix("SEQ")
        .or_else(|| trimmed.strip_prefix("seq"))
    {
        let width = rest
            .trim_start_matches([':', '-'])
            .trim()
            .parse::<usize>()
            .unwrap_or(0);
        return pad(seq, width);
    }

    // A4-T4: a check digit over the sequence number, so a mistyped
    // reference is caught on entry.
    match trimmed {
        "LUHN" | "luhn" => return luhn_digit(seq).to_string(),
        "MOD11" | "mod11" => return mod11_digit(seq).to_string(),
        // AG1-T5: the Hijri date of the deployment-local day. They start with
        // `h`, so they never read as a sequence or a Gregorian pattern.
        "hyyyy" | "hmm" | "hdd" => return render_hijri(trimmed, now),
        _ => {}
    }

    render_datetime_pattern(trimmed, now)
}

/// One Hijri token for `now`'s local day. Past the Umm al-Qura table (after
/// 2077) the token renders as zeros rather than a wrong date.
fn render_hijri(token: &str, now: DateTime<FixedOffset>) -> String {
    let date = attome_core::calendar::hijri::to_hijri(now.date_naive()).ok();
    match token {
        "hyyyy" => format!("{:04}", date.map_or(0, |d| d.year)),
        "hmm" => format!("{:02}", date.map_or(0, |d| d.month)),
        _ => format!("{:02}", date.map_or(0, |d| d.day)),
    }
}

/// The decimal digits of `seq`, most significant first.
fn digits(seq: i64) -> Vec<u32> {
    seq.unsigned_abs()
        .to_string()
        .chars()
        .filter_map(|c| c.to_digit(10))
        .collect()
}

/// The Luhn check digit for `seq` (the digit to append).
pub fn luhn_digit(seq: i64) -> u32 {
    let sum: u32 = digits(seq)
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 0 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    (10 - sum % 10) % 10
}

/// The mod 11 check character for `seq`: weights 2 to 7 from the right,
/// `11 - sum % 11`, with 10 as `X` and 11 as `0`.
pub fn mod11_digit(seq: i64) -> char {
    let sum: u32 = digits(seq)
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| d * (2 + (i as u32 % 6)))
        .sum();
    match 11 - sum % 11 {
        10 => 'X',
        11 => '0',
        n => char::from_digit(n, 10).unwrap_or('0'),
    }
}

fn pad(seq: i64, width: usize) -> String {
    format!("{seq:0width$}")
}

/// Greedy longest-match over the recognised date units; every other character
/// is literal, which is what lets `YY-MM-DD` keep its own hyphens.
fn render_datetime_pattern(pattern: &str, now: DateTime<FixedOffset>) -> String {
    const UNITS: &[&str] = &["YYYY", "YY", "MM", "DD", "HH", "mm", "ss"];

    let mut out = String::with_capacity(pattern.len());
    let bytes = pattern.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let rest = &pattern[i..];
        let matched = UNITS.iter().find(|unit| rest.starts_with(**unit));
        match matched {
            Some(unit) => {
                out.push_str(&match *unit {
                    "YYYY" => format!("{:04}", now.year()),
                    "YY" => format!("{:02}", now.year().rem_euclid(100)),
                    "MM" => format!("{:02}", now.month()),
                    "DD" => format!("{:02}", now.day()),
                    "HH" => format!("{:02}", now.hour()),
                    "mm" => format!("{:02}", now.minute()),
                    _ => format!("{:02}", now.second()),
                });
                i += unit.len();
            }
            None => {
                // Step by whole characters — `pattern` may be non-ASCII.
                let ch = rest.chars().next().unwrap_or_default();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }

    out
}

// ── Create-path integration ──────────────────────────────────────────────────

/// Generates every auto value owed by a record being created into
/// `entity_logicalname`, returning `(attribute, value)` pairs to merge into
/// the request body.
///
/// Three rules about what it will *not* do, all of them deliberate:
///
/// * A field the caller supplied explicitly is left alone, and its counter is
///   not advanced. An import that carries real historical invoice numbers has
///   to be able to keep them.
/// * A rule naming an attribute the entity does not actually have is skipped
///   with a warning. Otherwise a stale rule would inject an unknown field and
///   turn every create on that entity into a validation error.
/// * A rule whose allocation fails propagates the error, failing the create.
///   The alternative — inserting the record with the field blank — would
///   silently produce an unnumbered invoice, which is worse than a 500.
///
/// Costs one SELECT per create even when the entity has no rules. That is a
/// sequential scan — `ensure_attribute` records `is_filterable` as metadata
/// but does not build an index (only its `_with_index_job` variant does) —
/// and deliberately left that way: this table holds one row per configured
/// entity+field across the whole deployment, a size at which Postgres would
/// ignore an index anyway.
///
/// Not cached either: a cache here would need cluster-wide invalidation on
/// every rule edit to stop two nodes issuing the same number, and that
/// correctness burden buys nothing against a scan of a few dozen rows.
pub async fn generate_for_create(
    conn: &mut PgConnection,
    entity_logicalname: &str,
    attrs: &[AttrInfo],
    supplied: &serde_json::Map<String, Value>,
    now: DateTime<FixedOffset>,
    allow_supplied: bool,
) -> Result<Vec<(String, String)>, AppError> {
    let rules = load_rules(&mut *conn, entity_logicalname).await?;
    let mut generated = Vec::new();

    for rule in rules {
        let field = rule.attribute_logicalname.as_str();

        if supplied
            .get(field)
            .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
        {
            // A4-T2: a number the system issues is not the caller's to pick.
            // A data migration (an approved staged import, a bundle record
            // set) keeps the numbers it brings.
            if allow_supplied {
                continue;
            }
            return Err(AppError::Validation(format!(
                "{field} is numbered automatically; leave it empty"
            )));
        }

        if !attrs.iter().any(|a| a.logicalname == field) {
            tracing::warn!(
                rule_id = %rule.id,
                entity = %entity_logicalname,
                field,
                "auto value rule names an attribute this entity does not have; skipping"
            );
            continue;
        }

        let Some(value) = rule.allocate(&mut *conn, now).await? else {
            tracing::debug!(
                rule_id = %rule.id,
                entity = %entity_logicalname,
                field,
                "auto value rule went inactive mid-create; leaving the field unset"
            );
            continue;
        };
        tracing::debug!(rule_id = %rule.id, entity = %entity_logicalname, field, "auto value generated");
        generated.push((rule.attribute_logicalname.clone(), value));
    }

    Ok(generated)
}

/// One `autovalue` row as loaded by [`load_rules`]. Every column
/// except the primary key is nullable: the rule table is admin-editable
/// through the generic form, so a half-filled rule is reachable and must
/// degrade rather than fail the create it is attached to.
#[derive(sqlx::FromRow)]
struct RuleRow {
    id: Uuid,
    attribute_logicalname: String,
    format: Option<String>,
    initial_value: Option<i64>,
    reset_scope: Option<String>,
}

/// Loads the active rules targeting one entity, oldest first so a multi-rule
/// entity allocates in a stable order (and therefore takes row locks in a
/// stable order, which is what keeps two concurrent creates from deadlocking
/// against each other).
async fn load_rules(
    conn: &mut PgConnection,
    entity_logicalname: &str,
) -> Result<Vec<AutoValue>, AppError> {
    // `initial_value` is a `number` attribute, so its column is NUMERIC;
    // cast in SQL rather than decoding a decimal and rounding in Rust.
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT id, attribute_logicalname, format, \
                initial_value::bigint AS initial_value, reset_scope \
           FROM autovalue \
          WHERE entity_logicalname = $1 \
            AND is_active = TRUE \
            AND attribute_logicalname IS NOT NULL \
            AND attribute_logicalname <> '' \
          ORDER BY created_at ASC NULLS LAST, id",
    )
    .bind(entity_logicalname)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(|row| AutoValue {
            id: row.id,
            entity_logicalname: entity_logicalname.to_owned(),
            attribute_logicalname: row.attribute_logicalname,
            // A rule saved without a format still yields the bare number
            // rather than an empty string, so a half-configured rule produces
            // something traceable instead of a blank field.
            format: row.format.unwrap_or_else(|| "{SEQ}".to_owned()),
            initial_value: row.initial_value.unwrap_or(1),
            reset_scope: ResetScope::parse(row.reset_scope.as_deref()),
        })
        .collect())
}

// ── Seed ─────────────────────────────────────────────────────────────────────

/// Test-fixture equivalent of applying `platform-bundles/
/// attome-metadata-autovalue.json` — what boot does through
/// `attome_server::bundle::apply_platform_bundle` (`system.rs`), which this
/// crate sits below and cannot call. D-478 (seeds-to-bundles, second
/// pass): the `ensure_entity`/`ensure_attribute`/`ensure_default_query`
/// calls that used to live here as `seed()` are gone; the bundle is the
/// single source of truth and this walks it through the same primitives.
///
/// Why the bundle's attributes look the way they do (none `is_required`,
/// `next_value`/`scope_key` as ordinary attributes): the generic create
/// path validates required fields *before* this module fills anything
/// in, so a required auto-value-managed field would reject the very
/// create that was about to populate it — rules express necessity
/// through the format, not `is_required`; and a column only exists at
/// all if it is a registered attribute, and an admin genuinely does need
/// to fast-forward a counter (starting invoices at 5000 mid-year).
pub async fn seed_for_tests(db: &DbPool) -> Result<(), AppError> {
    crate::provision::seed_bundle_for_tests(
        db,
        "attome-metadata-autovalue",
        include_str!("../seed/autovalue.json"),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(y: i32, m: u32, d: u32) -> DateTime<FixedOffset> {
        chrono::Utc
            .with_ymd_and_hms(y, m, d, 13, 4, 5)
            .unwrap()
            .fixed_offset()
    }

    #[test]
    fn check_digits_catch_a_mistyped_number() {
        // 7992739871 → Luhn check digit 3 (the textbook example).
        assert_eq!(luhn_digit(7_992_739_871), 3);
        assert_eq!(luhn_digit(0), 0);
        assert_eq!(
            render_format("INV-{SEQ:6}{LUHN}", 42, at(2026, 1, 1)),
            "INV-0000422"
        );
        // Mod 11: 123456 from the right with weights 2..7 sums to 77,
        // 77 % 11 = 0, so 11 - 0 = 11, written 0.
        assert_eq!(mod11_digit(123_456), '0');
        assert_eq!(
            render_format("{SEQ}-{MOD11}", 123_456, at(2026, 1, 1)),
            "123456-0"
        );
        // 12345: 5*2 + 4*3 + 3*4 + 2*5 + 1*6 = 50, 50 % 11 = 6, 11 - 6 = 5.
        assert_eq!(mod11_digit(12_345), '5');
        // A swapped pair changes the Luhn digit.
        assert_ne!(luhn_digit(1234), luhn_digit(1243));
    }

    /// A4-T1: the date tokens and the reset key read the local date. At
    /// 22:30 UTC on 31 December it is already 1 January in Riyadh (UTC+3).
    #[test]
    fn dates_and_resets_follow_the_local_date() {
        let riyadh = FixedOffset::east_opt(3 * 3600).unwrap();
        let utc_evening = chrono::Utc
            .with_ymd_and_hms(2026, 12, 31, 22, 30, 0)
            .unwrap();
        let local = utc_evening.with_timezone(&riyadh);
        assert_eq!(render_format("{YYYY-MM-DD}", 1, local), "2027-01-01");
        assert_eq!(ResetScope::Yearly.scope_key(local), "2027");
        assert_eq!(
            render_format("{YYYY-MM-DD}", 1, utc_evening.fixed_offset()),
            "2026-12-31"
        );
    }

    #[test]
    fn hijri_year_token_renders() {
        assert_eq!(
            render_format("INV-{hyyyy}-{####}", 7, at(2026, 2, 18)),
            "INV-1447-0007"
        );
    }

    #[test]
    fn hijri_month_token_pads() {
        // 2026-02-18 is 1 Ramadan 1447; the day before is 29 Shaban.
        assert_eq!(render_format("{hmm}/{hdd}", 1, at(2026, 2, 18)), "09/01");
        assert_eq!(render_format("{hmm}/{hdd}", 1, at(2026, 2, 17)), "08/29");
    }

    #[test]
    fn renders_the_motivating_example() {
        // `{DDDD}` is the sequence, `{YY-MM-DD}` is the date — the whole
        // point of the structural disambiguation rule.
        assert_eq!(
            render_format("AVG-{DDDD}-{YY-MM-DD}", 1, at(2026, 8, 7)),
            "AVG-0001-26-08-07"
        );
    }

    #[test]
    fn sequence_pads_to_token_width_and_overflows_it_rather_than_truncating() {
        assert_eq!(render_format("{DD}", 7, at(2026, 8, 7)), "07");
        assert_eq!(render_format("{####}", 42, at(2026, 8, 7)), "0042");
        assert_eq!(render_format("{SEQ:6}", 42, at(2026, 8, 7)), "000042");
        assert_eq!(render_format("{SEQ}", 42, at(2026, 8, 7)), "42");
        // A number wider than its token keeps every digit — silently losing
        // the high digits would mint duplicate identifiers.
        assert_eq!(render_format("{DDD}", 123456, at(2026, 8, 7)), "123456");
    }

    #[test]
    fn date_pattern_units_and_literals() {
        let now = at(2026, 8, 7);
        assert_eq!(render_format("{YYYY}", 1, now), "2026");
        assert_eq!(render_format("{YYYY/MM/DD}", 1, now), "2026/08/07");
        // MM is month, mm is minute.
        assert_eq!(render_format("{HH:mm:ss}", 1, now), "13:04:05");
        assert_eq!(render_format("{MM}-{mm}", 1, now), "08-04");
    }

    #[test]
    fn literal_text_and_escaped_braces_survive() {
        assert_eq!(render_format("INV", 1, at(2026, 8, 7)), "INV");
        assert_eq!(render_format("{{x}}", 1, at(2026, 8, 7)), "{x}");
        // Unterminated braces are emitted verbatim: a typo in a format must
        // not make the target entity un-creatable.
        assert_eq!(render_format("A-{DDD", 1, at(2026, 8, 7)), "A-{DDD");
    }

    #[test]
    fn scope_keys_change_exactly_when_their_period_rolls_over() {
        let aug7 = at(2026, 8, 7);
        let aug8 = at(2026, 8, 8);
        let sep7 = at(2026, 9, 7);
        let next_year = at(2027, 1, 1);

        assert_eq!(
            ResetScope::Never.scope_key(aug7),
            ResetScope::Never.scope_key(next_year)
        );
        assert_eq!(
            ResetScope::Yearly.scope_key(aug7),
            ResetScope::Yearly.scope_key(sep7)
        );
        assert_ne!(
            ResetScope::Yearly.scope_key(aug7),
            ResetScope::Yearly.scope_key(next_year)
        );
        assert_eq!(
            ResetScope::Monthly.scope_key(aug7),
            ResetScope::Monthly.scope_key(aug8)
        );
        assert_ne!(
            ResetScope::Monthly.scope_key(aug7),
            ResetScope::Monthly.scope_key(sep7)
        );
        assert_ne!(
            ResetScope::Daily.scope_key(aug7),
            ResetScope::Daily.scope_key(aug8)
        );
    }

    #[test]
    fn unknown_reset_scope_degrades_to_never_instead_of_failing() {
        assert_eq!(ResetScope::parse(Some("Yearly")), ResetScope::Yearly);
        assert_eq!(ResetScope::parse(Some(" DAILY ")), ResetScope::Daily);
        assert_eq!(ResetScope::parse(Some("nonsense")), ResetScope::Never);
        assert_eq!(ResetScope::parse(None), ResetScope::Never);
    }
}
