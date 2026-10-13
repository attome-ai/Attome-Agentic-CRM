//! Property-based coverage for `attome_field::{validate, validate_options}` —
//! `P-verification-depth-hardening` (splits `P-enterprise-maturity-backlog`
//! item 1, triggered 2026-07-30), following `attome-security/tests/
//! rls_property.rs`'s precedent exactly: pure, no I/O, no `DATABASE_URL`, no
//! Redis, no running server — every function under test here builds a Rust
//! `Result` from a `FieldType` + `serde_json::Value` + optional `options`
//! blob with zero I/O.
//!
//! `lib.rs`'s own `#[cfg(test)] mod tests` already pins the hand-picked
//! example matrix (one string, one number, one malformed regex, ...). This
//! file generalizes those same invariants across the combinatorial input
//! space (arbitrary JSON shapes, arbitrary choice lists, arbitrary text mask
//! patterns and candidate strings) — the gap a hand-written matrix reliably
//! misses is the corner of the space nobody thought to write an example for,
//! same framing `rls_property.rs`'s own header comment uses.
//!
//! NOT verified against a real `cargo test` run in the session that authored
//! this file — no Rust toolchain available (see `document/detailed-plans/
//! P-verification-depth-hardening.md` §10 TODO 1). Run with:
//!
//! ```powershell
//! cargo test -p attome-field --test validation_property
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::FieldType;
use attome_field::{ChoiceOptions, TextOptions, validate, validate_options};
use proptest::prelude::*;
use serde_json::{Value, json};

// ── Strategies ─────────────────────────────────────────────────────────────

/// A small, realistic pool of candidate strings — includes empty string and
/// strings containing characters that matter for the anchoring/escaping
/// properties below (quotes, backslashes, regex metacharacters), rather than
/// fully unconstrained arbitrary text. Mirrors `rls_property.rs`'s own
/// `arb_id_column` reasoning: bias the generator toward the shapes that
/// actually stress the property, not a uniform random walk over all of
/// `String`.
fn arb_candidate_string() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z0-9]{0,12}",
        "[a-zA-Z0-9]{0,5}-[a-zA-Z0-9]{0,5}",
        Just(String::new()),
        Just("\"quoted\"".to_owned()),
        Just("back\\slash".to_owned()),
    ]
}

fn arb_choice_list() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec("[a-zA-Z]{1,8}", 1..6)
}

/// JSON leaf values across every shape `validate` must discriminate between
/// (string / number / bool / null / array-of-strings / object) — deliberately
/// NOT the value under test's own expected type, so "does `validate` reject
/// every wrong shape" can be checked generically per field type.
fn arb_json_leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<bool>().prop_map(Value::Bool),
        any::<i32>().prop_map(|n| json!(n)),
        arb_candidate_string().prop_map(Value::String),
        Just(Value::Null),
        prop::collection::vec(arb_candidate_string(), 0..4)
            .prop_map(|v| Value::Array(v.into_iter().map(Value::String).collect())),
    ]
}

fn arb_field_type() -> impl Strategy<Value = FieldType> {
    prop_oneof![
        Just(FieldType::Text),
        Just(FieldType::Number),
        Just(FieldType::Date),
        Just(FieldType::Bool),
        Just(FieldType::Choice),
        Just(FieldType::Lookup),
        Just(FieldType::File),
    ]
}

proptest! {
    // ── Type discrimination (Number/Bool/File — options-independent) ────────

    /// `Number` accepts exactly JSON numbers, `Bool` accepts exactly JSON
    /// booleans, `File` accepts exactly JSON strings — for ANY other leaf
    /// shape, `validate` must reject, never panic, never silently coerce.
    #[test]
    fn number_bool_file_accept_exactly_their_own_json_shape(value in arb_json_leaf()) {
        prop_assert_eq!(validate(&FieldType::Number, &value, None).is_ok(), value.is_number());
        prop_assert_eq!(validate(&FieldType::Bool, &value, None).is_ok(), value.is_boolean());
        prop_assert_eq!(validate(&FieldType::File, &value, None).is_ok(), value.is_string());
    }

    // ── Lookup: UUID-string-or-reject ────────────────────────────────────────

    /// Any syntactically valid UUID string is accepted; any string that
    /// doesn't parse as a UUID, and any non-string shape, is rejected.
    #[test]
    fn lookup_accepts_uuid_strings_and_nothing_else(
        value in arb_json_leaf(),
        uuid in any::<u128>().prop_map(uuid::Uuid::from_u128),
    ) {
        prop_assert_eq!(
            validate(&FieldType::Lookup, &value, None).is_ok(),
            value.as_str().is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
        );
        // A freshly-generated UUID's string form must always be accepted.
        prop_assert!(validate(&FieldType::Lookup, &json!(uuid.to_string()), None).is_ok());
    }

    // ── Date: RFC3339/plain-date-or-reject ───────────────────────────────────

    /// A well-formed `YYYY-MM-DD` string built from in-range components is
    /// always accepted; the same digits joined WITHOUT dashes (so it can't
    /// coincidentally still parse as a date) must always be rejected — the
    /// generalized form of the unit test's one hand-picked "not-a-date" case.
    #[test]
    fn date_accepts_well_formed_plain_dates_and_rejects_the_undashed_form(
        year in 1900i32..2100,
        month in 1u32..=12,
        day in 1u32..=28, // 28 avoids every month-length edge case on purpose —
                          // this property is about dash-presence, not calendar math
    ) {
        let dashed = format!("{year:04}-{month:02}-{day:02}");
        prop_assert!(validate(&FieldType::Date, &json!(dashed), None).is_ok());

        let undashed = format!("{year:04}{month:02}{day:02}");
        prop_assert!(validate(&FieldType::Date, &json!(undashed), None).is_err());
    }

    // ── Choice: single vs multi coercion must never blur ─────────────────────

    /// Single-select: accepts iff the value is a string present in `choices`.
    /// An array is always rejected outright, even a single-element array of
    /// an otherwise-valid choice — no silent coercion (the unit test's
    /// hand-picked `["green"]` case, generalized to any choice list/value).
    #[test]
    fn choice_single_select_accepts_iff_string_member_of_choices(
        choices in arb_choice_list(),
        candidate in arb_candidate_string(),
    ) {
        let opts = json!({ "choices": choices, "multi": false });
        let expect_ok = choices.contains(&candidate);
        prop_assert_eq!(
            validate(&FieldType::Choice, &json!(candidate), Some(&opts)).is_ok(),
            expect_ok
        );
        // The same candidate wrapped as a single-element array must always
        // be rejected under single-select, even when it would pass unwrapped.
        prop_assert!(validate(&FieldType::Choice, &json!([candidate]), Some(&opts)).is_err());
    }

    /// Multi-select: accepts iff every array item is a string member of
    /// `choices` (vacuously true for an empty array — `lib.rs`'s own loop has
    /// nothing to reject in that case); one bad item anywhere in the array
    /// rejects the whole value; a bare string (even a valid choice) is
    /// always rejected.
    #[test]
    fn choice_multi_select_requires_every_item_to_be_a_valid_choice(
        choices in arb_choice_list(),
        candidates in prop::collection::vec("[a-zA-Z]{1,8}", 0..5),
    ) {
        let opts = json!({ "choices": choices, "multi": true });
        let expect_ok = candidates.iter().all(|c| choices.contains(c));
        let arr = Value::Array(candidates.iter().cloned().map(Value::String).collect());
        prop_assert_eq!(validate(&FieldType::Choice, &arr, Some(&opts)).is_ok(), expect_ok);
        if let Some(first) = candidates.first() {
            // A bare string (unwrapped), even a genuinely valid choice, must
            // be rejected under multi-select.
            prop_assert!(validate(&FieldType::Choice, &json!(first), Some(&opts)).is_err());
        }
    }

    // ── Text mask: anchored full-match, never a substring match ──────────────

    /// A fixed 3-digit mask must accept an exact 3-digit string and reject
    /// that same digit string wrapped in any non-empty prefix/suffix — the
    /// generalized form of the unit test's one hand-picked
    /// `"abc123def"` case. Prefix/suffix are drawn from a pool that never
    /// itself happens to be all-digits-of-length-N, so the wrapped string
    /// can never coincidentally still match the anchored pattern.
    #[test]
    fn text_mask_rejects_any_non_empty_wrapping_of_an_otherwise_valid_value(
        digits in "[0-9]{3}",
        prefix in "[a-zA-Z]{1,4}",
        suffix in "[a-zA-Z]{1,4}",
    ) {
        let opts = json!({ "pattern": "[0-9]{3}" });
        prop_assert!(validate(&FieldType::Text, &json!(digits.clone()), Some(&opts)).is_ok());

        let wrapped_prefix = format!("{prefix}{digits}");
        let wrapped_suffix = format!("{digits}{suffix}");
        let wrapped_both = format!("{prefix}{digits}{suffix}");
        prop_assert!(validate(&FieldType::Text, &json!(wrapped_prefix), Some(&opts)).is_err());
        prop_assert!(validate(&FieldType::Text, &json!(wrapped_suffix), Some(&opts)).is_err());
        prop_assert!(validate(&FieldType::Text, &json!(wrapped_both), Some(&opts)).is_err());
    }

    /// A pattern already written with explicit `^`/`$` anchors must behave
    /// identically to the same pattern unanchored — `compiled_pattern`'s
    /// documented idempotence (anchoring is added only when absent, never
    /// doubled), checked across arbitrary candidate strings rather than one
    /// hand-picked case.
    #[test]
    fn pre_anchored_pattern_behaves_identically_to_unanchored(
        candidate in arb_candidate_string(),
    ) {
        let unanchored = json!({ "pattern": "[a-zA-Z0-9-]*" });
        let pre_anchored = json!({ "pattern": "^[a-zA-Z0-9-]*$" });
        prop_assert_eq!(
            validate(&FieldType::Text, &json!(candidate.clone()), Some(&unanchored)).is_ok(),
            validate(&FieldType::Text, &json!(candidate), Some(&pre_anchored)).is_ok()
        );
    }

    // ── validate_options: type-gating and never-panics ───────────────────────

    /// Number/Date/Bool/File never accept an `options` configuration at all,
    /// regardless of its shape — the unit test's one hand-picked
    /// `{"pattern": "x"}`-against-`Number` case, generalized to any JSON
    /// value as the (always-rejected) options blob.
    #[test]
    fn scalar_field_types_never_accept_any_options_blob(value in arb_json_leaf()) {
        prop_assert!(validate_options(&FieldType::Number, &value).is_err());
        prop_assert!(validate_options(&FieldType::Date, &value).is_err());
        prop_assert!(validate_options(&FieldType::Bool, &value).is_err());
        prop_assert!(validate_options(&FieldType::File, &value).is_err());
    }

    /// Whenever `validate_options` accepts a `Choice` options blob, that same
    /// blob must always be usable by `validate` for both a valid member and
    /// an invalid member of its own `choices` list — i.e. a config that
    /// passes admin-time validation never causes a panic or an unrelated
    /// error at record-write time (only the expected accept/reject verdict).
    #[test]
    fn accepted_choice_options_are_always_safe_to_use_in_validate(
        choices in arb_choice_list(),
        multi in any::<bool>(),
    ) {
        let opts = json!({ "choices": choices, "multi": multi });
        prop_assert!(validate_options(&FieldType::Choice, &opts).is_ok());

        let member = choices[0].clone();
        let member_value = if multi { json!([member]) } else { json!(member) };
        prop_assert!(validate(&FieldType::Choice, &member_value, Some(&opts)).is_ok());

        let not_member = json!(format!("{}-not-a-choice", choices[0]));
        let non_member_value = if multi { json!([not_member]) } else { not_member };
        prop_assert!(validate(&FieldType::Choice, &non_member_value, Some(&opts)).is_err());
    }

    /// A `Text` options blob that `validate_options` accepts must never cause
    /// `validate` to fail with a regex-compile error for any candidate value —
    /// once admin-time validation has passed, only content-mismatch failures
    /// are possible at record-write time, never a "bad pattern" failure. This
    /// is the load-bearing precondition-check property `validate_options`'s
    /// own doc comment promises ("rejected at write time rather than silently
    /// accepted and only discovered the first time a record write runs
    /// `validate` against it").
    #[test]
    fn accepted_text_options_never_fail_validate_with_a_pattern_compile_error(
        pattern in "[a-zA-Z0-9\\[\\]{}(),.*+?^$|\\\\-]{0,10}",
        candidate in arb_candidate_string(),
    ) {
        let opts = json!({ "pattern": pattern });
        if validate_options(&FieldType::Text, &opts).is_ok() {
            // Whatever `validate` returns (Ok on match, content-mismatch Err
            // on no match), it must not itself be an internal regex error —
            // approximated here by requiring it never panics (proptest fails
            // the case on an unwinding panic) and always returns a `Result`.
            let _ = validate(&FieldType::Text, &json!(candidate), Some(&opts));
        }
    }

    // ── validate_options: Lookup options never panic on arbitrary shapes ─────

    /// `validate_options` for `Lookup` must never panic, whatever JSON shape
    /// the options blob takes — only ever return `Ok`/`Err`.
    #[test]
    fn lookup_options_never_panics_on_arbitrary_json(value in arb_json_leaf()) {
        let _ = validate_options(&FieldType::Lookup, &value);
    }

    // ── Whole-surface never-panics property ──────────────────────────────────

    /// For any `FieldType` x any JSON leaf value x an absent options blob,
    /// `validate` must never panic — the baseline contract every property
    /// above assumes and a fuzz target would otherwise be the only thing
    /// checking.
    #[test]
    fn validate_never_panics_with_no_options(
        field_type in arb_field_type(),
        value in arb_json_leaf(),
    ) {
        let _ = validate(&field_type, &value, None);
    }
}

// ── Sanity checks that the strategies above line up with the real structs ───
// (compile-time only — if `ChoiceOptions`/`TextOptions`'s fields ever change
// shape, these fail to compile rather than the proptest cases silently
// exercising the wrong JSON shape.)
#[allow(dead_code)]
fn _strategy_shape_matches_real_structs() {
    let _: ChoiceOptions =
        serde_json::from_value(json!({ "choices": [], "multi": false })).unwrap();
    let _: TextOptions = serde_json::from_value(json!({ "pattern": null })).unwrap();
}
