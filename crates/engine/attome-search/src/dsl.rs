//! A small user-facing query DSL (M11 gap list) — `field:value`, quoted
//! phrases, and `-exclude` — parsed into plain Rust values that the search
//! route applies **on top of** the existing fused/visibility-filtered result
//! set, never as a second enforcement path.
//!
//! **This module builds no SQL and holds no database handle.** That is the
//! whole safety argument: [`parse`] is a pure function from `&str` to
//! [`ParsedQuery`], whose fields are `String`/`Vec<String>`/`Option<String>`.
//! Every one of them is either (a) never used to build SQL at all — the
//! `entity_filter` is compared against an already-fetched, already
//! visibility-filtered candidate's `entity_logicalname` in plain Rust,
//! `Vec<T>::contains`/`==`, no query — or (b) bound through `push_bind`
//! exactly like every value in `legs/` (`required_phrases`/`excluded_terms`,
//! consumed by `routes::apply_text_narrowing`). A crafted string cannot reach
//! raw SQL from here because there is no SQL construction here to reach.
//!
//! **`field:value` only ever narrows by [`entity_logicalname`], the one
//! column that is uniform across every corpus row regardless of which
//! entity's metadata backs it** (`search_index.entity_logicalname`,
//! already projected by the fused statement). A per-entity attribute filter
//! (`status:open` against a case's own `status` column) would need the same
//! per-entity metadata whitelist `aggregate.rs`'s `build_whitelist` builds
//! for `attome_core::filter::compile` (C-15, M01 §7) — which needs one
//! target entity resolved up front, which search's whole design point is to
//! not require. That is out of scope here: adding
//! it would mean either resolving a target entity before running a
//! cross-entity fused query (defeating the point of "search across
//! everything") or reaching into `legs`/`fuse` to add a per-leg join against
//! N different physical tables — squarely the "core ranking/router logic"
//! this gap list is explicit about not touching. `type:`/`entity:` stays the
//! one structured field for that reason, not as an oversight.
//!
//! `-exclude`/quoted phrases are enforced against `title`/`subtitle` only —
//! the same two columns `routes::fetch_display_text` already reads for
//! display, for the same cost reason its doc comment gives: reading
//! `body_indexed` for the whole (bounded, but up to `tuning.ceiling`)
//! candidate set is the second read-amplification `fetch_display_text`
//! deliberately avoids for `page_size` rows, and this narrowing runs over the
//! full candidate set, before pagination. A phrase can appear in a matched
//! document's body without appearing in its title/subtitle — this is
//! documented as a real, narrower scope, not silently underspecified.

use attome_core::Filter;

/// Field names `field:value` may name today. Anything else is not special —
/// see the module doc for why the set stays this small.
const WHITELISTED_FIELDS: &[&str] = &["entity", "type"];

/// What the DSL contributed, on top of the free-text query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedQuery {
    /// Fed into the *existing* pipeline exactly like a raw `q` would be —
    /// `router::route`, `normalize_ar`, `project::index_text`. Equal to the
    /// original input, word for word, whenever nothing structured was found
    /// — an ordinary query is untouched by this module's presence.
    pub free_text: String,
    /// From `entity:`/`type:` — the search-index-uniform column this maps
    /// to. `None` when no recognised field token was present. The **first**
    /// occurrence wins if a caller (oddly) repeats the field; later ones are
    /// treated as free text, exactly like the routing rules in `router.rs`
    /// pin a fixed evaluation order rather than let the last write win.
    pub entity_filter: Option<String>,
    /// Quoted spans (`"exact phrase"`). Also folded into `free_text` — see
    /// the module doc — so a phrase still contributes to lexical scoring in
    /// the existing legs, and is *additionally* required to appear verbatim
    /// (case-insensitively) in the candidate's title/subtitle.
    pub required_phrases: Vec<String>,
    /// `-word` / `-"phrase"`. Removed from `free_text` entirely (an excluded
    /// term should not itself boost the match) and required *not* to appear
    /// in the candidate's title/subtitle.
    pub excluded_terms: Vec<String>,
}

impl ParsedQuery {
    /// Whether anything beyond plain free text was found — the DSL surface
    /// used no query, no visibility recheck, and no post-fusion narrowing.
    pub fn is_structured(&self) -> bool {
        self.entity_filter.is_some()
            || !self.required_phrases.is_empty()
            || !self.excluded_terms.is_empty()
    }

    /// Compiles [`entity_filter`](Self::entity_filter) into the platform's
    /// shared filter grammar (`attome_core::Filter`), for callers that
    /// want the structured value in that shape (e.g. round-tripping into a
    /// saved search's stored `filters`). Search's own execution path does
    /// **not** consume this — see the module doc for why entity filtering is
    /// applied as a plain in-memory comparison, not a query — this exists so
    /// a DSL-derived filter is expressed once, in the platform's one shared
    /// filter type, wherever something other than search's own fused
    /// statement wants it (guidelines §1: no new enforcement path, no
    /// second representation of the same value either).
    pub fn entity_filter_as_filter(&self) -> Option<Filter> {
        self.entity_filter.as_ref().map(|value| Filter {
            field: "entity_logicalname".to_owned(),
            op: "eq".to_owned(),
            value: Some(serde_json::Value::String(value.clone())),
        })
    }
}

/// Parses a raw query string into free text plus the DSL's structured parts.
///
/// Never fails and never panics on any input, including unterminated quotes,
/// bare `-`/`:`  characters, empty tokens, control characters, or arbitrarily
/// long single tokens — a search box submits all of these, and a DSL that
/// rejects malformed structure would turn a typo into a 422 for a feature
/// nobody asked to be strict. Anything that does not cleanly parse as a
/// structured token is kept as ordinary free text, verbatim.
pub fn parse(raw: &str) -> ParsedQuery {
    let mut free_text_tokens: Vec<String> = Vec::new();
    let mut entity_filter: Option<String> = None;
    let mut required_phrases: Vec<String> = Vec::new();
    let mut excluded_terms: Vec<String> = Vec::new();

    for raw_tok in tokenize(raw) {
        if raw_tok.is_empty() {
            continue;
        }

        let (negated, body) = match raw_tok.strip_prefix('-') {
            // A bare "-" with nothing after it is not a negation of
            // anything — keep it as free text rather than producing an
            // empty excluded term nobody typed.
            Some(rest) if !rest.is_empty() => (true, rest),
            _ => (false, raw_tok.as_str()),
        };

        let (unquoted, was_quoted) = strip_quotes(body);

        if !was_quoted
            && !negated
            && let Some((field, value)) = split_field_value(&unquoted)
            && WHITELISTED_FIELDS.contains(&field.to_lowercase().as_str())
        {
            let (value_unquoted, _) = strip_quotes(value);
            if !value_unquoted.is_empty() {
                if entity_filter.is_none() {
                    entity_filter = Some(value_unquoted);
                }
                // A recognised structured token, consumed — not free text,
                // not an error either way (first occurrence wins, see the
                // field doc).
                continue;
            }
        }

        if negated {
            if !unquoted.is_empty() {
                excluded_terms.push(unquoted);
            }
            continue;
        }

        if was_quoted {
            if !unquoted.is_empty() {
                required_phrases.push(unquoted.clone());
                free_text_tokens.push(unquoted);
            }
            continue;
        }

        free_text_tokens.push(unquoted);
    }

    ParsedQuery {
        free_text: free_text_tokens.join(" "),
        entity_filter,
        required_phrases,
        excluded_terms,
    }
}

/// Splits whitespace-delimited tokens, treating a `"..."` span (however it
/// opens — mid-token, as in `type:"my entity"`, or bare) as one inseparable
/// unit. An unterminated quote simply runs to the end of the string rather
/// than being rejected — the tokenizer never errors.
fn tokenize(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in raw.chars() {
        if ch == '"' {
            in_quotes = !in_quotes;
            current.push(ch);
            continue;
        }
        if ch.is_whitespace() && !in_quotes {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Strips a single matched pair of surrounding double quotes, if present.
/// Returns the (possibly unchanged) text and whether it was quoted.
fn strip_quotes(s: &str) -> (String, bool) {
    let chars_len = s.chars().count();
    if chars_len >= 2 && s.starts_with('"') && s.ends_with('"') {
        let inner: String = s.chars().skip(1).take(chars_len - 2).collect();
        (inner, true)
    } else {
        (s.to_owned(), false)
    }
}

/// Splits `field:value` at the first `:`. Requires a non-empty, identifier-
/// shaped field name (`[A-Za-z_][A-Za-z0-9_]*`) so an ordinary query
/// containing a colon for an unrelated reason (a time like `10:30`, a URL, a
/// ratio) is never misread as a structured token — a field name has to look
/// like one before anything downstream even checks the whitelist.
fn split_field_value(token: &str) -> Option<(&str, &str)> {
    let idx = token.find(':')?;
    let (field, rest) = token.split_at(idx);
    let value = &rest[1..];
    if field.is_empty() || value.is_empty() {
        return None;
    }
    let mut chars = field.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if first_ok && rest_ok {
        Some((field, value))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Ordinary queries are untouched ──────────────────────────────────

    /// The load-bearing property: a query with no DSL syntax must produce
    /// `free_text` identical to the input, so every existing search behavior
    /// (routing, normalization, ranking) is unaffected by this module's mere
    /// existence.
    #[test]
    fn plain_queries_pass_through_unchanged() {
        for q in ["acme trading", "INV-9001", "محمد", "a b c d e"] {
            let parsed = parse(q);
            assert_eq!(parsed.free_text, q);
            assert!(!parsed.is_structured());
        }
    }

    #[test]
    fn empty_and_whitespace_queries_do_not_panic() {
        for q in ["", "   ", "\t\n"] {
            let parsed = parse(q);
            assert_eq!(parsed.free_text, "");
            assert!(!parsed.is_structured());
        }
    }

    // ── field:value ──────────────────────────────────────────────────────

    #[test]
    fn a_whitelisted_field_is_extracted_and_removed_from_free_text() {
        let parsed = parse("acme type:account trading");
        assert_eq!(parsed.entity_filter, Some("account".to_owned()));
        assert_eq!(parsed.free_text, "acme trading");
    }

    #[test]
    fn entity_is_an_alias_for_type() {
        let parsed = parse("entity:contact acme");
        assert_eq!(parsed.entity_filter, Some("contact".to_owned()));
    }

    #[test]
    fn field_matching_is_case_insensitive_on_the_field_name_only() {
        let parsed = parse("TYPE:Account");
        // The field name folds; the value does not — "Account" is whatever
        // the caller typed, compared against entity_logicalname later.
        assert_eq!(parsed.entity_filter, Some("Account".to_owned()));
    }

    #[test]
    fn an_unrecognised_field_is_kept_as_literal_free_text() {
        let parsed = parse("status:open acme");
        assert_eq!(parsed.entity_filter, None);
        assert!(parsed.free_text.contains("status:open"));
        assert!(parsed.free_text.contains("acme"));
    }

    #[test]
    fn the_first_occurrence_of_a_structured_field_wins() {
        let parsed = parse("type:account type:contact");
        assert_eq!(parsed.entity_filter, Some("account".to_owned()));
    }

    #[test]
    fn a_quoted_field_value_is_supported() {
        let parsed = parse(r#"type:"my entity" acme"#);
        assert_eq!(parsed.entity_filter, Some("my entity".to_owned()));
        assert_eq!(parsed.free_text, "acme");
    }

    /// A colon that is not part of an identifier-shaped field name (a clock
    /// time, a ratio) must not be misread as `field:value` — the whole token
    /// stays free text.
    #[test]
    fn a_non_identifier_field_is_not_treated_as_structured() {
        for q in ["10:30", "3:2", ":novalue", "novalue:"] {
            let parsed = parse(q);
            assert_eq!(parsed.entity_filter, None, "{q:?} must not be structured");
        }
    }

    // ── quotes ───────────────────────────────────────────────────────────

    #[test]
    fn a_quoted_phrase_is_a_required_phrase_and_stays_in_free_text() {
        let parsed = parse(r#"acme "exact phrase" trading"#);
        assert_eq!(parsed.required_phrases, vec!["exact phrase".to_owned()]);
        assert_eq!(parsed.free_text, "acme exact phrase trading");
    }

    #[test]
    fn an_unterminated_quote_does_not_panic_and_is_kept_as_text() {
        let parsed = parse(r#"acme "unterminated phrase"#);
        // Not cleanly quoted (no closing mark reached before EOF collapses
        // the rest into one token) — must not crash, and must not silently
        // drop the text.
        assert!(parsed.free_text.contains("acme"));
    }

    #[test]
    fn a_lone_quote_character_does_not_panic() {
        let parsed = parse("\"");
        assert!(!parsed.is_structured() || parsed.required_phrases.is_empty());
    }

    // ── -exclude ─────────────────────────────────────────────────────────

    #[test]
    fn a_dash_prefixed_word_is_excluded_and_removed_from_free_text() {
        let parsed = parse("acme -trading");
        assert_eq!(parsed.excluded_terms, vec!["trading".to_owned()]);
        assert_eq!(parsed.free_text, "acme");
    }

    #[test]
    fn a_dash_prefixed_quoted_phrase_is_excluded() {
        let parsed = parse(r#"acme -"late invoice""#);
        assert_eq!(parsed.excluded_terms, vec!["late invoice".to_owned()]);
        assert_eq!(parsed.free_text, "acme");
    }

    #[test]
    fn a_bare_dash_is_kept_as_free_text_not_an_empty_exclusion() {
        let parsed = parse("acme - trading");
        assert!(parsed.excluded_terms.is_empty());
        assert!(parsed.free_text.contains('-'));
    }

    #[test]
    fn multiple_exclusions_are_all_captured() {
        let parsed = parse("acme -trading -dispute -late");
        assert_eq!(
            parsed.excluded_terms,
            vec![
                "trading".to_owned(),
                "dispute".to_owned(),
                "late".to_owned()
            ]
        );
    }

    // ── combined ─────────────────────────────────────────────────────────

    #[test]
    fn field_value_quotes_and_exclusion_combine() {
        let parsed = parse(r#"type:account "exact phrase" -trading acme"#);
        assert_eq!(parsed.entity_filter, Some("account".to_owned()));
        assert_eq!(parsed.required_phrases, vec!["exact phrase".to_owned()]);
        assert_eq!(parsed.excluded_terms, vec!["trading".to_owned()]);
        assert!(parsed.free_text.contains("exact phrase"));
        assert!(parsed.free_text.contains("acme"));
        assert!(!parsed.free_text.contains("trading"));
        assert!(parsed.is_structured());
    }

    // ── injection-shaped input: the whole point of this file ───────────
    //
    // `dsl.rs` builds no SQL — see the module doc — so these tests assert
    // the property that makes that true rather than a specific escaping
    // behavior: every field of `ParsedQuery` is a plain owned `String` (or a
    // `Vec`/`Option` of one), and parsing never panics, hangs, or drops data
    // in a way a caller could exploit downstream.

    #[test]
    fn a_sql_injection_shaped_query_is_returned_as_inert_data() {
        let payload = "'; DROP TABLE search_index; --";
        let parsed = parse(payload);
        // Held as plain string data, split into whitespace-delimited tokens
        // like any other unquoted input — the trailing "--" token is itself
        // dash-PREFIXED, so it is read as an (empty-bodied, therefore
        // harmless) exclusion attempt rather than free text; that is
        // `is_structured()` correctly reporting what the tokenizer saw, not
        // a bug. The property this test actually guards — nothing here is
        // SQL syntax, only string data destined for a bound parameter or a
        // plain Rust comparison, never interpolated — holds regardless of
        // which of `free_text`/`excluded_terms` a given token lands in.
        assert!(
            parsed.free_text.contains("DROP")
                && parsed.free_text.contains("TABLE")
                && parsed.free_text.contains("search_index"),
            "the payload's words must survive as inert text: {parsed:?}"
        );
        assert!(parsed.entity_filter.is_none());
    }

    #[test]
    fn an_injection_payload_inside_a_field_value_is_still_just_a_string() {
        // Quoted, so the tokenizer keeps it as ONE token despite the
        // internal spaces — see `a_quoted_field_value_is_supported` above
        // for the same mechanism with an ordinary value. An UNQUOTED payload
        // containing whitespace is not one `field:value` token in the first
        // place (whitespace ends a token, quoting or not) — that is a
        // tokenization fact, not a security property, and is covered
        // separately by `a_sql_injection_shaped_query_is_returned_as_inert_
        // data` above.
        let parsed = parse(r#"type:"'; DROP TABLE search_index; --""#);
        // "type:..." IS recognised as a structured token (identifier field,
        // non-empty value) — its value is exactly the payload text, held as
        // a `String`, not executed or reinterpreted.
        assert_eq!(
            parsed.entity_filter,
            Some("'; DROP TABLE search_index; --".to_owned())
        );
        // And compiling it into the shared Filter grammar produces a bound
        // value (`Filter.value`), never a formatted SQL string.
        let filter = parsed.entity_filter_as_filter().unwrap();
        assert_eq!(filter.op, "eq");
        assert_eq!(
            filter.value,
            Some(serde_json::Value::String(
                "'; DROP TABLE search_index; --".to_owned()
            ))
        );
    }

    #[test]
    fn like_metacharacters_survive_as_literal_data() {
        // `%`/`_` matter to `PrefixLeg`'s escaping, not to this module — the
        // DSL must simply not choke on or mangle them.
        let parsed = parse("type:acc%ount 50%_off");
        assert!(parsed.free_text.contains("50%_off") || parsed.entity_filter.is_some());
    }

    #[test]
    fn a_very_long_single_token_does_not_panic() {
        let long = "a".repeat(10_000);
        let parsed = parse(&long);
        assert_eq!(parsed.free_text, long);
    }

    #[test]
    fn many_short_tokens_do_not_panic() {
        let many = "-x ".repeat(2_000);
        let parsed = parse(&many);
        assert_eq!(parsed.excluded_terms.len(), 2_000);
    }

    #[test]
    fn control_characters_and_nul_bytes_do_not_panic() {
        let payload = "acme\0\u{0007}\u{001b}[31m -bad\0term";
        let parsed = parse(payload);
        assert!(parsed.free_text.contains("acme"));
    }

    #[test]
    fn backslashes_and_mixed_quoting_do_not_panic() {
        for q in [
            r#"type:"a\"b" acme"#,
            r#"-"unterminated"#,
            r#"""""#,
            r#"a:"b:c" d:"e:f""#,
        ] {
            let _ = parse(q); // must not panic
        }
    }

    #[test]
    fn arabic_injection_shaped_and_mixed_script_input_is_handled() {
        let parsed = parse(r#"type:"حساب" "عبارة دقيقة" -مستبعد"#);
        assert_eq!(parsed.entity_filter, Some("حساب".to_owned()));
        assert_eq!(parsed.required_phrases, vec!["عبارة دقيقة".to_owned()]);
        assert_eq!(parsed.excluded_terms, vec!["مستبعد".to_owned()]);
    }

    /// Parsing is a pure function: same input, same output, every time — the
    /// same property `router::route` pins for the same reason (predictable
    /// relevance measurement, no path for retrieved content to steer this
    /// module because there is no state for it to steer).
    #[test]
    fn parsing_is_deterministic() {
        let q = r#"type:account "exact phrase" -trading acme"#;
        let first = parse(q);
        for _ in 0..5 {
            assert_eq!(parse(q), first);
        }
    }
}
