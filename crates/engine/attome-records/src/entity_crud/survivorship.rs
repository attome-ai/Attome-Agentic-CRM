//! D-432 / M13 (Master Data Management, scoped to dedup + survivorship only)
//! — the pure decision logic `merge.rs`'s `do_merge_core` applies once it has
//! both rows in hand, plus the one query that loads a rule set for an entity.
//! Kept as its own module (not inlined into `merge.rs`) so the decision table
//! itself — the part most likely to be reviewed/extended in isolation — is
//! readable without the surrounding transaction/authorization machinery, and
//! so [`compute_fill`] can be unit-tested as a pure function with no database.
//!
//! An entity with zero configured rules merges exactly as it did before this
//! module existed: `Strategy::MostComplete` (the implicit default below) is
//! the same "canonical wins outright, the duplicate only fills a null/absent
//! canonical value" behavior `merge.rs` always had.

use attome_core::AttrInfo;
use attome_types::AppError;
use serde_json::{Map, Value};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Strategy {
    MostRecent,
    MostComplete,
    SourcePriority,
    Manual,
}

impl Strategy {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "most_recent" => Some(Self::MostRecent),
            "most_complete" => Some(Self::MostComplete),
            "source_priority" => Some(Self::SourcePriority),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SurvivorshipRule {
    pub strategy: Strategy,
    pub priority_owner_ids: Vec<Uuid>,
}

/// Loads every active `survivorship_rule` row for `entity_name`,
/// keyed by field logicalname. A field with no row falls back to
/// [`Strategy::MostComplete`] in [`compute_fill`] — see this module's doc
/// comment.
pub(crate) async fn load_survivorship_rules(
    db: &attome_db::DbPool,
    entity_name: &str,
) -> Result<HashMap<String, SurvivorshipRule>, AppError> {
    let rows: Vec<(String, String, Option<Vec<Uuid>>)> = sqlx::query_as(
        "SELECT field_logicalname, strategy, priority_owner_ids \
           FROM survivorship_rule \
          WHERE entity_logicalname = $1 AND NOT is_deleted",
    )
    .bind(entity_name)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut out = HashMap::with_capacity(rows.len());
    for (field, strategy, priority_owner_ids) in rows {
        // The CHECK constraint (migration 0219) already restricts `strategy`
        // to the four known values — an unrecognized value here would mean
        // this binary predates a wider constraint a newer one wrote, so skip
        // it defensively (same "don't crash a merge over a row a rolling
        // deploy wrote" posture `ChangeOperation::parse` takes) rather than
        // failing the whole merge.
        let Some(strategy) = Strategy::parse(&strategy) else {
            tracing::warn!(
                entity = entity_name,
                field,
                strategy,
                "unrecognized survivorship strategy — falling back to most_complete for this field"
            );
            continue;
        };
        out.insert(
            field,
            SurvivorshipRule {
                strategy,
                priority_owner_ids: priority_owner_ids.unwrap_or_default(),
            },
        );
    }
    Ok(out)
}

/// A15-T10: a person's choice of source per field, applied over the
/// survivorship fill. `picks` maps a field to `"survivor"` (keep the
/// surviving record's value) or `"merged"` (take the merged record's value,
/// even an empty one). A picked field is no longer a conflict. A field that
/// is not a writable attribute of the entity (or a formula) is refused.
pub(crate) fn apply_picks(
    attrs: &[AttrInfo],
    canonical: &Map<String, Value>,
    duplicate: &Map<String, Value>,
    picks: &Map<String, Value>,
    fill: &mut Map<String, Value>,
    conflicts: &mut Vec<String>,
) -> Result<(), AppError> {
    for (field, source) in picks {
        let known = attrs
            .iter()
            .any(|a| &a.logicalname == field && !a.is_formula());
        if !known {
            return Err(AppError::Validation(format!(
                "picks: '{field}' is not a field this merge can set"
            )));
        }
        match source.as_str() {
            Some("survivor") => {
                fill.remove(field);
            }
            Some("merged") => {
                let value = duplicate.get(field).cloned().unwrap_or(Value::Null);
                if canonical.get(field).cloned().unwrap_or(Value::Null) == value {
                    fill.remove(field);
                } else {
                    fill.insert(field.clone(), value);
                }
            }
            _ => {
                return Err(AppError::Validation(format!(
                    "picks: '{field}' must be \"survivor\" or \"merged\""
                )));
            }
        }
        conflicts.retain(|c| c != field);
    }
    Ok(())
}

/// The `picks` object of a merge or merge-preview body (see [`apply_picks`]);
/// absent is no picks.
pub(crate) fn picks_of(body: &Value) -> Result<Map<String, Value>, AppError> {
    match body.get("picks") {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(picks)) => Ok(picks.clone()),
        Some(_) => Err(AppError::Validation("picks must be an object".into())),
    }
}

/// The decision itself. `canonical`/`duplicate` are the two rows' full
/// `row_to_json` objects (system columns included — `modified_at`/`owner_ref`
/// feed `MostRecent`/`SourcePriority`).
///
/// Returns `(fill, conflicts)`:
/// * `fill` — attribute values to splice into the canonical record's UPDATE,
///   same contract `merge.rs` already had (empty values are never inserted;
///   an attribute missing from `fill` means "leave the canonical row
///   unchanged").
/// * `conflicts` — field names a `Manual`-strategy rule could not decide
///   (both rows carry a non-null, differing value) — the canonical value is
///   left exactly as it was pre-merge, and the caller surfaces this list for
///   a steward to resolve by hand.
#[expect(
    clippy::expect_used,
    reason = "duplicate_present is only true when the value is Some"
)]
pub(crate) fn compute_fill(
    attrs: &[AttrInfo],
    canonical: &Map<String, Value>,
    duplicate: &Map<String, Value>,
    rules: &HashMap<String, SurvivorshipRule>,
) -> (Map<String, Value>, Vec<String>) {
    let mut fill = Map::new();
    let mut conflicts = Vec::new();

    // Lexicographic comparison is correct here because `row_to_json` always
    // renders a `timestamptz` in a fixed-width, fixed-offset ("+00")
    // ISO-8601 form — the same property `attome_core::change_feed`'s own
    // ordering leans on elsewhere in this codebase. `None` (column absent —
    // never true for a system column, but defensive) sorts as "never
    // modified", i.e. loses to any real timestamp.
    let canonical_modifiedon = canonical.get("modified_at").and_then(Value::as_str);
    let duplicate_modifiedon = duplicate.get("modified_at").and_then(Value::as_str);
    let duplicate_is_more_recent = match (canonical_modifiedon, duplicate_modifiedon) {
        (Some(c), Some(d)) => d > c,
        (None, Some(_)) => true,
        _ => false,
    };

    let canonical_owner = canonical.get("owner_ref").and_then(Value::as_str);
    let duplicate_owner = duplicate.get("owner_ref").and_then(Value::as_str);

    // A formula field (B-R6, D-604) is recomputed by the fill's own
    // `update_one`, never copied — and `validate_body` refuses a written
    // formula value, so copying one would fail the whole merge.
    for attr in attrs.iter().filter(|a| !a.is_formula()) {
        let canonical_val = canonical.get(&attr.logicalname);
        let duplicate_val = duplicate.get(&attr.logicalname);
        let canonical_present = canonical_val.is_some_and(|v| !v.is_null());
        let duplicate_present = duplicate_val.is_some_and(|v| !v.is_null());
        if !duplicate_present {
            // Nothing the duplicate can contribute to this field either way.
            continue;
        }
        let duplicate_val = duplicate_val.expect("duplicate_present implies Some");

        let strategy = rules
            .get(&attr.logicalname)
            .map(|r| r.strategy)
            .unwrap_or(Strategy::MostComplete);

        match strategy {
            Strategy::MostComplete => {
                if !canonical_present {
                    fill.insert(attr.logicalname.clone(), duplicate_val.clone());
                }
            }
            Strategy::MostRecent => {
                if !canonical_present || duplicate_is_more_recent {
                    fill.insert(attr.logicalname.clone(), duplicate_val.clone());
                }
            }
            Strategy::SourcePriority => {
                if !canonical_present {
                    fill.insert(attr.logicalname.clone(), duplicate_val.clone());
                    continue;
                }
                let rule = rules.get(&attr.logicalname);
                let priority = rule.map(|r| r.priority_owner_ids.as_slice()).unwrap_or(&[]);
                let rank_of = |owner: Option<&str>| -> Option<usize> {
                    let owner = Uuid::parse_str(owner?).ok()?;
                    priority.iter().position(|id| *id == owner)
                };
                let canonical_rank = rank_of(canonical_owner);
                let duplicate_rank = rank_of(duplicate_owner);
                let duplicate_wins = match (canonical_rank, duplicate_rank) {
                    (Some(c), Some(d)) => d < c,
                    (None, Some(_)) => true,
                    _ => false,
                };
                if duplicate_wins {
                    fill.insert(attr.logicalname.clone(), duplicate_val.clone());
                }
            }
            Strategy::Manual => {
                if !canonical_present {
                    fill.insert(attr.logicalname.clone(), duplicate_val.clone());
                } else if canonical_val != Some(duplicate_val) {
                    conflicts.push(attr.logicalname.clone());
                }
            }
        }
    }

    (fill, conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(name: &str) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int: 3,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            options: None,
        }
    }

    fn obj(pairs: &[(&str, Value)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    #[test]
    fn no_rule_at_all_fills_only_a_missing_canonical_value_most_complete_default() {
        let attrs = vec![attr("email"), attr("phone")];
        let canonical = obj(&[("email", Value::Null), ("phone", "555-1234".into())]);
        let duplicate = obj(&[("email", "a@b.com".into()), ("phone", "555-9999".into())]);
        let (fill, conflicts) = compute_fill(&attrs, &canonical, &duplicate, &HashMap::new());
        assert_eq!(fill.get("email"), Some(&Value::from("a@b.com")));
        // canonical already had a phone number — most_complete never overwrites it.
        assert!(!fill.contains_key("phone"));
        assert!(conflicts.is_empty());
    }

    #[test]
    fn most_recent_overwrites_an_older_canonical_value() {
        let attrs = vec![attr("phone")];
        let canonical = obj(&[
            ("phone", "555-1111".into()),
            ("modified_at", "2024-01-01T00:00:00+00:00".into()),
        ]);
        let duplicate = obj(&[
            ("phone", "555-2222".into()),
            ("modified_at", "2024-06-01T00:00:00+00:00".into()),
        ]);
        let mut rules = HashMap::new();
        rules.insert(
            "phone".to_owned(),
            SurvivorshipRule {
                strategy: Strategy::MostRecent,
                priority_owner_ids: vec![],
            },
        );
        let (fill, conflicts) = compute_fill(&attrs, &canonical, &duplicate, &rules);
        assert_eq!(fill.get("phone"), Some(&Value::from("555-2222")));
        assert!(conflicts.is_empty());
    }

    #[test]
    fn most_recent_keeps_a_newer_canonical_value() {
        let attrs = vec![attr("phone")];
        let canonical = obj(&[
            ("phone", "555-1111".into()),
            ("modified_at", "2024-06-01T00:00:00+00:00".into()),
        ]);
        let duplicate = obj(&[
            ("phone", "555-2222".into()),
            ("modified_at", "2024-01-01T00:00:00+00:00".into()),
        ]);
        let mut rules = HashMap::new();
        rules.insert(
            "phone".to_owned(),
            SurvivorshipRule {
                strategy: Strategy::MostRecent,
                priority_owner_ids: vec![],
            },
        );
        let (fill, _) = compute_fill(&attrs, &canonical, &duplicate, &rules);
        assert!(!fill.contains_key("phone"));
    }

    #[test]
    fn source_priority_prefers_the_higher_ranked_owner() {
        let team_a = Uuid::now_v7();
        let team_b = Uuid::now_v7();
        let attrs = vec![attr("phone")];
        let canonical = obj(&[
            ("phone", "555-1111".into()),
            ("owner_ref", team_b.to_string().into()),
        ]);
        let duplicate = obj(&[
            ("phone", "555-2222".into()),
            ("owner_ref", team_a.to_string().into()),
        ]);
        let mut rules = HashMap::new();
        rules.insert(
            "phone".to_owned(),
            SurvivorshipRule {
                strategy: Strategy::SourcePriority,
                priority_owner_ids: vec![team_a, team_b],
            },
        );
        let (fill, _) = compute_fill(&attrs, &canonical, &duplicate, &rules);
        // team_a (the duplicate's owner) ranks ahead of team_b (canonical's owner).
        assert_eq!(fill.get("phone"), Some(&Value::from("555-2222")));
    }

    #[test]
    fn manual_strategy_flags_a_genuine_disagreement_and_leaves_canonical_untouched() {
        let attrs = vec![attr("tax_id")];
        let canonical = obj(&[("tax_id", "111-22-3333".into())]);
        let duplicate = obj(&[("tax_id", "999-88-7777".into())]);
        let mut rules = HashMap::new();
        rules.insert(
            "tax_id".to_owned(),
            SurvivorshipRule {
                strategy: Strategy::Manual,
                priority_owner_ids: vec![],
            },
        );
        let (fill, conflicts) = compute_fill(&attrs, &canonical, &duplicate, &rules);
        assert!(
            !fill.contains_key("tax_id"),
            "manual must not silently pick a winner"
        );
        assert_eq!(conflicts, vec!["tax_id".to_owned()]);
    }

    #[test]
    fn manual_strategy_fills_a_genuinely_missing_canonical_value_with_no_conflict() {
        let attrs = vec![attr("tax_id")];
        let canonical = obj(&[("tax_id", Value::Null)]);
        let duplicate = obj(&[("tax_id", "999-88-7777".into())]);
        let mut rules = HashMap::new();
        rules.insert(
            "tax_id".to_owned(),
            SurvivorshipRule {
                strategy: Strategy::Manual,
                priority_owner_ids: vec![],
            },
        );
        let (fill, conflicts) = compute_fill(&attrs, &canonical, &duplicate, &rules);
        assert_eq!(fill.get("tax_id"), Some(&Value::from("999-88-7777")));
        assert!(conflicts.is_empty());
    }

    #[test]
    fn manual_strategy_agreeing_values_produce_no_fill_and_no_conflict() {
        let attrs = vec![attr("tax_id")];
        let canonical = obj(&[("tax_id", "111-22-3333".into())]);
        let duplicate = obj(&[("tax_id", "111-22-3333".into())]);
        let mut rules = HashMap::new();
        rules.insert(
            "tax_id".to_owned(),
            SurvivorshipRule {
                strategy: Strategy::Manual,
                priority_owner_ids: vec![],
            },
        );
        let (fill, conflicts) = compute_fill(&attrs, &canonical, &duplicate, &rules);
        assert!(fill.is_empty());
        assert!(conflicts.is_empty());
    }

    #[test]
    fn picks_override_the_fill_and_clear_conflicts() {
        let attrs = vec![attr("email"), attr("phone")];
        let canonical = obj(&[("email", Value::Null), ("phone", "555-1234".into())]);
        let duplicate = obj(&[("email", "a@b.com".into()), ("phone", "555-9999".into())]);
        let (mut fill, mut conflicts) =
            compute_fill(&attrs, &canonical, &duplicate, &HashMap::new());
        conflicts.push("phone".into());
        let picks = obj(&[("email", "survivor".into()), ("phone", "merged".into())]);
        apply_picks(
            &attrs,
            &canonical,
            &duplicate,
            &picks,
            &mut fill,
            &mut conflicts,
        )
        .expect("valid picks");
        assert!(!fill.contains_key("email"));
        assert_eq!(fill.get("phone"), Some(&Value::from("555-9999")));
        assert!(conflicts.is_empty());
    }

    #[test]
    fn a_pick_of_an_unknown_field_or_source_is_refused() {
        let attrs = vec![attr("email")];
        let empty = Map::new();
        let mut fill = Map::new();
        let mut conflicts = Vec::new();
        for picks in [
            obj(&[("nope", "merged".into())]),
            obj(&[("email", "both".into())]),
        ] {
            let refused = apply_picks(&attrs, &empty, &empty, &picks, &mut fill, &mut conflicts);
            assert!(matches!(refused, Err(AppError::Validation(_))));
        }
    }
}
