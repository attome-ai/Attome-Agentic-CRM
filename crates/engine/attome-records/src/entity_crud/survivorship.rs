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
//!
//! L1-T3: [`SourceSystemRank`] (`source_system_rank`, its trust per source
//! system per attribute in the rule's `config`) chooses among a golden
//! record's source contributions ([`SourceSystemRank::choose`]). A merge of
//! two records carries no source systems, so there it fills like
//! `most_complete`.

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
    /// L1-T3: see [`SourceSystemRank`].
    SourceSystemRank,
}

impl Strategy {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "most_recent" => Some(Self::MostRecent),
            "most_complete" => Some(Self::MostComplete),
            "source_priority" => Some(Self::SourcePriority),
            "manual" => Some(Self::Manual),
            "source_system_rank" => Some(Self::SourceSystemRank),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SurvivorshipRule {
    pub strategy: Strategy,
    pub priority_owner_ids: Vec<Uuid>,
    /// L1-T3: a `source_system_rank` rule's trust order.
    #[allow(
        dead_code,
        reason = "read by the contribution path, not by a two-record merge"
    )]
    pub source_system_rank: Option<SourceSystemRank>,
}

/// L1-T3: how a `source_system_rank` rule breaks a tie between two
/// contributions from equally trusted systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TieBreak {
    /// The newer contribution wins.
    Recency,
    /// The contribution with more filled values wins, then the newer.
    Completeness,
}

/// L1-T3: trust per source system per attribute (`config` of a
/// `source_system_rank` survivorship rule):
/// `{"ranks": {"billing_address": ["erp", "crm"], "*": ["crm"]},
///   "tie_break": "recency" | "completeness", "validated_only": true}`.
/// An attribute without its own list uses `"*"`; a system on no list ranks
/// after every listed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSystemRank {
    pub ranks: Vec<(String, Vec<String>)>,
    pub tie_break: TieBreak,
    pub validated_only: bool,
}

/// L1-T3: one source system's contribution to a golden record (a row of
/// the master entity's `<entity>__contribution`).
#[derive(Debug, Clone, PartialEq)]
pub struct Contribution {
    pub id: Uuid,
    pub system: String,
    pub received_at: chrono::DateTime<chrono::Utc>,
    pub payload: Map<String, Value>,
    /// It passed its source's validation (attached, not held).
    pub validated: bool,
}

/// The rule name a choice is recorded under (`<entity>__provenance.rule`).
pub const SOURCE_SYSTEM_RANK: &str = "source_system_rank";

fn filled(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::String(s) => !s.trim().is_empty(),
        _ => true,
    }
}

impl SourceSystemRank {
    /// Reads and checks a rule's `config`.
    pub fn from_config(config: &Value) -> Result<Self, String> {
        let ranks_v = config
            .get("ranks")
            .and_then(Value::as_object)
            .ok_or("config.ranks is an object of attribute to its systems, most trusted first")?;
        if ranks_v.is_empty() {
            return Err("config.ranks names at least one attribute (or \"*\")".into());
        }
        let mut ranks = Vec::with_capacity(ranks_v.len());
        for (attribute, systems) in ranks_v {
            let systems = systems
                .as_array()
                .ok_or_else(|| format!("config.ranks.{attribute} is a list of systems"))?;
            let mut names = Vec::with_capacity(systems.len());
            for s in systems {
                let name = s
                    .as_str()
                    .map(str::trim)
                    .filter(|n| !n.is_empty() && n.len() <= 200)
                    .ok_or_else(|| format!("config.ranks.{attribute} holds system names"))?;
                if names.iter().any(|n: &String| n == name) {
                    return Err(format!("config.ranks.{attribute} lists {name} twice"));
                }
                names.push(name.to_owned());
            }
            if names.is_empty() {
                return Err(format!(
                    "config.ranks.{attribute} names at least one system"
                ));
            }
            ranks.push((attribute.clone(), names));
        }
        let tie_break = match config.get("tie_break").and_then(Value::as_str) {
            None | Some("recency") => TieBreak::Recency,
            Some("completeness") => TieBreak::Completeness,
            Some(other) => {
                return Err(format!(
                    "config.tie_break is recency or completeness, not {other}"
                ));
            }
        };
        let validated_only = match config.get("validated_only") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err("config.validated_only is true or false".into()),
        };
        Ok(Self {
            ranks,
            tie_break,
            validated_only,
        })
    }

    fn systems_for(&self, attribute: &str) -> &[String] {
        self.ranks
            .iter()
            .find(|(a, _)| a == attribute)
            .or_else(|| self.ranks.iter().find(|(a, _)| a == "*"))
            .map(|(_, s)| s.as_slice())
            .unwrap_or(&[])
    }

    /// The value `attribute` takes from `contributions`: the most trusted
    /// system's filled value, ties broken by [`TieBreak`], unvalidated ones
    /// skipped when `validated_only`. The value, the contribution it came
    /// from and the rule. Pure.
    pub fn choose<'a>(
        &self,
        attribute: &str,
        contributions: &'a [Contribution],
    ) -> Option<(&'a Value, Uuid, &'static str)> {
        let systems = self.systems_for(attribute);
        let rank = |c: &Contribution| {
            systems
                .iter()
                .position(|s| s.eq_ignore_ascii_case(&c.system))
                .unwrap_or(usize::MAX)
        };
        let completeness = |c: &Contribution| c.payload.values().filter(|v| filled(v)).count();
        contributions
            .iter()
            .filter(|c| !self.validated_only || c.validated)
            .filter_map(|c| {
                c.payload
                    .get(attribute)
                    .filter(|v| filled(v))
                    .map(|v| (c, v))
            })
            .min_by(|(a, _), (b, _)| {
                rank(a).cmp(&rank(b)).then_with(|| match self.tie_break {
                    TieBreak::Recency => b.received_at.cmp(&a.received_at),
                    TieBreak::Completeness => completeness(b)
                        .cmp(&completeness(a))
                        .then_with(|| b.received_at.cmp(&a.received_at)),
                })
            })
            .map(|(c, v)| (v, c.id, SOURCE_SYSTEM_RANK))
    }
}

/// L1-T3: checks a survivorship rule's `config` for its strategy: required
/// and well formed for `source_system_rank`, absent for the others.
pub fn check_rule_config(strategy: &str, config: Option<&Value>) -> Result<(), String> {
    match (strategy, config) {
        ("source_system_rank", Some(c)) => SourceSystemRank::from_config(c).map(|_| ()),
        ("source_system_rank", None) => Err("a source_system_rank rule needs config.ranks".into()),
        (_, None | Some(Value::Null)) => Ok(()),
        (other, Some(_)) => Err(format!("a {other} rule takes no config")),
    }
}

/// Loads every active `survivorship_rule` row for `entity_name`,
/// keyed by field logicalname. A field with no row falls back to
/// [`Strategy::MostComplete`] in [`compute_fill`] — see this module's doc
/// comment.
pub(crate) async fn load_survivorship_rules(
    db: &attome_db::DbPool,
    entity_name: &str,
) -> Result<HashMap<String, SurvivorshipRule>, AppError> {
    type RuleRow = (String, String, Option<Vec<Uuid>>, Option<Value>);
    let rows: Vec<RuleRow> = sqlx::query_as(attome_db::tagged_sql!(
        "entity.survivorship",
        "SELECT field_logicalname, strategy, priority_owner_ids, config \
           FROM survivorship_rule \
          WHERE entity_logicalname = $1 AND NOT is_deleted"
    ))
    .bind(entity_name)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut out = HashMap::with_capacity(rows.len());
    for (field, strategy, priority_owner_ids, config) in rows {
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
        let source_system_rank = match (strategy, config.as_ref()) {
            (Strategy::SourceSystemRank, Some(config)) => {
                match SourceSystemRank::from_config(config) {
                    Ok(rank) => Some(rank),
                    Err(problem) => {
                        tracing::warn!(
                            entity = entity_name,
                            field,
                            problem,
                            "invalid source_system_rank config — falling back to most_complete for this field"
                        );
                        continue;
                    }
                }
            }
            _ => None,
        };
        out.insert(
            field,
            SurvivorshipRule {
                strategy,
                priority_owner_ids: priority_owner_ids.unwrap_or_default(),
                source_system_rank,
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
            // L1-T3: two records carry no source systems to rank; the rank
            // decides among contributions (`SourceSystemRank::choose`).
            Strategy::MostComplete | Strategy::SourceSystemRank => {
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
    fn contribution(
        system: &str,
        minutes_ago: i64,
        validated: bool,
        payload: Value,
    ) -> Contribution {
        Contribution {
            id: Uuid::now_v7(),
            system: system.to_owned(),
            received_at: chrono::Utc::now() - chrono::Duration::minutes(minutes_ago),
            payload: payload.as_object().cloned().unwrap_or_default(),
            validated,
        }
    }

    fn rank(config: Value) -> SourceSystemRank {
        SourceSystemRank::from_config(&config).unwrap()
    }

    fn erp_and_crm() -> Vec<Contribution> {
        vec![
            contribution(
                "crm",
                1,
                true,
                serde_json::json!({"billing_address": "CRM street 1", "mobile": "+966500000001"}),
            ),
            contribution(
                "erp",
                60,
                true,
                serde_json::json!({"billing_address": "ERP road 9", "mobile": "+966500000009"}),
            ),
        ]
    }

    fn ranks() -> SourceSystemRank {
        rank(serde_json::json!({
            "ranks": {"billing_address": ["erp", "crm"], "mobile": ["crm", "erp"]}
        }))
    }

    #[test]
    fn source_system_rank_erp_wins_billing() {
        let all = erp_and_crm();
        let (value, from, rule) = ranks().choose("billing_address", &all).unwrap();
        assert_eq!(value, "ERP road 9", "ERP is trusted first, though older");
        assert_eq!(from, all[1].id);
        assert_eq!(rule, SOURCE_SYSTEM_RANK);
    }

    #[test]
    fn source_system_rank_crm_wins_mobile() {
        let all = erp_and_crm();
        let (value, from, _) = ranks().choose("mobile", &all).unwrap();
        assert_eq!(value, "+966500000001");
        assert_eq!(from, all[0].id);
        // An empty value from the trusted system does not win.
        let blank = vec![
            contribution("crm", 1, true, serde_json::json!({"mobile": " "})),
            contribution(
                "erp",
                5,
                true,
                serde_json::json!({"mobile": "+966500000009"}),
            ),
        ];
        assert_eq!(ranks().choose("mobile", &blank).unwrap().0, "+966500000009");
    }

    #[test]
    fn source_system_rank_recency_tie_break() {
        let r = rank(serde_json::json!({"ranks": {"*": ["erp"]}}));
        let two_erps = vec![
            contribution("erp", 30, true, serde_json::json!({"city": "Jeddah"})),
            contribution("erp", 2, true, serde_json::json!({"city": "Riyadh"})),
        ];
        assert_eq!(r.choose("city", &two_erps).unwrap().0, "Riyadh");
        let complete =
            rank(serde_json::json!({"ranks": {"*": ["erp"]}, "tie_break": "completeness"}));
        let fuller = vec![
            contribution("erp", 2, true, serde_json::json!({"city": "Riyadh"})),
            contribution(
                "erp",
                30,
                true,
                serde_json::json!({"city": "Jeddah", "street": "King Road", "zip": "21411"}),
            ),
        ];
        assert_eq!(complete.choose("city", &fuller).unwrap().0, "Jeddah");
        // Unlisted systems rank after listed ones.
        let unlisted = vec![
            contribution("legacy", 1, true, serde_json::json!({"city": "Dammam"})),
            contribution("erp", 90, true, serde_json::json!({"city": "Riyadh"})),
        ];
        assert_eq!(r.choose("city", &unlisted).unwrap().0, "Riyadh");
    }

    #[test]
    fn source_system_rank_skips_unvalidated() {
        let r = rank(
            serde_json::json!({"ranks": {"vat_number": ["erp", "crm"]}, "validated_only": true}),
        );
        let all = vec![
            contribution(
                "erp",
                1,
                false,
                serde_json::json!({"vat_number": "300000000000003"}),
            ),
            contribution(
                "crm",
                9,
                true,
                serde_json::json!({"vat_number": "311111111111113"}),
            ),
        ];
        assert_eq!(r.choose("vat_number", &all).unwrap().0, "311111111111113");
        let none_valid = vec![all[0].clone()];
        assert!(r.choose("vat_number", &none_valid).is_none());
        assert!(SourceSystemRank::from_config(&serde_json::json!({"ranks": {}})).is_err());
        assert!(
            SourceSystemRank::from_config(&serde_json::json!({"ranks": {"a": ["x", "x"]}}))
                .is_err()
        );
        assert!(check_rule_config("source_system_rank", None).is_err());
        assert!(check_rule_config("most_recent", Some(&serde_json::json!({"ranks": {}}))).is_err());
        assert!(check_rule_config("most_recent", None).is_ok());
    }
}
