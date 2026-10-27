//! O1-T1: generic prediction model definitions: which entity, which
//! attribute to predict, the features, and the algorithm.
//!
//! ```json
//! { "entity": "opportunity", "target": "is_won", "algorithm": "logistic_regression",
//!   "min_rows": 300,
//!   "features": [
//!     { "attribute": "amount" },
//!     { "path": "account.industry" },
//!     { "time": "created_at", "part": "month" },
//!     { "rollup": "activity", "via": "opportunity_ref", "func": "count", "alias": "touches" } ] }
//! ```
//!
//! Features are never hand-written SQL: [`training_spec`] compiles the
//! attribute, lookup-path and time features into one QuerySpec, and
//! [`rollup_specs`] each rollup into a grouped QuerySpec over the child
//! entity, so the secured compiler (`attome_records::query_spec`) puts the
//! reader's record and field security into the SQL. Time features are
//! derived from the fetched value ([`time_feature`]). A model trains only
//! with at least [`ModelDef::min_rows`] labelled rows ([`check_rows`]).

use std::collections::BTreeSet;

use attome_core::FieldType;
use attome_types::AppError;
use serde::{Deserialize, Serialize};

/// Rows a model needs unless its definition asks for more.
pub const DEFAULT_MIN_ROWS: u32 = 200;
/// The fewest rows a definition may ask for.
pub const FLOOR_MIN_ROWS: u32 = 50;
/// Most features in one model.
pub const MAX_FEATURES: usize = 100;

/// How a model learns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    /// A yes/no or two-valued target.
    LogisticRegression,
    /// A yes/no or categorical target.
    RandomForest,
    /// A number target.
    LinearRegression,
}

/// A part of a date a time feature takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimePart {
    DayOfWeek,
    Month,
    Hour,
    /// Whole days from the value to the moment of scoring.
    AgeDays,
}

/// One feature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Feature {
    /// An attribute of the entity.
    Attribute { attribute: String },
    /// An attribute reached through lookups (`account.industry`).
    Path { path: String },
    /// A part of a date attribute.
    Time { time: String, part: TimePart },
    /// An aggregate over child records whose `via` lookup points at the row.
    Rollup {
        rollup: String,
        via: String,
        func: RollupFunc,
        #[serde(default)]
        field: Option<String>,
        alias: String,
    },
}

/// How a rollup aggregates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupFunc {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

/// A model definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelDef {
    pub entity: String,
    pub target: String,
    pub features: Vec<Feature>,
    pub algorithm: Algorithm,
    #[serde(default)]
    pub min_rows: Option<u32>,
}

impl ModelDef {
    /// The labelled rows this model needs before it trains.
    pub fn min_rows(&self) -> u32 {
        self.min_rows
            .unwrap_or(DEFAULT_MIN_ROWS)
            .max(FLOOR_MIN_ROWS)
    }
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Checks a definition against the metadata: `attr_type(entity, attribute)`
/// answers an attribute's field type, or `None` when there is no such
/// attribute. Paths are checked by shape only (the compiler checks each hop
/// with the reader's security). Answers every problem found.
pub fn validate(
    def: &ModelDef,
    attr_type: impl Fn(&str, &str) -> Option<FieldType>,
) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    if !identifier(&def.entity) {
        problems.push("entity is a logical name".to_owned());
    }
    match attr_type(&def.entity, &def.target) {
        None => problems.push(format!("{}.{} does not exist", def.entity, def.target)),
        Some(t) => {
            let numeric = matches!(t, FieldType::Number | FieldType::Currency);
            let categorical = matches!(t, FieldType::Bool | FieldType::Choice);
            let fits = match def.algorithm {
                Algorithm::LinearRegression => numeric,
                Algorithm::LogisticRegression => matches!(t, FieldType::Bool),
                Algorithm::RandomForest => categorical,
            };
            if !fits {
                problems.push(format!(
                    "{:?} cannot predict the {} attribute {}",
                    def.algorithm,
                    t.as_str(),
                    def.target
                ));
            }
        }
    }
    if def.features.is_empty() || def.features.len() > MAX_FEATURES {
        problems.push(format!("a model has 1 to {MAX_FEATURES} features"));
    }
    let mut names = BTreeSet::new();
    for feature in &def.features {
        let name = feature_name(feature);
        if !names.insert(name.clone()) {
            problems.push(format!("the feature {name} appears twice"));
        }
        if name == def.target {
            problems.push(format!("{name} is the target and cannot be a feature"));
        }
        match feature {
            Feature::Attribute { attribute } => {
                if attr_type(&def.entity, attribute).is_none() {
                    problems.push(format!("{}.{attribute} does not exist", def.entity));
                }
            }
            Feature::Path { path } => {
                let hops: Vec<&str> = path.split('.').collect();
                if hops.len() < 2 || hops.len() > 4 || !hops.iter().all(|h| identifier(h)) {
                    problems.push(format!("{path} is not a lookup path"));
                } else if attr_type(&def.entity, hops[0]) != Some(FieldType::Lookup) {
                    problems.push(format!("{}.{} is not a lookup", def.entity, hops[0]));
                }
            }
            Feature::Time { time, .. } => {
                if !attr_type(&def.entity, time).is_some_and(|t| t.is_temporal()) {
                    problems.push(format!("{}.{time} is not a date", def.entity));
                }
            }
            Feature::Rollup {
                rollup,
                via,
                func,
                field,
                alias,
            } => {
                if !identifier(alias) {
                    problems.push(format!("{alias} is not a usable feature name"));
                }
                if attr_type(rollup, via) != Some(FieldType::Lookup) {
                    problems.push(format!("{rollup}.{via} is not a lookup"));
                }
                match (func, field) {
                    (RollupFunc::Count, _) => {}
                    (_, Some(f)) => {
                        if !matches!(
                            attr_type(rollup, f),
                            Some(FieldType::Number | FieldType::Currency)
                        ) {
                            problems.push(format!("{rollup}.{f} is not a number"));
                        }
                    }
                    (_, None) => problems.push(format!("the rollup {alias} needs a field")),
                }
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// The column a feature arrives under.
pub fn feature_name(feature: &Feature) -> String {
    match feature {
        Feature::Attribute { attribute } => attribute.clone(),
        Feature::Path { path } => path.clone(),
        Feature::Time { time, part } => format!("{time}__{}", time_part_name(*part)),
        Feature::Rollup { alias, .. } => alias.clone(),
    }
}

fn time_part_name(part: TimePart) -> &'static str {
    match part {
        TimePart::DayOfWeek => "day_of_week",
        TimePart::Month => "month",
        TimePart::Hour => "hour",
        TimePart::AgeDays => "age_days",
    }
}

/// The QuerySpec of a model's rows: the id, the target and every
/// attribute, path and time-feature source, for rows whose target is set.
/// Paging (`cursor`, `page_size`) is the caller's.
pub fn training_spec(def: &ModelDef) -> attome_records::query_spec::QuerySpec {
    let mut select: Vec<String> = vec!["id".to_owned(), def.target.clone()];
    for feature in &def.features {
        let column = match feature {
            Feature::Attribute { attribute } => Some(attribute.clone()),
            Feature::Path { path } => Some(path.clone()),
            Feature::Time { time, .. } => Some(time.clone()),
            Feature::Rollup { .. } => None,
        };
        if let Some(column) = column
            && !select.contains(&column)
        {
            select.push(column);
        }
    }
    attome_records::query_spec::QuerySpec {
        entity: def.entity.clone(),
        select,
        r#where: Some(attome_records::query_spec::Condition::Compare {
            field: def.target.clone(),
            op: "is_not_null".into(),
            value: None,
        }),
        sort: vec![attome_records::query_spec::SortKey {
            field: "id".into(),
            desc: false,
        }],
        page_size: Some(attome_records::query_spec::compile::MAX_PAGE_SIZE),
        cursor: None,
        group_by: Vec::new(),
        aggregates: Vec::new(),
        having: None,
        explain: false,
        as_of: None,
        params: Default::default(),
        totals: None,
    }
}

/// One grouped QuerySpec per rollup feature: the child entity grouped by its
/// lookup to the model's entity, with the aggregate under the feature's
/// alias.
pub fn rollup_specs(def: &ModelDef) -> Vec<(String, attome_records::query_spec::QuerySpec)> {
    use attome_records::query_spec::{AggFunc, Aggregate, GroupKey, QuerySpec};
    def.features
        .iter()
        .filter_map(|feature| {
            let Feature::Rollup {
                rollup,
                via,
                func,
                field,
                alias,
            } = feature
            else {
                return None;
            };
            let func = match func {
                RollupFunc::Count => AggFunc::Count,
                RollupFunc::Sum => AggFunc::Sum,
                RollupFunc::Avg => AggFunc::Avg,
                RollupFunc::Min => AggFunc::Min,
                RollupFunc::Max => AggFunc::Max,
            };
            Some((
                alias.clone(),
                QuerySpec {
                    entity: rollup.clone(),
                    select: Vec::new(),
                    r#where: None,
                    sort: Vec::new(),
                    page_size: None,
                    cursor: None,
                    group_by: vec![GroupKey {
                        field: via.clone(),
                        bucket: None,
                    }],
                    aggregates: vec![Aggregate {
                        func,
                        field: if func == AggFunc::Count {
                            None
                        } else {
                            field.clone()
                        },
                        alias: alias.clone(),
                    }],
                    having: None,
                    explain: false,
                    as_of: None,
                    params: Default::default(),
                    totals: None,
                },
            ))
        })
        .collect()
}

/// A time feature's number from a date value (RFC 3339 or `YYYY-MM-DD`),
/// at `now` for `AgeDays`. Pure.
pub fn time_feature(
    part: TimePart,
    value: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<f64> {
    use chrono::{Datelike, Timelike};
    let at = chrono::DateTime::parse_from_rfc3339(value)
        .map(|d| d.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
                .map(|d| d.and_utc())
        })?;
    Some(match part {
        TimePart::DayOfWeek => f64::from(at.weekday().num_days_from_monday()),
        TimePart::Month => f64::from(at.month()),
        TimePart::Hour => f64::from(at.hour()),
        TimePart::AgeDays => (now - at).num_days() as f64,
    })
}

/// Refuses to train on fewer labelled rows than the model needs.
pub fn check_rows(def: &ModelDef, rows: usize) -> Result<(), AppError> {
    let needed = def.min_rows();
    if rows < needed as usize {
        Err(AppError::Validation(format!(
            "the model needs at least {needed} labelled rows of {} and has {rows}",
            def.entity
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn types(entity: &str, attribute: &str) -> Option<FieldType> {
        match (entity, attribute) {
            ("opportunity", "is_won") => Some(FieldType::Bool),
            ("opportunity", "amount") => Some(FieldType::Currency),
            ("opportunity", "stage") => Some(FieldType::Choice),
            ("opportunity", "account") => Some(FieldType::Lookup),
            ("opportunity", "created_at") => Some(FieldType::Date),
            ("activity", "opportunity_ref") => Some(FieldType::Lookup),
            ("activity", "minutes") => Some(FieldType::Number),
            _ => None,
        }
    }

    fn def() -> ModelDef {
        serde_json::from_value(json!({
            "entity": "opportunity", "target": "is_won", "algorithm": "logistic_regression",
            "features": [
                { "attribute": "amount" },
                { "path": "account.industry" },
                { "time": "created_at", "part": "month" },
                { "rollup": "activity", "via": "opportunity_ref", "func": "count", "alias": "touches" },
                { "rollup": "activity", "via": "opportunity_ref", "func": "sum", "field": "minutes", "alias": "minutes_spent" }
            ]
        }))
        .unwrap()
    }

    #[test]
    fn model_def_valid_definition_compiles_to_specs() {
        let d = def();
        assert_eq!(validate(&d, types), Ok(()));
        let spec = training_spec(&d);
        assert_eq!(spec.entity, "opportunity");
        assert_eq!(
            spec.select,
            vec!["id", "is_won", "amount", "account.industry", "created_at"]
        );
        assert!(matches!(
            spec.r#where,
            Some(attome_records::query_spec::Condition::Compare { ref op, .. }) if op == "is_not_null"
        ));
        let rollups = rollup_specs(&d);
        assert_eq!(rollups.len(), 2);
        assert_eq!(rollups[0].1.entity, "activity");
        assert_eq!(rollups[0].1.group_by[0].field, "opportunity_ref");
        assert_eq!(rollups[0].1.aggregates[0].field, None);
        assert_eq!(rollups[1].1.aggregates[0].field.as_deref(), Some("minutes"));
        assert_eq!(feature_name(&d.features[2]), "created_at__month");
    }

    #[test]
    fn model_def_refuses_what_does_not_fit() {
        let mut d = def();
        d.algorithm = Algorithm::LinearRegression;
        d.features.push(Feature::Attribute {
            attribute: "nope".into(),
        });
        d.features.push(Feature::Attribute {
            attribute: "amount".into(),
        });
        d.features.push(Feature::Time {
            time: "amount".into(),
            part: TimePart::Hour,
        });
        let problems = validate(&d, types).unwrap_err();
        assert!(
            problems.iter().any(|p| p.contains("cannot predict")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("opportunity.nope does not exist"))
        );
        assert!(problems.iter().any(|p| p.contains("appears twice")));
        assert!(problems.iter().any(|p| p.contains("is not a date")));

        let target_as_feature = ModelDef {
            features: vec![Feature::Attribute {
                attribute: "is_won".into(),
            }],
            ..def()
        };
        assert!(validate(&target_as_feature, types).is_err());
    }

    #[test]
    fn model_def_minimum_rows() {
        let d = def();
        assert_eq!(d.min_rows(), DEFAULT_MIN_ROWS);
        assert!(check_rows(&d, 199).is_err());
        assert!(check_rows(&d, 200).is_ok());
        let small = ModelDef {
            min_rows: Some(5),
            ..def()
        };
        assert_eq!(small.min_rows(), FLOOR_MIN_ROWS, "never below the floor");
    }

    #[test]
    fn model_def_time_features() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-25T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(
            time_feature(TimePart::Month, "2026-03-15T10:30:00Z", now),
            Some(3.0)
        );
        assert_eq!(
            time_feature(TimePart::DayOfWeek, "2026-10-26", now),
            Some(0.0),
            "a Monday"
        );
        assert_eq!(
            time_feature(TimePart::Hour, "2026-03-15T10:30:00Z", now),
            Some(10.0)
        );
        assert_eq!(
            time_feature(TimePart::AgeDays, "2026-10-15", now),
            Some(10.0)
        );
        assert_eq!(time_feature(TimePart::Month, "soon", now), None);
    }
}
