//! L6-T2: an entity profiled in one sampled scan.
//!
//! One `SELECT` reads every profiled attribute as text: the whole table up to
//! [`SAMPLE_TARGET`] rows (or when a full scan is asked), else a
//! `TABLESAMPLE SYSTEM` percentage aimed at that many rows. The rows stream
//! through one [`FieldStats`] per attribute, which counts nulls and blanks,
//! distinct values (exact up to [`DISTINCT_EXACT_LIMIT`], then reported as a
//! lower bound), the top values, and by kind: number min, max, mean,
//! median, percentiles, a ten-bucket histogram and IQR outliers; date
//! range; text length spread. The scan runs under a statement timeout.
//! A labelled attribute (personal, special category, masked) keeps only the
//! shapes of its values, as before (L6-T1). L6-T3: a text attribute also
//! reports its pattern shapes, the share matching its declared format and
//! the Arabic-aware measures (`super::patterns`).

use std::collections::HashMap;

use serde_json::{Value, json};

/// Rows a sampled profile aims at.
pub const SAMPLE_TARGET: i64 = 100_000;

/// Distinct values counted exactly before the count becomes a lower bound.
pub const DISTINCT_EXACT_LIMIT: usize = 100_000;

/// Most frequent values kept per attribute.
const TOP_VALUES: usize = 10;

/// Buckets of a number histogram.
const HISTOGRAM_BUCKETS: usize = 10;

/// How an attribute's values are summarised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Number,
    Date,
    Text,
    /// Booleans, lookups, lists: counts and top values only.
    Other,
}

impl FieldKind {
    /// From the attribute's SQL cast (`attome_records::entity_mutation::sql_cast`).
    pub fn of_cast(cast: &str) -> Self {
        match cast {
            "::numeric" => FieldKind::Number,
            "::timestamptz" => FieldKind::Date,
            "::boolean" | "::uuid" | "::text[]" | "::jsonb" => FieldKind::Other,
            _ => FieldKind::Text,
        }
    }
}

/// The sample percentage for a table of `rows` rows; `None` scans it all.
pub fn sample_percent(rows: i64, full_scan: bool) -> Option<f64> {
    if full_scan || rows <= SAMPLE_TARGET {
        return None;
    }
    Some((SAMPLE_TARGET as f64 * 100.0 / rows as f64).clamp(0.01, 100.0))
}

/// One attribute's running statistics.
#[derive(Debug)]
pub struct FieldStats {
    kind: FieldKind,
    rows: u64,
    nulls: u64,
    blanks: u64,
    counts: HashMap<String, u64>,
    distinct_capped: bool,
    numbers: Vec<f64>,
    lengths: Vec<usize>,
    min_text: Option<String>,
    max_text: Option<String>,
    patterns: Option<super::patterns::PatternStats>,
}

impl FieldStats {
    pub fn new(kind: FieldKind) -> Self {
        FieldStats {
            kind,
            rows: 0,
            nulls: 0,
            blanks: 0,
            counts: HashMap::new(),
            distinct_capped: false,
            numbers: Vec::new(),
            lengths: Vec::new(),
            min_text: None,
            max_text: None,
            patterns: None,
        }
    }

    /// L6-T3: also counts shapes and Arabic measures of every value.
    pub fn with_patterns(mut self, patterns: super::patterns::PatternStats) -> Self {
        self.patterns = Some(patterns);
        self
    }

    /// Adds one row's value (its text form, `None` for SQL null).
    pub fn push(&mut self, value: Option<&str>) {
        self.rows += 1;
        let Some(value) = value else {
            self.nulls += 1;
            return;
        };
        if value.trim().is_empty() {
            self.blanks += 1;
        }
        if let Some(patterns) = &mut self.patterns {
            patterns.push(value);
        }
        if let Some(count) = self.counts.get_mut(value) {
            *count += 1;
        } else if self.counts.len() < DISTINCT_EXACT_LIMIT {
            self.counts.insert(value.to_owned(), 1);
        } else {
            self.distinct_capped = true;
        }
        match self.kind {
            FieldKind::Number => {
                if let Ok(n) = value.parse::<f64>()
                    && n.is_finite()
                {
                    self.numbers.push(n);
                }
            }
            FieldKind::Text => self.lengths.push(value.chars().count()),
            FieldKind::Date | FieldKind::Other => {}
        }
        if matches!(self.kind, FieldKind::Date | FieldKind::Text) {
            if self.min_text.as_deref().is_none_or(|m| value < m) {
                self.min_text = Some(value.to_owned());
            }
            if self.max_text.as_deref().is_none_or(|m| value > m) {
                self.max_text = Some(value.to_owned());
            }
        }
    }

    /// The summary; `mask` turns every kept value into its shape.
    pub fn finish(mut self, field: &str, mask: impl Fn(&str) -> String, labelled: bool) -> Value {
        let keep = |v: &str| if labelled { mask(v) } else { v.to_owned() };
        let mut top: Vec<(&String, &u64)> = self.counts.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let top_values: Vec<Value> = top
            .into_iter()
            .take(TOP_VALUES)
            .map(|(v, n)| json!({ "value": keep(v), "count": n }))
            .collect();
        let null_pct = if self.rows > 0 {
            self.nulls as f64 * 100.0 / self.rows as f64
        } else {
            0.0
        };
        let mut out = json!({
            "field": field,
            "rows": self.rows,
            "null_pct": null_pct,
            "nulls": self.nulls,
            "blanks": self.blanks,
            "distinct_count": self.counts.len(),
            "distinct_is_lower_bound": self.distinct_capped,
            "top_values": top_values,
            "masked": labelled,
        });
        match self.kind {
            FieldKind::Number if !self.numbers.is_empty() => {
                self.numbers.sort_by(f64::total_cmp);
                out["number"] = number_summary(&self.numbers);
            }
            FieldKind::Text if !self.lengths.is_empty() => {
                self.lengths.sort_unstable();
                let n = self.lengths.len();
                let mean = self.lengths.iter().sum::<usize>() as f64 / n as f64;
                out["length"] = json!({
                    "min": self.lengths[0],
                    "max": self.lengths[n - 1],
                    "mean": mean,
                    "median": self.lengths[n / 2],
                });
                out["min"] = self.min_text.as_deref().map(keep).into();
                out["max"] = self.max_text.as_deref().map(keep).into();
            }
            FieldKind::Date => {
                out["date_range"] = json!({
                    "earliest": self.min_text.as_deref().map(keep),
                    "latest": self.max_text.as_deref().map(keep),
                });
            }
            _ => {}
        }
        if let Some(patterns) = self.patterns.take() {
            out["patterns"] = patterns.finish();
        }
        out
    }
}

/// The value at quantile `q` of sorted `values` (nearest rank).
fn quantile(values: &[f64], q: f64) -> f64 {
    let rank = ((values.len() - 1) as f64 * q).round() as usize;
    values[rank.min(values.len() - 1)]
}

/// Min, max, mean, median, percentiles, histogram and outliers of sorted,
/// non-empty `values`.
pub fn number_summary(values: &[f64]) -> Value {
    let n = values.len();
    let (min, max) = (values[0], values[n - 1]);
    let mean = values.iter().sum::<f64>() / n as f64;
    let (q1, q3) = (quantile(values, 0.25), quantile(values, 0.75));
    let iqr = q3 - q1;
    let (low, high) = (q1 - 1.5 * iqr, q3 + 1.5 * iqr);
    let outliers = values.iter().filter(|v| **v < low || **v > high).count();
    let width = (max - min) / HISTOGRAM_BUCKETS as f64;
    let mut buckets = vec![0_u64; HISTOGRAM_BUCKETS];
    for v in values {
        let i = if width > 0.0 {
            (((v - min) / width) as usize).min(HISTOGRAM_BUCKETS - 1)
        } else {
            0
        };
        buckets[i] += 1;
    }
    json!({
        "min": min,
        "max": max,
        "mean": mean,
        "median": quantile(values, 0.5),
        "percentiles": {
            "p5": quantile(values, 0.05),
            "p25": q1,
            "p75": q3,
            "p95": quantile(values, 0.95),
        },
        "histogram": { "from": min, "bucket_width": width, "counts": buckets },
        "outliers": outliers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_scan_profiles_a_number_field() {
        let mut stats = FieldStats::new(FieldKind::Number);
        for v in ["1", "2", "2", "3", "100"] {
            stats.push(Some(v));
        }
        stats.push(None);
        let out = stats.finish("amount", |v| v.to_owned(), false);
        assert_eq!(out["rows"], 6);
        assert_eq!(out["nulls"], 1);
        assert_eq!(out["distinct_count"], 4);
        assert_eq!(out["top_values"][0]["value"], "2");
        assert_eq!(out["number"]["median"], 2.0);
        assert_eq!(out["number"]["max"], 100.0);
        assert_eq!(
            out["number"]["outliers"], 1,
            "100 lies past the upper fence"
        );
        let counts = out["number"]["histogram"]["counts"].as_array().unwrap();
        assert_eq!(counts.iter().map(|c| c.as_u64().unwrap()).sum::<u64>(), 5);
    }

    #[test]
    fn one_scan_profiles_text_blanks_lengths_and_masks() {
        let mut stats = FieldStats::new(FieldKind::Text);
        for v in ["ahmed@x.sa", " ", "sara@y.sa"] {
            stats.push(Some(v));
        }
        let out = stats.finish("email", |v| v.replace(char::is_alphanumeric, "A"), true);
        assert_eq!(out["blanks"], 1);
        assert_eq!(out["length"]["max"], 10);
        assert_eq!(out["masked"], true);
        assert!(
            out["top_values"]
                .as_array()
                .unwrap()
                .iter()
                .all(|t| !t["value"].as_str().unwrap().contains("ahmed")),
            "a labelled field keeps no value"
        );
    }

    #[test]
    fn one_scan_samples_large_tables_only() {
        assert_eq!(sample_percent(50_000, false), None);
        assert_eq!(sample_percent(10_000_000, true), None);
        let p = sample_percent(1_000_000, false).unwrap();
        assert!((p - 10.0).abs() < 1e-9);
        assert_eq!(FieldKind::of_cast("::numeric"), FieldKind::Number);
        assert_eq!(FieldKind::of_cast("::timestamptz"), FieldKind::Date);
        assert_eq!(FieldKind::of_cast(""), FieldKind::Text);
    }
}
