//! R14-T1: third-party risk: vendor questionnaires, answers and scores.
//!
//! The vendor-supplier pack's `0004` gives each `vendor` a `risk_tier`
//! (`critical`, `high`, `medium`, `low`), a `risk_rating` and its next
//! assessment date, and adds two entities:
//!
//! - `vendor_questionnaire`: a published survey (G14) named by its response
//!   entity, the tier it applies to (or `all`), and its scoring rules as
//!   JSON ([`Scoring`]);
//! - `vendor_assessment`: one questionnaire sent to one vendor, `sent` until
//!   answered, then `scored` with its points and rating (or `expired`).
//!
//! The questions go out through the survey engine: the questionnaire's
//! survey sends on `vendor_assessment.status = sent` to `contact_ref`, so
//! the vendor's contact gets the signed link G14-T2 already mails and
//! answers it once. Nothing here sends mail.
//!
//! The daily GRC sweep then, for each tiered, active vendor whose next
//! assessment is due (or that was never assessed) and has none open, opens
//! an assessment with the questionnaire for its tier (the tier's own before
//! an `all` one); scores every open assessment whose answers have arrived,
//! writes the rating onto the vendor and sets its next assessment by tier
//! ([`interval_days`]: the riskier the tier, the sooner); and expires
//! assessments unanswered after [`ANSWER_DAYS`]. Every write bumps the row
//! version and emits a change event, in one transaction per record. A
//! deployment without the pack's `0004` does nothing.
//!
//! Scoring rules, per question key of the survey:
//!
//! ```json
//! { "questions": {
//!     "iso27001":   { "type": "bool", "weight": 10 },
//!     "encryption": { "type": "choice", "points": { "full": 10, "partial": 5, "none": 0 } },
//!     "controls":   { "type": "multi_choice", "points": { "mfa": 4, "edr": 3, "backup": 3 } },
//!     "incidents":  { "type": "number", "weight": 10, "max": 5, "lower_is_better": true },
//!     "maturity":   { "type": "rating", "weight": 10, "scale": 5 } },
//!   "bands": { "low": 80, "medium": 60, "high": 40 } }
//! ```
//!
//! A question left unanswered scores nothing but still counts toward the
//! maximum, so skipping questions never improves a score. The percentage
//! falls into a band: at least `low` is low risk, at least `medium` medium,
//! at least `high` high, and below that critical (defaults 80, 60, 40).

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_core::change_feed::ChangeOperation;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::NaiveDate;
use serde_json::{Map, Value};
use uuid::Uuid;

/// Days a vendor has to answer before the assessment expires.
pub const ANSWER_DAYS: i64 = 60;
/// Most assessments opened or scored per sweep step.
const BATCH: i64 = 200;
/// Most questions a scoring document may rate.
pub const MAX_RULES: usize = 200;

/// A vendor's risk tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Critical,
    High,
    Medium,
    Low,
}

impl Tier {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "critical" => Some(Tier::Critical),
            "high" => Some(Tier::High),
            "medium" => Some(Tier::Medium),
            "low" => Some(Tier::Low),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Critical => "critical",
            Tier::High => "high",
            Tier::Medium => "medium",
            Tier::Low => "low",
        }
    }
}

/// Days between assessments for a tier: twice a year for critical, yearly
/// for high, every two years for medium and every three for low.
pub fn interval_days(tier: Tier) -> i64 {
    match tier {
        Tier::Critical => 182,
        Tier::High => 365,
        Tier::Medium => 730,
        Tier::Low => 1095,
    }
}

/// The next assessment date after one on `assessed_on`. Pure.
pub fn next_assessment(tier: Tier, assessed_on: NaiveDate) -> NaiveDate {
    assessed_on
        .checked_add_signed(chrono::Duration::days(interval_days(tier)))
        .unwrap_or(assessed_on)
}

/// A risk rating from a score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rating {
    Low,
    Medium,
    High,
    Critical,
}

impl Rating {
    pub fn as_str(self) -> &'static str {
        match self {
            Rating::Low => "low",
            Rating::Medium => "medium",
            Rating::High => "high",
            Rating::Critical => "critical",
        }
    }
}

/// How one question scores.
#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    /// `true` (or `expect`) earns `weight`.
    Bool { weight: f64, expect: bool },
    /// The chosen option earns its points.
    Choice { points: BTreeMap<String, f64> },
    /// Each chosen option earns its points; the maximum is every positive one.
    MultiChoice { points: BTreeMap<String, f64> },
    /// `weight` scaled by the answer against `max` (or by how far below it).
    Number {
        weight: f64,
        max: f64,
        lower_is_better: bool,
    },
    /// `weight` scaled by the rating out of `scale`.
    Rating { weight: f64, scale: f64 },
}

impl Rule {
    fn max(&self) -> f64 {
        match self {
            Rule::Bool { weight, .. }
            | Rule::Number { weight, .. }
            | Rule::Rating { weight, .. } => *weight,
            Rule::Choice { points } => points.values().copied().fold(0.0, f64::max),
            Rule::MultiChoice { points } => points.values().filter(|p| **p > 0.0).sum(),
        }
    }

    fn earned(&self, answer: Option<&Value>) -> f64 {
        let Some(answer) = answer.filter(|a| !a.is_null()) else {
            return 0.0;
        };
        let number = || match answer {
            Value::Number(n) => n.as_f64(),
            Value::String(s) => s.trim().parse().ok(),
            _ => None,
        };
        let earned = match self {
            Rule::Bool { weight, expect } => {
                let yes = match answer {
                    Value::Bool(b) => Some(*b),
                    Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                        "true" | "yes" | "on" => Some(true),
                        "false" | "no" | "off" => Some(false),
                        _ => None,
                    },
                    _ => None,
                };
                if yes == Some(*expect) { *weight } else { 0.0 }
            }
            Rule::Choice { points } => answer
                .as_str()
                .and_then(|s| points.get(s.trim()))
                .copied()
                .unwrap_or(0.0),
            Rule::MultiChoice { points } => {
                let chosen: Vec<&str> = match answer {
                    Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
                    Value::String(s) => s.split(',').collect(),
                    _ => Vec::new(),
                };
                let mut seen = std::collections::BTreeSet::new();
                chosen
                    .into_iter()
                    .map(str::trim)
                    .filter(|c| seen.insert(*c))
                    .filter_map(|c| points.get(c))
                    .sum()
            }
            Rule::Number {
                weight,
                max,
                lower_is_better,
            } => match number() {
                Some(n) if n.is_finite() => {
                    let share = (n / max).clamp(0.0, 1.0);
                    weight * if *lower_is_better { 1.0 - share } else { share }
                }
                _ => 0.0,
            },
            Rule::Rating { weight, scale } => match number() {
                Some(n) if n.is_finite() => weight * (n / scale).clamp(0.0, 1.0),
                _ => 0.0,
            },
        };
        earned.min(self.max())
    }
}

/// A questionnaire's scoring rules and rating bands.
#[derive(Debug, Clone, PartialEq)]
pub struct Scoring {
    pub rules: BTreeMap<String, Rule>,
    /// The lowest percentages for low, medium and high risk.
    pub bands: (f64, f64, f64),
}

fn positive(v: Option<&Value>, what: &str, key: &str) -> Result<f64, String> {
    let n = v
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("{key}: {what} is a number"))?;
    if n.is_finite() && n > 0.0 {
        Ok(n)
    } else {
        Err(format!("{key}: {what} is above zero"))
    }
}

fn points_of(rule: &Map<String, Value>, key: &str) -> Result<BTreeMap<String, f64>, String> {
    let points = rule
        .get("points")
        .and_then(Value::as_object)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| format!("{key}: points name each option's score"))?;
    points
        .iter()
        .map(|(option, p)| match p.as_f64() {
            Some(n) if n.is_finite() => Ok((option.clone(), n)),
            _ => Err(format!("{key}: the points for {option:?} are a number")),
        })
        .collect()
}

impl Scoring {
    /// Parses and checks a questionnaire's `scoring` text.
    pub fn parse(text: &str) -> Result<Self, String> {
        let doc: Value =
            serde_json::from_str(text).map_err(|e| format!("scoring is not JSON: {e}"))?;
        let questions = doc
            .get("questions")
            .and_then(Value::as_object)
            .filter(|q| !q.is_empty())
            .ok_or("scoring needs a non-empty \"questions\" object")?;
        if questions.len() > MAX_RULES {
            return Err(format!("scoring rates at most {MAX_RULES} questions"));
        }
        let mut rules = BTreeMap::new();
        for (key, rule) in questions {
            let rule = rule
                .as_object()
                .ok_or_else(|| format!("{key}: a rule is an object"))?;
            let parsed = match rule.get("type").and_then(Value::as_str) {
                Some("bool") => Rule::Bool {
                    weight: positive(rule.get("weight"), "weight", key)?,
                    expect: rule.get("expect").and_then(Value::as_bool).unwrap_or(true),
                },
                Some("choice") => Rule::Choice {
                    points: points_of(rule, key)?,
                },
                Some("multi_choice") => Rule::MultiChoice {
                    points: points_of(rule, key)?,
                },
                Some("number") => Rule::Number {
                    weight: positive(rule.get("weight"), "weight", key)?,
                    max: positive(rule.get("max"), "max", key)?,
                    lower_is_better: rule
                        .get("lower_is_better")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                },
                Some("rating") => Rule::Rating {
                    weight: positive(rule.get("weight"), "weight", key)?,
                    scale: rule
                        .get("scale")
                        .map(|s| positive(Some(s), "scale", key))
                        .transpose()?
                        .unwrap_or(5.0),
                },
                _ => {
                    return Err(format!(
                        "{key}: type is bool, choice, multi_choice, number or rating"
                    ));
                }
            };
            rules.insert(key.clone(), parsed);
        }
        if rules.values().map(Rule::max).sum::<f64>() <= 0.0 {
            return Err("scoring can earn no points".into());
        }
        let band = |name: &str, default: f64| -> Result<f64, String> {
            match doc.get("bands").and_then(|b| b.get(name)) {
                None => Ok(default),
                Some(v) => match v.as_f64() {
                    Some(n) if (0.0..=100.0).contains(&n) => Ok(n),
                    _ => Err(format!("bands.{name} is a percentage")),
                },
            }
        };
        let bands = (
            band("low", 80.0)?,
            band("medium", 60.0)?,
            band("high", 40.0)?,
        );
        if bands.0 < bands.1 || bands.1 < bands.2 {
            return Err("bands run low >= medium >= high".into());
        }
        Ok(Scoring { rules, bands })
    }

    /// The rating a percentage falls in.
    pub fn rating(&self, percent: f64) -> Rating {
        let (low, medium, high) = self.bands;
        if percent >= low {
            Rating::Low
        } else if percent >= medium {
            Rating::Medium
        } else if percent >= high {
            Rating::High
        } else {
            Rating::Critical
        }
    }

    /// Scores one set of answers (the response record, keyed by question).
    pub fn score(&self, answers: &Map<String, Value>) -> Scored {
        let max: f64 = self.rules.values().map(Rule::max).sum();
        let points: f64 = self
            .rules
            .iter()
            .map(|(key, rule)| rule.earned(answers.get(key)))
            .sum::<f64>()
            .max(0.0);
        let percent = if max > 0.0 {
            (points / max * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };
        let round = |n: f64| (n * 100.0).round() / 100.0;
        Scored {
            points: round(points),
            max: round(max),
            percent: round(percent),
            rating: self.rating(percent),
        }
    }
}

/// One scored assessment.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Scored {
    pub points: f64,
    pub max: f64,
    pub percent: f64,
    pub rating: Rating,
}

/// What one sweep did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TprmSweep {
    pub opened: u64,
    pub scored: u64,
    pub expired: u64,
    /// Answers whose questionnaire's scoring rules do not parse.
    pub unscorable: u64,
}

async fn installed(db: &DbPool) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT to_regclass('vendor_questionnaire') IS NOT NULL \
            AND to_regclass('vendor_assessment') IS NOT NULL \
            AND EXISTS (SELECT 1 FROM information_schema.columns \
                         WHERE table_schema = current_schema() AND table_name = 'vendor' \
                           AND column_name = 'next_assessment_on')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// `(vendor, vendor name, questionnaire, questionnaire name, contact)`.
type DueVendor = (Uuid, Option<String>, Uuid, String, Option<Uuid>);

/// Opens an assessment for every due vendor that has none open.
async fn open_due(db: &DbPool, today: NaiveDate) -> Result<u64, AppError> {
    let due: Vec<DueVendor> = sqlx::query_as(
        "SELECT v.id, v.name, q.id, q.name, v.contact_ref \
           FROM vendor v \
           JOIN LATERAL ( \
             SELECT id, name FROM vendor_questionnaire \
              WHERE status::text = 'active' AND is_active \
                AND applies_to_tier::text IN (v.risk_tier::text, 'all') \
              ORDER BY (applies_to_tier::text = 'all'), id LIMIT 1) q ON true \
          WHERE v.is_active AND v.risk_tier IS NOT NULL \
            AND COALESCE(v.lifecycle_status::text, 'active') IN ('active', 'onboarding') \
            AND (v.next_assessment_on::date <= $1 \
                 OR (v.next_assessment_on IS NULL AND v.last_assessed_on IS NULL)) \
            AND NOT EXISTS (SELECT 1 FROM vendor_assessment a \
                             WHERE a.vendor_ref = v.id AND a.is_active \
                               AND a.status::text = 'sent') \
          ORDER BY v.id LIMIT $2",
    )
    .bind(today)
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut opened = 0;
    for (vendor, vendor_name, questionnaire, questionnaire_name, contact) in due {
        if contact.is_none() {
            tracing::warn!(%vendor, "vendor assessment due but the vendor has no contact to answer it");
        }
        let name = format!(
            "{} - {questionnaire_name}",
            vendor_name.as_deref().unwrap_or("Vendor")
        );
        let mut tx = attome_db::tx::begin(db).await?;
        let id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO vendor_assessment \
               (name, vendor_ref, questionnaire_ref, contact_ref, status, sent_on) \
             SELECT $1, $2, $3, $4, 'sent', $5 \
              WHERE NOT EXISTS (SELECT 1 FROM vendor_assessment \
                                 WHERE vendor_ref = $2 AND is_active AND status::text = 'sent') \
             RETURNING id",
        )
        .bind(name.chars().take(200).collect::<String>())
        .bind(vendor)
        .bind(questionnaire)
        .bind(contact)
        .bind(today)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if let Some(id) = id {
            attome_core::change_feed::emit_tx(
                &mut tx,
                "vendor_assessment",
                id,
                ChangeOperation::Create,
            )
            .await?;
            opened += 1;
        }
        attome_db::tx::commit(tx).await?;
    }
    Ok(opened)
}

/// `(assessment, vendor, vendor tier, response entity, scoring)`.
type OpenAssessment = (Uuid, Uuid, Option<String>, String, String);

/// Scores open assessments whose answers have arrived.
async fn score_answered(
    state: &EngineState,
    today: NaiveDate,
    sweep: &mut TprmSweep,
) -> Result<(), AppError> {
    let db = &state.base.db;
    let open: Vec<OpenAssessment> = sqlx::query_as(
        "SELECT a.id, a.vendor_ref, v.risk_tier::text, q.response_entity, q.scoring \
           FROM vendor_assessment a \
           JOIN vendor_questionnaire q ON q.id = a.questionnaire_ref \
           JOIN vendor v ON v.id = a.vendor_ref \
          WHERE a.is_active AND a.status::text = 'sent' \
          ORDER BY a.id LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (assessment, vendor, tier, response_entity, scoring) in open {
        // The response entity comes from a record, so only a registered
        // entity's name ever reaches the SQL text.
        if state.entities.load().get(&response_entity).is_none() {
            continue;
        }
        let target = attome_core::quote_ident(&response_entity);
        let answers: Option<Value> = sqlx::query_scalar(&format!(
            "SELECT to_jsonb(r) FROM {target} r \
              WHERE r.regarding_entity = 'vendor_assessment' AND r.regarding_id = $1 \
                AND r.submitted_at IS NOT NULL \
              ORDER BY r.submitted_at DESC LIMIT 1"
        ))
        .bind(assessment.to_string())
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let Some(Value::Object(answers)) = answers else {
            continue;
        };
        let scoring = match Scoring::parse(&scoring) {
            Ok(scoring) => scoring,
            Err(error) => {
                tracing::warn!(%assessment, %error, "vendor assessment answered but its scoring rules do not parse");
                sweep.unscorable += 1;
                continue;
            }
        };
        let scored = scoring.score(&answers);
        let next = tier
            .as_deref()
            .and_then(Tier::parse)
            .map(|t| next_assessment(t, today));
        let mut tx = attome_db::tx::begin(db).await?;
        let claimed = sqlx::query(
            "UPDATE vendor_assessment SET status = 'scored', assessed_on = $2, \
                    score = $3::float8, max_score = $4::float8, score_percent = $5::float8, \
                    risk_rating = $6, row_version = row_version + 1, modified_at = now() \
              WHERE id = $1 AND status::text = 'sent'",
        )
        .bind(assessment)
        .bind(today)
        .bind(scored.points)
        .bind(scored.max)
        .bind(scored.percent)
        .bind(scored.rating.as_str())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if claimed == 0 {
            attome_db::tx::commit(tx).await?;
            continue;
        }
        sqlx::query(
            "UPDATE vendor SET risk_rating = $2, last_assessed_on = $3, \
                    next_assessment_on = COALESCE($4, next_assessment_on), \
                    row_version = row_version + 1, modified_at = now() \
              WHERE id = $1",
        )
        .bind(vendor)
        .bind(scored.rating.as_str())
        .bind(today)
        .bind(next)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_core::change_feed::emit_tx(
            &mut tx,
            "vendor_assessment",
            assessment,
            ChangeOperation::Update,
        )
        .await?;
        attome_core::change_feed::emit_tx(&mut tx, "vendor", vendor, ChangeOperation::Update)
            .await?;
        attome_db::tx::commit(tx).await?;
        sweep.scored += 1;
    }
    Ok(())
}

/// Expires assessments left unanswered for [`ANSWER_DAYS`].
async fn expire_unanswered(db: &DbPool, today: NaiveDate) -> Result<u64, AppError> {
    let before = today
        .checked_sub_signed(chrono::Duration::days(ANSWER_DAYS))
        .unwrap_or(today);
    let mut tx = attome_db::tx::begin(db).await?;
    let expired: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE vendor_assessment SET status = 'expired', row_version = row_version + 1, \
                modified_at = now() \
          WHERE status::text = 'sent' AND sent_on::date < $1 RETURNING id",
    )
    .bind(before)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for id in &expired {
        attome_core::change_feed::emit_tx(
            &mut tx,
            "vendor_assessment",
            *id,
            ChangeOperation::Update,
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(expired.len() as u64)
}

/// One day's third-party risk sweep.
pub async fn sweep(state: &EngineState, today: NaiveDate) -> Result<TprmSweep, AppError> {
    let db = &state.base.db;
    if !installed(db).await? {
        return Ok(TprmSweep::default());
    }
    let mut run = TprmSweep::default();
    score_answered(state, today, &mut run).await?;
    run.expired = expire_unanswered(db, today).await?;
    run.opened = open_due(db, today).await?;
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RULES: &str = r#"{ "questions": {
        "iso27001":   { "type": "bool", "weight": 10 },
        "encryption": { "type": "choice", "points": { "full": 10, "partial": 5, "none": 0 } },
        "controls":   { "type": "multi_choice", "points": { "mfa": 4, "edr": 3, "backup": 3 } },
        "incidents":  { "type": "number", "weight": 10, "max": 5, "lower_is_better": true },
        "maturity":   { "type": "rating", "weight": 10, "scale": 5 } },
      "bands": { "low": 80, "medium": 60, "high": 40 } }"#;

    fn answers(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn tprm_full_marks_and_low_risk() {
        let s = Scoring::parse(RULES).unwrap();
        let scored = s.score(&answers(json!({
            "iso27001": true, "encryption": "full", "controls": ["mfa", "edr", "backup"],
            "incidents": 0, "maturity": 5
        })));
        assert_eq!(scored.max, 50.0);
        assert_eq!(scored.points, 50.0);
        assert_eq!(scored.percent, 100.0);
        assert_eq!(scored.rating, Rating::Low);
    }

    #[test]
    fn tprm_partial_answers_and_bands() {
        let s = Scoring::parse(RULES).unwrap();
        // 0 + 5 + 4 + 10*(1-2/5)=6 + 10*3/5=6 = 21 of 50 = 42%: high risk.
        let scored = s.score(&answers(json!({
            "iso27001": "no", "encryption": "partial", "controls": "mfa, mfa",
            "incidents": "2", "maturity": 3
        })));
        assert_eq!(scored.points, 21.0);
        assert_eq!(scored.percent, 42.0);
        assert_eq!(scored.rating, Rating::High);
        assert_eq!(s.rating(80.0), Rating::Low);
        assert_eq!(s.rating(79.99), Rating::Medium);
        assert_eq!(s.rating(39.0), Rating::Critical);
    }

    #[test]
    fn tprm_unanswered_counts_against_the_vendor() {
        let s = Scoring::parse(RULES).unwrap();
        let scored = s.score(&answers(
            json!({ "iso27001": true, "encryption": "unknown" }),
        ));
        assert_eq!(scored.points, 10.0);
        assert_eq!(scored.percent, 20.0);
        assert_eq!(scored.rating, Rating::Critical);
        // Out-of-range numbers are clamped, never more than the weight.
        let scored = s.score(&answers(json!({ "incidents": -4, "maturity": 9 })));
        assert_eq!(scored.points, 20.0);
    }

    #[test]
    fn tprm_scoring_rules_are_checked() {
        assert!(Scoring::parse("not json").is_err());
        assert!(Scoring::parse(r#"{"questions": {}}"#).is_err());
        assert!(Scoring::parse(r#"{"questions": {"a": {"type": "bool"}}}"#).is_err());
        assert!(
            Scoring::parse(r#"{"questions": {"a": {"type": "choice", "points": {}}}}"#).is_err()
        );
        assert!(Scoring::parse(r#"{"questions": {"a": {"type": "text", "weight": 1}}}"#).is_err());
        assert!(
            Scoring::parse(r#"{"questions": {"a": {"type": "choice", "points": {"x": 0}}}}"#)
                .is_err(),
            "a questionnaire that earns nothing"
        );
        assert!(
            Scoring::parse(
                r#"{"questions": {"a": {"type": "bool", "weight": 1}}, "bands": {"low": 50, "medium": 70}}"#
            )
            .is_err()
        );
        let s = Scoring::parse(
            r#"{"questions": {"a": {"type": "bool", "weight": 1, "expect": false}}}"#,
        )
        .unwrap();
        assert_eq!(s.score(&answers(json!({"a": false}))).percent, 100.0);
        assert_eq!(s.bands, (80.0, 60.0, 40.0));
    }

    #[test]
    fn tprm_tier_drives_frequency() {
        assert!(interval_days(Tier::Critical) < interval_days(Tier::High));
        assert!(interval_days(Tier::High) < interval_days(Tier::Medium));
        assert!(interval_days(Tier::Medium) < interval_days(Tier::Low));
        assert_eq!(next_assessment(Tier::High, d(2026, 1, 1)), d(2027, 1, 1));
        assert_eq!(
            next_assessment(Tier::Critical, d(2026, 1, 1)),
            d(2026, 7, 2)
        );
        assert_eq!(Tier::parse(" medium "), Some(Tier::Medium));
        assert_eq!(Tier::parse("extreme"), None);
        assert_eq!(Tier::Low.as_str(), "low");
    }
}
