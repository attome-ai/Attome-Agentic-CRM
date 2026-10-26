//! Explaining a search result and its rank (roadmap A25-T4).
//!
//! With `explain=true`, a caller who builds or tunes the deployment (an
//! administrator, or a holder of `metadata.read`) gets each result's
//! [`ScoreParts`]: what each leg contributed to the fused rank (the fused
//! statement's per-leg counts), the fused score, what the entity boost and
//! the personal additions added, whether a pin placed it, and the synonyms
//! the query ran with. The parts add up to the score shown. Everyone else
//! gets no explanation, and none is computed unless it was asked for.

use attome_server::security::SecurityContext;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

use crate::controls::{Personal, PersonalWeights};

/// The privilege besides administration that sees explanations.
pub const EXPLAIN_PRIVILEGE: &str = "metadata.read";

/// How one result came to its score.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct ScoreParts {
    /// The fused rank score from the legs, before any tuning.
    pub fused: f64,
    /// The entity's boost (1 changes nothing).
    pub boost: f64,
    /// What the boost added: `fused * (boost - 1)`.
    pub boost_added: f64,
    /// Added because the caller owns the record.
    pub owner: f64,
    /// Added because the caller opened it from a search lately.
    pub opened: f64,
    /// Added because a team of the caller's owns it.
    pub team: f64,
    /// Placed by a pin for this query.
    pub pinned: bool,
    /// The legs that matched, with the fused statement's per-leg values.
    pub legs: Vec<String>,
    #[schema(value_type = Object)]
    pub leg_values: Value,
    /// The synonyms the query also ran with.
    pub synonyms: Vec<String>,
    /// The score shown: `fused + boost_added + owner + opened + team`.
    pub score: f64,
}

/// Whether `ctx` may see explanations.
pub fn may_explain(ctx: &SecurityContext) -> bool {
    ctx.is_admin || ctx.privileges.contains(EXPLAIN_PRIVILEGE)
}

/// One result's parts, from its fused score and the tuning applied to it.
/// Pure.
#[allow(clippy::too_many_arguments)]
pub fn parts(
    fused: f64,
    boost: f64,
    personal: Option<&Personal>,
    weights: PersonalWeights,
    pinned: bool,
    legs: &[String],
    leg_values: &Value,
    synonyms: &[String],
) -> ScoreParts {
    let p = personal.copied().unwrap_or_default();
    let owner = if p.owned { weights.owner } else { 0.0 };
    let opened = if p.opened { weights.opened } else { 0.0 };
    let team = if p.team_owned { weights.team } else { 0.0 };
    let boost_added = fused * (boost - 1.0);
    ScoreParts {
        fused,
        boost,
        boost_added,
        owner,
        opened,
        team,
        pinned,
        legs: legs.to_vec(),
        leg_values: leg_values.clone(),
        synonyms: synonyms.to_vec(),
        score: fused + boost_added + owner + opened + team,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_parts_sum_to_score() {
        let weights = PersonalWeights {
            owner: 0.2,
            opened: 0.1,
            team: 0.05,
        };
        let personal = Personal {
            owned: true,
            opened: false,
            team_owned: true,
        };
        let p = parts(
            0.5,
            1.5,
            Some(&personal),
            weights,
            false,
            &["lexical".to_owned()],
            &serde_json::json!({"lexical": 1}),
            &["commercial registration".to_owned()],
        );
        // What `controls::rerank` computes: score * boost + additions.
        let reranked = 0.5 * 1.5 + 0.2 + 0.05;
        assert!((p.score - reranked).abs() < 1e-12, "{p:?}");
        assert!((p.fused + p.boost_added + p.owner + p.opened + p.team - p.score).abs() < 1e-12);
        assert_eq!(p.opened, 0.0);

        let plain = parts(0.3, 1.0, None, weights, false, &[], &Value::Null, &[]);
        assert_eq!(plain.boost_added, 0.0);
        assert!((plain.score - 0.3).abs() < 1e-12);
    }
}
