//! G6-T3: suggest the likely reply template for a case.
//!
//! Three signals, all explainable, none a model call:
//!
//! - **similar cases** — templates used on earlier records of the same
//!   entity whose indexed text matches this one (`reply_template_use`
//!   joined to the search index, ranked by `ts_rank`), weighted by how often;
//! - **wording** — how much of the template's own words (folder and body,
//!   normalised and stemmed like search) the case shares;
//! - **usage** — how often the template was used at all lately.
//!
//! The ranking here is pure; the route that gathers the signals is
//! `attome-api`'s `GET /api/v1/model/reply-suggestions`. Only templates the
//! person may see are ranked (their `visibility`).

use std::collections::{HashMap, HashSet};

use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// The most words of a case used to find similar cases.
pub const MAX_QUERY_TERMS: usize = 16;
/// The most suggestions returned.
pub const MAX_SUGGESTIONS: usize = 5;

/// Weights of the three signals; they sum to 1.
const SIMILAR_WEIGHT: f64 = 0.5;
const WORDING_WEIGHT: f64 = 0.3;
const USAGE_WEIGHT: f64 = 0.2;

/// Who is asking, for a template's `visibility`.
#[derive(Debug, Clone, Default)]
pub struct Viewer {
    pub user_id: Uuid,
    pub is_admin: bool,
    pub team_ids: Vec<Uuid>,
    pub role_ids: Vec<Uuid>,
    pub queue_ids: Vec<Uuid>,
}

/// Whether `viewer` may use the template `doc`. A template with no
/// visibility is for everyone. Pure.
pub fn visible(doc: &Value, viewer: &Viewer) -> bool {
    if viewer.is_admin {
        return true;
    }
    let scope = doc["visibility"]["scope"].as_str().unwrap_or("everyone");
    let named = doc["visibility"]["ref"]
        .as_str()
        .and_then(|r| Uuid::parse_str(r).ok());
    match (scope, named) {
        ("everyone", _) => true,
        ("user", Some(id)) => id == viewer.user_id,
        ("team", Some(id)) => viewer.team_ids.contains(&id),
        ("role", Some(id)) => viewer.role_ids.contains(&id),
        ("queue", Some(id)) => viewer.queue_ids.contains(&id),
        _ => false,
    }
}

/// Text normalised and stemmed exactly as the search index stores it, so a
/// template's words and a case's indexed words compare.
pub fn index_text(raw: &str) -> String {
    attome_search::project::index_text(raw)
}

/// The distinct words of already indexed text (search's normalised, stemmed
/// form), in order, letters and digits only. Pure.
pub fn terms(indexed: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    indexed
        .split_whitespace()
        .map(|w| {
            w.chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
        })
        .filter(|w| w.chars().count() >= 2)
        .filter(|w| seen.insert(w.clone()))
        .collect()
}

/// A `to_tsquery` text matching any of the first [`MAX_QUERY_TERMS`] terms,
/// or `None` when there are none. Every term is letters and digits only, so
/// nothing in it is tsquery syntax. Pure.
pub fn any_term_query(terms: &[String]) -> Option<String> {
    let picked: Vec<&str> = terms
        .iter()
        .take(MAX_QUERY_TERMS)
        .map(String::as_str)
        .collect();
    (!picked.is_empty()).then(|| picked.join(" | "))
}

/// How much two word sets share, 0 to 1 (cosine over sets). Pure.
pub fn overlap(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let shared = a.intersection(b).count() as f64;
    shared / ((a.len() as f64) * (b.len() as f64)).sqrt()
}

/// One template to rank.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The template's model id.
    pub id: String,
    pub name: String,
    pub folder: Option<String>,
    /// Its folder and body, indexed like search.
    pub indexed: String,
}

/// How a template was used on cases like this one.
#[derive(Debug, Clone, Copy, Default)]
pub struct SimilarUse {
    /// The best `ts_rank` of a similar case it was used on.
    pub best_rank: f64,
    /// How many similar cases it was used on.
    pub cases: i64,
}

/// One suggestion.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Suggestion {
    pub id: String,
    pub name: String,
    pub folder: Option<String>,
    /// 0 to 1.
    pub score: f64,
    /// Why it was suggested, for the person: `similar_cases`, `wording` or
    /// `often_used`, strongest first.
    pub reasons: Vec<String>,
    /// The reply, rendered for the case and channel.
    pub reply: String,
}

/// Ranks `candidates` for a case whose indexed text is `case_indexed`, best
/// first, at most [`MAX_SUGGESTIONS`], leaving out any with no signal at all.
/// `render` gives each kept template's reply. Pure but for `render`.
pub fn rank(
    case_indexed: &str,
    candidates: &[Candidate],
    similar: &HashMap<String, SimilarUse>,
    usage: &HashMap<String, i64>,
    render: impl Fn(&str) -> String,
) -> Vec<Suggestion> {
    let case_terms: HashSet<String> = terms(case_indexed).into_iter().collect();
    let best_rank = similar
        .values()
        .map(|s| s.best_rank * (1.0 + s.cases as f64).ln())
        .fold(0.0_f64, f64::max);
    let most_used = usage.values().copied().max().unwrap_or(0);
    let mut out: Vec<Suggestion> = candidates
        .iter()
        .filter_map(|c| {
            let template_terms: HashSet<String> = terms(&c.indexed).into_iter().collect();
            let wording = overlap(&case_terms, &template_terms);
            let similar_score = similar
                .get(&c.id)
                .filter(|_| best_rank > 0.0)
                .map(|s| s.best_rank * (1.0 + s.cases as f64).ln() / best_rank)
                .unwrap_or(0.0);
            let usage_score = match usage.get(&c.id) {
                Some(&n) if most_used > 0 => (1.0 + n as f64).ln() / (1.0 + most_used as f64).ln(),
                _ => 0.0,
            };
            let score = SIMILAR_WEIGHT * similar_score
                + WORDING_WEIGHT * wording
                + USAGE_WEIGHT * usage_score;
            if score <= 0.0 {
                return None;
            }
            let mut reasons: Vec<(f64, &str)> = vec![
                (SIMILAR_WEIGHT * similar_score, "similar_cases"),
                (WORDING_WEIGHT * wording, "wording"),
                (USAGE_WEIGHT * usage_score, "often_used"),
            ];
            reasons.retain(|(s, _)| *s > 0.0);
            reasons.sort_by(|a, b| b.0.total_cmp(&a.0));
            Some(Suggestion {
                id: c.id.clone(),
                name: c.name.clone(),
                folder: c.folder.clone(),
                score: (score * 1000.0).round() / 1000.0,
                reasons: reasons.into_iter().map(|(_, r)| r.to_owned()).collect(),
                reply: String::new(),
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.name.cmp(&b.name))
    });
    out.truncate(MAX_SUGGESTIONS);
    for s in &mut out {
        s.reply = render(&s.id);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn candidate(id: &str, indexed: &str) -> Candidate {
        Candidate {
            id: id.into(),
            name: id.into(),
            folder: None,
            indexed: indexed.into(),
        }
    }

    #[test]
    fn reply_suggest_prefers_what_solved_similar_cases() {
        let candidates = vec![
            candidate("refund", "refund invoic paid"),
            candidate("password", "password reset link"),
            candidate("greeting", "thank contact"),
        ];
        let mut similar = HashMap::new();
        similar.insert(
            "refund".to_owned(),
            SimilarUse {
                best_rank: 0.4,
                cases: 6,
            },
        );
        let mut usage = HashMap::new();
        usage.insert("greeting".to_owned(), 50);
        usage.insert("refund".to_owned(), 8);
        let ranked = rank(
            "customer ask refund invoic charg twice",
            &candidates,
            &similar,
            &usage,
            |id| format!("reply {id}"),
        );
        let ids: Vec<&str> = ranked.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["refund", "greeting"], "{ranked:?}");
        assert_eq!(ranked[0].reasons[0], "similar_cases");
        assert_eq!(ranked[0].reply, "reply refund");
        assert_eq!(ranked[1].reasons, vec!["often_used"]);
    }

    #[test]
    fn reply_suggest_matches_wording_without_history() {
        let candidates = vec![
            candidate("password", "password reset link"),
            candidate("refund", "refund invoic"),
        ];
        let ranked = rank(
            "cannot log in need password reset",
            &candidates,
            &HashMap::new(),
            &HashMap::new(),
            |_| String::new(),
        );
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].id, "password");
        assert_eq!(ranked[0].reasons, vec!["wording"]);
    }

    #[test]
    fn reply_suggest_respects_visibility() {
        let me = Uuid::now_v7();
        let team = Uuid::now_v7();
        let viewer = Viewer {
            user_id: me,
            team_ids: vec![team],
            ..Viewer::default()
        };
        assert!(visible(&json!({"body": "x"}), &viewer));
        assert!(visible(
            &json!({"visibility": {"scope": "team", "ref": team.to_string()}}),
            &viewer
        ));
        assert!(!visible(
            &json!({"visibility": {"scope": "user", "ref": Uuid::now_v7().to_string()}}),
            &viewer
        ));
        assert!(!visible(
            &json!({"visibility": {"scope": "queue"}}),
            &viewer
        ));
        let admin = Viewer {
            is_admin: true,
            ..Viewer::default()
        };
        assert!(visible(
            &json!({"visibility": {"scope": "role", "ref": Uuid::now_v7().to_string()}}),
            &admin
        ));
    }

    #[test]
    fn reply_suggest_queries_only_plain_terms() {
        let t = terms("refund refund (invoic) a & paid!");
        assert_eq!(t, vec!["refund", "invoic", "paid"]);
        assert_eq!(
            any_term_query(&t).as_deref(),
            Some("refund | invoic | paid")
        );
        assert_eq!(any_term_query(&[]), None);
    }
}
