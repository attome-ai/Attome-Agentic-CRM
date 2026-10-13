//! The Knowledge Base retrieval benchmark (D-498 step 3).
//!
//! `eval` and `coverage` measure record search over `golden.json`. This applies
//! the same discipline — graded judgments, a fingerprinted fixture, a committed
//! baseline — to `search_knowledge`, with three things record search does not
//! need:
//!
//! * **Judgments name article sections, not chunks.** `search_knowledge`
//!   returns the enclosing section, and chunk ordinals move whenever the
//!   chunker's size limits do. A section key (`article#Heading/Sub`) survives a
//!   chunking change, which is what lets a later embedding or reranker run be
//!   compared against this baseline at all.
//! * **Answerability is declared, not inferred.** A question the corpus cannot
//!   answer is scored by whether retrieval returned anything at all (the
//!   unanswerable retrieval rate, URR) and never averaged into recall. An
//!   unanswerable question scores zero on every ranking metric, so mixing it in
//!   would make "returned nothing, correctly" read as a ranking failure.
//! * **The fixture has a review state.** A `draft` fixture is validated and its
//!   sections are checked against real chunks, but it is never scored: judgments
//!   adjusted after seeing what retrieval returns measure the system against its
//!   own behaviour. Only a `frozen` fixture — reviewed, its Arabic judgments by a
//!   native speaker (`P-search-and-retrieval`, Stage 1 fixtures) — produces a
//!   baseline.
//!
//! ## Grading rubric
//!
//! Every judgment grades one section against one question:
//!
//! | Grade | The section… |
//! |---|---|
//! | 3 | answers the question on its own. |
//! | 2 | holds part of the answer, or a fact a complete answer needs. |
//! | 1 | is on topic and useful context, but answers nothing. |
//! | 0 | is off topic. An ungraded section scores 0. |
//!
//! Recall and MRR count grades 2 and 3 as relevant; nDCG uses every grade. The
//! rubric is documentation, not data: it sits outside the fixture fingerprint,
//! so clarifying its wording never invalidates a baseline, while changing a
//! grade under it does.
//!
//! Permission cases are hard assertions in the harness, each paired with a
//! positive control, and never appear in an average — the rule `ranking_eval`
//! already applies to `QueryKind::Forbidden`.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::corpus::knowledge::section_heading_paths;
use crate::eval::Judgment;

/// Whether the fixture may produce scores yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureStatus {
    /// Validated and wired, never scored. Awaiting review.
    Draft,
    /// Reviewed and fingerprinted; scored against a committed baseline.
    Frozen,
}

/// The language a question or article is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    En,
    Ar,
    /// Arabic and English in one text — the GCC norm, not an edge case.
    Mixed,
}

/// How a question is phrased relative to the text that answers it.
///
/// Orthogonal to [`KnowledgeQuestion::answerable`] and
/// [`KnowledgeQuestion::multi_hop`], except where [`KnowledgeBenchmark::validate`]
/// says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Uses the article's own terms.
    ExactTerminology,
    /// A whole question, as a person would type it.
    NaturalQuestion,
    /// Some content terms appear in the answer and some do not.
    PartialOverlap,
    /// The answer uses different words. A lexical baseline is expected to miss
    /// most of these; they exist so a later change has something to improve.
    Paraphrase,
    /// Shares an incidental content word with an unrelated article, and the
    /// corpus does not answer it. Always unanswerable: it measures how
    /// permissive any-term matching is.
    LooseMatch,
    /// The corpus answers it, but the asking caller cannot read the collection.
    /// Asserted in the harness with a positive control; never scored.
    PermissionRestricted,
}

/// A seeded Knowledge Base Data Source — the permission unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionSpec {
    pub key: String,
    pub name: String,
}

/// A seeded, non-admin caller and the collections it may read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerSpec {
    pub key: String,
    pub readable: Vec<String>,
    #[serde(default)]
    pub note: String,
}

/// One published article.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArticleSpec {
    pub key: String,
    pub collection: String,
    pub language: Language,
    pub title: String,
    /// Markdown-ish text; `#` headings define the sections judgments name.
    pub text: String,
}

/// One benchmark question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeQuestion {
    pub id: String,
    pub question: String,
    pub language: Language,
    pub category: Category,
    /// Which [`CallerSpec`] asks it.
    pub caller: String,
    /// Whether the corpus contains enough to answer it — for *some* caller.
    pub answerable: bool,
    /// The answer needs sections from two or more articles.
    #[serde(default)]
    pub multi_hop: bool,
    /// Graded section keys (see [`section_key`]).
    #[serde(default)]
    pub judgments: Vec<Judgment>,
    /// For [`Category::PermissionRestricted`]: a caller who may read the answer.
    #[serde(default)]
    pub control_caller: Option<String>,
    /// Why the case exists. Excluded from the fingerprint.
    #[serde(default)]
    pub note: String,
}

/// The whole fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeBenchmark {
    pub status: FixtureStatus,
    pub collections: Vec<CollectionSpec>,
    pub callers: Vec<CallerSpec>,
    pub articles: Vec<ArticleSpec>,
    pub questions: Vec<KnowledgeQuestion>,
}

/// The key a judgment uses for one article section: `article#Heading/Sub`,
/// and `article#` for the lede before the first heading.
pub fn section_key(article: &str, heading_path: &[String]) -> String {
    format!("{article}#{}", heading_path.join("/"))
}

impl KnowledgeBenchmark {
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Every section key the corpus produces, mapped to its article.
    pub fn sections(&self) -> BTreeMap<String, &ArticleSpec> {
        let mut out = BTreeMap::new();
        for article in &self.articles {
            for path in section_heading_paths(&article.text) {
                out.insert(section_key(&article.key, &path), article);
            }
        }
        out
    }

    /// The collections `caller` may read, or `None` for an unknown caller.
    pub fn readable_by(&self, caller: &str) -> Option<HashSet<&str>> {
        self.callers
            .iter()
            .find(|c| c.key == caller)
            .map(|c| c.readable.iter().map(String::as_str).collect())
    }

    /// Structural validation — everything checkable without a database.
    ///
    /// Each rule exists because breaking it silently changes what a number
    /// means. A judgment naming a section the chunker never emits makes a
    /// question unsatisfiable, and the drop reads as a retrieval regression.
    pub fn validate(&self) -> Result<(), String> {
        unique(
            self.collections.iter().map(|c| c.key.as_str()),
            "collection",
        )?;
        unique(self.callers.iter().map(|c| c.key.as_str()), "caller")?;
        unique(self.articles.iter().map(|a| a.key.as_str()), "article")?;
        unique(self.questions.iter().map(|q| q.id.as_str()), "question")?;

        let collections: HashSet<&str> = self.collections.iter().map(|c| c.key.as_str()).collect();
        for caller in &self.callers {
            for c in &caller.readable {
                if !collections.contains(c.as_str()) {
                    return Err(format!(
                        "caller {} reads unknown collection {c}",
                        caller.key
                    ));
                }
            }
        }
        for article in &self.articles {
            validate_article(article, &collections)?;
        }

        let sections = self.sections();
        for q in &self.questions {
            self.validate_question(q, &sections)?;
        }
        Ok(())
    }

    fn validate_question(
        &self,
        q: &KnowledgeQuestion,
        sections: &BTreeMap<String, &ArticleSpec>,
    ) -> Result<(), String> {
        let id = &q.id;
        if q.question.trim().is_empty() {
            return Err(format!("question {id} is empty"));
        }
        let caller = self
            .readable_by(&q.caller)
            .ok_or_else(|| format!("question {id} uses unknown caller {}", q.caller))?;

        let mut judged = HashSet::new();
        for j in &q.judgments {
            if !sections.contains_key(&j.doc) {
                return Err(format!("question {id} judges unknown section {}", j.doc));
            }
            if j.grade > 3 {
                return Err(format!("question {id} grade {} out of range", j.grade));
            }
            if !judged.insert(j.doc.as_str()) {
                return Err(format!("question {id} judges {} twice", j.doc));
            }
        }
        let relevant: Vec<&ArticleSpec> = q
            .judgments
            .iter()
            .filter(|j| j.grade >= 2)
            .map(|j| sections[&j.doc])
            .collect();

        if !q.answerable {
            if q.judgments.iter().any(|j| j.grade > 0) {
                return Err(format!(
                    "question {id} is unanswerable but grades a section as relevant"
                ));
            }
            if q.multi_hop || q.control_caller.is_some() {
                return Err(format!(
                    "question {id} is unanswerable, so it cannot be multi-hop or have a control"
                ));
            }
            if q.category == Category::PermissionRestricted {
                return Err(format!(
                    "question {id}: a permission case is answerable for its control caller"
                ));
            }
            return Ok(());
        }

        if q.category == Category::LooseMatch {
            return Err(format!(
                "question {id}: a loose-match case is always unanswerable"
            ));
        }
        if relevant.is_empty() {
            return Err(format!(
                "question {id} is answerable but grades no section 2 or above"
            ));
        }
        if q.multi_hop {
            let articles: HashSet<&str> = relevant.iter().map(|a| a.key.as_str()).collect();
            if articles.len() < 2 {
                return Err(format!(
                    "question {id} is multi-hop but its relevant sections sit in one article"
                ));
            }
        }

        let caller_reads = relevant
            .iter()
            .any(|a| caller.contains(a.collection.as_str()));
        if q.category == Category::PermissionRestricted {
            let control = q
                .control_caller
                .as_deref()
                .ok_or_else(|| format!("permission question {id} needs a control_caller"))?;
            let control = self
                .readable_by(control)
                .ok_or_else(|| format!("question {id} uses unknown control caller {control}"))?;
            if caller_reads {
                return Err(format!(
                    "permission question {id}: its caller can read a relevant section"
                ));
            }
            if !relevant
                .iter()
                .all(|a| control.contains(a.collection.as_str()))
            {
                return Err(format!(
                    "permission question {id}: the control caller cannot read every relevant section"
                ));
            }
        } else {
            if q.control_caller.is_some() {
                return Err(format!(
                    "question {id}: only permission cases take a control_caller"
                ));
            }
            if !relevant
                .iter()
                .all(|a| caller.contains(a.collection.as_str()))
            {
                return Err(format!(
                    "question {id}: its caller cannot read every relevant section — \
                     declare it permission_restricted instead"
                ));
            }
        }
        Ok(())
    }
}

fn unique<'a>(keys: impl Iterator<Item = &'a str>, what: &str) -> Result<(), String> {
    let mut seen = HashSet::new();
    for k in keys {
        if !seen.insert(k) {
            return Err(format!("duplicate {what} {k}"));
        }
    }
    Ok(())
}

fn validate_article(article: &ArticleSpec, collections: &HashSet<&str>) -> Result<(), String> {
    let key = &article.key;
    if key.contains('#') {
        return Err(format!("article key {key} must not contain '#'"));
    }
    if !collections.contains(article.collection.as_str()) {
        return Err(format!(
            "article {key} is in unknown collection {}",
            article.collection
        ));
    }
    if article.title.trim().is_empty() {
        return Err(format!("article {key} has no title"));
    }
    let paths = section_heading_paths(&article.text);
    if paths.is_empty() {
        return Err(format!("article {key} has no text"));
    }
    let mut seen: HashMap<Vec<String>, ()> = HashMap::new();
    for path in paths {
        if path.iter().any(|h| h.contains('/')) {
            return Err(format!("article {key} has a heading containing '/'"));
        }
        if seen.insert(path.clone(), ()).is_some() {
            return Err(format!(
                "article {key} repeats the heading path {}: a section key would be ambiguous",
                path.join("/")
            ));
        }
    }
    Ok(())
}

// ── Scoring ─────────────────────────────────────────────────────────────────

/// `search.knowledge` hands an agent five passages by default.
pub const K_AGENT: usize = 5;
/// The wider view, and the limit the harness retrieves with.
pub const K_WIDE: usize = 10;

/// What retrieval returned for one question: section keys in rank order, each
/// once.
#[derive(Debug, Clone)]
pub struct Retrieved {
    pub question: String,
    pub ranked: Vec<String>,
}

/// Ranking scores over answerable questions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct AnswerableScores {
    pub questions: usize,
    pub recall_at_5: f64,
    pub recall_at_10: f64,
    pub mrr_at_10: f64,
    pub ndcg_at_10: f64,
    /// Share of questions with **every** section graded 2+ in the top ten. The
    /// multi-hop number: half the evidence produces a fluent wrong answer, so a
    /// mean recall of 0.5 there is not half a success (`coverage`'s argument).
    pub complete_at_10: f64,
}

/// Scores over unanswerable questions. Lower is better.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct UnanswerableScores {
    pub questions: usize,
    /// **Unanswerable Retrieval Rate (URR):** the share of unanswerable
    /// questions for which retrieval returned at least one candidate section.
    ///
    /// Defined on *candidates*, deliberately. v1 has no evidence-acceptance
    /// threshold, so any returned section counts. Once one exists, "retrieved a
    /// candidate" and "accepted it as evidence" become different events; that
    /// later measure needs its own name rather than a silent change to this one.
    pub unanswerable_retrieval_rate: f64,
    pub mean_sections_returned: f64,
}

/// Every aggregate the baseline records.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KnowledgeScores {
    pub answerable: AnswerableScores,
    pub answerable_by_language: BTreeMap<Language, AnswerableScores>,
    pub answerable_by_category: BTreeMap<Category, AnswerableScores>,
    pub multi_hop: AnswerableScores,
    pub unanswerable: UnanswerableScores,
    pub unanswerable_by_language: BTreeMap<Language, UnanswerableScores>,
    pub unanswerable_by_category: BTreeMap<Category, UnanswerableScores>,
}

/// The scores plus the diagnostics a failing gate needs.
#[derive(Debug, Clone)]
pub struct KnowledgeReport {
    pub scores: KnowledgeScores,
    /// Answerable questions whose 2+ sections never came back at any rank — a
    /// retrieval miss, not a ranking one.
    pub never_retrieved: Vec<(String, Vec<String>)>,
}

struct AnswerableCase {
    recall5: f64,
    recall10: f64,
    mrr10: f64,
    ndcg10: f64,
    complete10: bool,
}

fn mean(values: impl Iterator<Item = f64>) -> f64 {
    let v: Vec<f64> = values.collect();
    if v.is_empty() {
        0.0
    } else {
        v.iter().sum::<f64>() / v.len() as f64
    }
}

/// The distinct values of `items`, sorted — the groups a report breaks down by.
fn distinct<T: Ord>(items: impl Iterator<Item = T>) -> Vec<T> {
    let mut v: Vec<T> = items.collect();
    v.sort();
    v.dedup();
    v
}

fn answerable_scores(cases: &[&AnswerableCase]) -> AnswerableScores {
    AnswerableScores {
        questions: cases.len(),
        recall_at_5: mean(cases.iter().map(|c| c.recall5)),
        recall_at_10: mean(cases.iter().map(|c| c.recall10)),
        mrr_at_10: mean(cases.iter().map(|c| c.mrr10)),
        ndcg_at_10: mean(cases.iter().map(|c| c.ndcg10)),
        complete_at_10: mean(cases.iter().map(|c| f64::from(u8::from(c.complete10)))),
    }
}

fn unanswerable_scores(returned: &[usize]) -> UnanswerableScores {
    UnanswerableScores {
        questions: returned.len(),
        unanswerable_retrieval_rate: mean(returned.iter().map(|n| f64::from(u8::from(*n > 0)))),
        mean_sections_returned: mean(returned.iter().map(|n| *n as f64)),
    }
}

/// Scores a run. Permission cases are skipped — the harness asserts them.
///
/// Fails if a scored question has no [`Retrieved`] entry: a question the
/// harness silently skipped would otherwise vanish from every average.
pub fn score(
    bench: &KnowledgeBenchmark,
    retrieved: &[Retrieved],
) -> Result<KnowledgeReport, String> {
    use crate::eval::{ndcg_at_k, recall_at_k, reciprocal_rank};

    let by_id: HashMap<&str, &Retrieved> =
        retrieved.iter().map(|r| (r.question.as_str(), r)).collect();

    let mut answerable: Vec<(&KnowledgeQuestion, AnswerableCase)> = Vec::new();
    let mut unanswerable: Vec<(&KnowledgeQuestion, usize)> = Vec::new();
    let mut never_retrieved = Vec::new();

    for q in &bench.questions {
        if q.category == Category::PermissionRestricted {
            continue;
        }
        let r = by_id
            .get(q.id.as_str())
            .ok_or_else(|| format!("question {} was never run", q.id))?;
        if !q.answerable {
            unanswerable.push((q, r.ranked.len()));
            continue;
        }
        let relevant: Vec<&str> = q
            .judgments
            .iter()
            .filter(|j| j.grade >= 2)
            .map(|j| j.doc.as_str())
            .collect();
        let top10: HashSet<&str> = r.ranked.iter().take(K_WIDE).map(String::as_str).collect();
        let missed: Vec<String> = relevant
            .iter()
            .filter(|s| !r.ranked.iter().any(|x| x == *s))
            .map(|s| (*s).to_owned())
            .collect();
        if !missed.is_empty() {
            never_retrieved.push((q.id.clone(), missed));
        }
        answerable.push((
            q,
            AnswerableCase {
                recall5: recall_at_k(&r.ranked, &q.judgments, K_AGENT).unwrap_or(0.0),
                recall10: recall_at_k(&r.ranked, &q.judgments, K_WIDE).unwrap_or(0.0),
                mrr10: reciprocal_rank(&r.ranked, &q.judgments, K_WIDE),
                ndcg10: ndcg_at_k(&r.ranked, &q.judgments, K_WIDE).unwrap_or(0.0),
                complete10: relevant.iter().all(|s| top10.contains(s)),
            },
        ));
    }

    let group_a = |pick: &dyn Fn(&KnowledgeQuestion) -> bool| {
        let cases: Vec<&AnswerableCase> = answerable
            .iter()
            .filter(|(q, _)| pick(q))
            .map(|(_, c)| c)
            .collect();
        answerable_scores(&cases)
    };
    let group_u = |pick: &dyn Fn(&KnowledgeQuestion) -> bool| {
        let returned: Vec<usize> = unanswerable
            .iter()
            .filter(|(q, _)| pick(q))
            .map(|(_, n)| *n)
            .collect();
        unanswerable_scores(&returned)
    };

    let scores = KnowledgeScores {
        answerable: group_a(&|_| true),
        answerable_by_language: distinct(answerable.iter().map(|(q, _)| q.language))
            .into_iter()
            .map(|l| (l, group_a(&|q| q.language == l)))
            .collect(),
        answerable_by_category: distinct(answerable.iter().map(|(q, _)| q.category))
            .into_iter()
            .map(|c| (c, group_a(&|q| q.category == c)))
            .collect(),
        multi_hop: group_a(&|q| q.multi_hop),
        unanswerable: group_u(&|_| true),
        unanswerable_by_language: distinct(unanswerable.iter().map(|(q, _)| q.language))
            .into_iter()
            .map(|l| (l, group_u(&|q| q.language == l)))
            .collect(),
        unanswerable_by_category: distinct(unanswerable.iter().map(|(q, _)| q.category))
            .into_iter()
            .map(|c| (c, group_u(&|q| q.category == c)))
            .collect(),
    };
    Ok(KnowledgeReport {
        scores,
        never_retrieved,
    })
}

impl KnowledgeReport {
    /// Human-readable, for the CI log and the baseline evidence note.
    pub fn render(&self) -> String {
        let s = &self.scores;
        let a = |label: &str, x: &AnswerableScores| {
            format!(
                "  {label:<22} n={:<3} R@5 {:.3}  R@10 {:.3}  MRR {:.3}  nDCG {:.3}  complete {:.3}\n",
                x.questions,
                x.recall_at_5,
                x.recall_at_10,
                x.mrr_at_10,
                x.ndcg_at_10,
                x.complete_at_10
            )
        };
        let u = |label: &str, x: &UnanswerableScores| {
            format!(
                "  {label:<22} n={:<3} URR {:.3}  mean sections {:.2}\n",
                x.questions, x.unanswerable_retrieval_rate, x.mean_sections_returned
            )
        };
        let mut out = String::from("knowledge retrieval — answerable\n");
        out.push_str(&a("overall", &s.answerable));
        for (l, x) in &s.answerable_by_language {
            out.push_str(&a(&format!("lang {l:?}"), x));
        }
        for (c, x) in &s.answerable_by_category {
            out.push_str(&a(&format!("{c:?}"), x));
        }
        out.push_str(&a("multi-hop", &s.multi_hop));
        out.push_str("knowledge retrieval — unanswerable (lower is better)\n");
        out.push_str(&u("overall", &s.unanswerable));
        for (l, x) in &s.unanswerable_by_language {
            out.push_str(&u(&format!("lang {l:?}"), x));
        }
        for (c, x) in &s.unanswerable_by_category {
            out.push_str(&u(&format!("{c:?}"), x));
        }
        if !self.never_retrieved.is_empty() {
            out.push_str("never retrieved (a retrieval miss, not a ranking one):\n");
            for (id, missed) in &self.never_retrieved {
                out.push_str(&format!("    {id}: {}\n", missed.join(", ")));
            }
        }
        out
    }
}

// ── Baseline ────────────────────────────────────────────────────────────────

/// A recorded baseline, keyed by the fixture it was measured on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeBaseline {
    pub fixture_fingerprint: String,
    pub scores: KnowledgeScores,
}

/// A fingerprint of everything that changes a score: collections, callers,
/// article text, questions and judgments. Notes and the review status are
/// excluded, so freezing a reviewed fixture or fixing a comment does not
/// invalidate its baseline. Unlike `eval::fixture_fingerprint`, the corpus is
/// included — editing an article changes what every question can retrieve.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub fn fixture_fingerprint(bench: &KnowledgeBenchmark) -> String {
    use sha2::{Digest, Sha256};
    let mut canonical = bench.clone();
    canonical.status = FixtureStatus::Frozen;
    for c in &mut canonical.callers {
        c.note.clear();
    }
    for q in &mut canonical.questions {
        q.note.clear();
    }
    let bytes = serde_json::to_vec(&canonical).expect("the fixture serializes");
    format!("{:x}", Sha256::digest(&bytes))[..16].to_string()
}

/// Every metric that moved past `eval::REGRESSION_TOLERANCE` in the wrong
/// direction, or a group the baseline has and this run lost.
pub fn check_regression(now: &KnowledgeScores, baseline: &KnowledgeScores) -> Vec<String> {
    use crate::eval::REGRESSION_TOLERANCE as TOL;
    let mut out = Vec::new();

    let mut higher = |what: String, n: f64, was: f64| {
        if n < was - TOL {
            out.push(format!("{what} regressed: {n:.3} vs baseline {was:.3}"));
        }
    };
    let mut answerable = |label: &str, n: &AnswerableScores, was: &AnswerableScores| {
        higher(format!("{label} recall@5"), n.recall_at_5, was.recall_at_5);
        higher(
            format!("{label} recall@10"),
            n.recall_at_10,
            was.recall_at_10,
        );
        higher(format!("{label} MRR@10"), n.mrr_at_10, was.mrr_at_10);
        higher(format!("{label} nDCG@10"), n.ndcg_at_10, was.ndcg_at_10);
        higher(
            format!("{label} complete@10"),
            n.complete_at_10,
            was.complete_at_10,
        );
    };
    answerable("answerable", &now.answerable, &baseline.answerable);
    answerable("multi-hop", &now.multi_hop, &baseline.multi_hop);
    let mut lost = Vec::new();
    for (l, was) in &baseline.answerable_by_language {
        match now.answerable_by_language.get(l) {
            Some(n) => answerable(&format!("answerable {l:?}"), n, was),
            None => lost.push(format!("answerable group {l:?} missing from this run")),
        }
    }
    for (c, was) in &baseline.answerable_by_category {
        match now.answerable_by_category.get(c) {
            Some(n) => answerable(&format!("answerable {c:?}"), n, was),
            None => lost.push(format!("answerable group {c:?} missing from this run")),
        }
    }

    let mut lower = |what: String, n: &UnanswerableScores, was: &UnanswerableScores| {
        if n.unanswerable_retrieval_rate > was.unanswerable_retrieval_rate + TOL {
            out.push(format!(
                "{what} URR rose: {:.3} vs baseline {:.3}",
                n.unanswerable_retrieval_rate, was.unanswerable_retrieval_rate
            ));
        }
    };
    lower(
        "unanswerable".into(),
        &now.unanswerable,
        &baseline.unanswerable,
    );
    for (l, was) in &baseline.unanswerable_by_language {
        match now.unanswerable_by_language.get(l) {
            Some(n) => lower(format!("unanswerable {l:?}"), n, was),
            None => lost.push(format!("unanswerable group {l:?} missing from this run")),
        }
    }
    for (c, was) in &baseline.unanswerable_by_category {
        match now.unanswerable_by_category.get(c) {
            Some(n) => lower(format!("unanswerable {c:?}"), n, was),
            None => lost.push(format!("unanswerable group {c:?} missing from this run")),
        }
    }
    out.extend(lost);
    out
}

// ── Similarity calibration (D-498 step 5e) ──────────────────────────────────

/// One section, in vector retrieval's rank order, with the cosine similarity of
/// its closest chunk to the question.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoredSection {
    pub key: String,
    pub similarity: f64,
}

/// Every section one caller can read, ranked as vector retrieval ranks them,
/// for one question. No floor and no limit applied.
#[derive(Debug, Clone)]
pub struct ScoredRetrieval {
    pub question: String,
    pub sections: Vec<ScoredSection>,
}

/// What a minimum-similarity floor inside retrieval would return: sections
/// below `floor` dropped, the rest in rank order, cut to `k`. `None` applies
/// no floor.
///
/// Filtering the ranked sections gives the same list as filtering candidate
/// chunks before sections are assembled. A section survives exactly when its
/// closest chunk does. A surviving item keeps its closest chunk, so its place
/// among surviving items is unchanged, and its sections stay in document order.
pub fn apply_similarity_floor(
    sections: &[ScoredSection],
    floor: Option<f64>,
    k: usize,
) -> Vec<String> {
    sections
        .iter()
        .filter(|s| floor.is_none_or(|f| s.similarity >= f))
        .take(k)
        .map(|s| s.key.clone())
        .collect()
}

/// Nearest-rank quantiles of a set of similarities.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Distribution {
    pub n: usize,
    pub min: f64,
    pub p10: f64,
    pub p25: f64,
    pub median: f64,
    pub p75: f64,
    pub p90: f64,
    pub max: f64,
}

/// `None` for an empty set.
pub fn distribution(values: &[f64]) -> Option<Distribution> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    let at = |p: f64| v[((p * v.len() as f64).ceil() as usize).clamp(1, v.len()) - 1];
    Some(Distribution {
        n: v.len(),
        min: v[0],
        p10: at(0.10),
        p25: at(0.25),
        median: at(0.50),
        p75: at(0.75),
        p90: at(0.90),
        max: v[v.len() - 1],
    })
}

/// The probability that a value drawn from `higher` exceeds one drawn from
/// `lower`, ties counting half: 1.0 means some floor separates the two sets
/// completely, 0.5 means similarity does not tell them apart at all.
pub fn separation(higher: &[f64], lower: &[f64]) -> Option<f64> {
    if higher.is_empty() || lower.is_empty() {
        return None;
    }
    let mut wins = 0.0;
    for h in higher {
        for l in lower {
            wins += match h.total_cmp(l) {
                std::cmp::Ordering::Greater => 1.0,
                std::cmp::Ordering::Equal => 0.5,
                std::cmp::Ordering::Less => 0.0,
            };
        }
    }
    Some(wins / (higher.len() * lower.len()) as f64)
}

/// The benchmark scored with one floor applied.
#[derive(Debug, Clone)]
pub struct FloorRow {
    pub floor: Option<f64>,
    /// Scored as usual. Under a floor, the unanswerable retrieval rate counts
    /// questions with at least one section *at or above the floor*, so the
    /// report calls it the unanswerable acceptance rate (UAR) rather than
    /// silently redefining URR (see [`UnanswerableScores`]).
    pub scores: KnowledgeScores,
    /// Mean sections left per answerable question: the evidence an agent
    /// would still be handed.
    pub answerable_mean_sections: f64,
}

/// Whether dense similarity alone can separate evidence from non-evidence:
/// the similarity of relevant sections against the best match for questions
/// the corpus cannot answer, and the benchmark rescored under every floor on
/// a fixed grid. Measured, never gated.
#[derive(Debug, Clone)]
pub struct SimilarityCalibration {
    pub distributions: Vec<(String, Option<Distribution>)>,
    pub separations: Vec<(String, Option<f64>)>,
    pub floors: Vec<FloorRow>,
}

fn by_question(runs: &[ScoredRetrieval]) -> HashMap<&str, &ScoredRetrieval> {
    runs.iter().map(|r| (r.question.as_str(), r)).collect()
}

fn lookup<'a>(
    runs: &HashMap<&str, &'a ScoredRetrieval>,
    id: &str,
    what: &str,
) -> Result<&'a ScoredRetrieval, String> {
    runs.get(id)
        .copied()
        .ok_or_else(|| format!("question {id} has no {what} run"))
}

fn best<'a>(sections: impl Iterator<Item = &'a ScoredSection>) -> Option<f64> {
    sections.map(|s| s.similarity).reduce(f64::max)
}

impl SimilarityCalibration {
    /// `runs` holds one entry per scored question, `restricted` and `controls`
    /// one per permission case (its asking caller and its control caller).
    /// Floors run from just below the lowest similarity seen to just above the
    /// highest, `step` apart, after a first row with no floor.
    pub fn measure(
        bench: &KnowledgeBenchmark,
        runs: &[ScoredRetrieval],
        restricted: &[ScoredRetrieval],
        controls: &[ScoredRetrieval],
        step: f64,
    ) -> Result<Self, String> {
        if step <= 0.0 {
            return Err(format!("the floor step must be positive, not {step}"));
        }
        let (runs_by, restricted_by, controls_by) = (
            by_question(runs),
            by_question(restricted),
            by_question(controls),
        );

        let mut relevant_all = Vec::new();
        // (language, best relevant section, best non-relevant section)
        let mut answerable_best: Vec<(Language, f64, Option<f64>)> = Vec::new();
        let mut unanswerable_best: Vec<(Language, Category, f64)> = Vec::new();
        let mut restricted_best = Vec::new();
        let mut control_relevant = Vec::new();

        for q in &bench.questions {
            let graded = |s: &ScoredSection, min: u8| {
                q.judgments.iter().any(|j| j.doc == s.key && j.grade >= min)
            };
            if q.category == Category::PermissionRestricted {
                let r = lookup(&restricted_by, &q.id, "restricted-caller")?;
                restricted_best.extend(best(r.sections.iter()));
                let c = lookup(&controls_by, &q.id, "control-caller")?;
                control_relevant.extend(best(c.sections.iter().filter(|s| graded(s, 2))));
                continue;
            }
            let run = lookup(&runs_by, &q.id, "scored")?;
            if !q.answerable {
                if let Some(v) = best(run.sections.iter()) {
                    unanswerable_best.push((q.language, q.category, v));
                }
                continue;
            }
            relevant_all.extend(
                run.sections
                    .iter()
                    .filter(|s| graded(s, 2))
                    .map(|s| s.similarity),
            );
            if let Some(v) = best(run.sections.iter().filter(|s| graded(s, 2))) {
                // Grade 1 is on-topic context: neither relevant nor a distractor.
                let distractor = best(run.sections.iter().filter(|s| !graded(s, 1)));
                answerable_best.push((q.language, v, distractor));
            }
        }

        let best_relevant: Vec<f64> = answerable_best.iter().map(|(_, v, _)| *v).collect();
        let unanswerable: Vec<f64> = unanswerable_best.iter().map(|(_, _, v)| *v).collect();
        let unanswerable_in = |c: Category| -> Vec<f64> {
            unanswerable_best
                .iter()
                .filter(|(_, cat, _)| *cat == c)
                .map(|(_, _, v)| *v)
                .collect()
        };

        let mut distributions = vec![
            (
                "answerable: every relevant section (grade 2-3)".to_owned(),
                distribution(&relevant_all),
            ),
            (
                "answerable: best relevant section".to_owned(),
                distribution(&best_relevant),
            ),
        ];
        for l in distinct(answerable_best.iter().map(|(l, _, _)| *l)) {
            let v: Vec<f64> = answerable_best
                .iter()
                .filter(|(x, _, _)| *x == l)
                .map(|(_, v, _)| *v)
                .collect();
            distributions.push((format!("  lang {l:?}"), distribution(&v)));
        }
        let distractors: Vec<f64> = answerable_best.iter().filter_map(|(_, _, d)| *d).collect();
        distributions.push((
            "answerable: best non-relevant section (grade 0)".to_owned(),
            distribution(&distractors),
        ));
        distributions.push((
            "unanswerable: best section".to_owned(),
            distribution(&unanswerable),
        ));
        for c in distinct(unanswerable_best.iter().map(|(_, c, _)| *c)) {
            distributions.push((format!("  {c:?}"), distribution(&unanswerable_in(c))));
        }
        for l in distinct(unanswerable_best.iter().map(|(l, _, _)| *l)) {
            let v: Vec<f64> = unanswerable_best
                .iter()
                .filter(|(x, _, _)| *x == l)
                .map(|(_, _, v)| *v)
                .collect();
            distributions.push((format!("  lang {l:?}"), distribution(&v)));
        }
        distributions.push((
            "permission case: best section the asking caller can read".to_owned(),
            distribution(&restricted_best),
        ));
        distributions.push((
            "permission case: best relevant section, control caller".to_owned(),
            distribution(&control_relevant),
        ));

        let outscored = answerable_best
            .iter()
            .filter(|(_, rel, d)| d.is_none_or(|d| *rel > d))
            .count();
        let separations = vec![
            (
                "best relevant (answerable) vs best section (unanswerable)".to_owned(),
                separation(&best_relevant, &unanswerable),
            ),
            (
                "  vs LooseMatch".to_owned(),
                separation(&best_relevant, &unanswerable_in(Category::LooseMatch)),
            ),
            (
                "  vs NaturalQuestion".to_owned(),
                separation(&best_relevant, &unanswerable_in(Category::NaturalQuestion)),
            ),
            (
                "best relevant vs asking caller's best (permission cases)".to_owned(),
                separation(&best_relevant, &restricted_best),
            ),
            (
                "answerable questions whose best relevant section outscores every grade-0 one"
                    .to_owned(),
                (!answerable_best.is_empty())
                    .then(|| outscored as f64 / answerable_best.len() as f64),
            ),
        ];

        let mut floors: Vec<Option<f64>> = vec![None];
        let seen = runs
            .iter()
            .flat_map(|r| r.sections.iter().map(|s| s.similarity));
        if let (Some(lo), Some(hi)) = (seen.clone().reduce(f64::min), seen.reduce(f64::max)) {
            let (first, last) = ((lo / step).floor() as i64, (hi / step).ceil() as i64);
            floors.extend((first..=last).map(|i| Some(i as f64 * step)));
        }

        let answerable_ids: HashSet<&str> = bench
            .questions
            .iter()
            .filter(|q| q.answerable && q.category != Category::PermissionRestricted)
            .map(|q| q.id.as_str())
            .collect();
        let floors = floors
            .into_iter()
            .map(|floor| {
                let floored: Vec<Retrieved> = runs
                    .iter()
                    .map(|r| Retrieved {
                        question: r.question.clone(),
                        ranked: apply_similarity_floor(&r.sections, floor, K_WIDE),
                    })
                    .collect();
                let report = score(bench, &floored)?;
                let answerable_mean_sections = mean(
                    floored
                        .iter()
                        .filter(|r| answerable_ids.contains(r.question.as_str()))
                        .map(|r| r.ranked.len() as f64),
                );
                Ok(FloorRow {
                    floor,
                    scores: report.scores,
                    answerable_mean_sections,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(Self {
            distributions,
            separations,
            floors,
        })
    }

    /// Human-readable, for the test log and the evidence note.
    pub fn render(&self) -> String {
        let mut out = String::from(
            "similarity distributions (cosine similarity of a section's closest chunk to the question)\n",
        );
        out.push_str(&format!(
            "  {:<60} {:>3} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6}\n",
            "", "n", "min", "p10", "p25", "median", "p75", "p90", "max"
        ));
        for (label, d) in &self.distributions {
            match d {
                Some(d) => out.push_str(&format!(
                    "  {label:<60} {:>3} {:>6.3} {:>6.3} {:>6.3} {:>6.3} {:>6.3} {:>6.3} {:>6.3}\n",
                    d.n, d.min, d.p10, d.p25, d.median, d.p75, d.p90, d.max
                )),
                None => out.push_str(&format!("  {label:<60}   0\n")),
            }
        }
        out.push_str(
            "separation (share of pairs where the first similarity is higher: 1.000 = some floor \
             separates them, 0.500 = no signal)\n",
        );
        for (label, s) in &self.separations {
            match s {
                Some(s) => out.push_str(&format!("  {label:<78} {s:.3}\n")),
                None => out.push_str(&format!("  {label:<78} n/a\n")),
            }
        }
        out.push_str(
            "minimum-similarity floor sweep (sections below the floor dropped, then cut to 10; \
             UAR = share of unanswerable questions with a section at or above the floor)\n",
        );
        out.push_str(
            "  floor    R@5   R@10    MRR   nDCG  compl  ans.sec |   UAR  un.sec  Loose  Natur | \
             R@10 En     Ar  Mixed   Para\n",
        );
        let lang = |s: &KnowledgeScores, l: Language| {
            s.answerable_by_language
                .get(&l)
                .map_or(f64::NAN, |x| x.recall_at_10)
        };
        let unans = |s: &KnowledgeScores, c: Category| {
            s.unanswerable_by_category
                .get(&c)
                .map_or(f64::NAN, |x| x.unanswerable_retrieval_rate)
        };
        for row in &self.floors {
            let s = &row.scores;
            let floor = row.floor.map_or("none".to_owned(), |f| format!("{f:.2}"));
            out.push_str(&format!(
                "  {floor:>5}  {:.3}  {:.3}  {:.3}  {:.3}  {:.3}  {:>7.2} | {:.3}  {:>6.2}  {:.3}  {:.3} | \
                 {:.3}  {:.3}  {:.3}  {:.3}\n",
                s.answerable.recall_at_5,
                s.answerable.recall_at_10,
                s.answerable.mrr_at_10,
                s.answerable.ndcg_at_10,
                s.answerable.complete_at_10,
                row.answerable_mean_sections,
                s.unanswerable.unanswerable_retrieval_rate,
                s.unanswerable.mean_sections_returned,
                unans(s, Category::LooseMatch),
                unans(s, Category::NaturalQuestion),
                lang(s, Language::En),
                lang(s, Language::Ar),
                lang(s, Language::Mixed),
                s.answerable_by_category
                    .get(&Category::Paraphrase)
                    .map_or(f64::NAN, |x| x.recall_at_10),
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bench(questions: serde_json::Value) -> KnowledgeBenchmark {
        serde_json::from_value(json!({
            "status": "draft",
            "collections": [{"key": "general", "name": "General"}, {"key": "hr", "name": "HR"}],
            "callers": [
                {"key": "staff", "readable": ["general"]},
                {"key": "hr_officer", "readable": ["general", "hr"]}
            ],
            "articles": [
                {"key": "leave", "collection": "hr", "language": "en", "title": "Leave",
                 "text": "Intro.\n\n# Annual\n\nThirty days.\n\n# Sick\n\nTen days."},
                {"key": "expenses", "collection": "general", "language": "en", "title": "Expenses",
                 "text": "# Travel\n\nEconomy class."}
            ],
            "questions": questions
        }))
        .expect("test fixture deserializes")
    }

    fn q(extra: serde_json::Value) -> serde_json::Value {
        let mut base = json!({
            "id": "q1", "question": "how many days", "language": "en",
            "category": "natural_question", "caller": "hr_officer", "answerable": true,
            "judgments": [{"doc": "leave#Annual", "grade": 3}]
        });
        base.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        base
    }

    #[test]
    fn section_keys_follow_the_chunkers_own_split() {
        let keys: Vec<String> = bench(json!([])).sections().into_keys().collect();
        assert_eq!(
            keys,
            vec!["expenses#Travel", "leave#", "leave#Annual", "leave#Sick"]
        );
    }

    #[test]
    fn a_well_formed_fixture_validates() {
        bench(json!([q(json!({}))])).validate().expect("valid");
    }

    #[test]
    fn a_judgment_must_name_a_real_section() {
        let err = bench(json!([q(
            json!({"judgments": [{"doc": "leave#Maternity", "grade": 3}]})
        )]))
        .validate()
        .unwrap_err();
        assert!(err.contains("unknown section"), "{err}");
    }

    #[test]
    fn a_loose_match_can_never_be_answerable() {
        let err = bench(json!([q(json!({"category": "loose_match"}))]))
            .validate()
            .unwrap_err();
        assert!(err.contains("always unanswerable"), "{err}");
    }

    #[test]
    fn an_unanswerable_question_grades_nothing_relevant() {
        let err = bench(json!([q(json!({"answerable": false}))]))
            .validate()
            .unwrap_err();
        assert!(err.contains("unanswerable"), "{err}");
    }

    /// A question whose caller cannot read the answer is a permission case,
    /// and must say so — or it would be scored as a recall failure.
    #[test]
    fn an_unreadable_answer_must_be_declared_a_permission_case() {
        let err = bench(json!([q(json!({"caller": "staff"}))]))
            .validate()
            .unwrap_err();
        assert!(err.contains("permission_restricted"), "{err}");

        bench(json!([q(json!({
            "caller": "staff", "category": "permission_restricted", "control_caller": "hr_officer"
        }))]))
        .validate()
        .expect("declared permission case is valid");
    }

    #[test]
    fn a_permission_case_whose_caller_can_read_the_answer_is_rejected() {
        let err = bench(json!([q(json!({
            "category": "permission_restricted", "control_caller": "hr_officer"
        }))]))
        .validate()
        .unwrap_err();
        assert!(err.contains("can read a relevant section"), "{err}");
    }

    #[test]
    fn multi_hop_needs_two_articles() {
        let err = bench(json!([q(json!({"multi_hop": true}))]))
            .validate()
            .unwrap_err();
        assert!(err.contains("one article"), "{err}");

        bench(json!([q(json!({"multi_hop": true, "judgments": [
            {"doc": "leave#Annual", "grade": 3}, {"doc": "expenses#Travel", "grade": 2}
        ]}))]))
        .validate()
        .expect("two-article multi-hop is valid");
    }

    #[test]
    fn a_repeated_heading_path_is_ambiguous() {
        let mut b = bench(json!([]));
        b.articles[1].text = "# Travel\n\nOne.\n\n# Travel\n\nTwo.".into();
        let err = b.validate().unwrap_err();
        assert!(err.contains("ambiguous"), "{err}");
    }

    fn ran(id: &str, ranked: &[&str]) -> Retrieved {
        Retrieved {
            question: id.into(),
            ranked: ranked.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn unanswerable(id: &str) -> serde_json::Value {
        json!({"id": id, "question": "mars colony policy", "language": "en",
               "category": "natural_question", "caller": "staff", "answerable": false})
    }

    /// An unanswerable question never touches the ranking averages: a correct
    /// "nothing" must not read as a recall failure, and an unanswerable retrieval must
    /// not hide inside a mean.
    #[test]
    fn answerable_and_unanswerable_are_scored_apart() {
        let b = bench(json!([q(json!({})), unanswerable("q2")]));
        let r = score(
            &b,
            &[
                ran("q1", &["expenses#Travel", "leave#Annual"]),
                ran("q2", &["expenses#Travel"]),
            ],
        )
        .unwrap();
        assert_eq!(r.scores.answerable.questions, 1);
        assert_eq!(r.scores.answerable.recall_at_5, 1.0);
        assert_eq!(r.scores.answerable.mrr_at_10, 0.5);
        assert_eq!(r.scores.unanswerable.questions, 1);
        assert_eq!(r.scores.unanswerable.unanswerable_retrieval_rate, 1.0);
    }

    #[test]
    fn returning_nothing_is_the_right_answer_to_an_unanswerable_question() {
        let b = bench(json!([unanswerable("q2")]));
        let r = score(&b, &[ran("q2", &[])]).unwrap();
        assert_eq!(r.scores.unanswerable.unanswerable_retrieval_rate, 0.0);
    }

    #[test]
    fn permission_cases_are_asserted_elsewhere_and_never_scored() {
        let b = bench(json!([q(json!({
            "caller": "staff", "category": "permission_restricted", "control_caller": "hr_officer"
        }))]));
        let r = score(&b, &[]).expect("a permission case needs no retrieval entry");
        assert_eq!(r.scores.answerable.questions, 0);
    }

    #[test]
    fn a_question_the_harness_never_ran_is_an_error() {
        let b = bench(json!([q(json!({}))]));
        assert!(score(&b, &[]).unwrap_err().contains("never run"));
    }

    /// Half the evidence for a multi-hop question is not half an answer.
    #[test]
    fn multi_hop_completion_needs_every_relevant_section() {
        let b = bench(json!([q(json!({"multi_hop": true, "judgments": [
            {"doc": "leave#Annual", "grade": 3}, {"doc": "expenses#Travel", "grade": 2}
        ]}))]));
        let r = score(&b, &[ran("q1", &["leave#Annual"])]).unwrap();
        assert_eq!(r.scores.multi_hop.recall_at_10, 0.5);
        assert_eq!(r.scores.multi_hop.complete_at_10, 0.0);
        assert_eq!(
            r.never_retrieved,
            vec![("q1".to_string(), vec!["expenses#Travel".to_string()])]
        );
    }

    #[test]
    fn regression_catches_a_rising_urr_and_a_lost_group() {
        let b = bench(json!([q(json!({})), unanswerable("q2")]));
        let base = score(&b, &[ran("q1", &["leave#Annual"]), ran("q2", &[])])
            .unwrap()
            .scores;

        let worse = score(
            &b,
            &[ran("q1", &["leave#Annual"]), ran("q2", &["leave#Annual"])],
        )
        .unwrap()
        .scores;
        let failures = check_regression(&worse, &base);
        assert!(
            failures.iter().any(|f| f.contains("URR rose")),
            "{failures:?}"
        );

        let mut lost = base.clone();
        lost.answerable_by_language.clear();
        let failures = check_regression(&lost, &base);
        assert!(
            failures.iter().any(|f| f.contains("missing from this run")),
            "{failures:?}"
        );

        assert!(check_regression(&base, &base).is_empty());
    }

    /// Freezing a reviewed fixture or fixing a note keeps its baseline; editing
    /// what retrieval sees does not.
    #[test]
    fn the_fingerprint_ignores_notes_and_status_but_not_article_text() {
        let b = bench(json!([q(json!({}))]));
        let fp = fixture_fingerprint(&b);

        let mut reviewed = b.clone();
        reviewed.status = FixtureStatus::Frozen;
        reviewed.questions[0].note = "reviewed by a native speaker".into();
        assert_eq!(fixture_fingerprint(&reviewed), fp);

        let mut edited = b.clone();
        edited.articles[0].text.push_str(" Changed.");
        assert_ne!(fixture_fingerprint(&edited), fp);
    }

    fn scored(id: &str, sections: &[(&str, f64)]) -> ScoredRetrieval {
        ScoredRetrieval {
            question: id.into(),
            sections: sections
                .iter()
                .map(|(key, similarity)| ScoredSection {
                    key: (*key).into(),
                    similarity: *similarity,
                })
                .collect(),
        }
    }

    #[test]
    fn a_floor_drops_weak_sections_keeps_rank_order_then_cuts() {
        let r = scored("q1", &[("a", 0.40), ("b", 0.70), ("c", 0.55), ("d", 0.60)]);
        assert_eq!(
            apply_similarity_floor(&r.sections, None, 3),
            ["a", "b", "c"]
        );
        assert_eq!(
            apply_similarity_floor(&r.sections, Some(0.55), 10),
            ["b", "c", "d"]
        );
        assert_eq!(
            apply_similarity_floor(&r.sections, Some(0.55), 2),
            ["b", "c"]
        );
        assert!(apply_similarity_floor(&r.sections, Some(0.71), 10).is_empty());
    }

    #[test]
    fn distributions_use_nearest_rank_quantiles() {
        let v: Vec<f64> = (1..=10).rev().map(f64::from).collect();
        let d = distribution(&v).unwrap();
        assert_eq!(
            (d.n, d.min, d.p10, d.p25, d.median, d.p75, d.p90, d.max),
            (10, 1.0, 1.0, 3.0, 5.0, 8.0, 9.0, 10.0)
        );
        assert!(distribution(&[]).is_none());
    }

    #[test]
    fn separation_is_one_when_a_floor_splits_the_sets_and_half_when_it_cannot() {
        assert_eq!(separation(&[0.7, 0.8], &[0.3, 0.4]), Some(1.0));
        assert_eq!(separation(&[0.3], &[0.7]), Some(0.0));
        assert_eq!(separation(&[0.5], &[0.5]), Some(0.5));
        assert_eq!(separation(&[], &[0.5]), None);
    }

    /// A floor that removes the unanswerable question's only match, and the
    /// weak section ranked above the answer, improves both numbers at once.
    #[test]
    fn calibration_rescores_the_benchmark_under_each_floor() {
        let b = bench(json!([q(json!({})), unanswerable("q2")]));
        let runs = [
            scored(
                "q1",
                &[
                    ("expenses#Travel", 0.40),
                    ("leave#Annual", 0.70),
                    ("leave#Sick", 0.55),
                ],
            ),
            scored("q2", &[("expenses#Travel", 0.35)]),
        ];
        let c = SimilarityCalibration::measure(&b, &runs, &[], &[], 0.05).unwrap();

        let none = &c.floors[0];
        assert_eq!(none.floor, None);
        assert_eq!(none.scores.answerable.mrr_at_10, 0.5);
        assert_eq!(none.scores.unanswerable.unanswerable_retrieval_rate, 1.0);

        let half = c
            .floors
            .iter()
            .find(|r| r.floor.is_some_and(|f| (f - 0.5).abs() < 1e-9))
            .expect("0.50 is on the grid");
        assert_eq!(half.scores.answerable.mrr_at_10, 1.0);
        assert_eq!(half.scores.unanswerable.unanswerable_retrieval_rate, 0.0);
        assert_eq!(half.answerable_mean_sections, 2.0);

        assert_eq!(c.separations[0].1, Some(1.0));
        let best_relevant = c
            .distributions
            .iter()
            .find(|(label, _)| label == "answerable: best relevant section")
            .and_then(|(_, d)| *d)
            .unwrap();
        assert_eq!(best_relevant.max, 0.70);
        assert!(c.render().contains("UAR"));
    }

    #[test]
    fn calibration_needs_a_run_for_every_scored_question() {
        let b = bench(json!([q(json!({}))]));
        let err = SimilarityCalibration::measure(&b, &[], &[], &[], 0.01).unwrap_err();
        assert!(err.contains("q1"), "{err}");
    }
}
