//! Trackers (roadmap D22-T4): a tracker (`call_tracker`) names something to
//! listen for in calls — a competitor, a pricing question — by exact terms
//! and by example phrases. A transcript is split into chunks of up to three
//! sentences; a chunk hits a tracker when one of its exact terms appears in
//! it (Arabic and English, compared after Arabic normalisation and case
//! folding), else when the chunk's embedding is close enough to one of the
//! tracker's example embeddings.
//!
//! The embeddings come from the caller (the inference engine); this module
//! only compares vectors, so it is testable with fixed ones.

use attome_rules::arabic::normalize_ar;
use serde::Serialize;
use uuid::Uuid;

use super::talk::Segment;

/// Cosine similarity at or above which a chunk means the same as an example.
pub const MEANING_THRESHOLD: f32 = 0.80;

/// The most sentences one chunk holds.
pub const SENTENCES_PER_CHUNK: usize = 3;

/// One tracker, ready to match.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledTracker {
    pub id: Uuid,
    pub version: i64,
    /// Exact terms, already normalised.
    pub terms: Vec<String>,
    /// One embedding per example phrase.
    pub example_vectors: Vec<Vec<f32>>,
}

/// Every active tracker, and the newest tracker version they were built
/// from (a cache keyed by it is rebuilt when a tracker changes).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CompiledTrackers {
    pub version: i64,
    pub trackers: Vec<CompiledTracker>,
}

/// One tracker as loaded: id, version, exact terms and example vectors.
pub type TrackerRow = (Uuid, i64, Vec<String>, Vec<Vec<f32>>);

impl CompiledTrackers {
    /// Builds the set from `(id, version, exact terms, example vectors)`.
    pub fn build(rows: Vec<TrackerRow>) -> Self {
        let version = rows.iter().map(|r| r.1).max().unwrap_or(0);
        let trackers = rows
            .into_iter()
            .map(|(id, version, terms, example_vectors)| CompiledTracker {
                id,
                version,
                terms: terms
                    .iter()
                    .map(|t| normalise(t))
                    .filter(|t| !t.is_empty())
                    .collect(),
                example_vectors,
            })
            .collect();
        Self { version, trackers }
    }
}

/// How a chunk hit a tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HitKind {
    ExactTerm,
    Meaning,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrackerHit {
    pub tracker: Uuid,
    pub kind: HitKind,
    /// 1.0 for an exact term, the cosine similarity for a meaning hit.
    pub score: f32,
}

/// A transcript chunk with its time span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub text: String,
    pub start_ms: u64,
    pub end_ms: u64,
}

fn normalise(s: &str) -> String {
    normalize_ar(s)
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

/// The trackers `chunk_text` hits: an exact term first, otherwise the best
/// example similarity at or above [`MEANING_THRESHOLD`]. `chunk_vec` is the
/// chunk's embedding, when one was computed.
pub fn match_chunk(
    compiled: &CompiledTrackers,
    chunk_text: &str,
    chunk_vec: Option<&[f32]>,
) -> Vec<TrackerHit> {
    let text = format!(" {} ", normalise(chunk_text));
    let mut hits = Vec::new();
    for tracker in &compiled.trackers {
        if tracker
            .terms
            .iter()
            .any(|term| text.contains(&format!(" {term} ")))
        {
            hits.push(TrackerHit {
                tracker: tracker.id,
                kind: HitKind::ExactTerm,
                score: 1.0,
            });
            continue;
        }
        let Some(vec) = chunk_vec else { continue };
        let best = tracker
            .example_vectors
            .iter()
            .map(|e| cosine(vec, e))
            .fold(f32::MIN, f32::max);
        if best >= MEANING_THRESHOLD {
            hits.push(TrackerHit {
                tracker: tracker.id,
                kind: HitKind::Meaning,
                score: best,
            });
        }
    }
    hits
}

/// Splits each segment's text into sentences (`.`, `?`, `!`, the Arabic
/// question mark and full stop) and groups up to [`SENTENCES_PER_CHUNK`] of
/// them; a chunk keeps its segment's time span.
pub fn chunk_transcript(segments: &[Segment]) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    for segment in segments {
        let mut sentences = Vec::new();
        let mut current = String::new();
        for c in segment.text.chars() {
            current.push(c);
            if matches!(c, '.' | '?' | '!' | '\u{061F}' | '\u{06D4}') {
                let s = current.trim().to_owned();
                if !s.is_empty() {
                    sentences.push(s);
                }
                current.clear();
            }
        }
        let rest = current.trim();
        if !rest.is_empty() {
            sentences.push(rest.to_owned());
        }
        for group in sentences.chunks(SENTENCES_PER_CHUNK) {
            chunks.push(Chunk {
                text: group.join(" "),
                start_ms: segment.start_ms,
                end_ms: segment.end_ms,
            });
        }
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::super::talk::Speaker;
    use super::*;

    fn trackers() -> CompiledTrackers {
        CompiledTrackers::build(vec![
            (
                Uuid::from_u128(1),
                3,
                vec!["أسعار".into(), "Acme Corp".into()],
                vec![vec![1.0, 0.0, 0.0]],
            ),
            (Uuid::from_u128(2), 5, vec![], vec![vec![0.0, 1.0, 0.0]]),
        ])
    }

    #[test]
    fn exact_arabic_term_matches_after_normalisation() {
        let compiled = trackers();
        assert_eq!(compiled.version, 5);
        // "اسعار" without the hamza still hits "أسعار".
        let hits = match_chunk(&compiled, "ما هي اسعار الباقات؟", None);
        assert_eq!(
            hits,
            vec![TrackerHit {
                tracker: Uuid::from_u128(1),
                kind: HitKind::ExactTerm,
                score: 1.0
            }]
        );
        let hits = match_chunk(&compiled, "We also looked at ACME corp last year.", None);
        assert_eq!(hits.len(), 1);
        assert!(
            match_chunk(&compiled, "acmecorp", None).is_empty(),
            "whole words only"
        );
    }

    #[test]
    fn meaning_match_uses_threshold() {
        let compiled = trackers();
        let near = [0.1, 0.95, 0.0];
        let hits = match_chunk(&compiled, "nothing exact here", Some(&near));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].tracker, Uuid::from_u128(2));
        assert_eq!(hits[0].kind, HitKind::Meaning);
        let far = [0.7, 0.7, 0.2];
        assert!(match_chunk(&compiled, "nothing exact here", Some(&far)).is_empty());
    }

    #[test]
    fn transcripts_split_into_three_sentence_chunks() {
        let segment = Segment {
            speaker: Speaker::Customer,
            start_ms: 0,
            end_ms: 9000,
            text: "One. Two? Three! Four. هل لديكم خصم؟".into(),
        };
        let chunks = chunk_transcript(&[segment]);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].text, "One. Two? Three!");
        assert_eq!(chunks[1].text, "Four. هل لديكم خصم؟");
        assert_eq!(chunks[1].end_ms, 9000);
    }
}
