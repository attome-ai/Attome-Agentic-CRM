//! Reranking (roadmap N15-T1): a cross-encoder scores each candidate passage
//! against the question, so the strongest passages come first after the
//! lexical and vector legs are fused.
//!
//! The server is text-embeddings-inference's `POST {base_url}/rerank`
//! (`{"query", "texts"}` in, `[{"index", "score"}]` out), the same TEI
//! process family the embeddings use, with a reranker model such as
//! `BAAI/bge-reranker-v2-m3`. Like embeddings, the endpoint must be inside the
//! deployment: the passages are customer data. At most [`MAX_TEXTS`] passages
//! of at most [`MAX_TEXT_CHARS`] characters go in one call.

use attome_config::InferenceSection;
use serde::{Deserialize, Serialize};

use crate::{InferenceError, Transport};

/// The rerank path, relative to the endpoint's `base_url`.
pub const RERANK_PATH: &str = "/rerank";
/// The most passages scored in one call.
pub const MAX_TEXTS: usize = 64;
/// Each passage is cut to this many characters.
pub const MAX_TEXT_CHARS: usize = 2_000;

#[derive(Serialize)]
struct RerankRequest<'a> {
    query: &'a str,
    texts: Vec<String>,
    truncate: bool,
}

#[derive(Deserialize)]
struct Scored {
    index: usize,
    score: f32,
}

/// A rerank client over `inference.rerank`.
#[derive(Clone)]
pub struct RerankClient {
    transport: Transport,
}

impl std::fmt::Debug for RerankClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RerankClient").finish_non_exhaustive()
    }
}

impl RerankClient {
    pub fn new(section: &InferenceSection) -> Result<Self, InferenceError> {
        Ok(Self {
            transport: Transport::new(section.rerank.clone(), "rerank", false)?,
        })
    }

    pub fn model_id(&self) -> &str {
        self.transport.model()
    }

    /// One score per text, in the caller's order (higher is more relevant).
    /// A response that skips, repeats or invents an index is refused.
    pub async fn rerank(&self, query: &str, texts: &[&str]) -> Result<Vec<f32>, InferenceError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        if texts.len() > MAX_TEXTS {
            return Err(InferenceError::Misconfigured {
                endpoint: "rerank",
                reason: "too many passages for one rerank call",
            });
        }
        let started = std::time::Instant::now();
        let request = RerankRequest {
            query,
            texts: texts
                .iter()
                .map(|t| t.chars().take(MAX_TEXT_CHARS).collect())
                .collect(),
            truncate: true,
        };
        let result = self
            .transport
            .post::<_, Vec<Scored>>(RERANK_PATH, &request)
            .await
            .and_then(|scored| aligned(scored, texts.len()));
        crate::telemetry::record("rerank", started, &result);
        result
    }
}

/// The scores in input order, or a bad response when an index is missing,
/// repeated or out of range.
fn aligned(scored: Vec<Scored>, len: usize) -> Result<Vec<f32>, InferenceError> {
    let bad = |reason| InferenceError::BadResponse {
        endpoint: "rerank",
        reason,
    };
    let mut out: Vec<Option<f32>> = vec![None; len];
    for s in scored {
        let slot = out
            .get_mut(s.index)
            .ok_or(bad("rerank index out of range"))?;
        if slot.is_some() {
            return Err(bad("rerank index repeated"));
        }
        if !s.score.is_finite() {
            return Err(bad("rerank score is not a number"));
        }
        *slot = Some(s.score);
    }
    out.into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(bad("rerank response skipped a passage"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_come_back_in_input_order() {
        let scored = vec![
            Scored {
                index: 1,
                score: 0.9,
            },
            Scored {
                index: 0,
                score: 0.1,
            },
        ];
        assert_eq!(aligned(scored, 2).unwrap(), vec![0.1, 0.9]);
        assert!(
            aligned(
                vec![Scored {
                    index: 0,
                    score: 0.5
                }],
                2
            )
            .is_err()
        );
        assert!(
            aligned(
                vec![Scored {
                    index: 2,
                    score: 0.5
                }],
                2
            )
            .is_err()
        );
        assert!(
            aligned(
                vec![
                    Scored {
                        index: 0,
                        score: 0.5
                    },
                    Scored {
                        index: 0,
                        score: 0.4
                    }
                ],
                1
            )
            .is_err()
        );
    }
}
