//! Embeddings — TODO-028's batch-by-contract client.
//!
//! `AiService::embed` (the seam this supersedes) took one text and returned
//! one vector. Against a GPU that is an N+1 (guidelines §14): embedding a
//! thousand records meant a thousand round trips, each paying full request
//! overhead for work the accelerator would have done in one pass. **The batch
//! is the contract here, not an optimisation a caller may skip** — the API
//! takes a slice and there is no single-text entry point to reach for.
//!
//! Embedding is a pure function of its input, so a transient failure is worth
//! replaying: a TEI or vLLM restart used to fail the drain's whole batch of 32
//! and a query embedding outright. D-645 (BIN-D1) bounds that at two retries
//! for connect/429/502/503/504, inside the request deadline — through the
//! endpoint's outbound service since AB6-T3, which also gives it a breaker —
//! and generation is deliberately excluded, because replaying it can mint new
//! tool-call ids (D-553).

use attome_config::InferenceSection;
use serde::{Deserialize, Serialize};

use crate::{InferenceError, Transport, Usage};

/// The embeddings path, relative to an endpoint's `base_url`. Public for the
/// same reason as [`crate::generate::CHAT_COMPLETIONS_PATH`].
pub const EMBEDDINGS_PATH: &str = "/embeddings";

/// Whether the text being embedded is a query or a document.
///
/// BGE-M3 (the search plan's chosen embedding model) does not need asymmetric
/// prefixes, but E5 and Qwen3 do, and the trait must outlive one model choice.
/// Embedding a query with the document prefix silently degrades recall — it
/// does not error — so this is exactly the kind of mistake that must be
/// impossible to make by omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbedKind {
    Query,
    Document,
}

impl EmbedKind {
    /// The prefix this endpoint expects for this kind of text.
    ///
    /// An explicit `query_prefix`/`document_prefix` in the endpoint's own
    /// configuration wins outright (BIN-D6): recall loss becomes impossible by
    /// configuration, whatever the model is called. Otherwise the family
    /// heuristic applies, and it is **case-insensitive** — `Qwen3-Embedding-0.6B`
    /// needs the prefix every bit as much as the lowercase spelling does, and
    /// the old case-sensitive substring match handed the first one none
    /// (BIN-G5/F14).
    fn prefix<'a>(self, model: &str, explicit: Option<&'a str>) -> &'a str {
        if let Some(prefix) = explicit {
            return prefix;
        }
        let model = model.to_ascii_lowercase();
        let needs_prefix = model.contains("e5") || model.contains("qwen");
        match (needs_prefix, self) {
            (false, _) => "",
            (true, EmbedKind::Query) => "query: ",
            (true, EmbedKind::Document) => "passage: ",
        }
    }
}
#[derive(Serialize)]
struct EmbeddingRequest<'a> {
    model: &'a str,
    input: Vec<String>,
}

#[derive(Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
    #[serde(default)]
    usage: Option<ResponseUsage>,
}

#[derive(Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
    #[serde(default)]
    index: usize,
}

#[derive(Deserialize, Default)]
struct ResponseUsage {
    #[serde(default)]
    prompt_tokens: u32,
}

/// Cheap to clone (BIN-FX1); see [`crate::GenerationClient`].
#[derive(Clone)]
pub struct EmbeddingClient {
    transport: Transport,
    /// `inference.embedding_query_prefix`, when the operator set one.
    query_prefix: Option<String>,
    /// `inference.embedding_document_prefix`, when the operator set one.
    document_prefix: Option<String>,
}

impl std::fmt::Debug for EmbeddingClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingClient")
            .field("query_prefix", &self.query_prefix)
            .field("document_prefix", &self.document_prefix)
            .finish_non_exhaustive()
    }
}

impl EmbeddingClient {
    pub fn new(section: &InferenceSection) -> Result<Self, InferenceError> {
        Ok(Self {
            query_prefix: section.embedding_query_prefix.clone(),
            document_prefix: section.embedding_document_prefix.clone(),
            // D-506, local-only phase: an embedding endpoint must be inside the
            // deployment whatever `allow_external_provider` says, because
            // external embedding needs an administrator opt-in that does not
            // exist yet. Boot validation refuses the same configuration; this
            // is the transport-level half of that rule.
            transport: Transport::new(section.embedding.clone(), "embedding", false)?,
        })
    }

    pub fn model_id(&self) -> &str {
        self.transport.model()
    }

    /// Embeds a batch. One HTTP call per attempt, whatever the batch size.
    ///
    /// Results are returned in the **caller's input order**, not the server's
    /// response order: the OpenAI-compatible schema carries an `index` per
    /// item and does not promise to preserve ordering. A caller that zipped
    /// the response against its own input would mis-attribute every vector on
    /// a server that reorders — a defect that produces plausible-looking
    /// nonsense rather than an error, so it is corrected here once instead of
    /// being a rule every caller has to remember.
    pub async fn embed(
        &self,
        texts: &[&str],
        kind: EmbedKind,
    ) -> Result<(Vec<Vec<f32>>, Usage), InferenceError> {
        if texts.is_empty() {
            return Ok((Vec::new(), Usage::default()));
        }
        let started = std::time::Instant::now();
        let result = self.embed_once(texts, kind).await;
        crate::telemetry::record("embedding", started, &result);
        result
    }

    async fn embed_once(
        &self,
        texts: &[&str],
        kind: EmbedKind,
    ) -> Result<(Vec<Vec<f32>>, Usage), InferenceError> {
        let explicit = match kind {
            EmbedKind::Query => self.query_prefix.as_deref(),
            EmbedKind::Document => self.document_prefix.as_deref(),
        };
        let prefix = kind.prefix(self.transport.model(), explicit);
        let input: Vec<String> = texts.iter().map(|t| format!("{prefix}{t}")).collect();
        let request = EmbeddingRequest {
            model: self.transport.model(),
            input,
        };

        // AB6-T3: replayed through the endpoint's outbound service (D-645:
        // an embedding is a pure function of its input).
        let response: EmbeddingResponse = self
            .transport
            .post_idempotent(EMBEDDINGS_PATH, &request)
            .await?;

        if response.data.len() != texts.len() {
            return Err(InferenceError::BadResponse {
                endpoint: self.transport.label(),
                reason: "embedding count did not match the input count",
            });
        }

        let mut ordered: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
        for item in response.data {
            let slot = ordered
                .get_mut(item.index)
                .ok_or(InferenceError::BadResponse {
                    endpoint: self.transport.label(),
                    reason: "embedding index out of range",
                })?;
            if slot.is_some() {
                return Err(InferenceError::BadResponse {
                    endpoint: self.transport.label(),
                    reason: "embedding index repeated",
                });
            }
            *slot = Some(item.embedding);
        }

        let vectors =
            ordered
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .ok_or(InferenceError::BadResponse {
                    endpoint: self.transport.label(),
                    reason: "embedding response skipped an index",
                })?;

        validate_vectors(&vectors, self.transport.label())?;

        let usage = Usage {
            model_id: self.transport.model().to_owned(),
            reported: response.usage.is_some(),
            prompt_tokens: response.usage.unwrap_or_default().prompt_tokens,
            completion_tokens: 0,
            cached_prompt_tokens: None,
        };
        Ok((vectors, usage))
    }
}

/// Refuses vectors a downstream consumer cannot use.
///
/// A ragged batch (different dimensions) or a vector carrying `NaN`/infinity
/// is not a model answer, and quietly handing it on turns a transport fault
/// into a pgvector reject or a silently broken similarity score. Checking here
/// costs one pass over data already in memory (BIN-C2).
fn validate_vectors(vectors: &[Vec<f32>], label: &'static str) -> Result<(), InferenceError> {
    let mut expected: Option<usize> = None;
    for vector in vectors {
        if vector.is_empty() {
            return Err(InferenceError::BadResponse {
                endpoint: label,
                reason: "embedding vector was empty",
            });
        }
        match expected {
            None => expected = Some(vector.len()),
            Some(len) if len != vector.len() => {
                return Err(InferenceError::BadResponse {
                    endpoint: label,
                    reason: "embedding dimensions were ragged",
                });
            }
            Some(_) => {}
        }
        if vector.iter().any(|value| !value.is_finite()) {
            return Err(InferenceError::BadResponse {
                endpoint: label,
                reason: "embedding vector carried a non-finite value",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BGE-M3 is symmetric; E5 and Qwen3 are not. Getting this wrong degrades
    /// recall silently, which is why it lives in one place.
    #[test]
    fn prefixes_are_applied_only_for_model_families_that_need_them() {
        assert_eq!(EmbedKind::Query.prefix("bge-m3", None), "");
        assert_eq!(EmbedKind::Document.prefix("bge-m3", None), "");
        assert_eq!(
            EmbedKind::Query.prefix("multilingual-e5-large", None),
            "query: "
        );
        assert_eq!(
            EmbedKind::Document.prefix("multilingual-e5-large", None),
            "passage: "
        );
        assert_eq!(
            EmbedKind::Query.prefix("qwen3-embedding-0.6b", None),
            "query: "
        );
    }

    /// **BIN-G5/F14.** The model id an operator writes in a config file is
    /// whatever the serving process calls itself, and case is not part of the
    /// contract. `Qwen3-Embedding-0.6B` needs the prefix exactly as much as the
    /// lowercase spelling does.
    #[test]
    fn the_family_match_is_case_insensitive() {
        assert_eq!(
            EmbedKind::Query.prefix("Qwen3-Embedding-0.6B", None),
            "query: "
        );
        assert_eq!(
            EmbedKind::Document.prefix("Qwen3-Embedding-0.6B", None),
            "passage: "
        );
        assert_eq!(
            EmbedKind::Query.prefix("intfloat/Multilingual-E5-Large", None),
            "query: "
        );
        assert_eq!(EmbedKind::Query.prefix("BGE-M3", None), "");
    }

    /// BIN-D6: an explicit prefix in configuration overrides the heuristic in
    /// both directions — including for a model family the heuristic would
    /// otherwise prefix.
    #[test]
    fn an_explicit_configured_prefix_wins_over_the_heuristic() {
        assert_eq!(
            EmbedKind::Query.prefix("bge-m3", Some("search_query: ")),
            "search_query: "
        );
        assert_eq!(
            EmbedKind::Document.prefix("bge-m3", Some("")),
            "",
            "an empty explicit prefix must mean 'none', not 'fall back'"
        );
        assert_eq!(
            EmbedKind::Query.prefix("qwen3-embedding-0.6b", Some("")),
            "",
            "an explicit empty prefix disables the heuristic's prefix"
        );
    }

    /// BIN-C2: a model answer a consumer cannot use is refused here rather than
    /// becoming a pgvector reject or a silently wrong similarity score.
    #[test]
    fn ragged_empty_and_non_finite_vectors_are_refused() {
        assert!(validate_vectors(&[vec![0.1, 0.2], vec![0.3, 0.4]], "embedding").is_ok());
        for bad in [
            vec![vec![0.1, 0.2], vec![0.3]],
            vec![vec![]],
            vec![vec![0.1, f32::NAN]],
            vec![vec![0.1, f32::INFINITY]],
        ] {
            assert!(
                matches!(
                    validate_vectors(&bad, "embedding"),
                    Err(InferenceError::BadResponse { .. })
                ),
                "{bad:?} must be refused"
            );
        }
    }

    /// The API takes a slice. This is the compile-time half of batch-by-
    /// contract — there is no single-text entry point to reach for, so a
    /// caller cannot reintroduce the N+1 by accident. The assertion is that
    /// this function compiles at all; adding an `embed_one(&str)` would not
    /// break it, but adding one is a visible act and this is where the reason
    /// not to is written down.
    #[allow(dead_code)]
    async fn _batch_is_the_only_entry_point(
        client: &EmbeddingClient,
        texts: &[&str],
    ) -> Result<(Vec<Vec<f32>>, Usage), InferenceError> {
        client.embed(texts, EmbedKind::Document).await
    }

    /// D-506: an external embedding endpoint is refused even when external
    /// providers are allowed for generation.
    #[test]
    fn an_external_embedding_endpoint_is_refused_even_when_external_is_allowed() {
        let external = InferenceSection {
            allow_external_provider: true,
            embedding: attome_config::InferenceEndpoint {
                base_url: "https://api.example.com/v1".into(),
                model: "bge-m3".into(),
                ..attome_config::InferenceEndpoint::default()
            },
            ..InferenceSection::default()
        };
        assert!(matches!(
            EmbeddingClient::new(&external),
            Err(InferenceError::ExternalProviderForbidden("embedding"))
        ));

        let local = InferenceSection {
            embedding: attome_config::InferenceEndpoint {
                base_url: "http://127.0.0.1:8088/v1".into(),
                model: "bge-m3".into(),
                ..attome_config::InferenceEndpoint::default()
            },
            ..InferenceSection::default()
        };
        assert!(EmbeddingClient::new(&local).is_ok());
    }
}
