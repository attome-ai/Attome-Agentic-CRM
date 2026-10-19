//! Z9-T1: one provider-neutral way to call a model. A [`ModelAdapter`]
//! answers a chat request (whole, or streamed delta by delta) and embeds
//! texts, and says what it can do ([`Caps`]). The request and answer are this
//! crate's own [`GenerationRequest`] and [`GenerationResult`]: messages, tool
//! definitions and calls, tool choice, usage and finish reason, none of them
//! tied to one provider's wire format.
//!
//! [`OpenAiCompatible`] is today's client behind the trait: the OpenAI-shaped
//! `/chat/completions` and `/embeddings` that every configured model server
//! speaks. It delegates to [`GenerationClient`] and [`EmbeddingClient`]
//! unchanged, so behaviour (budgets, retries, timeouts, telemetry) is exactly
//! theirs. Other providers implement the same trait.

use std::future::Future;
use std::pin::Pin;

use attome_config::InferenceSection;

use crate::{
    EmbedKind, EmbeddingClient, GenerationClient, GenerationRequest, GenerationResult,
    InferenceError, Usage,
};

/// A boxed future, so the trait stays object safe without a macro.
pub type AdapterFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, InferenceError>> + Send + 'a>>;

/// What an adapter can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Caps {
    /// Chat with tool definitions and tool calls.
    pub tools: bool,
    /// Streamed chat, delta by delta.
    pub streaming: bool,
    /// Embeddings.
    pub embeddings: bool,
}

/// A model provider, called the same way whatever it is.
pub trait ModelAdapter: Send + Sync + std::fmt::Debug {
    /// What this adapter supports.
    fn capabilities(&self) -> Caps;

    /// One chat completion, whole.
    fn chat(&self, request: GenerationRequest) -> AdapterFuture<'_, GenerationResult>;

    /// One chat completion, each text delta passed to `on_delta` as it
    /// arrives; the whole result at the end.
    fn chat_stream<'a>(
        &'a self,
        request: GenerationRequest,
        on_delta: &'a mut (dyn FnMut(&str) + Send),
    ) -> AdapterFuture<'a, GenerationResult>;

    /// Embeddings of `texts`, in their order.
    fn embed<'a>(
        &'a self,
        texts: &'a [&'a str],
        kind: EmbedKind,
    ) -> AdapterFuture<'a, (Vec<Vec<f32>>, Usage)>;
}

/// The OpenAI-compatible model servers (vLLM, llama.cpp, Ollama, the hosted
/// APIs): today's generation and embedding clients behind the trait.
#[derive(Debug)]
pub struct OpenAiCompatible {
    generation: GenerationClient,
    embedding: EmbeddingClient,
}

impl OpenAiCompatible {
    /// Both clients from the inference configuration.
    pub fn new(section: &InferenceSection) -> Result<Self, InferenceError> {
        Ok(Self {
            generation: GenerationClient::new(section)?,
            embedding: EmbeddingClient::new(section)?,
        })
    }

    /// From clients already built.
    pub fn from_clients(generation: GenerationClient, embedding: EmbeddingClient) -> Self {
        Self {
            generation,
            embedding,
        }
    }
}

impl ModelAdapter for OpenAiCompatible {
    fn capabilities(&self) -> Caps {
        Caps {
            tools: true,
            streaming: true,
            embeddings: true,
        }
    }

    fn chat(&self, request: GenerationRequest) -> AdapterFuture<'_, GenerationResult> {
        Box::pin(self.generation.generate(request))
    }

    fn chat_stream<'a>(
        &'a self,
        request: GenerationRequest,
        on_delta: &'a mut (dyn FnMut(&str) + Send),
    ) -> AdapterFuture<'a, GenerationResult> {
        Box::pin(self.generation.generate_stream(
            request,
            |delta: &str| on_delta(delta),
            std::future::pending::<()>(),
        ))
    }

    fn embed<'a>(
        &'a self,
        texts: &'a [&'a str],
        kind: EmbedKind,
    ) -> AdapterFuture<'a, (Vec<Vec<f32>>, Usage)> {
        Box::pin(self.embedding.embed(texts, kind))
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::ChatMessage;
    use crate::testing::{FakeModelServer, json};
    use attome_config::InferenceEndpoint;

    fn section(server: &FakeModelServer) -> InferenceSection {
        let base = server.base_url();
        InferenceSection {
            generation: InferenceEndpoint {
                base_url: base.clone(),
                model: "test-model".into(),
                request_timeout_secs: 5,
                ..InferenceEndpoint::default()
            },
            embedding: InferenceEndpoint {
                base_url: base,
                model: "bge-m3".into(),
                request_timeout_secs: 5,
                ..InferenceEndpoint::default()
            },
            ..InferenceSection::default()
        }
    }

    #[tokio::test]
    async fn chat_and_embed_go_through_the_adapter() {
        let server = FakeModelServer::start(vec![
            json(
                "{\"choices\":[{\"message\":{\"content\":\"hi\"},\"finish_reason\":\"stop\"}],\
                 \"usage\":{\"prompt_tokens\":3,\"completion_tokens\":1}}",
            ),
            json("{\"data\":[{\"index\":0,\"embedding\":[0.5,0.25]}],\"usage\":{\"prompt_tokens\":4}}"),
        ])
        .await;
        let adapter: Box<dyn ModelAdapter> =
            Box::new(OpenAiCompatible::new(&section(&server)).unwrap());
        assert!(adapter.capabilities().tools && adapter.capabilities().embeddings);

        let answer = adapter
            .chat(GenerationRequest::new(vec![ChatMessage::user("hello")]))
            .await
            .unwrap();
        assert_eq!(answer.text, "hi");

        let (vectors, _) = adapter.embed(&["hi"], EmbedKind::Query).await.unwrap();
        assert_eq!(vectors, vec![vec![0.5, 0.25]]);
        assert_eq!(server.request_count(), 2);
    }
}
