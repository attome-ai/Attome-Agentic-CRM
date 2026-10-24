//! Z9-T2: Azure OpenAI behind [`ModelAdapter`]. The wire is the
//! OpenAI-compatible one, so chat and streaming are [`GenerationClient`]'s;
//! what differs is the address and the key. The base URL names the
//! deployment (`https://{resource}.openai.azure.com/openai/deployments/{deployment}`,
//! [`AzureOpenAi::deployment_url`]), every request carries `api-version`, and
//! the key is an `api-key` header or a Microsoft Entra access token as a
//! bearer token.
//!
//! No embeddings: an Azure endpoint is outside the data plane, and external
//! embedding needs an administrator opt-in that does not exist yet (D-506).

use attome_config::InferenceEndpoint;

use super::{AdapterFuture, Caps, ModelAdapter};
use crate::{
    DialClient, EmbedKind, GenerationClient, GenerationRequest, GenerationResult, InferenceError,
    KeyHeader, Transport, Usage,
};

/// The API version requests name unless the deployment sets another.
pub const DEFAULT_API_VERSION: &str = "2024-10-21";

/// How the endpoint's `api_key` is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AzureAuth {
    /// A resource key, in the `api-key` header.
    ApiKey,
    /// A Microsoft Entra access token (scope
    /// `https://cognitiveservices.azure.com/.default`), as a bearer token.
    /// The token expires; whoever holds the endpoint replaces it.
    EntraToken,
}

/// One Azure OpenAI deployment.
#[derive(Clone)]
pub struct AzureOpenAi {
    generation: GenerationClient,
}

impl std::fmt::Debug for AzureOpenAi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureOpenAi")
            .field("model", &self.generation.model_id())
            .finish_non_exhaustive()
    }
}

impl AzureOpenAi {
    /// The base URL of `deployment` on the resource at `resource_url`
    /// (`https://{resource}.openai.azure.com`).
    pub fn deployment_url(resource_url: &str, deployment: &str) -> String {
        format!(
            "{}/openai/deployments/{deployment}",
            resource_url.trim_end_matches('/')
        )
    }

    /// For `endpoint`, whose `base_url` is a deployment URL. Azure is
    /// outside the data plane, so this needs `allow_external`.
    pub fn new(
        endpoint: InferenceEndpoint,
        max_output_tokens: u32,
        allow_external: bool,
        auth: AzureAuth,
        api_version: &str,
    ) -> Result<Self, InferenceError> {
        Ok(Self::over(
            Transport::new(endpoint, "generation", allow_external)?,
            max_output_tokens,
            auth,
            api_version,
        ))
    }

    /// For an endpoint the caller has already decided is reachable, over
    /// its client.
    pub fn for_endpoint(
        endpoint: InferenceEndpoint,
        max_output_tokens: u32,
        http: DialClient,
        auth: AzureAuth,
        api_version: &str,
    ) -> Result<Self, InferenceError> {
        Ok(Self::over(
            Transport::with_client(http, endpoint, "generation")?,
            max_output_tokens,
            auth,
            api_version,
        ))
    }

    fn over(
        transport: Transport,
        max_output_tokens: u32,
        auth: AzureAuth,
        api_version: &str,
    ) -> Self {
        let transport = transport
            .with_key_header(match auth {
                AzureAuth::ApiKey => KeyHeader::Named("api-key"),
                AzureAuth::EntraToken => KeyHeader::Bearer,
            })
            .with_query("api-version", api_version);
        Self {
            generation: GenerationClient::from_transport(transport, max_output_tokens),
        }
    }
}

impl ModelAdapter for AzureOpenAi {
    fn capabilities(&self) -> Caps {
        Caps {
            tools: true,
            streaming: true,
            embeddings: false,
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
        _texts: &'a [&'a str],
        _kind: EmbedKind,
    ) -> AdapterFuture<'a, (Vec<Vec<f32>>, Usage)> {
        Box::pin(async { Err(InferenceError::NotConfigured("embedding")) })
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::testing::{FakeModelServer, Reply, json, sse_event, sse_head};
    use crate::{ChatMessage, FinishReason};

    fn endpoint(server: &FakeModelServer) -> InferenceEndpoint {
        InferenceEndpoint {
            base_url: AzureOpenAi::deployment_url(
                server.base_url().trim_end_matches("/v1"),
                "gpt-chat",
            ),
            model: "gpt-chat".into(),
            api_key: Some("azure-key".into()),
            request_timeout_secs: 5,
        }
    }

    #[tokio::test]
    async fn chat_names_the_deployment_version_and_key() {
        let server = FakeModelServer::start(vec![json(
            "{\"choices\":[{\"message\":{\"content\":\"hi\"},\"finish_reason\":\"stop\"}],\
             \"usage\":{\"prompt_tokens\":3,\"completion_tokens\":1}}",
        )])
        .await;
        let adapter = AzureOpenAi::new(
            endpoint(&server),
            256,
            false,
            AzureAuth::ApiKey,
            DEFAULT_API_VERSION,
        )
        .unwrap();
        let answer = adapter
            .chat(GenerationRequest::new(vec![ChatMessage::user("hello")]))
            .await
            .unwrap();
        assert_eq!(answer.text, "hi");
        let raw = server.last_request().to_ascii_lowercase();
        assert!(
            raw.starts_with(
                "post /openai/deployments/gpt-chat/chat/completions?api-version=2024-10-21 "
            ),
            "{raw}"
        );
        assert!(raw.contains("api-key: azure-key"), "{raw}");
        assert!(!raw.contains("authorization:"), "{raw}");
    }

    #[tokio::test]
    async fn a_streamed_tool_call_with_an_entra_token() {
        let body = [
            sse_event(
                "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\
                 \"type\":\"function\",\"function\":{\"name\":\"weather\",\"arguments\":\"{\\\"city\\\":\"}}]}}]}",
            ),
            sse_event(
                "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\
                 \"function\":{\"arguments\":\"\\\"Abha\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}",
            ),
            sse_event("[DONE]"),
        ]
        .concat();
        let server =
            FakeModelServer::start(vec![Reply::Raw(format!("{}{body}", sse_head()))]).await;
        let adapter = AzureOpenAi::new(
            endpoint(&server),
            256,
            false,
            AzureAuth::EntraToken,
            "2025-01-01-preview",
        )
        .unwrap();
        let mut deltas = String::new();
        let result = adapter
            .chat_stream(
                GenerationRequest::new(vec![ChatMessage::user("weather?")]),
                &mut |d: &str| deltas.push_str(d),
            )
            .await
            .unwrap();
        assert_eq!(result.finish_reason, FinishReason::ToolCalls);
        assert_eq!(result.tool_calls[0].arguments, "{\"city\":\"Abha\"}");
        assert!(deltas.is_empty());
        let raw = server.last_request().to_ascii_lowercase();
        assert!(raw.contains("api-version=2025-01-01-preview"), "{raw}");
        assert!(raw.contains("authorization: bearer azure-key"), "{raw}");
    }
}
