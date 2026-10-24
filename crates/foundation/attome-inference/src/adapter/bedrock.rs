//! Z9-T2: Amazon Bedrock's Converse API (`POST /model/{id}/converse`) behind
//! [`ModelAdapter`], each request signed with AWS Signature Version 4.
//!
//! The base URL is the region's runtime endpoint
//! (`https://bedrock-runtime.{region}.amazonaws.com`) and the endpoint's
//! `model` is the Bedrock model id. Credentials are passed in
//! ([`AwsCredentials`]); the signature is made here over the exact bytes sent,
//! with `sha2` and `hmac`, so nothing new is linked.
//!
//! Streaming: Bedrock's `ConverseStream` answers in AWS's binary event-stream
//! framing, which this adapter does not read. A streamed call runs as one
//! whole call and hands the text over as one delta; [`Caps::streaming`] says
//! so.

use attome_config::{InferenceEndpoint, Secret};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{AdapterFuture, Caps, ModelAdapter};
use crate::{
    DialClient, EmbedKind, FinishReason, GenerationRequest, GenerationResult, InferenceError,
    KeyHeader, Role, ToolCall, ToolChoice, Transport, Usage,
};

/// The service name requests are signed for.
const SERVICE: &str = "bedrock";

/// An AWS access key, with the session token of temporary credentials.
#[derive(Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: Secret,
    pub session_token: Option<Secret>,
}

impl std::fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

/// One Bedrock model in one region.
#[derive(Clone)]
pub struct Bedrock {
    transport: Transport,
    region: String,
    credentials: AwsCredentials,
    max_output_tokens: u32,
}

impl std::fmt::Debug for Bedrock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bedrock")
            .field("model", &self.transport.model())
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl Bedrock {
    /// For `endpoint` in `region`. Bedrock is outside the data plane, so
    /// this needs `allow_external`.
    pub fn new(
        endpoint: InferenceEndpoint,
        region: &str,
        credentials: AwsCredentials,
        max_output_tokens: u32,
        allow_external: bool,
    ) -> Result<Self, InferenceError> {
        Ok(Self {
            transport: Transport::new(endpoint, "generation", allow_external)?
                .with_key_header(KeyHeader::None),
            region: region.to_owned(),
            credentials,
            max_output_tokens,
        })
    }

    /// For an endpoint the caller has already decided is reachable, over
    /// its client.
    pub fn for_endpoint(
        endpoint: InferenceEndpoint,
        region: &str,
        credentials: AwsCredentials,
        max_output_tokens: u32,
        http: DialClient,
    ) -> Result<Self, InferenceError> {
        Ok(Self {
            transport: Transport::with_client(http, endpoint, "generation")?
                .with_key_header(KeyHeader::None),
            region: region.to_owned(),
            credentials,
            max_output_tokens,
        })
    }

    async fn chat_once(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationResult, InferenceError> {
        let max_tokens = request
            .max_output_tokens
            .unwrap_or(self.max_output_tokens)
            .min(self.max_output_tokens);
        let path = format!(
            "/model/{}/converse",
            uri_encode(self.transport.model(), true)
        );
        let body = serde_json::to_vec(&to_wire(&request, max_tokens)).map_err(|_| {
            InferenceError::BadResponse {
                endpoint: self.transport.label(),
                reason: "request could not be serialised",
            }
        })?;
        let headers = sign(
            "POST",
            &self.transport.url(&path),
            "application/json",
            &body,
            &self.region,
            &self.credentials,
            Utc::now(),
        );
        let response: ConverseResponse = self.transport.post_signed(&path, body, headers).await?;
        Ok(response.into_result(self.transport.model()))
    }
}

impl ModelAdapter for Bedrock {
    fn capabilities(&self) -> Caps {
        Caps {
            tools: true,
            streaming: false,
            embeddings: false,
        }
    }

    fn chat(&self, request: GenerationRequest) -> AdapterFuture<'_, GenerationResult> {
        Box::pin(async move {
            let started = std::time::Instant::now();
            let result = self.chat_once(request).await;
            crate::telemetry::record("generation", started, &result);
            result
        })
    }

    fn chat_stream<'a>(
        &'a self,
        request: GenerationRequest,
        on_delta: &'a mut (dyn FnMut(&str) + Send),
    ) -> AdapterFuture<'a, GenerationResult> {
        Box::pin(async move {
            let result = self.chat(request).await?;
            if !result.text.is_empty() {
                on_delta(&result.text);
            }
            Ok(result)
        })
    }

    fn embed<'a>(
        &'a self,
        _texts: &'a [&'a str],
        _kind: EmbedKind,
    ) -> AdapterFuture<'a, (Vec<Vec<f32>>, Usage)> {
        Box::pin(async { Err(InferenceError::NotConfigured("embedding")) })
    }
}

/// The Converse request for `request`.
pub(crate) fn to_wire(request: &GenerationRequest, max_tokens: u32) -> Value {
    let mut system: Vec<Value> = Vec::new();
    let mut turns: Vec<(&'static str, Vec<Value>)> = Vec::new();
    for message in &request.messages {
        let (role, blocks) = match message.role {
            Role::System => {
                if !message.content.is_empty() {
                    system.push(json!({"text": message.content}));
                }
                continue;
            }
            Role::User => ("user", text_block(&message.content)),
            Role::Assistant => {
                let mut blocks = text_block(&message.content);
                for call in &message.tool_calls {
                    let input = serde_json::from_str::<Value>(&call.arguments)
                        .ok()
                        .filter(Value::is_object)
                        .unwrap_or_else(|| json!({}));
                    blocks.push(json!({"toolUse": {
                        "toolUseId": call.id, "name": call.name, "input": input
                    }}));
                }
                ("assistant", blocks)
            }
            Role::Tool => (
                "user",
                vec![json!({"toolResult": {
                    "toolUseId": message.tool_call_id.clone().unwrap_or_default(),
                    "content": [{"text": message.content}],
                }})],
            ),
        };
        if blocks.is_empty() {
            continue;
        }
        match turns.last_mut() {
            Some((last, existing)) if *last == role => existing.extend(blocks),
            _ => turns.push((role, blocks)),
        }
    }
    let mut body = json!({
        "messages": turns
            .into_iter()
            .map(|(role, content)| json!({"role": role, "content": content}))
            .collect::<Vec<_>>(),
        "inferenceConfig": {"maxTokens": max_tokens, "temperature": request.temperature},
    });
    if !system.is_empty() {
        body["system"] = Value::Array(system);
    }
    // Converse has no "no tools" choice: a turn that must not call one is
    // sent without them.
    if !request.tools.is_empty() && request.tool_choice != ToolChoice::None {
        body["toolConfig"] = json!({
            "tools": request.tools.iter().map(|t| json!({"toolSpec": {
                "name": t.name,
                "description": t.description,
                "inputSchema": {"json": t.parameters},
            }})).collect::<Vec<_>>(),
            "toolChoice": if request.tool_choice == ToolChoice::Required {
                json!({"any": {}})
            } else {
                json!({"auto": {}})
            },
        });
    }
    body
}

fn text_block(text: &str) -> Vec<Value> {
    if text.is_empty() {
        Vec::new()
    } else {
        vec![json!({"text": text})]
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConverseResponse {
    output: Option<Output>,
    stop_reason: Option<String>,
    usage: Option<WireUsage>,
}

#[derive(Deserialize)]
struct Output {
    message: Option<OutputMessage>,
}

#[derive(Deserialize)]
struct OutputMessage {
    #[serde(default)]
    content: Vec<Value>,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
struct WireUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
    cache_read_input_tokens: Option<u32>,
}

impl ConverseResponse {
    fn into_result(self, model: &str) -> GenerationResult {
        let mut text = String::new();
        let mut tool_calls = Vec::new();
        let blocks = self
            .output
            .and_then(|o| o.message)
            .map(|m| m.content)
            .unwrap_or_default();
        for block in blocks {
            if let Some(t) = block.get("text").and_then(Value::as_str) {
                text.push_str(t);
            } else if let Some(call) = block.get("toolUse") {
                let field = |name: &str| {
                    call.get(name)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                tool_calls.push(ToolCall {
                    id: field("toolUseId"),
                    name: field("name"),
                    arguments: call
                        .get("input")
                        .filter(|v| !v.is_null())
                        .map_or_else(|| "{}".to_owned(), Value::to_string),
                });
            }
        }
        let finish_reason = match self.stop_reason.as_deref() {
            Some("end_turn" | "stop_sequence") => FinishReason::Stop,
            Some("tool_use") => FinishReason::ToolCalls,
            Some("max_tokens") => FinishReason::Length,
            Some("guardrail_intervened" | "content_filtered") => FinishReason::ContentFilter,
            Some(other) => FinishReason::Other(other.to_owned()),
            None if !tool_calls.is_empty() => FinishReason::ToolCalls,
            None => FinishReason::Stop,
        };
        GenerationResult {
            truncated: finish_reason == FinishReason::Length,
            text,
            usage: Usage {
                model_id: model.to_owned(),
                prompt_tokens: self.usage.map_or(0, |u| u.input_tokens),
                completion_tokens: self.usage.map_or(0, |u| u.output_tokens),
                reported: self.usage.is_some(),
                cached_prompt_tokens: self.usage.and_then(|u| u.cache_read_input_tokens),
            },
            tool_calls,
            finish_reason,
        }
    }
}

/// RFC 3986 percent-encoding as SigV4 wants it: unreserved characters kept,
/// everything else `%XX` in upper case; `/` kept only when `encode_slash` is
/// false.
fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    // HMAC takes a key of any length; this cannot fail.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// The SigV4 headers (`x-amz-date`, the session token when there is one,
/// and `authorization`) for a request with these parts. `host` and
/// `content-type` are signed and sent as they are.
pub(crate) fn sign(
    method: &str,
    url: &reqwest::Url,
    content_type: &str,
    body: &[u8],
    region: &str,
    credentials: &AwsCredentials,
    now: DateTime<Utc>,
) -> Vec<(String, String)> {
    sign_for(
        SERVICE,
        method,
        url,
        content_type,
        body,
        region,
        credentials,
        now,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the parts of one signed request; the service is a parameter only for the test vector"
)]
fn sign_for(
    service: &str,
    method: &str,
    url: &reqwest::Url,
    content_type: &str,
    body: &[u8],
    region: &str,
    credentials: &AwsCredentials,
    now: DateTime<Utc>,
) -> Vec<(String, String)> {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let host = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_owned(),
    };
    // Non-S3 services sign the path encoded once more.
    let canonical_uri = url
        .path()
        .split('/')
        .map(|segment| uri_encode(segment, true))
        .collect::<Vec<_>>()
        .join("/");
    let mut query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (uri_encode(&k, true), uri_encode(&v, true)))
        .collect();
    query.sort();
    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let mut headers: Vec<(&str, String)> = vec![
        ("content-type", content_type.to_owned()),
        ("host", host),
        ("x-amz-date", amz_date.clone()),
    ];
    if let Some(token) = &credentials.session_token {
        headers.push(("x-amz-security-token", token.expose().to_owned()));
    }
    let canonical_headers: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();
    let signed_headers = headers
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{}",
        sha256_hex(body)
    );
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac(
        format!("AWS4{}", credentials.secret_access_key.expose()).as_bytes(),
        &date,
    );
    let k_region = hmac(&k_date, region);
    let k_service = hmac(&k_region, service);
    let k_signing = hmac(&k_service, "aws4_request");
    let signature = hex::encode(hmac(&k_signing, &string_to_sign));

    let mut out = vec![("x-amz-date".to_owned(), amz_date)];
    if let Some(token) = &credentials.session_token {
        out.push(("x-amz-security-token".to_owned(), token.expose().to_owned()));
    }
    out.push((
        "authorization".to_owned(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            credentials.access_key_id
        ),
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChatMessage, ToolDefinition};

    fn example_credentials() -> AwsCredentials {
        AwsCredentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    /// AWS's own worked example ("Create a signed AWS API request", IAM
    /// ListUsers, 2015-08-30).
    #[test]
    fn signature_matches_aws_s_worked_example() {
        let url =
            reqwest::Url::parse("https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")
                .unwrap();
        let now = "2015-08-30T12:36:00Z".parse().unwrap();
        let headers = sign_for(
            "iam",
            "GET",
            &url,
            "application/x-www-form-urlencoded; charset=utf-8",
            b"",
            "us-east-1",
            &example_credentials(),
            now,
        );
        assert_eq!(headers[0], ("x-amz-date".into(), "20150830T123600Z".into()));
        assert_eq!(
            headers[1].1,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn a_model_id_is_encoded_in_the_path_and_signed_encoded_twice() {
        assert_eq!(
            uri_encode("anthropic.claude-v2:1", true),
            "anthropic.claude-v2%3A1"
        );
        let url = reqwest::Url::parse(
            "https://bedrock-runtime.me-central-1.amazonaws.com/model/anthropic.claude-v2%3A1/converse",
        )
        .unwrap();
        let mut creds = example_credentials();
        creds.session_token = Some("session".into());
        let headers = sign(
            "POST",
            &url,
            "application/json",
            b"{}",
            "me-central-1",
            &creds,
            Utc::now(),
        );
        assert_eq!(
            headers[1],
            ("x-amz-security-token".into(), "session".into())
        );
        assert!(headers[2].1.contains(
            "/me-central-1/bedrock/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token,"
        ));
    }

    #[test]
    fn converse_shapes_tools_and_results() {
        let request = GenerationRequest::new(vec![
            ChatMessage::system("Be brief."),
            ChatMessage::user("Weather?"),
            ChatMessage::assistant_tool_calls(
                "",
                vec![ToolCall {
                    id: "t1".into(),
                    name: "weather".into(),
                    arguments: "{\"city\":\"Tabuk\"}".into(),
                }],
            ),
            ChatMessage::tool_result("t1", "18C"),
        ])
        .with_tools(vec![ToolDefinition {
            name: "weather".into(),
            description: "Weather".into(),
            parameters: json!({"type": "object"}),
        }]);
        let wire = to_wire(&request, 128);
        assert_eq!(wire["system"][0]["text"], "Be brief.");
        assert_eq!(wire["inferenceConfig"]["maxTokens"], 128);
        assert_eq!(wire["toolConfig"]["toolChoice"], json!({"auto": {}}));
        assert_eq!(
            wire["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"]["json"]["type"],
            "object"
        );
        assert_eq!(
            wire["messages"][1]["content"][0]["toolUse"]["input"]["city"],
            "Tabuk"
        );
        assert_eq!(
            wire["messages"][2]["content"][0]["toolResult"]["toolUseId"],
            "t1"
        );

        let response: ConverseResponse = serde_json::from_value(json!({
            "output": {"message": {"role": "assistant", "content": [
                {"text": "One moment."},
                {"toolUse": {"toolUseId": "t2", "name": "weather", "input": {"city": "Hail"}}}
            ]}},
            "stopReason": "tool_use",
            "usage": {"inputTokens": 30, "outputTokens": 9}
        }))
        .unwrap();
        let result = response.into_result("anthropic.claude");
        assert_eq!(result.text, "One moment.");
        assert_eq!(result.finish_reason, FinishReason::ToolCalls);
        assert_eq!(result.tool_calls[0].arguments, "{\"city\":\"Hail\"}");
        assert_eq!(result.usage.prompt_tokens, 30);
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn chat_is_signed_and_a_stream_is_one_delta() {
        use crate::testing::{FakeModelServer, json as reply};
        let server = FakeModelServer::start(vec![reply(
            "{\"output\":{\"message\":{\"content\":[{\"text\":\"marhaba\"}]}},\
             \"stopReason\":\"end_turn\",\"usage\":{\"inputTokens\":4,\"outputTokens\":2}}",
        )])
        .await;
        let endpoint = InferenceEndpoint {
            base_url: server.base_url().trim_end_matches("/v1").to_owned(),
            model: "amazon.nova-pro-v1:0".into(),
            request_timeout_secs: 5,
            ..InferenceEndpoint::default()
        };
        let adapter =
            Bedrock::new(endpoint, "us-east-1", example_credentials(), 256, false).unwrap();
        assert!(!adapter.capabilities().streaming);
        let mut deltas = Vec::new();
        let result = adapter
            .chat_stream(
                GenerationRequest::new(vec![ChatMessage::user("hello")]),
                &mut |d: &str| deltas.push(d.to_owned()),
            )
            .await
            .unwrap();
        assert_eq!(result.text, "marhaba");
        assert_eq!(deltas, vec!["marhaba"]);
        let raw = server.last_request().to_ascii_lowercase();
        assert!(
            raw.starts_with("post /model/amazon.nova-pro-v1%3a0/converse "),
            "{raw}"
        );
        assert!(
            raw.contains("authorization: aws4-hmac-sha256 credential=akidexample/"),
            "{raw}"
        );
        assert!(raw.contains("x-amz-date: "), "{raw}");
    }
}
