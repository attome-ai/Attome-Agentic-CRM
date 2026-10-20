//! A scripted OpenAI-compatible model server on a real loopback socket
//! (BIN-B1), behind the `test-support` feature.
//!
//! One fake for every consumer: before it, eight test targets across four
//! crates each hand-rolled their own (AUDIT-2026-09-20). It answers requests
//! strictly in order, whatever the path — `/chat/completions`, `/embeddings`
//! and `/models` alike — records every raw request, and counts TCP accepts and
//! peer closes, so a test can assert on bytes and connections rather than on a
//! function's return value.
//!
//! Every reply closes its connection (`Connection: close`), so one request is
//! one accept and a retry is visibly a second one.
//!
//! [`FakeModelServer::recorded`] answers from recordings instead (Z9-T7):
//! each request is matched by the hash of its messages ([`messages_hash`]) to
//! a recorded answer — a completion with its tool calls, or a stream's chunks —
//! kept in a fixture file ([`Recordings::load`]). To record one, run the test
//! against an empty set: the `404` names the hash to record under. With
//! `ATTOME_TEST_NO_NETWORK=1` every inference call to a host other than
//! loopback fails, so no test reaches a real model.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The longest any scripted wait lasts, so a forgotten stall cannot hang a
/// test binary.
const MAX_HOLD: Duration = Duration::from_secs(30);

/// One scripted answer.
#[derive(Debug, Clone)]
pub enum Reply {
    /// Exactly these bytes, then close. Build status lines, redirects,
    /// oversized declarations and garbage with [`http`] or by hand.
    Raw(String),
    /// Never answer; hold the connection open until the client gives up.
    Stall,
    /// These bytes after a pause, then close.
    Delayed(Duration, String),
    /// A response delivered in pieces: each `(pause, bytes)` is written after
    /// its pause. With `hold`, the connection then stays open until the peer
    /// closes it (counted by [`FakeModelServer::peer_close_count`]); without
    /// it, the server closes — a mid-stream close when the pieces stop short.
    Chunks {
        pieces: Vec<(Duration, String)>,
        hold: bool,
    },
}

/// A complete response with `Connection: close` and an exact `Content-Length`.
pub fn http(status: u16, reason: &str, headers: &[(&str, &str)], body: &str) -> Reply {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(body);
    Reply::Raw(out)
}

/// A `200 OK` JSON answer.
pub fn json(body: &str) -> Reply {
    http(200, "OK", &[("Content-Type", "application/json")], body)
}

/// The head of a streamed `200 OK` whose body ends when the connection does.
pub fn sse_head() -> String {
    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/event-stream\r\n\r\n".to_owned()
}

/// One SSE `data:` event carrying `payload`.
pub fn sse_event(payload: &str) -> String {
    format!("data: {payload}\n\n")
}

/// The scripted server. Dropping it does not stop the accept loop; the
/// listener lives until the test's runtime shuts down.
pub struct FakeModelServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    accepts: Arc<AtomicUsize>,
    peer_closes: Arc<AtomicUsize>,
}

impl std::fmt::Debug for FakeModelServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeModelServer")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl FakeModelServer {
    /// Binds `127.0.0.1:0` and answers with `replies` in order; once they run
    /// out, the last one repeats.
    pub async fn start(replies: Vec<Reply>) -> Self {
        Self::serve_script(Script::Ordered(replies)).await
    }

    /// Binds `127.0.0.1:0` and answers each request with the recording whose
    /// [`messages_hash`] matches it, in any order and as often as asked
    /// (Z9-T7); an unmatched request gets a `404` naming its hash.
    pub async fn recorded(recordings: Recordings) -> Self {
        Self::serve_script(Script::Recorded(recordings.recordings)).await
    }

    async fn serve_script(script: Script) -> Self {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => panic!("bind a loopback port: {error}"),
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(error) => panic!("read the loopback address: {error}"),
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let accepts = Arc::new(AtomicUsize::new(0));
        let peer_closes = Arc::new(AtomicUsize::new(0));
        let script = Arc::new(script);
        let cursor = Arc::new(AtomicUsize::new(0));
        let (rq, ac, pc) = (requests.clone(), accepts.clone(), peer_closes.clone());
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                ac.fetch_add(1, Ordering::SeqCst);
                let (rq, pc, script, cursor) =
                    (rq.clone(), pc.clone(), script.clone(), cursor.clone());
                // Each connection on its own task, so a held stream does not
                // block the next accept.
                tokio::spawn(async move {
                    serve(socket, rq, pc, &script, &cursor).await;
                });
            }
        });
        Self {
            addr,
            requests,
            accepts,
            peer_closes,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:{port}/v1`, the shape an `InferenceEndpoint` takes.
    pub fn base_url(&self) -> String {
        format!("http://{}/v1", self.addr)
    }

    /// Every request seen so far, raw (request line, headers, body).
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().map(|r| r.clone()).unwrap_or_default()
    }

    pub fn request_count(&self) -> usize {
        self.requests.lock().map(|r| r.len()).unwrap_or(0)
    }

    pub fn last_request(&self) -> String {
        self.requests().pop().unwrap_or_default()
    }

    /// TCP connections accepted, including ones that never sent a request.
    pub fn accept_count(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// Held streams the client closed ([`Reply::Chunks`] with `hold`).
    pub fn peer_close_count(&self) -> usize {
        self.peer_closes.load(Ordering::SeqCst)
    }
}

/// How a server picks its answers.
enum Script {
    /// In order, the last repeating.
    Ordered(Vec<Reply>),
    /// By the request's [`messages_hash`] (Z9-T7).
    Recorded(Vec<Recording>),
}

async fn serve(
    mut socket: tokio::net::TcpStream,
    requests: Arc<Mutex<Vec<String>>>,
    peer_closes: Arc<AtomicUsize>,
    script: &Script,
    cursor: &AtomicUsize,
) {
    let Some(raw) = read_request(&mut socket).await else {
        return;
    };
    let reply = match script {
        Script::Ordered(replies) => {
            let index = cursor.fetch_add(1, Ordering::SeqCst);
            replies.get(index).or_else(|| replies.last()).cloned()
        }
        Script::Recorded(recordings) => Some(recorded_reply(&raw, recordings)),
    };
    if let Ok(mut seen) = requests.lock() {
        seen.push(raw);
    }
    match reply.as_ref() {
        Some(Reply::Raw(bytes)) => {
            let _ = socket.write_all(bytes.as_bytes()).await;
        }
        Some(Reply::Stall) => tokio::time::sleep(MAX_HOLD).await,
        Some(Reply::Delayed(pause, bytes)) => {
            tokio::time::sleep(*pause).await;
            let _ = socket.write_all(bytes.as_bytes()).await;
        }
        Some(Reply::Chunks { pieces, hold }) => {
            for (pause, bytes) in pieces {
                tokio::time::sleep(*pause).await;
                if socket.write_all(bytes.as_bytes()).await.is_err()
                    || socket.flush().await.is_err()
                {
                    peer_closes.fetch_add(1, Ordering::SeqCst);
                    return;
                }
            }
            if *hold {
                let mut probe = [0u8; 64];
                if let Ok(Ok(0) | Err(_)) =
                    tokio::time::timeout(MAX_HOLD, socket.read(&mut probe)).await
                {
                    peer_closes.fetch_add(1, Ordering::SeqCst);
                }
                return;
            }
        }
        None => {}
    }
    let _ = socket.flush().await;
    let _ = socket.shutdown().await;
}

/// Reads one request: headers, then `Content-Length` bytes of body.
async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut header_end: Option<usize> = None;
    let mut content_length = 0usize;
    loop {
        let n = match socket.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        if header_end.is_none()
            && let Some(pos) = find(&buf, b"\r\n\r\n")
        {
            header_end = Some(pos + 4);
            content_length = content_length_of(&buf[..pos]);
        }
        if let Some(end) = header_end
            && buf.len() >= end + content_length
        {
            break;
        }
    }
    (!buf.is_empty()).then(|| String::from_utf8_lossy(&buf).into_owned())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn content_length_of(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0)
}

// ── Recorded answers (Z9-T7) ────────────────────────────────────────────────

/// One recorded model answer, matched to a request by the hash of its
/// `messages` ([`messages_hash`]), so a test answers the same conversation
/// the same way whatever order it asks in.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Recording {
    /// [`messages_hash`] of the request this answers.
    pub messages_hash: String,
    /// The JSON body of a non-streamed answer: a chat completion, tool calls
    /// included, or an embeddings response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
    /// The `data:` payloads of a streamed answer, in order; `[DONE]` is sent
    /// after them. Answers a request with `"stream": true`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stream: Vec<serde_json::Value>,
}

/// A fixture file: `{"recordings": [Recording, ...]}`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Recordings {
    pub recordings: Vec<Recording>,
}

impl Recordings {
    /// Reads a fixture file; panics with the path on a missing or malformed
    /// file, since a test cannot run without its recordings.
    pub fn load(path: impl AsRef<std::path::Path>) -> Self {
        let path = path.as_ref();
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => panic!("read recordings {}: {error}", path.display()),
        };
        match serde_json::from_str(&text) {
            Ok(recordings) => recordings,
            Err(error) => panic!("parse recordings {}: {error}", path.display()),
        }
    }
}

/// The key a request is matched by: FNV-1a 64 over the compact JSON of its
/// `messages` (`input` for an embeddings request), as 16 hex digits. Stable
/// across runs and platforms; not a security hash.
pub fn messages_hash(request: &serde_json::Value) -> String {
    let key = request
        .get("messages")
        .or_else(|| request.get("input"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.to_string().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// The answer to `raw` (a whole HTTP request) from `recordings`: the
/// recorded JSON or stream, or a `404` naming the unmatched hash so the test
/// author can record it.
fn recorded_reply(raw: &str, recordings: &[Recording]) -> Reply {
    let body = raw.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    let request: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let hash = messages_hash(&request);
    let streamed = request
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let found = recordings.iter().find(|r| {
        r.messages_hash == hash
            && if streamed {
                !r.stream.is_empty()
            } else {
                r.response.is_some()
            }
    });
    match found {
        Some(recording) if streamed => {
            let mut out = sse_head();
            for chunk in &recording.stream {
                out.push_str(&sse_event(&chunk.to_string()));
            }
            out.push_str(&sse_event("[DONE]"));
            Reply::Raw(out)
        }
        Some(recording) => json(
            &recording
                .response
                .as_ref()
                .map(serde_json::Value::to_string)
                .unwrap_or_default(),
        ),
        None => http(
            404,
            "Not Found",
            &[("Content-Type", "application/json")],
            &serde_json::json!({
                "error": format!(
                    "no recorded answer for messages_hash {hash} (stream: {streamed})"
                )
            })
            .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "test helpers: a failed setup step should panic with its message"
    )]

    use super::*;
    use crate::{ChatMessage, GenerationClient, GenerationRequest};
    use attome_config::{InferenceEndpoint, InferenceSection};

    fn client(server: &FakeModelServer) -> GenerationClient {
        GenerationClient::new(&InferenceSection {
            generation: InferenceEndpoint {
                base_url: server.base_url(),
                model: "test-model".into(),
                request_timeout_secs: 5,
                ..InferenceEndpoint::default()
            },
            ..InferenceSection::default()
        })
        .expect("a loopback generation client")
    }

    fn request() -> GenerationRequest {
        GenerationRequest::new(vec![
            ChatMessage::system("You look up accounts."),
            ChatMessage::user("Find Acme"),
        ])
    }

    /// The record step: an empty fake refuses with a 404, and the request it
    /// saw gives the hash to record the answer under.
    async fn hash_of_request(stream: bool) -> String {
        let server = FakeModelServer::recorded(Recordings::default()).await;
        let client = client(&server);
        if stream {
            let _ = client
                .generate_stream(request(), |_| {}, std::future::pending::<()>())
                .await;
        } else {
            let _ = client.generate(request()).await;
        }
        let raw = server.last_request();
        let body = raw.split_once("\r\n\r\n").expect("a request body").1;
        messages_hash(&serde_json::from_str(body).expect("a JSON request"))
    }

    #[tokio::test]
    async fn fake_model_answers_a_recorded_tool_call() {
        let hash = hash_of_request(false).await;
        let server = FakeModelServer::recorded(Recordings {
            recordings: vec![Recording {
                messages_hash: hash,
                response: Some(serde_json::json!({
                    "id": "rec-1",
                    "object": "chat.completion",
                    "model": "test-model",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_1",
                                "type": "function",
                                "function": { "name": "lookup_account", "arguments": "{\"name\":\"Acme\"}" }
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": { "prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19 }
                })),
                stream: Vec::new(),
            }],
        })
        .await;
        let result = client(&server)
            .generate(request())
            .await
            .expect("the recorded answer");
        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].name, "lookup_account");
        assert_eq!(result.tool_calls[0].arguments, "{\"name\":\"Acme\"}");
        // The same conversation is answered the same way again.
        let again = client(&server).generate(request()).await.expect("again");
        assert_eq!(again.tool_calls, result.tool_calls);
    }

    #[tokio::test]
    async fn fake_model_streams_recorded_chunks() {
        let hash = hash_of_request(true).await;
        let server = FakeModelServer::recorded(Recordings {
            recordings: vec![Recording {
                messages_hash: hash,
                response: None,
                stream: vec![
                    serde_json::json!({"choices":[{"index":0,"delta":{"content":"Acme "}}]}),
                    serde_json::json!({"choices":[{"index":0,"delta":{"content":"found"}}]}),
                    serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
                ],
            }],
        })
        .await;
        let mut deltas = Vec::new();
        let result = client(&server)
            .generate_stream(
                request(),
                |delta| deltas.push(delta.to_owned()),
                std::future::pending::<()>(),
            )
            .await
            .expect("the recorded stream");
        assert_eq!(result.text, "Acme found");
        assert_eq!(deltas, vec!["Acme ".to_owned(), "found".to_owned()]);
    }

    #[tokio::test]
    async fn fake_model_refuses_an_unrecorded_request_naming_its_hash() {
        let server = FakeModelServer::recorded(Recordings::default()).await;
        assert!(client(&server).generate(request()).await.is_err());
        let raw = server.last_request();
        let body = raw.split_once("\r\n\r\n").expect("a request body").1;
        let hash = messages_hash(&serde_json::from_str(body).expect("a JSON request"));
        let Reply::Raw(reply) = recorded_reply(&raw, &[]) else {
            panic!("a 404 reply");
        };
        assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
        assert!(reply.contains(&hash), "{reply}");
    }

    #[test]
    fn fake_model_hash_ignores_everything_but_the_messages() {
        let a = serde_json::json!({"model": "a", "messages": [{"role": "user", "content": "hi"}]});
        let b = serde_json::json!({"model": "b", "temperature": 0.2, "messages": [{"role": "user", "content": "hi"}]});
        let c =
            serde_json::json!({"model": "a", "messages": [{"role": "user", "content": "hello"}]});
        assert_eq!(messages_hash(&a), messages_hash(&b));
        assert_ne!(messages_hash(&a), messages_hash(&c));
        assert_eq!(messages_hash(&a).len(), 16);
    }

    #[test]
    fn fake_model_recordings_load_from_a_fixture_file() {
        let dir = std::env::temp_dir().join(format!("attome-z9t7-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("recordings.json");
        let fixtures = Recordings {
            recordings: vec![Recording {
                messages_hash: "0123456789abcdef".into(),
                response: Some(serde_json::json!({"ok": true})),
                stream: Vec::new(),
            }],
        };
        std::fs::write(&path, serde_json::to_string(&fixtures).expect("JSON")).expect("write");
        assert_eq!(Recordings::load(&path).recordings, fixtures.recordings);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fake_model_no_network_refuses_a_real_host_only() {
        let real = reqwest::Url::parse("https://api.openai.com/v1").expect("url");
        let loopback = reqwest::Url::parse("http://127.0.0.1:9/v1").expect("url");
        let localhost = reqwest::Url::parse("http://localhost:9/v1").expect("url");
        assert!(crate::test_network_guard(&real, "generation", true).is_err());
        assert!(crate::test_network_guard(&loopback, "generation", true).is_ok());
        assert!(crate::test_network_guard(&localhost, "generation", true).is_ok());
        assert!(crate::test_network_guard(&real, "generation", false).is_ok());
    }
}
