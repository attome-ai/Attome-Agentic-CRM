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
        let replies = Arc::new(replies);
        let cursor = Arc::new(AtomicUsize::new(0));
        let (rq, ac, pc) = (requests.clone(), accepts.clone(), peer_closes.clone());
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                ac.fetch_add(1, Ordering::SeqCst);
                let (rq, pc, replies, cursor) =
                    (rq.clone(), pc.clone(), replies.clone(), cursor.clone());
                // Each connection on its own task, so a held stream does not
                // block the next accept.
                tokio::spawn(async move {
                    serve(socket, rq, pc, &replies, &cursor).await;
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

async fn serve(
    mut socket: tokio::net::TcpStream,
    requests: Arc<Mutex<Vec<String>>>,
    peer_closes: Arc<AtomicUsize>,
    replies: &[Reply],
    cursor: &AtomicUsize,
) {
    let Some(raw) = read_request(&mut socket).await else {
        return;
    };
    if let Ok(mut seen) = requests.lock() {
        seen.push(raw);
    }
    let index = cursor.fetch_add(1, Ordering::SeqCst);
    match replies.get(index).or_else(|| replies.last()) {
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
