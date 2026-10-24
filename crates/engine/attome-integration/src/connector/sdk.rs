//! S12-T1: the connector SDK — a connector as a declarative definition, and
//! one runtime that runs any of them.
//!
//! A [`Definition`] is metadata (an integration system's `config.sdk`): the
//! base URL, how calls authenticate (none, a bearer token, basic, an API key
//! header, OAuth client credentials), each endpoint (method, a path
//! template, where the records sit in the answer, how it pages), a rate
//! limit, and a retry policy. Nothing in it is code: the runtime builds
//! every request with the fixed logic below.
//!
//! The runtime ([`fetch_all`]) fills the path template from parameters
//! (each value percent-encoded), adds the credential, pages (by cursor,
//! page number, offset or `Link: rel="next"`) up to [`MAX_PAGES`], keeps to
//! the rate limit, and retries a 429 or 5xx with exponential backoff
//! (honouring `Retry-After`), up to the policy's attempts. Secrets come in
//! as a [`Secret`], whose `Debug` never shows the value; the runtime never
//! logs a header or a body.
//!
//! Calls go through a [`Transport`]: the deployment's is the SSRF-guarded
//! client (`attome_server::ssrf_guard::GuardedClient`); tests use a mock.
//! A custom auth or paging style beyond these is an extension (Y10), not a
//! definition knob.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use attome_types::AppError;
use serde::Deserialize;
use serde_json::Value;

/// The most pages one fetch reads.
pub const MAX_PAGES: usize = 1_000;
/// The most records one fetch returns.
pub const MAX_RECORDS: usize = 200_000;

/// A secret value; its `Debug` and `Display` show nothing of it.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    fn expose(&self) -> &str {
        &self.0
    }

    /// The value, for an adapter of this crate to put on the wire.
    pub(crate) fn wire_value(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// How calls authenticate.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Auth {
    None,
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// `Authorization: Basic base64(<username>:<secret>)`.
    Basic {
        username: String,
    },
    /// `<header>: <secret>`.
    Header {
        header: String,
    },
    /// A token from `token_url` with the client credentials grant
    /// (`client_id` here, the client secret as the secret), as a bearer.
    OauthClientCredentials {
        token_url: String,
        client_id: String,
        #[serde(default)]
        scope: Option<String>,
    },
}

/// How an endpoint pages.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Paging {
    #[default]
    None,
    /// The next cursor at `next` (a JSON pointer) is sent as `param`.
    Cursor { param: String, next: String },
    /// Page numbers from `start` (default 1) in `param`, `size` per page in
    /// `size_param`; a short page is the last.
    Page {
        param: String,
        #[serde(default)]
        size_param: Option<String>,
        size: u32,
        #[serde(default = "one")]
        start: u32,
    },
    /// Record offsets in `param`, `size` per page in `size_param`.
    Offset {
        param: String,
        #[serde(default)]
        size_param: Option<String>,
        size: u32,
    },
    /// The `Link` header's `rel="next"` URL.
    LinkHeader,
}

fn one() -> u32 {
    1
}

/// One endpoint.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Endpoint {
    #[serde(default = "get")]
    pub method: String,
    /// `/customers/{id}/orders`: `{name}` is filled from the parameters.
    pub path: String,
    /// Where the records are (a JSON pointer, `""` for the whole answer).
    #[serde(default)]
    pub records: String,
    #[serde(default)]
    pub paging: Paging,
    /// Fixed query parameters.
    #[serde(default)]
    pub query: BTreeMap<String, String>,
}

fn get() -> String {
    "GET".into()
}

/// Calls per second, and the burst allowed above it.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
pub struct RateLimit {
    pub per_second: f64,
    #[serde(default = "burst")]
    pub burst: u32,
}

fn burst() -> u32 {
    1
}

/// When and how often a call is retried.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct Retry {
    #[serde(default = "attempts")]
    pub max_attempts: u32,
    #[serde(default = "backoff")]
    pub backoff_ms: u64,
}

fn attempts() -> u32 {
    3
}

fn backoff() -> u64 {
    500
}

impl Default for Retry {
    fn default() -> Self {
        Retry {
            max_attempts: attempts(),
            backoff_ms: backoff(),
        }
    }
}

/// A connector, declaratively.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Definition {
    pub name: String,
    pub base_url: String,
    pub auth: Auth,
    pub endpoints: BTreeMap<String, Endpoint>,
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
    #[serde(default)]
    pub retry: Retry,
}

impl Definition {
    /// Reads and checks a definition from an integration system's config
    /// (`config.sdk`).
    pub fn from_config(config: &Value) -> Result<Self, Vec<String>> {
        let def: Definition =
            serde_json::from_value(config["sdk"].clone()).map_err(|e| vec![format!("sdk: {e}")])?;
        def.check()?;
        Ok(def)
    }

    /// Every problem with the definition.
    pub fn check(&self) -> Result<(), Vec<String>> {
        let mut problems = Vec::new();
        match url::Url::parse(&self.base_url) {
            Ok(u) if u.scheme() == "https" || u.scheme() == "http" => {}
            _ => problems.push("base_url is an http(s) URL".to_owned()),
        }
        if self.endpoints.is_empty() {
            problems.push("a connector has at least one endpoint".into());
        }
        for (name, e) in &self.endpoints {
            if !matches!(
                e.method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
            ) {
                problems.push(format!("{name}: method {} is not supported", e.method));
            }
            if !e.path.starts_with('/') {
                problems.push(format!("{name}: path starts with /"));
            }
            if !(e.records.is_empty() || e.records.starts_with('/')) {
                problems.push(format!("{name}: records is a JSON pointer"));
            }
            match &e.paging {
                Paging::Page { size, .. } | Paging::Offset { size, .. } if *size == 0 => {
                    problems.push(format!("{name}: a page size is at least 1"));
                }
                Paging::Cursor { next, .. } if !next.starts_with('/') => {
                    problems.push(format!("{name}: the next cursor is a JSON pointer"));
                }
                _ => {}
            }
        }
        if let Some(limit) = self.rate_limit
            && !(limit.per_second > 0.0 && limit.per_second.is_finite())
        {
            problems.push("rate_limit.per_second is above 0".into());
        }
        if self.retry.max_attempts == 0 || self.retry.max_attempts > 10 {
            problems.push("retry.max_attempts is 1 to 10".into());
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }
}

/// One request the runtime makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// One answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// Sends requests.
pub trait Transport: Send + Sync {
    fn send<'a>(&'a self, request: Request) -> BoxFuture<'a, Response>;
}

/// The deployment's transport: the SSRF-guarded client.
pub struct GuardedTransport(pub attome_server::ssrf_guard::GuardedClient);

impl std::fmt::Debug for GuardedTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardedTransport").finish_non_exhaustive()
    }
}

impl Transport for GuardedTransport {
    fn send<'a>(&'a self, request: Request) -> BoxFuture<'a, Response> {
        Box::pin(async move {
            let url = url::Url::parse(&request.url)
                .map_err(|e| AppError::Validation(format!("connector URL: {e}")))?;
            let method = reqwest::Method::from_bytes(request.method.as_bytes())
                .map_err(|_| AppError::Validation("connector method".into()))?;
            let mut builder = self
                .0
                .request(method, url)
                .map_err(|e| AppError::Validation(format!("connector URL refused: {e}")))?;
            for (name, value) in &request.headers {
                builder = builder.header(name, value);
            }
            if let Some(body) = request.body {
                builder = builder.body(body);
            }
            let built = builder.build().map_err(AppError::internal)?;
            let answer = self
                .0
                .execute(built)
                .await
                .map_err(|e| AppError::internal(format!("connector call failed: {e}")))?;
            let status = answer.status().as_u16();
            let headers = answer
                .headers()
                .iter()
                .filter_map(|(n, v)| {
                    v.to_str()
                        .ok()
                        .map(|v| (n.as_str().to_owned(), v.to_owned()))
                })
                .collect();
            let body = answer.text().await.map_err(AppError::internal)?;
            Ok(Response {
                status,
                headers,
                body,
            })
        })
    }
}

/// Percent-encodes one path or query value.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// The endpoint's path with its `{name}` parameters filled.
pub fn fill_path(path: &str, params: &BTreeMap<String, String>) -> Result<String, AppError> {
    let mut out = String::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..]
            .find('}')
            .ok_or_else(|| AppError::Validation(format!("unclosed parameter in {path}")))?;
        let name = &rest[open + 1..open + close];
        let value = params
            .get(name)
            .ok_or_else(|| AppError::Validation(format!("parameter {name} is required")))?;
        out.push_str(&encode(value));
        rest = &rest[open + close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn with_query(url: &str, query: &[(String, String)]) -> String {
    if query.is_empty() {
        return url.to_owned();
    }
    let joined = query
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    if url.contains('?') {
        format!("{url}&{joined}")
    } else {
        format!("{url}?{joined}")
    }
}

/// The `rel="next"` URL of a `Link` header.
pub fn next_link(header: &str) -> Option<String> {
    header.split(',').find_map(|part| {
        let (url, params) = part.split_once(';')?;
        params
            .split(';')
            .any(|p| p.trim().replace(' ', "") == "rel=\"next\"")
            .then(|| {
                url.trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_owned()
            })
    })
}

fn basic(username: &str, secret: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{secret}"))
    )
}

/// A token bucket over the definition's rate limit.
struct Limiter {
    per_second: f64,
    burst: f64,
    tokens: f64,
    at: tokio::time::Instant,
}

impl Limiter {
    fn new(limit: Option<RateLimit>) -> Option<Self> {
        limit.map(|l| Limiter {
            per_second: l.per_second,
            burst: f64::from(l.burst.max(1)),
            tokens: f64::from(l.burst.max(1)),
            at: tokio::time::Instant::now(),
        })
    }

    async fn take(&mut self) {
        let now = tokio::time::Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * self.per_second)
            .min(self.burst);
        self.at = now;
        if self.tokens < 1.0 {
            let wait = (1.0 - self.tokens) / self.per_second;
            tokio::time::sleep(Duration::from_secs_f64(wait)).await;
            self.tokens = 0.0;
            self.at = tokio::time::Instant::now();
        } else {
            self.tokens -= 1.0;
        }
    }
}

/// The runtime for one definition.
pub struct Runtime<'a> {
    pub definition: &'a Definition,
    pub transport: &'a dyn Transport,
    pub secret: Option<Secret>,
    limiter: Option<Limiter>,
    token: Option<String>,
}

impl std::fmt::Debug for Runtime<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime").finish_non_exhaustive()
    }
}

impl<'a> Runtime<'a> {
    pub fn new(
        definition: &'a Definition,
        transport: &'a dyn Transport,
        secret: Option<Secret>,
    ) -> Self {
        Runtime {
            definition,
            transport,
            secret,
            limiter: Limiter::new(definition.rate_limit),
            token: None,
        }
    }

    fn secret(&self) -> Result<&str, AppError> {
        self.secret
            .as_ref()
            .map(Secret::expose)
            .ok_or_else(|| AppError::Validation("the connector has no credential".into()))
    }

    async fn auth_headers(&mut self) -> Result<Vec<(String, String)>, AppError> {
        // The definition outlives the runtime; borrowing it apart from
        // `self` leaves `self` free for the token call.
        let definition = self.definition;
        Ok(match &definition.auth {
            Auth::None => Vec::new(),
            Auth::Bearer => vec![("Authorization".into(), format!("Bearer {}", self.secret()?))],
            Auth::Basic { username } => {
                vec![("Authorization".into(), basic(username, self.secret()?))]
            }
            Auth::Header { header } => vec![(header.clone(), self.secret()?.to_owned())],
            Auth::OauthClientCredentials {
                token_url,
                client_id,
                scope,
            } => {
                if self.token.is_none() {
                    let mut form = vec![
                        ("grant_type".to_owned(), "client_credentials".to_owned()),
                        ("client_id".to_owned(), client_id.clone()),
                        ("client_secret".to_owned(), self.secret()?.to_owned()),
                    ];
                    if let Some(scope) = scope {
                        form.push(("scope".into(), scope.clone()));
                    }
                    let body = form
                        .iter()
                        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
                        .collect::<Vec<_>>()
                        .join("&");
                    let answer = self
                        .send_with_retry(Request {
                            method: "POST".into(),
                            url: token_url.clone(),
                            headers: vec![(
                                "Content-Type".into(),
                                "application/x-www-form-urlencoded".into(),
                            )],
                            body: Some(body),
                        })
                        .await?;
                    let token: Value = serde_json::from_str(&answer.body)
                        .map_err(|_| AppError::internal("the token endpoint answered no JSON"))?;
                    self.token = Some(
                        token["access_token"]
                            .as_str()
                            .ok_or_else(|| {
                                AppError::internal("the token endpoint gave no access_token")
                            })?
                            .to_owned(),
                    );
                }
                vec![(
                    "Authorization".into(),
                    format!("Bearer {}", self.token.as_deref().unwrap_or_default()),
                )]
            }
        })
    }

    /// Sends `request`, within the rate limit, retrying a 429 or 5xx.
    async fn send_with_retry(&mut self, request: Request) -> Result<Response, AppError> {
        let retry = self.definition.retry;
        let mut attempt = 0;
        loop {
            attempt += 1;
            if let Some(limiter) = &mut self.limiter {
                limiter.take().await;
            }
            let answer = self.transport.send(request.clone()).await;
            let retryable = match &answer {
                Ok(r) => r.status == 429 || r.status >= 500,
                // A request the runtime built wrong is not retried; a
                // network failure is.
                Err(AppError::Validation(_)) => false,
                Err(_) => true,
            };
            if !retryable || attempt >= retry.max_attempts {
                let answer = answer?;
                if answer.status >= 400 {
                    return Err(AppError::internal(format!(
                        "{} answered {}",
                        self.definition.name, answer.status
                    )));
                }
                return Ok(answer);
            }
            let after = answer
                .as_ref()
                .ok()
                .and_then(|r| r.header("retry-after"))
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(|s| Duration::from_secs(s.min(60)));
            let backoff =
                Duration::from_millis(retry.backoff_ms.saturating_mul(1 << (attempt - 1).min(6)));
            tokio::time::sleep(after.unwrap_or(backoff)).await;
        }
    }

    /// Every record of `endpoint`, page after page.
    pub async fn fetch_all(
        &mut self,
        endpoint: &str,
        params: &BTreeMap<String, String>,
    ) -> Result<Vec<Value>, AppError> {
        let e = self
            .definition
            .endpoints
            .get(endpoint)
            .ok_or_else(|| AppError::Validation(format!("no endpoint {endpoint}")))?
            .clone();
        let base = format!(
            "{}{}",
            self.definition.base_url.trim_end_matches('/'),
            fill_path(&e.path, params)?
        );
        let fixed: Vec<(String, String)> = e
            .query
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut records = Vec::new();
        let mut cursor: Option<String> = None;
        let mut page: u64 = match &e.paging {
            Paging::Page { start, .. } => u64::from(*start),
            _ => 0,
        };
        let mut next_url: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut query = fixed.clone();
            match &e.paging {
                Paging::Cursor { param, .. } => {
                    if let Some(c) = &cursor {
                        query.push((param.clone(), c.clone()));
                    }
                }
                Paging::Page {
                    param,
                    size_param,
                    size,
                    ..
                } => {
                    query.push((param.clone(), page.to_string()));
                    if let Some(sp) = size_param {
                        query.push((sp.clone(), size.to_string()));
                    }
                }
                Paging::Offset {
                    param,
                    size_param,
                    size,
                } => {
                    query.push((param.clone(), (page * u64::from(*size)).to_string()));
                    if let Some(sp) = size_param {
                        query.push((sp.clone(), size.to_string()));
                    }
                }
                Paging::None | Paging::LinkHeader => {}
            }
            let url = next_url.take().unwrap_or_else(|| with_query(&base, &query));
            let headers = self.auth_headers().await?;
            let answer = self
                .send_with_retry(Request {
                    method: e.method.clone(),
                    url,
                    headers,
                    body: None,
                })
                .await?;
            let value: Value = serde_json::from_str(&answer.body).map_err(|_| {
                AppError::internal(format!("{} answered no JSON", self.definition.name))
            })?;
            let found = if e.records.is_empty() {
                &value
            } else {
                value.pointer(&e.records).unwrap_or(&Value::Null)
            };
            let batch: Vec<Value> = found.as_array().cloned().unwrap_or_default();
            let got = batch.len();
            records.extend(batch);
            if records.len() > MAX_RECORDS {
                return Err(AppError::Validation(format!(
                    "{} returned more than {MAX_RECORDS} records",
                    self.definition.name
                )));
            }
            let more = match &e.paging {
                Paging::None => false,
                Paging::Cursor { next, .. } => {
                    cursor = value.pointer(next).and_then(|v| match v {
                        Value::String(s) if !s.is_empty() => Some(s.clone()),
                        Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    });
                    cursor.is_some() && got > 0
                }
                Paging::Page { size, .. } | Paging::Offset { size, .. } => {
                    page += 1;
                    got >= *size as usize
                }
                Paging::LinkHeader => {
                    next_url = answer.header("link").and_then(next_link);
                    next_url.is_some()
                }
            };
            if !more {
                return Ok(records);
            }
        }
        Err(AppError::Validation(format!(
            "{} paged more than {MAX_PAGES} times",
            self.definition.name
        )))
    }

    /// S14-T1: one call of `endpoint` with a JSON `body` (a create or an
    /// update in the outside system), within the rate limit and the retry
    /// policy. The answer's JSON, `null` when it has no body. A key, when
    /// given, goes as `Idempotency-Key`, so the outside system can drop a
    /// retried write it already made.
    pub async fn call(
        &mut self,
        endpoint: &str,
        params: &BTreeMap<String, String>,
        body: Option<&Value>,
        idempotency_key: Option<&str>,
    ) -> Result<Value, AppError> {
        let e = self
            .definition
            .endpoints
            .get(endpoint)
            .ok_or_else(|| AppError::Validation(format!("no endpoint {endpoint}")))?
            .clone();
        let query: Vec<(String, String)> = e
            .query
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let url = with_query(
            &format!(
                "{}{}",
                self.definition.base_url.trim_end_matches('/'),
                fill_path(&e.path, params)?
            ),
            &query,
        );
        let mut headers = self.auth_headers().await?;
        if let Some(key) = idempotency_key {
            headers.push(("Idempotency-Key".into(), key.to_owned()));
        }
        let body = match body {
            Some(b) => {
                headers.push(("Content-Type".into(), "application/json".into()));
                Some(serde_json::to_string(b).map_err(AppError::internal)?)
            }
            None => None,
        };
        let answer = self
            .send_with_retry(Request {
                method: e.method.clone(),
                url,
                headers,
                body,
            })
            .await?;
        if answer.body.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&answer.body)
            .map_err(|_| AppError::internal(format!("{} answered no JSON", self.definition.name)))
    }
}

/// Runs `endpoint` of `definition` once over `transport`.
pub async fn fetch_all(
    definition: &Definition,
    transport: &dyn Transport,
    secret: Option<Secret>,
    endpoint: &str,
    params: &BTreeMap<String, String>,
) -> Result<Vec<Value>, AppError> {
    Runtime::new(definition, transport, secret)
        .fetch_all(endpoint, params)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    /// A mock API: answers in order, recording every request.
    struct Mock {
        answers: Mutex<Vec<Response>>,
        seen: Mutex<Vec<Request>>,
    }

    /// A canned answer: status, body and headers.
    type Answer<'a> = (u16, Value, Vec<(&'a str, &'a str)>);

    impl Mock {
        fn new(answers: Vec<Answer<'_>>) -> Self {
            Mock {
                answers: Mutex::new(
                    answers
                        .into_iter()
                        .rev()
                        .map(|(status, body, headers)| Response {
                            status,
                            headers: headers
                                .into_iter()
                                .map(|(n, v)| (n.to_owned(), v.to_owned()))
                                .collect(),
                            body: body.to_string(),
                        })
                        .collect(),
                ),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn urls(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|r| r.url.clone())
                .collect()
        }
    }

    #[tokio::test]
    async fn connector_sdk_call_sends_the_body_and_the_key() {
        let def: Definition = serde_json::from_value(json!({
            "name": "shop",
            "base_url": "https://shop.example",
            "auth": { "kind": "bearer" },
            "endpoints": { "create": { "method": "POST", "path": "/customers/{group}" } }
        }))
        .unwrap();
        let mock = Mock {
            answers: Mutex::new(vec![Response {
                status: 201,
                headers: vec![],
                body: r#"{"id":"c-7"}"#.into(),
            }]),
            seen: Mutex::new(vec![]),
        };
        let params = BTreeMap::from([("group".to_owned(), "vip one".to_owned())]);
        let answer = Runtime::new(&def, &mock, Some(Secret::new("tok")))
            .call(
                "create",
                &params,
                Some(&json!({"name": "Sara"})),
                Some("run:1"),
            )
            .await
            .unwrap();
        assert_eq!(answer, json!({"id": "c-7"}));
        let seen = mock.seen.lock().unwrap();
        assert_eq!(seen[0].url, "https://shop.example/customers/vip%20one");
        assert_eq!(seen[0].body.as_deref(), Some(r#"{"name":"Sara"}"#));
        assert!(
            seen[0]
                .headers
                .contains(&("Idempotency-Key".into(), "run:1".into()))
        );
        assert!(
            seen[0]
                .headers
                .contains(&("Authorization".into(), "Bearer tok".into()))
        );
    }

    impl Transport for Mock {
        fn send<'a>(&'a self, request: Request) -> BoxFuture<'a, Response> {
            self.seen.lock().unwrap().push(request);
            let answer = self.answers.lock().unwrap().pop();
            Box::pin(async move {
                answer.ok_or_else(|| AppError::internal("the mock has no more answers"))
            })
        }
    }

    fn definition(paging: Value, auth: Value) -> Definition {
        Definition::from_config(&json!({ "sdk": {
            "name": "shop",
            "base_url": "https://api.shop.example/v1/",
            "auth": auth,
            "endpoints": {
                "orders": {
                    "path": "/stores/{store}/orders",
                    "records": "/data",
                    "paging": paging,
                    "query": { "status": "paid" }
                }
            },
            "retry": { "max_attempts": 3, "backoff_ms": 1 }
        }}))
        .unwrap()
    }

    fn store() -> BTreeMap<String, String> {
        BTreeMap::from([("store".to_owned(), "riyadh main".to_owned())])
    }

    #[tokio::test]
    async fn connector_sdk_syncs_every_cursor_page_from_a_mock_api() {
        let def = definition(
            json!({ "kind": "cursor", "param": "after", "next": "/next" }),
            json!({ "kind": "bearer" }),
        );
        let mock = Mock::new(vec![
            (
                200,
                json!({ "data": [{ "id": 1 }, { "id": 2 }], "next": "c2" }),
                vec![],
            ),
            (200, json!({ "data": [{ "id": 3 }], "next": null }), vec![]),
        ]);
        let records = fetch_all(&def, &mock, Some(Secret::new("tok")), "orders", &store())
            .await
            .unwrap();
        assert_eq!(records.len(), 3);
        let urls = mock.urls();
        assert_eq!(
            urls,
            vec![
                "https://api.shop.example/v1/stores/riyadh%20main/orders?status=paid",
                "https://api.shop.example/v1/stores/riyadh%20main/orders?status=paid&after=c2",
            ]
        );
        let seen = mock.seen.lock().unwrap();
        assert!(
            seen[0]
                .headers
                .contains(&("Authorization".into(), "Bearer tok".into()))
        );
    }

    #[tokio::test]
    async fn connector_sdk_pages_by_number_and_link_header() {
        let def = definition(
            json!({ "kind": "page", "param": "page", "size_param": "per_page", "size": 2 }),
            json!({ "kind": "header", "header": "X-Api-Key" }),
        );
        let mock = Mock::new(vec![
            (200, json!({ "data": [{ "id": 1 }, { "id": 2 }] }), vec![]),
            (200, json!({ "data": [{ "id": 3 }] }), vec![]),
        ]);
        let records = fetch_all(&def, &mock, Some(Secret::new("k")), "orders", &store())
            .await
            .unwrap();
        assert_eq!(records.len(), 3, "a short page is the last");
        assert!(mock.urls()[1].ends_with("page=2&per_page=2"));

        let def = definition(json!({ "kind": "link_header" }), json!({ "kind": "none" }));
        let mock = Mock::new(vec![
            (
                200,
                json!({ "data": [{ "id": 1 }] }),
                vec![(
                    "Link",
                    "<https://api.shop.example/v1/next?p=2>; rel=\"next\"",
                )],
            ),
            (200, json!({ "data": [{ "id": 2 }] }), vec![]),
        ]);
        let records = fetch_all(&def, &mock, None, "orders", &store())
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(mock.urls()[1], "https://api.shop.example/v1/next?p=2");
    }

    #[tokio::test]
    async fn connector_sdk_retries_429_and_5xx_then_gives_up() {
        let def = definition(json!({ "kind": "none" }), json!({ "kind": "none" }));
        let mock = Mock::new(vec![
            (429, json!({}), vec![("Retry-After", "0")]),
            (503, json!({}), vec![]),
            (200, json!({ "data": [{ "id": 1 }] }), vec![]),
        ]);
        let records = fetch_all(&def, &mock, None, "orders", &store())
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(mock.urls().len(), 3);

        let mock = Mock::new(vec![
            (500, json!({}), vec![]),
            (500, json!({}), vec![]),
            (500, json!({}), vec![]),
        ]);
        let err = fetch_all(&def, &mock, None, "orders", &store())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AppError::Internal(m) if m.contains("answered 500")),
            "{err:?}"
        );
        let mock = Mock::new(vec![(404, json!({}), vec![])]);
        assert!(
            fetch_all(&def, &mock, None, "orders", &store())
                .await
                .is_err()
        );
        assert_eq!(mock.urls().len(), 1, "a 404 is not retried");
    }

    #[tokio::test]
    async fn connector_sdk_oauth_client_credentials_token_once() {
        let def = definition(
            json!({ "kind": "offset", "param": "offset", "size": 1 }),
            json!({ "kind": "oauth_client_credentials", "token_url": "https://id.shop.example/token",
                    "client_id": "attome" }),
        );
        let mock = Mock::new(vec![
            (
                200,
                json!({ "access_token": "at-1", "expires_in": 3600 }),
                vec![],
            ),
            (200, json!({ "data": [{ "id": 1 }] }), vec![]),
            (200, json!({ "data": [] }), vec![]),
        ]);
        let records = fetch_all(&def, &mock, Some(Secret::new("cs")), "orders", &store())
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        let seen = mock.seen.lock().unwrap();
        assert_eq!(seen.len(), 3, "one token call, two pages");
        assert!(
            seen[0]
                .body
                .as_deref()
                .unwrap()
                .contains("client_secret=cs")
        );
        assert!(
            seen[2]
                .headers
                .contains(&("Authorization".into(), "Bearer at-1".into()))
        );
        assert!(seen[2].url.contains("offset=1"));
    }

    #[test]
    fn connector_sdk_definitions_are_checked_and_secrets_hidden() {
        let bad = Definition::from_config(&json!({ "sdk": {
            "name": "x", "base_url": "ftp://x", "auth": { "kind": "none" },
            "endpoints": { "a": { "method": "TRACE", "path": "no-slash",
                                  "paging": { "kind": "page", "param": "p", "size": 0 } } },
            "retry": { "max_attempts": 0 }
        }}))
        .unwrap_err();
        assert_eq!(bad.len(), 5, "{bad:?}");
        assert_eq!(format!("{:?}", Secret::new("hunter2")), "Secret(***)");
        assert!(fill_path("/a/{id}", &BTreeMap::new()).is_err());
        assert_eq!(
            next_link("<https://a/1>; rel=\"prev\", <https://a/3>; rel=\"next\"").as_deref(),
            Some("https://a/3")
        );
    }
}
