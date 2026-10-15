//! Server-side CAPTCHA verification (D-588 item 2: portal signup).
//!
//! Fails closed: with a provider configured, a missing token, a timeout, a
//! transport error or an unparseable answer is a refusal, never a pass. With
//! no provider configured (`CaptchaProvider::None`), every call passes; the
//! caller's other controls (budgets, verification before creation) still
//! apply.

use std::time::Duration;

use attome_config::{CaptchaConfig, CaptchaProvider};
use serde::Deserialize;

const TURNSTILE_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const HCAPTCHA_URL: &str = "https://api.hcaptcha.com/siteverify";

#[derive(Deserialize)]
struct SiteVerify {
    success: bool,
}

/// Whether the CAPTCHA `token` a client sent is valid.
pub async fn verify(config: &CaptchaConfig, token: Option<&str>, remote_ip: Option<&str>) -> bool {
    let url = match config.provider {
        CaptchaProvider::None => return true,
        CaptchaProvider::Turnstile => TURNSTILE_URL,
        CaptchaProvider::Hcaptcha => HCAPTCHA_URL,
    };
    verify_at(url, config, token, remote_ip).await
}

/// [`verify`] against `url`, so tests can point it at a local endpoint.
async fn verify_at(
    url: &str,
    config: &CaptchaConfig,
    token: Option<&str>,
    remote_ip: Option<&str>,
) -> bool {
    let Some(token) = token.filter(|t| !t.trim().is_empty()) else {
        return false;
    };
    let mut form = vec![("secret", config.secret.expose()), ("response", token)];
    if let Some(ip) = remote_ip {
        form.push(("remoteip", ip));
    }
    // BAU-6 (findings BAU-F3/F10): the shared, process-lifetime client — which
    // carries a connect timeout, a whole-request ceiling and
    // `redirect(Policy::none())` — instead of a fresh `reqwest::Client::new()`
    // per call (no connect timeout at all). One timeout covers the send *and*
    // the body; the previous shape gave each its own, so a provider that
    // answered its headers and then stalled held the caller for twice the
    // configured budget. Errors are stripped of their URL (the endpoint is a
    // constant here, but nothing about this path should carry one).
    let client = crate::oidc::http_client();
    let call = async {
        let response = client
            .post(url)
            .form(&form)
            .send()
            .await
            .map_err(|e| e.without_url())?;
        response
            .json::<SiteVerify>()
            .await
            .map_err(|e| e.without_url())
    };
    match tokio::time::timeout(Duration::from_millis(config.timeout_ms.max(1)), call).await {
        Ok(Ok(v)) => v.success,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "captcha: provider call failed; refusing");
            false
        }
        Err(_) => {
            tracing::warn!("captcha: provider call timed out; refusing");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_provider_passes_and_a_configured_one_needs_a_token() {
        let none = CaptchaConfig::default();
        assert!(verify(&none, None, None).await);
        let turnstile = CaptchaConfig {
            provider: CaptchaProvider::Turnstile,
            secret: "s".into(),
            timeout_ms: 50,
        };
        assert!(!verify(&turnstile, None, None).await);
        assert!(!verify(&turnstile, Some("  "), None).await);
    }

    // ── BAU-18 (F10): the provider paths, against a local endpoint ──────────

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn configured(timeout_ms: u64) -> CaptchaConfig {
        CaptchaConfig {
            provider: CaptchaProvider::Turnstile,
            secret: "captcha-test-secret".into(),
            timeout_ms,
        }
    }

    /// Serves one canned HTTP response per connection, or holds every
    /// connection open without answering when `response` is `None`.
    async fn endpoint(response: Option<String>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a local endpoint");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let response = response.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let _ = socket.read(&mut buf).await;
                    match response {
                        Some(body) => {
                            let _ = socket.write_all(body.as_bytes()).await;
                            let _ = socket.shutdown().await;
                        }
                        None => tokio::time::sleep(Duration::from_secs(30)).await,
                    }
                });
            }
        });
        format!("http://{addr}/siteverify")
    }

    fn http(status: &str, extra_headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}
content-type: application/json
{extra_headers}content-length: {}
connection: close

{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn a_provider_success_passes() {
        let url = endpoint(Some(http("200 OK", "", r#"{"success":true}"#))).await;
        assert!(verify_at(&url, &configured(2000), Some("token"), Some("203.0.113.9")).await);
    }

    #[tokio::test]
    async fn a_provider_refusal_is_refused() {
        let url = endpoint(Some(http(
            "200 OK",
            "",
            r#"{"success":false,"error-codes":["invalid-input-response"]}"#,
        )))
        .await;
        assert!(!verify_at(&url, &configured(2000), Some("token"), None).await);
    }

    #[tokio::test]
    async fn a_stalled_provider_is_refused_within_the_timeout() {
        let url = endpoint(None).await;
        let started = std::time::Instant::now();
        assert!(!verify_at(&url, &configured(300), Some("token"), None).await);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the timeout bounds the call, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_non_json_answer_is_refused() {
        let url = endpoint(Some(http("200 OK", "", "<html>not json</html>"))).await;
        assert!(!verify_at(&url, &configured(2000), Some("token"), None).await);
    }

    #[tokio::test]
    async fn a_refused_connection_is_refused() {
        assert!(
            !verify_at(
                "http://127.0.0.1:1/siteverify",
                &configured(2000),
                Some("token"),
                None
            )
            .await
        );
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let success = endpoint(Some(http("200 OK", "", r#"{"success":true}"#))).await;
        let url = endpoint(Some(http(
            "307 Temporary Redirect",
            &format!(
                "location: {success}
"
            ),
            "",
        )))
        .await;
        assert!(!verify_at(&url, &configured(2000), Some("token"), None).await);
    }
}
