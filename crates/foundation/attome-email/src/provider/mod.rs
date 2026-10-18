//! Z8-T1: where an email goes out. One [`EmailProvider`] per way out: SMTP
//! (the relay in `config.email`, the default), Amazon SES (its v2 HTTPS API,
//! signed with SigV4) and SendGrid (its v3 mail send). Which one a message
//! takes is chosen per sender identity: `email.providers.by_sender` maps a
//! From address to a provider, and every other address takes
//! `email.providers.default` (SMTP when unset).
//!
//! Every provider reports through the same [`SendError`] classes, so the job
//! handler's retry rules and the D-661 suppression rule do not change with
//! the provider: a refused credential is `Config`, a throttle or a server
//! error is `Transient`, a rejected message is `Permanent` (never
//! recipient-attributable: SES and SendGrid report bounces later, not in the
//! send answer), and a request that may have reached the provider before it
//! failed is `Unknown`, never retried.

use std::future::Future;
use std::sync::OnceLock;
use std::time::Duration;

use attome_config::EmailSection;
use lettre::Message;
use lettre::message::Mailbox;

use crate::error::SendError;
use crate::message::EmailMessage;

pub mod sendgrid;
pub mod ses;
pub mod smtp;

/// The provider names `email.providers` accepts.
pub const SMTP: &str = "smtp";
pub const SES: &str = "ses";
pub const SENDGRID: &str = "sendgrid";

/// What the provider called the accepted message, when it says.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProviderMessageId(pub Option<String>);

/// One message ready to leave: the producer's message, its built MIME form,
/// and the resolved sender and recipient (the catch-all in test mode).
pub struct OutgoingEmail<'a> {
    pub message: &'a EmailMessage,
    pub mime: &'a Message,
    pub from: &'a Mailbox,
    pub to: &'a Mailbox,
    /// The real recipient, when test mode sent the message to the catch-all.
    pub original_to: Option<&'a str>,
}

/// One way out.
pub trait EmailProvider {
    fn name(&self) -> &str;
    fn send(
        &self,
        msg: &OutgoingEmail<'_>,
    ) -> impl Future<Output = Result<ProviderMessageId, SendError>> + Send;
}

/// The provider a message from `from_address` takes.
pub enum Provider<'a> {
    Smtp(smtp::Smtp<'a>),
    Ses(ses::Ses<'a>),
    SendGrid(sendgrid::SendGrid<'a>),
}

impl Provider<'_> {
    pub fn name(&self) -> &str {
        match self {
            Self::Smtp(p) => p.name(),
            Self::Ses(p) => p.name(),
            Self::SendGrid(p) => p.name(),
        }
    }

    pub async fn send(&self, msg: &OutgoingEmail<'_>) -> Result<ProviderMessageId, SendError> {
        match self {
            Self::Smtp(p) => p.send(msg).await,
            Self::Ses(p) => p.send(msg).await,
            Self::SendGrid(p) => p.send(msg).await,
        }
    }
}

/// The provider name configured for `from_address`: its `by_sender` entry,
/// else the default, else SMTP.
pub fn provider_name<'a>(cfg: &'a EmailSection, from_address: &str) -> &'a str {
    let providers = &cfg.providers;
    providers
        .by_sender
        .iter()
        .find(|(address, _)| address.trim().eq_ignore_ascii_case(from_address.trim()))
        .map(|(_, name)| name.as_str())
        .or(providers.default.as_deref())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(SMTP)
}

/// The provider for a message from `from_address`. A provider named without
/// its settings, or a name no provider has, is a `Config` error.
pub fn select<'a>(cfg: &'a EmailSection, from_address: &str) -> Result<Provider<'a>, SendError> {
    let name = provider_name(cfg, from_address);
    match name.to_ascii_lowercase().as_str() {
        SMTP => Ok(Provider::Smtp(smtp::Smtp { cfg })),
        SES => cfg
            .providers
            .ses
            .as_ref()
            .map(|settings| Provider::Ses(ses::Ses { settings }))
            .ok_or_else(|| SendError::Config {
                message: "email provider \"ses\" needs email.providers.ses".into(),
            }),
        SENDGRID => cfg
            .providers
            .sendgrid
            .as_ref()
            .map(|settings| Provider::SendGrid(sendgrid::SendGrid { settings }))
            .ok_or_else(|| SendError::Config {
                message: "email provider \"sendgrid\" needs email.providers.sendgrid".into(),
            }),
        other => Err(SendError::Config {
            message: format!(
                "unknown email provider {other:?}; one of {SMTP:?}, {SES:?}, {SENDGRID:?}"
            ),
        }),
    }
}

/// The one HTTP client the HTTPS providers share, with its own connect and
/// request timeouts (the whole send also sits under the send deadline).
pub(crate) fn http_client() -> Result<&'static reqwest::Client, SendError> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| SendError::Config {
            message: format!("email HTTP client: {e}"),
        })?;
    Ok(CLIENT.get_or_init(|| client))
}

/// A provider's non-success answer as a send outcome.
pub(crate) fn classify_http_status(provider: &str, status: u16, body: &str) -> SendError {
    let excerpt: String = body.chars().take(300).collect();
    let message = format!("{provider} answered {status}: {excerpt}");
    match status {
        // Our credential or our account, not the message: no retry fixes it.
        401 | 403 | 413 => SendError::Config { message },
        408 | 429 | 500..=599 => SendError::Transient { message },
        _ => SendError::Permanent {
            code: status.to_string(),
            message,
            recipient_attributable: false,
        },
    }
}

/// A request that failed before an answer. Only a failed connect is surely
/// unsent; anything later may have reached the provider.
pub(crate) fn classify_transport(provider: &str, error: &reqwest::Error) -> SendError {
    let message = format!("{provider}: {error}");
    if error.is_builder() {
        SendError::Config { message }
    } else if error.is_connect() {
        SendError::Transient { message }
    } else {
        SendError::Unknown { message }
    }
}

/// `scheme://host[:port]` without the scheme: the `Host` a request carries.
pub(crate) fn host_of(endpoint: &str) -> Result<&str, SendError> {
    endpoint
        .split_once("://")
        .map(|(_, rest)| rest.split('/').next().unwrap_or(rest))
        .filter(|host| !host.is_empty())
        .ok_or_else(|| SendError::Config {
            message: format!("email provider endpoint {endpoint:?} is not a URL"),
        })
}

#[cfg(test)]
pub(crate) mod mock {
    //! One scripted HTTP exchange, for the HTTPS providers' tests.

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    /// Answers one request with `status`, the extra `headers` (each ending in
    /// `\r\n`) and `body`; hands back the base URL and the raw request.
    pub(crate) async fn serve_once(
        status: u16,
        headers: &'static str,
        body: &'static str,
    ) -> (String, oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut request = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let n = socket.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
                if let Some(end) = find(&request, b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let reply = format!(
                "HTTP/1.1 {status} Scripted\r\ncontent-length: {}\r\nconnection: close\r\n{headers}\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(reply.as_bytes()).await;
            let _ = socket.shutdown().await;
            let _ = tx.send(String::from_utf8_lossy(&request).into_owned());
        });
        (url, rx)
    }
}

#[cfg(test)]
mod tests {
    use attome_config::{EmailProviders, SendGridSettings};

    use super::*;

    fn with_providers(providers: EmailProviders) -> EmailSection {
        EmailSection {
            enabled: true,
            smtp_host: "localhost".to_string(),
            smtp_port: 1025,
            smtp_user: String::new(),
            smtp_password: String::new().into(),
            smtp_from_address: "noreply@example.com".to_string(),
            smtp_from_name: "Attome".to_string(),
            smtp_use_tls: None,
            tls_mode: None,
            test_mode_catch_all: None,
            providers,
        }
    }

    #[test]
    fn a_sender_identity_picks_its_provider() {
        let cfg = with_providers(EmailProviders {
            default: None,
            by_sender: [("Billing@Example.com".to_string(), "sendgrid".to_string())].into(),
            ses: None,
            sendgrid: Some(SendGridSettings {
                api_key: "SG.key".into(),
                endpoint: None,
            }),
        });
        assert_eq!(provider_name(&cfg, "billing@example.com"), "sendgrid");
        assert_eq!(provider_name(&cfg, "noreply@example.com"), SMTP);
        assert_eq!(
            select(&cfg, "billing@example.com").unwrap().name(),
            SENDGRID
        );
        assert_eq!(select(&cfg, "noreply@example.com").unwrap().name(), SMTP);
    }

    #[test]
    fn a_provider_without_its_settings_is_a_configuration_error() {
        let cfg = with_providers(EmailProviders {
            default: Some("ses".into()),
            ..EmailProviders::default()
        });
        assert!(matches!(
            select(&cfg, "noreply@example.com"),
            Err(SendError::Config { .. })
        ));
        let cfg = with_providers(EmailProviders {
            default: Some("pigeon".into()),
            ..EmailProviders::default()
        });
        assert!(matches!(
            select(&cfg, "noreply@example.com"),
            Err(SendError::Config { .. })
        ));
    }

    #[test]
    fn http_answers_classify_like_smtp_replies() {
        assert!(matches!(
            classify_http_status("ses", 403, "denied"),
            SendError::Config { .. }
        ));
        assert!(matches!(
            classify_http_status("ses", 429, "slow down"),
            SendError::Transient { .. }
        ));
        assert!(matches!(
            classify_http_status("ses", 503, ""),
            SendError::Transient { .. }
        ));
        assert!(matches!(
            classify_http_status("ses", 400, "MessageRejected"),
            SendError::Permanent {
                recipient_attributable: false,
                ..
            }
        ));
        assert_eq!(
            host_of("https://email.eu-west-1.amazonaws.com").unwrap(),
            "email.eu-west-1.amazonaws.com"
        );
        assert_eq!(host_of("http://127.0.0.1:9/x").unwrap(), "127.0.0.1:9");
        assert!(host_of("nonsense").is_err());
    }
}
