//! Z8-T3: send pacing, in messages per minute, per stream, provider and
//! recipient domain (`email.rate_limits`).
//!
//! The windows live in this process: a deployment with several worker nodes
//! sends up to the limit from each. That is pacing, not a quota; nothing
//! durable depends on it, and a restart only starts a fresh minute. A send
//! over a limit waits for its minute to turn, up to [`MAX_WAIT`]; past that
//! it is a transient failure and the job retries later.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use attome_config::{EmailSection, EmailStreamRates};

use crate::error::SendError;
use crate::message::EmailStream;

/// The longest one send waits for room before giving up.
pub const MAX_WAIT: Duration = Duration::from_secs(60);

const WINDOW: Duration = Duration::from_secs(60);

/// Fixed one-minute windows, one per key.
#[derive(Default)]
pub struct Pacer {
    windows: Mutex<HashMap<String, (Instant, u32)>>,
}

impl Pacer {
    /// Takes one send from every `(key, per_minute)` window, or none of them
    /// when any is full; then answers how long until the fullest one turns.
    pub fn take(&self, limits: &[(String, u32)], now: Instant) -> Option<Duration> {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut wait = None::<Duration>;
        for (key, per_minute) in limits {
            if let Some((started, used)) = windows.get(key)
                && now.duration_since(*started) < WINDOW
                && used >= per_minute
            {
                let left = WINDOW - now.duration_since(*started);
                wait = Some(wait.map_or(left, |w| w.max(left)));
            }
        }
        if wait.is_some() {
            return wait;
        }
        for (key, _) in limits {
            let window = windows.entry(key.clone()).or_insert((now, 0));
            if now.duration_since(window.0) >= WINDOW {
                *window = (now, 0);
            }
            window.1 += 1;
        }
        None
    }
}

static PACER: LazyLock<Pacer> = LazyLock::new(Pacer::default);

/// The limits one send to `recipient` through `provider` falls under. Pure.
pub fn limits_for(
    cfg: &EmailSection,
    stream: EmailStream,
    provider: &str,
    recipient: &str,
) -> Vec<(String, u32)> {
    let rates: &EmailStreamRates = match stream {
        EmailStream::Transactional => &cfg.rate_limits.transactional,
        EmailStream::Bulk => &cfg.rate_limits.bulk,
    };
    let stream = stream.as_str();
    let domain = recipient
        .rsplit_once('@')
        .map(|(_, d)| d.to_ascii_lowercase())
        .unwrap_or_default();
    let mut out = Vec::new();
    if let Some((name, n)) = rates
        .providers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(provider))
    {
        out.push((
            format!("{stream}:provider:{}", name.to_ascii_lowercase()),
            *n,
        ));
    }
    if let Some((name, n)) = rates
        .domains
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(&domain))
    {
        out.push((format!("{stream}:domain:{}", name.to_ascii_lowercase()), *n));
    }
    out
}

/// Waits until the send fits every limit, or fails transiently after
/// [`MAX_WAIT`].
pub async fn pace(limits: &[(String, u32)]) -> Result<(), SendError> {
    if limits.is_empty() {
        return Ok(());
    }
    let started = Instant::now();
    loop {
        let Some(wait) = PACER.take(limits, Instant::now()) else {
            return Ok(());
        };
        if started.elapsed() + wait > MAX_WAIT {
            metrics::counter!("email_rate_limited_total").increment(1);
            return Err(SendError::Transient {
                message: "email rate limit reached; retrying later".into(),
            });
        }
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_rate_window_fills_and_turns() {
        let pacer = Pacer::default();
        let limits = vec![("bulk:domain:gmail.com".to_owned(), 2)];
        let t0 = Instant::now();
        assert_eq!(pacer.take(&limits, t0), None);
        assert_eq!(pacer.take(&limits, t0), None);
        let wait = pacer.take(&limits, t0 + Duration::from_secs(10));
        assert_eq!(wait, Some(Duration::from_secs(50)));
        assert_eq!(pacer.take(&limits, t0 + Duration::from_secs(60)), None);
    }

    #[test]
    fn email_rate_full_window_takes_nothing_from_the_others() {
        let pacer = Pacer::default();
        let t0 = Instant::now();
        let provider = ("bulk:provider:ses".to_owned(), 10);
        let domain = ("bulk:domain:gmail.com".to_owned(), 1);
        assert_eq!(pacer.take(&[provider.clone(), domain.clone()], t0), None);
        assert!(pacer.take(&[provider.clone(), domain], t0).is_some());
        // The refused send did not count against the provider: nine left.
        for _ in 0..9 {
            assert_eq!(pacer.take(std::slice::from_ref(&provider), t0), None);
        }
        assert!(pacer.take(&[provider], t0).is_some());
    }

    #[test]
    fn email_rate_limits_follow_the_stream() {
        let mut cfg: EmailSection = serde_json::from_value(serde_json::json!({
            "smtp_host": "h", "smtp_port": 25, "smtp_user": "", "smtp_password": "",
            "smtp_from_address": "a@b.c", "smtp_from_name": "A",
            "rate_limits": { "bulk": { "providers": { "SMTP": 100 }, "domains": { "gmail.com": 5 } } }
        }))
        .unwrap();
        let bulk = limits_for(&cfg, EmailStream::Bulk, "smtp", "x@Gmail.com");
        assert_eq!(
            bulk,
            vec![
                ("bulk:provider:smtp".to_owned(), 100),
                ("bulk:domain:gmail.com".to_owned(), 5)
            ]
        );
        assert!(limits_for(&cfg, EmailStream::Transactional, "smtp", "x@gmail.com").is_empty());
        cfg.rate_limits
            .transactional
            .domains
            .insert("gmail.com".into(), 50);
        assert_eq!(
            limits_for(&cfg, EmailStream::Transactional, "smtp", "x@gmail.com"),
            vec![("transactional:domain:gmail.com".to_owned(), 50)]
        );
    }
}
