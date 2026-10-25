//! Built-in alert delivery (roadmap AB10-T2): every firing and resolution of
//! a built-in alert (`ops_alert_event`, written by
//! `attome_server::alerts`) goes to `observability.alert_emails` as queued
//! email jobs and to `observability.alert_webhooks` as a `{"text": ...}`
//! POST (the shape Slack and Teams incoming webhooks take).
//!
//! Once a minute the oldest unsent events are claimed with
//! `FOR UPDATE SKIP LOCKED` (several nodes never send one twice), their
//! emails are queued in the same transaction that marks them sent, and the
//! webhooks are called after it commits, each bounded by a timeout. A
//! webhook that fails is logged, not retried: the event stays in
//! `ops_alert_event` and on the alerts screen.
//!
//! A firing event's message carries its runbook (AB10-T3), filled with this
//! deployment's addresses by `attome_server::runbooks`.

use std::time::Duration;

use attome_config::AppConfig;
use attome_core::jobs::EngineJob;
use attome_db::DbPool;
use attome_email::EmailMessage;
use attome_server::runbooks::{self, RunbookValues};
use chrono::{DateTime, Utc};
use uuid::Uuid;

const EVERY: Duration = Duration::from_secs(60);
const BATCH: i64 = 50;
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, sqlx::FromRow)]
struct AlertEvent {
    id: Uuid,
    name: String,
    event: String,
    severity: String,
    summary: String,
    value: Option<f64>,
    at: DateTime<Utc>,
}

/// One line saying what happened, for an email subject or a chat message.
fn headline(event: &AlertEvent) -> String {
    let what = if event.event == "firing" {
        "FIRING"
    } else {
        "resolved"
    };
    format!(
        "[{}] {} {}: {}",
        event.severity, event.name, what, event.summary
    )
}

/// The message: what happened, then, while firing, the filled runbook. A
/// resolution names the runbook file only.
fn body(event: &AlertEvent, values: &RunbookValues) -> String {
    let value = event
        .value
        .map(|v| format!("{v}"))
        .unwrap_or_else(|| "-".to_owned());
    let mut text = format!(
        "{}\n\nAt: {}\nValue: {value}\nReported by: {}\nRunbook: observability/runbooks/{}.md\n",
        headline(event),
        event.at.to_rfc3339(),
        values.node,
        event.name
    );
    if event.event == "firing"
        && let Some(runbook) = runbooks::render(&event.name, values)
    {
        text.push('\n');
        text.push_str(&runbook);
    }
    text
}

/// Claims and sends one batch; returns how many events were handled.
async fn send_batch(
    db: &DbPool,
    config: &AppConfig,
    http: &attome_outbound::http::Outbound,
) -> Result<usize, attome_types::AppError> {
    let node = attome_server::metrics_store::node_name(config.app.port);
    let values = RunbookValues::from_config(config, &node);
    let mut tx = attome_db::tx::begin(db).await?;
    let events: Vec<AlertEvent> = sqlx::query_as(
        "SELECT id, name, event, severity, summary, value, at FROM ops_alert_event \
          WHERE notified_at IS NULL ORDER BY at LIMIT $1 FOR UPDATE SKIP LOCKED",
    )
    .bind(BATCH)
    .fetch_all(&mut *tx)
    .await
    .map_err(attome_types::AppError::internal)?;
    if events.is_empty() {
        return Ok(0);
    }
    let emails: Vec<&String> = config
        .observability
        .alert_emails
        .iter()
        .filter(|e| e.contains('@'))
        .collect();
    for event in &events {
        for to in &emails {
            attome_jobs::enqueue_in_tx(
                &mut tx,
                EngineJob::SendEmail(Box::new(EmailMessage {
                    to: (*to).clone(),
                    subject: headline(event),
                    text_body: body(event, &values),
                    html_body: None,
                    delivery_id: None,
                    from_override: None,
                    message_id: None,
                    in_reply_to: None,
                    references: None,
                    communication_id: None,
                    attachments: Vec::new(),
                    stream: Default::default(),
                })),
            )
            .await
            .map_err(attome_types::AppError::internal)?;
        }
    }
    let ids: Vec<Uuid> = events.iter().map(|e| e.id).collect();
    sqlx::query("UPDATE ops_alert_event SET notified_at = now() WHERE id = ANY($1)")
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .map_err(attome_types::AppError::internal)?;
    attome_db::tx::commit(tx).await?;

    // External calls only after the transaction is gone (guidelines §4).
    for url in &config.observability.alert_webhooks {
        for event in &events {
            let text = body(event, &values);
            let sent = http
                .post(url)
                .timeout(WEBHOOK_TIMEOUT)
                .json(&serde_json::json!({ "text": text }))
                .send()
                .await
                .and_then(reqwest::Response::error_for_status);
            if let Err(error) = sent {
                tracing::warn!(
                    alert = %event.name,
                    error = %error.without_url(),
                    "built-in alert: the webhook did not take the message"
                );
            }
        }
    }
    Ok(events.len())
}

/// Starts the once-a-minute delivery. Does nothing when nobody is set to
/// hear about alerts. Process-lifetime supervision: a failed minute is
/// logged and the next one tries again.
pub fn spawn(db: DbPool, config: AppConfig) {
    if config.observability.alert_emails.is_empty()
        && config.observability.alert_webhooks.is_empty()
    {
        return;
    }
    tokio::spawn(async move {
        // Q21-T1: the webhooks are the operator's (`observability.alert_webhooks`),
        // so their hosts may be on the private network (an on-premise chat server).
        let purpose = attome_outbound::http::Purpose::public("alert-webhook").with_private_urls(
            config
                .observability
                .alert_webhooks
                .iter()
                .map(String::as_str),
        );
        let http = attome_outbound::http::shared(purpose, |b| b);
        let mut ticker = tokio::time::interval(EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(error) = send_batch(&db, &config, &http).await {
                tracing::warn!(%error, "built-in alerts: this minute's alerts were not sent");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_says_what_fired_and_where_to_look() {
        let event = AlertEvent {
            id: Uuid::nil(),
            name: "ObjectStorageDown".into(),
            event: "firing".into(),
            severity: "critical".into(),
            summary: "The file store does not answer".into(),
            value: Some(0.0),
            at: DateTime::<Utc>::from_timestamp(1_800_000_000, 0).expect("time"),
        };
        assert_eq!(
            headline(&event),
            "[critical] ObjectStorageDown FIRING: The file store does not answer"
        );
        let values = RunbookValues {
            node: "web-1:7865".into(),
            app_url: "https://crm.example.com".into(),
            api_base: "http://10.0.0.5:7865".into(),
            metrics_url: "http://10.0.0.5:9464/metrics".into(),
            database: "db:5432/attome".into(),
            cache: "Redis at cache:6379".into(),
            storage: "http://files:9000 (bucket attome)".into(),
            alert_emails: "ops@example.com".into(),
        };
        let text = body(&event, &values);
        assert!(text.contains("web-1:7865"), "{text}");
        assert!(
            text.contains("observability/runbooks/ObjectStorageDown.md"),
            "{text}"
        );
        // AB10-T3: a firing alert carries its runbook, filled.
        assert!(text.contains("## Checks"), "{text}");
        assert!(text.contains("http://files:9000 (bucket attome)"), "{text}");
        assert!(!text.contains("{{"), "{text}");

        let resolved = AlertEvent {
            event: "resolved".into(),
            ..event
        };
        let text = body(&resolved, &values);
        assert!(!text.contains("## Checks"), "{text}");
    }
}
