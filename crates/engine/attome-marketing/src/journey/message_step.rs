//! E8-T6: the journey message steps.
//!
//! `marketing.send_email` (config `design_id`, a saved email design;
//! `purpose`, the consent purpose; `on_blocked`, `skip` or `wait`;
//! optional `send_time: "best"`) sends the design to the run's person:
//!
//! 1. with `send_time: "best"`, the step first waits once until the
//!    person's best hour within the next day (E5, from the opens of the
//!    campaign emails they were sent, [`crate::send_time::best_moment`]);
//! 2. the rules ([`super::rules::check`]): no consent, a suppressed address
//!    or a sunset person blocks the step (a `marketing_journey_block` row;
//!    the run goes on with `on_blocked: skip`, waits a day and tries again
//!    with `wait`), quiet hours make it wait for the first allowed minute,
//!    and the weekly cap blocks it;
//! 3. allowed, the step claims `(journey, instance, node)` in
//!    `marketing_message_log` (unique since migration 0365; a replayed step
//!    finds the claim and sends nothing) and, in the same
//!    transaction, queues the email as an E3 send of one recipient, so the
//!    `email_campaign` job sends it like any campaign email: consent read
//!    again, the unsubscribe link and `List-Unsubscribe`, the bulk stream.
//!    The send's `list_id` is the journey's id.
//!
//! A test enrolment (`is_test` in the run's data) sends to the first of
//! the journey's `test_addresses` instead, directly and without the rules,
//! and logs nothing against the person.
//!
//! `marketing.send_sms`, `marketing.send_whatsapp`, `marketing.send_push`,
//! `marketing.send_in_app` and `marketing.create_task` are declared so a
//! journey naming them is refused at publish with `channel_unavailable`.

use attome_core::EngineState;
use attome_core::workflow_step::{StepFuture, StepInvocation, StepOutcome, WorkflowStepHandler};
use attome_modules::{MODULE_MARKETING, ModuleId};
use attome_types::AppError;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use super::rules::{RuleVerdict, check};

/// The steps declared but without a sender yet.
pub const UNAVAILABLE_CHANNELS: [&str; 5] = [
    "marketing.send_sms",
    "marketing.send_whatsapp",
    "marketing.send_push",
    "marketing.send_in_app",
    "marketing.create_task",
];

/// A send step's configuration, checked. Pure.
pub fn config_problem(config: &Value) -> Option<&'static str> {
    let text = |k: &str| config.get(k).and_then(Value::as_str).map(str::trim);
    if text("design_id")
        .and_then(|d| Uuid::parse_str(d).ok())
        .is_none()
    {
        return Some("design_id names a saved email design");
    }
    if text("purpose").is_none_or(str::is_empty) {
        return Some("purpose names the consent purpose");
    }
    if !matches!(text("on_blocked"), None | Some("skip") | Some("wait")) {
        return Some("on_blocked is skip or wait");
    }
    if !matches!(text("send_time"), None | Some("now") | Some("best")) {
        return Some("send_time is now or best");
    }
    None
}

/// The email step.
#[derive(Debug)]
pub struct SendEmail;

/// A declared step with no sender.
#[derive(Debug)]
pub struct ChannelUnavailable {
    pub key: &'static str,
}

impl WorkflowStepHandler for ChannelUnavailable {
    fn key(&self) -> &'static str {
        self.key
    }
    fn module_id(&self) -> ModuleId {
        MODULE_MARKETING
    }
    fn available(&self) -> bool {
        false
    }
    fn validate_config(&self, _config: &Value) -> Result<(), String> {
        Err("channel_unavailable".into())
    }
    fn run<'a>(&'a self, _state: &'a EngineState, _inv: StepInvocation) -> StepFuture<'a> {
        Box::pin(async { Err(AppError::FeatureUnavailable) })
    }
}

/// A saved design as read: subject, locale, design JSON.
type DesignRow = (Option<String>, Option<String>, Option<String>);

/// A rendered email: subject, locale, HTML, text.
pub(crate) type Rendered = (String, String, String, String);

/// The design, rendered: subject, locale, HTML, text.
pub(crate) async fn rendered(state: &EngineState, design_id: Uuid) -> Result<Rendered, AppError> {
    let row: Option<DesignRow> = sqlx::query_as(
        "SELECT subject, locale, design FROM marketing_email_design \
          WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(design_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(subject), locale, Some(design))) = row else {
        return Err(AppError::Validation(
            "the step's email design is gone or has no subject".into(),
        ));
    };
    let design: crate::email_render::EmailDesign =
        serde_json::from_str(&design).map_err(|e| AppError::Validation(format!("design: {e}")))?;
    let mail = crate::email_render::render(&design)
        .map_err(|e| AppError::Validation(format!("design: {e}")))?;
    Ok((
        subject,
        locale.unwrap_or_else(|| "en".to_owned()),
        mail.html,
        mail.text,
    ))
}

/// The first of the journey's test addresses.
async fn test_address(
    state: &EngineState,
    journey: Option<Uuid>,
) -> Result<Option<String>, AppError> {
    let Some(journey) = journey else {
        return Ok(None);
    };
    let addresses: Option<String> =
        sqlx::query_scalar("SELECT test_addresses FROM marketing_journey WHERE id = $1")
            .bind(journey)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    Ok(addresses.and_then(|a| {
        a.split([',', ';', '\n', ' '])
            .map(str::trim)
            .find(|a| a.contains('@'))
            .map(str::to_owned)
    }))
}

fn uuid_in(value: &Value, key: &str) -> Option<Uuid> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
}

impl WorkflowStepHandler for SendEmail {
    fn key(&self) -> &'static str {
        "marketing.send_email"
    }
    fn module_id(&self) -> ModuleId {
        MODULE_MARKETING
    }
    fn config_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "design_id": { "type": "string", "format": "uuid", "title": "Email design" },
                "purpose": { "type": "string", "title": "Consent purpose" },
                "on_blocked": { "type": "string", "enum": ["skip", "wait"], "default": "skip", "title": "When blocked" },
                "send_time": { "type": "string", "enum": ["now", "best"], "default": "now", "title": "Send time" }
            },
            "required": ["design_id", "purpose"]
        })
    }
    fn validate_config(&self, config: &Value) -> Result<(), String> {
        config_problem(config).map_or(Ok(()), |p| Err(p.to_owned()))
    }
    fn run<'a>(&'a self, state: &'a EngineState, inv: StepInvocation) -> StepFuture<'a> {
        Box::pin(async move {
            if let Some(problem) = config_problem(&inv.config) {
                return Err(AppError::Validation(problem.into()));
            }
            let design_id = uuid_in(&inv.config, "design_id").ok_or(AppError::NotFound)?;
            let purpose = inv.config["purpose"].as_str().unwrap_or_default().trim();
            let wait_when_blocked = inv.config["on_blocked"].as_str() == Some("wait");
            let Some(person) = inv.correlation_entity_id else {
                return Ok(StepOutcome::Blocked {
                    reason: "the run has no person".into(),
                    continue_after: true,
                });
            };
            let entity = inv.input["person_entity"]
                .as_str()
                .unwrap_or("contact")
                .to_owned();
            let journey = uuid_in(&inv.input, "journey_id");
            let is_test = inv.input["is_test"].as_bool() == Some(true);
            if inv.simulate {
                return Ok(StepOutcome::Done(json!({
                    "would": "send email",
                    "design_id": design_id,
                    "test": is_test,
                })));
            }
            let (subject, locale, html, text) = rendered(state, design_id).await?;

            if is_test {
                let Some(to) = test_address(state, journey).await? else {
                    return Ok(StepOutcome::Blocked {
                        reason: "the journey has no test address".into(),
                        continue_after: true,
                    });
                };
                let mut tx = attome_db::tx::begin(&state.base.db).await?;
                let claimed = sqlx::query(
                    "INSERT INTO marketing_message_log \
                       (person_id, channel, purpose, source_kind, source_id, source_node, is_test) \
                     VALUES ($1, 'email', $2, 'journey', $3, $4, true) ON CONFLICT DO NOTHING",
                )
                .bind(person)
                .bind(purpose)
                .bind(inv.instance_id)
                .bind(&inv.node_id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?
                .rows_affected();
                if claimed == 1 {
                    attome_jobs::enqueue_in_tx(
                        &mut tx,
                        attome_core::jobs::EngineJob::SendEmail(Box::new(
                            attome_email::EmailMessage {
                                to: to.clone(),
                                subject: format!("[test] {subject}"),
                                text_body: text,
                                html_body: Some(html),
                                delivery_id: None,
                                from_override: None,
                                message_id: None,
                                in_reply_to: None,
                                references: None,
                                communication_id: None,
                                attachments: Vec::new(),
                                stream: Default::default(),
                                list_unsubscribe: None,
                            },
                        )),
                    )
                    .await
                    .map_err(AppError::internal)?;
                }
                attome_db::tx::commit(tx).await?;
                return Ok(StepOutcome::Done(json!({ "sent_to": to, "test": true })));
            }

            // E5: the person's best hour, waited for once (the first visit
            // claims `marketing_message_wait`; the resumed step goes on).
            if inv.config["send_time"].as_str() == Some("best") {
                let first = sqlx::query(
                    "INSERT INTO marketing_message_wait (instance_id, node_id) VALUES ($1, $2) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(inv.instance_id)
                .bind(&inv.node_id)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?
                .rows_affected()
                    == 1;
                if first {
                    let at = crate::send_time::best_moment(state, &entity, person).await?;
                    if at > Utc::now() + Duration::minutes(1) {
                        return Ok(StepOutcome::Waiting {
                            resume_at: Some(at),
                            wait_event: None,
                        });
                    }
                }
            }

            let address: Option<String> = sqlx::query_scalar(&format!(
                "SELECT trim(email) FROM {} WHERE id = $1",
                attome_core::quote_ident(&entity)
            ))
            .bind(person)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .flatten();
            let Some(address) = address.filter(|a| a.contains('@')) else {
                return Ok(StepOutcome::Blocked {
                    reason: "no email address".into(),
                    continue_after: true,
                });
            };
            let now = Utc::now();
            match check(state, &entity, person, &address, "email", purpose, now).await? {
                RuleVerdict::Deferred(at) => {
                    return Ok(StepOutcome::Waiting {
                        resume_at: Some(at),
                        wait_event: None,
                    });
                }
                RuleVerdict::Blocked(reason) => {
                    sqlx::query(
                        "INSERT INTO marketing_journey_block (instance_id, node_id, reason) \
                         VALUES ($1, $2, $3)",
                    )
                    .bind(inv.instance_id)
                    .bind(&inv.node_id)
                    .bind(&reason)
                    .execute(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                    if wait_when_blocked {
                        return Ok(StepOutcome::Waiting {
                            resume_at: Some(now + Duration::days(1)),
                            wait_event: None,
                        });
                    }
                    return Ok(StepOutcome::Blocked {
                        reason,
                        continue_after: true,
                    });
                }
                RuleVerdict::Allowed => {}
            }

            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let claimed = sqlx::query(
                "INSERT INTO marketing_message_log \
                   (person_id, channel, purpose, source_kind, source_id, source_node) \
                 VALUES ($1, 'email', $2, 'journey', $3, $4) ON CONFLICT DO NOTHING",
            )
            .bind(person)
            .bind(purpose)
            .bind(inv.instance_id)
            .bind(&inv.node_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            if claimed == 0 {
                attome_db::tx::commit(tx).await?;
                return Ok(StepOutcome::Done(json!({ "replayed": true })));
            }
            let send_id: Uuid = sqlx::query_scalar(
                "INSERT INTO email_campaign_send \
                   (list_id, subject, html_body, text_body, purpose_key, locale, design_id) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
            )
            .bind(journey.unwrap_or(inv.instance_id))
            .bind(&subject)
            .bind(&html)
            .bind(&text)
            .bind(purpose)
            .bind(&locale)
            .bind(design_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            sqlx::query(
                "INSERT INTO email_campaign_recipient \
                   (send_id, subject_entity, subject_id, email, unsubscribe_token) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(send_id)
            .bind(&entity)
            .bind(person)
            .bind(&address)
            .bind(format!(
                "{}{}",
                Uuid::new_v4().simple(),
                Uuid::new_v4().simple()
            ))
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            attome_db::tx::commit(tx).await?;
            Ok(StepOutcome::Done(json!({ "send_id": send_id })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_send_step_names_its_design_and_purpose() {
        let design = Uuid::now_v7().to_string();
        assert_eq!(
            config_problem(&json!({ "design_id": design, "purpose": "newsletter" })),
            None
        );
        assert!(config_problem(&json!({ "purpose": "newsletter" })).is_some());
        assert!(config_problem(&json!({ "design_id": design })).is_some());
        assert!(
            config_problem(&json!({ "design_id": design, "purpose": "n", "on_blocked": "retry" }))
                .is_some()
        );
    }
}
