//! Notification Engine dispatch queue (P2.11, F163/F164/F172).
//!
//! `create_dispatch` (called from `engine::create_dispatch` on the request
//! path) inserts a `notification_dispatch` row and never opens SMTP
//! itself, so the HTTP handler stays fast regardless of SMTP/provider
//! latency (guidelines §10). For most channels, delivery happens later on
//! `attome-api`'s background poller (see `crate::poller`), which claims rows
//! via `FOR UPDATE SKIP LOCKED` so multiple app nodes can run the scanner
//! concurrently without double-sending (guidelines' multi-server rule).
//!
//! M51 Phase 1's `email` channel is the one exception, and only for a
//! **direct** dispatch (`recipient_user_ref` set): once the recipient's
//! address and `email_suppression` status are known,
//! `create_dispatch` enqueues `attome_core::jobs::EngineJob::SendEmail` in the same
//! transaction as the dispatch insert (apalis-on-Postgres makes this safe —
//! same shape as `attome-auth`'s account-lifecycle producers) rather than
//! waiting for the poller. This durably hands the send off to the existing
//! apalis job queue instead of opening SMTP on the request path — the actual
//! SMTP attempt still happens off-request, in the job worker
//! (`crates/server/src/jobs.rs`'s `SendEmail` arm), not here. Organization/
//! global email dispatches remain out of Phase 1's scope (see `send_email`'s
//! doc comment below) and are still a no-op via the poller, unchanged.
//!
//! F165 (trigger-based alerts on workflow events) is not implemented in this
//! crate: `attome-workflow` owns it. Its `send_notification` node
//! (`attome_workflow::scheduler::execute_send_notification`) calls into this
//! crate from a workflow run, and any other caller can trigger a notification
//! via `POST /api/v1/notification/dispatch` (`engine::create_dispatch`).

use std::collections::HashMap;
use std::sync::Arc;

use attome_core::EngineState;
use attome_core::services::NotificationService;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::recipient;
use utoipa::ToSchema;

const MAX_ATTEMPTS: i32 = 5;
const PROCESSING_STALE_AFTER_MINUTES: i64 = 5;
// REVIEW-2026-09-02 finding #3: was `&["in_app"]` only, so every dispatch
// with no explicit `channels` and no template `default_channels` (or a
// template that doesn't set one) silently never reached email even though
// M51 email delivery (D-402) has been wired since 2026-08-26. This is the
// platform-wide fallback every producer below now relies on instead of
// hardcoding its own channel list.
const DEFAULT_CHANNELS: &[&str] = &["in_app", "email"];

/// The `AppError::CapabilityUnavailable` name `send_via_service` returns when
/// no `NotificationService` provider is wired (T3-7). Named here, next to the
/// channel constants, so the dispatch tests and any future
/// `/health/dependencies` probe agree on the spelling.
pub const NOTIFICATION_PROVIDER_CAPABILITY: &str = "notification_provider";

/// Well under `PROCESSING_STALE_AFTER_MINUTES` so a worker still actively
/// sending a single slow channel keeps refreshing `updated_at` faster than
/// another node's reclaim query can decide it's stale.
const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

fn default_locale() -> String {
    "en".to_string()
}
fn default_priority() -> String {
    "normal".to_string()
}

#[derive(Deserialize, ToSchema)]
pub struct DispatchRequest {
    pub template_key: Option<String>,
    #[serde(default = "default_locale")]
    pub locale: String,
    pub recipient_user_ref: Option<Uuid>,
    #[serde(default)]
    pub is_global: bool,
    pub organization_ref: Option<Uuid>,
    pub channels: Option<Vec<String>>,
    pub subject: Option<String>,
    pub body_html: Option<String>,
    pub body_text: Option<String>,
    pub route: Option<String>,
    #[serde(default)]
    pub variables: HashMap<String, String>,
    #[serde(default = "default_priority")]
    pub priority: String,
    pub escalate_after_minutes: Option<i32>,
    pub escalate_channels: Option<Vec<String>>,
}

impl std::fmt::Debug for DispatchRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchRequest").finish_non_exhaustive()
    }
}

/// True iff `email` (normalized the same way `create_dispatch` normalizes an
/// address before checking it) is on `email_suppression`.
///
/// Extracted from `create_dispatch`'s own inline check — REVIEW-2026-09-02
/// finding #4: M52 compose (`attome_api::communication`) enqueued
/// `EngineJob::SendEmail` directly for every `to` address, never
/// consulting this table, so a bounced or withdrawn address could still be
/// emailed through compose even though a direct M51 dispatch already
/// refuses it. `E: PgExecutor` (same bound `consent_gate::has_active_consent`
/// uses) so a caller can pass either a pool or an open transaction — a
/// caller building its own email loop wants this check in the same
/// transaction as its own send decision, the same reason `create_dispatch`
/// itself runs it inside `tx`.
pub async fn is_email_suppressed<'e, E>(executor: E, email: &str) -> Result<bool, AppError>
where
    E: PgExecutor<'e>,
{
    // BEM-12/F8 — delegates to the workspace's one suppression query instead
    // of repeating its SQL. This copy could drift from the choke point
    // `attome_email::send` enforces (a different normalization, a missing
    // `is_deleted` predicate) and nothing would catch it; attome-email's
    // `suppression::is_suppressed` is the same `E: PgExecutor` shape, so the
    // pool-or-transaction callers here are unaffected.
    attome_email::suppression::is_suppressed(executor, email)
        .await
        .map_err(AppError::internal)
}

struct TemplateRow {
    subject: Option<String>,
    body_html: Option<String>,
    body_text: Option<String>,
    default_channels: Option<String>,
    escalate_after_minutes: Option<i32>,
    escalate_channels: Option<String>,
    /// M24/D-428 — see `crate::consent_gate`.
    consent_purpose_key: Option<String>,
    /// B-R5 / D-602 — a mandatory template ignores every user's
    /// notification preferences.
    is_mandatory: bool,
}

type TemplateRowTuple = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i32>,
    Option<String>,
    Option<String>,
    bool,
);

/// Substitutes `{{name}}` through the platform's one placeholder merge
/// (`attome_html::merge_placeholders`). This caller's unknown-name rule: a
/// placeholder with no matching variable is left **verbatim**, so a missing
/// variable is visible in the delivered message rather than silently blank.
///
/// Values are inserted as given: this is the merge for the plain-text parts
/// (`subject`, `body_text`), which are never rendered as HTML. The HTML body
/// goes through [`apply_variables_html`] instead.
fn apply_variables(text: &str, vars: &HashMap<String, String>) -> String {
    if vars.is_empty() {
        return text.to_string();
    }
    attome_html::merge_placeholders(text, |name| {
        vars.get(name)
            .map(|v| std::borrow::Cow::Borrowed(v.as_str()))
    })
}

/// The `{{name}}` merge for `body_html` (owner decision 2, CLEANUP-REVIEW
/// batch 1): every value is HTML-escaped (`attome_html::escape_html`) before it
/// is inserted, so a variable carrying `<script>`, markup or quotes renders as
/// text in the email/in-app HTML instead of becoming part of the document.
/// The template's own markup is trusted (it is admin-authored metadata); a
/// variable is data, whoever supplied it — the dispatch endpoint takes
/// `variables` from the caller, and a workflow's `send_notification` node
/// fills them from record data.
///
/// There is deliberately no raw (unescaped) variable form: no caller in the
/// workspace passes pre-rendered HTML in a variable (checked when this was
/// introduced). A caller that needs formatted HTML puts it in `body_html`
/// itself, where it is the caller's own trusted markup.
///
/// Unknown names are left verbatim, as in [`apply_variables`].
fn apply_variables_html(text: &str, vars: &HashMap<String, String>) -> String {
    if vars.is_empty() {
        return text.to_string();
    }
    attome_html::merge_placeholders(text, |name| {
        vars.get(name)
            .map(|v| std::borrow::Cow::Owned(attome_html::escape_html(v)))
    })
}

fn parse_channel_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty())
        .collect()
}

/// Derives a plain-text fallback from `body_html` (M51 Phase 1) when a
/// template/request supplies HTML but no explicit `body_text` -- strips
/// tags, turns the handful of block-level boundaries email templates
/// actually use into newlines, and unescapes the common HTML entities.
/// Deliberately not a full HTML parser (no new dependency for this crate):
/// adequate for the platform's own template bodies, not a sanitizer for
/// arbitrary/untrusted HTML.
fn derive_text_from_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut tag_name = String::new();
    let mut collecting_name = false;

    for c in html.chars() {
        match c {
            '<' => {
                in_tag = true;
                collecting_name = true;
                tag_name.clear();
            }
            '>' if in_tag => {
                in_tag = false;
                if matches!(
                    tag_name.to_lowercase().as_str(),
                    "br" | "p" | "div" | "tr" | "li" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6"
                ) {
                    out.push('\n');
                }
            }
            _ if in_tag => {
                if collecting_name {
                    if c.is_alphanumeric() {
                        tag_name.push(c);
                    } else if c != '/' {
                        collecting_name = false;
                    }
                }
            }
            _ => out.push(c),
        }
    }

    // `&amp;` last: decoding it first would turn an escaped `&amp;lt;` (the
    // text "&lt;", as `apply_variables_html` escapes it) into `<`.
    let out = out
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");

    out.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Looks up the template row for (template_key, locale), falling back to the
/// "en" locale if the requested one has no row -- bilingual support (F164)
/// degrades to the base locale rather than failing the whole dispatch.
async fn load_template(
    conn: &mut sqlx::PgConnection,
    key: &str,
    locale: &str,
) -> Result<Option<TemplateRow>, AppError> {
    // `is_mandatory IS TRUE`: the column is a nullable bundle attribute
    // (D-602); a template that never set it is not mandatory.
    const SELECT: &str = r#"SELECT subject, body_html, body_text, default_channels,
                                    escalate_after_minutes, escalate_channels,
                                    consent_purpose_key, (is_mandatory IS TRUE)
                             FROM notification_template
                             WHERE template_key = $1 AND locale = $2 AND is_active = TRUE"#;

    let row: Option<TemplateRowTuple> = sqlx::query_as(SELECT)
        .bind(key)
        .bind(locale)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)?;

    let row = match row {
        Some(r) => Some(r),
        None if locale != "en" => sqlx::query_as(
            r#"SELECT subject, body_html, body_text, default_channels,
                          escalate_after_minutes, escalate_channels,
                          consent_purpose_key, (is_mandatory IS TRUE)
                   FROM notification_template
                   WHERE template_key = $1 AND locale = 'en' AND is_active = TRUE"#,
        )
        .bind(key)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)?,
        None => None,
    };

    Ok(row.map(
        |(
            subject,
            body_html,
            body_text,
            default_channels,
            escalate_after_minutes,
            escalate_channels,
            consent_purpose_key,
            is_mandatory,
        )| {
            TemplateRow {
                subject,
                body_html,
                body_text,
                default_channels,
                escalate_after_minutes,
                escalate_channels,
                consent_purpose_key,
                is_mandatory,
            }
        },
    ))
}

/// Every active `system.admin` holder (moved here from `attome-ai`'s
/// quality monitor so engines below `attome-ai` can alert administrators) — direct grant or role-mediated
/// (`user_account_mm_privilege` / `role_mm_privilege` joined
/// through `user_account_mm_role`), same join shape
/// `attome_security::db::resolve_privileges` uses per-user, inverted here to
/// resolve every user holding one specific privilege. Team-mediated
/// `system.admin` grants (via `role_mm_team`) are not swept — a
/// best-effort audience for a best-effort alert, the same trade-off
/// `attome_metric::metric::run_scheduled_snapshot_sweep`'s per-metric failure
/// isolation documents for a comparable "one gap costs one data point, not
/// the whole sweep" reason.
pub async fn admin_recipients(db: &DbPool) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT DISTINCT su.id \
         FROM user_account su \
         WHERE (su.is_active IS NULL OR su.is_active = true) \
           AND ( \
             EXISTS ( \
               SELECT 1 FROM user_account_mm_privilege up \
               JOIN privilege p ON p.id = up.privilege_ref \
               WHERE up.user_ref = su.id AND up.is_active = true AND p.is_active = true \
                 AND p.key = 'system.admin' \
             ) \
             OR EXISTS ( \
               SELECT 1 FROM user_account_mm_role ur \
               JOIN role_mm_privilege rp ON rp.role_ref = ur.role_ref \
               JOIN privilege p ON p.id = rp.privilege_ref \
               WHERE ur.user_ref = su.id AND ur.is_deleted = false AND rp.is_deleted = false \
                 AND p.is_active = true AND p.key = 'system.admin' \
             ) \
           )",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Sends one alert to every administrator, best effort: a failure is logged
/// and never fails the caller's job (the caller has already logged the fact).
pub async fn alert_admins(
    db: &DbPool,
    notification_cfg: &attome_config::NotificationSection,
    subject: String,
    body: String,
    route: &str,
) {
    let recipients = match admin_recipients(db).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "ai alert: failed to resolve admin recipients");
            return;
        }
    };
    for user_id in recipients {
        let req = DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user_id),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some(subject.clone()),
            body_html: None,
            body_text: Some(body.clone()),
            route: Some(route.to_string()),
            variables: HashMap::new(),
            priority: "high".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        if let Err(e) = create_dispatch(db, notification_cfg, req).await {
            tracing::error!(error = %e, user_id = %user_id, "ai alert: dispatch failed for one recipient");
        }
    }
}

/// Persists a dispatch intent. Most channels are delivered later, off the
/// request path (`process_claimed`, driven by `crate::poller`) -- the
/// `email` channel on a direct dispatch is the one exception (M51 Phase 1),
/// enqueued durably in-transaction here; see this module's doc comment.
/// `notification_cfg` supplies `email_from` for that channel only.
///
/// The recipient's notification preferences (U5, D-602) apply under the
/// dispatch's `template_key`; [`create_dispatch_in_tx`] can name a platform
/// event category instead.
pub async fn create_dispatch(
    db: &DbPool,
    notification_cfg: &attome_config::NotificationSection,
    req: DispatchRequest,
) -> Result<Uuid, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let id = create_dispatch_in_tx(&mut tx, notification_cfg, req, None).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(id)
}

/// [`create_dispatch`] inside a caller's transaction (`user-calendar.md` R7,
/// D-602): the dispatch row, its in-app recipient row and any email job
/// commit or roll back with the caller's own state change. The reminder
/// sweep marks a reminder sent in the same transaction that creates its
/// notification. Same shape as `attome_jobs::enqueue_in_tx`.
///
/// `category` is the preference category (B-R5), a platform event name such
/// as `reminder`. `None` falls back to the request's `template_key`. With
/// neither, or with a template marked mandatory, preferences are not read.
/// A preference only ever removes a channel; each removed channel is
/// recorded as `muted` in `channel_outcomes`.
pub async fn create_dispatch_in_tx(
    tx: &mut attome_db::Tx<'_>,
    notification_cfg: &attome_config::NotificationSection,
    req: DispatchRequest,
    category: Option<&str>,
) -> Result<Uuid, AppError> {
    let audience_count = usize::from(req.recipient_user_ref.is_some())
        + usize::from(req.organization_ref.is_some())
        + usize::from(req.is_global);
    if audience_count != 1 {
        return Err(AppError::Validation(
            "exactly one of recipient_user_ref, organization_ref, or is_global is required".into(),
        ));
    }

    let mut subject = req.subject.clone();
    let mut body_html = req.body_html.clone();
    let mut body_text = req.body_text.clone();
    let mut channels = req.channels.clone();
    let mut escalate_after_minutes = req.escalate_after_minutes;
    let mut escalate_channels = req.escalate_channels.clone();
    // M24/D-428 — see `crate::consent_gate`. Only a template can name a
    // purpose today; a request with no `template_key` has no gate to check.
    let mut consent_purpose_key: Option<String> = None;
    let mut is_mandatory = false;

    if let Some(key) = &req.template_key {
        let tpl = load_template(tx, key, &req.locale)
            .await?
            .ok_or_else(|| AppError::Validation(format!("unknown template_key: {key}")))?;
        subject = subject.or(tpl.subject);
        body_html = body_html.or(tpl.body_html);
        if body_text.is_none() {
            body_text = tpl.body_text;
        }
        if channels.is_none() {
            channels = tpl.default_channels.as_deref().map(parse_channel_list);
        }
        if escalate_after_minutes.is_none() {
            escalate_after_minutes = tpl.escalate_after_minutes;
        }
        if escalate_channels.is_none() {
            escalate_channels = tpl.escalate_channels.as_deref().map(parse_channel_list);
        }
        consent_purpose_key = tpl.consent_purpose_key;
        is_mandatory = tpl.is_mandatory;
    }

    // B-R5: the category preferences are checked against, or `None` when
    // they do not apply to this dispatch at all.
    let preference_category: Option<String> = if is_mandatory {
        None
    } else {
        category
            .map(str::to_owned)
            .or_else(|| req.template_key.clone())
            .filter(|c| !c.trim().is_empty())
    };

    let subject = subject.map(|t| apply_variables(&t, &req.variables));
    let body_html = body_html.map(|t| apply_variables_html(&t, &req.variables));
    let body_text = body_text
        .map(|t| apply_variables(&t, &req.variables))
        .filter(|t| !t.trim().is_empty())
        // F164/M51 Phase 1: a template (or request) that supplies HTML but no
        // explicit text still produces a usable text/plain part instead of
        // failing the whole dispatch.
        .or_else(|| {
            body_html
                .as_deref()
                .map(derive_text_from_html)
                .filter(|t| !t.trim().is_empty())
        })
        .ok_or_else(|| {
            AppError::Validation(
                "body_text is required (directly, via template_key, or derivable from body_html)"
                    .into(),
            )
        })?;

    let mut channels = channels
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| DEFAULT_CHANNELS.iter().map(|s| s.to_string()).collect());

    // U5 (B-R5): a direct recipient's own mutes remove channels from what the
    // request or template resolved. Applied after the default fallback above,
    // so a fully muted dispatch stays muted instead of falling back to the
    // defaults. An organization/global dispatch applies them per user when
    // its in-app rows are materialized (`recipient::fan_out_notification`).
    let mut muted: Vec<String> = Vec::new();
    if let (Some(user_id), Some(category)) = (req.recipient_user_ref, &preference_category) {
        muted = crate::preferences::muted_channels(tx, user_id, category).await?;
        muted.retain(|c| channels.contains(c));
        channels.retain(|c| !muted.contains(c));
        if let Some(esc) = escalate_channels.as_mut() {
            esc.retain(|c| !muted.contains(c));
        }
    }

    let in_app_requested = channels.iter().any(|channel| channel == "in_app");
    let email_requested = channels.iter().any(|channel| channel == "email");

    let dispatch_id = Uuid::now_v7();

    // M51 Phase 1: for a direct dispatch, resolve the recipient's email and
    // suppression status in the same transaction as the active-user check
    // below (and, further down, the dispatch insert + job enqueue) so the
    // whole decision is atomic. Scoped to `recipient_user_ref` only --
    // organization/global email fan-out is Phase 1's explicitly deferred
    // scope (see `send_email`'s doc comment); those channels remain a no-op
    // via the poller, unchanged.
    let mut email_target: Option<String> = None;
    let mut email_outcome: Option<&'static str> = None;

    if let Some(user_id) = req.recipient_user_ref {
        let row: Option<(bool, Option<String>)> =
            sqlx::query_as("SELECT is_active, email FROM user_account WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(AppError::internal)?;
        let (active, email) = row.unwrap_or((false, None));
        if !active {
            return Err(AppError::Validation(
                "recipient_user_ref must identify an active user".into(),
            ));
        }

        if email_requested {
            match email.filter(|e| !e.trim().is_empty()) {
                Some(addr) => {
                    // M24/D-428: a template naming a consent purpose blocks
                    // this recipient's email outright when they hold no
                    // active consent for it — checked before, and
                    // independently of, the suppression-list lookup below
                    // (a withdrawn/never-granted consent is a stronger "must
                    // not send" than a generic suppression entry), inside
                    // the same transaction as the rest of this decision so
                    // it's atomic with the dispatch insert further down.
                    // R1-T1: a consent-gated (marketing) email is processing
                    // a restricted person may have stopped.
                    let consent_ok = match &consent_purpose_key {
                        Some(purpose_key) => {
                            // E27-T2: the E27 ledger decides first; the M24
                            // row counts only where the ledger knows nothing.
                            let ledger = attome_core::consent_rules::gate(
                                tx,
                                ("user_account", user_id),
                                None,
                                purpose_key,
                                "email",
                                None,
                            )
                            .await?;
                            let legacy = crate::consent_gate::has_active_consent(
                                &mut **tx,
                                "user_account",
                                &user_id.to_string(),
                                purpose_key,
                            )
                            .await?;
                            crate::consent_gate::email_allowed(ledger, legacy)
                                && !attome_core::processing_restriction::record_is_restricted(
                                    &mut **tx,
                                    "user_account",
                                    user_id,
                                )
                                .await?
                        }
                        None => true,
                    };
                    if !consent_ok {
                        email_outcome = Some("consent_blocked");
                    } else {
                        let suppressed = is_email_suppressed(&mut **tx, &addr).await?;
                        if suppressed {
                            email_outcome = Some("suppressed");
                        } else {
                            email_target = Some(addr);
                            email_outcome = Some("sent");
                        }
                    }
                }
                None => email_outcome = Some("no_email"),
            }
        }
    }

    // `channels_sent` means "this channel's creation-time obligation has been
    // discharged", not necessarily "already delivered end-to-end" -- the
    // existing in_app convention (a fan-out dispatch marks `in_app` sent
    // immediately even though per-user materialization happens async). Email
    // follows the same convention once resolved above: `sent` (enqueued),
    // `suppressed`, and `no_email` are all terminal decisions the poller
    // must not retry, so all three land in `channels_sent`; only the
    // `channel_outcomes` map beneath it distinguishes them for operators.
    let channels_sent: Vec<String> = channels
        .iter()
        .filter(|channel| channel.as_str() == "in_app" || channel.as_str() == "email")
        .filter(|channel| channel.as_str() != "email" || email_outcome.is_some())
        .cloned()
        .collect();

    let mut channel_outcomes = serde_json::Map::new();
    for channel in &muted {
        channel_outcomes.insert(channel.clone(), serde_json::Value::String("muted".into()));
    }
    if let Some(outcome) = email_outcome {
        channel_outcomes.insert(
            "email".to_string(),
            serde_json::Value::String(outcome.into()),
        );
    }

    let created_at: DateTime<Utc> = sqlx::query_scalar(
        r#"INSERT INTO notification_dispatch
               (id, organization_ref, is_global, recipient_user_ref, template_key, locale,
                subject, body_html, body_text, route, channels, priority,
                escalate_after_minutes, escalate_channels, channels_sent, channel_outcomes,
                preference_category)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
           RETURNING created_at"#,
    )
    .bind(dispatch_id)
    .bind(req.organization_ref)
    .bind(req.is_global)
    .bind(req.recipient_user_ref)
    .bind(&req.template_key)
    .bind(&req.locale)
    .bind(&subject)
    .bind(&body_html)
    .bind(&body_text)
    .bind(&req.route)
    .bind(serde_json::to_value(&channels).map_err(AppError::internal)?)
    .bind(&req.priority)
    .bind(escalate_after_minutes)
    .bind(
        escalate_channels
            .as_ref()
            .map(|c| serde_json::to_value(c).unwrap_or_default()),
    )
    .bind(serde_json::to_value(&channels_sent).map_err(AppError::internal)?)
    .bind(serde_json::Value::Object(channel_outcomes))
    .bind(&preference_category)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    if in_app_requested {
        if let Some(user_id) = req.recipient_user_ref {
            let msg = recipient::RecipientMessage {
                dispatch_id,
                created_at,
                title: subject.as_deref(),
                message: &body_text,
                route: req.route.as_deref(),
                audience_kind: "direct",
            };
            recipient::insert_recipient(tx, &msg, user_id).await?;
        } else {
            recipient::enqueue_fanout_in_tx(tx, dispatch_id).await?;
        }
    }

    // M51 Phase 1: hand the resolved, not-suppressed direct-recipient email
    // off to the existing apalis SendEmail job, durably, in this same
    // transaction -- never opens SMTP itself (D-402).
    if let (Some(to), Some(user_id)) = (email_target, req.recipient_user_ref) {
        let delivery_id = Uuid::now_v7();
        attome_email::delivery::record_queued_in_tx(
            tx,
            delivery_id,
            attome_email::delivery::EmailDeliveryKind::Generic,
            &to,
            subject.as_deref().unwrap_or(""),
            Some(user_id),
            None,
            Some(dispatch_id),
        )
        .await
        .map_err(AppError::internal)?;

        // Idempotency key: a retried enqueue attempt for this exact
        // (dispatch, recipient) pair can never double-send (guidelines §2 --
        // apalis dedup, not a lock, since this is an insert-shaped op).
        let dedup_key = format!("{dispatch_id}:{user_id}");
        attome_jobs::enqueue_in_tx_dedup(
            tx,
            attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
                to,
                subject: subject.clone().unwrap_or_default(),
                text_body: body_text.clone(),
                html_body: body_html.clone(),
                delivery_id: Some(delivery_id),
                from_override: notification_cfg.email_from.clone(),
                message_id: None,
                in_reply_to: None,
                references: None,
                communication_id: None,
                attachments: Vec::new(),
            })),
            &dedup_key,
        )
        .await
        .map_err(AppError::internal)?;
    }

    Ok(dispatch_id)
}

/// Borrowed view over the fields `send_channel`/`send_in_app` need to deliver one
/// channel. Built from `ClaimedDispatch` for the primary dispatch path and from
/// `DueEscalation` (with a rewritten `[Escalated]` subject) for the escalation path —
/// both are shaped from the same `notification_dispatch` row set.
struct ChannelPayload<'a> {
    id: Uuid,
    created_at: DateTime<Utc>,
    organization_ref: Option<Uuid>,
    is_global: bool,
    recipient_user_ref: Option<Uuid>,
    subject: Option<&'a str>,
    body_html: Option<&'a str>,
    body_text: &'a str,
    route: Option<&'a str>,
}

#[derive(sqlx::FromRow)]
struct ClaimedDispatch {
    id: Uuid,
    created_at: DateTime<Utc>,
    organization_ref: Option<Uuid>,
    is_global: bool,
    recipient_user_ref: Option<Uuid>,
    subject: Option<String>,
    body_html: Option<String>,
    body_text: String,
    route: Option<String>,
    channels: serde_json::Value,
    channels_sent: serde_json::Value,
    attempts: i32,
}

impl ClaimedDispatch {
    fn payload(&self) -> ChannelPayload<'_> {
        ChannelPayload {
            id: self.id,
            created_at: self.created_at,
            organization_ref: self.organization_ref,
            is_global: self.is_global,
            recipient_user_ref: self.recipient_user_ref,
            subject: self.subject.as_deref(),
            body_html: self.body_html.as_deref(),
            body_text: &self.body_text,
            route: self.route.as_deref(),
        }
    }
}

/// Claims up to `limit` pending or stale-processing rows via `FOR UPDATE SKIP LOCKED` in a
/// single statement (its own implicit transaction, so this never holds a
/// transaction open across the actual channel I/O below — guidelines §4).
/// Safe under concurrent pollers on multiple app nodes: SKIP LOCKED means
/// two nodes racing this query never claim the same row.
async fn claim_pending_batch(db: &DbPool, limit: i64) -> Result<Vec<ClaimedDispatch>, AppError> {
    sqlx::query_as(
        r#"UPDATE notification_dispatch
           SET status = 'processing', updated_at = NOW(),
               attempts = attempts + 1, row_version = row_version + 1
           WHERE id IN (
               SELECT id FROM notification_dispatch
               WHERE is_deleted = FALSE
                 AND (
                     status = 'pending'
                     OR (
                         status = 'processing'
                         AND updated_at < NOW() - ($3 * INTERVAL '1 minute')
                     )
                 )
                 AND attempts < $2
               ORDER BY created_at
               LIMIT $1
               FOR UPDATE SKIP LOCKED
           )
           RETURNING id, created_at, organization_ref, is_global, recipient_user_ref,
                     subject, body_html, body_text, route, channels, channels_sent, attempts"#,
    )
    .bind(limit)
    .bind(MAX_ATTEMPTS)
    .bind(PROCESSING_STALE_AFTER_MINUTES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Refreshes `updated_at` on a still-processing/escalating row without
/// touching `status`/`attempts` — a heartbeat, not a claim. Row-missing or a
/// status change out from under it (e.g. concurrent `finish_dispatch`) is not
/// an error here: the heartbeat is best-effort and the send it's guarding
/// will persist its own real outcome momentarily.
async fn touch_processing(db: &DbPool, id: Uuid) -> Result<(), AppError> {
    sqlx::query("UPDATE notification_dispatch SET updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// Races `fut` against a periodic heartbeat so `claim_pending_batch`'s
/// staleness reclaim only fires when the worker actually died mid-send, not
/// merely because one channel's external I/O (SMTP, a webhook, ...) outlives
/// `PROCESSING_STALE_AFTER_MINUTES`. Without this, a second node's poller
/// tick could reclaim and re-send a row whose original claimant is still
/// alive and working on it — a genuine double-send, not just a crash-recovery
/// retry.
async fn send_channel_with_heartbeat(
    db: &DbPool,
    dispatch_id: Uuid,
    fut: impl std::future::Future<Output = Result<(), AppError>>,
) -> Result<(), AppError> {
    tokio::pin!(fut);
    let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
    ticker.tick().await; // first tick is immediate; consume it before racing
    loop {
        tokio::select! {
            result = &mut fut => return result,
            _ = ticker.tick() => {
                if let Err(e) = touch_processing(db, dispatch_id).await {
                    tracing::warn!(
                        dispatch_id = %dispatch_id,
                        error = %e,
                        "notification dispatch heartbeat failed"
                    );
                }
            }
        }
    }
}

async fn finish_dispatch(
    db: &DbPool,
    id: Uuid,
    channels_sent: &[String],
    all_done: bool,
    attempts: i32,
    last_error: Option<&str>,
) -> Result<(), AppError> {
    let status = if all_done {
        "sent"
    } else if attempts >= MAX_ATTEMPTS {
        "failed"
    } else {
        "pending"
    };
    let dispatched_at = all_done.then(Utc::now);

    sqlx::query(
        r#"UPDATE notification_dispatch
           SET status = $2, channels_sent = $3, last_error = $4,
               dispatched_at = COALESCE($5, dispatched_at), updated_at = NOW()
           WHERE id = $1"#,
    )
    .bind(id)
    .bind(status)
    .bind(serde_json::to_value(channels_sent).map_err(AppError::internal)?)
    .bind(last_error)
    .bind(dispatched_at)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Persists each successful primary channel immediately. If the worker dies
/// later in the same batch, the next attempt can skip this channel.
async fn mark_channel_sent(db: &DbPool, id: Uuid, channel: &str) -> Result<(), AppError> {
    let channel_json = serde_json::to_value([channel]).map_err(AppError::internal)?;
    let result = sqlx::query(
        r#"UPDATE notification_dispatch
           SET channels_sent = channels_sent || $2::jsonb,
               row_version = row_version + 1, updated_at = NOW()
           WHERE id = $1"#,
    )
    .bind(id)
    .bind(channel_json)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    if result.rows_affected() != 1 {
        return Err(AppError::internal(
            "notification dispatch disappeared while marking a channel sent",
        ));
    }
    Ok(())
}

/// Persists each successful escalation channel immediately. Escalation is not
/// complete until every requested channel is present in this JSON array.
async fn mark_escalation_channel_sent(
    db: &DbPool,
    id: Uuid,
    channel: &str,
) -> Result<(), AppError> {
    let channel_json = serde_json::to_value([channel]).map_err(AppError::internal)?;
    let result = sqlx::query(
        r#"UPDATE notification_dispatch
           SET escalation_channels_sent = escalation_channels_sent || $2::jsonb,
               row_version = row_version + 1, updated_at = NOW()
           WHERE id = $1"#,
    )
    .bind(id)
    .bind(channel_json)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    if result.rows_affected() != 1 {
        return Err(AppError::internal(
            "notification dispatch disappeared while marking an escalation channel sent",
        ));
    }
    Ok(())
}

async fn finish_escalation(
    db: &DbPool,
    id: Uuid,
    all_done: bool,
    last_error: Option<&str>,
) -> Result<(), AppError> {
    let escalated_at = all_done.then(Utc::now);
    let result = sqlx::query(
        r#"UPDATE notification_dispatch
           SET status = 'escalated',
               escalated_at = COALESCE($2, escalated_at),
               last_error = $3, row_version = row_version + 1, updated_at = NOW()
           WHERE id = $1 AND status = 'escalated'"#,
    )
    .bind(id)
    .bind(escalated_at)
    .bind(last_error)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    if result.rows_affected() != 1 {
        return Err(AppError::internal(
            "notification dispatch disappeared while finishing escalation",
        ));
    }
    Ok(())
}

/// Delivers the in-app channel into the canonical recipient table. Direct
/// rows are inserted idempotently; organization/global audiences hand off to
/// the durable fan-out job. The legacy `notification_inbox` table is not
/// written by this path.
async fn send_in_app(db: &DbPool, payload: &ChannelPayload<'_>) -> Result<(), AppError> {
    if let Some(user_id) = payload.recipient_user_ref {
        let mut tx = attome_db::tx::begin(db).await?;
        let msg = recipient::RecipientMessage {
            dispatch_id: payload.id,
            created_at: payload.created_at,
            title: payload.subject,
            message: payload.body_text,
            route: payload.route,
            audience_kind: "direct",
        };
        let inserted = recipient::insert_recipient(&mut tx, &msg, user_id).await?;
        tx.commit().await.map_err(AppError::internal)?;
        if !inserted {
            tracing::debug!(
                dispatch_id = %payload.id,
                user_id = %user_id,
                "in_app send: recipient row already existed (idempotent no-op)"
            );
        }
        Ok(())
    } else if payload.is_global || payload.organization_ref.is_some() {
        attome_jobs::enqueue_on_pool(
            db,
            attome_core::jobs::EngineJob::FanOutNotification {
                dispatch_id: payload.id,
            },
        )
        .await
        .map_err(AppError::internal)
    } else {
        Err(AppError::Validation(
            "notification dispatch has no valid audience".into(),
        ))
    }
}

/// Email is a per-recipient channel: an `is_global` broadcast with no
/// `recipient_user_ref`, or a recipient with no email on file, is treated as
/// a no-op success (nothing to send) rather than a retry-forever failure.
/// Retries are at-least-once: a crash after an SMTP/provider accept but before
/// progress persistence can result in a duplicate external delivery.
async fn send_email(
    db: &DbPool,
    cfg: &attome_config::EmailSection,
    recipient_user_ref: Option<Uuid>,
    subject: &str,
    body_text: &str,
    body_html: Option<&str>,
) -> Result<(), AppError> {
    let Some(user_id) = recipient_user_ref else {
        return Ok(());
    };
    let to: Option<String> = sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .flatten();
    let Some(to) = to else {
        return Ok(());
    };

    attome_email::send(
        cfg,
        db,
        attome_email::EmailMessage {
            to,
            subject: subject.to_string(),
            text_body: body_text.to_string(),
            html_body: body_html.map(|s| s.to_string()),
            // This path (org/global no-op today, and escalation resends --
            // both out of M51 Phase 1's scope) has no `NotificationSection`
            // in scope, so it always rides the deployment default "From"
            // rather than `notification.email_from`; only the direct-dispatch
            // path in `create_dispatch` applies that override.
            from_override: None,
            // Not one of the three account-lifecycle producers -- this
            // path keeps its own independent attempts/status tracking
            // (notification_dispatch) rather than a email_delivery
            // row. It still gets the suppression/classification hardening
            // for free via send() itself.
            delivery_id: None,
            // M52 Phase 1 (D-465): this escalation/org-global send path has
            // no threading or `communication` concept — `None` for all
            // four, same as every other non-M52 producer.
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
            attachments: Vec::new(),
        },
    )
    .await
    .map_err(Into::into)
}

/// SMS/push/chat (F163) — this environment has no provider credentials, so
/// these route through the pluggable `NotificationService` trait
/// (`attome_core::services`): a deployment wires a real provider via
/// `EngineSystem::builder().notifications(..)`, everything above this line stays
/// unchanged.
///
/// With no provider wired (`NotificationService::is_noop`, i.e. the default
/// `NoopNotifications`) this is a real failure, not a success: the dispatch
/// row keeps its attempt/error bookkeeping and the channel is never marked
/// `sent`, so an operator can see that `sms`/`push`/`chat` audiences are
/// configured on a deployment that cannot deliver them (T3-7, review item
/// 3.17). `CapabilityUnavailable` is the established D-344 shape for "a named
/// dependency is confirmed absent on this node" (503), which is exactly this.
async fn send_via_service(
    notifications: &Arc<dyn NotificationService>,
    recipient_user_ref: Option<Uuid>,
    subject: &str,
    body_text: &str,
) -> Result<(), AppError> {
    if notifications.is_noop() {
        return Err(AppError::CapabilityUnavailable(
            NOTIFICATION_PROVIDER_CAPABILITY,
        ));
    }
    let recipient = recipient_user_ref
        .map(|u| u.to_string())
        .unwrap_or_else(|| "global".to_string());
    notifications
        .send(&recipient, subject, body_text)
        .await
        .map_err(AppError::internal)
}

/// Channel delivery is at-least-once until a real provider integration defines
/// and implements provider-specific idempotency/reconciliation semantics.
async fn send_channel(
    state: &EngineState,
    channel: &str,
    payload: &ChannelPayload<'_>,
) -> Result<(), AppError> {
    let subject = payload.subject.unwrap_or("");
    match channel {
        "in_app" => send_in_app(&state.base.db, payload).await,
        // J4-T1: to the recipient's phone, through the SMS provider.
        "sms" => {
            attome_integration::sms::send_to_user(
                state,
                payload.recipient_user_ref,
                payload.body_text,
            )
            .await
        }
        // J12-T1: to every address the recipient registered.
        "push" => {
            crate::push::send_to_user(
                state,
                payload.recipient_user_ref,
                &crate::push::PushMessage {
                    title: subject.to_owned(),
                    body: payload.body_text.to_owned(),
                    route: payload.route.map(str::to_owned),
                },
            )
            .await
        }
        "email" => {
            send_email(
                &state.base.db,
                &state.base.config.email,
                payload.recipient_user_ref,
                subject,
                payload.body_text,
                payload.body_html,
            )
            .await
        }
        _ => {
            send_via_service(
                &state.notifications,
                payload.recipient_user_ref,
                subject,
                payload.body_text,
            )
            .await
        }
    }
}

/// Claims and processes one batch of pending dispatch rows. Called from
/// `crate::poller` on an interval, not the request path.
pub async fn run_pending_batch(state: &EngineState, limit: i64) {
    let rows = match claim_pending_batch(&state.base.db, limit).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "notification dispatch: claim batch failed");
            return;
        }
    };

    for row in rows {
        let requested: Vec<String> =
            serde_json::from_value(row.channels.clone()).unwrap_or_default();
        let mut sent: Vec<String> =
            serde_json::from_value(row.channels_sent.clone()).unwrap_or_default();
        let mut last_error: Option<String> = None;

        for channel in &requested {
            if sent.contains(channel) {
                continue;
            }
            let result = send_channel_with_heartbeat(
                &state.base.db,
                row.id,
                send_channel(state, channel, &row.payload()),
            )
            .await;

            match result {
                Ok(()) => {
                    if let Err(e) = mark_channel_sent(&state.base.db, row.id, channel).await {
                        tracing::warn!(
                            dispatch_id = %row.id,
                            channel = %channel,
                            error = %e,
                            "notification channel sent but progress persistence failed"
                        );
                        last_error = Some(e.to_string());
                    } else {
                        sent.push(channel.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!(dispatch_id = %row.id, channel = %channel, error = %e, "notification channel send failed");
                    last_error = Some(e.to_string());
                }
            }
        }

        let all_done = requested.iter().all(|c| sent.contains(c));
        if let Err(e) = finish_dispatch(
            &state.base.db,
            row.id,
            &sent,
            all_done,
            row.attempts,
            last_error.as_deref(),
        )
        .await
        {
            tracing::error!(dispatch_id = %row.id, error = %e, "notification dispatch: finish update failed");
        }
    }
}

#[derive(sqlx::FromRow)]
struct DueEscalation {
    id: Uuid,
    created_at: DateTime<Utc>,
    subject: Option<String>,
    body_text: String,
    recipient_user_ref: Option<Uuid>,
    organization_ref: Option<Uuid>,
    is_global: bool,
    escalate_channels: Option<serde_json::Value>,
    escalation_channels_sent: serde_json::Value,
}

/// F172 — escalation if a notification is ignored. Claims every due
/// `sent` dispatch with at least one unread recipient row, then sends
/// `escalate_channels`. `status = 'escalated'` is the in-progress claim;
/// `escalated_at` is written only after every requested escalation channel has
/// been persisted as sent. Stale claims are reclaimed after the same threshold
/// used by the primary dispatch path.
pub async fn run_due_escalations(state: &EngineState, limit: i64) {
    let rows: Result<Vec<DueEscalation>, _> = sqlx::query_as(
        r#"UPDATE notification_dispatch d
           SET status = 'escalated', updated_at = NOW()
           WHERE d.id IN (
               SELECT d2.id FROM notification_dispatch d2
               WHERE d2.is_deleted = FALSE AND d2.escalated_at IS NULL
                 AND d2.escalate_after_minutes IS NOT NULL
                 AND (
                     d2.status = 'sent'
                     OR (
                         d2.status = 'escalated'
                         AND d2.updated_at < NOW() - ($2 * INTERVAL '1 minute')
                     )
                )
                AND d2.dispatched_at + (d2.escalate_after_minutes || ' minutes')::interval <= NOW()
                 AND EXISTS (
                     SELECT 1 FROM notification_recipient nr
                      WHERE nr.dispatch_ref = d2.id
                        AND nr.is_deleted = FALSE
                        AND nr.read_at IS NULL
                 )
               ORDER BY d2.dispatched_at
               LIMIT $1
               FOR UPDATE OF d2 SKIP LOCKED
           )
            RETURNING d.id, d.created_at, d.subject, d.body_text, d.recipient_user_ref,
                      d.organization_ref, d.is_global, d.escalate_channels,
                      d.escalation_channels_sent"#,
    )
    .bind(limit)
    .bind(PROCESSING_STALE_AFTER_MINUTES)
    .fetch_all(&state.base.db)
    .await;

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "notification escalation: claim failed");
            return;
        }
    };

    for row in rows {
        let channels: Vec<String> = row
            .escalate_channels
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let mut sent: Vec<String> =
            serde_json::from_value(row.escalation_channels_sent.clone()).unwrap_or_default();
        let mut last_error: Option<String> = None;
        let subject = row
            .subject
            .as_deref()
            .map(|s| format!("[Escalated] {s}"))
            .unwrap_or_else(|| "[Escalated]".to_string());
        let payload = ChannelPayload {
            id: row.id,
            created_at: row.created_at,
            organization_ref: row.organization_ref,
            is_global: row.is_global,
            recipient_user_ref: row.recipient_user_ref,
            subject: Some(&subject),
            body_html: None,
            body_text: &row.body_text,
            route: None,
        };

        for channel in &channels {
            if sent.contains(channel) {
                continue;
            }
            let result = send_channel_with_heartbeat(
                &state.base.db,
                row.id,
                send_channel(state, channel, &payload),
            )
            .await;
            match result {
                Ok(()) => {
                    if let Err(e) =
                        mark_escalation_channel_sent(&state.base.db, row.id, channel).await
                    {
                        tracing::warn!(
                            dispatch_id = %row.id,
                            channel = %channel,
                            error = %e,
                            "escalation channel sent but progress persistence failed"
                        );
                        last_error = Some(e.to_string());
                    } else {
                        sent.push(channel.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        dispatch_id = %row.id,
                        channel = %channel,
                        error = %e,
                        "escalation channel send failed"
                    );
                    last_error = Some(e.to_string());
                }
            }
        }

        let all_done = channels.iter().all(|channel| sent.contains(channel));
        if let Err(e) =
            finish_escalation(&state.base.db, row.id, all_done, last_error.as_deref()).await
        {
            tracing::error!(dispatch_id = %row.id, error = %e, "notification escalation: finish update failed");
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────
//
// Everything else in this module (`create_dispatch`, `claim_pending_batch`,
// `run_pending_batch`, `run_due_escalations`, ...) needs a live Postgres with
// the platform's migrations applied — see `tests/dispatch.rs` (requires
// `DATABASE_URL`, not runnable in this sandbox). `apply_variables`,
// `parse_channel_list`, and `derive_text_from_html` are pure string logic
// with no I/O, so they're covered directly here.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_variables_replaces_every_placeholder() {
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "Ada".to_string());
        vars.insert("amount".to_string(), "42".to_string());

        let out = apply_variables("Hi {{name}}, you have {{amount}} credits.", &vars);
        assert_eq!(out, "Hi Ada, you have 42 credits.");
    }

    #[test]
    fn apply_variables_is_a_no_op_when_no_variables_are_given() {
        let vars = HashMap::new();
        let out = apply_variables("Hi {{name}}, welcome.", &vars);
        assert_eq!(out, "Hi {{name}}, welcome.");
    }

    #[test]
    fn apply_variables_leaves_unmatched_placeholders_untouched() {
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "Ada".to_string());
        let out = apply_variables("Hi {{name}}, ref {{unknown}}.", &vars);
        assert_eq!(out, "Hi Ada, ref {{unknown}}.");
    }

    /// A variable's value is never expanded again: the old whole-string
    /// replace loop expanded `{{b}}` inside `a`'s value, or not, depending on
    /// `HashMap` iteration order.
    #[test]
    fn apply_variables_does_not_expand_placeholders_inside_values() {
        let mut vars = HashMap::new();
        vars.insert("a".to_string(), "{{b}}".to_string());
        vars.insert("b".to_string(), "B".to_string());
        assert_eq!(apply_variables("{{a}} {{ b }}", &vars), "{{b}} B");
    }

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// Owner decision 2: a variable merged into `body_html` is escaped, so
    /// markup in it renders as text and never executes.
    #[test]
    fn apply_variables_html_escapes_script_markup_in_values() {
        let v = vars(&[("name", "<script>alert(1)</script>")]);
        assert_eq!(
            apply_variables_html("<p>Hi {{name}}</p>", &v),
            "<p>Hi &lt;script&gt;alert(1)&lt;/script&gt;</p>"
        );
    }

    #[test]
    fn apply_variables_html_escapes_ampersands_and_quotes() {
        let v = vars(&[("company", r#"Tom & "Jerry's""#)]);
        assert_eq!(
            apply_variables_html(r#"<a title="{{company}}">{{ company }}</a>"#, &v),
            "<a title=\"Tom &amp; &quot;Jerry&#39;s&quot;\">Tom &amp; &quot;Jerry&#39;s&quot;</a>"
        );
    }

    /// The template's own markup is not touched; unknown names stay verbatim.
    #[test]
    fn apply_variables_html_keeps_template_markup_and_unknown_placeholders() {
        let v = vars(&[("name", "Ada")]);
        assert_eq!(
            apply_variables_html("<p><b>{{name}}</b> {{unknown}}</p>", &v),
            "<p><b>Ada</b> {{unknown}}</p>"
        );
        assert_eq!(
            apply_variables_html("<p>{{name}}</p>", &HashMap::new()),
            "<p>{{name}}</p>"
        );
    }

    /// Subjects and plain-text bodies are not HTML, so they are not escaped.
    #[test]
    fn apply_variables_leaves_plain_text_values_unescaped() {
        let v = vars(&[("name", r#"<b>Tom</b> & "Jerry's""#)]);
        assert_eq!(
            apply_variables("Hi {{name}}", &v),
            r#"Hi <b>Tom</b> & "Jerry's""#
        );
    }

    /// The text fallback derived from an escaped HTML body shows the value as
    /// the sender typed it — including a literal entity, decoded only once.
    #[test]
    fn derive_text_from_an_escaped_html_body_round_trips_the_value() {
        let v = vars(&[("name", "<b>Tom</b> & &lt;Jerry&gt;")]);
        let html = apply_variables_html("<p>Hi {{name}}</p>", &v);
        assert_eq!(
            derive_text_from_html(&html),
            "Hi <b>Tom</b> & &lt;Jerry&gt;"
        );
    }

    #[test]
    fn parse_channel_list_trims_lowercases_and_drops_empty_segments() {
        let out = parse_channel_list(" Email, IN_APP ,, sms ");
        assert_eq!(out, vec!["email", "in_app", "sms"]);
    }

    #[test]
    fn parse_channel_list_of_a_single_channel() {
        let out = parse_channel_list("in_app");
        assert_eq!(out, vec!["in_app"]);
    }

    #[test]
    fn parse_channel_list_of_an_empty_string_is_empty() {
        let out = parse_channel_list("");
        assert!(out.is_empty());
    }

    #[test]
    fn derive_text_from_html_strips_tags_and_turns_block_boundaries_into_newlines() {
        let out = derive_text_from_html("<p>Hello <b>Ada</b>,</p><p>You have a task.</p>");
        assert_eq!(out, "Hello Ada,\nYou have a task.");
    }

    #[test]
    fn derive_text_from_html_unescapes_common_entities() {
        let out = derive_text_from_html("<p>Terms &amp; Conditions &mdash;? &lt;ok&gt;</p>");
        assert_eq!(out, "Terms & Conditions &mdash;? <ok>");
    }

    #[test]
    fn derive_text_from_html_of_plain_text_with_no_markup_is_unchanged() {
        let out = derive_text_from_html("just plain text, no tags");
        assert_eq!(out, "just plain text, no tags");
    }

    #[test]
    fn derive_text_from_html_of_empty_or_whitespace_only_html_is_empty() {
        assert_eq!(derive_text_from_html(""), "");
        assert_eq!(derive_text_from_html("<p>   </p>"), "");
    }

    // T3-7 (review item 3.17): the noop backend must surface as a failure,
    // not a phantom delivery. Pure in-memory — no DB, no state.
    #[tokio::test]
    async fn send_via_service_fails_closed_on_the_noop_backend() {
        let noop: Arc<dyn NotificationService> = Arc::new(attome_core::NoopNotifications);
        let err = send_via_service(&noop, Some(Uuid::now_v7()), "subject", "body")
            .await
            .expect_err("noop backend must not report success");
        assert!(
            matches!(err, AppError::CapabilityUnavailable(name) if name == NOTIFICATION_PROVIDER_CAPABILITY),
            "expected CapabilityUnavailable({NOTIFICATION_PROVIDER_CAPABILITY:?}), got {err:?}"
        );
    }

    #[tokio::test]
    async fn send_via_service_delivers_through_a_real_provider() {
        // A provider that keeps the trait's default `is_noop() == false` and
        // records what it was asked to send.
        struct Recording(std::sync::Mutex<Vec<(String, String, String)>>);
        impl NotificationService for Recording {
            fn send<'a>(
                &'a self,
                recipient: &'a str,
                subject: &'a str,
                body: &'a str,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<(), attome_core::ServiceError>>
                        + Send
                        + 'a,
                >,
            > {
                self.0.lock().unwrap().push((
                    recipient.to_owned(),
                    subject.to_owned(),
                    body.to_owned(),
                ));
                Box::pin(async { Ok(()) })
            }
        }

        let provider = Arc::new(Recording(std::sync::Mutex::new(Vec::new())));
        let svc: Arc<dyn NotificationService> = provider.clone();
        let user = Uuid::now_v7();

        send_via_service(&svc, Some(user), "subject", "body")
            .await
            .expect("a wired provider delivers");
        send_via_service(&svc, None, "s2", "b2")
            .await
            .expect("a global audience is addressed as \"global\"");

        let sent = provider.0.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], (user.to_string(), "subject".into(), "body".into()));
        assert_eq!(sent[1].0, "global");
    }
}
