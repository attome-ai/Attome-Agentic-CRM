//! D-435 — the nightly AI quality monitor: scans `ai_suggestion_outcome`
//! for accept/edit/reject rates per `(action, model, prompt_version)`, flags
//! a significant drift against the prior period, and raises an M51 in-app
//! alert to platform admins. Feeds the same table the stored query in
//! `platform-bundles/attome-ai-quality.json` reads for the M27 `ai.acceptance_rate` metric, but computes its own
//! per-group breakdown independently — the metric snapshot is one aggregate
//! number for a dashboard tile, and this job's job is the drift *signal*, not
//! the number.
//!
//! **"Hallucination" proxy.** Per the module plan: reject rate on factual
//! actions is the proxy available today; true grounding checks (an answer
//! citing a traversed node/chunk) arrive with M38 and are out of scope here.
//!
//! **Why per-group, not one platform-wide rate.** A single blended rate
//! hides the failure this exists to catch: one action or one model quietly
//! degrading while everything else looks fine drowns in the average. Grouping
//! by `(action_id, model_id, prompt_version)` is also what lets a prompt
//! change be judged in isolation — the exact reason every prompt in this
//! crate is version-stamped in the first place (`prompt_registry.rs`'s doc
//! comment).
//!
//! Invoked by `EngineJob::AiQualityMonitor` (`crates/server/src/jobs.rs`),
//! scheduled once/day like the other maintenance-class sweeps in that file.

use std::collections::HashMap;

use attome_config::NotificationSection;
use attome_db::DbPool;
use attome_notification::dispatch::{DispatchRequest, create_dispatch};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A group needs at least this many DECIDED (non-pending) suggestions in
/// BOTH the current and prior period before a drift is trusted — a group
/// with 2 decided outcomes swinging from 100% to 0% is noise, not drift, and
/// alerting on it trains operators to ignore this alert.
const MIN_SAMPLE: i64 = 10;

/// A drop of at least this many percentage points in the acceptance rate
/// (accepted+edited over decided) is "significant" enough to alert on.
const ACCEPTANCE_DROP_THRESHOLD: f64 = 0.15;
/// N31-T1: a drop this large switches the action off automatically
/// (`scope_switch::trip`, cause `quality`) until an administrator turns it
/// back on.
pub const SEVERE_DROP_THRESHOLD: f64 = 0.30;

const PERIOD_DAYS: i64 = 7;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GroupOutcome {
    pub action_id: String,
    pub model_id: String,
    pub prompt_version: String,
    pub current_total: i64,
    pub current_accepted: i64,
    pub current_edited: i64,
    pub current_rejected: i64,
    pub prior_total: i64,
    pub prior_accepted: i64,
    pub prior_edited: i64,
}

impl GroupOutcome {
    pub fn current_acceptance_rate(&self) -> Option<f64> {
        if self.current_total == 0 {
            None
        } else {
            Some((self.current_accepted + self.current_edited) as f64 / self.current_total as f64)
        }
    }

    pub fn prior_acceptance_rate(&self) -> Option<f64> {
        if self.prior_total == 0 {
            None
        } else {
            Some((self.prior_accepted + self.prior_edited) as f64 / self.prior_total as f64)
        }
    }

    /// Pure — unit-tested directly without a database. Both periods must
    /// clear [`MIN_SAMPLE`] and the drop must clear [`ACCEPTANCE_DROP_THRESHOLD`].
    /// A significant drop of at least [`SEVERE_DROP_THRESHOLD`] (N31-T1).
    pub fn is_severe_drop(&self) -> bool {
        self.is_significant_drop()
            && match (self.prior_acceptance_rate(), self.current_acceptance_rate()) {
                (Some(prior), Some(current)) => prior - current >= SEVERE_DROP_THRESHOLD,
                _ => false,
            }
    }

    pub fn is_significant_drop(&self) -> bool {
        if self.current_total < MIN_SAMPLE || self.prior_total < MIN_SAMPLE {
            return false;
        }
        match (self.prior_acceptance_rate(), self.current_acceptance_rate()) {
            (Some(prior), Some(current)) => prior - current >= ACCEPTANCE_DROP_THRESHOLD,
            _ => false,
        }
    }
}

async fn fetch_group_outcomes(
    db: &DbPool,
    now: DateTime<Utc>,
) -> Result<Vec<GroupOutcome>, AppError> {
    let period_start = now - chrono::Duration::days(PERIOD_DAYS);
    let prior_start = now - chrono::Duration::days(PERIOD_DAYS * 2);

    sqlx::query_as::<_, GroupOutcome>(
        "SELECT action_id, model_id, prompt_version, \
                COUNT(*) FILTER (WHERE created_at >= $1 AND outcome != 'pending') AS current_total, \
                COUNT(*) FILTER (WHERE created_at >= $1 AND outcome = 'accepted') AS current_accepted, \
                COUNT(*) FILTER (WHERE created_at >= $1 AND outcome = 'edited') AS current_edited, \
                COUNT(*) FILTER (WHERE created_at >= $1 AND outcome = 'rejected') AS current_rejected, \
                COUNT(*) FILTER (WHERE created_at >= $2 AND created_at < $1 AND outcome != 'pending') \
                    AS prior_total, \
                COUNT(*) FILTER (WHERE created_at >= $2 AND created_at < $1 AND outcome = 'accepted') \
                    AS prior_accepted, \
                COUNT(*) FILTER (WHERE created_at >= $2 AND created_at < $1 AND outcome = 'edited') \
                    AS prior_edited \
         FROM ai_suggestion_outcome \
         WHERE created_at >= $2 \
         GROUP BY action_id, model_id, prompt_version",
    )
    .bind(period_start)
    .bind(prior_start)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Every active `system.admin` holder — direct grant or role-mediated
/// (`user_account_mm_privilege` / `role_mm_privilege` joined
/// through `user_account_mm_role`), same join shape
/// `attome_security::db::resolve_privileges` uses per-user, inverted here to
/// resolve every user holding one specific privilege. Team-mediated
/// `system.admin` grants (via `role_mm_team`) are not swept — a
/// best-effort audience for a best-effort alert, the same trade-off
/// `attome_metric::metric::run_scheduled_snapshot_sweep`'s per-metric failure
/// isolation documents for a comparable "one gap costs one data point, not
/// the whole sweep" reason.
async fn admin_recipients(db: &DbPool) -> Result<Vec<Uuid>, AppError> {
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

/// Best-effort: a dispatch failure for one admin (or the whole recipient
/// resolution) is logged and never fails the sweep — the drop is already
/// logged at `warn` by [`run`] regardless of whether the notification
/// reaches anyone, same "the log is the fact, the alert is a convenience"
/// posture the rest of this job takes.
async fn alert_significant_drop(
    db: &DbPool,
    notification_cfg: &NotificationSection,
    group: &GroupOutcome,
) {
    let recipients = match admin_recipients(db).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                error = %e,
                "ai quality monitor: failed to resolve admin recipients for a drift alert"
            );
            return;
        }
    };

    let subject = format!(
        "AI acceptance rate dropped: {} / {} / {}",
        group.action_id, group.model_id, group.prompt_version
    );
    let body = format!(
        "Acceptance rate for action '{}' using model '{}' (prompt {}) dropped from {:.0}% to \
         {:.0}% over the last {PERIOD_DAYS} days (n={} decided vs n={} decided in the prior \
         period). Review at /admin/ai/compliance-report.",
        group.action_id,
        group.model_id,
        group.prompt_version,
        group.prior_acceptance_rate().unwrap_or(0.0) * 100.0,
        group.current_acceptance_rate().unwrap_or(0.0) * 100.0,
        group.current_total,
        group.prior_total,
    );

    for user_id in recipients {
        let req = DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(user_id),
            is_global: false,
            organization_ref: None,
            channels: None, // REVIEW-2026-09-02 finding #3: inherit the platform default (in_app+email), not an in-app-only override
            subject: Some(subject.clone()),
            body_html: None,
            body_text: Some(body.clone()),
            route: Some("/admin/ai/compliance-report".to_string()),
            variables: HashMap::new(),
            priority: "high".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        if let Err(e) = create_dispatch(db, notification_cfg, req).await {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                "ai quality monitor: drift alert dispatch failed for one recipient"
            );
        }
    }
}

/// Sends one alert to every administrator, best effort: a failure is logged
/// and never fails the caller's job (the caller has already logged the fact).
pub async fn alert_admins(
    db: &DbPool,
    notification_cfg: &NotificationSection,
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

pub struct QualityMonitorSummary {
    pub groups_checked: usize,
    pub groups_flagged: usize,
    /// Actions whose acceptance fell by [`SEVERE_DROP_THRESHOLD`] or more,
    /// for the caller to switch off (N31-T1).
    pub severe_actions: Vec<String>,
}

impl std::fmt::Debug for QualityMonitorSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QualityMonitorSummary")
            .finish_non_exhaustive()
    }
}

/// The job's entry point (`EngineJob::AiQualityMonitor`'s handler). Failure
/// isolation matches `run_scheduled_snapshot_sweep`'s posture at the group
/// level implicitly — a failure inside `fetch_group_outcomes` fails the whole
/// run (there's one query, not one per group), but a failure alerting on one
/// flagged group never stops the rest (`alert_significant_drop` never
/// propagates an error).
pub async fn run(
    db: &DbPool,
    notification_cfg: &NotificationSection,
) -> Result<QualityMonitorSummary, AppError> {
    let groups = fetch_group_outcomes(db, Utc::now()).await?;
    let mut flagged = 0usize;
    let mut severe_actions: Vec<String> = Vec::new();

    for group in &groups {
        if group.is_significant_drop() {
            flagged += 1;
            tracing::warn!(
                action_id = %group.action_id,
                model_id = %group.model_id,
                prompt_version = %group.prompt_version,
                current_rate = ?group.current_acceptance_rate(),
                prior_rate = ?group.prior_acceptance_rate(),
                current_total = group.current_total,
                prior_total = group.prior_total,
                "ai quality monitor: significant acceptance-rate drop detected"
            );
            alert_significant_drop(db, notification_cfg, group).await;
            if group.is_severe_drop() && !severe_actions.contains(&group.action_id) {
                severe_actions.push(group.action_id.clone());
            }
        }
    }

    Ok(QualityMonitorSummary {
        groups_checked: groups.len(),
        groups_flagged: flagged,
        severe_actions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(
        current_total: i64,
        current_accepted: i64,
        prior_total: i64,
        prior_accepted: i64,
    ) -> GroupOutcome {
        GroupOutcome {
            action_id: "record.summarize".to_string(),
            model_id: "test-model".to_string(),
            prompt_version: "record.summarize/v1".to_string(),
            current_total,
            current_accepted,
            current_edited: 0,
            current_rejected: current_total - current_accepted,
            prior_total,
            prior_accepted,
            prior_edited: 0,
        }
    }

    #[test]
    fn only_a_severe_drop_trips() {
        // 90% to 50%: severe. 90% to 72%: significant only.
        assert!(group(20, 10, 20, 18).is_severe_drop());
        let mild = group(50, 36, 20, 18);
        assert!(mild.is_significant_drop());
        assert!(!mild.is_severe_drop());
    }

    #[test]
    fn a_real_drop_past_threshold_is_flagged() {
        // prior: 18/20 = 90%, current: 10/20 = 50% -- a 40pt drop.
        let g = group(20, 10, 20, 18);
        assert!(g.is_significant_drop());
    }

    #[test]
    fn a_small_fluctuation_is_not_flagged() {
        // prior: 18/20 = 90%, current: 17/20 = 85% -- a 5pt drop, under threshold.
        let g = group(20, 17, 20, 18);
        assert!(!g.is_significant_drop());
    }

    #[test]
    fn a_drop_below_the_sample_floor_is_never_flagged() {
        // prior: 2/2 = 100%, current: 0/2 = 0% -- a huge swing, but n=2 is noise.
        let g = group(2, 0, 2, 2);
        assert!(
            !g.is_significant_drop(),
            "a group under MIN_SAMPLE must never alert, however large the swing"
        );
    }

    #[test]
    fn a_group_with_no_prior_period_data_is_never_flagged() {
        let g = group(20, 5, 0, 0);
        assert!(!g.is_significant_drop());
        assert_eq!(g.prior_acceptance_rate(), None);
    }

    #[test]
    fn an_improvement_is_never_flagged() {
        // prior: 10/20 = 50%, current: 18/20 = 90% -- got BETTER.
        let g = group(20, 18, 20, 10);
        assert!(!g.is_significant_drop());
    }

    #[test]
    fn acceptance_rate_counts_edited_as_used() {
        let mut g = group(20, 10, 20, 10);
        g.current_edited = 5;
        // (10 accepted + 5 edited) / 20 = 75%.
        assert_eq!(g.current_acceptance_rate(), Some(0.75));
    }
}
