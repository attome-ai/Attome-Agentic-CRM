//! Deliverability alerts (roadmap E6-T10), evaluated daily over the
//! previous day:
//!
//! - bounce and complaint rates per sending domain and mailbox provider
//!   above the policy's `bounce_warn_percent` (default 2%) and
//!   `complaint_warn_percent` (default 0.3%), once at least
//!   [`MIN_SENT`] messages were sent;
//! - a sending target newly on a blocklist (E6-T8);
//! - DMARC failures spiking: a domain's failing share at least doubled day
//!   over day (and at least 5% of [`MIN_DMARC`] messages);
//! - reputation dropping (Postmaster high, medium, low, bad; SNDS green,
//!   yellow, red).
//!
//! Each alert is one `marketing_deliverability_alert` row per (subject,
//! kind, day); only a newly inserted row notifies, so a re-run notifies no
//! one twice. The people told are those in the policy's marketing owner
//! role, and the administrators, through a notification with plain guidance
//! in English and Arabic. (AB10's alerting watches the operations metrics
//! store for operators; these are business alerts for the marketing owner.)

use std::collections::HashMap;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{Duration, NaiveDate};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::deliverability::rollup::{RollupCounts, totals};

/// Messages a domain and provider must have sent before a rate counts.
pub const MIN_SENT: i64 = 100;
/// DMARC messages a domain must have before a spike counts.
pub const MIN_DMARC: i64 = 50;
const DEFAULT_BOUNCE_PERCENT: f64 = 2.0;
const DEFAULT_COMPLAINT_PERCENT: f64 = 0.3;

/// One alert.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Alert {
    /// The sending domain (with provider), or the blocklisted target.
    pub subject: String,
    /// `bounce_rate`, `complaint_rate`, `blocklisted`, `dmarc_failures`,
    /// `reputation_drop`.
    pub kind: &'static str,
    pub value: f64,
    pub threshold: f64,
}

/// Rate alerts for one day's rollup. Pure.
pub fn rate_alerts(
    rows: &[(String, String, RollupCounts)],
    bounce_percent: f64,
    complaint_percent: f64,
) -> Vec<Alert> {
    let mut by: HashMap<(String, String), RollupCounts> = HashMap::new();
    for (domain, provider, c) in rows {
        let e = by.entry((domain.clone(), provider.clone())).or_default();
        e.sent += c.sent;
        e.bounced += c.bounced;
        e.complaints += c.complaints;
    }
    let mut keys: Vec<_> = by.keys().cloned().collect();
    keys.sort();
    let mut out = Vec::new();
    for key in keys {
        let c = by[&key];
        if c.sent < MIN_SENT {
            continue;
        }
        let subject = format!("{} ({})", key.0, key.1);
        let bounce = c.bounced as f64 * 100.0 / c.sent as f64;
        if bounce > bounce_percent {
            out.push(Alert {
                subject: subject.clone(),
                kind: "bounce_rate",
                value: bounce,
                threshold: bounce_percent,
            });
        }
        let complaint = c.complaints as f64 * 100.0 / c.sent as f64;
        if complaint > complaint_percent {
            out.push(Alert {
                subject,
                kind: "complaint_rate",
                value: complaint,
                threshold: complaint_percent,
            });
        }
    }
    out
}

/// Whether a DMARC failing share spiked: at least doubled, and at least 5%
/// now. Pure.
pub fn dmarc_spike(before: (i64, i64), now: (i64, i64)) -> bool {
    let (now_fail, now_total) = now;
    if now_total < MIN_DMARC {
        return false;
    }
    let share_now = now_fail as f64 / now_total as f64;
    let share_before = if before.1 > 0 {
        before.0 as f64 / before.1 as f64
    } else {
        0.0
    };
    share_now >= 0.05 && share_now >= share_before * 2.0
}

/// A reputation label's rank, higher is better; `None` for an unknown one.
/// Pure.
pub fn reputation_rank(label: &str) -> Option<u8> {
    match label.trim().to_ascii_lowercase().as_str() {
        "high" | "green" => Some(3),
        "medium" | "yellow" => Some(2),
        "low" | "red" => Some(1),
        "bad" => Some(0),
        _ => None,
    }
}

/// The guidance for a kind, in English and Arabic.
pub fn guidance(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "bounce_rate" => (
            "Bounces are high: remove invalid addresses, stop mailing old lists, and check the import that added them.",
            "معدل الارتداد مرتفع: احذف العناوين غير الصالحة، وتوقف عن مراسلة القوائم القديمة، وراجع الاستيراد الذي أضافها.",
        ),
        "complaint_rate" => (
            "Spam complaints are high: send only to people who asked for mail, make unsubscribing easy, and send less often.",
            "شكاوى البريد المزعج مرتفعة: أرسل فقط لمن طلب الرسائل، وسهّل إلغاء الاشتراك، وقلّل عدد الرسائل.",
        ),
        "blocklisted" => (
            "A sending domain or address is on a blocklist: pause bulk sends from it, find the cause, then ask the list to remove it.",
            "نطاق أو عنوان إرسال مدرج في قائمة حظر: أوقف الإرسال الجماعي منه، وابحث عن السبب، ثم اطلب إزالته من القائمة.",
        ),
        "dmarc_failures" => (
            "DMARC failures doubled: check that every service sending as this domain is in its SPF record and signs with DKIM.",
            "تضاعفت إخفاقات DMARC: تأكد من أن كل خدمة ترسل باسم هذا النطاق مدرجة في سجل SPF وتوقّع بـ DKIM.",
        ),
        _ => (
            "The mailbox provider's view of this sender dropped: slow down, send to your most engaged people, and watch complaints.",
            "تراجعت سمعة المرسل لدى مزود البريد: خفّف الإرسال، وأرسل لأكثر الناس تفاعلاً، وراقب الشكاوى.",
        ),
    }
}

struct Policy {
    bounce: f64,
    complaint: f64,
    owner_role: Option<String>,
}

async fn policy(state: &EngineState) -> Result<Policy, AppError> {
    let row: Option<(Option<f64>, Option<f64>, Option<String>)> = sqlx::query_as(
        "SELECT bounce_warn_percent::float8, complaint_warn_percent::float8, marketing_owner_role \
           FROM marketing_deliverability_policy WHERE is_active IS NOT FALSE \
          ORDER BY created_at LIMIT 1",
    )
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (b, c, role) = row.unwrap_or((None, None, None));
    Ok(Policy {
        bounce: b.filter(|v| *v > 0.0).unwrap_or(DEFAULT_BOUNCE_PERCENT),
        complaint: c.filter(|v| *v > 0.0).unwrap_or(DEFAULT_COMPLAINT_PERCENT),
        owner_role: role.filter(|r| !r.trim().is_empty()),
    })
}

/// Everyone told: the marketing owner role's members and the administrators.
async fn recipients(state: &EngineState, role: Option<&str>) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT DISTINCT u FROM ( \
            SELECT ur.user_ref AS u FROM user_account_mm_role ur \
              JOIN role r ON r.id = ur.role_ref AND r.is_deleted = false \
             WHERE ur.is_deleted = false AND r.name = $1 \
            UNION \
            SELECT up.user_ref FROM user_account_mm_privilege up \
              JOIN privilege p ON p.id = up.privilege_ref AND p.key = 'system.admin' \
             WHERE (up.is_active IS NULL OR up.is_active = true) \
         ) x JOIN user_account a ON a.id = x.u AND a.is_active = true",
    )
    .bind(role)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Evaluates `day` and notifies each new alert once. Returns the alerts
/// raised now.
pub async fn evaluate(state: &EngineState, day: NaiveDate) -> Result<Vec<Alert>, AppError> {
    let db = &state.base.db;
    let policy = policy(state).await?;
    let mut alerts = rate_alerts(
        &totals(db, None, day, day).await?,
        policy.bounce,
        policy.complaint,
    );

    let listed: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT c.target || ' (' || c.list_name || ')' FROM marketing_blocklist_check c \
          WHERE c.checked_at::date = $1 AND c.listed \
            AND NOT EXISTS (SELECT 1 FROM marketing_blocklist_check p \
                             WHERE p.target = c.target AND p.list_name = c.list_name \
                               AND p.checked_at::date < $1 AND p.listed \
                               AND p.checked_at >= $1::date - 7)",
    )
    .bind(day)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    alerts.extend(listed.into_iter().map(|subject| Alert {
        subject,
        kind: "blocklisted",
        value: 1.0,
        threshold: 0.0,
    }));

    let dmarc: Vec<(String, NaiveDate, i64, i64)> = sqlx::query_as(
        "SELECT rep.domain, rep.date_begin::date, \
                COALESCE(sum(rec.message_count) FILTER (WHERE COALESCE(rec.dkim, '') <> 'pass' \
                                                  AND COALESCE(rec.spf, '') <> 'pass'), 0)::int8, \
                COALESCE(sum(rec.message_count), 0)::int8 \
           FROM marketing_dmarc_report rep JOIN marketing_dmarc_record rec ON rec.report_ref = rep.id \
          WHERE rep.date_begin::date IN ($1, $1::date - 1) \
          GROUP BY rep.domain, rep.date_begin::date",
    )
    .bind(day)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut by_domain: HashMap<String, ((i64, i64), (i64, i64))> = HashMap::new();
    for (domain, d, fail, total) in dmarc {
        let e = by_domain.entry(domain).or_default();
        if d == day {
            e.1 = (fail, total)
        } else {
            e.0 = (fail, total)
        }
    }
    for (domain, (before, now)) in by_domain {
        if dmarc_spike(before, now) {
            alerts.push(Alert {
                subject: domain,
                kind: "dmarc_failures",
                value: now.0 as f64 * 100.0 / now.1 as f64,
                threshold: if before.1 > 0 {
                    before.0 as f64 * 200.0 / before.1 as f64
                } else {
                    5.0
                },
            });
        }
    }

    let rep: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT t.sending_domain, t.source, t.reputation, y.reputation \
           FROM marketing_reputation_daily t \
           JOIN marketing_reputation_daily y ON y.sending_domain = t.sending_domain \
                AND y.source = t.source AND y.day = $1::date - 1 \
          WHERE t.day = $1",
    )
    .bind(day)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (subject, source, now, before) in rep {
        if let (Some(n), Some(b)) = (
            now.as_deref().and_then(reputation_rank),
            before.as_deref().and_then(reputation_rank),
        ) && n < b
        {
            alerts.push(Alert {
                subject: format!("{subject} ({source})"),
                kind: "reputation_drop",
                value: f64::from(n),
                threshold: f64::from(b),
            });
        }
    }

    let mut raised = Vec::new();
    let mut to_notify = Vec::new();
    let mut tx = attome_db::tx::begin(db).await?;
    for alert in alerts {
        let inserted = sqlx::query(
            "INSERT INTO marketing_deliverability_alert (day, subject, kind, detail) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (day, subject, kind) DO NOTHING",
        )
        .bind(day)
        .bind(&alert.subject)
        .bind(alert.kind)
        .bind(json!({ "value": alert.value, "threshold": alert.threshold }))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if inserted == 1 {
            to_notify.push(alert.clone());
            raised.push(alert);
        }
    }
    if !to_notify.is_empty() {
        let people = recipients(state, policy.owner_role.as_deref()).await?;
        for alert in &to_notify {
            let (en, ar) = guidance(alert.kind);
            let body = format!(
                "{}: {:.2} (limit {:.2}).\n{en}\n\n{ar}",
                alert.subject, alert.value, alert.threshold
            );
            for person in &people {
                attome_notification::dispatch::create_dispatch_in_tx(
                    &mut tx,
                    &state.base.config.notification,
                    attome_notification::dispatch::DispatchRequest {
                        template_key: None,
                        locale: "en".to_owned(),
                        recipient_user_ref: Some(*person),
                        is_global: false,
                        organization_ref: None,
                        channels: None,
                        subject: Some(format!("Deliverability alert: {}", alert.subject)),
                        body_html: None,
                        body_text: Some(body.clone()),
                        route: Some("/xrm/entity/marketing_deliverability_policy/list".to_owned()),
                        variables: HashMap::new(),
                        priority: "high".to_owned(),
                        escalate_after_minutes: None,
                        escalate_channels: None,
                    },
                    Some("marketing.deliverability_alert"),
                )
                .await?;
            }
        }
    }
    attome_db::tx::commit(tx).await?;
    Ok(raised)
}

/// Yesterday, the day the daily evaluation looks at. Pure.
pub fn evaluation_day(today: NaiveDate) -> NaiveDate {
    today - Duration::days(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(sent: i64, bounced: i64, complaints: i64) -> RollupCounts {
        RollupCounts {
            sent,
            bounced,
            complaints,
            ..RollupCounts::default()
        }
    }

    #[test]
    fn gmail_complaint_over_threshold_raises_one_alert() {
        let rows = vec![
            (
                "example.com".to_owned(),
                "gmail".to_owned(),
                counts(1000, 5, 4),
            ),
            (
                "example.com".to_owned(),
                "outlook".to_owned(),
                counts(1000, 5, 1),
            ),
            (
                "example.com".to_owned(),
                "yahoo".to_owned(),
                counts(20, 10, 5),
            ),
        ];
        let alerts = rate_alerts(&rows, 2.0, 0.3);
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        assert_eq!(alerts[0].kind, "complaint_rate");
        assert_eq!(alerts[0].subject, "example.com (gmail)");
        assert!((alerts[0].value - 0.4).abs() < 1e-9);
        let (en, ar) = guidance("complaint_rate");
        assert!(en.contains("complaints") && !ar.is_empty());
    }

    #[test]
    fn alert_deduplicated_per_day() {
        // The same day's rollup evaluated twice gives the same alert keys;
        // the table's (day, subject, kind) key keeps only the first.
        let rows = vec![(
            "example.com".to_owned(),
            "gmail".to_owned(),
            counts(1000, 50, 4),
        )];
        let first = rate_alerts(&rows, 2.0, 0.3);
        let second = rate_alerts(&rows, 2.0, 0.3);
        let keys = |a: &[Alert]| {
            a.iter()
                .map(|x| (x.subject.clone(), x.kind))
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(&first), keys(&second));
        assert_eq!(first.len(), 2, "bounce and complaint are separate kinds");
        assert!(dmarc_spike((5, 100), (12, 100)));
        assert!(!dmarc_spike((5, 100), (8, 100)));
        assert!(!dmarc_spike((0, 0), (10, 20)), "too few messages");
        assert!(reputation_rank("LOW") < reputation_rank("medium"));
    }
}
