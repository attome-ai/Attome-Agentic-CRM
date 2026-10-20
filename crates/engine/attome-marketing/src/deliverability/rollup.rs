//! The daily deliverability rollup (roadmap E6-T4): per day, sending
//! domain, mailbox provider and send, how many emails were sent, delivered,
//! bounced, opened and clicked, and how many complaints came in.
//!
//! **Sources.** Delivery and engagement are the `communication_event` rows
//! (Z8's provider callbacks and D16's open and click tracking) of email
//! communications, counted on the day the event happened. A message's
//! sending domain is its `Message-ID`'s domain, its recipient the first
//! address in `to_addresses`, classified into a provider by
//! [`super::provider::classify`]; a communication on a `campaign` record
//! counts under that campaign as its send. Complaints are the day's
//! `email_suppression` rows with reason `complaint`, per recipient
//! provider, with no sending domain or send.
//!
//! **Idempotent.** Recomputing a day deletes and rewrites its rows in one
//! transaction, so a re-run leaves the same rows and totals. The dashboard
//! reads only `marketing_deliverability_daily`.

use std::collections::BTreeMap;

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{Days, NaiveDate};

use super::provider::classify;

/// One rollup row's key: sending domain, provider, send.
pub type RollupKey = (String, String, String);

/// One rollup row's counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RollupCounts {
    pub sent: i64,
    pub delivered: i64,
    pub bounced: i64,
    pub opened: i64,
    pub clicked: i64,
    pub complaints: i64,
}

impl RollupCounts {
    fn add(&mut self, event: &str, n: i64) {
        match event {
            "sent" => self.sent += n,
            "delivered" => self.delivered += n,
            "bounced" => self.bounced += n,
            "opened" => self.opened += n,
            "clicked" => self.clicked += n,
            "complaint" => self.complaints += n,
            _ => {}
        }
    }
}

/// The domain of an address or a `Message-ID` (`<id@domain>`), lower case.
/// Pure.
pub fn domain_of(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .rsplit_once('@')
        .map(|(_, d)| d.trim().trim_end_matches('>').to_ascii_lowercase())
        .unwrap_or_default()
}

/// Folds `(sending domain, recipient domain, send, event, count)` rows into
/// rollup rows by provider. Pure.
pub fn fold(rows: &[(String, String, String, String, i64)]) -> BTreeMap<RollupKey, RollupCounts> {
    let mut out: BTreeMap<RollupKey, RollupCounts> = BTreeMap::new();
    for (sending, recipient, send, event, n) in rows {
        let key = (sending.clone(), classify(recipient).key(), send.clone());
        out.entry(key).or_default().add(event, *n);
    }
    out
}

/// Recomputes one day's rollup. Returns the rows written.
pub async fn rollup_day(db: &DbPool, day: NaiveDate) -> Result<usize, AppError> {
    let next = day
        .checked_add_days(Days::new(1))
        .ok_or_else(|| AppError::Validation("day out of range".into()))?;
    let tables: (bool, bool) = sqlx::query_as(
        "SELECT to_regclass('communication') IS NOT NULL, \
                to_regclass('communication_event') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let mut rows: Vec<(String, String, String, String, i64)> = if tables == (true, true) {
        sqlx::query_as(
            "SELECT COALESCE(c.message_id, ''), \
                    lower(btrim(split_part(COALESCE(c.to_addresses, ''), ',', 1))), \
                    CASE WHEN c.entity_name = 'campaign' THEN COALESCE(c.record_id, '') ELSE '' END, \
                    e.event_type, COUNT(*)::bigint \
               FROM communication_event e \
               JOIN communication c ON c.id = e.communication_id \
              WHERE c.channel = 'email' AND e.occurred_at >= $1 AND e.occurred_at < $2 \
                AND e.event_type IN ('sent', 'delivered', 'bounced', 'opened', 'clicked') \
              GROUP BY 1, 2, 3, 4",
        )
        .bind(day)
        .bind(next)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
    } else {
        Vec::new()
    };
    for row in &mut rows {
        row.0 = domain_of(&row.0);
        row.1 = domain_of(&row.1);
    }
    let complaints: Vec<(String, i64)> = sqlx::query_as(
        "SELECT lower(split_part(email, '@', 2)), COUNT(*)::bigint FROM email_suppression \
          WHERE reason = 'complaint' AND created_at >= $1 AND created_at < $2 \
          GROUP BY 1",
    )
    .bind(day)
    .bind(next)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    rows.extend(complaints.into_iter().map(|(domain, n)| {
        (
            String::new(),
            domain,
            String::new(),
            "complaint".to_owned(),
            n,
        )
    }));
    let folded = fold(&rows);

    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("DELETE FROM marketing_deliverability_daily WHERE day = $1")
        .bind(day)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    for ((sending, provider, send), c) in &folded {
        sqlx::query(
            "INSERT INTO marketing_deliverability_daily \
               (day, sending_domain, mailbox_provider, send_ref, sent, delivered, bounced, \
                opened, clicked, complaints) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (day, sending_domain, mailbox_provider, send_ref) DO UPDATE SET \
               sent = EXCLUDED.sent, delivered = EXCLUDED.delivered, bounced = EXCLUDED.bounced, \
               opened = EXCLUDED.opened, clicked = EXCLUDED.clicked, \
               complaints = EXCLUDED.complaints, computed_at = now()",
        )
        .bind(day)
        .bind(sending)
        .bind(provider)
        .bind(send)
        .bind(c.sent)
        .bind(c.delivered)
        .bind(c.bounced)
        .bind(c.opened)
        .bind(c.clicked)
        .bind(c.complaints)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(folded.len())
}

/// A totals row: provider, send, then sent, delivered, bounced, opened, clicked, complained.
type TotalsRow = (String, String, i64, i64, i64, i64, i64, i64);

/// The rollup's totals per mailbox provider and send for `domain` (every
/// sending domain when `None`) over the days `[from, to]`.
pub async fn totals(
    db: &DbPool,
    domain: Option<&str>,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<(String, String, RollupCounts)>, AppError> {
    let rows: Vec<TotalsRow> = sqlx::query_as(
        "SELECT mailbox_provider, send_ref, SUM(sent)::bigint, SUM(delivered)::bigint, \
                SUM(bounced)::bigint, SUM(opened)::bigint, SUM(clicked)::bigint, \
                SUM(complaints)::bigint \
           FROM marketing_deliverability_daily \
          WHERE day >= $1 AND day <= $2 AND ($3::text IS NULL OR sending_domain = lower($3)) \
          GROUP BY mailbox_provider, send_ref ORDER BY mailbox_provider, send_ref",
    )
    .bind(from)
    .bind(to)
    .bind(domain)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(provider, send, sent, delivered, bounced, opened, clicked, complaints)| {
                (
                    provider,
                    send,
                    RollupCounts {
                        sent,
                        delivered,
                        bounced,
                        opened,
                        clicked,
                        complaints,
                    },
                )
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_come_from_addresses_and_message_ids() {
        assert_eq!(domain_of("<abc.123@Mail.Acme.sa>"), "mail.acme.sa");
        assert_eq!(domain_of(" sara@Gmail.com "), "gmail.com");
        assert_eq!(domain_of("no-at-sign"), "");
    }

    #[test]
    fn events_fold_into_provider_rows() {
        let rows = vec![
            (
                "acme.sa".into(),
                "gmail.com".into(),
                String::new(),
                "sent".into(),
                10,
            ),
            (
                "acme.sa".into(),
                "googlemail.com".into(),
                String::new(),
                "delivered".into(),
                9,
            ),
            (
                "acme.sa".into(),
                "hotmail.com".into(),
                String::new(),
                "bounced".into(),
                1,
            ),
            (
                "acme.sa".into(),
                "gmail.com".into(),
                String::new(),
                "opened".into(),
                4,
            ),
            (
                String::new(),
                "gmail.com".into(),
                String::new(),
                "complaint".into(),
                1,
            ),
        ];
        let folded = fold(&rows);
        let gmail = folded[&("acme.sa".into(), "gmail".into(), String::new())];
        assert_eq!((gmail.sent, gmail.delivered, gmail.opened), (10, 9, 4));
        assert_eq!(
            folded[&("acme.sa".into(), "outlook".into(), String::new())].bounced,
            1
        );
        assert_eq!(
            folded[&(String::new(), "gmail".into(), String::new())].complaints,
            1
        );
        assert_eq!(folded.len(), 3);
    }
}
