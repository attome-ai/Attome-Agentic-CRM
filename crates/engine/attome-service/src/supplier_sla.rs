//! Supplier SLAs (roadmap G9-T3): when work on a ticket is handed to a
//! supplier (`service_ticket.supplier_vendor_id` set, with the supplier's
//! own target in `supplier_target_minutes`), a supplier clock starts; it
//! stops when the work comes back (the field cleared or changed to another
//! supplier) or the ticket is resolved, and is `met` or `breached` by its
//! due time. A running clock past its due time is `breached` at once, so
//! reports see it before the work returns. The customer's own SLA clock is
//! untouched: supplier time is reported separately ([`report`]).
//!
//! [`plan`] is the pure decision; [`reconcile`] applies it for one ticket
//! and runs from the ticket event sweep (`clock::sweep_auto_pause`) and
//! [`mark_overdue`] from the SLA breach sweep.

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use uuid::Uuid;

/// The target when the ticket names none: one business day of wall time.
pub const DEFAULT_TARGET_MINUTES: i64 = 24 * 60;

/// A clock as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenClock {
    pub id: Uuid,
    pub vendor: String,
    pub due_at: DateTime<Utc>,
}

/// What to do for one ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Nothing,
    Start {
        vendor: String,
        due_at: DateTime<Utc>,
    },
    /// Stop `clock`, `met` when `now` is not after its due time.
    Stop {
        clock: Uuid,
        met: bool,
    },
    /// Stop the old supplier's clock and start the new one's.
    Switch {
        clock: Uuid,
        met: bool,
        vendor: String,
        due_at: DateTime<Utc>,
    },
}

/// Decides for a ticket now handed to `vendor` (if any), with its open
/// clock (if any).
pub fn plan(
    vendor: Option<&str>,
    target_minutes: Option<i64>,
    resolved: bool,
    open: Option<&OpenClock>,
    now: DateTime<Utc>,
) -> Plan {
    let vendor = vendor.map(str::trim).filter(|v| !v.is_empty() && !resolved);
    let due = || {
        now + Duration::minutes(
            target_minutes
                .filter(|m| *m > 0)
                .unwrap_or(DEFAULT_TARGET_MINUTES),
        )
    };
    match (vendor, open) {
        (None, None) => Plan::Nothing,
        (Some(v), None) => Plan::Start {
            vendor: v.to_owned(),
            due_at: due(),
        },
        (None, Some(c)) => Plan::Stop {
            clock: c.id,
            met: now <= c.due_at,
        },
        (Some(v), Some(c)) if c.vendor == v => Plan::Nothing,
        (Some(v), Some(c)) => Plan::Switch {
            clock: c.id,
            met: now <= c.due_at,
            vendor: v.to_owned(),
            due_at: due(),
        },
    }
}

async fn installed(db: &DbPool) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass('supplier_sla_clock') IS NOT NULL")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

type TicketRow = (Option<String>, Option<f64>, Option<String>);

/// Applies [`plan`] to one ticket; whether anything changed.
pub async fn reconcile(db: &DbPool, ticket: Uuid, now: DateTime<Utc>) -> Result<bool, AppError> {
    if !installed(db).await? {
        return Ok(false);
    }
    let mut tx = attome_db::tx::begin(db).await?;
    let row: Option<TicketRow> = sqlx::query_as(
        "SELECT supplier_vendor_id, supplier_target_minutes::float8, status \
         FROM service_ticket WHERE id = $1 FOR UPDATE",
    )
    .bind(ticket)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((vendor, target, status)) = row else {
        return Ok(false);
    };
    let resolved = matches!(status.as_deref(), Some("resolved" | "closed"));
    let open: Option<(Uuid, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, vendor_id, due_at FROM supplier_sla_clock \
         WHERE ticket_ref = $1 AND stopped_at IS NULL AND (is_active IS NULL OR is_active = true) \
         ORDER BY started_at DESC LIMIT 1",
    )
    .bind(ticket.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let open = open.map(|(id, vendor, due_at)| OpenClock { id, vendor, due_at });
    let decision = plan(
        vendor.as_deref(),
        target.map(|t| t as i64),
        resolved,
        open.as_ref(),
        now,
    );
    let (stop, start) = match decision {
        Plan::Nothing => return Ok(false),
        Plan::Start { vendor, due_at } => (None, Some((vendor, due_at))),
        Plan::Stop { clock, met } => (Some((clock, met)), None),
        Plan::Switch {
            clock,
            met,
            vendor,
            due_at,
        } => (Some((clock, met)), Some((vendor, due_at))),
    };
    if let Some((clock, met)) = stop {
        sqlx::query(
            "UPDATE supplier_sla_clock SET stopped_at = $2, status = $3, modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
        )
        .bind(clock)
        .bind(now)
        .bind(if met { "met" } else { "breached" })
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    if let Some((vendor, due_at)) = start {
        let has_vendor: bool = sqlx::query_scalar("SELECT to_regclass('vendor') IS NOT NULL")
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        let vendor_name: Option<String> = match Uuid::parse_str(&vendor) {
            Ok(id) if has_vendor => sqlx::query_scalar("SELECT name FROM vendor WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(AppError::internal)?,
            _ => None,
        };
        sqlx::query(
            "INSERT INTO supplier_sla_clock \
               (ticket_ref, vendor_id, vendor_name, target_minutes, started_at, due_at, status) \
             VALUES ($1, $2, $3, $4::float8::numeric, $5, $6, 'running')",
        )
        .bind(ticket.to_string())
        .bind(&vendor)
        .bind(vendor_name.unwrap_or_else(|| vendor.clone()))
        .bind((due_at - now).num_minutes() as f64)
        .bind(now)
        .bind(due_at)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

/// Marks running clocks past their due time `breached` (they keep running
/// until the work returns); the number marked.
pub async fn mark_overdue(db: &DbPool, now: DateTime<Utc>) -> Result<u64, AppError> {
    if !installed(db).await? {
        return Ok(0);
    }
    Ok(sqlx::query(
        "UPDATE supplier_sla_clock SET status = 'breached', modified_at = now(), \
         row_version = row_version + 1 \
         WHERE status = 'running' AND stopped_at IS NULL AND due_at < $1 \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(now)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected())
}

/// One supplier's record over a period.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SupplierRecord {
    pub vendor_id: String,
    pub vendor_name: Option<String>,
    pub handed_over: i64,
    pub met: i64,
    pub breached: i64,
    pub running: i64,
    /// Met out of finished, in percent; `None` before anything finished.
    pub met_percent: Option<f64>,
}

/// Supplier performance for clocks started in `[from, to)`.
pub async fn report(
    db: &DbPool,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<SupplierRecord>, AppError> {
    if !installed(db).await? {
        return Ok(Vec::new());
    }
    let rows: Vec<(String, Option<String>, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT vendor_id, max(vendor_name), count(*), \
                count(*) FILTER (WHERE status = 'met'), \
                count(*) FILTER (WHERE status = 'breached'), \
                count(*) FILTER (WHERE status = 'running') \
         FROM supplier_sla_clock \
         WHERE started_at >= $1 AND started_at < $2 AND (is_active IS NULL OR is_active = true) \
         GROUP BY vendor_id ORDER BY vendor_id",
    )
    .bind(from)
    .bind(to)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(vendor_id, vendor_name, handed_over, met, breached, running)| {
                let finished = met + breached;
                SupplierRecord {
                    vendor_id,
                    vendor_name,
                    handed_over,
                    met,
                    breached,
                    running,
                    met_percent: (finished > 0).then(|| met as f64 * 100.0 / finished as f64),
                }
            },
        )
        .collect())
}

#[cfg(test)]
mod supplier_sla {
    use super::*;
    use chrono::TimeZone;

    fn at(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 3, hour, 0, 0)
            .single()
            .unwrap_or_default()
    }

    fn clock(vendor: &str, due_hour: u32) -> OpenClock {
        OpenClock {
            id: Uuid::from_u128(1),
            vendor: vendor.into(),
            due_at: at(due_hour),
        }
    }

    #[test]
    fn handing_work_to_a_supplier_starts_its_clock() {
        assert_eq!(
            plan(Some("v1"), Some(120), false, None, at(9)),
            Plan::Start {
                vendor: "v1".into(),
                due_at: at(11)
            }
        );
        assert_eq!(
            plan(Some("v1"), None, false, None, at(0)),
            Plan::Start {
                vendor: "v1".into(),
                due_at: at(0) + Duration::minutes(DEFAULT_TARGET_MINUTES)
            },
            "no target: the default"
        );
        assert_eq!(plan(None, None, false, None, at(9)), Plan::Nothing);
        assert_eq!(
            plan(Some("v1"), None, false, Some(&clock("v1", 11)), at(10)),
            Plan::Nothing,
            "the same supplier keeps its clock"
        );
    }

    #[test]
    fn the_clock_stops_met_or_breached() {
        let open = clock("v1", 11);
        assert_eq!(
            plan(None, None, false, Some(&open), at(10)),
            Plan::Stop {
                clock: open.id,
                met: true
            }
        );
        assert_eq!(
            plan(Some("v1"), None, true, Some(&open), at(12)),
            Plan::Stop {
                clock: open.id,
                met: false
            },
            "resolving the ticket stops it too"
        );
        assert!(matches!(
            plan(Some("v2"), Some(60), false, Some(&open), at(10)),
            Plan::Switch { met: true, ref vendor, .. } if vendor == "v2"
        ));
    }
}
