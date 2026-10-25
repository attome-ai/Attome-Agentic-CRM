//! Q22-T1: detection rules over security events, each detection a case in
//! the security queue.
//!
//! The `security_detections` job (every five minutes) reads the security
//! events the audit log gained since its cursor (`audit_header`, with a
//! [`LOOKBACK`] of context before it and an [`OVERLAP`] re-read, so an event
//! the chainer wrote late is still seen) and runs five rules:
//!
//! - **spray** — the password-spray detections Q20 already writes
//!   (`login.spray_detected:{address}`), one case each;
//! - **impossible travel** — two successful sign-ins of one person from
//!   different countries less than [`TRAVEL_WINDOW`] apart (countries from
//!   the offline GeoIP database, `auth.geoip_database`; without one this
//!   rule is idle);
//! - **mass export** — one person's exports (`affected_count` records each,
//!   else one) adding up to more than [`EXPORT_THRESHOLD`] records within
//!   [`EXPORT_WINDOW`]; personal data left the system, so this also opens a
//!   privacy breach record (privacy pack, R5) with the 72-hour notification
//!   deadline;
//! - **privilege escalation** — someone granting access to themselves, a
//!   grant naming `system.admin`, or [`BURST_GRANTS`] access grants by one
//!   person within [`EXPORT_WINDOW`];
//! - **new device** — a sign-in from a browser the person has not used in
//!   [`DEVICE_DAYS`] days, when they have used another one in that time (a
//!   first-ever sign-in is not a new device). History is kept hashed
//!   (`security_device_seen`, SHA-256 of person and user agent), never the
//!   user agent itself.
//!
//! A case (`security_case`, migration 0247) is opened once per detection:
//! its `dedup_key` is unique, so re-reading an event never opens a second
//! one. While any case is open the `security_cases_open` operations alert
//! fires (critical when a high-severity case is among them), and it clears
//! when the last one is closed.

use std::collections::BTreeMap;

use attome_core::change_feed::ChangeOperation;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "security_detections";
/// The operations alert raised while cases are open.
pub const ALERT: &str = "security_cases_open";

/// Context read before the cursor, so windowed rules see earlier events.
pub const LOOKBACK: Duration = Duration::hours(2);
/// How far behind the cursor events are re-read (late chainer writes).
pub const OVERLAP: Duration = Duration::minutes(10);
/// Two sign-ins from different countries closer than this are impossible.
pub const TRAVEL_WINDOW: Duration = Duration::hours(2);
/// The window exports and grants are counted in.
pub const EXPORT_WINDOW: Duration = Duration::minutes(10);
/// More exported records than this in [`EXPORT_WINDOW`] is a mass export.
pub const EXPORT_THRESHOLD: i64 = 5_000;
/// Access grants by one person in [`EXPORT_WINDOW`] that make a burst.
pub const BURST_GRANTS: usize = 5;
/// How long a device stays known.
pub const DEVICE_DAYS: i64 = 90;
/// Most events read per run.
const MAX_EVENTS: i64 = 20_000;
/// Days a privacy breach must be notified within (PDPL: 72 hours).
const BREACH_NOTIFY_HOURS: i64 = 72;

const OP_EXPORT: i32 = 8;
const OP_LOGIN: i32 = 9;
const OP_FAILED_LOGIN: i32 = 11;
const OP_PERMISSION_CHANGE: i32 = 12;
const OP_ROLE_CHANGE: i32 = 13;
const OP_GRANT: i32 = 28;

/// The tables an access grant writes.
const ACCESS_TABLES: &[&str] = &[
    "user_account_mm_role",
    "user_account_mm_privilege",
    "user_account_mm_team",
    "role_mm_privilege",
    "role_mm_team",
];

/// One security event, as the rules read it.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Event {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub user_id: Option<Uuid>,
    pub record_id: Option<Uuid>,
    pub entity_name: Option<String>,
    pub operation: Option<i32>,
    pub outcome: Option<i16>,
    pub event_name: Option<String>,
    pub event_comment: Option<String>,
    pub ip_address: Option<String>,
    pub browser: Option<String>,
    pub affected_count: Option<i32>,
}

impl Event {
    fn is(&self, op: i32) -> bool {
        self.operation == Some(op)
    }

    /// A sign-in that let the person in.
    pub fn is_successful_login(&self) -> bool {
        self.is(OP_LOGIN)
            && self.outcome.unwrap_or(0) == 0
            && self
                .event_name
                .as_deref()
                .is_some_and(|n| n.starts_with("login ") && !n.contains("refused"))
    }
}

/// Which rule found something.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    Spray,
    ImpossibleTravel,
    MassExport,
    PrivilegeEscalation,
    NewDevice,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::Spray => "spray",
            Rule::ImpossibleTravel => "impossible_travel",
            Rule::MassExport => "mass_export",
            Rule::PrivilegeEscalation => "privilege_escalation",
            Rule::NewDevice => "new_device",
        }
    }
}

/// One detection, before it becomes a case.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub rule: Rule,
    /// `low`, `medium` or `high`.
    pub severity: &'static str,
    /// Unique per detection; a second read of the same events gives the same key.
    pub dedup_key: String,
    pub subject: Option<Uuid>,
    pub summary: String,
    pub evidence: Value,
    /// Personal data may have left: a privacy breach record is opened too.
    pub personal_data: bool,
    /// When the triggering event happened.
    pub at: DateTime<Utc>,
}

fn hour_bucket(at: DateTime<Utc>) -> String {
    at.format("%Y%m%d%H").to_string()
}

/// Q20's spray detections, one case each. Pure.
pub fn spray(events: &[Event]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.is(OP_FAILED_LOGIN) || e.is(OP_LOGIN))
        .filter_map(|e| {
            let address = e
                .event_name
                .as_deref()?
                .strip_prefix("login.spray_detected:")?;
            Some(Detection {
                rule: Rule::Spray,
                severity: "high",
                dedup_key: format!("spray:{}", e.id),
                subject: None,
                summary: format!("Password spray from one address ({address})"),
                evidence: json!({ "event": e.id, "address_key": address }),
                personal_data: false,
                at: e.created_at,
            })
        })
        .collect()
}

/// Sign-ins of one person from two countries too close in time. Pure;
/// `country` answers an address's ISO code.
pub fn impossible_travel(
    events: &[Event],
    country: impl Fn(&str) -> Option<String>,
) -> Vec<Detection> {
    let mut by_user: BTreeMap<Uuid, Vec<(&Event, String)>> = BTreeMap::new();
    for e in events.iter().filter(|e| e.is_successful_login()) {
        let (Some(user), Some(ip)) = (e.user_id, e.ip_address.as_deref()) else {
            continue;
        };
        if let Some(code) = country(ip) {
            by_user.entry(user).or_default().push((e, code));
        }
    }
    let mut found = Vec::new();
    for (user, mut logins) in by_user {
        logins.sort_by_key(|(e, _)| (e.created_at, e.id));
        for pair in logins.windows(2) {
            let ((a, from), (b, to)) = (&pair[0], &pair[1]);
            if from != to && b.created_at - a.created_at < TRAVEL_WINDOW {
                let minutes = (b.created_at - a.created_at).num_minutes();
                found.push(Detection {
                    rule: Rule::ImpossibleTravel,
                    severity: "high",
                    dedup_key: format!("travel:{}", b.id),
                    subject: Some(user),
                    summary: format!("Signed in from {from} and then {to} {minutes} minutes later"),
                    evidence: json!({ "from_event": a.id, "to_event": b.id,
                                      "from_country": from, "to_country": to }),
                    personal_data: false,
                    at: b.created_at,
                });
            }
        }
    }
    found
}

/// One person exporting more than [`EXPORT_THRESHOLD`] records within
/// [`EXPORT_WINDOW`]; one case per person per hour. Pure.
pub fn mass_export(events: &[Event]) -> Vec<Detection> {
    let mut by_user: BTreeMap<Uuid, Vec<&Event>> = BTreeMap::new();
    for e in events.iter().filter(|e| e.is(OP_EXPORT)) {
        if let Some(user) = e.user_id {
            by_user.entry(user).or_default().push(e);
        }
    }
    let mut found: BTreeMap<String, Detection> = BTreeMap::new();
    for (user, mut exports) in by_user {
        exports.sort_by_key(|e| (e.created_at, e.id));
        let mut start = 0;
        let mut total: i64 = 0;
        for (end, last) in exports.iter().enumerate() {
            total += i64::from(last.affected_count.unwrap_or(1).max(0));
            while last.created_at - exports[start].created_at > EXPORT_WINDOW {
                total -= i64::from(exports[start].affected_count.unwrap_or(1).max(0));
                start += 1;
            }
            if total > EXPORT_THRESHOLD {
                let at = last.created_at;
                let key = format!("export:{user}:{}", hour_bucket(at));
                found.entry(key.clone()).or_insert_with(|| Detection {
                    rule: Rule::MassExport,
                    severity: "high",
                    dedup_key: key,
                    subject: Some(user),
                    summary: format!(
                        "{total} records exported within {} minutes",
                        EXPORT_WINDOW.num_minutes()
                    ),
                    evidence: json!({
                        "events": exports[start..=end].iter().map(|e| e.id).collect::<Vec<_>>(),
                        "records": total,
                    }),
                    personal_data: true,
                    at,
                });
            }
        }
    }
    found.into_values().collect()
}

fn is_access_change(e: &Event) -> bool {
    (e.is(OP_GRANT) || e.is(OP_ROLE_CHANGE) || e.is(OP_PERMISSION_CHANGE))
        && e.entity_name
            .as_deref()
            .is_some_and(|n| ACCESS_TABLES.contains(&n))
}

/// Access granted to oneself, a grant naming `system.admin`, or a burst of
/// grants by one person. Pure.
pub fn privilege_escalation(events: &[Event]) -> Vec<Detection> {
    let mut found: BTreeMap<String, Detection> = BTreeMap::new();
    let mut by_actor: BTreeMap<Uuid, Vec<&Event>> = BTreeMap::new();
    for e in events.iter().filter(|e| is_access_change(e)) {
        let names_admin = [e.event_name.as_deref(), e.event_comment.as_deref()]
            .into_iter()
            .flatten()
            .any(|t| t.contains("system.admin"));
        let to_self = e.user_id.is_some() && e.user_id == e.record_id;
        if to_self || names_admin {
            let key = format!("escalation:{}", e.id);
            found.insert(
                key.clone(),
                Detection {
                    rule: Rule::PrivilegeEscalation,
                    severity: "high",
                    dedup_key: key,
                    subject: e.user_id,
                    summary: if to_self {
                        "Someone granted access to themselves".to_owned()
                    } else {
                        "Administrator access was granted".to_owned()
                    },
                    evidence: json!({ "event": e.id, "table": e.entity_name }),
                    personal_data: false,
                    at: e.created_at,
                },
            );
        }
        if let Some(actor) = e.user_id {
            by_actor.entry(actor).or_default().push(e);
        }
    }
    for (actor, mut grants) in by_actor {
        grants.sort_by_key(|e| (e.created_at, e.id));
        let mut start = 0;
        for (end, last) in grants.iter().enumerate() {
            while last.created_at - grants[start].created_at > EXPORT_WINDOW {
                start += 1;
            }
            if end + 1 - start >= BURST_GRANTS {
                let at = last.created_at;
                let key = format!("escalation-burst:{actor}:{}", hour_bucket(at));
                found.entry(key.clone()).or_insert_with(|| Detection {
                    rule: Rule::PrivilegeEscalation,
                    severity: "medium",
                    dedup_key: key,
                    subject: Some(actor),
                    summary: format!(
                        "{} access grants within {} minutes",
                        end + 1 - start,
                        EXPORT_WINDOW.num_minutes()
                    ),
                    evidence: json!({
                        "events": grants[start..=end].iter().map(|e| e.id).collect::<Vec<_>>()
                    }),
                    personal_data: false,
                    at,
                });
            }
        }
    }
    found.into_values().collect()
}

/// The hashed device a sign-in came from.
pub fn device_hash(user: Uuid, user_agent: &str) -> String {
    let mut h = Sha256::new();
    h.update(user.as_bytes());
    h.update(user_agent.trim().as_bytes());
    hex::encode(h.finalize())
}

/// Whether a sign-in is from a new device: not seen in [`DEVICE_DAYS`]
/// days while another device was. Pure.
pub fn is_new_device(seen_recently: bool, other_devices_recently: bool) -> bool {
    !seen_recently && other_devices_recently
}

/// What one run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectionRun {
    pub events: u64,
    pub cases_opened: u64,
    pub breaches_opened: u64,
    pub open_cases: i64,
}

async fn cursor(db: &DbPool, now: DateTime<Utc>) -> Result<DateTime<Utc>, AppError> {
    let at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_created_at FROM security_detection_cursor WHERE id = 1")
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(at.unwrap_or(now - Duration::hours(1)))
}

async fn events_since(
    db: &DbPool,
    from: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<Vec<Event>, AppError> {
    sqlx::query_as(
        "SELECT id, created_at, user_id, record_id, entity_name::text AS entity_name, \
                operation, outcome, event_name::text AS event_name, event_comment, ip_address, \
                browser, affected_count \
           FROM audit_header \
          WHERE created_at > $1 AND created_at <= $2 \
            AND operation = ANY($3) \
          ORDER BY created_at, id LIMIT $4",
    )
    .bind(from)
    .bind(until)
    .bind(
        [
            OP_EXPORT,
            OP_LOGIN,
            OP_FAILED_LOGIN,
            OP_PERMISSION_CHANGE,
            OP_ROLE_CHANGE,
            OP_GRANT,
        ]
        .as_slice(),
    )
    .bind(MAX_EVENTS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Records each new successful sign-in's device and reports the new ones.
async fn new_devices(
    db: &DbPool,
    logins: &[&Event],
    now: DateTime<Utc>,
) -> Result<Vec<Detection>, AppError> {
    let since = now - Duration::days(DEVICE_DAYS);
    let mut found = Vec::new();
    for e in logins {
        let (Some(user), Some(agent)) = (e.user_id, e.browser.as_deref()) else {
            continue;
        };
        if agent.trim().is_empty() {
            continue;
        }
        let hash = device_hash(user, agent);
        let mut tx = attome_db::tx::begin(db).await?;
        let (seen, others): (bool, bool) = sqlx::query_as(
            "SELECT EXISTS (SELECT 1 FROM security_device_seen \
                             WHERE user_id = $1 AND device_hash = $2 AND last_seen >= $3), \
                    EXISTS (SELECT 1 FROM security_device_seen \
                             WHERE user_id = $1 AND device_hash <> $2 AND last_seen >= $3)",
        )
        .bind(user)
        .bind(&hash)
        .bind(since)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(
            "INSERT INTO security_device_seen (user_id, device_hash, first_seen, last_seen) \
             VALUES ($1, $2, $3, $3) \
             ON CONFLICT (user_id, device_hash) DO UPDATE \
               SET last_seen = GREATEST(security_device_seen.last_seen, EXCLUDED.last_seen)",
        )
        .bind(user)
        .bind(&hash)
        .bind(e.created_at)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        if is_new_device(seen, others) {
            found.push(Detection {
                rule: Rule::NewDevice,
                severity: "low",
                dedup_key: format!("device:{}", e.id),
                subject: Some(user),
                summary: "Signed in from a device not used in the last 90 days".to_owned(),
                evidence: json!({ "event": e.id }),
                personal_data: false,
                at: e.created_at,
            });
        }
    }
    Ok(found)
}

/// Opens the case (once) and, for personal data, its breach record.
async fn open_case(db: &DbPool, d: &Detection, run: &mut DetectionRun) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let case: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO security_case \
           (rule, severity, dedup_key, subject_user_id, summary, evidence, opened_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (dedup_key) DO NOTHING RETURNING id",
    )
    .bind(d.rule.as_str())
    .bind(d.severity)
    .bind(&d.dedup_key)
    .bind(d.subject)
    .bind(&d.summary)
    .bind(&d.evidence)
    .bind(d.at)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(case) = case else {
        attome_db::tx::commit(tx).await?;
        return Ok(());
    };
    run.cases_opened += 1;
    let has_breaches: bool = sqlx::query_scalar("SELECT to_regclass('privacy_breach') IS NOT NULL")
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if d.personal_data && has_breaches {
        let breach: Uuid = sqlx::query_scalar(
            "INSERT INTO privacy_breach \
               (title, discovered_at, notify_deadline, description, severity, status) \
             VALUES ($1, $2, $3, $4, 'high', 'open') RETURNING id",
        )
        .bind(format!("Security case: {}", d.summary))
        .bind(d.at)
        .bind(d.at + Duration::hours(BREACH_NOTIFY_HOURS))
        .bind(format!(
            "Opened by the {} detection (security case {case}).",
            d.rule.as_str()
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_core::change_feed::emit_tx(
            &mut tx,
            "privacy_breach",
            breach,
            ChangeOperation::Create,
        )
        .await?;
        sqlx::query("UPDATE security_case SET breach_ref = $2 WHERE id = $1")
            .bind(case)
            .bind(breach)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        run.breaches_opened += 1;
    }
    attome_db::tx::commit(tx).await?;
    metrics::counter!("security_detection_total", "rule" => d.rule.as_str()).increment(1);
    tracing::warn!(case = %case, rule = d.rule.as_str(), severity = d.severity, "security case opened");
    Ok(())
}

/// One run of every rule over the events since the cursor.
pub async fn run(db: &DbPool, now: DateTime<Utc>) -> Result<DetectionRun, AppError> {
    let cursor_at = cursor(db, now).await?;
    let events = events_since(db, cursor_at - LOOKBACK, now).await?;
    let fresh_after = cursor_at - OVERLAP;
    let fresh = |d: &Detection| d.at > fresh_after;

    let mut detections: Vec<Detection> = Vec::new();
    detections.extend(spray(&events).into_iter().filter(fresh));
    detections.extend(
        impossible_travel(&events, |ip| {
            ip.parse()
                .ok()
                .and_then(attome_server::login_restrictions::geoip::country)
        })
        .into_iter()
        .filter(fresh),
    );
    detections.extend(mass_export(&events).into_iter().filter(fresh));
    detections.extend(privilege_escalation(&events).into_iter().filter(fresh));
    let new_logins: Vec<&Event> = events
        .iter()
        .filter(|e| e.is_successful_login() && e.created_at > fresh_after)
        .collect();
    detections.extend(new_devices(db, &new_logins, now).await?);

    let mut run = DetectionRun {
        events: events.len() as u64,
        ..DetectionRun::default()
    };
    for d in &detections {
        open_case(db, d, &mut run).await?;
    }

    // A full read means more remain: advance only to the last event read.
    let advance_to = if events.len() as i64 >= MAX_EVENTS {
        events.last().map_or(now, |e| e.created_at)
    } else {
        now
    };
    sqlx::query(
        "INSERT INTO security_detection_cursor (id, last_created_at) VALUES (1, $1) \
         ON CONFLICT (id) DO UPDATE SET last_created_at = GREATEST( \
             security_detection_cursor.last_created_at, EXCLUDED.last_created_at)",
    )
    .bind(advance_to)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    sqlx::query("DELETE FROM security_device_seen WHERE last_seen < $1")
        .bind(now - Duration::days(DEVICE_DAYS))
        .execute(db)
        .await
        .map_err(AppError::internal)?;

    let (open, high): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE severity = 'high') \
           FROM security_case WHERE status <> 'closed'",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    run.open_cases = open;
    let severity = if high > 0 { "critical" } else { "warning" };
    let summary = format!("{open} security case(s) open, {high} high severity");
    if let Err(error) = attome_server::alerts::set_job_alert(
        db,
        ALERT,
        severity,
        &summary,
        Some(open as f64),
        open > 0,
    )
    .await
    {
        tracing::warn!(%error, "security cases alert not updated");
    }
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(minute: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000 + minute * 60, 0).unwrap()
    }

    fn event(n: u128, minute: i64, op: i32, user: Option<u128>) -> Event {
        Event {
            id: Uuid::from_u128(n),
            created_at: t(minute),
            user_id: user.map(Uuid::from_u128),
            record_id: None,
            entity_name: None,
            operation: Some(op),
            outcome: Some(0),
            event_name: None,
            event_comment: None,
            ip_address: None,
            browser: None,
            affected_count: None,
        }
    }

    fn login(n: u128, minute: i64, user: u128, ip: &str) -> Event {
        Event {
            event_name: Some("login password".into()),
            ip_address: Some(ip.into()),
            ..event(n, minute, OP_LOGIN, Some(user))
        }
    }

    #[test]
    fn detections_spray_cases_come_from_q20_events() {
        let mut e = event(1, 0, OP_FAILED_LOGIN, None);
        e.event_name = Some("login.spray_detected:ab12".into());
        let other = event(2, 0, OP_FAILED_LOGIN, Some(5));
        let found = spray(&[e, other]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, Rule::Spray);
        assert_eq!(found[0].dedup_key, format!("spray:{}", Uuid::from_u128(1)));
    }

    #[test]
    fn detections_impossible_travel() {
        let country = |ip: &str| match ip {
            "1.1.1.1" => Some("SA".to_owned()),
            "2.2.2.2" => Some("BR".to_owned()),
            _ => None,
        };
        let events = [
            login(1, 0, 7, "1.1.1.1"),
            login(2, 30, 7, "2.2.2.2"),
            // Same countries but far apart in time: fine.
            login(3, 0, 8, "1.1.1.1"),
            login(4, 300, 8, "2.2.2.2"),
            // Unknown country: never a detection.
            login(5, 10, 9, "1.1.1.1"),
            login(6, 20, 9, "9.9.9.9"),
        ];
        let found = impossible_travel(&events, country);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].subject, Some(Uuid::from_u128(7)));
        assert_eq!(found[0].dedup_key, format!("travel:{}", Uuid::from_u128(2)));
        // A refused sign-in is not a sign-in.
        let mut refused = login(7, 31, 7, "2.2.2.2");
        refused.event_name = Some("login password refused: country".into());
        assert!(!refused.is_successful_login());
    }

    #[test]
    fn detections_mass_export_counts_records_in_the_window() {
        let mut events = Vec::new();
        for (i, minute) in [0, 3, 6].into_iter().enumerate() {
            let mut e = event(i as u128 + 1, minute, OP_EXPORT, Some(3));
            e.affected_count = Some(2_000);
            events.push(e);
        }
        let found = mass_export(&events);
        assert_eq!(found.len(), 1, "6,000 records in 6 minutes");
        assert!(found[0].personal_data);
        assert_eq!(found[0].severity, "high");

        // The same total spread over an hour is not a mass export.
        let spread: Vec<Event> = events
            .iter()
            .enumerate()
            .map(|(i, e)| Event {
                created_at: t(i as i64 * 30),
                ..e.clone()
            })
            .collect();
        assert!(mass_export(&spread).is_empty());
    }

    #[test]
    fn detections_privilege_escalation() {
        let grant = |n: u128, minute: i64, actor: u128, subject: Option<u128>| Event {
            entity_name: Some("user_account_mm_role".into()),
            record_id: subject.map(Uuid::from_u128),
            ..event(n, minute, OP_GRANT, Some(actor))
        };
        let found = privilege_escalation(&[grant(1, 0, 4, Some(4)), grant(2, 0, 4, Some(5))]);
        assert_eq!(found.len(), 1, "only the grant to oneself");
        assert_eq!(found[0].severity, "high");

        let mut admin = grant(3, 0, 4, None);
        admin.event_comment = Some("granted system.admin".into());
        assert_eq!(privilege_escalation(&[admin]).len(), 1);

        let burst: Vec<Event> = (0..5).map(|i| grant(10 + i, i as i64, 6, None)).collect();
        let found = privilege_escalation(&burst);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, "medium");
        assert!(privilege_escalation(&burst[..4]).is_empty());

        // A grant on a table that is not about access is not looked at.
        let mut other = grant(20, 0, 4, Some(4));
        other.entity_name = Some("account".into());
        assert!(privilege_escalation(&[other]).is_empty());
    }

    #[test]
    fn detections_new_device_needs_history() {
        assert!(is_new_device(false, true));
        assert!(!is_new_device(true, true));
        assert!(
            !is_new_device(false, false),
            "a first sign-in is not a new device"
        );
        let a = device_hash(Uuid::from_u128(1), "Mozilla/5.0");
        assert_eq!(a, device_hash(Uuid::from_u128(1), " Mozilla/5.0 "));
        assert_ne!(a, device_hash(Uuid::from_u128(2), "Mozilla/5.0"));
        assert_eq!(a.len(), 64);
    }
}
