//! AB2-T10: the failover drill, through the platform's own handles
//! (V2-D1628 (3)), not Docker.
//!
//! `attome drill failover --scenario <leader|router|redis> --confirm <scenario> ...`
//! starts a write loop, breaks one part of a high-availability rig, and
//! measures what the loop saw:
//!
//! - **leader**: Patroni's `POST /failover` (`--patroni <url>`, repeatable)
//!   moves the leader to a synchronous replica (else any replica) while the
//!   loop inserts into `drill_failover_probe` through `--database-url` (the
//!   HAProxy write port of a rig, never the deployment's own database);
//! - **router**: the service manager stops `--service <name>` on this host
//!   (`sc.exe stop` on Windows, `systemctl stop` elsewhere) and starts it
//!   again once the loop has recovered or given up; the loop writes as for
//!   the leader, through an address that must reach another router;
//! - **redis**: `SENTINEL FAILOVER <--sentinel-service>` is sent to
//!   `--sentinel <host:port>`, and the loop writes `SET` keys to whichever
//!   master the sentinel names at each write.
//!
//! The loop writes every [`WRITE_EVERY`] and keeps the ids that were
//! acknowledged. The **recovery time** is from the first failed write to the
//! next one that succeeds (zero when no write failed); the loop gives up
//! after `--max-wait` seconds (60 by default). Then every acknowledged id is
//! read back: **writes lost** are those not found ([`writes_lost`]). **Split
//! brain** is more than one member answering as primary (`--member-url`
//! for Postgres, `--redis-member` for Redis; [`split_brain`]). The evidence
//! (`attome-evidence/v1`, kind `failover`) has the checks `rto` (recovered
//! within [`RTO_LIMIT`]), `writes_lost` (none) and `split_brain` (none), is
//! signed with `--key` and written to
//! `<--out>/failover-drill-evidence-<yyyy-mm-dd>-<scenario>.json`.

use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::error::OpsError;
use crate::evidence::{Check, CheckResult, Evidence, EvidenceKind, SCHEMA};

/// How often the loop writes.
pub const WRITE_EVERY: Duration = Duration::from_millis(50);
/// How long one write may take before it counts as failed.
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// Writes before the fault, which must all succeed.
const WARMUP: Duration = Duration::from_secs(2);
/// How long the loop keeps writing once it has recovered.
const SETTLE: Duration = Duration::from_secs(3);
/// The recovery time the drill accepts.
pub const RTO_LIMIT: Duration = Duration::from_secs(30);

/// What the drill breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    Leader,
    Router,
    Redis,
}

impl Scenario {
    pub fn parse(name: &str) -> Option<Scenario> {
        match name {
            "leader" => Some(Scenario::Leader),
            "router" => Some(Scenario::Router),
            "redis" => Some(Scenario::Redis),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Scenario::Leader => "leader",
            Scenario::Router => "router",
            Scenario::Redis => "redis",
        }
    }
}

/// The drill's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailoverArgs {
    pub scenario: Scenario,
    pub database_url: Option<String>,
    pub member_urls: Vec<String>,
    pub patroni_urls: Vec<String>,
    pub service: Option<String>,
    pub sentinel: Option<String>,
    pub sentinel_service: Option<String>,
    pub redis_members: Vec<String>,
    pub redis_password: Option<String>,
    pub max_wait: Duration,
    pub key: PathBuf,
    pub out: PathBuf,
}

/// Parses the arguments after `failover`; every problem at once. Pure.
pub fn parse_args(args: &[String]) -> Result<FailoverArgs, String> {
    let mut scenario = None;
    let mut confirm = None;
    let mut parsed = FailoverArgs {
        scenario: Scenario::Leader,
        database_url: None,
        member_urls: Vec::new(),
        patroni_urls: Vec::new(),
        service: None,
        sentinel: None,
        sentinel_service: None,
        redis_members: Vec::new(),
        redis_password: None,
        max_wait: Duration::from_secs(60),
        key: PathBuf::new(),
        out: PathBuf::from("drill-evidence"),
    };
    let mut key = None;
    let mut problems = Vec::new();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let Some(value) = iter.next() else {
            problems.push(format!("{flag} needs a value"));
            break;
        };
        match flag.as_str() {
            "--scenario" => scenario = Some(value.clone()),
            "--confirm" => confirm = Some(value.clone()),
            "--database-url" => parsed.database_url = Some(value.clone()),
            "--member-url" => parsed.member_urls.push(value.clone()),
            "--patroni" => parsed.patroni_urls.push(value.clone()),
            "--service" => parsed.service = Some(value.clone()),
            "--sentinel" => parsed.sentinel = Some(value.clone()),
            "--sentinel-service" => parsed.sentinel_service = Some(value.clone()),
            "--redis-member" => parsed.redis_members.push(value.clone()),
            "--redis-password" => parsed.redis_password = Some(value.clone()),
            "--max-wait" => match value.parse::<u64>() {
                Ok(secs) if (5..=600).contains(&secs) => {
                    parsed.max_wait = Duration::from_secs(secs);
                }
                _ => problems.push("--max-wait is 5 to 600 seconds".into()),
            },
            "--key" => key = Some(PathBuf::from(value)),
            "--out" => parsed.out = PathBuf::from(value),
            other => problems.push(format!("unknown argument {other}")),
        }
    }
    match scenario.as_deref().and_then(Scenario::parse) {
        Some(s) => parsed.scenario = s,
        None => problems.push("--scenario is leader, router or redis".into()),
    }
    if confirm != scenario {
        problems.push("--confirm must repeat --scenario: the drill breaks a live rig".into());
    }
    match key {
        Some(path) => parsed.key = path,
        None => problems.push("--key names the drill signing key".into()),
    }
    match parsed.scenario {
        Scenario::Leader | Scenario::Router => {
            if parsed.database_url.is_none() {
                problems.push("--database-url is the rig's write address".into());
            }
            if parsed.member_urls.is_empty() {
                problems.push("--member-url names each database member, for split brain".into());
            }
            if parsed.scenario == Scenario::Leader && parsed.patroni_urls.is_empty() {
                problems.push("--patroni names a Patroni API".into());
            }
            if parsed.scenario == Scenario::Router
                && !parsed.service.as_deref().is_some_and(service_name_ok)
            {
                problems
                    .push("--service names the router's service (letters, digits, - _ .)".into());
            }
        }
        Scenario::Redis => {
            if parsed.sentinel.is_none() || parsed.sentinel_service.is_none() {
                problems.push("--sentinel <host:port> and --sentinel-service are needed".into());
            }
            if parsed.redis_members.is_empty() {
                problems.push("--redis-member names each Redis member, for split brain".into());
            }
        }
    }
    if problems.is_empty() {
        Ok(parsed)
    } else {
        Err(problems.join("; "))
    }
}

/// A service name safe to pass to the service manager. Pure.
pub fn service_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

/// The acknowledged ids not found after recovery, in order. Pure.
pub fn writes_lost(acknowledged: &[i64], found: &HashSet<i64>) -> Vec<i64> {
    acknowledged
        .iter()
        .copied()
        .filter(|id| !found.contains(id))
        .collect()
}

/// Whether more than one member answered as primary. Pure.
pub fn split_brain(primaries: usize) -> bool {
    primaries > 1
}

/// What the write loop saw.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LoopOutcome {
    pub acknowledged: Vec<i64>,
    /// From the first failed write to the next success; zero when none
    /// failed; `None` when the loop never recovered.
    pub rto: Option<Duration>,
    pub warmup_ok: bool,
}

/// Writes `first_id`, `first_id + 1`, … with `write` every [`WRITE_EVERY`]:
/// a warm-up that must succeed, then `fault` runs, then until the writes
/// recover and [`SETTLE`] passes, or `max_wait` passes.
pub async fn write_loop<W, WF, F>(
    first_id: i64,
    mut write: W,
    fault: F,
    max_wait: Duration,
) -> LoopOutcome
where
    W: FnMut(i64) -> WF,
    WF: Future<Output = bool>,
    F: Future<Output = Result<(), OpsError>>,
{
    let mut outcome = LoopOutcome {
        warmup_ok: true,
        ..LoopOutcome::default()
    };
    let mut next = first_id;
    let mut attempt = |id: i64| {
        let pending = write(id);
        async move {
            tokio::time::timeout(WRITE_TIMEOUT, pending)
                .await
                .unwrap_or(false)
        }
    };
    let warmup_end = Instant::now() + WARMUP;
    while Instant::now() < warmup_end {
        if attempt(next).await {
            outcome.acknowledged.push(next);
        } else {
            outcome.warmup_ok = false;
        }
        next += 1;
        tokio::time::sleep(WRITE_EVERY).await;
    }
    if !outcome.warmup_ok {
        return outcome;
    }
    if let Err(error) = fault.await {
        tracing::warn!(%error, "drill: the fault was not injected");
        outcome.warmup_ok = false;
        return outcome;
    }
    let started = Instant::now();
    let mut outage: Option<Instant> = None;
    let mut recovered: Option<Instant> = None;
    while started.elapsed() < max_wait {
        let ok = attempt(next).await;
        let now = Instant::now();
        if ok {
            outcome.acknowledged.push(next);
            if recovered.is_none() {
                recovered = Some(now);
            }
        } else {
            outage.get_or_insert(now);
            recovered = None;
        }
        next += 1;
        if recovered.is_some_and(|at| now.duration_since(at) >= SETTLE) {
            break;
        }
        tokio::time::sleep(WRITE_EVERY).await;
    }
    outcome.rto = match (outage, recovered) {
        (None, Some(_)) => Some(Duration::ZERO),
        (Some(down), Some(up)) => Some(up.duration_since(down)),
        _ => None,
    };
    outcome
}

/// The evidence of one run. Pure apart from the clock and the id.
pub fn evidence(
    scenario: Scenario,
    started_at: chrono::DateTime<Utc>,
    outcome: &LoopOutcome,
    lost: usize,
    primaries: usize,
    detail: Option<String>,
) -> Evidence {
    let check = |name: &str, pass: bool, detail: String| Check {
        name: name.to_owned(),
        result: if pass {
            CheckResult::Pass
        } else {
            CheckResult::Fail
        },
        detail: Some(detail),
    };
    let rto_ms = outcome.rto.map(|d| d.as_millis());
    let rto_ok = outcome.warmup_ok && outcome.rto.is_some_and(|d| d <= RTO_LIMIT);
    let rto_text = match (outcome.warmup_ok, rto_ms) {
        (false, _) => {
            "the writes failed before the fault, or the fault was not injected".to_owned()
        }
        (true, Some(ms)) => format!("writes recovered after {ms} ms"),
        (true, None) => "writes did not recover".to_owned(),
    };
    let mut checks = vec![
        check("rto", rto_ok, rto_text),
        check(
            "writes_lost",
            lost == 0,
            format!(
                "{lost} of {} acknowledged writes missing",
                outcome.acknowledged.len()
            ),
        ),
        check(
            "split_brain",
            !split_brain(primaries),
            format!("{primaries} member(s) answered as primary"),
        ),
    ];
    if let Some(detail) = detail {
        checks.push(Check {
            name: "note".to_owned(),
            result: CheckResult::Pass,
            detail: Some(detail),
        });
    }
    let mut extra = Map::new();
    extra.insert("scenario".into(), json!(scenario.name()));
    extra.insert(
        "rto_ms".into(),
        json!(rto_ms.map(|ms| u64::try_from(ms).unwrap_or(u64::MAX))),
    );
    extra.insert("writes_lost".into(), json!(lost));
    extra.insert("acknowledged".into(), json!(outcome.acknowledged.len()));
    extra.insert("split_brain".into(), json!(split_brain(primaries)));
    let mut evidence = Evidence {
        schema: SCHEMA.to_owned(),
        kind: EvidenceKind::Failover,
        drill_id: Uuid::now_v7(),
        started_at,
        finished_at: Utc::now(),
        platform_version: env!("CARGO_PKG_VERSION").to_owned(),
        image_digest: None,
        deployment_id: None,
        checks,
        rpo_seconds: None,
        rto_seconds: outcome.rto.map(|d| d.as_secs_f64()),
        data_size_bytes: None,
        restore_ok: false,
        provenance_ok: false,
        overall_ok: false,
        extra,
    };
    evidence.compute_overall();
    evidence
}

/// The evidence file's name. Pure.
pub fn evidence_file_name(scenario: Scenario, date: chrono::NaiveDate) -> String {
    format!(
        "failover-drill-evidence-{}-{}.json",
        date.format("%Y-%m-%d"),
        scenario.name()
    )
}

// ── Postgres ────────────────────────────────────────────────────────────────

fn pg_pool(url: &str) -> Result<sqlx::PgPool, OpsError> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(WRITE_TIMEOUT)
        .connect_lazy(url)
        .map_err(|e| OpsError::Validation(format!("a database address does not read: {e}")))
}

async fn pg_prepare(pool: &sqlx::PgPool) -> Result<(), OpsError> {
    sqlx::query("CREATE TABLE IF NOT EXISTS drill_failover_probe (id bigint PRIMARY KEY)")
        .execute(pool)
        .await
        .map_err(|e| OpsError::Validation(format!("the probe table could not be made: {e}")))?;
    Ok(())
}

async fn pg_write(pool: sqlx::PgPool, id: i64) -> bool {
    sqlx::query("INSERT INTO drill_failover_probe (id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(id)
        .execute(&pool)
        .await
        .is_ok()
}

async fn pg_found(pool: &sqlx::PgPool, ids: &[i64]) -> Result<HashSet<i64>, OpsError> {
    let found: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM drill_failover_probe WHERE id = ANY($1)")
            .bind(ids)
            .fetch_all(pool)
            .await
            .map_err(|e| OpsError::Validation(format!("the probe rows could not be read: {e}")))?;
    Ok(found.into_iter().collect())
}

/// How many database members answer as primary; a member that does not
/// answer counts as not primary.
async fn pg_primaries(urls: &[String]) -> usize {
    let mut primaries = 0;
    for url in urls {
        let Ok(pool) = pg_pool(url) else { continue };
        let primary: Option<bool> = sqlx::query_scalar("SELECT NOT pg_is_in_recovery()")
            .fetch_one(&pool)
            .await
            .ok();
        if primary == Some(true) {
            primaries += 1;
        }
        pool.close().await;
    }
    primaries
}

/// The failover body Patroni's `POST /failover` takes: the leader and a
/// synchronous replica, else any replica. Pure.
pub fn failover_body(cluster: &crate::cluster::PatroniCluster) -> Result<Value, OpsError> {
    let leader = cluster
        .leader()
        .ok_or_else(|| OpsError::Validation("the cluster has no leader".into()))?;
    let candidate = cluster
        .members
        .iter()
        .find(|m| m.role == "sync_standby")
        .or_else(|| cluster.members.iter().find(|m| m.role == "replica"))
        .ok_or_else(|| OpsError::Validation("the cluster has no replica to fail over to".into()))?;
    Ok(json!({ "leader": leader.name, "candidate": candidate.name }))
}

async fn patroni_failover(urls: &[String]) -> Result<(), OpsError> {
    let cluster = crate::cluster::fetch_cluster(urls).await?;
    let body = failover_body(&cluster)?;
    let purpose = attome_outbound::http::Purpose::public("patroni")
        .with_private_urls(urls.iter().map(String::as_str))
        .no_redirects();
    let http = attome_outbound::http::client(purpose, |b| b.timeout(Duration::from_secs(10)))
        .map_err(|e| OpsError::Internal(e.to_string()))?;
    for url in urls {
        let target = format!("{}/failover", url.trim_end_matches('/'));
        if let Ok(answer) = http.post(&target).json(&body).send().await
            && answer.status().is_success()
        {
            return Ok(());
        }
    }
    Err(OpsError::Unavailable("patroni"))
}

// ── The service manager ─────────────────────────────────────────────────────

/// The service manager's command to stop or start `service`. Pure.
pub fn service_command(service: &str, start: bool) -> (String, Vec<String>) {
    if cfg!(windows) {
        let verb = if start { "start" } else { "stop" };
        ("sc.exe".into(), vec![verb.into(), service.into()])
    } else {
        let verb = if start { "start" } else { "stop" };
        ("systemctl".into(), vec![verb.into(), service.into()])
    }
}

async fn service(service: &str, start: bool) -> Result<(), OpsError> {
    let (program, args) = service_command(service, start);
    let status = tokio::process::Command::new(&program)
        .args(&args)
        .status()
        .await
        .map_err(|e| OpsError::Internal(format!("{program}: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(OpsError::Validation(format!(
            "{program} {} exited with {status}",
            args.join(" ")
        )))
    }
}

// ── Redis, spoken directly ──────────────────────────────────────────────────

/// A command in RESP. Pure.
pub fn resp_command(args: &[&str]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        out.extend_from_slice(arg.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// One reply, flattened: a simple string or error line, an integer, a bulk
/// string, or an array's elements (one level). Errors start with `-`.
async fn resp_read(reader: &mut BufReader<TcpStream>) -> Result<Vec<String>, OpsError> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|_| OpsError::Unavailable("redis"))?;
    let line = line.trim_end().to_owned();
    match line.chars().next() {
        Some('+' | '-' | ':') => Ok(vec![line]),
        Some('$') => Ok(vec![resp_bulk(reader, &line).await?]),
        Some('*') => {
            let count: i64 = line[1..].parse().unwrap_or(0);
            let mut items = Vec::new();
            for _ in 0..count.max(0) {
                let mut head = String::new();
                reader
                    .read_line(&mut head)
                    .await
                    .map_err(|_| OpsError::Unavailable("redis"))?;
                let head = head.trim_end().to_owned();
                if head.starts_with('$') {
                    items.push(resp_bulk(reader, &head).await?);
                } else {
                    items.push(head);
                }
            }
            Ok(items)
        }
        _ => Err(OpsError::Validation(
            "Redis answered something unreadable".into(),
        )),
    }
}

async fn resp_bulk(reader: &mut BufReader<TcpStream>, head: &str) -> Result<String, OpsError> {
    let len: i64 = head[1..].parse().unwrap_or(-1);
    if len < 0 {
        return Ok(String::new());
    }
    let mut value = String::new();
    reader
        .read_line(&mut value)
        .await
        .map_err(|_| OpsError::Unavailable("redis"))?;
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}

/// Sends commands to `addr` (after `AUTH` when a password is given) and
/// answers the last reply.
async fn resp_call(
    addr: &str,
    password: Option<&str>,
    commands: &[Vec<&str>],
) -> Result<Vec<String>, OpsError> {
    let stream = tokio::time::timeout(WRITE_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| OpsError::Unavailable("redis"))?
        .map_err(|_| OpsError::Unavailable("redis"))?;
    let mut reader = BufReader::new(stream);
    if let Some(password) = password {
        reader
            .get_mut()
            .write_all(&resp_command(&["AUTH", password]))
            .await
            .map_err(|_| OpsError::Unavailable("redis"))?;
        resp_read(&mut reader).await?;
    }
    let mut last = Vec::new();
    for command in commands {
        reader
            .get_mut()
            .write_all(&resp_command(command))
            .await
            .map_err(|_| OpsError::Unavailable("redis"))?;
        last = resp_read(&mut reader).await?;
    }
    Ok(last)
}

async fn redis_master(sentinel: &str, service: &str) -> Result<String, OpsError> {
    let reply = resp_call(
        sentinel,
        None,
        &[vec!["SENTINEL", "get-master-addr-by-name", service]],
    )
    .await?;
    match reply.as_slice() {
        [host, port] if !host.is_empty() => Ok(format!("{host}:{port}")),
        _ => Err(OpsError::Validation(
            "the sentinel names no master for the service".into(),
        )),
    }
}

fn redis_key(id: i64) -> String {
    format!("attome-ops:drill-failover:{id}")
}

async fn redis_primaries(members: &[String], password: Option<&str>) -> usize {
    let mut primaries = 0;
    for member in members {
        if let Ok(reply) = resp_call(member, password, &[vec!["ROLE"]]).await
            && reply.first().map(String::as_str) == Some("master")
        {
            primaries += 1;
        }
    }
    primaries
}

// ── The run ─────────────────────────────────────────────────────────────────

/// Runs the drill; the evidence, not yet signed.
pub async fn run(args: &FailoverArgs) -> Result<Evidence, OpsError> {
    let started_at = Utc::now();
    let first_id = started_at.timestamp_millis() * 1000;
    match args.scenario {
        Scenario::Leader | Scenario::Router => {
            let url = args.database_url.as_deref().unwrap_or_default();
            let pool = pg_pool(url)?;
            pg_prepare(&pool).await?;
            let write = |id: i64| pg_write(pool.clone(), id);
            let outcome = match args.scenario {
                Scenario::Leader => {
                    write_loop(
                        first_id,
                        write,
                        patroni_failover(&args.patroni_urls),
                        args.max_wait,
                    )
                    .await
                }
                _ => {
                    let name = args.service.as_deref().unwrap_or_default();
                    let outcome =
                        write_loop(first_id, write, service(name, false), args.max_wait).await;
                    // Always started again, however the loop ended.
                    if let Err(error) = service(name, true).await {
                        tracing::error!(%error, service = name, "drill: the router was not started again; start it by hand");
                    }
                    outcome
                }
            };
            let found = pg_found(&pool, &outcome.acknowledged).await?;
            let lost = writes_lost(&outcome.acknowledged, &found).len();
            let primaries = pg_primaries(&args.member_urls).await;
            pool.close().await;
            Ok(evidence(
                args.scenario,
                started_at,
                &outcome,
                lost,
                primaries,
                None,
            ))
        }
        Scenario::Redis => {
            let sentinel = args.sentinel.clone().unwrap_or_default();
            let service_name = args.sentinel_service.clone().unwrap_or_default();
            let password = args.redis_password.clone();
            let write = |id: i64| {
                let (sentinel, service_name, password) =
                    (sentinel.clone(), service_name.clone(), password.clone());
                async move {
                    let Ok(master) = redis_master(&sentinel, &service_name).await else {
                        return false;
                    };
                    let key = redis_key(id);
                    resp_call(
                        &master,
                        password.as_deref(),
                        &[vec!["SET", key.as_str(), "1", "EX", "86400"]],
                    )
                    .await
                    .is_ok_and(|reply| reply.first().is_some_and(|r| r == "+OK"))
                }
            };
            let fault = async {
                let reply = resp_call(
                    &sentinel,
                    None,
                    &[vec!["SENTINEL", "FAILOVER", service_name.as_str()]],
                )
                .await?;
                if reply.first().is_some_and(|r| r.starts_with('-')) {
                    return Err(OpsError::Validation(format!(
                        "the sentinel refused the failover: {}",
                        reply.join(" ")
                    )));
                }
                Ok(())
            };
            let outcome = write_loop(first_id, write, fault, args.max_wait).await;
            let master = redis_master(&sentinel, &service_name).await?;
            let mut found = HashSet::new();
            for id in &outcome.acknowledged {
                let key = redis_key(*id);
                let reply = resp_call(
                    &master,
                    password.as_deref(),
                    &[vec!["EXISTS", key.as_str()]],
                )
                .await?;
                if reply.first().is_some_and(|r| r == ":1") {
                    found.insert(*id);
                }
            }
            let lost = writes_lost(&outcome.acknowledged, &found).len();
            let primaries = redis_primaries(&args.redis_members, password.as_deref()).await;
            Ok(evidence(
                args.scenario,
                started_at,
                &outcome,
                lost,
                primaries,
                Some(format!("master after the drill: {master}")),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn writes_lost_counts_missing_acknowledged_ids() {
        let found: HashSet<i64> = [1, 2, 4].into_iter().collect();
        assert_eq!(writes_lost(&[1, 2, 3, 4, 5], &found), vec![3, 5]);
        assert!(writes_lost(&[], &found).is_empty());
        assert!(split_brain(2));
        assert!(!split_brain(1));
    }

    #[test]
    fn the_scenario_must_be_confirmed() {
        let leader = args(&[
            "--scenario",
            "leader",
            "--confirm",
            "leader",
            "--database-url",
            "postgres://rig/drill",
            "--member-url",
            "postgres://pg1/drill",
            "--patroni",
            "http://pg1:8008",
            "--key",
            "drill.key",
        ]);
        let parsed = parse_args(&leader).unwrap();
        assert_eq!(parsed.scenario, Scenario::Leader);
        let mut unconfirmed = leader.clone();
        unconfirmed[3] = "router".into();
        assert!(parse_args(&unconfirmed).unwrap_err().contains("--confirm"));
        let router = args(&[
            "--scenario",
            "router",
            "--confirm",
            "router",
            "--database-url",
            "postgres://rig/drill",
            "--member-url",
            "postgres://pg1/drill",
            "--service",
            "haproxy; rm -rf /",
            "--key",
            "drill.key",
        ]);
        assert!(parse_args(&router).unwrap_err().contains("--service"));
    }

    #[test]
    fn evidence_passes_only_a_clean_quick_failover() {
        let quick = LoopOutcome {
            acknowledged: vec![1, 2, 3],
            rto: Some(Duration::from_millis(4_200)),
            warmup_ok: true,
        };
        let good = evidence(Scenario::Leader, Utc::now(), &quick, 0, 1, None);
        assert!(good.overall_ok);
        assert_eq!(good.extra["rto_ms"], json!(4_200));
        assert!(!evidence(Scenario::Leader, Utc::now(), &quick, 1, 1, None).overall_ok);
        assert!(!evidence(Scenario::Leader, Utc::now(), &quick, 0, 2, None).overall_ok);
        let stuck = LoopOutcome { rto: None, ..quick };
        assert!(!evidence(Scenario::Leader, Utc::now(), &stuck, 0, 1, None).overall_ok);
    }

    #[test]
    fn resp_and_failover_shapes() {
        assert_eq!(
            resp_command(&["SENTINEL", "FAILOVER", "main"]),
            b"*3\r\n$8\r\nSENTINEL\r\n$8\r\nFAILOVER\r\n$4\r\nmain\r\n".to_vec()
        );
        let cluster = crate::cluster::parse_cluster(&json!({ "members": [
            { "name": "pg1", "role": "leader" },
            { "name": "pg2", "role": "replica" },
            { "name": "pg3", "role": "sync_standby" }
        ]}))
        .unwrap();
        assert_eq!(
            failover_body(&cluster).unwrap(),
            json!({ "leader": "pg1", "candidate": "pg3" })
        );
        assert_eq!(
            evidence_file_name(
                Scenario::Redis,
                chrono::NaiveDate::from_ymd_opt(2026, 11, 2).unwrap()
            ),
            "failover-drill-evidence-2026-11-02-redis.json"
        );
    }

    #[tokio::test]
    async fn write_loop_measures_the_outage() {
        let down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = down.clone();
        let write = move |_id: i64| {
            let flag = flag.clone();
            async move { !flag.load(std::sync::atomic::Ordering::SeqCst) }
        };
        let switch = down.clone();
        let fault = async move {
            switch.store(true, std::sync::atomic::Ordering::SeqCst);
            let back = switch.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                back.store(false, std::sync::atomic::Ordering::SeqCst);
            });
            Ok(())
        };
        let outcome = write_loop(1, write, fault, Duration::from_secs(10)).await;
        assert!(outcome.warmup_ok);
        let rto = outcome.rto.expect("recovered");
        assert!(
            rto >= Duration::from_millis(150) && rto < Duration::from_secs(2),
            "{rto:?}"
        );
    }
}
