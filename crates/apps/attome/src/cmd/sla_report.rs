//! `attome sla` (roadmap AB1-T1): availability measured from outside a
//! deployment, and the monthly SLA report.
//!
//! - `attome sla probe --url <server> --out <probes.jsonl> [--interval <s>] [--once]`
//!   asks the server's readiness route (`/health/ready`) every interval
//!   (60 seconds by default) and appends one JSON line per answer:
//!   `{"at": …, "ok": true|false, "ms": …, "status": …}`. Run it on another
//!   host: a server that is down cannot record its own downtime.
//! - `attome sla report --probes <probes.jsonl> --month <YYYY-MM>
//!   [--maintenance <windows.json>] [--target <percent>] --out <report.html>`
//!   works out the month's availability and writes a bilingual HTML report
//!   (print it to PDF).
//!
//! **How a month is measured** ([`measure`]): each probe speaks for the time
//! until the next one, at most two intervals; time no probe speaks for is
//! *unmeasured* and counts neither way. Agreed maintenance windows (a JSON
//! array of `{"start", "end"}`) are taken out of both the measured and the
//! down time. Availability is up time over measured time; consecutive
//! failing probes make one incident.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};

const USAGE: &str = "usage: attome sla probe --url <server> --out <probes.jsonl> [--interval <seconds>] [--once]\n       attome sla report --probes <probes.jsonl> --month <YYYY-MM> [--maintenance <windows.json>] [--target <percent>] --out <report.html>";
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_INTERVAL_SECS: u64 = 60;

/// One probe's answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Probe {
    pub at: DateTime<Utc>,
    pub ok: bool,
    #[serde(default)]
    pub ms: Option<u64>,
    #[serde(default)]
    pub status: Option<u16>,
}

/// An agreed maintenance window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Window {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// A month's measurement.
#[derive(Debug, Clone, PartialEq)]
pub struct Measurement {
    pub measured_secs: i64,
    pub down_secs: i64,
    pub maintenance_secs: i64,
    pub unmeasured_secs: i64,
    /// Up time over measured time, in percent; `None` when nothing was
    /// measured.
    pub availability: Option<f64>,
    /// Down periods outside maintenance, oldest first.
    pub incidents: Vec<(DateTime<Utc>, DateTime<Utc>)>,
}

fn overlap(a: (DateTime<Utc>, DateTime<Utc>), b: (DateTime<Utc>, DateTime<Utc>)) -> i64 {
    let start = a.0.max(b.0);
    let end = a.1.min(b.1);
    (end - start).num_seconds().max(0)
}

/// Splits `span` into the parts outside every window. Pure.
fn outside(
    span: (DateTime<Utc>, DateTime<Utc>),
    windows: &[Window],
) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    let mut parts = vec![span];
    for w in windows {
        parts = parts
            .into_iter()
            .flat_map(|(s, e)| {
                if w.end <= s || w.start >= e {
                    vec![(s, e)]
                } else {
                    let mut kept = Vec::new();
                    if w.start > s {
                        kept.push((s, w.start));
                    }
                    if w.end < e {
                        kept.push((w.end, e));
                    }
                    kept
                }
            })
            .collect();
    }
    parts
}

/// Measures availability in `[start, end)` from `probes`, each speaking
/// for at most `2 × interval`. Pure.
pub fn measure(
    probes: &[Probe],
    interval: Duration,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    maintenance: &[Window],
) -> Measurement {
    let mut sorted: Vec<&Probe> = probes.iter().filter(|p| p.at < end).collect();
    sorted.sort_by_key(|p| p.at);
    let reach = chrono::Duration::from_std(interval * 2).unwrap_or(chrono::Duration::minutes(2));
    let window = (start, end);
    let total = (end - start).num_seconds().max(0);
    let maintenance_secs: i64 = maintenance
        .iter()
        .map(|w| overlap((w.start, w.end), window))
        .sum();
    let (mut measured, mut down) = (0i64, 0i64);
    let mut incidents: Vec<(DateTime<Utc>, DateTime<Utc>)> = Vec::new();
    for (i, probe) in sorted.iter().enumerate() {
        let until = sorted
            .get(i + 1)
            .map_or(probe.at + reach, |next| next.at.min(probe.at + reach));
        let span = (probe.at.max(start), until.min(end));
        if span.1 <= span.0 {
            continue;
        }
        for part in outside(span, maintenance) {
            let secs = (part.1 - part.0).num_seconds();
            measured += secs;
            if !probe.ok {
                down += secs;
                match incidents.last_mut() {
                    Some(last) if last.1 >= part.0 => last.1 = part.1,
                    _ => incidents.push(part),
                }
            }
        }
    }
    let unmeasured = (total - maintenance_secs - measured).max(0);
    Measurement {
        measured_secs: measured,
        down_secs: down,
        maintenance_secs,
        unmeasured_secs: unmeasured,
        availability: (measured > 0).then(|| {
            ((measured - down) as f64 / measured as f64 * 100.0 * 1000.0).round() / 1000.0
        }),
        incidents,
    }
}

/// The first instant of a `YYYY-MM` month and of the next one, in UTC.
pub fn month_bounds(month: &str) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let first = NaiveDate::parse_from_str(&format!("{month}-01"), "%Y-%m-%d").ok()?;
    let next = if first.month() == 12 {
        NaiveDate::from_ymd_opt(first.year() + 1, 1, 1)?
    } else {
        NaiveDate::from_ymd_opt(first.year(), first.month() + 1, 1)?
    };
    Some((
        Utc.from_utc_datetime(&first.and_hms_opt(0, 0, 0)?),
        Utc.from_utc_datetime(&next.and_hms_opt(0, 0, 0)?),
    ))
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn minutes(secs: i64) -> String {
    format!("{:.1}", secs as f64 / 60.0)
}

/// The report page, English and Arabic. Pure.
pub fn report_html(url: &str, month: &str, m: &Measurement, target: Option<f64>) -> String {
    let availability = m
        .availability
        .map_or_else(|| "—".to_owned(), |a| format!("{a:.3}%"));
    let verdict = match (m.availability, target) {
        (Some(a), Some(t)) if a >= t => format!("Met the {t}% target / حقق الهدف {t}%"),
        (Some(_), Some(t)) => format!("Missed the {t}% target / لم يحقق الهدف {t}%"),
        _ => String::new(),
    };
    let rows: String = m
        .incidents
        .iter()
        .map(|(s, e)| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                s.format("%Y-%m-%d %H:%M UTC"),
                e.format("%Y-%m-%d %H:%M UTC"),
                minutes((*e - *s).num_seconds())
            )
        })
        .collect();
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>SLA report {month}</title>\
<style>body{{font-family:system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem}}\
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.3rem .5rem;text-align:start}}\
.ar{{direction:rtl}}</style></head><body>\
<h1>Availability report / تقرير التوفر — {month}</h1><p>{url}</p>\
<table><tr><th>Availability / التوفر</th><td>{availability}</td></tr>\
<tr><th>Measured (min) / المدة المقاسة (دقيقة)</th><td>{measured}</td></tr>\
<tr><th>Down (min) / مدة التوقف (دقيقة)</th><td>{down}</td></tr>\
<tr><th>Agreed maintenance (min) / الصيانة المتفق عليها (دقيقة)</th><td>{maint}</td></tr>\
<tr><th>Not measured (min) / غير مقاسة (دقيقة)</th><td>{unmeasured}</td></tr></table>\
<p><strong>{verdict}</strong></p>\
<h2>Incidents / الانقطاعات</h2><table><tr><th>From / من</th><th>To / إلى</th><th>Minutes / دقائق</th></tr>{rows}</table>\
<p class=\"ar\">تُحسب نسبة التوفر من الوقت المقاس فقط، وتُستثنى نوافذ الصيانة المتفق عليها.</p>\
</body></html>\n",
        month = escape(month),
        url = escape(url),
        measured = minutes(m.measured_secs),
        down = minutes(m.down_secs),
        maint = minutes(m.maintenance_secs),
        unmeasured = minutes(m.unmeasured_secs),
    )
}

#[derive(Debug, Default)]
struct Args {
    map: std::collections::BTreeMap<String, String>,
    once: bool,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--once" => out.once = true,
            "--url" | "--out" | "--interval" | "--probes" | "--month" | "--maintenance"
            | "--target" => {
                let value = it.next().ok_or(format!("{arg} needs a value"))?;
                out.map
                    .insert(arg.trim_start_matches('-').to_owned(), value.clone());
            }
            "--help" | "-h" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown option `{other}`\n{USAGE}")),
        }
    }
    Ok(out)
}

async fn probe_once(client: &attome_outbound::http::Outbound, url: &str) -> Probe {
    let started = std::time::Instant::now();
    let answer = client.get(format!("{url}/health/ready")).send().await;
    let ms = u64::try_from(started.elapsed().as_millis()).ok();
    match answer {
        Ok(response) => Probe {
            at: Utc::now(),
            ok: response.status().is_success(),
            ms,
            status: Some(response.status().as_u16()),
        },
        Err(_) => Probe {
            at: Utc::now(),
            ok: false,
            ms,
            status: None,
        },
    }
}

fn append(path: &PathBuf, probe: &Probe) -> Result<(), String> {
    let line = serde_json::to_string(probe).map_err(|e| e.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    writeln!(file, "{line}").map_err(|e| e.to_string())
}

async fn probe(args: Args) -> Result<(), String> {
    let url = args
        .map
        .get("url")
        .ok_or(USAGE)?
        .trim_end_matches('/')
        .to_owned();
    let out = PathBuf::from(args.map.get("out").ok_or(USAGE)?);
    let interval = args
        .map
        .get("interval")
        .map(|s| {
            s.parse::<u64>()
                .map_err(|_| "--interval is whole seconds".to_owned())
        })
        .transpose()?
        .unwrap_or(DEFAULT_INTERVAL_SECS)
        .max(5);
    let purpose =
        attome_outbound::http::Purpose::public("cli-sla-probe").with_private_urls([url.as_str()]);
    let client = attome_outbound::http::client(purpose, |b| b.timeout(PROBE_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let mut ticker = tokio::time::interval(Duration::from_secs(interval));
    loop {
        ticker.tick().await;
        let result = probe_once(&client, &url).await;
        let file = out.clone();
        let line = result.clone();
        tokio::task::spawn_blocking(move || append(&file, &line))
            .await
            .map_err(|e| e.to_string())??;
        println!(
            "{} {}",
            result.at.to_rfc3339(),
            if result.ok { "up" } else { "down" }
        );
        if args.once {
            return Ok(());
        }
    }
}

fn report(args: &Args) -> Result<String, String> {
    let probes_path = args.map.get("probes").ok_or(USAGE)?;
    let month = args.map.get("month").ok_or(USAGE)?;
    let out = args.map.get("out").ok_or(USAGE)?;
    let (start, end) = month_bounds(month).ok_or("--month is YYYY-MM")?;
    let text = std::fs::read_to_string(probes_path).map_err(|e| format!("{probes_path}: {e}"))?;
    let probes: Vec<Probe> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let maintenance: Vec<Window> = match args.map.get("maintenance") {
        Some(path) => serde_json::from_str(
            &std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?,
        )
        .map_err(|e| format!("{path}: {e}"))?,
        None => Vec::new(),
    };
    let interval = args
        .map
        .get("interval")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    let target = args.map.get("target").and_then(|t| t.parse::<f64>().ok());
    let measured = measure(
        &probes,
        Duration::from_secs(interval),
        start,
        end,
        &maintenance,
    );
    let url = args.map.get("url").cloned().unwrap_or_default();
    std::fs::write(out, report_html(&url, month, &measured, target))
        .map_err(|e| format!("{out}: {e}"))?;
    Ok(measured
        .availability
        .map_or_else(|| "nothing measured".to_owned(), |a| format!("{a:.3}%")))
}

/// `attome sla`.
#[tokio::main]
pub async fn run(args: &[String]) -> ExitCode {
    let (command, rest) = match args.split_first() {
        Some((c, rest)) => (c.as_str(), rest),
        None => {
            println!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let parsed = match parse_args(rest) {
        Ok(p) => p,
        Err(message) => {
            println!("{message}");
            return ExitCode::from(2);
        }
    };
    let result = match command {
        "probe" => probe(parsed).await.map(|()| String::new()),
        "report" => report(&parsed),
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(summary) => {
            if !summary.is_empty() {
                println!("availability {summary}");
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            println!("{message}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(min: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap() + chrono::Duration::minutes(min)
    }

    fn probes(states: &[bool]) -> Vec<Probe> {
        states
            .iter()
            .enumerate()
            .map(|(i, ok)| Probe {
                at: t(i as i64),
                ok: *ok,
                ms: Some(20),
                status: Some(if *ok { 200 } else { 503 }),
            })
            .collect()
    }

    #[test]
    fn sla_report_availability_from_probes() {
        // Ten one-minute probes, two failing in a row: 80% and one incident.
        let mut states = [true; 10];
        states[3] = false;
        states[4] = false;
        let m = measure(&probes(&states), Duration::from_secs(60), t(0), t(10), &[]);
        assert_eq!(m.measured_secs, 600);
        assert_eq!(m.down_secs, 120);
        assert_eq!(m.availability, Some(80.0));
        assert_eq!(m.incidents, vec![(t(3), t(5))]);
    }

    #[test]
    fn sla_report_excludes_maintenance_and_unmeasured_time() {
        let mut states = [true; 10];
        states[3] = false;
        states[4] = false;
        let window = Window {
            start: t(3),
            end: t(5),
        };
        let m = measure(
            &probes(&states),
            Duration::from_secs(60),
            t(0),
            t(20),
            &[window],
        );
        assert_eq!(m.down_secs, 0, "the outage was agreed maintenance");
        assert_eq!(m.availability, Some(100.0));
        assert_eq!(m.maintenance_secs, 120);
        // Probes stop at minute 9 and speak for two minutes at most.
        assert_eq!(m.measured_secs, 600 - 120 + 60);
        assert_eq!(m.unmeasured_secs, 1200 - 120 - m.measured_secs);
        assert!(m.incidents.is_empty());
    }

    #[test]
    fn sla_report_months_and_html() {
        let (start, end) = month_bounds("2026-12").unwrap();
        assert_eq!(start, Utc.with_ymd_and_hms(2026, 12, 1, 0, 0, 0).unwrap());
        assert_eq!(end, Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap());
        assert!(month_bounds("2026-13").is_none());
        let m = measure(
            &probes(&[true, false]),
            Duration::from_secs(60),
            t(0),
            t(2),
            &[],
        );
        let html = report_html("https://crm.example.sa", "2026-10", &m, Some(99.9));
        assert!(html.contains("50.000%"));
        assert!(html.contains("Missed the 99.9% target"));
        assert!(html.contains("تقرير التوفر"));
        let none = measure(&[], Duration::from_secs(60), t(0), t(2), &[]);
        assert_eq!(none.availability, None);
    }
}
