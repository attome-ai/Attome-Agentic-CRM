//! The built-in metrics store (roadmap U4-T1): once a minute this process's
//! Prometheus registry is sampled into `ops_metric_sample`, a table
//! partitioned by day, and partitions older than [`KEEP_DAYS`] are dropped,
//! so a Solo deployment has a month of history with no Prometheus to run.
//!
//! On by default on Solo (`cache.backend = "memory"`); set
//! `observability.builtin_store` to choose. Histogram buckets are left out
//! (their `_sum` and `_count` are kept), which keeps a minute's batch to the
//! registry's plain series.
//!
//! Partitions are DDL, so they are created and dropped through the migrator
//! pool; samples go in through the runtime pool. A failed minute is logged
//! and the next one runs as usual.

use std::time::Duration;

use attome_db::DbPool;
use chrono::{DateTime, NaiveDate, Utc};
use metrics_exporter_prometheus::PrometheusHandle;
use serde_json::{Map, Value};

/// Days of samples kept.
pub const KEEP_DAYS: i64 = 30;
/// How often the registry is sampled.
pub const SAMPLE_EVERY: Duration = Duration::from_secs(60);

/// One series value at one minute.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub name: String,
    pub labels: Map<String, Value>,
    pub value: f64,
}

/// The samples in Prometheus exposition text: comments, histogram buckets and
/// values that are not finite are left out.
pub fn parse(text: &str) -> Vec<Sample> {
    let mut samples = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (series, rest) = match line.find('{') {
            Some(open) => match line.rfind('}') {
                Some(close) if close > open => (&line[..=close], &line[close + 1..]),
                _ => continue,
            },
            None => match line.split_once(' ') {
                Some((name, rest)) => (name, rest),
                None => continue,
            },
        };
        let name = series.split('{').next().unwrap_or(series).trim();
        if name.is_empty() || name.ends_with("_bucket") {
            continue;
        }
        let Some(value) = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite())
        else {
            continue;
        };
        let labels = crate::metrics::labels_of(series)
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect();
        samples.push(Sample {
            name: name.to_owned(),
            labels,
            value,
        });
    }
    samples
}

/// The partition holding `day`'s samples.
pub fn partition_name(day: NaiveDate) -> String {
    format!("ops_metric_sample_p{}", day.format("%Y%m%d"))
}

/// The day a partition name holds, or `None` for any other table.
pub fn partition_day(name: &str) -> Option<NaiveDate> {
    let digits = name.strip_prefix("ops_metric_sample_p")?;
    if digits.len() != 8 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    NaiveDate::parse_from_str(digits, "%Y%m%d").ok()
}

/// Creates today's and tomorrow's partitions when missing.
pub async fn ensure_partitions(migrator: &DbPool, today: NaiveDate) -> Result<(), sqlx::Error> {
    for day in [Some(today), today.succ_opt()].into_iter().flatten() {
        let Some(start) = day.and_hms_opt(0, 0, 0).map(|t| t.and_utc()) else {
            continue;
        };
        let end = start + chrono::Duration::days(1);
        // DDL takes no bind parameters; the name and bounds are computed
        // from a date, never from input.
        let sql = format!(
            r#"CREATE TABLE IF NOT EXISTS "{}" PARTITION OF ops_metric_sample
                   FOR VALUES FROM ('{}') TO ('{}')"#,
            partition_name(day),
            start.to_rfc3339(),
            end.to_rfc3339()
        );
        sqlx::query(&sql).execute(migrator).await?;
    }
    Ok(())
}

/// The partitions to drop on `today`: those holding days before the last
/// [`KEEP_DAYS`].
pub fn expired(names: &[String], today: NaiveDate) -> Vec<String> {
    let cutoff = today - chrono::Duration::days(KEEP_DAYS);
    names
        .iter()
        .filter(|n| partition_day(n).is_some_and(|d| d < cutoff))
        .cloned()
        .collect()
}

/// Drops partitions older than [`KEEP_DAYS`]. Returns how many went.
pub async fn prune(migrator: &DbPool, today: NaiveDate) -> Result<usize, sqlx::Error> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT child.relname::text FROM pg_inherits i \
         JOIN pg_class parent ON parent.oid = i.inhparent \
         JOIN pg_class child ON child.oid = i.inhrelid \
         WHERE parent.oid = 'ops_metric_sample'::regclass",
    )
    .fetch_all(migrator)
    .await?;
    let gone = expired(&names, today);
    for name in &gone {
        // Names come from the catalog and match the partition pattern.
        sqlx::query(&format!(r#"DROP TABLE IF EXISTS "{name}""#))
            .execute(migrator)
            .await?;
    }
    Ok(gone.len())
}

/// Writes one minute's samples in one statement.
pub async fn insert(
    db: &DbPool,
    at: DateTime<Utc>,
    samples: &[Sample],
) -> Result<u64, sqlx::Error> {
    if samples.is_empty() {
        return Ok(0);
    }
    let names: Vec<&str> = samples.iter().map(|s| s.name.as_str()).collect();
    let labels: Vec<Value> = samples
        .iter()
        .map(|s| Value::Object(s.labels.clone()))
        .collect();
    let values: Vec<f64> = samples.iter().map(|s| s.value).collect();
    let done = sqlx::query(
        "INSERT INTO ops_metric_sample (ts, name, labels, value) \
         SELECT $1, n, l, v FROM unnest($2::text[], $3::jsonb[], $4::float8[]) AS s(n, l, v)",
    )
    .bind(at)
    .bind(&names)
    .bind(&labels)
    .bind(&values)
    .execute(db)
    .await?;
    Ok(done.rows_affected())
}

/// Starts the once-a-minute sampler. Process-lifetime supervision: a failed
/// minute is logged and the next one runs.
pub fn spawn(db: DbPool, migrator: DbPool, handle: PrometheusHandle) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SAMPLE_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut prepared_for: Option<NaiveDate> = None;
        loop {
            ticker.tick().await;
            let now = Utc::now();
            let today = now.date_naive();
            if prepared_for != Some(today) {
                match ensure_partitions(&migrator, today).await {
                    Ok(()) => {
                        prepared_for = Some(today);
                        match prune(&migrator, today).await {
                            Ok(0) => {}
                            Ok(dropped) => {
                                tracing::info!(dropped, "metrics store: old days dropped")
                            }
                            Err(error) => {
                                tracing::warn!(%error, "metrics store: old days were not dropped")
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "metrics store: today's partition could not be created");
                        continue;
                    }
                }
            }
            let samples = parse(&handle.render());
            if let Err(error) = insert(&db, now, &samples).await {
                tracing::warn!(%error, "metrics store: this minute's samples were not stored");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_store_parses_series_and_skips_buckets() {
        let text = "# HELP x y\n# TYPE x counter\n\
            http_requests_total{method=\"GET\",endpoint=\"/api/v1/x\"} 42\n\
            http_duration_seconds_bucket{le=\"0.1\"} 3\n\
            http_duration_seconds_sum 1.5\n\
            pool_size 8\n\
            broken_value{a=\"b\"} NaN\n";
        let samples = parse(text);
        let names: Vec<&str> = samples.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "http_requests_total",
                "http_duration_seconds_sum",
                "pool_size"
            ]
        );
        assert_eq!(samples[0].value, 42.0);
        assert_eq!(
            samples[0].labels.get("method"),
            Some(&Value::String("GET".into()))
        );
        assert!(samples[2].labels.is_empty());
    }

    #[test]
    fn metrics_store_prunes_days_past_the_window() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 14).unwrap();
        let names: Vec<String> = [
            "ops_metric_sample_p20260913",
            "ops_metric_sample_p20260914",
            "ops_metric_sample_p20261014",
            "ops_metric_sample_default",
            "something_else",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        assert_eq!(expired(&names, today), ["ops_metric_sample_p20260913"]);
        assert_eq!(partition_name(today), "ops_metric_sample_p20261014");
        assert_eq!(partition_day("ops_metric_sample_p20261014"), Some(today));
        assert_eq!(partition_day("ops_metric_sample_p2026101"), None);
    }
}
