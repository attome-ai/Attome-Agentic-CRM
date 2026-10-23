//! AB10-T3: one runbook per alert, filled with this deployment's values.
//!
//! `observability/runbooks/<Alert>.md` holds what an alert means, what to
//! check, how to fix it and whom to escalate to, for every rule in
//! `observability/alerts.yml` and `observability/builtin-alerts.json`. The
//! files are compiled in, so a node renders them with no repository at hand.
//! `{{name}}` placeholders ([`PLACEHOLDERS`]) are filled from the
//! configuration: addresses, never a secret (no password, key or token
//! reaches a runbook). The built-in alert emails (AB10-T2) carry the filled
//! runbook, and `attome runbook <Alert>` prints it.

use attome_config::AppConfig;

macro_rules! runbooks {
    ($($name:literal),* $(,)?) => {
        /// Every alert's runbook template, by alert name, sorted.
        pub const RUNBOOKS: &[(&str, &str)] = &[
            $(($name, include_str!(concat!("../../../../observability/runbooks/", $name, ".md"))),)*
        ];
    };
}

runbooks!(
    "ApalisBacklogGrowing",
    "ApalisBatchBacklogGrowing",
    "ApalisDeadLetterGrowing",
    "ApalisOldestPendingAgeHigh",
    "ApalisWorkerNeverSeen",
    "ApalisWorkerStale",
    "AuditChainerLag",
    "AuditChainerLagHigh",
    "BackupTooOld",
    "CapabilityRejectingTraffic",
    "CapabilityUnavailable",
    "ChangeFeedConsumerLagging",
    "ChangesPaused",
    "DbPoolAcquireTimeouts",
    "DbPoolNearExhaustion",
    "DeadLetterGroupGrowing",
    "DeadLetterGroupNew",
    "DeadLetterOldItem",
    "DiskSpaceCritical",
    "DiskSpaceLow",
    "EmailRelayFailureRatioHigh",
    "EmailSendOutcomeUnknown",
    "EmailSendSlow",
    "EmailSuppressionSpike",
    "EventDeliveryBacklogGrowing",
    "EventDeliveryDeadLettered",
    "FileIntegrityFailures",
    "HighHttpErrorRate",
    "HttpRejectionsSpike",
    "IdempotencyKeysStuckPending",
    "JobBacklogOld",
    "JobScheduleStale",
    "JobsInDeadLetter",
    "MetadataSwitchSlow",
    "NodeStoppedReporting",
    "ObjectStorageDown",
    "ObjectStorageProbeLatencyHigh",
    "PartitionBloatMetricMissing",
    "PartitionedTableDeadTupleRatioHigh",
    "PlatformJobFailures",
    "PortalCacheInvalidationFailed",
    "PortalGrantDrift",
    "PortalLoginFailureRatioHigh",
    "RedisCoordinationDown",
    "RedisCoordinationLatencyHigh",
    "RedisCoordinationMemoryHigh",
    "RedisCoordinationNoMemoryCeiling",
    "RedisDown",
    "RedisPersistenceDisabled",
    "RedisSnapshotStale",
    "ReplicaLagCritical",
    "ReplicaLagHigh",
    "S2sAccessLogBacklogGrowing",
    "SecurityAnomalyRateHigh",
    "SloErrorBurnFast",
    "SloErrorBurnSlow",
    "SloGaugeOverObjective",
    "SloLatencyBucketMissing",
    "SloLatencyBurnFast",
    "SloLatencyBurnSlow",
    "StoragePresignFailures",
    "UploadScanBacklogStale",
    "WalArchiveLagHigh",
    "WorkflowTriggerDeadLettered",
);

/// The placeholders a runbook may use, as `{{name}}`.
pub const PLACEHOLDERS: [&str; 8] = [
    "node",
    "app_url",
    "api_base",
    "metrics_url",
    "database",
    "cache",
    "storage",
    "alert_emails",
];

/// The values a runbook is filled with: one per [`PLACEHOLDERS`] entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunbookValues {
    /// The node that reports the alert (`host:port`).
    pub node: String,
    /// Where people open the application.
    pub app_url: String,
    /// The server's own address, for API calls from an operator's shell.
    pub api_base: String,
    /// The Prometheus scrape address, or a note that it is off.
    pub metrics_url: String,
    /// `host:port/dbname` of the primary database.
    pub database: String,
    /// The cache backend and, for Redis, its address.
    pub cache: String,
    /// The file store's endpoint and bucket.
    pub storage: String,
    /// Who hears about built-in alerts, or a note that nobody does.
    pub alert_emails: String,
}

impl RunbookValues {
    /// The values of this node's configuration. `node` is the reporting
    /// node's name (`metrics_store::node_name`).
    pub fn from_config(config: &AppConfig, node: &str) -> Self {
        let api_base = format!("http://{}:{}", config.app.server_host, config.app.port);
        let app_url = config
            .app
            .public_frontend_url
            .clone()
            .filter(|u| !u.trim().is_empty())
            .unwrap_or_else(|| api_base.clone());
        let metrics_url = if config.observability.metrics_port == 0 {
            "(metrics port off: observability.metrics_port is 0)".to_owned()
        } else {
            format!(
                "http://{}:{}/metrics",
                config.app.server_host, config.observability.metrics_port
            )
        };
        let db = &config.database;
        let cache = match config.cache.backend {
            attome_config::CacheBackend::Memory => "in-process memory (Solo)".to_owned(),
            attome_config::CacheBackend::Redis => {
                format!("Redis at {}:{}", config.cache.host, config.cache.port)
            }
        };
        let emails: Vec<&str> = config
            .observability
            .alert_emails
            .iter()
            .map(String::as_str)
            .filter(|e| e.contains('@'))
            .collect();
        Self {
            node: node.to_owned(),
            app_url,
            api_base,
            metrics_url,
            database: format!("{}:{}/{}", db.host, db.port, db.dbname),
            cache,
            storage: format!(
                "{} (bucket {})",
                config.storage.s3_endpoint, config.storage.s3_bucket
            ),
            alert_emails: if emails.is_empty() {
                "nobody yet (set observability.alert_emails)".to_owned()
            } else {
                emails.join(", ")
            },
        }
    }

    fn get(&self, name: &str) -> Option<&str> {
        Some(match name {
            "node" => &self.node,
            "app_url" => &self.app_url,
            "api_base" => &self.api_base,
            "metrics_url" => &self.metrics_url,
            "database" => &self.database,
            "cache" => &self.cache,
            "storage" => &self.storage,
            "alert_emails" => &self.alert_emails,
            _ => return None,
        })
    }
}

/// The runbook template of `alert`, unfilled.
pub fn template(alert: &str) -> Option<&'static str> {
    RUNBOOKS
        .binary_search_by(|(name, _)| (*name).cmp(alert))
        .ok()
        .map(|i| RUNBOOKS[i].1)
}

/// Fills every known `{{name}}` in `template`; an unknown one stays as it is.
pub fn fill(template: &str, values: &RunbookValues) -> String {
    let mut out = String::with_capacity(template.len() + 256);
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => match values.get(&after[..end]) {
                Some(value) => {
                    out.push_str(value);
                    rest = &after[end + 2..];
                }
                None => {
                    out.push_str("{{");
                    rest = after;
                }
            },
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// The filled runbook of `alert`, or `None` when it has none.
pub fn render(alert: &str, values: &RunbookValues) -> Option<String> {
    template(alert).map(|t| fill(t, values))
}

/// Every `{{name}}` a template uses.
pub fn placeholders_in(template: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        out.push(&after[..end]);
        rest = &after[end + 2..];
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "test: a failed read should panic with its message"
)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("the workspace root")
            .to_path_buf()
    }

    fn values() -> RunbookValues {
        RunbookValues {
            node: "app-1:7865".to_owned(),
            app_url: "https://crm.example.com".to_owned(),
            api_base: "http://10.0.0.5:7865".to_owned(),
            metrics_url: "http://10.0.0.5:9464/metrics".to_owned(),
            database: "db.internal:5432/attome".to_owned(),
            cache: "Redis at cache.internal:6379".to_owned(),
            storage: "http://files.internal:9000 (bucket attome)".to_owned(),
            alert_emails: "ops@example.com".to_owned(),
        }
    }

    /// Every alert the repository defines, Prometheus and built-in.
    fn alert_names() -> BTreeSet<String> {
        let root = root();
        let yml = std::fs::read_to_string(root.join("observability/alerts.yml"))
            .expect("observability/alerts.yml");
        let mut names: BTreeSet<String> = yml
            .lines()
            .filter_map(|l| l.trim().strip_prefix("- alert:"))
            .map(|n| n.trim().to_owned())
            .collect();
        let builtin: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("observability/builtin-alerts.json"))
                .expect("observability/builtin-alerts.json"),
        )
        .expect("builtin-alerts.json is JSON");
        for rule in builtin["rules"].as_array().expect("rules") {
            names.insert(rule["name"].as_str().expect("name").to_owned());
        }
        names
    }

    #[test]
    fn every_alert_has_a_runbook_and_every_runbook_an_alert() {
        let alerts = alert_names();
        let compiled: BTreeSet<String> = RUNBOOKS.iter().map(|(n, _)| (*n).to_owned()).collect();
        let on_disk: BTreeSet<String> = std::fs::read_dir(root().join("observability/runbooks"))
            .expect("observability/runbooks")
            .flatten()
            .filter_map(|e| {
                e.file_name()
                    .to_str()?
                    .strip_suffix(".md")
                    .map(str::to_owned)
            })
            .collect();
        assert_eq!(
            alerts, compiled,
            "add the runbook file and its name to RUNBOOKS"
        );
        assert_eq!(
            on_disk, compiled,
            "every file in observability/runbooks is compiled in"
        );
    }

    #[test]
    fn runbooks_are_sorted_for_lookup() {
        assert!(RUNBOOKS.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(template("BackupTooOld").is_some());
        assert!(template("NoSuchAlert").is_none());
    }

    #[test]
    fn every_runbook_has_the_four_sections_and_known_placeholders() {
        for (name, text) in RUNBOOKS {
            assert!(text.starts_with(&format!("# {name}\n")), "{name}: title");
            for section in ["## Meaning", "## Checks", "## Fix", "## Escalation"] {
                assert!(text.contains(section), "{name}: {section}");
            }
            for p in placeholders_in(text) {
                assert!(PLACEHOLDERS.contains(&p), "{name}: unknown placeholder {p}");
            }
            let filled = fill(text, &values());
            assert!(!filled.contains("{{"), "{name}: left unfilled");
        }
    }

    #[test]
    fn fill_replaces_known_and_keeps_unknown() {
        let v = values();
        assert_eq!(fill("on {{node}}", &v), "on app-1:7865");
        assert_eq!(fill("{{nope}} {{node}}", &v), "{{nope}} app-1:7865");
        assert_eq!(fill("open {{node", &v), "open {{node");
        assert!(
            render("BackupTooOld", &v)
                .expect("a runbook")
                .contains("db.internal:5432/attome")
        );
    }

    #[test]
    fn alert_links_point_at_their_runbook_file() {
        let root = root();
        let yml = std::fs::read_to_string(root.join("observability/alerts.yml"))
            .expect("observability/alerts.yml");
        let mut current = String::new();
        for line in yml.lines() {
            let line = line.trim();
            if let Some(n) = line.strip_prefix("- alert:") {
                current = n.trim().to_owned();
            } else if let Some(url) = line.strip_prefix("runbook_url:") {
                let url = url.trim().trim_matches('"');
                assert_eq!(
                    url,
                    format!("observability/runbooks/{current}.md"),
                    "{current}"
                );
            }
        }
        let builtin: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("observability/builtin-alerts.json"))
                .expect("builtin-alerts.json"),
        )
        .expect("JSON");
        for rule in builtin["rules"].as_array().expect("rules") {
            let name = rule["name"].as_str().expect("name");
            assert_eq!(
                rule["runbook"].as_str(),
                Some(format!("observability/runbooks/{name}.md").as_str()),
                "{name}"
            );
        }
    }
}
