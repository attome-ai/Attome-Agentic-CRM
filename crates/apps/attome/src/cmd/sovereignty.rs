//! `attome sovereignty report [--json]` (roadmap U1-T6): where this
//! deployment keeps copies of its data and every outside destination its
//! configuration names, read from the configuration alone (no connection is
//! made), so an operator can answer "where does our data live and where can it
//! go" from one command.
//!
//! Each place is marked `inside` (this deployment's own network, as
//! `deployment.sovereign` understands it) or `outside`. Backups and their
//! copies join the list when U6's backup settings exist.

use attome_config::{AppConfig, CacheBackend, endpoint_is_in_deployment};
use serde_json::{Value, json};

/// One place data is kept or sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    /// `store` (a copy of data lives there) or `destination` (data is sent there).
    pub kind: &'static str,
    pub what: String,
    pub location: String,
    pub inside: bool,
}

fn inside(config: &AppConfig, target: &str) -> bool {
    let url = if target.contains("://") {
        target.to_owned()
    } else {
        format!("http://{target}")
    };
    let allowed = url::Url::parse(&url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|host| {
            config
                .deployment
                .sovereign_allowed_hosts
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&host))
        });
    allowed || endpoint_is_in_deployment(&url)
}

/// Every place, in a fixed order: stores first, then destinations.
pub fn places(config: &AppConfig) -> Vec<Place> {
    let mut out = Vec::new();
    let mut add = |kind: &'static str, what: &str, location: String| {
        let inside = !location.is_empty() && inside(config, &location);
        out.push(Place {
            kind,
            what: what.to_owned(),
            location,
            inside,
        });
    };
    add(
        "store",
        "database (records, metadata, audit)",
        format!(
            "postgres://{}:{}/{}",
            config.database.host, config.database.port, config.database.dbname
        ),
    );
    let s3 = if config.storage.s3_endpoint.trim().is_empty() {
        "https://s3.amazonaws.com".to_owned()
    } else {
        config.storage.s3_endpoint.clone()
    };
    add(
        "store",
        "files (object store)",
        format!("{s3} bucket {}", config.storage.s3_bucket),
    );
    if let Some(anchor) = &config.audit.anchor_store {
        let endpoint = if anchor.s3_endpoint.trim().is_empty() {
            "https://s3.amazonaws.com".to_owned()
        } else {
            anchor.s3_endpoint.clone()
        };
        add("store", "audit anchors", endpoint);
    }
    match config.cache.backend {
        CacheBackend::Memory => {
            out.push(Place {
                kind: "store",
                what: "cache and coordination (process memory)".to_owned(),
                location: "this process".to_owned(),
                inside: true,
            });
        }
        _ => {
            let location = format!("redis://{}:{}", config.cache.host, config.cache.port);
            let inside = inside(config, &location);
            out.push(Place {
                kind: "store",
                what: "cache and coordination (Redis)".to_owned(),
                location,
                inside,
            });
        }
    }
    for (what, url) in [
        (
            "model server (generation)",
            &config.inference.generation.base_url,
        ),
        (
            "model server (embeddings, holds the knowledge base's vectors' inputs)",
            &config.inference.embedding.base_url,
        ),
    ] {
        if !url.trim().is_empty() {
            let inside = inside(config, url);
            out.push(Place {
                kind: "destination",
                what: what.to_owned(),
                location: url.clone(),
                inside,
            });
        }
    }
    if config.email.enabled {
        let location = format!(
            "smtp://{}:{}",
            config.email.smtp_host, config.email.smtp_port
        );
        let inside = inside(config, &location);
        out.push(Place {
            kind: "destination",
            what: "outgoing mail (SMTP relay)".to_owned(),
            location,
            inside,
        });
    }
    if let Some(endpoint) = config
        .observability
        .otlp_endpoint
        .as_ref()
        .filter(|e| !e.trim().is_empty())
    {
        let inside = inside(config, endpoint);
        out.push(Place {
            kind: "destination",
            what: "traces (OpenTelemetry collector)".to_owned(),
            location: endpoint.clone(),
            inside,
        });
    }
    if !config.docgen.render_service_url.trim().is_empty() {
        let location = config.docgen.render_service_url.clone();
        let inside = inside(config, &location);
        out.push(Place {
            kind: "destination",
            what: "document rendering service".to_owned(),
            location,
            inside,
        });
    }
    let mut providers: Vec<_> = config.oidc.providers.iter().collect();
    providers.sort_by(|a, b| a.0.cmp(b.0));
    for (name, provider) in providers {
        let inside = inside(config, &provider.issuer);
        out.push(Place {
            kind: "destination",
            what: format!("sign-in provider `{name}`"),
            location: provider.issuer.clone(),
            inside,
        });
    }
    if !config.google_ai.api_key.trim().is_empty() {
        out.push(Place {
            kind: "destination",
            what: "Google AI".to_owned(),
            location: "https://generativelanguage.googleapis.com".to_owned(),
            inside: false,
        });
    }
    out
}

/// The report as JSON.
pub fn report_json(config: &AppConfig) -> Value {
    let places = places(config);
    json!({
        "format": "attome-sovereignty-report/v1",
        "sovereign": config.deployment.sovereign,
        "outside": places.iter().filter(|p| !p.inside).count(),
        "places": places.iter().map(|p| json!({
            "kind": p.kind,
            "what": p.what,
            "location": p.location,
            "inside": p.inside,
        })).collect::<Vec<_>>(),
    })
}

/// The report as text.
pub fn report_text(config: &AppConfig) -> String {
    let places = places(config);
    let mut out = format!(
        "Sovereign preset: {}\n\n",
        if config.deployment.sovereign {
            "on"
        } else {
            "off"
        }
    );
    for (kind, title) in [
        ("store", "Where copies of data live"),
        ("destination", "Where data is sent"),
    ] {
        out.push_str(title);
        out.push('\n');
        for place in places.iter().filter(|p| p.kind == kind) {
            out.push_str(&format!(
                "  [{}] {}: {}\n",
                if place.inside { "inside " } else { "OUTSIDE" },
                place.what,
                place.location
            ));
        }
        out.push('\n');
    }
    out
}

/// `attome sovereignty report [--json]`.
pub fn run(args: &[String]) -> Result<(), String> {
    let json = match args {
        [report] if report == "report" => false,
        [report, flag] if report == "report" && flag == "--json" => true,
        _ => return Err("usage: attome sovereignty report [--json]".to_owned()),
    };
    let config = AppConfig::from_file().map_err(|error| error.to_string())?;
    let text = if json {
        serde_json::to_string_pretty(&report_json(&config)).map_err(|error| error.to_string())?
    } else {
        report_text(&config)
    };
    use std::io::Write;
    let _ = writeln!(std::io::stdout().lock(), "{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> AppConfig {
        serde_json::from_str(include_str!("../../../../../config.example.json")).unwrap()
    }

    #[test]
    fn the_report_lists_the_database_first_and_marks_outside_places() {
        let mut config = example();
        config.google_ai.api_key = String::new();
        let before = places(&config);
        assert!(before[0].what.starts_with("database"));
        assert!(before.iter().any(|p| p.what.starts_with("files")));

        config.google_ai.api_key = "k".to_owned();
        let after = places(&config);
        assert!(after.iter().any(|p| p.what == "Google AI" && !p.inside));
        let json = report_json(&config);
        assert!(json["outside"].as_u64().unwrap() >= 1);
        assert!(report_text(&config).contains("OUTSIDE"));
    }

    #[test]
    fn an_allowed_host_counts_as_inside() {
        let mut config = example();
        config.email.enabled = true;
        config.email.smtp_host = "mail.example.gov".to_owned();
        let smtp = |config: &AppConfig| {
            places(config)
                .into_iter()
                .find(|p| p.what.starts_with("outgoing mail"))
                .unwrap()
                .inside
        };
        assert!(!smtp(&config));
        config.deployment.sovereign_allowed_hosts = vec!["mail.example.gov".to_owned()];
        assert!(smtp(&config));
    }
}
