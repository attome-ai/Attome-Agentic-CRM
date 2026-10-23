//! R7-T1: the data residency map.
//!
//! `residency.allowed_regions` names where this deployment's data may live
//! (`["sa-riyadh", "sa-jeddah"]`); empty means no residency rule. Each
//! component that holds data has a region: the one configured in
//! `residency.components` (`{"backup": "sa-riyadh", "ai": "eu-west-1"}`),
//! else the one its own configuration declares (an S3 bucket's
//! `s3_region`), else the deployment's `deployment.data_region` for what
//! runs with the deployment itself (the database, the cache, a local backup
//! folder, local file storage).
//!
//! Boot refuses a configuration placing any component outside the allowed
//! regions, or leaving one whose region is unknown (`AppConfig::validate`,
//! as an insecure value): a backup target in another region stops boot.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The components that hold data, in report order.
pub const COMPONENTS: &[&str] = &[
    "database",
    "cache",
    "storage",
    "backup",
    "audit_anchor",
    "ai",
    "email",
    "traces",
];

/// `residency`.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct ResidencySection {
    /// The regions data may live in; empty for no rule.
    #[serde(default)]
    pub allowed_regions: Vec<String>,
    /// A component's region, overriding what its configuration declares.
    #[serde(default)]
    pub components: BTreeMap<String, String>,
}

/// Where a component's region came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `residency.components`.
    Configured,
    /// The component's own configuration (an S3 region).
    Provider,
    /// `deployment.data_region`: it runs with the deployment.
    Deployment,
}

/// One component's place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    pub component: String,
    pub region: Option<String>,
    pub source: Option<Source>,
}

/// What the configuration says about each component in use.
#[derive(Debug, Clone, Default)]
pub struct Facts<'a> {
    pub data_region: Option<&'a str>,
    /// The file store is a bucket outside this machine (else a local
    /// folder), with its declared region (`""` when it declares none).
    pub storage_remote: bool,
    pub storage_region: &'a str,
    pub backup_enabled: bool,
    /// The audit anchor bucket, when one is configured.
    pub anchor_s3_region: Option<&'a str>,
}

/// The residency map: every component in use with its region.
pub fn map(section: &ResidencySection, facts: &Facts<'_>) -> Vec<Placement> {
    let deployment = facts
        .data_region
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(str::to_owned);
    let declared = |r: &str| Some(r.trim()).filter(|r| !r.is_empty()).map(str::to_owned);
    COMPONENTS
        .iter()
        .filter_map(|component| {
            let configured = section
                .components
                .get(*component)
                .map(String::as_str)
                .and_then(declared);
            let (in_use, provider, runs_here) = match *component {
                "database" | "cache" => (true, None, true),
                "storage" if facts.storage_remote => (true, declared(facts.storage_region), false),
                "storage" => (true, None, true),
                "backup" => (facts.backup_enabled, None, true),
                "audit_anchor" => (
                    facts.anchor_s3_region.is_some(),
                    facts.anchor_s3_region.and_then(declared),
                    false,
                ),
                // Only what the operator names: a model provider, a mail relay
                // or a trace collector outside the deployment.
                _ => (configured.is_some(), None, false),
            };
            if !in_use {
                return None;
            }
            let (region, source) = if let Some(r) = configured {
                (Some(r), Some(Source::Configured))
            } else if let Some(r) = provider {
                (Some(r), Some(Source::Provider))
            } else if runs_here && deployment.is_some() {
                (deployment.clone(), Some(Source::Deployment))
            } else {
                (None, None)
            };
            Some(Placement {
                component: (*component).to_owned(),
                region,
                source,
            })
        })
        .collect()
}

/// Every placement outside the allowed regions, or of unknown region.
pub fn violations(section: &ResidencySection, placements: &[Placement]) -> Vec<String> {
    if section.allowed_regions.is_empty() {
        return Vec::new();
    }
    let allowed = |r: &str| {
        section
            .allowed_regions
            .iter()
            .any(|a| a.trim().eq_ignore_ascii_case(r))
    };
    let mut out = Vec::new();
    for p in placements {
        match &p.region {
            Some(r) if allowed(r) => {}
            Some(r) => out.push(format!(
                "{} is in {r}, outside the allowed regions ({})",
                p.component,
                section.allowed_regions.join(", ")
            )),
            None => out.push(format!(
                "{} has no declared region: set residency.components.{} or deployment.data_region",
                p.component, p.component
            )),
        }
    }
    for name in section.components.keys() {
        if !COMPONENTS.contains(&name.as_str()) {
            out.push(format!(
                "residency.components.{name} is not a component ({})",
                COMPONENTS.join(", ")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(allowed: &[&str], components: &[(&str, &str)]) -> ResidencySection {
        ResidencySection {
            allowed_regions: allowed.iter().map(|s| (*s).to_owned()).collect(),
            components: components
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    fn facts() -> Facts<'static> {
        Facts {
            data_region: Some("sa-riyadh"),
            storage_remote: true,
            storage_region: "me-central-1",
            backup_enabled: true,
            anchor_s3_region: None,
        }
    }

    #[test]
    fn residency_map_takes_configured_then_provider_then_deployment() {
        let s = section(&[], &[("ai", "eu-west-1")]);
        let placed = map(&s, &facts());
        let find = |c: &str| placed.iter().find(|p| p.component == c).cloned().unwrap();
        assert_eq!(find("database").region.as_deref(), Some("sa-riyadh"));
        assert_eq!(find("database").source, Some(Source::Deployment));
        assert_eq!(find("storage").region.as_deref(), Some("me-central-1"));
        assert_eq!(find("storage").source, Some(Source::Provider));
        assert_eq!(find("ai").source, Some(Source::Configured));
        assert!(
            !placed.iter().any(|p| p.component == "email"),
            "unnamed outside services are not in use"
        );
        assert!(
            violations(&s, &placed).is_empty(),
            "no allowed regions, no rule"
        );
    }

    #[test]
    fn residency_backup_outside_the_allowed_region_stops_boot() {
        let s = section(
            &["sa-riyadh", "me-central-1"],
            &[("backup", "eu-central-1")],
        );
        let problems = violations(&s, &map(&s, &facts()));
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].starts_with("backup is in eu-central-1"));

        let ok = section(&["SA-RIYADH", "me-central-1"], &[]);
        assert!(
            violations(&ok, &map(&ok, &facts())).is_empty(),
            "regions compare without case"
        );
    }

    #[test]
    fn residency_unknown_regions_and_components_are_refused() {
        let s = section(&["sa-riyadh"], &[("warehouse", "sa-riyadh")]);
        let mut f = facts();
        f.data_region = None;
        f.storage_remote = false;
        let problems = violations(&s, &map(&s, &f));
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with("database has no declared region"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("warehouse is not a component"))
        );
    }
}
