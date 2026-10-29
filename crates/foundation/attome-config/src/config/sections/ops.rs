//! AB4-T1: the `ops` section, read by the `attome-ops` engine (cluster
//! status and switchover, recovery drills). Empty by default: a single
//! server needs none of it (V2-D100, reliability is opt-in).

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct OpsSection {
    /// The Patroni REST API of each database node (`http://db1:8008`), for
    /// cluster status and switchover. Empty: no Patroni cluster.
    pub patroni_api_urls: Vec<String>,
    /// The private key that signs recovery-drill reports.
    pub drill_signing_key_path: Option<String>,
    /// Public keys (base64) a drill report's signature is checked against.
    pub drill_public_keys: Vec<String>,
    /// AB3-T1: the deployment profile recovery targets are read for: `solo`,
    /// `team`, `ha` or `scale`.
    pub profile: String,
    /// AB3-T8: the people the disaster runbook says to call.
    pub dr_contacts: Vec<DrContact>,
    /// AB2-T9: this deployment's standby cluster in another region, promoted by `attome drill standby-promote`. Its region must be listed in `residency.allowed_regions`.
    pub standby_region: Option<StandbyRegion>,
}

/// AB2-T9: a standby cluster in another region, replicating the main one through Patroni's `standby_cluster`.
#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
pub struct StandbyRegion {
    /// The standby's Patroni REST API (`http://dr-db1:8008`), where promotion is asked.
    pub patroni_api_url: String,
    /// The region the standby runs in (`sa-jeddah`), as `residency.allowed_regions` names regions.
    pub region_code: String,
    /// The standby cluster's Patroni scope (its cluster name), typed twice to promote it.
    pub scope: String,
}

/// AB3-T8: one disaster contact.
#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
pub struct DrContact {
    /// Their name.
    pub name: String,
    /// What they do in a disaster (`On call`, `Database owner`).
    #[serde(default)]
    pub role: String,
    /// How to reach them.
    #[serde(default)]
    pub phone: String,
}

impl Default for OpsSection {
    fn default() -> Self {
        Self {
            patroni_api_urls: Vec::new(),
            drill_signing_key_path: None,
            drill_public_keys: Vec::new(),
            profile: "solo".to_owned(),
            dr_contacts: Vec::new(),
            standby_region: None,
        }
    }
}

/// Whether `url` is `http` or `https` with a host.
fn is_http_url(url: &str) -> bool {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .is_some_and(|r| !r.split(['/', ':']).next().unwrap_or_default().is_empty())
}

impl OpsSection {
    /// Every Patroni URL is `http` or `https` with a host.
    pub fn check(&self) -> Result<(), (String, String)> {
        for (i, url) in self.patroni_api_urls.iter().enumerate() {
            if !is_http_url(url) {
                return Err((
                    format!("ops.patroni_api_urls[{i}]"),
                    "an http or https URL with a host".into(),
                ));
            }
        }
        if let Some(standby) = &self.standby_region {
            if !is_http_url(&standby.patroni_api_url) {
                return Err((
                    "ops.standby_region.patroni_api_url".into(),
                    "an http or https URL with a host".into(),
                ));
            }
            for (field, value) in [
                ("region_code", &standby.region_code),
                ("scope", &standby.scope),
            ] {
                if value.trim().is_empty() {
                    return Err((
                        format!("ops.standby_region.{field}"),
                        "a non-empty value".into(),
                    ));
                }
            }
        }
        if self
            .drill_signing_key_path
            .as_deref()
            .is_some_and(|p| p.trim().is_empty())
        {
            return Err((
                "ops.drill_signing_key_path".into(),
                "a file path, or leave it out".into(),
            ));
        }
        if !["solo", "team", "ha", "scale"].contains(&self.profile.as_str()) {
            return Err((
                "ops.profile".into(),
                "one of solo, team, ha or scale".into(),
            ));
        }
        Ok(())
    }

    /// AB2-T9: why the standby region may not be used, if it may not: a
    /// standby is a full copy of the data, so its region must be one
    /// `residency.allowed_regions` (`allowed`) names, and with no list there
    /// is nothing that allows it.
    pub fn standby_region_error(&self, allowed: &[String]) -> Option<String> {
        let standby = self.standby_region.as_ref()?;
        let code = standby.region_code.trim();
        if allowed.iter().any(|a| a.trim().eq_ignore_ascii_case(code)) {
            None
        } else {
            Some(format!(
                "the standby region {code} is not in residency.allowed_regions; a standby holds \
                 every record, so list its region there first"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_urls_must_be_http() {
        assert!(OpsSection::default().check().is_ok());
        let ok = OpsSection {
            patroni_api_urls: vec!["http://db1:8008".into(), "https://db2/".into()],
            ..OpsSection::default()
        };
        assert!(ok.check().is_ok());
        for bad in ["db1:8008", "ftp://db1", "http://", "https://:8008"] {
            let section = OpsSection {
                patroni_api_urls: vec![bad.into()],
                ..OpsSection::default()
            };
            assert!(section.check().is_err(), "{bad}");
        }
        let empty_path = OpsSection {
            drill_signing_key_path: Some(" ".into()),
            ..OpsSection::default()
        };
        assert!(empty_path.check().is_err());
    }

    fn standby(region: &str) -> OpsSection {
        OpsSection {
            standby_region: Some(StandbyRegion {
                patroni_api_url: "http://dr-db1:8008".into(),
                region_code: region.into(),
                scope: "attome-dr".into(),
            }),
            ..OpsSection::default()
        }
    }

    #[test]
    fn standby_outside_allowed_regions_is_refused() {
        let section = standby("eu-west-1");
        assert!(section.check().is_ok());
        let allowed = vec!["sa-riyadh".to_owned(), "sa-jeddah".to_owned()];
        assert!(section.standby_region_error(&allowed).is_some());
        // No residency list allows nothing for a full copy of the data.
        assert!(section.standby_region_error(&[]).is_some());
    }

    #[test]
    fn standby_inside_allowed_regions_is_accepted() {
        let allowed = vec!["sa-riyadh".to_owned(), "SA-Jeddah".to_owned()];
        assert_eq!(standby("sa-jeddah").standby_region_error(&allowed), None);
        assert_eq!(OpsSection::default().standby_region_error(&[]), None);
        let mut blank = standby("sa-jeddah");
        if let Some(s) = blank.standby_region.as_mut() {
            s.scope = " ".into();
        }
        assert!(blank.check().is_err());
    }
}
