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
        }
    }
}

impl OpsSection {
    /// Every Patroni URL is `http` or `https` with a host.
    pub fn check(&self) -> Result<(), (String, String)> {
        for (i, url) in self.patroni_api_urls.iter().enumerate() {
            let rest = url
                .strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"));
            if rest.is_none_or(|r| r.split(['/', ':']).next().unwrap_or_default().is_empty()) {
                return Err((
                    format!("ops.patroni_api_urls[{i}]"),
                    "an http or https URL with a host".into(),
                ));
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
}
