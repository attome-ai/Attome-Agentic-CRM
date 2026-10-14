//! `deployment` section — P-data-protection-governance §4's data-residency
//! declaration.

use serde::Deserialize;

/// Declares the region this deployment's data is contractually/
/// regulatorily supposed to stay in (e.g. `"bh-1"`, `"eu-west-1"`) — a
/// residency *claim*, not itself an enforcement mechanism. Paired with
/// `AppConfig::validate`'s boot-time check, which asserts this matches
/// `storage.s3_region`: the platform's per-customer dedicated data-plane
/// model (D-001/D-002) already places a customer's whole stack in-region, so
/// this doesn't enforce residency itself — it only catches the declared
/// region silently drifting out of sync with where the object store/backup
/// endpoint actually is. Also consumed by
/// `xrm_foundation::assert_transfer_allowed` (via `state.base.config`) as
/// the "deployment_region" side of the cross-border transfer-restriction
/// gate on every export path.
///
/// `None` (the default) means no residency claim is configured — both the
/// boot-time validator and the transfer gate are then a no-op, "ships dark"
/// like every other opt-in section added this session
/// (`retention`/`idempotency`/`approval`).
///
/// `bundle_ref`/`bundle_signing_public_key` (P-environment-promotion §5 step
/// 23 — the F273 `APP_VERTICAL` loader generalized) declare a signed
/// `attome-bundle/v1` artifact this deployment pulls and applies: `bundle_ref`
/// is a file path or `https://` URL to `{ "bundle": <canonical bundle JSON>,
/// "signature": "<base64 Ed25519 over the canonical bundle bytes>" }`, and
/// `bundle_signing_public_key` is the base64 Ed25519 public key that artifact
/// must verify against (same key-format/verify primitives
/// `xrm-license::verifier` uses, so an artifact `bundle-tool` signs verifies
/// with the identical machinery a license does). Both `None` (the default) is
/// "not configured" — `bundle::pull::fetch_and_verify` is then a no-op and
/// nothing changes about boot. Configuring one without the other is a boot
/// error (`AppConfig::validate`): a bundle without a key could never be
/// verified, and a key with nothing to verify configures nothing.
#[derive(Debug, Clone, Deserialize)]
pub struct DeploymentSection {
    #[serde(default)]
    pub data_region: Option<String>,
    #[serde(default)]
    pub bundle_ref: Option<String>,
    #[serde(default)]
    pub bundle_signing_public_key: Option<String>,
    /// D-585: the hosts the staff app and `/api/v1` answer on. Empty means
    /// "any host" (today's behaviour), and is refused once `portal_hosts` is
    /// set: a portal host must never also serve the staff API.
    #[serde(default)]
    pub staff_hosts: Vec<String>,
    /// D-585: the hosts web portals (`/{keyword}/...`) answer on, disjoint
    /// from `staff_hosts`. Empty means portals answer on any host outside
    /// the production profile, and on **no** host in it.
    #[serde(default)]
    pub portal_hosts: Vec<String>,
    /// U1-T5, the sovereign preset: when true, boot refuses any configured
    /// destination outside this deployment (object store, SMTP relay, model
    /// servers, identity providers, trace collector, render service) and any
    /// outside AI provider, so the deployment makes no outbound connection
    /// its operator did not name. See `AppConfig::sovereign_violations`.
    #[serde(default)]
    pub sovereign: bool,
    /// Host names a sovereign deployment may still reach although they are
    /// not on its own network: the organisation's own mail relay or identity
    /// provider, for example. Exact, lowercase host names.
    #[serde(default)]
    pub sovereign_allowed_hosts: Vec<String>,
}

impl DeploymentSection {
    /// D-585 item 1/3: host sets are bare lowercase host names, disjoint, a
    /// portal host set requires a staff host set, and no portal host is on
    /// the staff CORS allow-list. Returns the offending field and a reason.
    pub fn check_host_sets(&self, allowed_origins: &[String]) -> Result<(), (String, String)> {
        for (field, hosts) in [
            ("deployment.staff_hosts", &self.staff_hosts),
            ("deployment.portal_hosts", &self.portal_hosts),
        ] {
            for host in hosts {
                if !is_bare_host(host) {
                    return Err((
                        field.into(),
                        format!(
                            "{host:?} is not a bare lowercase host name (no scheme, port, path \
                             or wildcard)"
                        ),
                    ));
                }
            }
        }
        if !self.portal_hosts.is_empty() && self.staff_hosts.is_empty() {
            return Err((
                "deployment.staff_hosts".into(),
                "must be set when deployment.portal_hosts is: otherwise the staff API also \
                 answers on portal hosts (D-585)"
                    .into(),
            ));
        }
        if let Some(both) = self
            .portal_hosts
            .iter()
            .find(|h| self.staff_hosts.contains(h))
        {
            return Err((
                "deployment.portal_hosts".into(),
                format!("{both:?} is also a staff host; the two sets must be disjoint (D-585)"),
            ));
        }
        for origin in allowed_origins {
            if let Some(host) = origin_host(origin)
                && self.portal_hosts.contains(&host)
            {
                return Err((
                    "cors.allowed_origins".into(),
                    format!(
                        "{origin:?} is a portal host; a portal origin must never be on the \
                         staff CORS allow-list (D-585)"
                    ),
                ));
            }
        }
        Ok(())
    }
}

fn is_bare_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
        && !host.starts_with('.')
        && !host.ends_with('.')
}

/// The lowercase host of an `scheme://host[:port]` origin.
fn origin_host(origin: &str) -> Option<String> {
    let rest = origin.split_once("://")?.1;
    let host = rest.split(['/', ':']).next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

// Hand-written for the same reason as every other opt-in section in this
// file (see the doc comment above) — not a footgun a derive would actually
// hit here, but kept uniform.
#[allow(clippy::derivable_impls)]
impl Default for DeploymentSection {
    fn default() -> Self {
        Self {
            data_region: None,
            bundle_ref: None,
            bundle_signing_public_key: None,
            staff_hosts: Vec::new(),
            portal_hosts: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(staff: &[&str], portal: &[&str]) -> DeploymentSection {
        DeploymentSection {
            staff_hosts: staff.iter().map(|s| s.to_string()).collect(),
            portal_hosts: portal.iter().map(|s| s.to_string()).collect(),
            ..DeploymentSection::default()
        }
    }

    #[test]
    fn empty_host_sets_are_valid() {
        assert!(section(&[], &[]).check_host_sets(&[]).is_ok());
    }

    #[test]
    fn disjoint_sets_are_valid() {
        let origins = vec!["https://app.example.com".to_string()];
        assert!(
            section(&["app.example.com"], &["portal.example.com"])
                .check_host_sets(&origins)
                .is_ok()
        );
    }

    #[test]
    fn portal_hosts_without_staff_hosts_are_refused() {
        let err = section(&[], &["portal.example.com"]).check_host_sets(&[]);
        assert_eq!(err.unwrap_err().0, "deployment.staff_hosts");
    }

    #[test]
    fn overlapping_sets_are_refused() {
        let err = section(&["example.com"], &["example.com"]).check_host_sets(&[]);
        assert_eq!(err.unwrap_err().0, "deployment.portal_hosts");
    }

    #[test]
    fn a_portal_host_on_the_cors_list_is_refused() {
        let origins = vec!["https://portal.example.com:8443".to_string()];
        let err = section(&["app.example.com"], &["portal.example.com"]).check_host_sets(&origins);
        assert_eq!(err.unwrap_err().0, "cors.allowed_origins");
    }

    #[test]
    fn hosts_must_be_bare() {
        for bad in [
            "https://a.example",
            "a.example:443",
            "A.example",
            "*.example",
            "a/b",
            "",
        ] {
            assert!(
                section(&[bad], &[]).check_host_sets(&[]).is_err(),
                "{bad:?} should be refused"
            );
        }
    }
}
