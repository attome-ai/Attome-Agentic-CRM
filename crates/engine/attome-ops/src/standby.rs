//! AB2-T9: promoting the optional standby cluster in another region.
//!
//! A standby region is a second Patroni cluster bootstrapped with
//! `standby_cluster` (`deploy/ha/patroni-standby.yml.example`): it streams
//! from the main cluster and accepts no writes. Promoting it removes
//! `standby_cluster` from its dynamic configuration (`PATCH /config`), after
//! which its leader stops replicating and takes writes. It is the last step
//! of a regional disaster (`deploy/ha/README-standby.md`): never while the
//! main region is reachable, so `attome drill standby-promote` asks for the
//! cluster's name twice and checks it against the standby's own Patroni.

use serde_json::{Value, json};

use crate::error::OpsError;

/// How long one Patroni call may take.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The dynamic-configuration change that ends standby mode. Pure.
pub fn promote_body() -> Value {
    json!({ "standby_cluster": null })
}

/// The `--cluster` value, when `--cluster` and `--confirm` name the same
/// cluster. Pure.
pub fn confirmed_cluster(cluster: &str, confirm: &str) -> Result<String, String> {
    let cluster = cluster.trim();
    if cluster.is_empty() {
        return Err("--cluster names the standby cluster (its Patroni scope)".into());
    }
    if cluster != confirm.trim() {
        return Err("--confirm must repeat --cluster exactly; nothing was changed".into());
    }
    Ok(cluster.to_owned())
}

fn client(api_url: &str) -> Result<attome_outbound::http::Outbound, OpsError> {
    let purpose = attome_outbound::http::Purpose::public("patroni")
        .with_private_urls(std::iter::once(api_url))
        .no_redirects();
    attome_outbound::http::client(purpose, |b| b.timeout(TIMEOUT))
        .map_err(|e| OpsError::Internal(e.to_string()))
}

/// The standby's Patroni scope (its cluster name), from `GET /patroni`.
pub async fn patroni_scope(api_url: &str) -> Result<String, OpsError> {
    let target = format!("{}/patroni", api_url.trim_end_matches('/'));
    let answer = client(api_url)?
        .get(&target)
        .send()
        .await
        .map_err(|_| OpsError::Unavailable("patroni"))?;
    if !answer.status().is_success() {
        return Err(OpsError::Unavailable("patroni"));
    }
    let body: Value = answer
        .json()
        .await
        .map_err(|e| OpsError::Validation(format!("the Patroni answer does not read: {e}")))?;
    body.pointer("/patroni/scope")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| OpsError::Validation("the Patroni answer names no scope".into()))
}

/// Ends standby mode on the cluster at `api_url`.
pub async fn promote(api_url: &str) -> Result<(), OpsError> {
    let target = format!("{}/config", api_url.trim_end_matches('/'));
    let answer = client(api_url)?
        .patch(&target)
        .json(&promote_body())
        .send()
        .await
        .map_err(|_| OpsError::Unavailable("patroni"))?;
    if answer.status().is_success() {
        Ok(())
    } else {
        Err(OpsError::Validation(format!(
            "Patroni refused the change: HTTP {}",
            answer.status().as_u16()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promote_needs_the_name_twice() {
        assert_eq!(
            confirmed_cluster("attome-dr", "attome-dr").unwrap(),
            "attome-dr"
        );
        assert!(confirmed_cluster("attome-dr", "attome").is_err());
        assert!(confirmed_cluster(" ", " ").is_err());
        assert_eq!(promote_body(), json!({ "standby_cluster": null }));
    }
}
