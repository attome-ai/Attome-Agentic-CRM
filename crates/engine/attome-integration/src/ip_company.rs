//! E14-T10: the company a truncated IP address likely belongs to, from a
//! D24 provider the customer configured.
//!
//! The provider is the integration connection named [`CONNECTION`] (its
//! `base_url` and credential): a `GET {base_url}/{ip}` answering JSON with
//! the company as `company.name` and `company.domain` (IPinfo's shape) or
//! as top-level `name` and `domain`. A 404, or an answer without a name,
//! is no company. Without that connection there is no provider and nothing
//! leaves the deployment (V2-D470).
//!
//! Only the truncated address the tracking collector stores (the last IPv4
//! octet, the low 80 IPv6 bits zeroed) is ever sent.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::connection::Connection;

/// The integration connection that names the provider.
pub const CONNECTION: &str = "ip_company";

/// How long one provider call may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(2);

/// A company a network likely belongs to. Never a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LikelyCompany {
    pub name: String,
    /// The company's web domain, lower case, when the provider knows it.
    pub domain: Option<String>,
}

/// Answers the company behind a truncated address.
pub trait CompanyByIp: Send + Sync {
    /// The company `ip_prefix` likely belongs to; `None` when the provider
    /// knows none.
    fn lookup<'a>(
        &'a self,
        ip_prefix: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<LikelyCompany>, AppError>> + Send + 'a>>;
}

/// The company in a provider's answer. Pure.
pub fn parse_company(body: &Value) -> Option<LikelyCompany> {
    let holder = body
        .get("company")
        .filter(|c| c.is_object())
        .unwrap_or(body);
    let text = |key: &str| {
        holder
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    let name = text("name")?.chars().take(200).collect::<String>();
    let domain = text("domain").map(|d| {
        d.trim_start_matches("www.")
            .trim_end_matches('.')
            .to_ascii_lowercase()
    });
    Some(LikelyCompany { name, domain })
}

/// The provider behind the [`CONNECTION`] connection.
pub struct ConnectionProvider<'s> {
    state: &'s EngineState,
    connection: Connection,
}

impl std::fmt::Debug for ConnectionProvider<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionProvider")
            .field("connection", &self.connection.name)
            .finish_non_exhaustive()
    }
}

/// The configured provider; `None` when the customer configured none.
pub async fn configured(state: &EngineState) -> Result<Option<ConnectionProvider<'_>>, AppError> {
    match Connection::resolve(&state.base.db, CONNECTION).await {
        Ok(connection) => Ok(Some(ConnectionProvider { state, connection })),
        Err(AppError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

fn client() -> &'static attome_outbound::http::Outbound {
    // Q21-T1: the provider's public API only.
    static CLIENT: OnceLock<attome_outbound::http::Outbound> = OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(
            attome_outbound::http::Purpose::public("ip-company").no_redirects(),
            |b| b.timeout(CALL_TIMEOUT),
        )
    })
}

impl CompanyByIp for ConnectionProvider<'_> {
    fn lookup<'a>(
        &'a self,
        ip_prefix: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<LikelyCompany>, AppError>> + Send + 'a>> {
        Box::pin(async move {
            // Only an address goes into the path.
            let ip: IpAddr = ip_prefix
                .trim()
                .parse()
                .map_err(|_| AppError::Validation("ip_prefix: not an address".into()))?;
            let url = format!(
                "{}/{ip}",
                self.connection.base_url.trim().trim_end_matches('/')
            );
            let request = self
                .connection
                .apply_auth(
                    &self.state.base.db,
                    &crate::credential::ring(self.state),
                    client().get(url),
                    b"",
                )
                .await?;
            let res = request.send().await.map_err(AppError::internal)?;
            if res.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !res.status().is_success() {
                return Err(AppError::internal(format!(
                    "ip company provider answered {}",
                    res.status().as_u16()
                )));
            }
            let body: Value = res.json().await.map_err(AppError::internal)?;
            Ok(parse_company(&body))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_company_is_read_from_either_shape() {
        let nested = json!({"ip": "203.0.113.0", "company": {"name": "Acme Trading", "domain": "WWW.Acme.sa"}});
        assert_eq!(
            parse_company(&nested),
            Some(LikelyCompany {
                name: "Acme Trading".into(),
                domain: Some("acme.sa".into())
            })
        );
        let flat = json!({"name": "Acme Trading"});
        assert_eq!(parse_company(&flat).map(|c| c.domain), Some(None));
        assert_eq!(parse_company(&json!({"company": {"name": " "}})), None);
        assert_eq!(parse_company(&json!({"ip": "203.0.113.0"})), None);
    }
}
