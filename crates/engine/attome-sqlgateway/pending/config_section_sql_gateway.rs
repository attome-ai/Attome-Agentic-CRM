//! Y3-T1 — the SQL gateway (`attome-sqlgateway`): the PostgreSQL wire
//! protocol for BI tools, signed in with an API key and answered through the
//! secured SQL runner.
//!
//! `enabled` defaults `false`. Enabled, `AppConfig::validate` requires a
//! `bind` that parses as `ip:port` on a **loopback** address and
//! `max_connections` from 1 to 200: the gateway has no TLS of its own yet and
//! the API key travels as the password, so it is reached only through a
//! TLS-terminating proxy on the same host, never directly.
use std::net::SocketAddr;

use serde::Deserialize;

/// Where the gateway listens when nothing is configured.
pub const DEFAULT_BIND: &str = "127.0.0.1:5433";
/// The most sessions at once when nothing is configured.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 8;
/// The most sessions `max_connections` may allow.
pub const MAX_CONNECTIONS_CEILING: u32 = 200;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct SqlGatewaySection {
    pub enabled: bool,
    pub bind: String,
    pub max_connections: u32,
}

impl Default for SqlGatewaySection {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: DEFAULT_BIND.to_owned(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

impl SqlGatewaySection {
    /// The address to bind, when it parses.
    pub fn bind_addr(&self) -> Option<SocketAddr> {
        self.bind.trim().parse().ok()
    }

    /// The boot rule. Returns the offending field and why.
    pub(crate) fn check(&self) -> Result<(), (&'static str, &'static str)> {
        if !self.enabled {
            return Ok(());
        }
        let Some(addr) = self.bind_addr() else {
            return Err((
                "sql_gateway.bind",
                "the SQL gateway is enabled but bind is not an ip:port address",
            ));
        };
        if !addr.ip().is_loopback() {
            return Err((
                "sql_gateway.bind",
                "the SQL gateway has no TLS of its own; bind it to a loopback address and put \
                 a TLS-terminating proxy in front",
            ));
        }
        if self.max_connections == 0 || self.max_connections > MAX_CONNECTIONS_CEILING {
            return Err((
                "sql_gateway.max_connections",
                "the SQL gateway's max_connections must be between 1 and 200",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(enabled: bool, bind: &str, max: u32) -> SqlGatewaySection {
        SqlGatewaySection {
            enabled,
            bind: bind.to_owned(),
            max_connections: max,
        }
    }

    #[test]
    fn off_by_default_and_unchecked_when_off() {
        let default = SqlGatewaySection::default();
        assert!(!default.enabled);
        assert!(default.check().is_ok());
        assert!(section(false, "not an address", 0).check().is_ok());
    }

    #[test]
    fn enabled_needs_a_loopback_bind_and_a_bounded_pool() {
        assert!(section(true, "127.0.0.1:5433", 8).check().is_ok());
        assert!(section(true, "[::1]:5433", 8).check().is_ok());
        assert_eq!(section(true, "0.0.0.0:5433", 8).check().unwrap_err().0, "sql_gateway.bind");
        assert_eq!(section(true, "5433", 8).check().unwrap_err().0, "sql_gateway.bind");
        assert_eq!(
            section(true, "127.0.0.1:5433", 0).check().unwrap_err().0,
            "sql_gateway.max_connections"
        );
        assert_eq!(
            section(true, "127.0.0.1:5433", 201).check().unwrap_err().0,
            "sql_gateway.max_connections"
        );
    }
}
