//! A24: a migration source from a named integration system (Z1-T10). The
//! system's `base_url` is the source's address, its credential (or, for an
//! OAuth system, its current access token) the source's token, and its
//! `config.migration` says which source it is:
//!
//! ```json
//! { "migration": { "kind": "salesforce", "objects": ["Account", "Contact"] } }
//! ```
//!
//! `kind` is `salesforce`, `dynamics`, `hubspot`, `zoho` or `odoo`;
//! `objects` limits the entities read (empty: the connector's own
//! default); an Odoo source also names its `database` and `username` (the
//! credential is the user's API key). Calls go through the SSRF-guarded
//! client.

use attome_core::EngineState;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::Value;

use super::dynamics::DynamicsSource;
use super::hubspot::HubSpotSource;
use super::migration_source::{SourceConnector, SourceModel};
use super::odoo::OdooClient;
use super::odoo_source::OdooSource;
use super::salesforce::SalesforceSource;
use super::zoho::ZohoSource;
use crate::connection::Connection;
use crate::connector::sdk::{GuardedTransport, Secret, Transport};

/// Seconds one source call may take.
pub const SOURCE_TIMEOUT_SECS: u64 = 60;

/// The sources a migration reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Salesforce,
    Dynamics,
    Hubspot,
    Zoho,
    Odoo,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Salesforce => "salesforce",
            SourceKind::Dynamics => "dynamics",
            SourceKind::Hubspot => "hubspot",
            SourceKind::Zoho => "zoho",
            SourceKind::Odoo => "odoo",
        }
    }
}

/// `config.migration` of a source system.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct SourceSettings {
    pub kind: SourceKind,
    #[serde(default)]
    pub objects: Vec<String>,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

/// The migration settings in a system's raw `config`. Pure.
pub fn settings_of(config: Option<&str>) -> Result<SourceSettings, AppError> {
    let config: Value = config
        .and_then(|c| serde_json::from_str(c).ok())
        .unwrap_or(Value::Null);
    let migration = config.get("migration").cloned().ok_or_else(|| {
        AppError::Validation("the system's config has no `migration` part naming its kind".into())
    })?;
    let settings: SourceSettings = serde_json::from_value(migration)
        .map_err(|e| AppError::Validation(format!("the system's `migration` config: {e}")))?;
    if settings.kind == SourceKind::Odoo
        && (settings.database.is_none() || settings.username.is_none())
    {
        return Err(AppError::Validation(
            "an Odoo source names its `database` and `username`".into(),
        ));
    }
    Ok(settings)
}

/// The connector for `settings`, at `base_url` with `token`. Pure.
pub fn source<'a>(
    settings: &SourceSettings,
    base_url: &str,
    token: Secret,
    transport: &'a dyn Transport,
) -> Box<dyn SourceConnector + 'a> {
    let objects = settings.objects.clone();
    match settings.kind {
        SourceKind::Salesforce => {
            let mut s = SalesforceSource::new(base_url, token, None, transport);
            s.objects = objects;
            Box::new(s)
        }
        SourceKind::Dynamics => {
            let mut s = DynamicsSource::new(base_url, token, None, transport);
            s.tables = objects;
            Box::new(s)
        }
        SourceKind::Hubspot => {
            let mut s = HubSpotSource::new(base_url, token, transport);
            s.objects = objects;
            Box::new(s)
        }
        SourceKind::Zoho => {
            let mut s = ZohoSource::new(base_url, token, None, transport);
            s.modules = objects;
            Box::new(s)
        }
        SourceKind::Odoo => {
            let client = OdooClient::new(
                base_url,
                settings.database.as_deref().unwrap_or_default(),
                settings.username.as_deref().unwrap_or_default(),
                token,
                transport,
            );
            let mut s = OdooSource::new(client);
            s.models = objects;
            Box::new(s)
        }
    }
}

/// The token a connection's requests carry: an OAuth system's current
/// access token (renewed when about to expire), else its credential.
async fn token_of(state: &EngineState, connection: &Connection) -> Result<Secret, AppError> {
    let db = &state.base.db;
    let ring = crate::credential::ring(state);
    let credential = connection.credential(db, &ring).await?;
    let credential = connection.needs(credential.as_ref())?;
    if crate::oauth::OAUTH_AUTH_TYPES.contains(&connection.auth_type.as_str()) {
        let endpoint = crate::oauth::GuardedEndpoint::new()?;
        let token = crate::oauth::access_token(
            db,
            &ring,
            connection,
            connection.config(),
            credential,
            &endpoint,
        )
        .await?;
        return Ok(token.with_value(|v| Secret::new(v.to_owned())));
    }
    Ok(credential.with_value(|v| Secret::new(v.to_owned())))
}

/// The model of the source the integration system `system` names.
pub async fn describe_named(
    state: &EngineState,
    system: &str,
) -> Result<(SourceKind, SourceModel), AppError> {
    let connection = Connection::resolve(&state.base.db, system).await?;
    let settings = settings_of(connection.config())?;
    let token = token_of(state, &connection).await?;
    let client = attome_server::ssrf_guard::GuardedClient::new(SOURCE_TIMEOUT_SECS)
        .map_err(AppError::internal)?;
    let transport = GuardedTransport(client);
    let mut connector = source(&settings, &connection.base_url, token, &transport);
    let model = connector.describe_model().await?;
    Ok((settings.kind, model))
}

#[cfg(test)]
mod tests {
    use super::super::migration_source::fixture::Recorded;
    use super::*;

    #[test]
    fn sources_settings_name_the_kind() {
        let s = settings_of(Some(
            r#"{"migration": {"kind": "hubspot", "objects": ["contacts"]}}"#,
        ))
        .unwrap();
        assert_eq!(
            (s.kind, s.objects.as_slice()),
            (SourceKind::Hubspot, ["contacts".to_owned()].as_slice())
        );
        assert!(settings_of(Some(r#"{"migration": {"kind": "sugar"}}"#)).is_err());
        assert!(settings_of(Some(r#"{"migration": {"kind": "odoo"}}"#)).is_err());
        assert!(settings_of(None).is_err());
    }

    #[tokio::test]
    async fn sources_a_configured_source_describes_its_objects() {
        let recorded = Recorded::new(vec![(
            "GET",
            "https://api.hubapi.com/crm/v3/properties/deals",
            200,
            r#"{"results": [{"name": "dealname", "label": "Deal Name", "type": "string", "fieldType": "text"}]}"#,
            vec![],
        )]);
        let settings = settings_of(Some(
            r#"{"migration": {"kind": "hubspot", "objects": ["deals"]}}"#,
        ))
        .unwrap();
        let mut connector = source(
            &settings,
            "https://api.hubapi.com",
            Secret::new("t"),
            &recorded,
        );
        let model = connector.describe_model().await.unwrap();
        assert_eq!(model.entities[0].name, "deals");
        assert_eq!(model.entities[0].fields[0].name, "dealname");
    }
}
