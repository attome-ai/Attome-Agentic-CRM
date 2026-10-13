//! What the console holds while its gate is open: the outbound HTTP client,
//! the fleet key ring and the changeset directory. Built only by the gated
//! boot path ([`crate::mount`]) and by the gated jobs, so with the gate off
//! no fleet key is ever used (design §2.2).

use std::path::PathBuf;
use std::sync::Arc;

use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;

use crate::client::{CustomerClient, S2sCredential};
use crate::store::{self, DeploymentRow};

pub struct FleetRuntime {
    pub http: reqwest::Client,
    ring: KeyRing,
    pub changesets_dir: PathBuf,
}

impl std::fmt::Debug for FleetRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetRuntime")
            .field("ring", &self.ring)
            .field("changesets_dir", &self.changesets_dir)
            .finish_non_exhaustive()
    }
}

impl FleetRuntime {
    pub fn from_config(config: &AppConfig) -> Result<Self, AppError> {
        Ok(Self {
            http: crate::client::build_http(config.fleet.request_timeout_secs)?,
            ring: config.fleet.credential_encryption_key.clone(),
            changesets_dir: PathBuf::from(&config.fleet.changesets_dir),
        })
    }

    pub fn ring(&self) -> &KeyRing {
        &self.ring
    }

    /// A client for one deployment, with its rollout credential decrypted
    /// for this use only (none stored: the anonymous probes still work).
    pub async fn customer(
        &self,
        db: &DbPool,
        deployment: &DeploymentRow,
    ) -> Result<CustomerClient, AppError> {
        let credential = match store::load_credential(db, deployment.id).await? {
            Some((client_id, key_id, sealed)) => Some(S2sCredential {
                client_id,
                key_id,
                secret: crate::crypto::unseal(&self.ring, deployment.id, &sealed)?,
            }),
            None => None,
        };
        Ok(CustomerClient::new(
            self.http.clone(),
            deployment.base_url.clone(),
            credential,
        ))
    }
}

/// The fleet router's state: the platform's `EngineState` plus the runtime.
#[derive(Clone)]
pub struct FleetState {
    pub xrm: EngineState,
    pub runtime: Arc<FleetRuntime>,
}

impl std::fmt::Debug for FleetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetState").finish_non_exhaustive()
    }
}

impl FleetState {
    pub fn new(xrm: EngineState) -> Result<Self, AppError> {
        let runtime = FleetRuntime::from_config(&xrm.base.config)?;
        Ok(Self {
            xrm,
            runtime: Arc::new(runtime),
        })
    }
}
