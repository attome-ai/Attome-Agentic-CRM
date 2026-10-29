//! Q1-T3: every OpenID Connect provider a person can sign in with, from one
//! place. Two sources merge: the providers in configuration (`oidc.providers`,
//! read-only, D-065) and the ones an administrator adds on screen (the
//! `oidc_provider` table, Q1-T2), whose client secret is sealed under
//! `oidc.client_secret_encryption_key`. A key in both keeps the
//! configuration entry.
//!
//! The list is a snapshot ([`OidcRegistry`]) every sign-in reads, never the
//! table: it starts as the configuration providers, is rebuilt at boot, and
//! again when a change is announced on [`OIDC_PROVIDERS_CHANNEL`] or by the
//! periodic catch-up, so every node follows an edit. A row that cannot be
//! used (disabled, deleted, no key ring, a secret that does not open) is left
//! out with a warning that names the provider, never the secret.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use attome_config::{KeyRing, OidcProviderConfig, Secret};
use attome_db::DbPool;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::envelope::{RowBinding, decrypt_bound};

/// The channel a provider change is announced on; the payload is unused.
pub const OIDC_PROVIDERS_CHANNEL: &str = "attome-auth:oidc-providers:changed";

/// The envelope field name a database provider's client secret is sealed
/// under (bound to its row).
pub const CLIENT_SECRET_FIELD: &str = "oidc_provider.client_secret_enc";

/// Where a provider is defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSource {
    /// `oidc.providers` in configuration; read-only on screen.
    Config,
    /// The `oidc_provider` table; an administrator edits it.
    Database,
}

/// One provider, ready to sign someone in.
#[derive(Clone)]
pub struct ProviderEntry {
    pub key: String,
    pub source: ProviderSource,
    /// The `oidc_provider` row, for a database provider.
    pub id: Option<Uuid>,
    pub config: OidcProviderConfig,
    pub display_name_ar: Option<String>,
    /// `link_only` or `create` (Q1-T8); configured providers create.
    pub link_mode: String,
    pub default_role: Option<Uuid>,
    /// Whether the provider's own MFA counts as a second factor (Q1-T11).
    pub trusted_for_mfa: bool,
    /// Entra tenants allowed to sign in (Q1-T6); empty allows any.
    pub tenant_allowlist: Vec<String>,
    /// Claim names and provider-specific settings (Q1-T9, Q1-T11).
    pub claim_map: Value,
}

impl std::fmt::Debug for ProviderEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderEntry")
            .field("key", &self.key)
            .field("source", &self.source)
            .field("id", &self.id)
            .field("issuer", &self.config.issuer)
            .field("client_id", &self.config.client_id)
            .field("link_mode", &self.link_mode)
            .field("trusted_for_mfa", &self.trusted_for_mfa)
            .finish_non_exhaustive()
    }
}

/// One `oidc_provider` row as stored.
#[derive(Clone, sqlx::FromRow)]
pub struct ProviderRow {
    pub id: Uuid,
    pub key: String,
    pub display_name: String,
    pub display_name_ar: Option<String>,
    pub issuer: String,
    pub client_id: String,
    pub client_secret_enc: String,
    pub scopes: Vec<String>,
    pub claim_map: Value,
    pub link_mode: String,
    pub default_role_ref: Option<Uuid>,
    pub trusted_for_mfa: bool,
    pub tenant_allowlist: Vec<String>,
    pub enabled: bool,
    pub is_deleted: bool,
}

impl std::fmt::Debug for ProviderRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderRow")
            .field("id", &self.id)
            .field("key", &self.key)
            .field("issuer", &self.issuer)
            .field("enabled", &self.enabled)
            .field("is_deleted", &self.is_deleted)
            .finish_non_exhaustive()
    }
}

fn claim_text(claim_map: &Value, key: &str) -> Option<String> {
    claim_map
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The values of `key` in `claim_map`, one text or a list of texts.
fn claim_list(claim_map: &Value, key: &str) -> Vec<String> {
    match claim_map.get(key) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn from_config(key: &str, config: &OidcProviderConfig) -> ProviderEntry {
    ProviderEntry {
        key: key.to_owned(),
        source: ProviderSource::Config,
        id: None,
        config: config.clone(),
        display_name_ar: None,
        // Q1-T8: a configured provider keeps creating accounts, as it always
        // has; only a provider added on screen can be link-only.
        link_mode: "create".to_owned(),
        default_role: None,
        trusted_for_mfa: config.trust_idp_mfa,
        tenant_allowlist: Vec::new(),
        claim_map: Value::Object(serde_json::Map::new()),
    }
}

/// A database row as a provider, its secret opened by `open_secret`.
fn from_row(row: ProviderRow, secret: Secret) -> ProviderEntry {
    let config = OidcProviderConfig {
        display_name: row.display_name,
        issuer: row.issuer,
        client_id: row.client_id,
        client_secret: secret,
        scopes: row.scopes,
        email_claim: claim_text(&row.claim_map, "email").unwrap_or_else(|| "email".to_owned()),
        require_email_verified_claim: row
            .claim_map
            .get("require_email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        // Q1-T11: a new provider's MFA counts by the standard methods unless
        // its claim map names its own values.
        mfa_acr_values: match claim_list(&row.claim_map, "mfa_acr") {
            values if values.is_empty() => crate::oidc::STANDARD_MFA_AMR
                .iter()
                .map(|v| (*v).to_owned())
                .collect(),
            values => values,
        },
        trust_idp_mfa: row.trusted_for_mfa,
    };
    ProviderEntry {
        key: row.key,
        source: ProviderSource::Database,
        id: Some(row.id),
        config,
        display_name_ar: row.display_name_ar,
        link_mode: row.link_mode,
        default_role: row.default_role_ref,
        trusted_for_mfa: row.trusted_for_mfa,
        tenant_allowlist: row.tenant_allowlist,
        claim_map: row.claim_map,
    }
}

/// Merges the two sources: the configuration providers (with `overrides`,
/// the secrets bundle's client secrets, applied), then every enabled,
/// non-deleted row whose secret opens. A key in both keeps the
/// configuration entry. Sorted by key.
pub fn merge(
    config_providers: &HashMap<String, OidcProviderConfig>,
    overrides: &HashMap<String, Secret>,
    rows: Vec<ProviderRow>,
    open_secret: impl Fn(&ProviderRow) -> Result<Secret, AppError>,
) -> Vec<ProviderEntry> {
    let mut entries: Vec<ProviderEntry> = config_providers
        .iter()
        .map(|(key, config)| {
            let mut entry = from_config(key, config);
            if let Some(secret) = overrides.get(key) {
                entry.config.client_secret = secret.clone();
            }
            entry
        })
        .collect();
    for row in rows {
        if !row.enabled || row.is_deleted {
            continue;
        }
        if config_providers.contains_key(&row.key) {
            tracing::warn!(
                provider = %row.key,
                "a sign-in provider is defined in configuration and on screen; the configuration wins"
            );
            continue;
        }
        match open_secret(&row) {
            Ok(secret) => entries.push(from_row(row, secret)),
            Err(e) => tracing::warn!(
                provider = %row.key,
                error = %e,
                "a sign-in provider's client secret could not be opened; it is left out"
            ),
        }
    }
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    entries
}

/// Every `oidc_provider` row (the merge decides which are used).
pub async fn load_rows(db: &DbPool) -> Result<Vec<ProviderRow>, AppError> {
    sqlx::query_as(
        "SELECT id, key, display_name, display_name_ar, issuer, client_id, client_secret_enc, \
                scopes, claim_map, link_mode, default_role_ref, trusted_for_mfa, \
                tenant_allowlist, enabled, is_deleted \
           FROM oidc_provider \
          WHERE enabled AND NOT is_deleted",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Opens a row's client secret under `ring`.
pub fn open_with(ring: &KeyRing) -> impl Fn(&ProviderRow) -> Result<Secret, AppError> + '_ {
    move |row| {
        if ring.is_empty() {
            return Err(AppError::internal(
                "oidc.client_secret_encryption_key is not configured",
            ));
        }
        decrypt_bound(
            CLIENT_SECRET_FIELD,
            ring,
            &row.client_secret_enc,
            RowBinding {
                table: "oidc_provider",
                column: "client_secret_enc",
                row_id: row.id,
            },
        )
        .map(|plain| Secret::new(plain.expose_secret().to_owned()))
    }
}

/// Q1-T4: seals a client secret for row `id` under `ring`, the inverse of
/// [`open_with`]. Refused when no ring is configured.
pub fn seal_secret(ring: &KeyRing, id: Uuid, secret: &str) -> Result<String, AppError> {
    if ring.is_empty() {
        return Err(AppError::Validation(
            "oidc.client_secret_encryption_key is not configured, so a provider cannot be added on screen"
                .into(),
        ));
    }
    crate::envelope::encrypt_bound(
        CLIENT_SECRET_FIELD,
        ring,
        secret,
        RowBinding {
            table: "oidc_provider",
            column: "client_secret_enc",
            row_id: id,
        },
    )
}

/// Q1-T4: the first 8 hex characters of a secret's SHA-256, so an
/// administrator can tell which secret a provider holds without seeing it.
pub fn secret_fingerprint(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(secret.as_bytes()))[..8].to_owned()
}

/// Q1-T12: why a sign-in through a provider failed.
pub const FAILURE_KINDS: [&str; 5] = [
    "discovery",
    "jwks",
    "token_exchange",
    "id_token_rejected",
    "clock_skew",
];

/// Q1-T12: one provider's failures on this node since it started: per kind,
/// and the last one. Observational: per node, kept in memory, gone on
/// restart; the counter `oidc_provider_failures_total` is the durable view.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ProviderHealth {
    pub last_failure_kind: Option<&'static str>,
    pub last_failure_at: Option<chrono::DateTime<chrono::Utc>>,
    pub failures: std::collections::BTreeMap<&'static str, u64>,
}

fn health_store() -> &'static std::sync::Mutex<HashMap<String, ProviderHealth>> {
    static STORE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, ProviderHealth>>> =
        std::sync::OnceLock::new();
    STORE.get_or_init(Default::default)
}

/// Q1-T12: counts a failed sign-in step for `provider_key` (`kind` is one of
/// [`FAILURE_KINDS`]) and records it as the provider's last failure.
pub fn record_failure(provider_key: &str, kind: &'static str) {
    metrics::counter!(
        "oidc_provider_failures_total",
        "provider" => provider_key.to_owned(),
        "kind" => kind
    )
    .increment(1);
    let mut store = health_store()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let health = store.entry(provider_key.to_owned()).or_default();
    *health.failures.entry(kind).or_insert(0) += 1;
    health.last_failure_kind = Some(kind);
    health.last_failure_at = Some(chrono::Utc::now());
}

/// Q1-T12: `provider_key`'s failures on this node since it started.
pub fn health(provider_key: &str) -> ProviderHealth {
    health_store()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(provider_key)
        .cloned()
        .unwrap_or_default()
}

/// The providers every sign-in reads, swapped whole on a rebuild.
pub struct OidcRegistry {
    snapshot: ArcSwap<Vec<ProviderEntry>>,
}

impl std::fmt::Debug for OidcRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<String> = self.snapshot.load().iter().map(|p| p.key.clone()).collect();
        f.debug_struct("OidcRegistry")
            .field("providers", &keys)
            .finish()
    }
}

impl OidcRegistry {
    /// The configuration providers alone, until the first [`Self::reload`].
    pub fn from_config(
        config_providers: &HashMap<String, OidcProviderConfig>,
        overrides: &HashMap<String, Secret>,
    ) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(merge(config_providers, overrides, Vec::new(), |_| {
                Err(AppError::internal("no rows"))
            })),
        }
    }

    /// The provider with `key`.
    pub fn get(&self, key: &str) -> Option<ProviderEntry> {
        self.snapshot.load().iter().find(|p| p.key == key).cloned()
    }

    /// Every provider, sorted by key.
    pub fn list(&self) -> Arc<Vec<ProviderEntry>> {
        self.snapshot.load_full()
    }

    /// Rebuilds from configuration and the table. On a read failure the
    /// current list stays.
    pub async fn reload(
        &self,
        db: &DbPool,
        config_providers: &HashMap<String, OidcProviderConfig>,
        overrides: &HashMap<String, Secret>,
        ring: &KeyRing,
    ) -> Result<usize, AppError> {
        let rows = load_rows(db).await?;
        let entries = merge(config_providers, overrides, rows, open_with(ring));
        let count = entries.len();
        self.snapshot.store(Arc::new(entries));
        Ok(count)
    }
}

/// Tells every node to rebuild its list; the caller has committed the change.
pub async fn announce_change(redis: &attome_cache::Store) -> Result<(), AppError> {
    redis
        .publish(OIDC_PROVIDERS_CHANNEL, "changed")
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(issuer: &str) -> OidcProviderConfig {
        serde_json::from_value(serde_json::json!({
            "display_name": "Configured",
            "issuer": issuer,
            "client_id": "client",
            "client_secret": "configured-secret-value",
        }))
        .unwrap()
    }

    fn row(key: &str) -> ProviderRow {
        ProviderRow {
            id: Uuid::now_v7(),
            key: key.to_owned(),
            display_name: "On screen".to_owned(),
            display_name_ar: Some("على الشاشة".to_owned()),
            issuer: "https://db.example".to_owned(),
            client_id: "db-client".to_owned(),
            client_secret_enc: "sealed".to_owned(),
            scopes: vec!["openid".to_owned(), "email".to_owned()],
            claim_map: serde_json::json!({ "email": "upn", "mfa_acr": ["mfa"] }),
            link_mode: "create".to_owned(),
            default_role_ref: None,
            trusted_for_mfa: false,
            tenant_allowlist: vec!["tenant-a".to_owned()],
            enabled: true,
            is_deleted: false,
        }
    }

    fn open(_: &ProviderRow) -> Result<Secret, AppError> {
        Ok(Secret::new("opened-secret".to_owned()))
    }

    #[test]
    fn config_provider_wins_on_key_clash() {
        let configured = HashMap::from([("entra".to_owned(), config("https://config.example"))]);
        let merged = merge(
            &configured,
            &HashMap::new(),
            vec![row("entra"), row("okta")],
            open,
        );
        assert_eq!(merged.len(), 2);
        let entra = merged.iter().find(|p| p.key == "entra").unwrap();
        assert_eq!(entra.source, ProviderSource::Config);
        assert_eq!(entra.config.issuer, "https://config.example");
        let okta = merged.iter().find(|p| p.key == "okta").unwrap();
        assert_eq!(okta.source, ProviderSource::Database);
        assert_eq!(okta.config.email_claim, "upn");
        assert_eq!(okta.config.mfa_acr_values, vec!["mfa".to_owned()]);
        assert!(!okta.trusted_for_mfa && !okta.config.trust_idp_mfa);
        let mut plain = row("plain");
        plain.claim_map = serde_json::json!({});
        let merged = merge(&HashMap::new(), &HashMap::new(), vec![plain], open);
        assert_eq!(
            merged[0].config.mfa_acr_values,
            crate::oidc::STANDARD_MFA_AMR,
            "Q1-T11: an on-screen provider counts the standard methods"
        );
        assert_eq!(okta.config.client_secret.expose(), "opened-secret");
    }

    #[test]
    fn disabled_db_provider_is_skipped() {
        let mut disabled = row("disabled");
        disabled.enabled = false;
        let mut deleted = row("deleted");
        deleted.is_deleted = true;
        let merged = merge(
            &HashMap::new(),
            &HashMap::new(),
            vec![disabled, deleted, row("live")],
            open,
        );
        assert_eq!(
            merged.iter().map(|p| p.key.as_str()).collect::<Vec<_>>(),
            vec!["live"]
        );
    }

    #[test]
    fn a_row_whose_secret_does_not_open_is_left_out() {
        let merged = merge(&HashMap::new(), &HashMap::new(), vec![row("bad")], |_| {
            Err(AppError::internal("wrong key"))
        });
        assert!(merged.is_empty());
        let ring = KeyRing::default();
        assert!(
            open_with(&ring)(&row("x")).is_err(),
            "no ring, no database providers"
        );
    }

    #[test]
    fn a_sealed_secret_opens_for_its_own_row_only() {
        let ring = KeyRing::single("ab".repeat(32));
        let mut sealed = row("sealed");
        sealed.client_secret_enc = seal_secret(&ring, sealed.id, "s3cret").unwrap();
        assert_eq!(open_with(&ring)(&sealed).unwrap().expose(), "s3cret");
        let mut moved = sealed.clone();
        moved.id = Uuid::now_v7();
        assert!(open_with(&ring)(&moved).is_err(), "bound to its row");
        assert!(seal_secret(&KeyRing::default(), sealed.id, "s3cret").is_err());
        assert_eq!(secret_fingerprint("s3cret").len(), 8);
        assert_ne!(secret_fingerprint("s3cret"), secret_fingerprint("other"));
    }

    #[test]
    fn failure_is_recorded_in_snapshot() {
        let key = format!("health-{}", Uuid::now_v7().simple());
        assert_eq!(health(&key), ProviderHealth::default());
        record_failure(&key, "discovery");
        record_failure(&key, "jwks");
        record_failure(&key, "jwks");
        let snapshot = health(&key);
        assert_eq!(snapshot.last_failure_kind, Some("jwks"));
        assert!(snapshot.last_failure_at.is_some());
        assert_eq!(snapshot.failures.get("jwks"), Some(&2));
        assert_eq!(snapshot.failures.get("discovery"), Some(&1));
        assert!(health("another-provider").failures.is_empty());
    }

    #[test]
    fn the_secrets_bundle_overrides_a_configured_secret() {
        let configured = HashMap::from([("entra".to_owned(), config("https://config.example"))]);
        let overrides = HashMap::from([("entra".to_owned(), Secret::new("bundle".to_owned()))]);
        let merged = merge(&configured, &overrides, Vec::new(), open);
        assert_eq!(merged[0].config.client_secret.expose(), "bundle");
        let debug = format!("{:?}", merged[0]);
        assert!(!debug.contains("bundle"), "{debug}");
    }
}
