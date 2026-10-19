use attome_config::{AppConfig, CacheRole};
use fred::clients::SubscriberClient;
use fred::prelude::*;
use fred::rustls::crypto::CryptoProvider;
use fred::rustls::pki_types::CertificateDer;
use fred::rustls::pki_types::pem::PemObject;
use fred::rustls::{ClientConfig, RootCertStore};

use crate::ops::{self, Primitive};
use crate::timeouts::{BACKGROUND, CONNECT};

pub type RedisPool = fred::clients::RedisPool;

/// Readiness/liveness ping. Bounded by [`BACKGROUND`] (BCA-13): before that
/// it inherited `cache.timeout`, which fred reads as "no timeout" when the
/// operator sets `0` — exactly the unbounded readiness probe BSV-F07 and
/// BCA-F3 both describe. `false` still means "do not serve", and the outcome
/// is counted on `base_cache_redis_ops_total{primitive="ping"}`.
pub async fn redis_ping(pool: &RedisPool) -> bool {
    let result = tokio::time::timeout(BACKGROUND, pool.ping::<()>()).await;
    ops::record_op(Primitive::Ping, &result);
    matches!(result, Ok(Ok(())))
}

/// Installs rustls' process-level crypto provider when TLS is configured
/// (BCA-01b). rustls 0.23 refuses to guess when a build enables **both**
/// provider features, and this workspace's unit graph does exactly that:
/// fred's `enable-rustls` pulls `tokio-rustls/aws_lc_rs` while the workspace's
/// `rustls = { features = ["ring"] }` pin selects ring, and cargo unifies them
/// into one crate. `ClientConfig::builder()` — reached both by
/// [`custom_ca_tls_config`] and by fred's own `rediss://` default — then panics
/// with "CryptoProvider could not be determined from crate features".
///
/// `crates/server/src/boot.rs` installs ring as the process default for the
/// binaries for this same reason. The matrix's TLS leg runs the test binary
/// directly, so boot never runs and the provider was never installed — that is
/// the TLS leg's never-green failure. Installing it here, only when a TLS URL
/// is about to be parsed, keeps a plaintext-only deployment from touching
/// process-global rustls state at all.
///
/// Idempotent and non-overriding: a provider another component already
/// installed always wins.
fn ensure_rustls_crypto_provider() {
    static INSTALL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALL.get_or_init(|| {
        if CryptoProvider::get_default().is_none() {
            // Ring, matching the workspace pin and boot.rs.
            let _ = fred::rustls::crypto::ring::default_provider().install_default();
        }
    });
}

/// `RedisConfig::from_url`, with the crypto-provider install ordered *before*
/// the parse — a `rediss://` URL builds fred's own TLS config eagerly, so
/// installing afterwards would be too late.
fn redis_config_from_url(url: &str, tls: bool) -> Result<RedisConfig, RedisError> {
    if tls {
        ensure_rustls_crypto_provider();
    }
    RedisConfig::from_url(url)
}

/// Builds a custom-CA `TlsConfig` (P-datastore-tls) — pins the given CA
/// instead of trusting the system/default root store, matching D-002's
/// "certificates are deployment-provided, self-signed-with-pinned-CA is the
/// documented floor." Only called when a `tls_ca_path` is actually
/// configured; the `rediss://` scheme alone (no pinned CA) uses fred's own
/// default TLS config, built by `RedisConfig::from_url`.
fn custom_ca_tls_config(ca_path: &str) -> Result<TlsConfig, RedisError> {
    let roots = load_ca_roots(ca_path)?;
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(client_config.into())
}

/// Reads every `CERTIFICATE` section of the PEM bundle at `ca_path` into a
/// root store. Non-certificate sections and text outside PEM armour are
/// skipped; a malformed section, an unreadable file, a certificate rustls
/// cannot use as a trust anchor, or a bundle with no certificate at all is a
/// `Config` error naming the path. PEM decoding is rustls-pki-types'
/// `PemObject` (RUSTSEC-2025-0134 retired the unmaintained rustls-pemfile).
fn load_ca_roots(ca_path: &str) -> Result<RootCertStore, RedisError> {
    let file = std::fs::File::open(ca_path).map_err(|e| {
        RedisError::new(
            RedisErrorKind::Config,
            format!("cache.tls_ca_path {ca_path:?}: {e}"),
        )
    })?;

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_reader_iter(file) {
        let cert = cert.map_err(|e| {
            RedisError::new(
                RedisErrorKind::Config,
                format!("cache.tls_ca_path {ca_path:?}: invalid PEM certificate: {e}"),
            )
        })?;
        roots.add(cert).map_err(|e| {
            RedisError::new(
                RedisErrorKind::Config,
                format!("cache.tls_ca_path {ca_path:?}: {e}"),
            )
        })?;
    }
    if roots.is_empty() {
        return Err(RedisError::new(
            RedisErrorKind::Config,
            format!("cache.tls_ca_path {ca_path:?}: no certificates found in file"),
        ));
    }
    Ok(roots)
}

/// Applies a pinned CA (if configured) on top of whatever `RedisConfig::from_url`
/// already derived from the `rediss://` scheme. A `tls_ca_path` of `None` means
/// "trust the default root store" — leave `from_url`'s own TLS config as-is.
fn apply_tls_ca(redis_config: &mut RedisConfig, ca_path: Option<&str>) -> Result<(), RedisError> {
    if let Some(ca_path) = ca_path {
        redis_config.tls = Some(custom_ca_tls_config(ca_path)?);
    }
    Ok(())
}

/// Every client this crate builds reconnects on its own (BCA-F1, G-2). With no
/// `ReconnectPolicy`, fred 9.4 ends a client's router task on the first failed
/// write after the socket drops, and nothing here calls `connect()` again: one
/// Redis restart or failover left every node disconnected, and the pre-auth
/// limiter then rejected every request (D-397) until each process restarted.
///
/// - **Reconnect:** exponential backoff from 100 ms to 5 s, unlimited attempts
///   (attome-cache plan OD-4). A node keeps trying for as long as it runs; the
///   fail-closed callers keep refusing while it is disconnected.
/// - **Connect timeout:** 2 s instead of fred's 10 s, so one attempt against a
///   dead endpoint does not stall a reconnect cycle.
/// - **Command timeout:** the configured `cache.timeout`, as before.
///
/// With the `count-redis` test feature, every client also traces its commands
/// (AA14-T3), so a test can count the Redis calls one request makes.
fn client_builder(redis_config: RedisConfig, command_timeout_ms: u64) -> Builder {
    #[cfg(feature = "count-redis")]
    let redis_config = RedisConfig {
        tracing: fred::types::TracingConfig::new(true),
        ..redis_config
    };
    let mut builder = Builder::from_config(redis_config);
    builder
        .set_policy(ReconnectPolicy::new_exponential(0, 100, 5_000, 2))
        .with_connection_config(|c| {
            c.connection_timeout = CONNECT;
        })
        .with_performance_config(|c| {
            c.default_command_timeout = std::time::Duration::from_millis(command_timeout_ms);
        });
    builder
}

pub async fn create_redis_pool(config: &AppConfig) -> Result<RedisPool, RedisError> {
    let mut redis_config = redis_config_from_url(&config.redis_url(), config.cache.tls_enabled)?;
    apply_tls_ca(&mut redis_config, config.cache.tls_ca_path.as_deref())?;
    let sentinel = redis_config.server.is_sentinel();
    let pool = client_builder(redis_config, config.cache.timeout)
        .build_pool(config.cache.connection_pool_size)?;

    pool.connect();
    pool.wait_for_connect().await?;

    tracing::info!(
        "redis pool connected (size={}, sentinel={sentinel})",
        config.cache.connection_pool_size
    );
    Ok(pool)
}

/// P1.15 §4(b) — role-split connection factory. When the deployment hasn't
/// configured an override for `role`, returns a clone of `general` (the
/// already-connected base pool) instead of opening a second, redundant
/// physical connection pool to the same instance — so a deployment that
/// never sets `cache.roles.*` is byte-for-byte unaffected (same pool, same
/// connections, same behavior as pre-P1.15). Only when an override is
/// present does this open a dedicated pool against the role's own endpoint.
pub async fn create_role_redis_pool(
    config: &AppConfig,
    role: CacheRole,
    general: &RedisPool,
) -> Result<RedisPool, RedisError> {
    if config.cache_role_override(role).is_none() {
        return Ok(general.clone());
    }

    let url = config.redis_url_for_role(role);
    let pool_size = config.redis_pool_size_for_role(role);
    let timeout_ms = config.redis_timeout_ms_for_role(role);
    let ca_path = config.redis_tls_ca_path_for_role(role);
    // The early return above guarantees an override exists; its own
    // `tls_enabled` decides whether the role URL is `rediss://`.
    let tls_enabled = config
        .cache_role_override(role)
        .is_some_and(|o| o.tls_enabled);

    let mut redis_config = redis_config_from_url(&url, tls_enabled)?;
    apply_tls_ca(&mut redis_config, ca_path.as_deref())?;
    let sentinel = redis_config.server.is_sentinel();
    let pool = client_builder(redis_config, timeout_ms).build_pool(pool_size)?;

    pool.connect();
    pool.wait_for_connect().await?;

    tracing::info!(
        ?role,
        "redis role pool connected (size={pool_size}, sentinel={sentinel})"
    );
    Ok(pool)
}

/// Test/observability counter — every [`create_subscriber_client`] call
/// increments this, so a test can assert how many dedicated subscriber
/// connections a boot sequence opened (C-18: `xrm-server` collapsed seven
/// per-registry subscriber connections into one shared client) without
/// parsing `CLIENT LIST` output. Also emitted as the
/// `redis_subscriber_clients_created_total` counter below for the same
/// signal in production.
pub static SUBSCRIBER_CLIENTS_CREATED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// A dedicated pub/sub connection, separate from the request-path `RedisPool`,
/// so a slow subscriber never head-of-line-blocks ordinary command traffic.
/// Callers still need `.subscribe(channel)` + `.manage_subscriptions()` after
/// connecting — this only establishes the connection.
pub async fn create_subscriber_client(config: &AppConfig) -> Result<SubscriberClient, RedisError> {
    let mut redis_config = redis_config_from_url(&config.redis_url(), config.cache.tls_enabled)?;
    apply_tls_ca(&mut redis_config, config.cache.tls_ca_path.as_deref())?;
    let client = client_builder(redis_config, config.cache.timeout).build_subscriber_client()?;

    client.connect();
    client.wait_for_connect().await?;

    SUBSCRIBER_CLIENTS_CREATED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    metrics::counter!("redis_subscriber_clients_created_total").increment(1);
    tracing::info!("redis subscriber client connected");
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only self-signed EC certificate (CN=localhost), the same one
    /// attome-storage's `tests/fixtures/self_signed_cert.pem` carries.
    const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBrTCCAVSgAwIBAgIUAmh24H1ClV8Vj6BrWfHJtk0Ik3IwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkyNTA4NDIwNloYDzIxMjYwOTAx
MDg0MjA2WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAASKwgTZy65HcsSyBPqoG5ZycB5nf6xd5fISkao2XUKmWLqTn6Ns0HvS
sDeQq5X6uvhr81mHyBGXpvN+8aVUjcrho4GBMH8wHQYDVR0OBBYEFEsjXVgYVZ8t
5DiqAf0pK+jhKoF3MB8GA1UdIwQYMBaAFEsjXVgYVZ8t5DiqAf0pK+jhKoF3MBoG
A1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAMBgNVHRMBAf8EAjAAMBMGA1UdJQQM
MAoGCCsGAQUFBwMBMAoGCCqGSM49BAMCA0cAMEQCIFFBkEQrEmAq3Ny2zru9F7Hr
nrprQGsRz67Zi08/u8v7AiARDrEXvmqG1mCfkXNcPZ5zgKn9pEmokKFeAlhtnGaz
Hg==
-----END CERTIFICATE-----
";

    /// Writes `contents` to a unique temp file, removed on drop.
    struct TempPem(std::path::PathBuf);

    impl TempPem {
        fn new(contents: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("attome-cache-ca-{}.pem", uuid::Uuid::now_v7()));
            std::fs::write(&path, contents).expect("write temp PEM");
            Self(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().expect("utf-8 temp path")
        }
    }

    impl Drop for TempPem {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn config_error(result: Result<RootCertStore, RedisError>) -> String {
        let err = result.expect_err("expected a Config error");
        assert_eq!(*err.kind(), RedisErrorKind::Config);
        err.details().to_string()
    }

    #[test]
    fn a_single_certificate_loads() {
        let pem = TempPem::new(CERT_PEM);
        assert_eq!(load_ca_roots(pem.path()).expect("loads").len(), 1);
    }

    #[test]
    fn a_chain_loads_every_certificate_and_skips_other_sections() {
        // A key section and stray text between certificates are ignored,
        // exactly as rustls_pemfile::certs ignored them.
        let bundle = format!(
            "leading comment\n{CERT_PEM}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n{CERT_PEM}"
        );
        let pem = TempPem::new(&bundle);
        assert_eq!(load_ca_roots(pem.path()).expect("loads").len(), 2);
    }

    #[test]
    fn an_empty_file_is_no_certificates_found() {
        let pem = TempPem::new("");
        assert!(config_error(load_ca_roots(pem.path())).contains("no certificates found in file"));
    }

    #[test]
    fn non_pem_garbage_is_no_certificates_found() {
        let pem = TempPem::new("this is not a certificate bundle\n\x01\x02garbage");
        assert!(config_error(load_ca_roots(pem.path())).contains("no certificates found in file"));
    }

    #[test]
    fn a_malformed_certificate_section_is_invalid_pem() {
        let pem = TempPem::new(
            "-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n",
        );
        assert!(config_error(load_ca_roots(pem.path())).contains("invalid PEM certificate"));
    }

    #[test]
    fn an_unterminated_certificate_section_is_invalid_pem() {
        let pem = TempPem::new("-----BEGIN CERTIFICATE-----\nMIIB\n");
        assert!(config_error(load_ca_roots(pem.path())).contains("invalid PEM certificate"));
    }

    #[test]
    fn well_formed_pem_that_is_not_a_certificate_is_rejected() {
        // Valid base64 but not DER: decoding succeeds, the trust-anchor parse fails.
        let pem = TempPem::new("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
        let msg = config_error(load_ca_roots(pem.path()));
        assert!(msg.contains("cache.tls_ca_path"), "{msg}");
        assert!(!msg.contains("no certificates found"), "{msg}");
    }

    #[test]
    fn a_missing_file_is_a_config_error_naming_the_path() {
        let missing = std::env::temp_dir().join("attome-cache-ca-does-not-exist.pem");
        let path = missing.to_str().expect("utf-8 temp path");
        assert!(config_error(load_ca_roots(path)).contains("attome-cache-ca-does-not-exist.pem"));
    }

    #[test]
    fn a_valid_bundle_builds_a_tls_config() {
        ensure_rustls_crypto_provider();
        let pem = TempPem::new(CERT_PEM);
        assert!(custom_ca_tls_config(pem.path()).is_ok());
    }
}
