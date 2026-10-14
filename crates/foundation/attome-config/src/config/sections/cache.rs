//! `cache` section — the Redis/Dragonfly connection block, its optional
//! Sentinel-mode wiring, and P1.15's per-role endpoint overrides.

use serde::Deserialize;

/// Where the platform keeps its shared, short-lived state: rate-limit
/// windows, replay nonces, revocation markers, caches and doorbells.
/// `docs/solo-memory-backend.md` is the design.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheBackend {
    /// Redis or Dragonfly (Standard and Cluster, and Solo if one is
    /// configured). The default.
    #[default]
    Redis,
    /// Process memory. For Solo: one server process, no Redis to install. A
    /// restart clears it, as a Redis restart without persistence would; every
    /// value in it is short-lived or reconstructable. It is not a cross-node
    /// source of truth, so a multi-node deployment must not use it.
    Memory,
}

#[derive(Clone, Deserialize)]
pub struct CacheSection {
    /// `redis` (the default) or `memory`. With `memory`, `host`, `port`,
    /// `password` and `db` are not used and may be left at any value.
    #[serde(default)]
    pub backend: CacheBackend,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub db: i64,
    /// Pool size — plausibly scales with hardware/load. Has a default so a
    /// deployment that hasn't tuned it can omit the key entirely.
    #[serde(default = "default_cache_connection_pool_size")]
    pub connection_pool_size: usize,
    /// Connect/command timeout in milliseconds — plausibly varies with
    /// network latency.
    #[serde(default = "default_cache_timeout")]
    pub timeout: u64,
    /// Rollback switch for Plan 1.2 (kept for one release, not deleted): when
    /// `false`, `resolve_entity` falls back to the pre-1.2 direct Postgres
    /// query path instead of the arc-swap metadata registry.
    #[serde(default = "default_metadata_registry_enabled")]
    pub metadata_registry_enabled: bool,
    /// P1.15 — optional per-role endpoint overrides. `None` (the default)
    /// means every role shares this base block, identical to pre-P1.15
    /// behavior. See `CacheRole`/`AppConfig::redis_url_for_role`.
    #[serde(default)]
    pub roles: CacheRoles,
    /// P-datastore-tls — connect via `rediss://` (fred's TLS-enabled scheme)
    /// instead of `redis://`. Default false — byte-for-byte identical to
    /// pre-TLS behavior when unset.
    #[serde(default)]
    pub tls_enabled: bool,
    /// P-datastore-tls — path to a CA certificate file (PEM) to pin, instead
    /// of trusting the system/default root store. Only meaningful when
    /// `tls_enabled` is true.
    #[serde(default)]
    pub tls_ca_path: Option<String>,
    /// P-redis-sentinel-config — closes the self-host HA tier's documented
    /// app-wiring gap (scale-out-ops skill / P-ha-failover-hardening):
    /// `create_redis_pool` previously only spoke a fixed `host:port`, so a
    /// Sentinel-fronted deployment needed an operator-managed proxy/VIP in
    /// front of Sentinel's resolved master. `None` (the default) is
    /// byte-for-byte today's centralized-connection behavior. Set this to
    /// connect via fred's `redis-sentinel://` scheme instead, whose documented
    /// contract is to re-resolve the current master through the sentinel quorum
    /// on every (re)connect — `host`/`port` above then name the first known
    /// sentinel node, not the Redis server itself.
    ///
    /// **Unproven here (BCA-55).** Re-resolving *a* master is fred's behaviour,
    /// not something this repo has ever exercised: no test or drill has failed
    /// a Sentinel quorum over and confirmed the pool follows, which is why
    /// D-153's "not verified" item 3 still stands and scale-out-ops does not
    /// yet present Sentinel as a supported recipe. Treat a Sentinel deployment
    /// as unvalidated until BCA-55 records a failover result; the plain-restart
    /// half (reconnect without a process restart) is proven — BCA-01/BCA-01b.
    #[serde(default)]
    pub sentinel: Option<CacheSentinelConfig>,
}

/// Hand-rolled: `password` is the Redis/Dragonfly auth credential — the
/// derived `Debug` would print it raw.
impl std::fmt::Debug for CacheSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheSection")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("password", &"[REDACTED]")
            .field("db", &self.db)
            .field("connection_pool_size", &self.connection_pool_size)
            .field("timeout", &self.timeout)
            .field("metadata_registry_enabled", &self.metadata_registry_enabled)
            .field("roles", &self.roles)
            .field("tls_enabled", &self.tls_enabled)
            .field("tls_ca_path", &self.tls_ca_path)
            .field("sentinel", &self.sentinel)
            .finish()
    }
}

fn default_cache_connection_pool_size() -> usize {
    32
}

fn default_cache_timeout() -> u64 {
    2000
}

fn default_metadata_registry_enabled() -> bool {
    true
}

/// Sentinel-mode connection details for a `CacheSection`/`CacheRoleOverride`
/// block (P-redis-sentinel-config). The enclosing block's `host`/`port`
/// name the first known sentinel node; `nodes` lists any additional sentinel
/// nodes for quorum. The enclosing block's `password` still authenticates to
/// the resolved master/replica (unchanged meaning) — `sentinel_username`/
/// `sentinel_password` here are separate credentials for the sentinel nodes
/// themselves, only honored under fred's `sentinel-auth` feature (enabled
/// workspace-wide, see root `Cargo.toml`). Leave them unset when the
/// sentinel nodes require no auth of their own, which most deployments do
/// (Sentinel exposes no customer data — see `deploy/ha/sentinel.conf.example`).
#[derive(Clone, Deserialize, Default)]
pub struct CacheSentinelConfig {
    /// Fred's `sentinelServiceName` — the name Sentinel knows the monitored
    /// master by (often `mymaster`). Required whenever `sentinel` is set.
    pub service_name: String,
    #[serde(default)]
    pub nodes: Vec<CacheSentinelNode>,
    #[serde(default)]
    pub sentinel_username: Option<String>,
    #[serde(default)]
    pub sentinel_password: Option<String>,
}

/// Hand-rolled: `sentinel_password` is a live credential (when the Sentinel
/// nodes themselves require auth, see the struct doc above) — the derived
/// `Debug` would print it raw.
impl std::fmt::Debug for CacheSentinelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheSentinelConfig")
            .field("service_name", &self.service_name)
            .field("nodes", &self.nodes)
            .field("sentinel_username", &self.sentinel_username)
            .field(
                "sentinel_password",
                &self.sentinel_password.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CacheSentinelNode {
    pub host: String,
    pub port: u16,
}

/// P1.15 — role-specific Redis endpoint overrides, generalizing `CacheSection`
/// from one host/port to "one base block, optionally overridden per role."
/// Widen this struct (never replace the base block) when a new role needs its
/// own override.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CacheRoles {
    /// S2S nonce replay guard, S2S + general HTTP sliding-window rate limits,
    /// and the idempotency `SET NX` gate — the "coordination-critical" keys
    /// callable out in P1.15. A deployment can point these at a dedicated
    /// Redis instance, isolated from general cache traffic (metadata pub/sub,
    /// authz L2 cache), once its load demands it. Omit to keep everything on
    /// the base `cache` block (today's default, unaffected).
    #[serde(default)]
    pub coordination: Option<CacheRoleOverride>,
}

#[derive(Clone, Deserialize)]
pub struct CacheRoleOverride {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub db: i64,
    #[serde(default = "default_role_pool_size")]
    pub connection_pool_size: usize,
    #[serde(default = "default_role_timeout")]
    pub timeout: u64,
    /// P-datastore-tls — see `CacheSection::tls_enabled`. A role override
    /// can point at a differently-secured endpoint than the base block.
    #[serde(default)]
    pub tls_enabled: bool,
    #[serde(default)]
    pub tls_ca_path: Option<String>,
    /// P-redis-sentinel-config — see `CacheSection::sentinel`'s doc comment;
    /// same meaning, scoped to this role's own endpoint.
    #[serde(default)]
    pub sentinel: Option<CacheSentinelConfig>,
}

/// Hand-rolled: `password` is the Redis/Dragonfly auth credential for this
/// role's endpoint — the derived `Debug` would print it raw.
impl std::fmt::Debug for CacheRoleOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheRoleOverride")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("password", &"[REDACTED]")
            .field("db", &self.db)
            .field("connection_pool_size", &self.connection_pool_size)
            .field("timeout", &self.timeout)
            .field("tls_enabled", &self.tls_enabled)
            .field("tls_ca_path", &self.tls_ca_path)
            .field("sentinel", &self.sentinel)
            .finish()
    }
}

fn default_role_pool_size() -> usize {
    16
}
fn default_role_timeout() -> u64 {
    2000
}

/// A Redis-dependent role that may have its own endpoint (P1.15 §4b). Add a
/// variant here (and a matching field on `CacheRoles`) when a new subsystem
/// needs its own isolation knob — never repurpose an existing variant for a
/// different subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheRole {
    Coordination,
}
