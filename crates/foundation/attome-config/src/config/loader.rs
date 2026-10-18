//! `impl AppConfig` — env/file loading, the Postgres/Redis URL builders, the
//! small derived-value accessors (`bind_addr`, token TTL conversions, CORS
//! allow-list resolution, ...), and the fail-fast `validate()`/
//! `validate_production_profile()` pass plus its private `check_*` helpers.
//!
//! Kept as one file rather than forced into further submodules — the
//! natural internal boundaries (URL builders / small accessors / the long
//! `validate()` family) all operate on the same `&self` and don't separate
//! cleanly enough to be worth the cross-file `impl AppConfig` split.

use std::net::IpAddr;
use std::time::Duration;

use crate::Secret;
use crate::keyring::KeyRing;

use super::helpers::{
    expand_env_vars_tracking, is_secret_path, postgres_url, template_secret_marker,
};
use super::{
    AnchorStoreSection, AppConfig, CacheRole, CacheRoleOverride, CacheSentinelConfig, ConfigError,
    build_redis_sentinel_url, build_redis_url, cidr_contains, parse_cidr, urlencoding,
};

impl AppConfig {
    /// BCF-10 — deserialize with `serde_ignored` watching, returning the config
    /// plus every dropped key path. Split out of `from_file` so a test can
    /// prove unknown-key reporting without a temp file or an env-var dance.
    ///
    /// A path segment starting with `_` is prose (`_readme`, `_comment*`) and
    /// is not reported: those keys document the file rather than configure the
    /// deployment.
    pub(crate) fn deserialize_tracked(
        text: &str,
    ) -> Result<(Self, Vec<String>), serde_json::Error> {
        let mut ignored = Vec::new();
        let mut deserializer = serde_json::Deserializer::from_str(text);
        let config = serde_ignored::deserialize(&mut deserializer, |unknown| {
            let path = unknown.to_string();
            if !path
                .split('.')
                .any(|segment| segment.trim_matches('"').starts_with('_'))
            {
                ignored.push(path);
            }
        })?;
        Ok((config, ignored))
    }

    /// The unknown keys in a configuration text, as dotted JSON paths: what
    /// `preflight` would refuse. For a generator (`attome init`) to check
    /// what it writes.
    pub fn unknown_keys_in(text: &str) -> Result<Vec<String>, serde_json::Error> {
        Self::deserialize_tracked(text).map(|(_, ignored)| ignored)
    }

    /// BCF-10 — the unknown keys `from_file` recorded, as dotted JSON paths.
    /// Boot warns on each one; `preflight` fails on any.
    /// Z1-T7: what this node was configured with, secrets masked; `Null`
    /// unless loaded by `from_file`.
    pub fn fingerprint_view(&self) -> &serde_json::Value {
        &self.fingerprint_view
    }

    /// Z1-T7: the SHA-256 hex of [`Self::fingerprint_view`].
    pub fn fingerprint(&self) -> String {
        crate::fingerprint::fingerprint_of(&self.fingerprint_view)
    }

    pub fn ignored_keys(&self) -> &[String] {
        &self.ignored_keys
    }

    /// Keys this config sets that are accepted but no longer do anything, as
    /// `(dotted path, operator message)`. Boot warns on each; unlike an
    /// unknown key it never fails `preflight`, because it is being retired on
    /// a published schedule (BIN-D7).
    pub fn deprecated_keys(&self) -> Vec<(&'static str, &'static str)> {
        let mut keys = Vec::new();
        if self.inference.caller_token_budget_per_min.is_some() {
            keys.push((
                "inference.caller_token_budget_per_min",
                "accepted and ignored — nothing enforces it; remove it before the next release",
            ));
        }
        keys
    }

    /// The path `from_file` will read, resolved by the selection order that
    /// method documents. Public so a diagnostic — `crates/server`'s
    /// `bin/preflight.rs` — can name and stat the file an actual boot would
    /// use, without restating the precedence rule and letting the two drift.
    ///
    /// Loads `.env` first for the same reason `from_file` does: `CONFIG_FILE`
    /// is commonly set there rather than in the process environment. Calling
    /// this and then `from_file` loads it twice, which is a no-op — `dotenvy`
    /// never overrides an already-set variable.
    pub fn config_file_path() -> String {
        dotenvy::dotenv().ok();

        std::env::var("CONFIG_FILE").unwrap_or_else(|_| {
            if crate::is_debug_env() {
                "config.debug.json".to_string()
            } else {
                "config.json".to_string()
            }
        })
    }

    /// Load from a JSON file.
    /// File selection order:
    ///   1. `CONFIG_FILE` env var (explicit path)
    ///   2. `APP_ENV=debug`  → `config.debug.json`
    ///   3. default          → `config.json`
    pub fn from_file() -> Result<Self, ConfigError> {
        let path = Self::config_file_path();

        // A bind mount whose host-side file is missing makes Docker create a
        // *directory* at the target path — `docker-compose.yml`'s
        // `./config.json` / `./config.runtime.json` mounts do exactly this on
        // a fresh clone, and `read_to_string` below would then fail with a
        // bare "Is a directory (os error 21)" that names neither the cause
        // nor the fix. Report it properly instead (F-017).
        if std::path::Path::new(&path).is_dir() {
            return Err(ConfigError::NotAFile { path });
        }

        let raw = std::fs::read_to_string(&path).map_err(|e| ConfigError::FileNotFound {
            path: path.clone(),
            error: e.to_string(),
        })?;

        // BCF-6 (D-615) — parse to JSON first, then expand `${VAR}` inside
        // string values only. The old textual splice put an environment value
        // straight into JSON syntax, so a secret containing a double quote
        // broke the parse and a literal backslash-n was decoded to a newline
        // (BCF-F4a). A `${...}` appearing outside a string is invalid JSON
        // (e.g. `"port": ${PORT}`); the parse error says so rather than
        // leaving the operator with a column number.
        let mut document: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
            let mut error = e.to_string();
            if raw.contains("${") {
                error.push_str(
                    " — note: a ${...} placeholder appeared outside a JSON string value; \
                     placeholders are only expanded inside string values",
                );
            }
            ConfigError::Parse {
                path: path.clone(),
                error,
            }
        })?;

        let mut unresolved = Vec::new();
        let mut literals = Vec::new();
        expand_env_vars_tracking(&mut document, &mut unresolved, &mut literals);

        // Fail-closed (D-038): an unresolved ${VAR} anywhere in the config is
        // a boot error — a missing DB password or Redis URL must never boot as
        // the literal string "${...}". Only APP_ENV=debug keeps the lenient
        // leave-the-literal behavior, for local dev configs that reference
        // optional vars; validate() still hard-checks the security secrets in
        // both modes.
        if !unresolved.is_empty() && !crate::is_debug_env() {
            return Err(ConfigError::UnresolvedPlaceholders {
                path,
                keys: unresolved.join(", "),
            });
        }

        // P-rate-limit-atomicity (D-145): `rate_limit.per_endpoint_limits` was
        // removed in favor of `rate_limit.categories` — serde silently drops
        // an unknown field by default, which would leave an operator
        // believing a still-referenced override is in effect when it no
        // longer does anything (D-038 fail-closed convention). Checked
        // against the parsed document, since the typed struct below has
        // already dropped the field by the time it exists.
        if document
            .get("rate_limit")
            .and_then(|rl| rl.get("per_endpoint_limits"))
            .is_some()
        {
            return Err(ConfigError::DeprecatedField {
                path,
                field: "rate_limit.per_endpoint_limits".to_string(),
                hint: "replaced by rate_limit.categories (one {anonymous_rpm, authenticated_rpm} \
                       pair per category — credential/mfa/password_reset/api/export/\
                       expensive_query); translate each old entry into the category its route \
                       belongs to, then delete this key"
                    .to_string(),
            });
        }

        let document_text = document.to_string();
        let (mut config, ignored_keys) =
            Self::deserialize_tracked(&document_text).map_err(|e| ConfigError::Parse {
                path: path.clone(),
                error: e.to_string(),
            })?;
        config.unresolved_placeholders = unresolved;
        config.ignored_keys = ignored_keys;
        config.literal_paths = literals;
        config.fingerprint_view = crate::fingerprint::view_of(&document);
        // BCF-5 (D-615) — the profile decides, not APP_ENV: a production node
        // must never boot on a literal "${VAR}", whatever APP_ENV says. The
        // gate above already covers the non-debug case; this closes the
        // `APP_ENV=debug` hole (BCF-F7) that turned an unset secret into an
        // opaque DNS/auth failure at first use.
        if config.app.deployment_profile == "production"
            && !config.unresolved_placeholders.is_empty()
        {
            return Err(ConfigError::UnresolvedPlaceholders {
                path,
                keys: config.unresolved_placeholders.join(", "),
            });
        }
        Ok(config)
    }

    /// PostgreSQL connection URL built from the `database` section.
    ///
    /// `search_path` is `{schema},public` — the app schema first (so an
    /// unqualified table name resolves there, not to a same-named table an
    /// extension might create in `public`), `public` second so extension
    /// functions installed there (`pgcrypto`'s `gen_random_bytes`, used by
    /// apalis's own migration) remain callable unqualified. A bare
    /// `search_path={schema}` silently drops the Postgres default `public`
    /// entry rather than adding to it.
    pub fn database_url(&self) -> String {
        let db = &self.database;
        // P-bootstrap-credential-scoping (D-204): `password` is `None` for a
        // process that was deliberately never given the bootstrap
        // credential (`server`/`worker` in production, D-148) — same
        // passwordless-userinfo behavior as the pre-existing empty-string
        // case, since every legitimate caller of this URL outside
        // `bin/migrate.rs`/`migrate_on_boot=true` is already fail-closed
        // gated before it can be reached (see `password`'s own doc comment).
        let userinfo = match db.password.as_ref().map(Secret::expose) {
            Some(password) if !password.is_empty() => format!(
                "{}:{}",
                urlencoding::encode(&db.user),
                urlencoding::encode(password)
            ),
            _ => urlencoding::encode(&db.user).into_owned(),
        };
        postgres_url(&userinfo, &db.host, db.port, &db.dbname, &db.schema)
    }

    /// P1.12 — the URL schema bootstrap + migrations must use: `direct_url`
    /// if a deployment set one (because `database_url()` points at
    /// pgbouncer), otherwise identical to `database_url()`.
    ///
    /// P-db-privilege-separation / D-117: deliberately NOT
    /// `migrator_database_url()`, even though schema bootstrap + migrations
    /// are conceptually "migrator" work. `run_migrations`/`ensure_schema`
    /// (and the role-password seeds, `readonly_role_seed`/
    /// `db_role_seed::seed_migrator`/`seed_runtime`) run on the pool this URL
    /// builds, and migration
    /// `0042_migrator_runtime_roles.sql` is what CREATEs the `attome_migrator`
    /// role in the first place — that bootstrap step, plus granting
    /// `attome_migrator` its login password, must happen on a role that
    /// already exists and already has sufficient privilege (`database.user`,
    /// same as today), not on `attome_migrator` itself. See
    /// `attome_db::create_migrator_pool` for the identity that
    /// entity/attribute provisioning actually uses, built only after this
    /// pool's boot sequence has run the migrator role-seed.
    pub fn direct_database_url(&self) -> String {
        self.database
            .direct_url
            .clone()
            .unwrap_or_else(|| self.database_url())
    }

    /// P-db-privilege-separation / D-117 — connection URL for the DDL-capable
    /// migrator identity, used ONLY by `attome_db::create_migrator_pool`/
    /// `create_migrator_connection` (entity/attribute provisioning + boot-time
    /// entity seeding) — never by `direct_database_url()`, see its doc
    /// comment for why. Falls back to `database_url()`'s credentials
    /// (`database.user`/`.password`) when `database.migrator` isn't
    /// configured — unlike `readonly_database_url()`, this never returns
    /// `None`: provisioning always needs *some* pool to run against, and the
    /// pre-split behavior (one shared identity) is what makes it safe for
    /// `main.rs` to build `db_migrator` unconditionally, right after its own
    /// boot-time check has already refused to proceed with this fallback
    /// outside `APP_ENV=debug` — that check, not this method, is what makes
    /// an unconfigured `database.migrator` a boot error now (DECISIONS.md's
    /// follow-up to D-117 supersedes D-117's original "additive, not
    /// fail-closed" framing).
    pub fn migrator_database_url(&self) -> String {
        let Some(migrator) = self.database.migrator.as_ref() else {
            return self.database_url();
        };
        let db = &self.database;
        let userinfo = if migrator.password.is_empty() {
            urlencoding::encode(&migrator.user).into_owned()
        } else {
            format!(
                "{}:{}",
                urlencoding::encode(&migrator.user),
                urlencoding::encode(migrator.password.expose())
            )
        };
        postgres_url(&userinfo, &db.host, db.port, &db.dbname, &db.schema)
    }

    /// P-db-privilege-separation / D-117 — connection URL for the DML-only
    /// runtime identity, used by `attome_db::create_pool` (`AppState.db`,
    /// ordinary request-time record CRUD). Falls back to `database_url()`'s
    /// credentials (`database.user`/`.password`) when `database.runtime`
    /// isn't configured — never `None`, same reasoning as
    /// `migrator_database_url`: `main.rs`'s own boot-time check is what
    /// refuses to proceed with this fallback outside `APP_ENV=debug`, not
    /// this method.
    pub fn runtime_database_url(&self) -> String {
        let Some(runtime) = self.database.runtime.as_ref() else {
            return self.database_url();
        };
        let db = &self.database;
        let userinfo = if runtime.password.is_empty() {
            urlencoding::encode(&runtime.user).into_owned()
        } else {
            format!(
                "{}:{}",
                urlencoding::encode(&runtime.user),
                urlencoding::encode(runtime.password.expose())
            )
        };
        postgres_url(&userinfo, &db.host, db.port, &db.dbname, &db.schema)
    }

    /// PostgreSQL connection URL for the SELECT-only role (P1.1e), if
    /// configured. `None` means the deployment hasn't set up the read-only
    /// role yet — callers must fall back to the primary pool with a loud
    /// warning, never silently.
    ///
    /// D-155: host/port come from `ReadonlyDbCredentials.host`/`.port` when
    /// set, falling back to the primary's `database.host`/`.port` otherwise
    /// (today's behavior, unchanged) — see that struct's doc comments.
    pub fn readonly_database_url(&self) -> Option<String> {
        let ro = self.database.readonly.as_ref()?;
        let db = &self.database;
        let host = ro.host.as_deref().unwrap_or(db.host.as_str());
        let port = ro.port.unwrap_or(db.port);
        let userinfo = if ro.password.is_empty() {
            urlencoding::encode(&ro.user).into_owned()
        } else {
            format!(
                "{}:{}",
                urlencoding::encode(&ro.user),
                urlencoding::encode(ro.password.expose())
            )
        };
        Some(postgres_url(&userinfo, host, port, &db.dbname, &db.schema))
    }

    /// P-api-consistency-hardening (a) — connection URL for the same
    /// SELECT-only `attome_readonly` role as `readonly_database_url()`, but
    /// **always** the primary's own `database.host`/`.port`, ignoring
    /// `ReadonlyDbCredentials.host`/`.port` (D-155) even when a deployment has
    /// pointed the ordinary replica pool at a distinct endpoint. `None` under
    /// the identical condition as `readonly_database_url` (no
    /// `database.readonly` configured — there is no readonly role to reuse).
    ///
    /// Used only by `attome_db::create_readonly_primary_pool`, which
    /// `query_exec.rs` routes a pinned (just-written) caller to instead of
    /// the ordinary `db_readonly` pool: same restricted grants, primary-fresh
    /// data, without ever borrowing the full-privilege pool `database_url()`
    /// builds — see that pool constructor's doc comment for why the
    /// alternative (route to the primary as the full-privilege role) was
    /// rejected.
    pub fn readonly_primary_database_url(&self) -> Option<String> {
        let ro = self.database.readonly.as_ref()?;
        let db = &self.database;
        let userinfo = if ro.password.is_empty() {
            urlencoding::encode(&ro.user).into_owned()
        } else {
            format!(
                "{}:{}",
                urlencoding::encode(&ro.user),
                urlencoding::encode(ro.password.expose())
            )
        };
        Some(format!(
            "postgres://{}@{}:{}/{}?options=-c%20search_path%3D{}%2Cpublic",
            userinfo, db.host, db.port, db.dbname, db.schema
        ))
    }

    /// Redis URL built from the `cache` section. `rediss://` scheme when
    /// `cache.tls_enabled` (P-datastore-tls) — the CA path (if any) isn't
    /// expressible in the URL, see `redis_tls_ca_path_for_role`.
    pub fn redis_url(&self) -> String {
        match &self.cache.sentinel {
            Some(sentinel) => build_redis_sentinel_url(
                &self.cache.host,
                self.cache.port,
                self.cache.password.expose(),
                self.cache.db,
                self.cache.tls_enabled,
                sentinel,
            ),
            None => build_redis_url(
                &self.cache.host,
                self.cache.port,
                self.cache.password.expose(),
                self.cache.db,
                self.cache.tls_enabled,
            ),
        }
    }

    /// The role-specific override, if the deployment configured one (P1.15 §4b).
    pub fn cache_role_override(&self, role: CacheRole) -> Option<&CacheRoleOverride> {
        match role {
            CacheRole::Coordination => self.cache.roles.coordination.as_ref(),
        }
    }

    /// Redis URL for a given role — the role's own override if configured,
    /// else identical to `redis_url()` (today's single-instance behavior).
    pub fn redis_url_for_role(&self, role: CacheRole) -> String {
        match self.cache_role_override(role) {
            Some(o) => match &o.sentinel {
                Some(sentinel) => build_redis_sentinel_url(
                    &o.host,
                    o.port,
                    o.password.expose(),
                    o.db,
                    o.tls_enabled,
                    sentinel,
                ),
                None => build_redis_url(&o.host, o.port, o.password.expose(), o.db, o.tls_enabled),
            },
            None => self.redis_url(),
        }
    }

    /// CA cert path (P-datastore-tls) for a given role's Redis connection —
    /// mirrors `redis_url_for_role`'s fallback exactly: the role override's
    /// own path when an override is configured (never the base block's —
    /// an override is a fully separate endpoint), else the base `cache`
    /// block's. `None` means "trust the default/system root store."
    pub fn redis_tls_ca_path_for_role(&self, role: CacheRole) -> Option<String> {
        match self.cache_role_override(role) {
            Some(o) => o.tls_ca_path.clone(),
            None => self.cache.tls_ca_path.clone(),
        }
    }

    /// Connection pool size for a given role — falls back to the base
    /// `cache.connection_pool_size` when no override is configured.
    pub fn redis_pool_size_for_role(&self, role: CacheRole) -> usize {
        self.cache_role_override(role)
            .map(|o| o.connection_pool_size)
            .unwrap_or(self.cache.connection_pool_size)
    }

    /// Per-command Redis timeout (ms) for a given role — falls back to the
    /// base `cache.timeout` when no override is configured.
    pub fn redis_timeout_ms_for_role(&self, role: CacheRole) -> u64 {
        self.cache_role_override(role)
            .map(|o| o.timeout)
            .unwrap_or(self.cache.timeout)
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.app.server_host, self.app.port)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.app.request_timeout_secs)
    }

    /// S1 (BSV-F13 / BSV-D11) — how long `crates/server/src/main.rs` keeps
    /// answering `/health/ready` with 503 before it signals the HTTP listeners
    /// to stop accepting new connections. See
    /// `AppSection::shutdown_drain_delay_secs`.
    pub fn shutdown_drain_delay(&self) -> Duration {
        Duration::from_secs(self.app.shutdown_drain_delay_secs)
    }

    /// Explicit CORS allow-list. Falls back to a dev-only default derived
    /// from `app.frontend_host`/`app.frontend_port` (`http://` only) when
    /// `cors.allowed_origins` is unset — production deployments behind TLS
    /// MUST set `cors.allowed_origins` explicitly.
    pub fn allowed_origins(&self) -> Vec<String> {
        if !self.cors.allowed_origins.is_empty() {
            return self.cors.allowed_origins.clone();
        }
        vec![format!(
            "http://{}:{}",
            self.app.frontend_host, self.app.frontend_port
        )]
    }

    /// Canonical public frontend URL for building links in emails — see
    /// `AppSection::public_frontend_url`.
    pub fn frontend_url(&self) -> String {
        self.app.public_frontend_url.clone().unwrap_or_else(|| {
            format!(
                "http://{}:{}",
                self.app.frontend_host, self.app.frontend_port
            )
        })
    }

    /// Access-token TTL in seconds (config stores minutes).
    pub fn access_token_expiry_secs(&self) -> u64 {
        self.auth.access_token_expiry_mins * 60
    }

    /// P-key-rotation-and-jwt (c) — the `aud` claim value: `auth.jwt_audience`
    /// if a deployment set one explicitly, else `auth.jwt_issuer` (plan §4:
    /// "a fixed per-deployment string, default = issuer").
    pub fn jwt_audience(&self) -> &str {
        if self.auth.jwt_audience.is_empty() {
            &self.auth.jwt_issuer
        } else {
            &self.auth.jwt_audience
        }
    }

    /// Refresh-token TTL in seconds (config stores days).
    pub fn refresh_token_expiry_secs(&self) -> i64 {
        (self.auth.refresh_token_expiry_days * 86_400) as i64
    }

    /// Refresh-family absolute lifetime in seconds (config stores days;
    /// D-504). Exactly 86 400 seconds per day, never a calendar day.
    pub fn refresh_absolute_lifetime_secs(&self) -> i64 {
        (self.auth.refresh_absolute_lifetime_days * 86_400) as i64
    }

    /// Whether `ip` belongs to an explicitly configured reverse-proxy network.
    /// This is deliberately fail-closed: an empty or malformed entry never
    /// makes a peer trusted.
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        // BSV-F17: a dual-stack bind reports an IPv4 peer as `::ffff:a.b.c.d`.
        let ip = ip.to_canonical();
        self.security
            .trusted_proxy_cidrs
            .iter()
            .any(|cidr| cidr_contains(cidr, ip))
    }

    /// Fail-fast validation for signing/encryption secrets. MUST run right
    /// after `expand_env_vars`, before any pool/state is built — an operator
    /// forgetting an env var must never boot the app on a known-constant key.
    /// U1-T5: every configured destination outside this deployment, as
    /// `(field, reason)`. Inside means what
    /// [`endpoint_is_in_deployment`](super::sections::inference::endpoint_is_in_deployment)
    /// says (loopback, private ranges, single-label and `.local` names), or a
    /// host on `deployment.sovereign_allowed_hosts`. `validate` refuses the
    /// first one when `deployment.sovereign` is on.
    pub fn sovereign_violations(&self) -> Vec<(String, String)> {
        let allowed = &self.deployment.sovereign_allowed_hosts;
        let inside = |target: &str| {
            let url = if target.contains("://") {
                target.to_owned()
            } else {
                format!("http://{target}")
            };
            let host = url::Url::parse(&url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase));
            host.is_some_and(|host| allowed.iter().any(|a| a.eq_ignore_ascii_case(&host)))
                || super::sections::inference::endpoint_is_in_deployment(&url)
        };
        let check = |field: &str, target: &str| -> Option<(String, String)> {
            let target = target.trim();
            (!target.is_empty() && !inside(target)).then(|| {
                (
                    field.to_owned(),
                    format!(
                        "{target} is outside this deployment; a sovereign deployment only reaches \
                         its own network (or deployment.sovereign_allowed_hosts)"
                    ),
                )
            })
        };
        let mut out: Vec<(String, String)> = Vec::new();
        // An empty S3 endpoint means AWS S3 itself.
        if self.storage.s3_endpoint.trim().is_empty() {
            out.push((
                "storage.s3_endpoint".to_owned(),
                "empty means AWS S3; a sovereign deployment names its own object store".to_owned(),
            ));
        } else {
            out.extend(check("storage.s3_endpoint", &self.storage.s3_endpoint));
        }
        if let Some(anchor) = &self.audit.anchor_store {
            if anchor.s3_endpoint.trim().is_empty() {
                out.push((
                    "audit.anchor_store.s3_endpoint".to_owned(),
                    "empty means AWS S3; a sovereign deployment names its own object store"
                        .to_owned(),
                ));
            } else {
                out.extend(check("audit.anchor_store.s3_endpoint", &anchor.s3_endpoint));
            }
        }
        if self.email.enabled {
            out.extend(check("email.smtp_host", &self.email.smtp_host));
        }
        out.extend(check(
            "inference.generation.base_url",
            &self.inference.generation.base_url,
        ));
        out.extend(check(
            "inference.embedding.base_url",
            &self.inference.embedding.base_url,
        ));
        if let Some(endpoint) = &self.observability.otlp_endpoint {
            out.extend(check("observability.otlp_endpoint", endpoint));
        }
        out.extend(check(
            "docgen.render_service_url",
            &self.docgen.render_service_url,
        ));
        for (name, provider) in &self.oidc.providers {
            out.extend(check(
                &format!("oidc.providers.{name}.issuer"),
                &provider.issuer,
            ));
        }
        if self.inference.allow_external_provider {
            out.push((
                "inference.allow_external_provider".to_owned(),
                "a sovereign deployment uses only its own model servers".to_owned(),
            ));
        }
        if !self.google_ai.api_key.expose().trim().is_empty() {
            out.push((
                "google_ai.api_key".to_owned(),
                "Google AI is an outside service; leave the key empty".to_owned(),
            ));
        }
        if !self.auth.oauth_google_client_id.trim().is_empty() {
            out.push((
                "auth.oauth_google_client_id".to_owned(),
                "Google sign-in is an outside service; use an identity provider on your own \
                 network"
                    .to_owned(),
            ));
        }
        out
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        // AA9-T2: every boot-config limit inside its registered range, all
        // failures reported together.
        let limits = crate::limits::boot_violations(self);
        if !limits.is_empty() {
            return Err(ConfigError::Invalid {
                field: "limits".into(),
                reason: limits.join("; "),
            });
        }
        // U1-T5 — the sovereign preset refuses outside destinations first, so
        // the operator sees that before any other complaint.
        if self.deployment.sovereign
            && let Some((field, reason)) = self.sovereign_violations().into_iter().next()
        {
            return Err(ConfigError::Insecure { field, reason });
        }
        // BCF-3/BCF-D1 — the shipped-template denylist is a production-profile
        // rule: config.example.json deliberately ships throwaway secrets for
        // the dev stack, and only a declared production node must refuse them.
        let production = self.app.deployment_profile == "production";
        // Z1-T5: in production a secret comes from the environment or a
        // mounted file (`${VAR}` / `VAR_FILE`), never typed into the file.
        // Names the path only, never the value.
        if production && let Some(path) = self.literal_paths.iter().find(|p| is_secret_path(p)) {
            return Err(ConfigError::Insecure {
                field: path.clone(),
                reason: "a secret in production must come from a ${VAR} placeholder \
                         (the VAR or VAR_FILE environment variable), not be written into \
                         the configuration file"
                    .into(),
            });
        }
        // S1 (BSV-F13) — the drain delay is the only knob over how long a
        // draining node keeps taking new connections after readiness reads
        // 503. 0 is legal (it restores the pre-S1 "flip and signal together"
        // behaviour); an absurd value would hold a rolling deploy open
        // indefinitely, so cap it.
        validate_shutdown_drain_delay_secs(self.app.shutdown_drain_delay_secs)?;
        // B1 (BSV-F05) — see `validate_request_timeout_secs`.
        validate_request_timeout_secs(self.app.request_timeout_secs)?;
        // B6 (BSV-F16) — see `validate_ipv6_bucket_prefix`.
        validate_ipv6_bucket_prefix(self.rate_limit.ipv6_bucket_prefix)?;
        // BAU-15a — see `validate_kdf`.
        validate_kdf(&self.auth.kdf)?;
        // A3 (BSV-F07) — see `validate_cache_timeout_ms`.
        validate_cache_timeout_ms("cache.timeout", self.cache.timeout)?;
        // The in-process store is private to one process: a split worker (its
        // own process) would read an empty store where the server wrote its
        // buffers, rate windows and revocations.
        if self.cache.backend == crate::config::CacheBackend::Memory && !self.jobs.run_worker_inline
        {
            return Err(ConfigError::Invalid {
                field: "cache.backend".into(),
                reason: "\"memory\" needs jobs.run_worker_inline = true: the in-process store \
                         cannot be shared with a separate worker process. Use \"redis\" for a \
                         split or multi-node deployment."
                    .into(),
            });
        }
        // BCA-14 — a role override is a fully separate endpoint with its own
        // timeout, so a `0` there is unbounded too. Checked here rather than
        // left to the role-specific production gate below, which only runs for
        // a declared production profile.
        if let Some(coordination) = &self.cache.roles.coordination {
            validate_cache_timeout_ms("cache.roles.coordination.timeout", coordination.timeout)?;
        }
        Self::check_secret_ring("auth.jwt_secret", &self.auth.jwt_secret, production)?;
        Self::check_signing_seeds("auth.jwt_signing_keys", &self.auth.jwt_signing_keys)?;
        // P-api-key-hashing (D-112, revised) — unconditional, unlike the
        // flag-gated secrets below: every deployment authenticates api-key
        // requests. Every pepper in the ring (current + previous) is
        // independently secret-checked; a weak retired pepper is exactly as
        // dangerous as a weak current one, since old rows still verify
        // against it. A duplicate id (current colliding with a previous
        // entry, or two previous entries sharing an id) is a config error,
        // not a runtime ambiguity — reject it outright rather than letting
        // `HashMap::insert` silently pick one.
        Self::check_secret(
            "auth.apikey_hash_pepper",
            self.auth.apikey_hash_pepper.expose(),
            production,
        )?;
        {
            let mut seen_ids = std::collections::HashSet::new();
            seen_ids.insert(self.auth.apikey_hash_pepper_id);
            for prev in &self.auth.apikey_hash_previous_peppers {
                Self::check_secret(
                    &format!("auth.apikey_hash_previous_peppers[id={}]", prev.id),
                    prev.secret.expose(),
                    production,
                )?;
                if !seen_ids.insert(prev.id) {
                    return Err(ConfigError::Invalid {
                        field: "auth.apikey_hash_previous_peppers".into(),
                        reason: format!(
                            "duplicate pepper id {} — each id (current or previous) must be unique",
                            prev.id
                        ),
                    });
                }
            }
        }
        // D-506, local-only until its administrator opt-in exists: an embedding
        // endpoint outside this deployment would send the whole knowledge base
        // off-deployment, so it fails boot whatever
        // `inference.allow_external_provider` says. An empty endpoint is a
        // supported lexical-only deployment (D-360 ruling 6).
        // BCF-7 — the encryption key protecting AI provider API keys at rest.
        // It had no validation at all before this item; whenever it is set it
        // is 32 bytes of AES-256 key material.
        if !self.inference.provider_credential_key.is_empty() {
            Self::check_secret_ring(
                "inference.provider_credential_key",
                &self.inference.provider_credential_key,
                production,
            )?;
            Self::check_hex_key_ring(
                "inference.provider_credential_key",
                &self.inference.provider_credential_key,
            )?;
        }
        // N24-T1 — money budgets.
        self.inference
            .spend
            .validate()
            .map_err(|(field, reason)| ConfigError::Invalid { field, reason })?;
        // BIN-C3 — a zero timeout fails every request at once.
        for (field, secs) in [
            (
                "inference.generation.request_timeout_secs",
                self.inference.generation.request_timeout_secs,
            ),
            (
                "inference.embedding.request_timeout_secs",
                self.inference.embedding.request_timeout_secs,
            ),
        ] {
            validate_inference_timeout_secs(field, secs)?;
        }
        // N26-T3: prompts are customer data. A generation endpoint outside this
        // deployment is refused at boot unless the operator said so
        // (`inference.allow_external_provider`), rather than at the first
        // request it would have carried.
        let generation_url = self.inference.generation.base_url.trim();
        if !generation_url.is_empty()
            && !self.inference.allow_external_provider
            && !super::sections::inference::endpoint_is_in_deployment(generation_url)
        {
            return Err(ConfigError::Insecure {
                field: "inference.generation.base_url".into(),
                reason: "points outside this deployment, which sends every prompt (record data                          included) to that provider; use a model server on your own network, or                          set inference.allow_external_provider = true to allow it"
                    .into(),
            });
        }
        let embedding_url = self.inference.embedding.base_url.trim();
        if !embedding_url.is_empty()
            && !super::sections::inference::endpoint_is_in_deployment(embedding_url)
        {
            return Err(ConfigError::Insecure {
                field: "inference.embedding.base_url".into(),
                reason: "points outside this deployment. External embedding sends the \
                         knowledge base off-deployment and is not available until D-506's \
                         administrator opt-in exists; use the in-deployment embedding server, \
                         or leave it empty for lexical-only search"
                    .into(),
            });
        }
        // D-558 §1: public web chat is off by default, and on only with an
        // agent definition and both spend caps — never an unbounded route.
        if let Err((field, reason)) = self.webchat.check() {
            return Err(ConfigError::Invalid {
                field: field.into(),
                reason: reason.into(),
            });
        }
        // D-588: portal OIDC providers and the signup CAPTCHA.
        if let Err((field, reason)) = self.portal.check(production) {
            return Err(ConfigError::Invalid { field, reason });
        }
        if self.s2s.enabled {
            Self::check_secret_ring(
                "s2s.key_encryption_key",
                &self.s2s.key_encryption_key,
                production,
            )?;
            Self::check_hex_key_ring("s2s.key_encryption_key", &self.s2s.key_encryption_key)?;
        }
        for (i, client) in self.s2s.seeded_clients.iter().enumerate() {
            if let Err(reason) = check_seeded_s2s_client(client) {
                return Err(ConfigError::Invalid {
                    field: format!("s2s.seeded_clients[{i}]"),
                    reason,
                });
            }
        }
        if self.events.webhooks_enabled {
            Self::check_secret_ring(
                "events.webhook_signing_key",
                &self.events.webhook_signing_key,
                production,
            )?;
        }
        if self.events.dispatch_batch_size <= 0 {
            return Err(ConfigError::Invalid {
                field: "events.dispatch_batch_size".into(),
                reason: "must be at least 1".into(),
            });
        }
        if self.einvoice.enabled {
            Self::check_secret_ring(
                "einvoice.key_encryption_key",
                &self.einvoice.key_encryption_key,
                production,
            )?;
            Self::check_hex_key_ring(
                "einvoice.key_encryption_key",
                &self.einvoice.key_encryption_key,
            )?;
        }
        if self.integration.enabled {
            Self::check_secret_ring(
                "integration.credential_encryption_key",
                &self.integration.credential_encryption_key,
                production,
            )?;
            Self::check_hex_key_ring(
                "integration.credential_encryption_key",
                &self.integration.credential_encryption_key,
            )?;
        }
        const VALID_MFA_POLICIES: &[&str] = &["off", "optional", "required"];
        if !VALID_MFA_POLICIES.contains(&self.auth.mfa_policy.as_str()) {
            return Err(ConfigError::Invalid {
                field: "auth.mfa_policy".into(),
                reason: format!(
                    "must be one of {VALID_MFA_POLICIES:?}, got {:?}",
                    self.auth.mfa_policy
                ),
            });
        }
        if self.auth.mfa_policy != "off" {
            Self::check_secret_ring(
                "auth.mfa_encryption_key",
                &self.auth.mfa_encryption_key,
                production,
            )?;
            Self::check_hex_key_ring("auth.mfa_encryption_key", &self.auth.mfa_encryption_key)?;
        }
        if self.auth.mfa_challenge_max_attempts == 0 {
            return Err(ConfigError::Invalid {
                field: "auth.mfa_challenge_max_attempts".into(),
                reason: "must be at least 1".into(),
            });
        }
        // D-504: 0 would reject every refresh, and above 365 migration 0462's
        // fallback anchor for an inconsistent lineage would no longer be
        // expired.
        if !(1..=365).contains(&self.auth.refresh_absolute_lifetime_days) {
            return Err(ConfigError::Invalid {
                field: "auth.refresh_absolute_lifetime_days".into(),
                reason: format!(
                    "must be between 1 and 365 days, got {}",
                    self.auth.refresh_absolute_lifetime_days
                ),
            });
        }
        const VALID_REGISTRATION_MODES: &[&str] = &["public", "invite", "disabled"];
        if !VALID_REGISTRATION_MODES.contains(&self.auth.registration_mode.as_str()) {
            return Err(ConfigError::Invalid {
                field: "auth.registration_mode".into(),
                reason: format!(
                    "must be one of {VALID_REGISTRATION_MODES:?}, got {:?}",
                    self.auth.registration_mode
                ),
            });
        }
        if self.idempotency.durable_retention_hours == 0 {
            return Err(ConfigError::Invalid {
                field: "idempotency.durable_retention_hours".into(),
                reason: "must be at least 1 — a 0-hour retention would let the retention sweep \
                         race a not-yet-replayed retry"
                    .into(),
            });
        }
        if self.idempotency.replay_max_bytes == 0 {
            return Err(ConfigError::Invalid {
                field: "idempotency.replay_max_bytes".into(),
                reason: "must be at least 1 — a 0-byte cap would make every successful \
                         idempotent response unreplayable"
                    .into(),
            });
        }
        if self.change_feed.retention_days <= 0 {
            return Err(ConfigError::Invalid {
                field: "change_feed.retention_days".into(),
                reason: "must be at least 1 — a non-positive retention floor would let the \
                         change-feed prune job race a consumer that has not read a just-written \
                         event yet"
                    .into(),
            });
        }
        // NOTE: idempotency.mandatory_operations is intentionally NOT
        // validated against the live route table here — see
        // IdempotencySection::mandatory_operations's doc comment TODO.
        if self.approval.ttl_hours <= 0 {
            return Err(ConfigError::Invalid {
                field: "approval.ttl_hours".into(),
                reason: "must be at least 1 — a non-positive TTL would make every submitted \
                         approval request expire immediately"
                    .into(),
            });
        }
        // NOTE: approval.required_actions is intentionally NOT validated
        // against the set of action_types a binary actually dispatches —
        // see ApprovalSection::required_actions's doc comment TODO.
        if self.audit.signing_enabled {
            Self::check_secret(
                "audit.signing_private_key",
                self.audit.signing_private_key.expose(),
                production,
            )?;
            Self::check_hex_key(
                "audit.signing_private_key",
                self.audit.signing_private_key.expose(),
            )?;
            if self.audit.signing_key_id.trim().is_empty() {
                return Err(ConfigError::Invalid {
                    field:  "audit.signing_key_id".into(),
                    reason: "required when audit.signing_enabled = true (identifies the key for future rotation)".into(),
                });
            }
        }
        if self.audit.erasure_active() {
            Self::check_secret_ring(
                "audit.erasure_key_encryption_key",
                &self.audit.erasure_key_encryption_key,
                production,
            )?;
            Self::check_hex_key_ring(
                "audit.erasure_key_encryption_key",
                &self.audit.erasure_key_encryption_key,
            )?;
        }
        if self.auth.require_verified_email && !self.email.enabled {
            return Err(ConfigError::Invalid {
                field: "auth.require_verified_email".into(),
                reason: "requires email.enabled = true — otherwise no local account could ever \
                         receive a verification link and every new registration locks itself out"
                    .into(),
            });
        }
        for (key, provider) in &self.oidc.providers {
            if key.is_empty()
                || !key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(ConfigError::Invalid {
                    field: "oidc.providers".into(),
                    reason: format!(
                        "provider key {key:?} must be non-empty ASCII alphanumeric/-/_ — it \
                         becomes a URL path segment (/api/v1/auth/oidc/{key}/login)"
                    ),
                });
            }
            Self::check_secret(
                &format!("oidc.providers.{key}.client_secret"),
                provider.client_secret.expose(),
                production,
            )?;
        }
        // attome-db hardening Phase 1.1: `database.timeout` is every pool's
        // acquire timeout and the unpooled connect timeout. attome-db used to
        // truncate it with `as u64`, so `0.5` meant "fail immediately under
        // any contention"; zero, negative, or non-finite values must not reach
        // the pool builders at all. 120s is well past any sane wait for a
        // connection — the request behind it would already have timed out.
        const MAX_DATABASE_TIMEOUT_SECS: f64 = 120.0;
        let timeout = self.database.timeout;
        let timeout_in_range =
            timeout.is_finite() && timeout > 0.0 && timeout <= MAX_DATABASE_TIMEOUT_SECS;
        if !timeout_in_range {
            return Err(ConfigError::Invalid {
                field: "database.timeout".into(),
                reason: format!(
                    "must be a finite number of seconds in (0, {MAX_DATABASE_TIMEOUT_SECS}], \
                     got {timeout}"
                ),
            });
        }
        // Each pool is sized from this value unless `database.pools` overrides
        // it (attome-db hardening Phase 2.3); 1000 is above any single-node pool
        // that fits under a PostgreSQL `max_connections`.
        const MAX_DATABASE_CONNECTION_NUMBER: u32 = 1000;
        if !(1..=MAX_DATABASE_CONNECTION_NUMBER).contains(&self.database.connection_number) {
            return Err(ConfigError::Invalid {
                field: "database.connection_number".into(),
                reason: format!(
                    "must be between 1 and {MAX_DATABASE_CONNECTION_NUMBER}, got {}",
                    self.database.connection_number
                ),
            });
        }
        let classes = &self.database.statement_classes;
        for (class, timeouts) in [
            ("fast", classes.fast),
            ("standard", classes.standard),
            ("report", classes.report),
            ("admin", classes.admin),
        ] {
            if let Some(t) = timeouts
                && (t.statement_timeout_ms == 0
                    || t.lock_timeout_ms == 0
                    || t.idle_in_transaction_timeout_ms == 0)
            {
                return Err(ConfigError::Invalid {
                    field: format!("database.statement_classes.{class}"),
                    reason: "every timeout must be above 0 ms".into(),
                });
            }
        }
        if self.database.node_count == 0 {
            return Err(ConfigError::Invalid {
                field: "database.node_count".into(),
                reason: "must be at least 1".into(),
            });
        }
        if self.database.max_server_connections == Some(0) {
            return Err(ConfigError::Invalid {
                field: "database.max_server_connections".into(),
                reason: "must be at least 1 when set".into(),
            });
        }
        let pools = &self.database.pools;
        for (field, size) in [
            ("database.pools.runtime.max_connections", pools.runtime),
            ("database.pools.readonly.max_connections", pools.readonly),
            (
                "database.pools.readonly_primary.max_connections",
                pools.readonly_primary,
            ),
            ("database.pools.migrator.max_connections", pools.migrator),
        ] {
            if let Some(size) = size
                && !(1..=MAX_DATABASE_CONNECTION_NUMBER).contains(&size.max_connections)
            {
                return Err(ConfigError::Invalid {
                    field: field.into(),
                    reason: format!(
                        "must be between 1 and {MAX_DATABASE_CONNECTION_NUMBER}, got {}",
                        size.max_connections
                    ),
                });
            }
        }
        const VALID_SSL_MODES: &[&str] = &[
            "disable",
            "allow",
            "prefer",
            "require",
            "verify-ca",
            "verify-full",
        ];
        if !VALID_SSL_MODES.contains(&self.database.ssl_mode.as_str()) {
            return Err(ConfigError::Invalid {
                field: "database.ssl_mode".into(),
                reason: format!(
                    "must be one of {VALID_SSL_MODES:?}, got {:?} — a typo here must never \
                     silently fall back to plaintext (D-038)",
                    self.database.ssl_mode
                ),
            });
        }
        if matches!(self.database.ssl_mode.as_str(), "verify-ca" | "verify-full")
            && self.database.ssl_root_cert.is_none()
        {
            return Err(ConfigError::Insecure {
                field: "database.ssl_root_cert".into(),
                reason: format!(
                    "required when database.ssl_mode = {:?} — nothing to verify the server's \
                     certificate against",
                    self.database.ssl_mode
                ),
            });
        }
        // P-bootstrap-credential-scoping (D-204): migrate_on_boot = true means
        // THIS process's own boot::init runs the inline schema-bootstrap
        // sequence (ensure_schema/run_migrations/role-password-seed) against
        // direct_database_url()/database_url(), which needs `password`
        // resolved — a `None` here would silently build a passwordless
        // connection URL and fail at connect time with an opaque auth error
        // instead of a clear boot-time one (D-038). migrate_on_boot = false
        // does NOT require the opposite (`None`) — a deployment that still
        // wants one shared config.json across migrate/server/worker remains
        // free to set it; this only closes the "forgot it entirely" gap for
        // the path that definitely needs it. The dedicated `migrate` binary
        // enforces its own unconditional requirement independently (it is
        // not gated by migrate_on_boot — see bin/migrate.rs's module doc).
        if self.database.migrate_on_boot && self.database.password.is_none() {
            return Err(ConfigError::Invalid {
                field: "database.password".into(),
                reason: "required when database.migrate_on_boot = true — the inline \
                         schema-bootstrap sequence (schema/migrations/role-password-seed) \
                         connects with this credential. Set DB_PASSWORD, or move schema \
                         bootstrap to the dedicated `migrate` binary and set \
                         migrate_on_boot = false."
                    .into(),
            });
        }
        // observability.metrics_port == 0 means "disabled" (P-observability-bcdr Track A) —
        // any nonzero value binds a second listener, which must not collide with the main
        // app port on the same process.
        if self.observability.metrics_port != 0 && self.observability.metrics_port == self.app.port
        {
            return Err(ConfigError::Invalid {
                field: "observability.metrics_port".into(),
                reason: format!(
                    "collides with app.port ({}) — the metrics listener binds a second, \
                     independent port and cannot share the main app's",
                    self.app.port
                ),
            });
        }
        // worker_health_port binds in the standalone `worker` binary, a different
        // process from the one `app.port`/`metrics_port` bind in — normally no
        // real collision. But `AppConfig` is shared verbatim by both binaries, and
        // a bare-metal/host-networking deployment could run `server` and `worker`
        // on the same host, so this stays a cheap, defensive distinctness check
        // rather than an assumption that they're always isolated (same posture as
        // the metrics_port check above).
        if self.observability.worker_health_port != 0
            && self.observability.worker_health_port == self.app.port
        {
            return Err(ConfigError::Invalid {
                field: "observability.worker_health_port".into(),
                reason: format!(
                    "collides with app.port ({}) — a deployment running `server` and `worker` \
                     on the same host needs these on distinct ports",
                    self.app.port
                ),
            });
        }
        if self.observability.worker_health_port != 0
            && self.observability.metrics_port != 0
            && self.observability.worker_health_port == self.observability.metrics_port
        {
            return Err(ConfigError::Invalid {
                field: "observability.worker_health_port".into(),
                reason: "collides with observability.metrics_port — a deployment running \
                         `server` and `worker` on the same host needs these on distinct ports"
                    .into(),
            });
        }
        // P-observability-completion — otlp_endpoint is not a secret (it
        // names a collector to send spans to, a plain public-config hostname
        // URL), so this is a plain empty-check, not `check_secret` (which
        // enforces a 32-byte-minimum meant for keys/tokens).
        if self.observability.enable_distributed_tracing
            && self
                .observability
                .otlp_endpoint
                .as_deref()
                .is_none_or(|v| v.trim().is_empty())
        {
            return Err(ConfigError::Invalid {
                field: "observability.otlp_endpoint".into(),
                reason: "required when observability.enable_distributed_tracing = true".into(),
            });
        }
        for (index, cidr) in self.security.trusted_proxy_cidrs.iter().enumerate() {
            if parse_cidr(cidr).is_none() {
                return Err(ConfigError::Invalid {
                    field: format!("security.trusted_proxy_cidrs[{index}]"),
                    reason: "must be a valid IPv4 or IPv6 CIDR".into(),
                });
            }
        }
        if let Some(sentinel) = &self.cache.sentinel {
            Self::check_sentinel("cache.sentinel", sentinel)?;
        }
        if let Some(role) = &self.cache.roles.coordination
            && let Some(sentinel) = &role.sentinel
        {
            Self::check_sentinel("cache.roles.coordination.sentinel", sentinel)?;
        }
        // app.rs::cors_layer used to build the CORS allow-list with
        // `.filter_map(|o| o.parse().ok())`, which silently dropped any entry
        // that failed to parse as an `http::HeaderValue` — a typo'd origin
        // (a stray path, a trailing slash, embedded credentials) just
        // vanished from the allow-list with no boot signal, producing a
        // narrower-than-intended (or entirely empty) CORS policy. Checked
        // unconditionally (not just under `validate_production_profile`)
        // since a malformed origin is a config bug in development too, not
        // only production; `validate_production_profile` (below) separately
        // requires `https://` specifically, once profile is known.
        for (index, origin) in self.cors.allowed_origins.iter().enumerate() {
            Self::check_cors_origin(&format!("cors.allowed_origins[{index}]"), origin)?;
        }
        // P-data-protection-governance §4 "Region-assertion boot check" —
        // asserts a configured residency claim (`deployment.data_region`)
        // matches where the object store actually is (`storage.s3_region`),
        // so residency is verified rather than assumed. Unconditional (not
        // gated behind `validate_production_profile`/deployment_profile) —
        // a Bahrain/GCC/EU customer's dev deployment deserves the same
        // check as its production one, once it opts in. `None` (the
        // default — no residency claim configured) is a no-op, same "ships
        // dark" posture as `retention`/`idempotency`/`approval`.
        if let Some(data_region) = &self.deployment.data_region
            && !data_region.eq_ignore_ascii_case(&self.storage.s3_region)
        {
            return Err(ConfigError::Invalid {
                field: "deployment.data_region".into(),
                reason: format!(
                    "declared data_region {data_region:?} does not match storage.s3_region \
                     {:?} — a residency claim must match where the object store actually is, \
                     not silently drift out of sync with it",
                    self.storage.s3_region
                ),
            });
        }
        // D-585: staff and portal host sets (unconditional; empty sets are
        // today's behaviour).
        if let Err((field, reason)) = self.deployment.check_host_sets(&self.cors.allowed_origins) {
            return Err(ConfigError::Invalid { field, reason });
        }
        // P-environment-promotion §5 step 23 — `deployment.bundle_ref` and
        // `deployment.bundle_signing_public_key` are a pair: a bundle
        // reference with no key could never be verified before applying it
        // (never apply an unverified bundle — `bundle::pull`'s hard rule),
        // and a key with no reference configures nothing. Unconditional, not
        // gated behind `validate_production_profile`/deployment_profile —
        // a half-configured pair is a config bug in development too.
        match (
            &self.deployment.bundle_ref,
            &self.deployment.bundle_signing_public_key,
        ) {
            (Some(_), None) => {
                return Err(ConfigError::Invalid {
                    field: "deployment.bundle_ref".into(),
                    reason: "set without deployment.bundle_signing_public_key — a bundle_ref \
                             with no signer key could never be verified before applying it"
                        .into(),
                });
            }
            (None, Some(_)) => {
                return Err(ConfigError::Invalid {
                    field: "deployment.bundle_signing_public_key".into(),
                    reason: "set without deployment.bundle_ref — a signer key with nothing to \
                             verify configures nothing; set bundle_ref too or remove the key"
                        .into(),
                });
            }
            (Some(_), Some(_)) | (None, None) => {}
        }
        // D-352 (TODO-004 / H-1) — shape checks for `audit.anchor_store` that
        // hold in every profile, because a typo'd retention mode or a shared
        // bucket is a config bug in development too. The *policy* half (WORM
        // required at all) is production-only, in
        // `validate_production_profile` below.
        if let Some(anchor) = &self.audit.anchor_store {
            if !AnchorStoreSection::VALID_OBJECT_LOCK_MODES
                .contains(&anchor.object_lock_mode.as_str())
            {
                return Err(ConfigError::Invalid {
                    field: "audit.anchor_store.object_lock_mode".into(),
                    reason: format!(
                        "must be one of {:?}, got {:?} — this field declares what was actually \
                         provisioned on the bucket out-of-band, so an unrecognized value cannot \
                         be read as \"probably fine\"",
                        AnchorStoreSection::VALID_OBJECT_LOCK_MODES,
                        anchor.object_lock_mode
                    ),
                });
            }
            if anchor.s3_bucket.trim().is_empty() {
                return Err(ConfigError::Invalid {
                    field: "audit.anchor_store.s3_bucket".into(),
                    reason: "must be set when audit.anchor_store is configured at all — an empty \
                             bucket name would silently fall back to nothing"
                        .into(),
                });
            }
            // The single most important check in this block. Anchors in the
            // upload bucket cannot be immutable: that bucket's credential
            // holds `DeleteObject` by necessity (quarantine cleanup, the
            // orphan sweep, record erasure), and Object Lock retention on it
            // would break all three. Sharing the bucket is therefore not a
            // weaker configuration of this feature, it is the absence of it.
            if anchor.s3_bucket == self.storage.s3_bucket
                && anchor.s3_endpoint == self.storage.s3_endpoint
            {
                return Err(ConfigError::Insecure {
                    field: "audit.anchor_store.s3_bucket".into(),
                    reason: format!(
                        "must not be the same bucket as storage.s3_bucket ({:?}) on the same \
                         endpoint — the upload bucket's credential must keep DeleteObject for \
                         quarantine cleanup and record erasure, so that bucket can never carry \
                         Object Lock retention. Provision a separate bucket; see \
                         deploy/audit-anchor/README.md",
                        self.storage.s3_bucket
                    ),
                });
            }
        }
        // D-785 — `metadata.changesets` shape, every profile.
        if let Err((field, reason)) = self.metadata.changesets.check() {
            return Err(ConfigError::Invalid { field, reason });
        }
        // Solution 7 Phase 2 design §10.5 — `metadata.release_report` shape.
        if let Err((field, reason)) = self.metadata.release_report.check() {
            return Err(ConfigError::Invalid { field, reason });
        }
        // D-788 rule 9 — the recovery-archive ring is optional (absent = the
        // archive-needing operations fail closed), but a configured one must
        // be well formed: a malformed ring is a boot error, never a runtime
        // surprise on the first field delete.
        if !self.metadata.recovery_archive_key_encryption_key.is_empty() {
            Self::check_secret_ring(
                "metadata.recovery_archive_key_encryption_key",
                &self.metadata.recovery_archive_key_encryption_key,
                production,
            )?;
            Self::check_hex_key_ring(
                "metadata.recovery_archive_key_encryption_key",
                &self.metadata.recovery_archive_key_encryption_key,
            )?;
        }
        // D-792 — the fleet console section: shape in every profile; a
        // configured key ring must be well formed (the gate itself, which
        // requires the ring once the console is requested, lives in
        // `xrm_fleet::gate`). The production refusal is below, in
        // `validate_production_profile`.
        if let Err((field, reason)) = self.fleet.check() {
            return Err(ConfigError::Invalid { field, reason });
        }
        if let Err((field, reason)) = self.backup.check() {
            return Err(ConfigError::Invalid { field, reason });
        }
        if !self.fleet.credential_encryption_key.is_empty() {
            Self::check_secret_ring(
                "fleet.credential_encryption_key",
                &self.fleet.credential_encryption_key,
                production,
            )?;
            Self::check_hex_key_ring(
                "fleet.credential_encryption_key",
                &self.fleet.credential_encryption_key,
            )?;
        }
        self.validate_email_transport()?;
        const VALID_DEPLOYMENT_PROFILES: &[&str] = &["development", "production"];
        if !VALID_DEPLOYMENT_PROFILES.contains(&self.app.deployment_profile.as_str()) {
            return Err(ConfigError::Invalid {
                field: "app.deployment_profile".into(),
                reason: format!(
                    "must be one of {VALID_DEPLOYMENT_PROFILES:?}, got {:?}",
                    self.app.deployment_profile
                ),
            });
        }
        if self.app.deployment_profile == "production" {
            self.validate_production_profile()?;
        }
        Ok(())
    }

    /// P-production-safety-profile — refuses to boot with any of the
    /// individually-valid-but-unsafe-in-combination defaults
    /// `config.example.json` ships (a dev template, D-099) still active. Only
    /// runs when `app.deployment_profile = "production"` — see that field's
    /// doc comment. No per-check escape hatch: every condition here is a hard
    /// boot error, not a warning, since a hatch on any one of them reopens
    /// exactly the gap this profile closes.
    /// BEM-5 (attome-email plan §4.3) — the SMTP transport security mode.
    ///
    /// `email.tls_mode` is the typed replacement for the deprecated
    /// `smtp_use_tls` bool: `"implicit"` (SMTPS, the default),
    /// `"starttls"` (the upgrade is required — lettre aborts the session if
    /// the relay does not offer it), or `"none"` (plaintext). An unrecognized
    /// value is a hard error rather than a silent fallback to a weaker mode.
    ///
    /// Plaintext is refused outside `APP_ENV=debug`, where the only
    /// legitimate users are the loopback SMTP sinks in `docker-compose.yml`:
    /// `auth()` in lettre has no encryption check, so over `none` a relay
    /// that advertises AUTH before TLS receives the deployment's SMTP password
    /// in clear (F5/BEM-D4).
    ///
    /// The deprecated bool still maps — BEM-D4's one-release compatibility, so
    /// an existing `config.json` keeps booting byte-identically — but the
    /// credential rule below applies whichever key selected the mode.
    fn validate_email_transport(&self) -> Result<(), ConfigError> {
        const MODES: &[&str] = &["implicit", "starttls", "none"];
        if let Some(mode) = self.email.tls_mode.as_deref() {
            if !MODES.contains(&mode) {
                return Err(ConfigError::Invalid {
                    field: "email.tls_mode".into(),
                    reason: format!("must be one of {MODES:?}, got {mode:?}"),
                });
            }
            if mode == "none" && !crate::is_debug_env() {
                return Err(ConfigError::Insecure {
                    field: "email.tls_mode".into(),
                    reason: "must not be \"none\" outside APP_ENV=debug — a plaintext SMTP \
                             session puts credentials and message bodies on the wire in clear \
                             text; use \"implicit\" (SMTPS) or \"starttls\""
                        .into(),
                });
            }
        }
        // No credential rides a plaintext link off this machine, whichever key
        // selected the mode. `attome-email`'s transport builder refuses the same
        // case at runtime; this is the boot-time half, so the mistake is named
        // at config time rather than at the first password reset.
        if self.email.effective_tls_mode() == "none"
            && !self.email.smtp_user.is_empty()
            && !is_loopback_smtp_host(&self.email.smtp_host)
        {
            return Err(ConfigError::Insecure {
                field: "email.tls_mode".into(),
                reason: format!(
                    "email.smtp_user is set but the effective transport mode is \"none\" for \
                     the non-loopback host {:?} — the SMTP password would cross the network in \
                     clear; use \"implicit\" or \"starttls\"",
                    self.email.smtp_host
                ),
            });
        }
        Ok(())
    }

    fn validate_production_profile(&self) -> Result<(), ConfigError> {
        // D-792 (FLEET-CONSOLE-DESIGN.md §2.3) — a production server must
        // never carry the fleet key or any fleet setting. First, so the
        // refusal names the fleet section rather than whichever unrelated
        // production check a developer config would fail next.
        if let Some((field, reason)) = self.fleet.production_refusal() {
            return Err(ConfigError::Insecure { field, reason });
        }
        // BCF-3/BCF-D1 — the shipped-template denylist for credentials the
        // `check_secret` family never sees. `check_secret`/`check_secret_ring`
        // cover the key-material secrets (JWT, peppers, encryption keys) via
        // their own `production` flag; these are the connection/API
        // credentials that previously had no shape check at all, so a
        // production node booted happily on `DB_PASSWORD=change_me`.
        if let Some(password) = self.database.password.as_ref().map(Secret::expose) {
            Self::check_not_template_secret("database.password", password)?;
        }
        if let Some(readonly) = &self.database.readonly {
            Self::check_not_template_secret(
                "database.readonly.password",
                readonly.password.expose(),
            )?;
        }
        if let Some(migrator) = &self.database.migrator {
            Self::check_not_template_secret(
                "database.migrator.password",
                migrator.password.expose(),
            )?;
        }
        if let Some(runtime) = &self.database.runtime {
            Self::check_not_template_secret(
                "database.runtime.password",
                runtime.password.expose(),
            )?;
        }
        Self::check_not_template_secret("cache.password", self.cache.password.expose())?;
        if let Some(coordination) = &self.cache.roles.coordination {
            Self::check_not_template_secret(
                "cache.roles.coordination.password",
                coordination.password.expose(),
            )?;
            if let Some(sentinel) = &coordination.sentinel
                && let Some(password) = sentinel.sentinel_password.as_ref().map(Secret::expose)
            {
                Self::check_not_template_secret(
                    "cache.roles.coordination.sentinel.sentinel_password",
                    password,
                )?;
            }
        }
        if let Some(sentinel) = &self.cache.sentinel
            && let Some(password) = sentinel.sentinel_password.as_ref().map(Secret::expose)
        {
            Self::check_not_template_secret("cache.sentinel.sentinel_password", password)?;
        }
        Self::check_not_template_secret("storage.s3_access_key", &self.storage.s3_access_key)?;
        Self::check_not_template_secret(
            "storage.s3_secret_key",
            self.storage.s3_secret_key.expose(),
        )?;
        if self.email.enabled {
            Self::check_not_template_secret(
                "email.smtp_password",
                self.email.smtp_password.expose(),
            )?;
        }
        if let Some(anchor) = &self.audit.anchor_store {
            Self::check_not_template_secret(
                "audit.anchor_store.s3_access_key",
                &anchor.s3_access_key,
            )?;
            Self::check_not_template_secret(
                "audit.anchor_store.s3_secret_key",
                anchor.s3_secret_key.expose(),
            )?;
        }
        for (field, api_key) in [
            (
                "inference.generation.api_key",
                &self.inference.generation.api_key,
            ),
            (
                "inference.embedding.api_key",
                &self.inference.embedding.api_key,
            ),
        ] {
            if let Some(api_key) = api_key {
                Self::check_not_template_secret(field, api_key.expose())?;
            }
        }
        if self.database.ssl_mode != "verify-full" {
            return Err(ConfigError::Insecure {
                field: "database.ssl_mode".into(),
                reason: format!(
                    "must be \"verify-full\" when app.deployment_profile = \"production\" — got \
                     {:?}; \"prefer\" (the template default) accepts an unauthenticated server \
                     and a transparently-downgraded plaintext connection",
                    self.database.ssl_mode
                ),
            });
        }
        if !self.cache.tls_enabled {
            return Err(ConfigError::Insecure {
                field: "cache.tls_enabled".into(),
                reason: "must be true when app.deployment_profile = \"production\" — the template \
                         default (false) connects to Redis/Dragonfly in plaintext"
                    .into(),
            });
        }
        if let Some(coordination) = &self.cache.roles.coordination
            && !coordination.tls_enabled
        {
            return Err(ConfigError::Insecure {
                field: "cache.roles.coordination.tls_enabled".into(),
                reason: "must be true when app.deployment_profile = \"production\" — this role \
                         has its own endpoint and its own TLS switch, independent of \
                         cache.tls_enabled above"
                    .into(),
            });
        }
        if !self.storage.s3_verify_ssl {
            return Err(ConfigError::Insecure {
                field: "storage.s3_verify_ssl".into(),
                reason: "must be true when app.deployment_profile = \"production\" — false \
                         accepts any certificate from the S3-compatible endpoint, defeating \
                         TLS verification"
                    .into(),
            });
        }
        // D-501 — same rule as audit.anchor_store.s3_endpoint below. The
        // endpoint's scheme alone decides plaintext vs TLS; `s3_verify_ssl`
        // only governs certificate verification, so it does not make an
        // `http://` endpoint safe.
        if !self.storage.s3_endpoint.is_empty() && !self.storage.s3_endpoint.starts_with("https://")
        {
            return Err(ConfigError::Insecure {
                field: "storage.s3_endpoint".into(),
                reason: format!(
                    "must use \"https://\" when app.deployment_profile = \"production\", got \
                     {:?} (an empty endpoint selects AWS S3 proper, which is always TLS)",
                    self.storage.s3_endpoint
                ),
            });
        }
        if !self.storage.s3_public_endpoint.is_empty()
            && !self.storage.s3_public_endpoint.starts_with("https://")
        {
            return Err(ConfigError::Insecure {
                field: "storage.s3_public_endpoint".into(),
                reason: format!(
                    "must use \"https://\" when app.deployment_profile = \"production\", got \
                     {:?} (browsers upload and download through presigned URLs signed for \
                     this address; leave it empty to sign for storage.s3_endpoint)",
                    self.storage.s3_public_endpoint
                ),
            });
        }
        if !self.security.csrf_enforce {
            return Err(ConfigError::Insecure {
                field: "security.csrf_enforce".into(),
                reason: "must be true when app.deployment_profile = \"production\" — false \
                         downgrades the Origin/Sec-Fetch-Metadata CSRF check to log-only \
                         (attome_server::middleware::csrf), silently letting a rejected \
                         cross-site cookie-authenticated request through"
                    .into(),
            });
        }
        // BCF-4 (finding BCF-F6) — the third sibling of csrf_enforce/
        // csp_enforce/strict_revocation, and the one that was missing from this
        // profile: false skips the always-on fail-closed authz-epoch re-check
        // ahead of the privileged/admin-gated route bundles (D-116), so a
        // just-revoked admin keeps using a still-live L1 cache entry for the
        // rest of the 60s TTL. bcf-config's
        // `every_security_kill_switch_is_production_gated` test keeps a new
        // default-true security bool from landing ungated like this one did.
        if !self.security.strict_privileged_authz {
            return Err(ConfigError::Insecure {
                field: "security.strict_privileged_authz".into(),
                reason: "must be true when app.deployment_profile = \"production\" — false \
                         skips the fail-closed authz-epoch re-check ahead of the privileged/\
                         admin-gated route bundles (D-116), so a just-revoked administrator \
                         keeps performing privileged operations from a still-live L1 cache \
                         entry for the rest of the 60s TTL"
                    .into(),
            });
        }
        if !self.security.csp_enforce {
            return Err(ConfigError::Insecure {
                field: "security.csp_enforce".into(),
                reason: "must be true when app.deployment_profile = \"production\" — false \
                         downgrades the response Content-Security-Policy header to \
                         Content-Security-Policy-Report-Only (attome_server::middleware::\
                         security_headers), observing violations instead of blocking them, a \
                         diagnostic rollout toggle that must not stay silently on in a real \
                         deployment"
                    .into(),
            });
        }
        // 180 days, not the one-year default: a deployment deliberately
        // running a shorter window during an HSTS rollout is a legitimate
        // posture, a deployment with the header off (0) or set to a token
        // few-minutes value is not — that leaves the very first request of
        // each browsing session downgradeable, which is the whole attack
        // HSTS exists to close.
        const MIN_PRODUCTION_HSTS_MAX_AGE: u64 = 15_552_000;
        if self.security.hsts_max_age_secs < MIN_PRODUCTION_HSTS_MAX_AGE {
            return Err(ConfigError::Insecure {
                field: "security.hsts_max_age_secs".into(),
                reason: format!(
                    "must be at least {MIN_PRODUCTION_HSTS_MAX_AGE} (180 days) when \
                     app.deployment_profile = \"production\" — 0 omits the \
                     Strict-Transport-Security header entirely and a short max-age leaves \
                     the first request of each session strippable to plain http \
                     (attome_server::middleware::security_headers)"
                ),
            });
        }
        if !self.security.strict_revocation {
            return Err(ConfigError::Insecure {
                field: "security.strict_revocation".into(),
                reason: "must be true when app.deployment_profile = \"production\" — false lets \
                         `XrmSecurityResolver::resolve` (xrm-security/src/cache.rs) skip the \
                         fail-closed authz-epoch re-check on ordinary (non-privileged-bundle) \
                         requests, reopening up to a 60s cross-node staleness window on a \
                         revoked privilege/role/field-security grant (D-027/D-116)"
                    .into(),
            });
        }
        if self.auth.apikey_default_expiry_days.is_none() {
            return Err(ConfigError::Insecure {
                field: "auth.apikey_default_expiry_days".into(),
                reason: "must be set when app.deployment_profile = \"production\" — null (the \
                         template default) mints API keys with no expiry unless every caller \
                         remembers to pass one explicitly"
                    .into(),
            });
        }
        if self.auth.registration_mode == "public" && !self.auth.require_verified_email {
            return Err(ConfigError::Insecure {
                field: "auth.require_verified_email".into(),
                reason: "must be true when app.deployment_profile = \"production\" and \
                         auth.registration_mode = \"public\" — open self-registration with no \
                         email-ownership check lets anyone claim any email address"
                    .into(),
            });
        }
        if !self.audit.signing_enabled {
            return Err(ConfigError::Insecure {
                field: "audit.signing_enabled".into(),
                reason: "must be true when app.deployment_profile = \"production\" — \
                         hash-chaining alone (today's default) is tamper-evident but not \
                         non-repudiable; signing_enabled adds the Ed25519 signature this profile \
                         requires"
                    .into(),
            });
        }
        // D-316 (engineering review 2026-08-10, F-001/F-010). The sync path
        // serializes every mutation in the deployment on one per-organization
        // advisory lock — D-002 means one organization, so one lock for the
        // whole system — and the review reproduced ordinary concurrent saves
        // failing with `Conflict` once the 200 × 5 ms retry budget ran out,
        // each retry sleeping inside an open transaction holding a pooled
        // connection. That is a throughput ceiling and a pool-pressure
        // amplifier, not a security control, which is why this check reads
        // "the sync path is a dev-only mode" rather than "the async path is
        // an optimization". `audit_chainer` MUST be deployed alongside the
        // server for this to be true — see config.production.example.json's
        // comment on the same field and docker-compose.yml's `audit_chainer`
        // service.
        if !self.audit.chainer_enabled {
            return Err(ConfigError::Insecure {
                field: "audit.chainer_enabled".into(),
                reason:
                    "must be true when app.deployment_profile = \"production\" — false selects \
                         the pre-P1.13 synchronous audit append, which holds a per-organization \
                         advisory lock inside every mutation's own transaction and fails ordinary \
                         concurrent saves with 409 Conflict once its retry budget runs out \
                         (D-316). Deploy the `audit_chainer` process alongside the server; \
                         without it, events stay durably captured in xrm_audit_ingest but are \
                         never chained, and the ingest backlog gate eventually refuses mutations"
                        .into(),
            });
        }
        // D-540 ruling 1 (audit 10/10 plan item 2.7). Hash v2 (D-539) digests
        // audit values as stored, and D-540 makes the stored form ciphertext
        // in production: detail values, lookup names, snapshots, remarks, IP
        // and user agent under per-record or per-actor keys, so erasure
        // (`destroy_key`) destroys recoverability without changing a hashed
        // byte (I3). A production deployment writing plaintext would store
        // personal data the ledger can never erase. `validate()` above already
        // checked the ring's format whenever encryption is active; this adds
        // "must be active" and "not the published development key".
        // Upgrade obligation: provision the key before upgrading, or boot
        // refuses (config.production.example.json, D-540 consequences).
        if !self.audit.erasure_active() {
            return Err(ConfigError::Insecure {
                field: "audit.erasure_enabled".into(),
                reason: "must be active when app.deployment_profile = \"production\" — set \
                         audit.erasure_key_encryption_key (64 hex chars, openssl rand -hex 32; \
                         a dedicated key) and leave erasure_enabled unset or true. Without it \
                         audit field values, snapshots, remarks, IP addresses and user agents \
                         are stored in plaintext and personal data in the ledger can never be \
                         erased (D-540)"
                    .into(),
            });
        }
        if self.audit.erasure_key_encryption_key.is_empty() {
            return Err(ConfigError::Insecure {
                field: "audit.erasure_key_encryption_key".into(),
                reason: "must hold at least one key when app.deployment_profile = \
                         \"production\" (D-540)"
                    .into(),
            });
        }
        for (key_id, value) in &self.audit.erasure_key_encryption_key.keys {
            if value.eq_ignore_ascii_case(super::sections::audit::DEVELOPMENT_ERASURE_KEY) {
                return Err(ConfigError::Insecure {
                    field: format!("audit.erasure_key_encryption_key.keys.{key_id}"),
                    reason: "is the public development key config.example.json ships — it \
                             protects nothing; generate a dedicated key with openssl rand -hex 32"
                        .into(),
                });
            }
        }
        // D-352 (TODO-004, review finding H-1). Anchoring's entire claim is
        // that a party who compromised this deployment — DB and app config
        // together, D-016's threat model — cannot silently rewrite history,
        // because a copy of each batch's Merkle root sits somewhere they
        // cannot reach. D-174 shipped the write path but anchored to the
        // deployment's own upload bucket with the deployment's own
        // credential, which that same party holds; `PutMode::Create` stops
        // *this application* overwriting an anchor and stops nothing else.
        // The bucket-side control (Object Lock retention) and the
        // identity-side control (an append-only producer credential, with
        // delete/retention authority held by an operator identity that never
        // touches this host) are both infrastructure, provisioned before boot
        // — application code cannot enable either. What it CAN do is refuse
        // to run while claiming a guarantee it does not have, which is what
        // this block is. Both controls are required together for the same
        // reason deploy/backup/README.md gives for the backup bucket: an
        // immutable destination without a locked-down producer still lets a
        // compromised credential exhaust the bucket, and a locked-down
        // producer without an immutable destination has no backstop when that
        // credential's restrictions are what got bypassed.
        if self.audit.external_anchoring_enabled {
            let Some(anchor) = &self.audit.anchor_store else {
                return Err(ConfigError::Insecure {
                    field: "audit.anchor_store".into(),
                    reason: "must be configured when audit.external_anchoring_enabled = true and \
                             app.deployment_profile = \"production\" — without it anchors are \
                             written to the general storage.s3_bucket with the application's own \
                             credential, which necessarily holds DeleteObject (quarantine \
                             cleanup, record erasure) and can therefore delete the very records \
                             anchoring exists to place beyond its own reach. Provision a \
                             dedicated Object Lock bucket and an append-only producer \
                             credential first; see deploy/audit-anchor/README.md"
                        .into(),
                });
            };
            if !anchor.declares_worm() {
                return Err(ConfigError::Insecure {
                    field: "audit.anchor_store.object_lock_mode".into(),
                    reason: format!(
                        "must be \"compliance\" or \"governance\" when \
                         audit.external_anchoring_enabled = true and app.deployment_profile = \
                         \"production\" — got {:?}. \"none\" means the bucket has no retention \
                         backstop, so the anchor's immutability rests entirely on the producer \
                         credential's permissions holding, with nothing behind them if they do \
                         not. Provision Object Lock (it cannot be retrofitted onto an existing \
                         bucket) and set this to the mode you actually configured; run \
                         scripts/audit/anchor-immutability-drill.sh to prove it",
                        anchor.object_lock_mode
                    ),
                });
            }
            if anchor.object_lock_retention_days == 0 {
                return Err(ConfigError::Insecure {
                    field: "audit.anchor_store.object_lock_retention_days".into(),
                    reason: "must be at least 1 when audit.external_anchoring_enabled = true and \
                             app.deployment_profile = \"production\" — a zero-day retention is \
                             an Object Lock configuration that locks nothing, and it fails in \
                             the worst possible way: the chain reads as anchored right up until \
                             the moment someone needs the anchor. Set it to at least this \
                             deployment's audit-retention obligation (retention.audit_days)"
                        .into(),
                });
            }
            if !anchor.s3_verify_ssl {
                return Err(ConfigError::Insecure {
                    field: "audit.anchor_store.s3_verify_ssl".into(),
                    reason: "must be true when app.deployment_profile = \"production\" — false \
                             accepts any certificate from the anchor endpoint, so an on-path \
                             attacker can serve whatever anchor bytes a verification drill \
                             asks for. Same rule, same reason, as storage.s3_verify_ssl"
                        .into(),
                });
            }
            if !anchor.s3_endpoint.is_empty() && !anchor.s3_endpoint.starts_with("https://") {
                return Err(ConfigError::Insecure {
                    field: "audit.anchor_store.s3_endpoint".into(),
                    reason: format!(
                        "must use \"https://\" when app.deployment_profile = \"production\", got \
                         {:?} (an empty endpoint selects AWS S3 proper, which is always TLS)",
                        anchor.s3_endpoint
                    ),
                });
            }
            Self::check_not_placeholder("audit.anchor_store.s3_endpoint", &anchor.s3_endpoint)?;
            Self::check_not_placeholder("audit.anchor_store.s3_bucket", &anchor.s3_bucket)?;
            Self::check_not_placeholder("audit.anchor_store.s3_access_key", &anchor.s3_access_key)?;
            if anchor.s3_access_key.trim().is_empty()
                || anchor.s3_secret_key.expose().trim().is_empty()
            {
                return Err(ConfigError::Insecure {
                    field: "audit.anchor_store.s3_access_key".into(),
                    reason: "both s3_access_key and s3_secret_key must be set when \
                             audit.external_anchoring_enabled = true and app.deployment_profile \
                             = \"production\" — this is the dedicated append-only producer \
                             identity, deliberately NOT storage.s3_access_key, which holds \
                             DeleteObject"
                        .into(),
                });
            }
            // Reusing the upload credential defeats the identity-side half
            // even when the bucket is genuinely separate and genuinely
            // locked: that credential is the one a deployment compromise
            // hands over, and on a governance-mode bucket it is exactly the
            // thing a BypassGovernanceRetention grant would be attached to.
            if anchor.s3_access_key == self.storage.s3_access_key {
                return Err(ConfigError::Insecure {
                    field: "audit.anchor_store.s3_access_key".into(),
                    reason: "must not be the same credential as storage.s3_access_key — that \
                             identity holds DeleteObject on the upload bucket and is what a \
                             deployment compromise yields. The anchor producer identity carries \
                             PutObject/GetObject/ListBucket and nothing else; see \
                             deploy/audit-anchor/aws-iam-anchor-producer-policy.json"
                        .into(),
                });
            }
        }
        if self.database.migrate_on_boot {
            return Err(ConfigError::Insecure {
                field: "database.migrate_on_boot".into(),
                reason: "must be false when app.deployment_profile = \"production\" — schema \
                         bootstrap/migrations/role-password-seeding must run as the dedicated \
                         one-shot `migrate` binary ahead of the deploy, not inline in every \
                         long-lived server process holding DDL-capable credentials"
                    .into(),
            });
        }
        // B7 (technical due diligence 2026-08-24). Until now the only thing
        // standing between a production node and running every request's
        // record CRUD as the DDL-capable bootstrap identity was
        // `crates/server/src/boot.rs`'s `APP_ENV != "debug"` check — a
        // process-environment gate, not a config one, so a container that
        // inherited `APP_ENV=debug` from a dev compose file booted a
        // production profile straight onto `database.user`. The profile is
        // the declaration that this IS a real deployment, so the
        // least-privilege runtime role is required here, unconditionally,
        // with no environment-variable opt-out. `database.migrator` is
        // deliberately not added alongside: the `migrate` binary's config
        // (config.production.example.json) legitimately carries the bootstrap
        // identity for the role-password seeds, and boot.rs's gate on that
        // field remains in force for the long-lived processes.
        if self.database.runtime.is_none() {
            return Err(ConfigError::Insecure {
                field: "database.runtime".into(),
                reason: "must be set when app.deployment_profile = \"production\" — without it \
                         ordinary request-time record CRUD (attome_db::create_pool, the pool every \
                         entity handler uses) falls back to database.user/.password, the \
                         DDL-capable schema-bootstrap identity that owns every table and can \
                         CREATE ROLE, so any SQL-level defect in a request path runs with the \
                         migration owner's privileges. Create the DML-only attome_runtime role \
                         (migrations/0042_migrator_runtime_roles.sql; the `migrate` binary \
                         applies its password via server::db_role_seed::seed_runtime) and set \
                         database.runtime = { \"user\": \"attome_runtime\", \"password\": \
                         \"${DB_RUNTIME_PASSWORD}\" } as config.production.example.json and \
                         config.production.runtime.example.json both already do"
                    .into(),
            });
        }
        if self.jobs.run_worker_inline {
            return Err(ConfigError::Insecure {
                field: "jobs.run_worker_inline".into(),
                reason: "must be false when app.deployment_profile = \"production\" — the job \
                         worker must run as its own scaled `worker` binary/process, not inline in \
                         the HTTP-serving process"
                    .into(),
            });
        }
        // config.production.example.json's own `_readme` tells an operator to
        // "replace every __TODO__ placeholder with a real deployment value",
        // but until this point nothing actually enforced that instruction —
        // every field below deserializes fine and passes every check above
        // with the literal template string still in place (proven by the
        // config_production_example_deserializes_and_validates test, which
        // needed zero substitutions beyond ${VAR} expansion and the one CIDR
        // swap trusted_proxy_cidrs already required for unrelated reasons).
        // A production boot with an unresolved placeholder here fails DNS/TLS
        // for that field's endpoint anyway; catching it here turns that into
        // an actionable boot-time error instead of an opaque connect failure.
        Self::check_not_placeholder("app.frontend_host", &self.app.frontend_host)?;
        if let Some(url) = &self.app.public_frontend_url {
            Self::check_not_placeholder("app.public_frontend_url", url)?;
            // BCF-18 (finding BCF-F18): only the `__TODO__` placeholder was
            // refused, so a real-but-plain-http value shipped. Password reset,
            // invitation and email-verification links are built from this URL,
            // and following one over plain http puts its single-use token on
            // the wire in clear text.
            if !url.starts_with("https://") {
                return Err(ConfigError::Insecure {
                    field: "app.public_frontend_url".into(),
                    reason: format!(
                        "must use \"https://\" when app.deployment_profile = \"production\", got \
                         {url:?} — password-reset, invitation and verification links are built \
                         from this URL, and a plain-http one carries its single-use token in \
                         clear text"
                    ),
                });
            }
        }
        Self::check_not_placeholder("database.host", &self.database.host)?;
        if let Some(cert) = &self.database.ssl_root_cert {
            Self::check_not_placeholder("database.ssl_root_cert", cert)?;
        }
        Self::check_not_placeholder("cache.host", &self.cache.host)?;
        if let Some(path) = &self.cache.tls_ca_path {
            Self::check_not_placeholder("cache.tls_ca_path", path)?;
        }
        Self::check_not_placeholder("storage.s3_endpoint", &self.storage.s3_endpoint)?;
        Self::check_not_placeholder("storage.clamd_address", &self.storage.clamd_address)?;
        if self.email.enabled {
            Self::check_not_placeholder("email.smtp_host", &self.email.smtp_host)?;
            Self::check_not_placeholder("email.smtp_user", &self.email.smtp_user)?;
            Self::check_not_placeholder("email.smtp_from_address", &self.email.smtp_from_address)?;
        }
        for (index, origin) in self.cors.allowed_origins.iter().enumerate() {
            let field = format!("cors.allowed_origins[{index}]");
            Self::check_not_placeholder(&field, origin)?;
            if !origin.starts_with("https://") {
                return Err(ConfigError::Insecure {
                    field,
                    reason: format!(
                        "must use \"https://\" when app.deployment_profile = \"production\", got {origin:?}"
                    ),
                });
            }
        }
        Ok(())
    }

    /// See the `_readme`/`__TODO__` comment at this function's call site in
    /// `validate_production_profile` — every field checked there ships in
    /// config.production.example.json as a literal `"__TODO__: ..."` or bare
    /// `"__TODO__"` string an operator is instructed to replace. Matching on
    /// the `__TODO__` prefix (not just "non-empty") deliberately still allows
    /// a field's other legitimate empty/absent state through, e.g.
    /// `storage.clamd_address = ""` intentionally fails malware scanning
    /// closed rather than pointing at a real clamd host.
    fn check_not_placeholder(field: &str, value: &str) -> Result<(), ConfigError> {
        if value.trim_start().starts_with("__TODO__") {
            return Err(ConfigError::Invalid {
                field: field.into(),
                reason: "still contains config.production.example.json's \"__TODO__\" \
                         placeholder — replace it with a real deployment value before \
                         app.deployment_profile = \"production\" can boot"
                    .into(),
            });
        }
        Ok(())
    }

    /// Validates one `cors.allowed_origins` entry as an exact origin —
    /// `scheme://host[:port]` and nothing else: no path/query/fragment, no
    /// embedded userinfo (`user@`/`user:pass@`), no `*` wildcard, and a
    /// syntactically valid host/port. Deliberately hand-rolled rather than
    /// pulling in the `url` crate — same reasoning as `mod urlencoding`
    /// below: this workspace has no URL-parsing dependency today, and the
    /// grammar this needs to check (bare origin, not a general URL) is small
    /// enough to keep local. Scheme is restricted to `http`/`https` here;
    /// `validate_production_profile` layers an additional `https://`-only
    /// requirement once `app.deployment_profile` is known.
    fn check_cors_origin(field: &str, origin: &str) -> Result<(), ConfigError> {
        let fail = |reason: String| {
            Err(ConfigError::Invalid {
                field: field.into(),
                reason,
            })
        };
        if origin == "*" {
            return fail(
                "must not be a wildcard — CORS is used with allow_credentials(true), which the \
                 fetch/XHR spec forbids combining with \"*\""
                    .into(),
            );
        }
        let Some((scheme, rest)) = origin.split_once("://") else {
            return fail(format!(
                "must be an absolute origin \"scheme://host[:port]\" (e.g. \
                 \"https://app.example.com\"), got {origin:?}"
            ));
        };
        if scheme != "http" && scheme != "https" {
            return fail(format!(
                "scheme must be \"http\" or \"https\", got {scheme:?}"
            ));
        }
        if rest.contains('@') {
            return fail(
                "must not embed credentials — a \"user@\" or \"user:pass@\" prefix before the \
                 host is not a valid origin"
                    .into(),
            );
        }
        if let Some(bad) = rest.find(['/', '?', '#']) {
            return fail(format!(
                "must be an origin only — no path/query/fragment, found {:?} at byte {bad}",
                &rest[bad..=bad]
            ));
        }
        let (host, port) = if let Some(after_bracket) = rest.strip_prefix('[') {
            // IPv6 literal, e.g. "[::1]" or "[::1]:4200" — the host itself
            // contains colons, so it can't go through the plain
            // rsplit_once(':') path below.
            let Some(end) = after_bracket.find(']') else {
                return fail("unterminated IPv6 literal — missing closing \"]\"".into());
            };
            let host = &after_bracket[..end];
            match after_bracket[end + 1..].strip_prefix(':') {
                Some(port) => (host, Some(port)),
                None if after_bracket[end + 1..].is_empty() => (host, None),
                None => {
                    return fail("unexpected characters after IPv6 literal's closing \"]\"".into());
                }
            }
        } else {
            match rest.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (rest, None),
            }
        };
        if host.is_empty() {
            return fail("missing host".into());
        }
        if let Some(port) = port
            && port.parse::<u16>().is_err()
        {
            return fail(format!("port {port:?} is not a valid 16-bit port number"));
        }
        Ok(())
    }

    /// P-redis-sentinel-config — `sentinelServiceName` is required by fred's
    /// `from_url_sentinel` itself; catching an empty one here fails closed at
    /// boot (D-038) instead of surfacing as an opaque `RedisError` the first
    /// time `create_redis_pool`/`create_role_redis_pool` connects.
    fn check_sentinel(field: &str, sentinel: &CacheSentinelConfig) -> Result<(), ConfigError> {
        if sentinel.service_name.trim().is_empty() {
            return Err(ConfigError::Invalid {
                field: format!("{field}.service_name"),
                reason: "required in sentinel mode — this is fred's sentinelServiceName, the \
                         name sentinel knows the monitored master by"
                    .into(),
            });
        }
        for (index, node) in sentinel.nodes.iter().enumerate() {
            if node.host.trim().is_empty() {
                return Err(ConfigError::Invalid {
                    field: format!("{field}.nodes[{index}].host"),
                    reason: "must not be empty".into(),
                });
            }
        }
        Ok(())
    }

    /// BCF-3/BCF-D1 — refuse a secret value shipped in this repository's
    /// templates. Production only: `config.example.json` deliberately ships
    /// throwaway values for the dev stack, and only a declared production node
    /// must refuse them.
    fn check_not_template_secret(field: &str, value: &str) -> Result<(), ConfigError> {
        if let Some(marker) = template_secret_marker(value) {
            return Err(ConfigError::Insecure {
                field: field.into(),
                reason: format!(
                    "is a value shipped in this repository's templates (matched {marker:?}) — it \
                     is publicly known, so it protects nothing; generate a real secret \
                     (`openssl rand -hex 32` for key material) and set it from the environment"
                ),
            });
        }
        Ok(())
    }

    /// `production` selects the shipped-template denylist (BCF-3); the
    /// unresolved-placeholder and minimum-length rules hold in every profile.
    fn check_secret(field: &str, value: &str, production: bool) -> Result<(), ConfigError> {
        if value.contains("${") {
            return Err(ConfigError::Insecure {
                field: field.into(),
                reason: "unresolved ${...} placeholder — the environment variable was not set"
                    .into(),
            });
        }
        if value.len() < 32 {
            return Err(ConfigError::Insecure {
                field: field.into(),
                reason: "must be at least 32 bytes".into(),
            });
        }
        if production {
            Self::check_not_template_secret(field, value)?;
        }
        Ok(())
    }

    /// P-key-rotation-and-jwt (a) — `check_secret` extended to every key in a
    /// ring, not just the active one: a retired key still sitting in the ring
    /// for its overlap window is exactly as security-sensitive as the active
    /// one (it still decrypts real data / verifies real tokens), so an
    /// unresolved `${VAR}` or too-short value anywhere in the map is just as
    /// much a boot error as one in the active slot.
    /// Z4-T3: an Ed25519 seed ring is optional, but every key in it is 64 hex
    /// characters and a non-empty ring names an active key. The message
    /// names the key id, never its value.
    fn check_signing_seeds(field: &str, ring: &KeyRing) -> Result<(), ConfigError> {
        if ring.is_empty() {
            return Ok(());
        }
        if ring.active().is_none() {
            return Err(ConfigError::Invalid {
                field: field.into(),
                reason: format!(
                    "active_key_id {:?} does not name any entry in keys",
                    ring.active_key_id
                ),
            });
        }
        Self::check_key_ring_ids(field, ring)?;
        for (key_id, seed) in &ring.keys {
            if seed.len() != 64 || !seed.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ConfigError::Invalid {
                    field: format!("{field}.keys.{key_id}"),
                    reason: "an Ed25519 seed is 32 bytes written as 64 hex characters".into(),
                });
            }
        }
        Ok(())
    }

    fn check_secret_ring(field: &str, ring: &KeyRing, production: bool) -> Result<(), ConfigError> {
        if ring.is_empty() {
            return Err(ConfigError::Insecure {
                field: field.into(),
                reason: "must be set (at least one key) when this feature is enabled".into(),
            });
        }
        if ring.active().is_none() {
            return Err(ConfigError::Invalid {
                field: field.into(),
                reason: format!(
                    "active_key_id {:?} does not name any entry in keys",
                    ring.active_key_id
                ),
            });
        }
        Self::check_key_ring_ids(field, ring)?;
        for (key_id, value) in &ring.keys {
            Self::check_secret(&format!("{field}.keys.{key_id}"), value, production)?;
        }
        Ok(())
    }

    /// BCF-7 — every ring id is a non-empty, printable-ASCII string of at most
    /// 255 bytes (it is persisted in the encrypted blob's header).
    fn check_key_ring_ids(field: &str, ring: &KeyRing) -> Result<(), ConfigError> {
        for key_id in ring.keys.keys() {
            if key_id.is_empty() {
                return Err(ConfigError::Invalid {
                    field: field.into(),
                    reason: "a keys entry has an empty id".into(),
                });
            }
            if key_id.len() > 255 {
                return Err(ConfigError::Invalid {
                    field: field.into(),
                    reason: format!("key id {key_id:?} is longer than 255 bytes"),
                });
            }
            if !key_id.bytes().all(|byte| byte.is_ascii_graphic()) {
                return Err(ConfigError::Invalid {
                    field: field.into(),
                    reason: format!("key id {key_id:?} must be printable ASCII"),
                });
            }
        }
        Ok(())
    }

    /// BCF-7 — 32 bytes of AES-256 key material is exactly 64 hex characters.
    /// `check_secret` alone is length-only, so a 40-character non-hex
    /// `audit.signing_private_key` used to pass and panic in
    /// `XrmState::new`.
    fn check_hex_key(field: &str, value: &str) -> Result<(), ConfigError> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ConfigError::Invalid {
                field: field.into(),
                reason: format!(
                    "must be 64 hex characters (32 bytes — generate with `openssl rand -hex 32`), got {} characters",
                    value.len()
                ),
            });
        }
        Ok(())
    }

    fn check_hex_key_ring(field: &str, ring: &KeyRing) -> Result<(), ConfigError> {
        for (key_id, value) in &ring.keys {
            Self::check_hex_key(&format!("{field}.keys.{key_id}"), value)?;
        }
        Ok(())
    }
}

/// S1 (BSV-F13 / BSV-D11) — the upper bound on
/// `app.shutdown_drain_delay_secs`. Past this the "temporarily not ready"
/// window is longer than any load balancer will keep a node in rotation
/// anyway, so a larger value is a configuration mistake rather than a tuning
/// choice (0 stays legal: it disables the delay).
pub(crate) const SHUTDOWN_DRAIN_DELAY_MAX_SECS: u64 = 300;

/// BIN-C3 — an inference endpoint's request timeout must be at least 1 s.
pub(crate) fn validate_inference_timeout_secs(field: &str, value: u64) -> Result<(), ConfigError> {
    if value == 0 {
        return Err(ConfigError::Invalid {
            field: field.into(),
            reason: "must be at least 1 second — a zero timeout fails every request at once".into(),
        });
    }
    Ok(())
}

/// B6 (BSV-F16) — `rate_limit.ipv6_bucket_prefix` bounds. Below /32 one
/// bucket would span whole providers; above /128 is not an IPv6 prefix.
pub(crate) const IPV6_BUCKET_PREFIX_MIN: u8 = 32;
pub(crate) const IPV6_BUCKET_PREFIX_MAX: u8 = 128;

pub(crate) fn validate_ipv6_bucket_prefix(value: u8) -> Result<(), ConfigError> {
    if !(IPV6_BUCKET_PREFIX_MIN..=IPV6_BUCKET_PREFIX_MAX).contains(&value) {
        return Err(ConfigError::Invalid {
            field: "rate_limit.ipv6_bucket_prefix".into(),
            reason: format!(
                "must be between {IPV6_BUCKET_PREFIX_MIN} and {IPV6_BUCKET_PREFIX_MAX}, got {value} — 64 buckets one host's /64 together, 128 buckets every address"
            ),
        });
    }
    Ok(())
}

/// BAU-15a (hardening 2.7) — the KDF knobs' floors and ceilings. The floors
/// are OWASP's Argon2id minimum (m = 19456 KiB, t = 2) and security contract
/// I2's 12-character password; the ceilings stop a typo from making one login
/// cost seconds or the executor unbounded.
pub(crate) fn validate_kdf(kdf: &super::KdfSection) -> Result<(), ConfigError> {
    let range = |field: &str, value: u64, min: u64, max: u64| {
        if (min..=max).contains(&value) {
            Ok(())
        } else {
            Err(ConfigError::Invalid {
                field: format!("auth.kdf.{field}"),
                reason: format!("must be between {min} and {max}, got {value}"),
            })
        }
    };
    range("hard_cap", kdf.hard_cap as u64, 1, 64)?;
    range("acquire_timeout_ms", kdf.acquire_timeout_ms, 100, 30_000)?;
    range(
        "argon2_m_cost",
        u64::from(kdf.argon2_m_cost),
        19_456,
        1_048_576,
    )?;
    range("argon2_t_cost", u64::from(kdf.argon2_t_cost), 2, 10)?;
    range(
        "password_min_length",
        kdf.password_min_length as u64,
        12,
        64,
    )?;
    // One operation's footprint: m_cost plus the measured ~1 MiB overhead.
    let one_op = u64::from(kdf.argon2_m_cost) * 1024 + 1024 * 1024;
    range(
        "memory_budget_bytes",
        kdf.memory_budget_bytes,
        one_op,
        64 * 1024 * 1024 * 1024,
    )?;
    Ok(())
}

/// B1 (BSV-F05) — the upper bound on `app.request_timeout_secs`, one second
/// below the durable idempotency tier's stale-pending window (5 minutes,
/// `attome-server`'s `idempotency_durable::STALE_PENDING_AFTER_MINUTES`). The
/// value is duplicated rather than shared because `attome-config` is the layer
/// *below* `attome-server` and cannot name it (guidelines §1); the two must be
/// changed together.
pub(crate) const REQUEST_TIMEOUT_MAX_SECS: u64 = 299;

/// B1 (BSV-F05) — range check for `app.request_timeout_secs`. Above this bound
/// a durable idempotency record can be reclaimed as stale while the request
/// that owns it is still running, so the retry and the original both execute a
/// mutation the durable tier exists to run once. Zero would time out every
/// request before it could do anything.
pub(crate) fn validate_request_timeout_secs(value: u64) -> Result<(), ConfigError> {
    if value == 0 || value > REQUEST_TIMEOUT_MAX_SECS {
        return Err(ConfigError::Invalid {
            field: "app.request_timeout_secs".into(),
            reason: format!(
                "must be between 1 and {REQUEST_TIMEOUT_MAX_SECS} seconds, got {value} — 0 times \
                 every request out immediately, and at or past 300 s a durable idempotency \
                 record past its 5-minute stale window can be reclaimed while the original \
                 request is still running, letting both execute (BSV-F05)"
            ),
        });
    }
    Ok(())
}

/// A3 (BSV-F07) + BCA-14 — a per-command Redis timeout in milliseconds. fred
/// reads 0 as "no timeout", which removes the only bound on a readiness `PING`
/// (and on every other Redis command), so the probe could block indefinitely.
/// See attome-cache's `redis_pool` doc. `field` names whichever key the bad
/// value came from — `cache.timeout` for the base block, or a role override's
/// own key — so the boot error does not send an operator to the wrong knob.
pub(crate) fn validate_cache_timeout_ms(field: &str, value: u64) -> Result<(), ConfigError> {
    if value == 0 {
        return Err(ConfigError::Invalid {
            field: field.into(),
            reason: "must be at least 1 ms — 0 means no command timeout, which leaves the \
                     readiness Redis ping (and every other Redis call) unbounded (BSV-F07)"
                .into(),
        });
    }
    Ok(())
}

/// S1 — range check for `app.shutdown_drain_delay_secs`, split out of
/// `validate()` so it is unit-testable without a full `AppConfig` fixture.
pub(crate) fn validate_shutdown_drain_delay_secs(value: u64) -> Result<(), ConfigError> {
    if value > SHUTDOWN_DRAIN_DELAY_MAX_SECS {
        return Err(ConfigError::Invalid {
            field: "app.shutdown_drain_delay_secs".into(),
            reason: format!(
                "must be between 0 and {SHUTDOWN_DRAIN_DELAY_MAX_SECS} seconds, got {value} — \
                 0 disables the drain delay, and a rolling deploy cannot wait longer than \
                 {SHUTDOWN_DRAIN_DELAY_MAX_SECS}s for a node to leave the load balancer"
            ),
        });
    }
    Ok(())
}

/// BEM-D4's loopback exception, duplicated from `attome-email`'s transport
/// builder because `attome-config` is the layer *below* it (guidelines §1) and
/// cannot call it. Deliberately tiny: the two copies must agree, and
/// `attome-email`'s `only_a_loopback_host_may_carry_credentials_over_plaintext`
/// test pins the same set.
fn is_loopback_smtp_host(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// D-771: shape checks for one `s2s.seeded_clients` entry. The secret is only
/// checked when configured — an unset `${VAR}` leaves the client inert.
pub(crate) fn check_seeded_s2s_client(client: &super::S2sSeededClient) -> Result<(), String> {
    let slug_ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    };
    if !slug_ok(&client.client_id) {
        return Err("client_id must be lowercase letters, digits, '-' or '_' (max 100)".into());
    }
    if client.name.trim().is_empty() {
        return Err("name is required".into());
    }
    if !client.service_user_email.contains('@') {
        return Err("service_user_email must be an email address".into());
    }
    match client.public_id.strip_prefix("s2s_") {
        Some(rest) if slug_ok(rest) => {}
        _ => {
            return Err(
                "public_id must be 's2s_' followed by lowercase letters, digits, '-' or '_'".into(),
            );
        }
    }
    if !matches!(client.slot.as_str(), "primary" | "secondary") {
        return Err("slot must be 'primary' or 'secondary'".into());
    }
    if client.rate_limit_rpm.is_some_and(|v| v < 1) || client.max_concurrent.is_some_and(|v| v < 1)
    {
        return Err("rate_limit_rpm and max_concurrent must be at least 1".into());
    }
    if let Some(secret) = client.configured_secret()
        && (secret.len() != 64 || !secret.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("secret must be 64 hex characters (openssl rand -hex 32)".into());
    }
    for p in &client.permissions {
        if p.entity.trim().is_empty() {
            return Err("every permission needs an entity".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        IPV6_BUCKET_PREFIX_MAX, IPV6_BUCKET_PREFIX_MIN, REQUEST_TIMEOUT_MAX_SECS,
        SHUTDOWN_DRAIN_DELAY_MAX_SECS, validate_cache_timeout_ms, validate_ipv6_bucket_prefix,
        validate_request_timeout_secs, validate_shutdown_drain_delay_secs,
    };

    /// D-771 — a seeded S2S client's shape is checked at load; an unset
    /// `${VAR}` secret is inert rather than an error, and Debug hides it.
    #[test]
    fn seeded_s2s_client_shape_is_checked_and_its_secret_redacted() {
        let client = |secret: &str, public_id: &str| -> super::super::S2sSeededClient {
            serde_json::from_value(serde_json::json!({
                "client_id": "attome-online", "name": "Game servers",
                "service_user_email": "game@example.test", "public_id": public_id,
                "secret": secret,
            }))
            .unwrap()
        };
        let good = "ab".repeat(32);
        assert!(super::check_seeded_s2s_client(&client(&good, "s2s_attome_online")).is_ok());
        assert!(super::check_seeded_s2s_client(&client("", "s2s_attome_online")).is_ok());
        assert!(
            super::check_seeded_s2s_client(&client("${UNSET_VAR}", "s2s_attome_online")).is_ok()
        );
        assert!(
            client("${UNSET_VAR}", "s2s_x")
                .configured_secret()
                .is_none()
        );
        assert!(super::check_seeded_s2s_client(&client("abc", "s2s_attome_online")).is_err());
        assert!(super::check_seeded_s2s_client(&client(&good, "attome_online")).is_err());
        assert!(!format!("{:?}", client(&good, "s2s_x")).contains(&good));
    }

    /// B6 (BSV-F16) — the default and both bounds are legal; either side of
    /// the range is a boot error naming the key.
    #[test]
    fn ipv6_bucket_prefix_is_range_checked() {
        for ok in [IPV6_BUCKET_PREFIX_MIN, 48, 64, IPV6_BUCKET_PREFIX_MAX] {
            assert!(
                validate_ipv6_bucket_prefix(ok).is_ok(),
                "{ok} must be accepted"
            );
        }
        for bad in [0, IPV6_BUCKET_PREFIX_MIN - 1, IPV6_BUCKET_PREFIX_MAX + 1] {
            let err = validate_ipv6_bucket_prefix(bad).expect_err("out of range must be refused");
            assert!(
                err.to_string().contains("rate_limit.ipv6_bucket_prefix"),
                "{err}"
            );
        }
    }

    /// BIN-C3 — both endpoints refuse 0 and name the field; 1 is legal.
    #[test]
    fn a_zero_inference_timeout_is_refused() {
        for field in [
            "inference.generation.request_timeout_secs",
            "inference.embedding.request_timeout_secs",
        ] {
            assert!(super::validate_inference_timeout_secs(field, 1).is_ok());
            let err =
                super::validate_inference_timeout_secs(field, 0).expect_err("0 must be refused");
            assert!(err.to_string().contains(field), "{err}");
        }
    }

    /// B6: an omitted key means /64, not a derived zero.
    #[test]
    fn ipv6_bucket_prefix_defaults_to_64() {
        assert_eq!(
            crate::config::sections::auth::default_ipv6_bucket_prefix(),
            64
        );
    }

    /// S1 (BSV-F13 / BSV-D11) — 0 (the pre-S1 behaviour) and the documented
    /// default are legal, the cap is inclusive, and one past it is a boot
    /// error naming the key.
    #[test]
    fn shutdown_drain_delay_is_range_checked() {
        for ok in [0, 10, SHUTDOWN_DRAIN_DELAY_MAX_SECS] {
            assert!(
                validate_shutdown_drain_delay_secs(ok).is_ok(),
                "{ok} must be accepted"
            );
        }
        let err = validate_shutdown_drain_delay_secs(SHUTDOWN_DRAIN_DELAY_MAX_SECS + 1)
            .expect_err("one past the cap must be refused");
        assert!(
            err.to_string().contains("app.shutdown_drain_delay_secs"),
            "{err}"
        );
    }

    /// B1 (BSV-F05) — 0 and anything at or past the durable tier's 5-minute
    /// stale-pending window are refused, because either lets a durable
    /// idempotency record be reclaimed while the request that owns it still
    /// runs (or times out before doing anything). The common values and the
    /// boundary are legal.
    #[test]
    fn request_timeout_is_bounded_by_the_stale_window() {
        for ok in [1, 30, 60, REQUEST_TIMEOUT_MAX_SECS] {
            assert!(
                validate_request_timeout_secs(ok).is_ok(),
                "{ok} must be accepted"
            );
        }
        for bad in [0, REQUEST_TIMEOUT_MAX_SECS + 1] {
            let err = validate_request_timeout_secs(bad)
                .expect_err("0 and anything past the stale window must be refused");
            assert!(
                err.to_string().contains("app.request_timeout_secs"),
                "{err}"
            );
        }
    }

    /// A3 (BSV-F07) + BCA-14 — a zero Redis command timeout would leave the
    /// readiness ping unbounded; any positive value is accepted, and the error
    /// names the key the bad value actually came from (the base block or a role
    /// override), never a fixed one.
    #[test]
    fn a_zero_cache_timeout_is_rejected() {
        for field in ["cache.timeout", "cache.roles.coordination.timeout"] {
            assert!(validate_cache_timeout_ms(field, 1).is_ok());
            assert!(validate_cache_timeout_ms(field, 2000).is_ok());
            let err = validate_cache_timeout_ms(field, 0).expect_err("0 must be refused");
            assert!(err.to_string().contains(field), "{field}: {err}");
        }
    }

    /// D-205: the field's default is 10, not a derived `Default`'s 0 — an
    /// omitted key must not silently disable the drain the LB needs.
    #[test]
    fn shutdown_drain_delay_defaults_to_ten() {
        let section: crate::config::AppSection = serde_json::from_str(
            r#"{"port": 1, "frontend_host": "localhost", "frontend_port": 4200}"#,
        )
        .expect("a minimal app section must deserialize with the key omitted");
        assert_eq!(
            section.shutdown_drain_delay_secs, 10,
            "an omitted app.shutdown_drain_delay_secs must default to the documented 10 s (D-205)"
        );
    }
}
