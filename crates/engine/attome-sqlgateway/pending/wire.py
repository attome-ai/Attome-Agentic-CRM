"""Wires attome-sqlgateway into the workspace (Y3-T1). Run once from the CRM root."""
import re

def edit(path, old, new, count=1):
    s = open(path, encoding="utf-8").read()
    assert old in s, f"{path}: anchor not found: {old[:60]!r}"
    s = s.replace(old, new, count)
    open(path, "w", encoding="utf-8", newline="").write(s)

cfg = "crates/foundation/attome-config/src/config/"
edit(cfg + "sections/mod.rs", "pub(crate) mod webchat;\n", "pub(crate) mod sql_gateway;\npub(crate) mod webchat;\n")
edit(cfg + "mod.rs", "pub use sections::webchat::WebchatSection;\n",
     "pub use sections::sql_gateway::SqlGatewaySection;\npub use sections::webchat::WebchatSection;\n")
edit(cfg + "mod.rs", "    pub extensions: ExtensionsSection,\n",
     "    pub extensions: ExtensionsSection,\n"
     "    /// Y3-T1 — the SQL gateway: the PostgreSQL wire protocol for BI tools, signed in\n"
     "    /// with an API key, every query through the secured SQL runner. Ships dark\n"
     "    /// (`enabled: false`) and binds only to a loopback address. See\n"
     "    /// `SqlGatewaySection`'s doc comment.\n"
     "    #[serde(default)]\n"
     "    pub sql_gateway: SqlGatewaySection,\n")
edit(cfg + "loader.rs",
     "        if let Err((field, reason)) = self.extensions.check() {\n            return Err(ConfigError::Invalid { field, reason });\n        }\n",
     "        if let Err((field, reason)) = self.extensions.check() {\n            return Err(ConfigError::Invalid { field, reason });\n        }\n"
     "        if let Err((field, reason)) = self.sql_gateway.check() {\n            return Err(ConfigError::Invalid { field, reason });\n        }\n")

edit("config.example.json", '  "_shed_comment"',
     '  "sql_gateway": {\n'
     '    "_comment": "Y3-T1: the SQL gateway for BI tools (PostgreSQL wire protocol; user name = API key public part, password = its secret; the key\'s user needs attome_report.author_sql). Off by default. It has no TLS of its own, so bind must be a loopback address with a TLS-terminating proxy in front; do not expose it before the security review.",\n'
     '    "enabled": false,\n'
     '    "bind": "127.0.0.1:5433",\n'
     '    "max_connections": 8\n'
     '  },\n'
     '  "_shed_comment"')

edit("Cargo.toml", '    "crates/engine/attome-search",\n',
     '    "crates/engine/attome-search",\n    "crates/engine/attome-sqlgateway",\n')
edit("Cargo.toml", 'attome-report    = { path = "crates/engine/attome-report" }\n',
     'attome-report    = { path = "crates/engine/attome-report" }\n'
     'attome-sqlgateway = { path = "crates/engine/attome-sqlgateway" }\n')
edit("Cargo.toml", 'hex           = "0.4"\n',
     'hex           = "0.4"\n'
     '# Y3-T1: the SQL gateway\'s wire protocol; ring, never the aws-lc-rs default (a native build).\n'
     'pgwire        = { version = "0.42", default-features = false, features = ["server-api-ring"] }\n')

edit("crates/engine/attome-testapp/Cargo.toml", "attome-workforce.workspace = true\n",
     "attome-workforce.workspace = true\nattome-sqlgateway.workspace = true\n")
edit("crates/apps/attome/Cargo.toml", "attome-report.workspace         = true\n",
     "attome-report.workspace         = true\nattome-sqlgateway.workspace     = true\n")

edit("crates/foundation/attome-server/src/middleware/auth.rs",
     "async fn resolve_api_key(\n",
     "/// Y3-T1: an API key checked as the HTTP API checks `X-API-Key`, for a\n"
     "/// caller outside HTTP (the SQL gateway's sign-in): the key's user, or\n"
     "/// `Unauthorized` (unknown key, wrong secret, revoked, expired, disabled\n"
     "/// user) or `Forbidden` (an IP outside the key's allow-list).\n"
     "pub async fn authenticate_api_key(\n"
     "    state: &AppState,\n"
     "    public_key: &str,\n"
     "    secret: &str,\n"
     "    caller_ip: Option<IpAddr>,\n"
     ") -> Result<Uuid, AppError> {\n"
     "    resolve_api_key(state, public_key, secret, caller_ip)\n"
     "        .await\n"
     "        .map(|(user_id, _, _)| user_id)\n"
     "}\n\n"
     "async fn resolve_api_key(\n")

edit("crates/apps/attome/src/serve.rs",
     "    let drain_state = attome_state.clone();\n",
     "    let drain_state = attome_state.clone();\n"
     "    // Y3-T1: the SQL gateway, dark unless configured; `AppConfig::validate`\n"
     "    // has already refused a non-loopback bind.\n"
     "    if config.sql_gateway.enabled\n"
     "        && let Some(bind) = config.sql_gateway.bind_addr()\n"
     "    {\n"
     "        attome_sqlgateway::start(\n"
     "            attome_state.clone(),\n"
     "            attome_sqlgateway::GatewayConfig {\n"
     "                bind,\n"
     "                max_connections: usize::try_from(config.sql_gateway.max_connections)\n"
     "                    .unwrap_or(1),\n"
     "            },\n"
     "        )\n"
     "        .await?;\n"
     "    }\n")
print("applied")
