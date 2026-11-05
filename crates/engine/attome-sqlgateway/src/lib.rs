//! Y3-T1: the SQL gateway. BI tools speak the PostgreSQL wire protocol to
//! it and see exactly what their user sees in the app.
//!
//! - **Sign-in.** The user name is an API key's public part and the password
//!   its secret, checked by the same code as the HTTP API's `X-API-Key`
//!   (`attome_server::middleware::auth::authenticate_api_key`: a disabled
//!   user, a revoked or expired key, an IP outside the key's allow-list all
//!   refuse). The key's user must hold `attome_report.author_sql`, the
//!   privilege `POST /api/v1/reports/sql/run` needs.
//! - **Queries.** The simple-query protocol, and the extended one (parse,
//!   describe, execute) without bound parameters: each statement runs through
//!   [`attome_report::secured_sql::run`] as that user, with the user's
//!   context re-read (fail-closed) for every run so a revoked privilege
//!   applies at once: per-run views of the rows and fields the user may read,
//!   a role with no other privilege, a read-only transaction that is rolled
//!   back, 10 seconds and 1,000 rows at most. A describe learns the columns
//!   by running the statement for one row. Values go back as text.
//! - **Audit.** Every query writes one `BusinessEvent`
//!   (`sql_gateway.query`) with the user, the outcome and the SQL's SHA-256
//!   and length; never the SQL itself, whose literals may be personal data.
//! - **Limits.** At most `max_connections` sessions at once; one over is
//!   closed at accept.
//!
//! Not yet: bound parameters (refused with `0A000`); TLS (the listener binds
//! to loopback and must stay behind a TLS-terminating proxy until it has its
//! own); catalog queries (`pg_catalog`) that BI tools send to list tables.
//! The gateway is off unless configured, and its port is not to be exposed
//! before the owner's security review (the task's stop rule).

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::{Sink, stream};
use pgwire::api::auth::cleartext::CleartextPasswordAuth;
use pgwire::api::auth::driver::AuthOutcome;
use pgwire::api::auth::mechanism::AuthMechanismFactory;
use pgwire::api::auth::{
    AuthDriver, AuthSource, DefaultServerParameterProvider, LoginInfo, Password, StartupHandler,
    protocol_negotiation, save_startup_parameters_to_metadata,
};
use pgwire::api::portal::Portal;
use pgwire::api::query::{ExtendedQueryHandler, SimpleQueryHandler};
use pgwire::api::stmt::{NoopQueryParser, StoredStatement};
use pgwire::api::store::PortalStore;
use pgwire::api::results::{
    DataRowEncoder, DescribePortalResponse, DescribeStatementResponse, FieldFormat, FieldInfo,
    QueryResponse, Response,
};
use pgwire::api::{ClientInfo, ClientPortalStore, PgWireServerHandlers, Type};
use pgwire::error::{ErrorInfo, PgWireError, PgWireResult};
use pgwire::messages::{PgWireBackendMessage, PgWireFrontendMessage};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use uuid::Uuid;

use attome_core::EngineState;
use attome_report::secured_sql::{self, RunOptions, SqlRun};
use attome_server::security::SecurityContext;
use attome_types::AppError;

/// The privilege a gateway user needs (the SQL report runner's).
pub const PRIVILEGE: &str = "attome_report.author_sql";
/// The audit event each query writes.
pub const EVENT: &str = "sql_gateway.query";

/// Where and how many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayConfig {
    pub bind: SocketAddr,
    pub max_connections: usize,
}

/// The signed-in user of one session, set once the key verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GatewayUser(Uuid);

/// Checks an API key given as user name and password.
#[derive(Clone)]
struct KeySource {
    state: EngineState,
}

impl Debug for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeySource")
    }
}

#[async_trait]
impl AuthSource<Uuid> for KeySource {
    async fn get_password(&self, login: &LoginInfo) -> PgWireResult<Password> {
        // Secrets are stored hashed; `verify_password` checks them.
        Err(PgWireError::InvalidPassword(
            login.user().unwrap_or_default().to_owned(),
        ))
    }

    async fn verify_password(
        &self,
        login: &LoginInfo,
        presented_password: &[u8],
    ) -> PgWireResult<Option<Uuid>> {
        let user = login.user().unwrap_or_default().to_owned();
        let refused = || PgWireError::InvalidPassword(user.clone());
        let secret = std::str::from_utf8(presented_password).map_err(|_| refused())?;
        let ip = login.host().parse().ok();
        match attome_server::middleware::auth::authenticate_api_key(
            &self.state.base,
            &user,
            secret,
            ip,
        )
        .await
        {
            Ok(user_id) => {
                let ctx = context(&self.state, user_id).await.map_err(to_wire)?;
                if !may_query(&ctx) {
                    return Err(user_error("42501", "permission denied: the key's user lacks attome_report.author_sql"));
                }
                Ok(Some(user_id))
            }
            Err(AppError::Unauthorized | AppError::Forbidden) => Err(refused()),
            Err(error) => {
                tracing::warn!(%error, "sql gateway: key check failed");
                Err(user_error("XX000", "internal error"))
            }
        }
    }
}

/// The user's context, read fail-closed (a revocation applies at once).
async fn context(state: &EngineState, user_id: Uuid) -> Result<Arc<SecurityContext>, AppError> {
    state.base.security.resolve_strict(user_id).await
}

/// Whether `ctx` may use the gateway. Pure.
fn may_query(ctx: &SecurityContext) -> bool {
    ctx.is_admin || ctx.privileges.contains(PRIVILEGE)
}

fn user_error(code: &str, message: &str) -> PgWireError {
    PgWireError::UserError(Box::new(ErrorInfo::new(
        "ERROR".to_owned(),
        code.to_owned(),
        message.to_owned(),
    )))
}

/// An application error as the client sees it: the runner's own messages
/// (a statement error, a refused table) as they are, anything else masked.
fn to_wire(error: AppError) -> PgWireError {
    match error {
        AppError::Validation(message) => user_error("42000", &message),
        AppError::Forbidden => user_error("42501", "permission denied"),
        AppError::Unauthorized => user_error("28000", "the API key is no longer valid"),
        other => {
            tracing::warn!(error = %other, "sql gateway: query failed");
            user_error("XX000", "internal error")
        }
    }
}

/// A result value as wire text: SQL NULL for null, `t`/`f` for booleans,
/// JSON text for arrays and objects. Pure.
fn text_value(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::Bool(b) => Some(if *b { "t" } else { "f" }.to_owned()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

/// The SQL's fingerprint for the audit trail: SHA-256, hex. Pure.
fn fingerprint(sql: &str) -> String {
    hex::encode(Sha256::digest(sql.as_bytes()))
}

/// A run as one wire result: every column `text`.
fn to_response(run: SqlRun) -> PgWireResult<Response> {
    let fields: Arc<Vec<FieldInfo>> = Arc::new(fields_of(&run));
    let mut rows = Vec::with_capacity(run.rows.len());
    for row in &run.rows {
        let mut encoder = DataRowEncoder::new(fields.clone());
        for name in &run.columns {
            encoder.encode_field(&row.get(name).and_then(text_value))?;
        }
        rows.push(encoder.finish());
    }
    Ok(Response::Query(QueryResponse::new(fields, stream::iter(rows))))
}

/// Writes the query's audit event.
async fn audit(state: &EngineState, user_id: Uuid, sql: &str, outcome: &Result<SqlRun, AppError>) {
    let comment = match outcome {
        Ok(run) => format!(
            "sha256 {} chars {} rows {}{}",
            fingerprint(sql),
            sql.chars().count(),
            run.rows.len(),
            if run.truncated { " (capped)" } else { "" }
        ),
        Err(_) => format!("sha256 {} chars {} failed", fingerprint(sql), sql.chars().count()),
    };
    let event = attome_audit::BusinessEvent::new(
        "attome_report",
        Uuid::now_v7(),
        attome_audit::AuditOperation::Export,
        EVENT,
        user_id,
    )
    .comment(comment)
    .source(attome_audit::AuditSource::Integration)
    .outcome(if outcome.is_ok() {
        attome_audit::AuditOutcome::Succeeded
    } else {
        attome_audit::AuditOutcome::Failed
    });
    let written = async {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        attome_audit::write_business_event_in_tx(&mut tx, &attome_audit::audit_service(state), event)
            .await?;
        attome_db::tx::commit(tx).await
    }
    .await;
    if let Err(error) = written {
        tracing::error!(%error, %user_id, "sql gateway: the query's audit event was not written");
    }
}

/// The protocol handlers of one gateway.
pub struct Gateway {
    state: EngineState,
    driver: AuthDriver<DefaultServerParameterProvider, Uuid>,
    cleartext: CleartextPasswordAuth<KeySource>,
}

impl Gateway {
    pub fn new(state: EngineState) -> Self {
        let source = Arc::new(KeySource {
            state: state.clone(),
        });
        Self {
            state,
            driver: AuthDriver::new(DefaultServerParameterProvider::default()),
            cleartext: CleartextPasswordAuth::new(source),
        }
    }
}

#[async_trait]
impl StartupHandler for Gateway {
    async fn on_startup<C>(&self, client: &mut C, message: PgWireFrontendMessage) -> PgWireResult<()>
    where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        match message {
            PgWireFrontendMessage::Startup(ref startup) => {
                protocol_negotiation(client, startup).await?;
                save_startup_parameters_to_metadata(client, startup);
                let mechanism = AuthMechanismFactory::<Uuid>::create(&self.cleartext);
                self.driver.begin_authentication(client, mechanism).await?;
                Ok(())
            }
            PgWireFrontendMessage::PasswordMessageFamily(message) => {
                match self.driver.advance_authentication(client, message).await? {
                    AuthOutcome::Authenticated {
                        identity: Some(user_id),
                        final_message,
                    } => {
                        client.session_extensions().insert(GatewayUser(user_id));
                        tracing::info!(%user_id, "sql gateway: signed in");
                        self.driver
                            .complete_authentication(client, final_message)
                            .await
                    }
                    AuthOutcome::Authenticated { identity: None, .. } => Err(
                        PgWireError::InvalidPassword(String::new()),
                    ),
                    AuthOutcome::InProgress => Ok(()),
                }
            }
            _ => Ok(()),
        }
    }
}

impl Gateway {
    /// Runs `sql` as the session's user: their context re-read fail-closed,
    /// the privilege checked, the runner's bounds. `audited` runs write the
    /// query's event; a describe's one-row run does not (it returns no rows).
    async fn run_as(
        &self,
        user: Option<Arc<GatewayUser>>,
        sql: &str,
        options: RunOptions,
        audited: bool,
    ) -> PgWireResult<SqlRun> {
        let Some(user) = user else {
            return Err(user_error("28000", "not signed in"));
        };
        let user_id = user.0;
        let ctx = context(&self.state, user_id).await.map_err(to_wire)?;
        if !may_query(&ctx) {
            return Err(user_error("42501", "permission denied"));
        }
        let started = std::time::Instant::now();
        let outcome = secured_sql::run(&self.state, &ctx, sql, options).await;
        if audited {
            audit(&self.state, user_id, sql, &outcome).await;
            tracing::info!(
                %user_id,
                chars = sql.chars().count(),
                ok = outcome.is_ok(),
                elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "sql gateway query"
            );
        }
        outcome.map_err(to_wire)
    }
}

/// Whether a query text holds no statement. Pure.
fn is_empty_query(sql: &str) -> bool {
    sql.trim().trim_end_matches(';').trim().is_empty()
}

#[async_trait]
impl SimpleQueryHandler for Gateway {
    async fn do_query<C>(&self, client: &mut C, query: &str) -> PgWireResult<Vec<Response>>
    where
        C: ClientInfo + ClientPortalStore + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::PortalStore: PortalStore,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        if is_empty_query(query) {
            return Ok(vec![Response::EmptyQuery]);
        }
        let user = client.session_extensions().get::<GatewayUser>();
        let run = self.run_as(user, query, RunOptions::default(), true).await?;
        Ok(vec![to_response(run)?])
    }
}

/// The columns of a run, all `text`. Pure.
fn fields_of(run: &SqlRun) -> Vec<FieldInfo> {
    run.columns
        .iter()
        .map(|name| FieldInfo::new(name.clone(), None, None, Type::TEXT, FieldFormat::Text))
        .collect()
}

/// Bound parameters are not taken yet: the runner has no binding of its own,
/// and writing values into the text is the injection this gateway exists to
/// avoid. Pure.
fn refuse_parameters(count: usize) -> PgWireResult<()> {
    if count > 0 {
        return Err(user_error(
            "0A000",
            "the SQL gateway does not take bound parameters yet; write the values into the query",
        ));
    }
    Ok(())
}

/// A describe learns the columns by running the statement for one row (the
/// runner has no describe of its own).
const DESCRIBE_ROWS: i64 = 1;

#[async_trait]
impl ExtendedQueryHandler for Gateway {
    type Statement = String;
    type QueryParser = NoopQueryParser;

    fn query_parser(&self) -> Arc<Self::QueryParser> {
        Arc::new(NoopQueryParser)
    }

    async fn do_describe_statement<C>(
        &self,
        client: &mut C,
        target: &StoredStatement<Self::Statement>,
    ) -> PgWireResult<DescribeStatementResponse>
    where
        C: ClientInfo + ClientPortalStore + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::PortalStore: PortalStore<Statement = Self::Statement>,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        refuse_parameters(target.parameter_types.len())?;
        if is_empty_query(&target.statement) {
            return Ok(DescribeStatementResponse::new(Vec::new(), Vec::new()));
        }
        let user = client.session_extensions().get::<GatewayUser>();
        let options = RunOptions {
            max_rows: DESCRIBE_ROWS,
            ..RunOptions::default()
        };
        let run = self.run_as(user, &target.statement, options, false).await?;
        Ok(DescribeStatementResponse::new(Vec::new(), fields_of(&run)))
    }

    async fn do_describe_portal<C>(
        &self,
        client: &mut C,
        target: &Portal<Self::Statement>,
    ) -> PgWireResult<DescribePortalResponse>
    where
        C: ClientInfo + ClientPortalStore + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::PortalStore: PortalStore<Statement = Self::Statement>,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        refuse_parameters(target.parameters.len())?;
        let sql = &target.statement.statement;
        if is_empty_query(sql) {
            return Ok(DescribePortalResponse::new(Vec::new()));
        }
        let user = client.session_extensions().get::<GatewayUser>();
        let options = RunOptions {
            max_rows: DESCRIBE_ROWS,
            ..RunOptions::default()
        };
        let run = self.run_as(user, sql, options, false).await?;
        Ok(DescribePortalResponse::new(fields_of(&run)))
    }

    async fn do_query<C>(
        &self,
        client: &mut C,
        portal: &Portal<Self::Statement>,
        _max_rows: usize,
    ) -> PgWireResult<Response>
    where
        C: ClientInfo + ClientPortalStore + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::PortalStore: PortalStore<Statement = Self::Statement>,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        refuse_parameters(portal.parameters.len())?;
        let sql = &portal.statement.statement;
        if is_empty_query(sql) {
            return Ok(Response::EmptyQuery);
        }
        let user = client.session_extensions().get::<GatewayUser>();
        let run = self.run_as(user, sql, RunOptions::default(), true).await?;
        to_response(run)
    }
}

/// Hands pgwire this gateway's handlers.
struct Handlers(Arc<Gateway>);

impl PgWireServerHandlers for Handlers {
    fn simple_query_handler(&self) -> Arc<impl SimpleQueryHandler> {
        self.0.clone()
    }

    fn extended_query_handler(&self) -> Arc<impl ExtendedQueryHandler> {
        self.0.clone()
    }

    fn startup_handler(&self) -> Arc<impl StartupHandler> {
        self.0.clone()
    }
}

/// Serves the gateway on `listener` until the process ends. A connection
/// beyond `max_connections` is closed at once.
pub async fn serve(state: EngineState, listener: TcpListener, max_connections: usize) {
    let gateway = Arc::new(Gateway::new(state));
    let slots = Arc::new(Semaphore::new(max_connections.max(1)));
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "sql gateway: accept failed");
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "sql gateway: connection refused, at max_connections");
            drop(socket);
            continue;
        };
        let handlers = Handlers(gateway.clone());
        tokio::spawn(async move {
            if let Err(error) = pgwire::tokio::process_socket(socket, None, handlers).await {
                tracing::debug!(%error, %peer, "sql gateway: connection ended with an error");
            }
            drop(permit);
        });
    }
}

/// Binds `config.bind` and serves on it in the background (process-lifetime
/// supervision, guidelines §10). Returns the bound address.
pub async fn start(state: EngineState, config: GatewayConfig) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(config.bind).await?;
    let addr = listener.local_addr()?;
    tracing::info!(%addr, max_connections = config.max_connections, "sql gateway listening");
    tokio::spawn(serve(state, listener, config.max_connections));
    Ok(addr)
}

#[cfg(test)]
mod gateway_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn values_go_out_as_postgres_text() {
        assert_eq!(text_value(&Value::Null), None);
        assert_eq!(text_value(&Value::Bool(true)).as_deref(), Some("t"));
        assert_eq!(text_value(&Value::Bool(false)).as_deref(), Some("f"));
        assert_eq!(text_value(&serde_json::json!(12.5)).as_deref(), Some("12.5"));
        assert_eq!(text_value(&serde_json::json!("Riyadh")).as_deref(), Some("Riyadh"));
        assert_eq!(text_value(&serde_json::json!([1, 2])).as_deref(), Some("[1,2]"));
    }

    #[test]
    fn the_audit_keeps_a_fingerprint_not_the_sql() {
        let print = fingerprint("select name from account where name = 'Secret Co'");
        assert_eq!(print.len(), 64);
        assert!(!print.contains("Secret"));
        assert_eq!(print, fingerprint("select name from account where name = 'Secret Co'"));
    }

    #[test]
    fn only_sql_authors_and_administrators_may_query() {
        let user = Uuid::now_v7();
        let plain = SecurityContext::human(user, HashSet::new());
        assert!(!may_query(&plain));
        let author = SecurityContext::human(user, HashSet::from([PRIVILEGE.to_owned()]));
        assert!(may_query(&author));
    }

    #[test]
    fn errors_reach_the_client_masked_unless_they_are_the_runners_own() {
        let code = |e: PgWireError| match e {
            PgWireError::UserError(info) => (info.code, info.message),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            code(to_wire(AppError::Validation("the query failed: x".into()))),
            ("42000".to_owned(), "the query failed: x".to_owned())
        );
        assert_eq!(code(to_wire(AppError::Forbidden)).0, "42501");
        let (c, m) = code(to_wire(AppError::internal("password=hunter2")));
        assert_eq!((c.as_str(), m.as_str()), ("XX000", "internal error"));
    }
}
