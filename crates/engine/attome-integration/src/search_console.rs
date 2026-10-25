//! E13-T10: the search-engine seam. A customer connects a site to a search
//! engine with an `integration_system` whose `config` names
//! `"search_console"`: `google`, `bing` or `indexnow`, and the site's
//! `domain` (as its content space has it). Optional: `site` (the property as
//! the engine knows it: `sc-domain:example.com`, or `https://example.com/`,
//! the default), `base_url` (a test double), and for IndexNow
//! `key_location` (where the site serves its key file, by default
//! `https://{domain}/{key}.txt`).
//!
//! - Google reads with the system's own auth, an OAuth refresh-token
//!   connection holding only the `webmasters.readonly` scope.
//! - Bing and IndexNow take the system's credential as the API key and the
//!   IndexNow key; it goes into the request and is never answered back.
//!
//! Nothing is called for a site without such a system: [`pull_day`] and
//! [`ping_indexnow`] look the systems up first and build no request when
//! there are none.

use std::sync::OnceLock;
use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::NaiveDate;
use serde_json::Value;
use uuid::Uuid;

use crate::connection::Connection;
use crate::connector::adapters::search_console::{
    self as codec, BING_BASE, GOOGLE_BASE, INDEXNOW_URL, PageStat,
};
use crate::system::IntegrationSystem;

/// Every call to a search engine gives up after this long; the job retries.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// The engines read for statistics.
pub const ENGINES: [&str; 2] = ["google", "bing"];

fn client() -> &'static attome_outbound::http::Outbound {
    static CLIENT: OnceLock<attome_outbound::http::Outbound> = OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(
            attome_outbound::http::Purpose::public("search_console"),
            |b| b.timeout(CALL_TIMEOUT),
        )
    })
}

/// A connected site.
#[derive(Debug, Clone)]
pub struct SiteSystem {
    pub system: IntegrationSystem,
    pub engine: String,
    pub domain: String,
    config: Value,
}

impl SiteSystem {
    fn text(&self, key: &str) -> Option<&str> {
        self.config
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// The property as the engine knows it.
    pub fn site(&self) -> String {
        self.text("site")
            .map_or_else(|| format!("https://{}/", self.domain), str::to_owned)
    }

    fn base(&self, default: &str) -> String {
        self.text("base_url").unwrap_or(default).to_owned()
    }
}

/// The active systems connecting a site to `engine`.
pub async fn systems(state: &EngineState, engine: &str) -> Result<Vec<SiteSystem>, AppError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM integration_system \
          WHERE status = 'active' AND (is_active IS NULL OR is_active = true) \
            AND CASE WHEN config IS JSON OBJECT \
                     THEN config::jsonb ->> 'search_console' END = $1 \
          ORDER BY created_at, id",
    )
    .bind(engine)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut out = Vec::new();
    for id in ids {
        let Some(system) = crate::system::load(&state.base.db, id).await? else {
            continue;
        };
        let config: Value = system
            .config
            .as_deref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or(Value::Null);
        let Some(domain) = config
            .get("domain")
            .and_then(Value::as_str)
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
        else {
            tracing::warn!(system = %id, "search console: a system without a domain is skipped");
            continue;
        };
        out.push(SiteSystem {
            system,
            engine: engine.to_owned(),
            domain,
            config,
        });
    }
    Ok(out)
}

async fn send(request: reqwest::RequestBuilder) -> Result<(u16, Value), AppError> {
    let res = request.send().await.map_err(AppError::internal)?;
    let status = res.status().as_u16();
    let body = res.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

/// One site's statistics for `day` from its engine.
pub async fn pull_site(
    state: &EngineState,
    site: &SiteSystem,
    day: NaiveDate,
) -> Result<Vec<PageStat>, AppError> {
    let db = &state.base.db;
    let ring = crate::credential::ring(state);
    let connection = Connection::of(&site.system);
    let (status, body) = match site.engine.as_str() {
        "google" => {
            let body = codec::google_body(&day.format("%Y-%m-%d").to_string());
            let bytes = serde_json::to_vec(&body).map_err(AppError::internal)?;
            let request = client()
                .post(codec::google_url(&site.base(GOOGLE_BASE), &site.site()))
                .json(&body);
            let request = connection.apply_auth(db, &ring, request, &bytes).await?;
            send(request).await?
        }
        "bing" => {
            let credential = connection.credential(db, &ring).await?.ok_or_else(|| {
                AppError::Validation("a Bing system needs its API key as the credential".into())
            })?;
            let url = credential
                .with_value(|key| codec::bing_url(&site.base(BING_BASE), &site.site(), key));
            send(client().get(url)).await?
        }
        other => {
            return Err(AppError::Validation(format!(
                "no statistics come from `{other}`"
            )));
        }
    };
    if !(200..300).contains(&status) {
        return Err(AppError::internal(format!(
            "{} answered HTTP {status}",
            site.engine
        )));
    }
    let day_start = day
        .and_hms_opt(0, 0, 0)
        .map(|t| t.and_utc().timestamp_millis())
        .unwrap_or_default();
    Ok(match site.engine.as_str() {
        "google" => codec::parse_google(&body),
        _ => codec::parse_bing(&body, day_start),
    })
}

/// Tells the engines through IndexNow that `urls` of `domain` changed.
/// `Ok(false)` when no IndexNow system connects the site (nothing is sent).
pub async fn ping_indexnow(
    state: &EngineState,
    domain: &str,
    urls: &[String],
) -> Result<bool, AppError> {
    if urls.is_empty() {
        return Ok(false);
    }
    let systems = systems(state, "indexnow").await?;
    let Some(site) = systems.iter().find(|s| s.domain == domain) else {
        return Ok(false);
    };
    let ring = crate::credential::ring(state);
    let credential = Connection::of(&site.system)
        .credential(&state.base.db, &ring)
        .await?
        .ok_or_else(|| {
            AppError::Validation("an IndexNow system needs the site's key as the credential".into())
        })?;
    let body = credential.with_value(|key| {
        let location = site
            .text("key_location")
            .map_or_else(|| format!("https://{domain}/{key}.txt"), str::to_owned);
        codec::indexnow_body(domain, key, &location, urls)
    });
    let (status, _) = send(client().post(site.base(INDEXNOW_URL)).json(&body)).await?;
    if !(200..300).contains(&status) {
        return Err(AppError::internal(format!(
            "IndexNow answered HTTP {status}"
        )));
    }
    Ok(true)
}
