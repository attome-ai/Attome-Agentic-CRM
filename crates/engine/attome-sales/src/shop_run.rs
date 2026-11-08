//! F8-T5: one shop connection's sync, as a registered background job.
//!
//! [`JOB`] (`shop_sync`) carries a [`ShopSyncJob`] (the connection, and why it
//! runs: `webhook` or `schedule`). It is queued by an inbound hook whose
//! handler is `{"type": "shop_sync", "connection": "<id>"}` (a signed shop
//! webhook, through the hook's own credential, address and replay checks), and
//! by the 15-minute tick [`TICK_JOB`], which queues one per `active`
//! connection. The sync never runs on a request: it is a job.
//!
//! A run, per kind of record the connection syncs (orders when `sync_orders`,
//! customers when `sync_customers`, products when `product_direction` is
//! `shop_to_attome`):
//!
//! 1. the stored cursor (`shop_sync_cursor`, none on the first run) is the
//!    adapter's `fetch_*_since` argument;
//! 2. each record of the page goes through [`upsert_from_source`] as the user
//!    who created the connection (a record already synced is updated, never
//!    made twice, so a replayed webhook or a repeated page is harmless);
//! 3. only when every record of the page was written does the cursor move,
//!    to the page's `next_cursor`, or, on the last page, stay where the page
//!    started (the next run reads that page again: it is idempotent). A page
//!    with a failed record stops that kind, keeps the cursor and fails the run
//!    after the other kinds ran.
//!
//! At most [`MAX_PAGES`] pages per kind per run, so a large backfill resumes
//! on the next run instead of holding a worker. A failed run sets the
//! connection's `status` to `error` (the next sync does not retry it until an
//! administrator resumes it) and logs the reason without any record contents;
//! a successful one sets `last_sync_at`.
//!
//! The connection's credential is the sealed integration credential named by
//! `integration_credential_ref`: a JSON object, per platform (see
//! [`build_platform`]). It is opened for the run only and never logged.

use attome_core::EngineState;
use attome_integration::connector::adapters::shop_sync::ShopPlatform;
use attome_integration::connector::adapters::{salla, shopify, woocommerce, zid};
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::shop_sync::{SourceRecord, upsert_from_source};

/// The registered job that runs one connection's sync.
pub const JOB: &str = "shop_sync";
/// The registered job that queues [`JOB`] for every active connection.
pub const TICK_JOB: &str = "shop_sync_tick";
/// Pages one run reads per kind.
pub const MAX_PAGES: usize = 20;

/// The job's payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShopSyncJob {
    pub connection_id: Uuid,
    /// `webhook` or `schedule`; for the log.
    #[serde(default)]
    pub reason: String,
}

/// The kinds of record a connection syncs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Order,
    Customer,
    Product,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Order => "order",
            Self::Customer => "customer",
            Self::Product => "product",
        }
    }
}

/// The kinds a connection's settings sync. Pure.
pub fn kinds_to_sync(
    sync_orders: bool,
    sync_customers: bool,
    product_direction: Option<&str>,
) -> Vec<Kind> {
    let mut kinds = Vec::new();
    if sync_orders {
        kinds.push(Kind::Order);
    }
    if sync_customers {
        kinds.push(Kind::Customer);
    }
    if product_direction == Some("shop_to_attome") {
        kinds.push(Kind::Product);
    }
    kinds
}

/// The cursor to store after a page was written: the page's next one, or, on
/// the last page, the one it started from. Pure.
pub fn cursor_after(started_from: Option<&str>, next: Option<&str>) -> Option<String> {
    next.or(started_from).map(str::to_owned)
}

fn field(secret: &Value, name: &str) -> Result<String, AppError> {
    secret[name]
        .as_str()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AppError::Validation(format!("the shop credential lacks {name}")))
}

/// The adapter for `platform` from the connection's credential (a JSON
/// object): Salla `{access_token}`, Zid `{partner_token, manager_token}`,
/// Shopify `{shop_domain, access_token}`, WooCommerce `{store_url,
/// consumer_key, consumer_secret}`. A Salla or Zid credential may also name
/// `base_url` (a sandbox). The error names the missing field, never a value.
pub fn build_platform(platform: &str, secret: &str) -> Result<Box<dyn ShopPlatform>, AppError> {
    let secret: Value = serde_json::from_str(secret)
        .map_err(|_| AppError::Validation("the shop credential is not a JSON object".into()))?;
    let base = |default: &str| secret["base_url"].as_str().unwrap_or(default).to_owned();
    let built: Box<dyn ShopPlatform> = match platform {
        "salla" => Box::new(salla::SallaShop::new(
            &base(salla::BASE_URL),
            field(&secret, "access_token")?,
        )?),
        "zid" => Box::new(zid::ZidShop::new(
            &base(zid::BASE_URL),
            field(&secret, "partner_token")?,
            field(&secret, "manager_token")?,
        )?),
        "shopify" => Box::new(shopify::ShopifyShop::new(
            &field(&secret, "shop_domain")?,
            field(&secret, "access_token")?,
        )?),
        "woocommerce" => Box::new(woocommerce::WooCommerceShop::new(
            &field(&secret, "store_url")?,
            &field(&secret, "consumer_key")?,
            &field(&secret, "consumer_secret")?,
        )?),
        other => {
            return Err(AppError::Validation(format!(
                "no shop adapter for platform {other}"
            )));
        }
    };
    Ok(built)
}

#[derive(Debug, sqlx::FromRow)]
struct Row {
    platform: String,
    integration_credential_ref: Option<String>,
    sync_orders: Option<bool>,
    sync_customers: Option<bool>,
    product_direction: Option<String>,
    status: Option<String>,
    created_by: Option<Uuid>,
}

async fn load_cursor(
    state: &EngineState,
    connection: Uuid,
    kind: Kind,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar(
        "SELECT cursor FROM shop_sync_cursor WHERE connection_id = $1 AND source_kind = $2",
    )
    .bind(connection)
    .bind(kind.name())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

async fn save_cursor(
    state: &EngineState,
    connection: Uuid,
    kind: Kind,
    cursor: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO shop_sync_cursor (connection_id, source_kind, cursor) VALUES ($1, $2, $3) \
         ON CONFLICT (connection_id, source_kind) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = now()",
    )
    .bind(connection)
    .bind(kind.name())
    .bind(cursor)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Sets the connection's operational state: the status, and `last_sync_at`
/// on success. Not a user edit, so it is not an audited record change; the
/// row version moves so a form open on the connection sees it changed.
async fn mark(state: &EngineState, connection: Uuid, status: &str, synced: bool) {
    let result = sqlx::query(
        "UPDATE shop_connection SET status = $2, \
                last_sync_at = CASE WHEN $3 THEN now() ELSE last_sync_at END, \
                modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(connection)
    .bind(status)
    .bind(synced)
    .execute(&state.base.db)
    .await;
    if let Err(error) = result {
        tracing::warn!(%connection, %error, "shop sync: the connection's state was not updated");
    }
}

/// Reads and writes up to [`MAX_PAGES`] pages of one kind. `Ok(records)` when
/// every page was written, `Err` at the first page with a failed record.
async fn sync_kind(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    platform: &dyn ShopPlatform,
    connection: Uuid,
    kind: Kind,
) -> Result<usize, AppError> {
    let mut cursor = load_cursor(state, connection, kind).await?;
    let mut written = 0usize;
    for _ in 0..MAX_PAGES {
        let started_from = cursor.clone();
        let (records, next): (Vec<SourceRecord>, Option<String>) = match kind {
            Kind::Order => {
                let page = platform.fetch_orders_since(started_from.as_deref()).await?;
                let next = page.next_cursor.clone();
                (
                    page.items.into_iter().map(SourceRecord::Order).collect(),
                    next,
                )
            }
            Kind::Customer => {
                let page = platform
                    .fetch_customers_since(started_from.as_deref())
                    .await?;
                let next = page.next_cursor.clone();
                (
                    page.items.into_iter().map(SourceRecord::Customer).collect(),
                    next,
                )
            }
            Kind::Product => {
                let page = platform
                    .fetch_products_since(started_from.as_deref())
                    .await?;
                let next = page.next_cursor.clone();
                (
                    page.items.into_iter().map(SourceRecord::Product).collect(),
                    next,
                )
            }
        };
        let mut failed = 0usize;
        for record in &records {
            match upsert_from_source(state, ctx, connection, record).await {
                Ok(_) => written += 1,
                Err(_) => failed += 1,
            }
        }
        if failed > 0 {
            return Err(AppError::Validation(format!(
                "{failed} of {} {} records were not written",
                records.len(),
                kind.name()
            )));
        }
        if let Some(stored) = cursor_after(started_from.as_deref(), next.as_deref()) {
            save_cursor(state, connection, kind, &stored).await?;
        }
        match next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok(written)
}

/// Runs one connection's sync; see the module documentation.
pub async fn run(state: &EngineState, job: ShopSyncJob) -> Result<(), AppError> {
    let connection = job.connection_id;
    let row: Option<Row> = sqlx::query_as(
        "SELECT platform::text AS platform, integration_credential_ref, sync_orders, \
                sync_customers, product_direction::text AS product_direction, \
                status::text AS status, created_by \
           FROM shop_connection WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(connection)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        tracing::info!(%connection, "shop sync: no such connection; nothing to do");
        return Ok(());
    };
    if row.status.as_deref() != Some("active") {
        tracing::info!(%connection, reason = %job.reason, "shop sync: the connection is not active; skipped");
        return Ok(());
    }
    let kinds = kinds_to_sync(
        row.sync_orders.unwrap_or(false),
        row.sync_customers.unwrap_or(false),
        row.product_direction.as_deref(),
    );
    if kinds.is_empty() {
        return Ok(());
    }
    let outcome = async {
        let ring = attome_integration::credential::ring(state);
        let credential = attome_integration::credential::resolve(
            &state.base.db,
            &ring,
            row.integration_credential_ref.as_deref(),
        )
        .await?
        .ok_or_else(|| AppError::Validation("the connection has no credential".into()))?;
        let platform = credential
            .with_value(|secret| build_platform(&row.platform, secret))?;
        let user = row
            .created_by
            .ok_or_else(|| AppError::Validation("the connection has no creator to run as".into()))?;
        let ctx = state.base.security.resolve(user).await?;
        let mut total = 0usize;
        let mut first_error: Option<AppError> = None;
        for kind in kinds {
            match sync_kind(state, &ctx, platform.as_ref(), connection, kind).await {
                Ok(n) => total += n,
                Err(error) => {
                    tracing::warn!(%connection, kind = kind.name(), %error, "shop sync: a kind stopped");
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(total),
        }
    }
    .await;
    match outcome {
        Ok(total) => {
            mark(state, connection, "active", true).await;
            tracing::info!(%connection, reason = %job.reason, records = total, "shop sync finished");
            Ok(())
        }
        Err(error) => {
            // A shop that is down is not the connection being wrong: only a
            // refusal sets `error`; an unreachable platform is retried.
            if !matches!(error, AppError::CapabilityUnavailable(_)) {
                mark(state, connection, "error", false).await;
            }
            Err(error)
        }
    }
}

/// The 15-minute tick: queues one [`JOB`] for every `active` connection, a
/// connection with one already waiting is not queued again. Returns how many
/// were queued.
pub async fn tick(state: &EngineState) -> Result<usize, AppError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM shop_connection \
          WHERE status::text = 'active' AND (is_active IS NULL OR is_active = true) \
          ORDER BY id",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut queued = 0usize;
    for id in ids {
        let job = attome_core::jobs::JOB_TYPES
            .job(
                JOB,
                &ShopSyncJob {
                    connection_id: id,
                    reason: "schedule".into(),
                },
            )
            .map_err(AppError::internal)?;
        let key = format!("shop-sync:{id}");
        if attome_jobs::enqueue_dedup(
            &state.base.db,
            attome_core::jobs::EngineJob::Registered(job),
            &key,
        )
        .await
        .map_err(AppError::internal)?
        {
            queued += 1;
        }
    }
    Ok(queued)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_follow_the_connection_settings() {
        assert_eq!(
            kinds_to_sync(true, true, Some("shop_to_attome")),
            vec![Kind::Order, Kind::Customer, Kind::Product]
        );
        assert_eq!(
            kinds_to_sync(true, false, Some("attome_to_shop")),
            vec![Kind::Order]
        );
        assert!(kinds_to_sync(false, false, None).is_empty());
    }

    #[test]
    fn the_cursor_moves_to_the_next_page_or_stays_on_the_last() {
        assert_eq!(cursor_after(Some("3"), Some("4")).as_deref(), Some("4"));
        assert_eq!(cursor_after(Some("9"), None).as_deref(), Some("9"));
        assert_eq!(
            cursor_after(None, None),
            None,
            "an empty first run stores nothing"
        );
    }

    #[test]
    fn a_credential_builds_its_platform_and_names_only_a_missing_field() {
        let salla = build_platform("salla", r#"{"access_token":"t"}"#).unwrap();
        assert_eq!(salla.platform(), "salla");
        let woo = build_platform(
            "woocommerce",
            r#"{"store_url":"https://s.example","consumer_key":"ck","consumer_secret":"cs"}"#,
        )
        .unwrap();
        assert_eq!(woo.platform(), "woocommerce");
        let err = build_platform("shopify", r#"{"shop_domain":"a.myshopify.com"}"#)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("access_token"), "{err}");
        assert!(
            build_platform("woocommerce", r#"{"store_url":"http://s.example","consumer_key":"k","consumer_secret":"SECRET-VALUE"}"#)
                .err()
                .is_some_and(|e| !e.to_string().contains("SECRET-VALUE"))
        );
        assert!(build_platform("etsy", "{}").is_err());
        assert!(build_platform("salla", "not json").is_err());
    }
}
