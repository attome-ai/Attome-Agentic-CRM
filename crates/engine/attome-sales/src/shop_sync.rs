//! F8-T2: a shop's orders, customers and products written into Attome, once
//! per source id.
//!
//! [`upsert_from_source`] takes one neutral record from a shop adapter
//! (`attome_integration::connector::adapters::shop_sync`) and writes it
//! through the record engine as the caller `ctx` (a shop connection's sync
//! runs as a service user), so validation, rules, audit and the change feed
//! run exactly as for any other write:
//!
//! - **The sync map.** `shop_sync_map` (sales pack changeset 0030) holds one
//!   row per `(shop_connection_ref, source_kind, source_id)`, its business
//!   key, so its unique index decides who syncs a source record first. The
//!   row is claimed before the target is written and names the target after;
//!   a second sync of the same source finds the target and updates it with
//!   its `row_version`, so a source record makes exactly one order, contact
//!   or product however often it is replayed. A claim whose target write
//!   failed is taken again by the next sync (its `row_version` decides
//!   between two).
//! - **Customers** become contacts, matched first to a live contact with the
//!   same E.164 mobile or phone, or the same lower-cased email. This is the
//!   exact match only: A15's duplicate matcher lives in attome-api, above
//!   this crate, and its scans still find what an exact match misses.
//! - **Products** match a live product with the same SKU before one is made;
//!   a product without a SKU in the shop gets `<platform>-<source id>`.
//! - **Orders** are written as a head and its lines, the head's `source`
//!   `shop:<platform>` and `source_order_number` the shop's number (sales
//!   pack changeset 0031), in the shop's currency. Each line's product and
//!   the customer are synced first. The record engine writes one record per
//!   transaction, so when a line fails the order is deleted again and the
//!   claim stays open for the next sync. The account is the contact's, else
//!   the connection's `default_account_ref`; without either the order is
//!   refused. A later sync of the same order updates its status and totals;
//!   its lines are written once.
//!
//! No shop API is called here: adapters fetch first, then call this.

use attome_core::EngineState;
use attome_integration::connector::adapters::shop_sync::{
    ShopCustomer, ShopOrder, ShopOrderLine, ShopProduct, normalise_email, normalise_phone,
    split_vat_inclusive,
};
use attome_records::entity_mutation::{DeleteKind, DeleteOrigin};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use rust_decimal::Decimal;
use serde_json::{Value, json};
use uuid::Uuid;

/// The calling code a phone without one is read in.
const DEFAULT_COUNTRY: &str = "966";
/// The sync map entity.
const MAP: &str = "shop_sync_map";

/// One record from a shop.
#[derive(Debug, Clone)]
pub enum SourceRecord {
    Order(ShopOrder),
    Customer(ShopCustomer),
    Product(ShopProduct),
}

impl SourceRecord {
    fn kind(&self) -> &'static str {
        match self {
            Self::Order(_) => "order",
            Self::Customer(_) => "customer",
            Self::Product(_) => "product",
        }
    }
}

/// What a sync wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Synced {
    pub target_entity: &'static str,
    pub target_id: Uuid,
    /// A new record was made (or an existing one first linked).
    pub created: bool,
}

/// The shop connection a sync runs for.
#[derive(Debug, Clone, sqlx::FromRow)]
struct Connection {
    platform: String,
    default_account_ref: Option<Uuid>,
}

async fn connection(state: &EngineState, id: Uuid) -> Result<Connection, AppError> {
    sqlx::query_as(
        "SELECT platform::text AS platform, default_account_ref FROM shop_connection \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// The live map row for a source record: `(id, row_version, target_id)`.
async fn map_row(
    state: &EngineState,
    connection: Uuid,
    kind: &str,
    source_id: &str,
) -> Result<Option<(Uuid, i64, Option<String>)>, AppError> {
    sqlx::query_as(
        "SELECT id, row_version, target_id FROM shop_sync_map \
          WHERE shop_connection_ref = $1 AND source_kind::text = $2 AND source_id = $3 \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(connection)
    .bind(kind)
    .bind(source_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Who writes a source record's target.
enum Claim {
    /// Already synced: the target.
    Existing(Uuid),
    /// This sync writes it; the map row to name it on.
    Mine(Uuid),
}

async fn claim(
    state: &EngineState,
    ctx: &SecurityContext,
    connection: Uuid,
    kind: &str,
    source_id: &str,
    target_entity: &str,
) -> Result<Claim, AppError> {
    let existing = |row: Option<(Uuid, i64, Option<String>)>| {
        row.and_then(|(_, _, target)| target.and_then(|t| Uuid::parse_str(&t).ok()))
    };
    let row = map_row(state, connection, kind, source_id).await?;
    if let Some(target) = existing(row.clone()) {
        return Ok(Claim::Existing(target));
    }
    if let Some((id, version, _)) = row {
        // An earlier claim whose target was never written: take it over.
        return match attome_records::entity_crud::update_record_for(
            state,
            ctx,
            ctx.user_id,
            MAP,
            id,
            version,
            json!({ "target_entity": target_entity }),
        )
        .await
        {
            Ok(_) => Ok(Claim::Mine(id)),
            Err(AppError::VersionConflict | AppError::VersionConflictAt { .. }) => {
                Err(AppError::Conflict("the shop record is being synced"))
            }
            Err(error) => Err(error),
        };
    }
    match attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        MAP,
        json!({
            "shop_connection_ref": connection,
            "source_kind": kind,
            "source_id": source_id,
            "target_entity": target_entity,
        }),
    )
    .await
    {
        Ok((id, _)) => Ok(Claim::Mine(id)),
        // Another sync made the row first (the business key's unique index).
        Err(AppError::Conflict(_)) => {
            match existing(map_row(state, connection, kind, source_id).await?) {
                Some(target) => Ok(Claim::Existing(target)),
                None => Err(AppError::Conflict("the shop record is being synced")),
            }
        }
        Err(error) => Err(error),
    }
}

/// Names `target` on the claimed map row.
async fn link(
    state: &EngineState,
    ctx: &SecurityContext,
    map_id: Uuid,
    target: Uuid,
) -> Result<(), AppError> {
    let version: i64 = sqlx::query_scalar("SELECT row_version FROM shop_sync_map WHERE id = $1")
        .bind(map_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        MAP,
        map_id,
        version,
        json!({ "target_id": target.to_string() }),
    )
    .await?;
    Ok(())
}

/// The live row version of a target record; `NotFound` once it is gone.
async fn version_of(state: &EngineState, entity: &str, id: Uuid) -> Result<i64, AppError> {
    let sql = match entity {
        "contact" => {
            "SELECT row_version FROM contact WHERE id = $1 AND is_active IS DISTINCT FROM false"
        }
        "product" => {
            "SELECT row_version FROM product WHERE id = $1 AND is_active IS DISTINCT FROM false"
        }
        "order" => {
            "SELECT row_version FROM \"order\" WHERE id = $1 AND is_active IS DISTINCT FROM false"
        }
        _ => return Err(AppError::internal("not a shop sync target")),
    };
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

async fn update_target(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    id: Uuid,
    body: Value,
) -> Result<(), AppError> {
    let version = version_of(state, entity, id).await?;
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        entity,
        id,
        version,
        body,
    )
    .await?;
    Ok(())
}

fn money(value: Decimal) -> Value {
    crate::order::number(&value.round_dp(2).to_string()).unwrap_or(Value::Null)
}

/// Writes one shop record into Attome as `ctx`, once per source id; see the
/// module documentation.
pub async fn upsert_from_source(
    state: &EngineState,
    ctx: &SecurityContext,
    connection_id: Uuid,
    record: &SourceRecord,
) -> Result<Synced, AppError> {
    ctx.require(MAP, "create")?;
    ctx.require(MAP, "update")?;
    let connection = connection(state, connection_id).await?;
    match record {
        SourceRecord::Customer(customer) => {
            sync_customer(state, ctx, connection_id, customer).await
        }
        SourceRecord::Product(product) => {
            sync_product(state, ctx, connection_id, &connection, product).await
        }
        SourceRecord::Order(order) => {
            sync_order(state, ctx, connection_id, &connection, order).await
        }
    }
    .inspect_err(|error| {
        tracing::warn!(
            connection = %connection_id,
            kind = record.kind(),
            %error,
            "shop sync: a record was not written"
        );
    })
}

fn contact_body(customer: &ShopCustomer) -> Value {
    let mut body = json!({ "full_name": customer.name.trim() });
    if let Some(email) = customer.email.as_deref().and_then(normalise_email) {
        body["email"] = json!(email);
    }
    if let Some(phone) = customer
        .phone
        .as_deref()
        .and_then(|p| normalise_phone(p, DEFAULT_COUNTRY))
    {
        body["mobile_phone"] = json!(phone);
    }
    body
}

async fn matching_contact(
    state: &EngineState,
    customer: &ShopCustomer,
) -> Result<Option<Uuid>, AppError> {
    let phone = customer
        .phone
        .as_deref()
        .and_then(|p| normalise_phone(p, DEFAULT_COUNTRY));
    let email = customer.email.as_deref().and_then(normalise_email);
    if phone.is_none() && email.is_none() {
        return Ok(None);
    }
    sqlx::query_scalar(
        "SELECT id FROM contact \
          WHERE (is_active IS NULL OR is_active = true) \
            AND (($1::text IS NOT NULL AND (mobile_phone = $1 OR phone = $1)) \
                 OR ($2::text IS NOT NULL AND lower(email) = $2)) \
          ORDER BY created_at, id LIMIT 1",
    )
    .bind(phone)
    .bind(email)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

async fn sync_customer(
    state: &EngineState,
    ctx: &SecurityContext,
    connection: Uuid,
    customer: &ShopCustomer,
) -> Result<Synced, AppError> {
    if customer.name.trim().is_empty() {
        return Err(AppError::Validation("a shop customer has no name".into()));
    }
    ctx.require("contact", "create")?;
    let body = contact_body(customer);
    match claim(
        state,
        ctx,
        connection,
        "customer",
        &customer.source_id,
        "contact",
    )
    .await?
    {
        Claim::Existing(id) => {
            update_target(state, ctx, "contact", id, body).await?;
            Ok(Synced {
                target_entity: "contact",
                target_id: id,
                created: false,
            })
        }
        Claim::Mine(map) => {
            let id = match matching_contact(state, customer).await? {
                Some(id) => id,
                None => {
                    attome_records::entity_crud::create_record_for(
                        state,
                        ctx,
                        ctx.user_id,
                        "contact",
                        body,
                    )
                    .await?
                    .0
                }
            };
            link(state, ctx, map, id).await?;
            Ok(Synced {
                target_entity: "contact",
                target_id: id,
                created: true,
            })
        }
    }
}

fn product_sku(platform: &str, source_id: &str, sku: Option<&str>) -> String {
    sku.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{platform}-{source_id}"))
}

async fn sync_product(
    state: &EngineState,
    ctx: &SecurityContext,
    connection_id: Uuid,
    connection: &Connection,
    product: &ShopProduct,
) -> Result<Synced, AppError> {
    ctx.require("product", "create")?;
    let sku = product_sku(
        &connection.platform,
        &product.source_id,
        product.sku.as_deref(),
    );
    let mut body = json!({ "name": product.name.trim(), "sku": sku });
    if let Some(description) = product.description.as_deref() {
        body["description"] = json!(description);
    }
    write_product(state, ctx, connection_id, &product.source_id, &sku, body).await
}

async fn write_product(
    state: &EngineState,
    ctx: &SecurityContext,
    connection: Uuid,
    source_id: &str,
    sku: &str,
    body: Value,
) -> Result<Synced, AppError> {
    match claim(state, ctx, connection, "product", source_id, "product").await? {
        Claim::Existing(id) => {
            update_target(state, ctx, "product", id, body).await?;
            Ok(Synced {
                target_entity: "product",
                target_id: id,
                created: false,
            })
        }
        Claim::Mine(map) => {
            let matched: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM product WHERE sku = $1 \
                   AND (is_active IS NULL OR is_active = true) ORDER BY created_at, id LIMIT 1",
            )
            .bind(sku)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let id = match matched {
                Some(id) => id,
                None => {
                    let mut body = body;
                    body["is_orderable"] = json!(true);
                    attome_records::entity_crud::create_record_for(
                        state,
                        ctx,
                        ctx.user_id,
                        "product",
                        body,
                    )
                    .await?
                    .0
                }
            };
            link(state, ctx, map, id).await?;
            Ok(Synced {
                target_entity: "product",
                target_id: id,
                created: true,
            })
        }
    }
}

/// The D10 status for a shop's status word; `None` leaves it as it is.
pub fn order_status(shop_status: &str) -> Option<&'static str> {
    match shop_status.trim().to_lowercase().as_str() {
        "cancelled" | "canceled" | "refunded" | "voided" => Some("cancelled"),
        "completed" | "delivered" | "fulfilled" => Some("fulfilled"),
        "processing" | "confirmed" | "paid" | "shipped" | "in_progress" => Some("confirmed"),
        _ => None,
    }
}

/// `(net, vat, gross)` of one line, from the shop's price and VAT basis.
pub fn line_amounts(line: &ShopOrderLine, prices_include_vat: bool) -> (Decimal, Decimal, Decimal) {
    let charged = line.quantity * line.unit_price;
    let rate = line.vat_rate.unwrap_or(Decimal::ZERO);
    if prices_include_vat {
        let (net, vat) = split_vat_inclusive(charged, rate);
        (net, vat, charged)
    } else {
        let vat = (charged * rate).round_dp(2);
        (charged, vat, charged + vat)
    }
}

async fn sync_order(
    state: &EngineState,
    ctx: &SecurityContext,
    connection_id: Uuid,
    connection: &Connection,
    order: &ShopOrder,
) -> Result<Synced, AppError> {
    ctx.require("order", "create")?;
    ctx.require("order_line", "create")?;
    if order.currency.trim().len() != 3 {
        return Err(AppError::Validation(
            "a shop order has no ISO currency".into(),
        ));
    }
    let amounts: Vec<(Decimal, Decimal, Decimal)> = order
        .lines
        .iter()
        .map(|line| line_amounts(line, order.prices_include_vat))
        .collect();
    let tax: Decimal = amounts.iter().map(|(_, vat, _)| *vat).sum();
    let mut head = json!({
        "currency": order.currency.trim().to_uppercase(),
        "tax_total": money(tax),
        "discount_total": money(order.discount),
        "grand_total": money(order.total),
    });
    if let Some(status) = order_status(&order.status) {
        head["status"] = json!(status);
    }
    let map = match claim(
        state,
        ctx,
        connection_id,
        "order",
        &order.source_id,
        "order",
    )
    .await?
    {
        Claim::Existing(id) => {
            update_target(state, ctx, "order", id, head).await?;
            return Ok(Synced {
                target_entity: "order",
                target_id: id,
                created: false,
            });
        }
        // Claimed: the customer and products first, then the order and lines.
        Claim::Mine(map) => map,
    };
    let contact = match &order.customer {
        Some(customer) => Some(
            sync_customer(state, ctx, connection_id, customer)
                .await?
                .target_id,
        ),
        None => None,
    };
    let contact_account: Option<Uuid> = match contact {
        Some(contact) => sqlx::query_scalar("SELECT account_ref FROM contact WHERE id = $1")
            .bind(contact)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .flatten(),
        None => None,
    };
    let Some(account) = contact_account.or(connection.default_account_ref) else {
        return Err(AppError::Validation(
            "set the shop connection's default account for customers without one".into(),
        ));
    };
    let mut products = Vec::with_capacity(order.lines.len());
    for line in &order.lines {
        let sku = product_sku(
            &connection.platform,
            &line.source_product_id,
            line.sku.as_deref(),
        );
        let body = json!({ "name": line.name.trim(), "sku": sku });
        products.push(
            write_product(
                state,
                ctx,
                connection_id,
                &line.source_product_id,
                &sku,
                body,
            )
            .await?
            .target_id,
        );
    }
    let subtotal: Decimal = amounts.iter().map(|(net, _, _)| *net).sum();
    head["name"] = json!(format!("Shop order {}", order.number.trim()));
    head["status"] = json!(order_status(&order.status).unwrap_or("draft"));
    head["ordered_on"] = json!(order.placed_at);
    head["account_ref"] = json!(account);
    head["subtotal"] = money(subtotal);
    head["source"] = json!(format!("shop:{}", connection.platform));
    head["source_order_number"] = json!(order.number.trim());
    if let Some(contact) = contact {
        head["updates_contact_ref"] = json!(contact);
    }
    if let Some(cod) = order.cod_amount {
        head["cod_amount"] = money(cod);
    }
    if let Some(address) = order.delivery_address.as_deref() {
        head["delivery_address"] = json!(address);
    }
    if let Some(phone) = order
        .delivery_phone
        .as_deref()
        .and_then(|p| normalise_phone(p, DEFAULT_COUNTRY))
    {
        head["delivery_phone"] = json!(phone);
    }
    let (order_id, _) =
        attome_records::entity_crud::create_record_for(state, ctx, ctx.user_id, "order", head)
            .await?;
    let lines = async {
        for ((line, product), (net, vat, _)) in order.lines.iter().zip(&products).zip(&amounts) {
            attome_records::entity_crud::create_record_for(
                state,
                ctx,
                ctx.user_id,
                "order_line",
                json!({
                    "order_ref": order_id,
                    "product_ref": product,
                    "description": line.name.trim(),
                    "quantity": money(line.quantity),
                    "unit_price": money(if line.quantity.is_zero() {
                        Decimal::ZERO
                    } else {
                        *net / line.quantity
                    }),
                    "tax_amount": money(*vat),
                    "line_total": money(*net),
                }),
            )
            .await?;
        }
        Ok::<(), AppError>(())
    }
    .await;
    if let Err(error) = lines {
        // Take the half-written order back; the claim stays open for the
        // next sync.
        if let Err(undo) = attome_records::entity_crud::delete_record_for(
            state,
            ctx,
            ctx.user_id,
            "order",
            order_id,
            None,
            &DeleteOrigin::new(DeleteKind::Import),
        )
        .await
        {
            tracing::error!(order = %order_id, error = %undo, "shop sync: a half-written order was not removed");
        }
        return Err(error);
    }
    link(state, ctx, map, order_id).await?;
    Ok(Synced {
        target_entity: "order",
        target_id: order_id,
        created: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    fn line(q: &str, p: &str, rate: Option<&str>) -> ShopOrderLine {
        ShopOrderLine {
            source_product_id: "1".into(),
            sku: None,
            name: "x".into(),
            quantity: dec(q),
            unit_price: dec(p),
            vat_rate: rate.map(dec),
        }
    }

    #[test]
    fn shop_sync_line_amounts_follow_the_vat_basis() {
        assert_eq!(
            line_amounts(&line("2", "57.50", Some("0.15")), true),
            (dec("100"), dec("15"), dec("115"))
        );
        assert_eq!(
            line_amounts(&line("2", "50", Some("0.15")), false),
            (dec("100"), dec("15"), dec("115"))
        );
        assert_eq!(
            line_amounts(&line("1", "20", None), true),
            (dec("20"), Decimal::ZERO, dec("20"))
        );
    }

    #[test]
    fn shop_sync_status_and_sku() {
        assert_eq!(order_status("Canceled"), Some("cancelled"));
        assert_eq!(order_status("delivered"), Some("fulfilled"));
        assert_eq!(order_status("under_review"), None);
        assert_eq!(product_sku("salla", "77", None), "salla-77");
        assert_eq!(product_sku("salla", "77", Some("  ")), "salla-77");
        assert_eq!(product_sku("salla", "77", Some("TS-1")), "TS-1");
    }
}
