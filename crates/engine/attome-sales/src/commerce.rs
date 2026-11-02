//! F7-T1: the shared commerce engine: what a portal member may buy, their
//! cart, and checkout into a D10 order, with an approval above a limit.
//!
//! Off by default: everything answers as absent unless the setting
//! [`ENABLED_SETTING`] is on. The portal routes (`attome-portal`) take the
//! account from the portal session and run checkout as the portal's service
//! user (V2-D1588 (1)).
//!
//! - **Catalogue visibility.** A product is on sale to a portal member when
//!   it is `is_orderable`, marked `portal_visible` (sales pack changeset
//!   0029), and has a price for the member's account in the shop's currency
//!   ([`CURRENCY_SETTING`], `SAR` by default) through D8's price resolution
//!   (the account's price, else its list, else the active list).
//! - **Cart.** One open cart per portal user (`commerce_cart`, migration
//!   0374); a line holds a product and a quantity only, never a price.
//! - **Checkout** re-prices every line for the account today (a product no
//!   longer on sale refuses the checkout), writes a `draft` order and its
//!   lines through the record engine as the service user, the audit naming
//!   the portal user, and closes the cart. When the order's total is above
//!   [`APPROVAL_LIMIT_SETTING`] (0, the default, means never) an approval
//!   request (`commerce.order_approval`, regarding the order) is submitted,
//!   and staff confirm the order once it is approved.
//! - **Offers** (F8-T6, [`crate::promotion`]): checkout applies the live
//!   promotions to the re-priced lines, and a coupon code when one is given
//!   (a code that matches no live offer refuses the checkout); each line
//!   keeps its discount and promotion, and the coupon's use is recorded
//!   with the order under the coupon's lock.

use std::str::FromStr;

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::Utc;
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::price_resolution::{PriceRequest, resolve};
use crate::quote::{line_total, load_price_inputs};

/// The setting that opens the shop (off by default).
pub const ENABLED_SETTING: &str = "commerce.enabled";
/// The shop's currency.
pub const CURRENCY_SETTING: &str = "commerce.currency";
/// The order total above which checkout asks for approval (0: never).
pub const APPROVAL_LIMIT_SETTING: &str = "commerce.approval_limit";
/// Products listed at most.
const MAX_PRODUCTS: i64 = 200;
/// Lines a cart holds at most.
pub const MAX_LINES: i64 = 100;

pub(crate) fn setting(state: &EngineState, key: &str) -> serde_json::Value {
    attome_core::setting_registry()
        .get(key)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .unwrap_or(serde_json::Value::Null)
}

/// Whether the shop is open.
pub fn enabled(state: &EngineState) -> bool {
    setting(state, ENABLED_SETTING).as_bool().unwrap_or(false)
}

pub(crate) fn currency(state: &EngineState) -> String {
    setting(state, CURRENCY_SETTING)
        .as_str()
        .map(str::trim)
        .filter(|c| c.len() == 3)
        .unwrap_or("SAR")
        .to_ascii_uppercase()
}

fn approval_limit(state: &EngineState) -> Decimal {
    let value = setting(state, APPROVAL_LIMIT_SETTING);
    value
        .as_f64()
        .and_then(|v| Decimal::from_str(&v.to_string()).ok())
        .unwrap_or(Decimal::ZERO)
}

/// A product on sale, priced for the account.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CatalogueItem {
    pub product_id: Uuid,
    pub name: Option<String>,
    pub name_ar: Option<String>,
    pub sku: Option<String>,
    /// The unit price for one, a decimal in text.
    pub price: String,
    pub currency: String,
}

/// A cart line, priced now.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CartLine {
    pub product_id: Uuid,
    pub name: Option<String>,
    pub quantity: String,
    /// `None` when the product is no longer on sale.
    pub unit_price: Option<String>,
    pub line_total: Option<String>,
}

/// The portal user's open cart.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Cart {
    pub cart_id: Option<Uuid>,
    pub currency: String,
    pub lines: Vec<CartLine>,
    pub total: String,
    /// False while a line is no longer on sale.
    pub can_check_out: bool,
}

/// One of the account's orders, as the shop lists it.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct ShopOrder {
    pub id: Uuid,
    pub name: Option<String>,
    pub order_number: Option<String>,
    pub status: Option<String>,
    pub currency: Option<String>,
    /// A decimal in text.
    pub grand_total: Option<String>,
    pub ordered_on: Option<String>,
}

/// What checkout made.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CheckedOut {
    pub order_id: Uuid,
    /// What the order comes to after offers.
    pub total: String,
    /// What the offers took off (F8-T6).
    pub discount_total: String,
    /// An approval request was submitted for the order.
    pub needs_approval: bool,
    pub approval_id: Option<Uuid>,
}

pub(crate) type ProductRow = (Uuid, Option<String>, Option<String>, Option<String>);

/// The products on sale whose name or SKU contains `search`.
pub(crate) async fn visible_products(
    state: &EngineState,
    search: Option<&str>,
    only: Option<&[Uuid]>,
) -> Result<Vec<ProductRow>, AppError> {
    sqlx::query_as(
        "SELECT id, name, to_jsonb(p) ->> 'name_ar', sku FROM product p \
          WHERE COALESCE(is_orderable, false) \
            AND COALESCE((to_jsonb(p) ->> 'portal_visible')::boolean, false) \
            AND (is_active IS NULL OR is_active = true) \
            AND ($1::text IS NULL OR name ILIKE '%' || $1 || '%' OR sku ILIKE '%' || $1 || '%') \
            AND ($2::uuid[] IS NULL OR id = ANY($2)) \
          ORDER BY name, id LIMIT $3",
    )
    .bind(search.map(str::trim).filter(|s| !s.is_empty()))
    .bind(only)
    .bind(MAX_PRODUCTS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// `product`'s unit price for `account` in `currency` today for
/// `quantity`; `None` without one.
pub(crate) async fn price(
    state: &EngineState,
    account: Option<Uuid>,
    product: Uuid,
    currency: &str,
    quantity: Decimal,
) -> Result<Option<Decimal>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let inputs = load_price_inputs(&mut tx, account, product, currency).await?;
    tx.rollback().await.map_err(AppError::internal)?;
    let request = PriceRequest {
        currency: currency.to_owned(),
        date: Utc::now().date_naive(),
        quantity,
        unit: None,
        default_unit: inputs.default_unit,
        account_price_list: None,
    };
    Ok(resolve(
        &request,
        &inputs.account_prices,
        &[],
        &inputs.lists,
        &inputs.factors,
    )
    .map(|p| p.price))
}

/// The products on sale to `account`, priced for one.
pub async fn catalogue(
    state: &EngineState,
    account: Uuid,
    search: Option<&str>,
) -> Result<Vec<CatalogueItem>, AppError> {
    let currency = currency(state);
    let mut out = Vec::new();
    for (id, name, name_ar, sku) in visible_products(state, search, None).await? {
        if let Some(p) = price(state, Some(account), id, &currency, Decimal::ONE).await? {
            out.push(CatalogueItem {
                product_id: id,
                name,
                name_ar,
                sku,
                price: p.to_string(),
                currency: currency.clone(),
            });
        }
    }
    Ok(out)
}

async fn open_cart(state: &EngineState, portal_user: Uuid) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar("SELECT id FROM commerce_cart WHERE portal_user_id = $1 AND status = 'open'")
        .bind(portal_user)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// The portal user's open cart, priced for `account` now.
pub async fn cart(state: &EngineState, portal_user: Uuid, account: Uuid) -> Result<Cart, AppError> {
    let currency = currency(state);
    let Some(cart) = open_cart(state, portal_user).await? else {
        return Ok(Cart {
            cart_id: None,
            currency,
            lines: Vec::new(),
            total: "0".into(),
            can_check_out: false,
        });
    };
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT product_id, quantity::text FROM commerce_cart_line WHERE cart_id = $1 \
          ORDER BY product_id",
    )
    .bind(cart)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let ids: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
    let on_sale = visible_products(state, None, Some(ids.as_slice())).await?;
    let mut lines = Vec::with_capacity(rows.len());
    let mut total = Decimal::ZERO;
    let mut ok = !rows.is_empty();
    for (product, quantity) in rows {
        let qty = Decimal::from_str(&quantity).unwrap_or(Decimal::ZERO);
        let listed = on_sale.iter().find(|p| p.0 == product);
        let unit = match listed {
            Some(_) => price(state, Some(account), product, &currency, qty).await?,
            None => None,
        };
        let line = unit.map(|u| line_total(qty, u, Decimal::ZERO));
        match line {
            Some(l) => total += l,
            None => ok = false,
        }
        lines.push(CartLine {
            product_id: product,
            name: listed.and_then(|p| p.1.clone()),
            quantity: qty.normalize().to_string(),
            unit_price: unit.map(|u| u.to_string()),
            line_total: line.map(|l| l.to_string()),
        });
    }
    Ok(Cart {
        cart_id: Some(cart),
        currency,
        lines,
        total: total.to_string(),
        can_check_out: ok,
    })
}

/// Sets `product`'s quantity in the portal user's open cart (0 removes it),
/// opening the cart when there is none. Only a product on sale to `account`.
pub async fn set_line(
    state: &EngineState,
    portal_user: Uuid,
    account: Uuid,
    product: Uuid,
    quantity: Decimal,
) -> Result<Cart, AppError> {
    if quantity < Decimal::ZERO {
        return Err(AppError::Validation("quantity: zero or more".into()));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if quantity.is_zero() {
        sqlx::query(
            "DELETE FROM commerce_cart_line WHERE product_id = $2 AND cart_id = \
                 (SELECT id FROM commerce_cart WHERE portal_user_id = $1 AND status = 'open')",
        )
        .bind(portal_user)
        .bind(product)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    } else {
        let listed = visible_products(state, None, Some(std::slice::from_ref(&product))).await?;
        let currency = currency(state);
        if listed.is_empty()
            || price(state, Some(account), product, &currency, quantity)
                .await?
                .is_none()
        {
            return Err(AppError::NotFound);
        }
        let cart: Uuid = sqlx::query_scalar(
            "INSERT INTO commerce_cart (id, portal_user_id, account_id) VALUES ($1, $2, $3) \
             ON CONFLICT (portal_user_id) WHERE status = 'open' \
             DO UPDATE SET updated_at = now(), abandoned_cart_outcome = NULL, \
                           abandoned_cart_notified_at = NULL RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(portal_user)
        .bind(account)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let lines: i64 =
            sqlx::query_scalar("SELECT count(*) FROM commerce_cart_line WHERE cart_id = $1")
                .bind(cart)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        sqlx::query(
            "INSERT INTO commerce_cart_line (cart_id, product_id, quantity) \
             SELECT $1, $2, $3::numeric \
              WHERE $4 < $5 OR EXISTS (SELECT 1 FROM commerce_cart_line \
                                        WHERE cart_id = $1 AND product_id = $2) \
             ON CONFLICT (cart_id, product_id) DO UPDATE SET quantity = EXCLUDED.quantity",
        )
        .bind(cart)
        .bind(product)
        .bind(quantity.to_string())
        .bind(lines)
        .bind(MAX_LINES)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    cart(state, portal_user, account).await
}

/// `account`'s orders, newest first (at most 50).
pub async fn orders(state: &EngineState, account: Uuid) -> Result<Vec<ShopOrder>, AppError> {
    sqlx::query_as(
        "SELECT id, name, to_jsonb(o) ->> 'order_number' AS order_number, status::text AS status, \
                currency, grand_total::text AS grand_total, ordered_on::text AS ordered_on \
           FROM \"order\" o \
          WHERE account_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY created_at DESC, id DESC LIMIT 50",
    )
    .bind(account)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Turns the portal user's open cart into a draft order for `account`, as
/// the portal's service user `ctx` for `behalf`, with the live offers and
/// `coupon` (for `contact`'s per-customer limit) applied.
#[allow(clippy::too_many_arguments)]
pub async fn checkout(
    state: &EngineState,
    ctx: &SecurityContext,
    behalf: &str,
    portal_user: Uuid,
    account: Uuid,
    contact: Option<Uuid>,
    coupon: Option<&str>,
) -> Result<CheckedOut, AppError> {
    let coupon = coupon.map(str::trim).filter(|c| !c.is_empty());
    let priced = cart(state, portal_user, account).await?;
    let Some(cart_id) = priced.cart_id else {
        return Err(AppError::Validation("the cart is empty".into()));
    };
    if !priced.can_check_out {
        return Err(AppError::Validation(
            "a product in the cart is no longer on sale; remove it first".into(),
        ));
    }
    let subtotal = Decimal::from_str(&priced.total).unwrap_or(Decimal::ZERO);
    let dec = |s: Option<&str>| s.and_then(|s| Decimal::from_str(s).ok());
    let priced_lines: Vec<crate::promotion::PricedLine> = priced
        .lines
        .iter()
        .map(|line| crate::promotion::PricedLine {
            product: line.product_id,
            quantity: dec(Some(line.quantity.as_str())).unwrap_or(Decimal::ZERO),
            unit_price: dec(line.unit_price.as_deref()).unwrap_or(Decimal::ZERO),
        })
        .collect();
    let now = Utc::now();
    let rule_view = json!({
        "account_ref": account,
        "subtotal": subtotal.to_string().parse::<f64>().unwrap_or(0.0),
        "line_count": priced.lines.len(),
        "currency": priced.currency,
    });
    let offers = crate::promotion::applicable_promotions(state, &rule_view, now, coupon).await?;
    if coupon.is_some() && !offers.iter().any(|o| o.coupon) {
        return Err(AppError::Validation(
            "the coupon does not apply to this cart".into(),
        ));
    }
    let discounts = crate::promotion::price_offers(&offers, &priced_lines, Decimal::ZERO, now);
    let discount_total: Decimal = discounts.iter().map(|d| d.amount).sum();
    let total = (subtotal - discount_total).max(Decimal::ZERO);
    // Claim the cart first, so two checkouts cannot both order it.
    let claimed = sqlx::query(
        "UPDATE commerce_cart SET status = 'ordered', updated_at = now() \
          WHERE id = $1 AND status = 'open'",
    )
    .bind(cart_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if claimed.rows_affected() != 1 {
        return Err(AppError::Conflict("the cart is being checked out already"));
    }
    let head = json!({
        "name": format!("Portal order {}", Utc::now().format("%Y-%m-%d")),
        "status": "draft",
        "ordered_on": Utc::now().date_naive(),
        "account_ref": account,
        "currency": priced.currency,
    });
    let mut head = head;
    head["subtotal"] = crate::order::number(&priced.total).unwrap_or(Value::Null);
    head["discount_total"] =
        crate::order::number(&discount_total.to_string()).unwrap_or(Value::Null);
    head["grand_total"] = crate::order::number(&total.to_string()).unwrap_or(Value::Null);
    let written = async {
        let (order, _) =
            attome_records::entity_crud::create_record_for(state, ctx, ctx.user_id, "order", head)
                .await?;
        for line in &priced.lines {
            let mine: Vec<&crate::promotion::Discount> = discounts
                .iter()
                .filter(|d| d.product == Some(line.product_id))
                .collect();
            let off: Decimal = mine.iter().map(|d| d.amount).sum();
            let gross = dec(line.line_total.as_deref()).unwrap_or(Decimal::ZERO);
            let mut body = json!({
                "order_ref": order,
                "product_ref": line.product_id,
                "quantity": crate::order::number(&line.quantity),
                "unit_price": line.unit_price.as_deref().and_then(crate::order::number),
                "line_total": crate::order::number(&(gross - off).max(Decimal::ZERO).to_string()),
            });
            if !off.is_zero() {
                body["discount_amount"] =
                    crate::order::number(&off.to_string()).unwrap_or(Value::Null);
                body["promotion_ref"] = json!(mine[0].promotion);
            }
            attome_records::entity_crud::create_record_for(
                state,
                ctx,
                ctx.user_id,
                "order_line",
                body,
            )
            .await?;
        }
        Ok::<Uuid, AppError>(order)
    }
    .await;
    let order = match written {
        Ok(order) => order,
        Err(error) => {
            // Give the cart back so the buyer can try again.
            sqlx::query("UPDATE commerce_cart SET status = 'open' WHERE id = $1")
                .bind(cart_id)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            return Err(error);
        }
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if let Some(code) = coupon
        && let Err(error) = crate::promotion::redeem_coupon(&mut tx, code, order, contact).await
    {
        drop(tx);
        // The coupon is used up or busy: take the order back and give
        // the cart back.
        if let Err(undo) = attome_records::entity_crud::delete_record_for(
            state,
            ctx,
            ctx.user_id,
            "order",
            order,
            None,
            &attome_records::entity_mutation::DeleteOrigin::new(
                attome_records::entity_mutation::DeleteKind::Portal,
            ),
        )
        .await
        {
            tracing::error!(%order, error = %undo, "checkout: an order was not taken back");
        }
        sqlx::query("UPDATE commerce_cart SET status = 'open' WHERE id = $1")
            .bind(cart_id)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        return Err(error);
    }
    sqlx::query("UPDATE commerce_cart SET order_id = $2 WHERE id = $1")
        .bind(cart_id)
        .bind(order)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "order",
            order,
            attome_audit::AuditOperation::Create,
            "sales.order.created",
            ctx.user_id,
        )
        .comment(format!(
            "{} line(s) from the portal, on behalf of {behalf}",
            priced.lines.len()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    // F8-T8: a risky order gets its review (and so a fulfilment hold).
    crate::risk::assess_logged(state, ctx, order).await;

    let limit = approval_limit(state);
    let approval_id = if limit > Decimal::ZERO && total > limit {
        let request = attome_approval::submit_regarding_with(
            &state.base.db,
            "commerce.order_approval",
            json!({ "order_id": order, "total": total.to_string(), "limit": limit.to_string(),
                    "requested_for": behalf }),
            ctx.user_id,
            1,
            chrono::Duration::days(7),
            Some(("order", order)),
            &attome_db::NoHook,
        )
        .await?;
        Some(request.id)
    } else {
        None
    };
    Ok(CheckedOut {
        order_id: order,
        total: total.to_string(),
        discount_total: discount_total.to_string(),
        needs_approval: approval_id.is_some(),
        approval_id,
    })
}
