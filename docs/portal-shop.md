# The portal shop

Portal members can buy from you on the portal: browse what is on sale to their account, keep a cart and
check out into an order. It is off until you turn on the setting `commerce.enabled`, and it needs the
sales module.

## What is on sale

A product is on sale to a portal member when it is **orderable**, marked **Sold on the portal**
(`portal_visible`), and has a price for the member's account in the shop's currency (`commerce.currency`,
`SAR` by default). The price is resolved the way quotes and orders resolve it: the account's own price,
else its price list, else the active list, with quantity breaks. A member never sends a price.

## Cart and checkout

Each portal user has one open cart. It holds products and quantities only; prices are worked out each time
the cart is read and again at checkout. Checkout:

1. re-prices every line for the account today, and refuses while a product is no longer on sale;
2. writes a **draft** order for the account with one line per product, through the record engine as the
   portal's **service user** (`webportal.service_user_ref`, which needs `order.create` and
   `order_line.create`), the audit naming the portal user;
3. closes the cart;
4. when the total is above `commerce.approval_limit` (0, the default, means never), submits an approval
   request (`commerce.order_approval`) regarding the order. Staff confirm the order as usual once it is
   approved.

## Promotions and coupons

Checkout applies the live promotions (`promotion`, sales pack changesets `0030` and `0032`) after the
list price and before VAT, in this order: percent, amount, buy X get Y, free shipping, bundle. Each
offer takes from what the earlier ones left, so a line never goes below zero. A promotion is live while
it is enabled, inside its start and end dates, at or above its minimum subtotal, and while its
eligibility rule holds for the cart (`account_ref`, `subtotal`, `line_count`, `currency`). It may name
one product (`product_ref`), buy and free quantities (`buy_quantity`, `get_quantity`), or the SKUs of a
bundle (`bundle_skus`, comma separated; `value` is the amount off each complete set).

A promotion with coupons applies only with one of its codes: `POST …/shop/cart/checkout?coupon=CODE`.
A code that matches no live offer is refused (422). The coupon's use is recorded with the order
(`coupon_redemption`, and the coupon's `uses_count`) under a lock per code, so a coupon with
`max_uses` 1 is used once however many people check out at the same moment; a coupon used up, or over
the promotion's `max_uses_per_customer` for the buyer's contact, refuses the checkout (409) and gives
the cart back. Each order line keeps its `discount_amount` and `promotion_ref`, so the cost of every
offer can be reported.

## Shipping and guest checkout

Shipping zones (`shipping_zone`: `countries` and optional `cities`, comma separated) hold rates
(`shipping_rate`): `flat`, `by_weight` (inside `min_weight`..`max_weight`; products carry no weight yet,
so only a band without a lower bound matches), `free_over` (nothing once the total reaches
`free_over_amount`) and `carrier_live` (nothing until a carrier connector quotes). Cash on delivery adds
the rate's `cod_fee`. `GET /{keyword}/api/v1/shop/shipping?country=SA&city=&total=` lists the options.

A buyer without a portal account can check out once `commerce.guest_account` names the account guest
orders go under (and `commerce.vat_rate`, 0 by default, is the VAT rate on them):

1. `POST /{keyword}/api/v1/shop/guest/start` `{phone, lines: [{product_id, quantity}]}` keeps the lines and
   texts a 6-digit code (through the SMS provider; only its SHA-256 is stored), valid 10 minutes; at most
   3 codes per phone in 15 minutes and 10 tries per address and minute.
2. `POST /{keyword}/api/v1/shop/guest/confirm` with an `Idempotency-Key` header and `{checkout_id, code,
   name, address, country, city, shipping_rate_id, cash_on_delivery, coupon}` places the order: prices,
   offers, shipping and VAT are worked out again here. A wrong code is 401 (5 tries); the same key again
   returns the same order; a second key for a spent code is 409. The contact is matched by phone or made.
   Cash on delivery sets `payment_status` `due_on_delivery` and `cod_amount`; otherwise a payment link for
   the order is returned as `payment_url`.

Both guest routes need the portal's own origin and its service user (`contact.create`, `order.create`,
`order_line.create`, and `payment_link.create` for paid orders).

## Reviews and risky orders

A portal member reviews a product they received (`POST /{keyword}/api/v1/shop/reviews` `{product_id,
rating, body}`; refused with 403 without a fulfilled order of the product for their contact, once per
product). Every review waits as `pending`: nothing is published automatically. A store person sets
`published`, `held` or `rejected` (with `moderation_reason`) on `product_review` through the record API.
`GET /{keyword}/api/v1/shop/products/{product_id}/reviews` lists only published reviews, without names.

After an order is placed, its risk signals are checked: cash on delivery above `commerce.risk.cod_limit`
(0, the default, is off), or 3 or more failed card payments for the account in the last 24 hours. Any
signal opens a `risky_order_review` (`open`, with the reasons); while it is open, fulfilment puts a
`fraud_check` hold on the order's fulfilment orders, so nothing ships until a person clears the hold and sets
the review `released` or `cancelled`.

## Abandoned carts

With `commerce.abandoned_cart.enabled` on (off by default), every 15 minutes the open portal carts that
hold a line and have sat unchanged for `commerce.abandoned_cart.idle_minutes` (60 by default, up to 7
days old) are looked at once. When the buyer's contact has a phone or email and its `marketing` consent,
a `cart.abandoned` event on the contact goes to the change feed, where a marketing journey with the
entry source `{"type": "event", "event_name": "cart.abandoned"}` picks it up and sends; without consent
the cart is marked skipped. Changing the cart makes it eligible again. Nothing is sent by the sweep
itself.

## Routes

- `GET /{keyword}/api/v1/shop/catalogue?search=`
- `GET /{keyword}/api/v1/shop/cart`
- `PUT /{keyword}/api/v1/shop/cart/lines/{product_id}` `{quantity}` (0 removes)
- `POST /{keyword}/api/v1/shop/cart/checkout?coupon=`
- `GET /{keyword}/api/v1/shop/orders`: the account's orders, newest first; each order's lines and
  tracking come from `GET /{keyword}/api/v1/fulfilment/orders/{order_id}` (with `fulfilment.portal` on).

All take the account from the signed-in member's contact and answer 404 while the shop is off.

- `GET /{keyword}/api/v1/shop/guest/catalogue?search=`: what a guest may buy, priced for the
  `commerce.guest_account` account; no sign-in; 404 while guests cannot check out.

Every catalogue item carries `vat` (the VAT on one at `commerce.vat_rate`) and `price_with_vat`, and,
when the shop tracks stock, `stock`: `in_stock`, `low` or `sold_out` from the free stock (on hand less
reserved) at the location `commerce.stock_location` names, `low` at or below `commerce.low_stock`
units (5 by default). Without a stock location, or for a product not stocked there, `stock` is absent.

## The shop pages

Members shop at `/shop/{keyword}` on the deployment's web app, in Arabic or English: the products on sale
with their prices and a search, a **quick order** (one `SKU quantity` per line), the cart (change a
quantity, remove a line, place the order; an order waiting for approval says so) and **My orders** with
each order's shipped quantities and tracking numbers.

### Store blocks on portal pages

The public store is built from portal pages (see `docs/pages.md`): a page places the store's blocks
as `{"type": "custom", "component": "<block>"}` nodes, and the portal renders them in Arabic (right to
left) or English:

| Block | Shows |
|---|---|
| `store.product_grid` | The guest catalogue: each product's price with VAT, the VAT in it and its stock badge, and an add to the basket (not when sold out). `props.search` narrows it; `props.detail_page` links each name to that page with `?product=`. |
| `store.product_detail` | One product (`?product=` in the address, else `props.product_id`): the price with VAT, the net price and the VAT, the stock badge, its variants to choose from and a quantity to add. |
| `store.cart` | The basket: quantities, removal and the total with VAT. |
| `store.checkout` | Guest checkout: the phone gets a code; with the code, name, address, a delivery option and cash on delivery or paying online, the order is placed once. Paying online opens the order's payment page. |
| `store.order_status` | The order this browser tab placed, and a signed-in member's orders. |

The basket lives in the browser tab (session storage) and holds products and quantities only; the
server prices the order again at checkout.

A product can be a variant of another (`product.variant_of_ref` and `product.variant_label`, sales
pack changeset 0034), such as a size or a colour; each variant is its own product with its own SKU,
price and stock. Catalogue items carry `variant_of` and `variant_label`. The grid shows a parent once
with its number of options, and the product detail lets the shopper pick a variant (a sold-out one
cannot be picked).
