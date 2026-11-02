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

## The shop pages

Members shop at `/shop/{keyword}` on the deployment's web app, in Arabic or English: the products on sale
with their prices and a search, a **quick order** (one `SKU quantity` per line), the cart (change a
quantity, remove a line, place the order; an order waiting for approval says so) and **My orders** with
each order's shipped quantities and tracking numbers.
