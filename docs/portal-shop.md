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
