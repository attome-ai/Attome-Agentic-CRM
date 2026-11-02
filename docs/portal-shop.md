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

## Routes

- `GET /{keyword}/api/v1/shop/catalogue?search=`
- `GET /{keyword}/api/v1/shop/cart`
- `PUT /{keyword}/api/v1/shop/cart/lines/{product_id}` `{quantity}` (0 removes)
- `POST /{keyword}/api/v1/shop/cart/checkout`

All take the account from the signed-in member's contact and answer 404 while the shop is off.
