# Subscriptions on the portal

With the setting `billing.portal.subscriptions` on (it is off by default), a person signed in to a
portal can read their own account's subscriptions: `GET /{keyword}/api/v1/billing/subscriptions` answers
each subscription's name, status, currency, term, billing frequency, renewal mode and any cancellation
date, the lines in force today (product, quantity, unit price) and up to twelve charges still to come.
The account is the portal user's contact's account, never one the request names. While the setting or
the billing module is off, and for a portal user with no account, the route answers 404.

## Changing a subscription from the portal

A portal user may change two things, both through the subscription service and both running as the
portal's **service user**: a staff account an administrator names on the portal
(`PATCH /api/v1/admin/webportals/{id}` with `service_user_ref`; it needs an active account and only the
`subscription.update` and `subscription.cancel` privileges). Each audit event is the service user's,
with "on behalf of portal user ..." in its comment. While the portal has no service user, both routes
answer 404.

- `POST /{keyword}/api/v1/billing/subscriptions/{id}/quantity` `{line_id, quantity}`: from today, at
  the price in force, prorated for the rest of the period. Only within the line's **Portal minimum
  quantity** and **Portal maximum quantity** (`portal_min_quantity`, `portal_max_quantity`); a line
  with neither cannot be changed on the portal.
- `POST /{keyword}/api/v1/billing/subscriptions/{id}/cancel` `{reason}` (`price`, `product_fit`,
  `budget`, `switched_vendor` or `other`): at the end of the term only, never at once. A subscription
  without a term end cannot be cancelled from the portal.

## Invoices and payment methods on the portal

With the setting `billing.portal.payments` on (off by default), the same portal user can read:

- `GET /{keyword}/api/v1/billing/invoices/open`: the account's issued invoices with an amount still
  open (number, currency, total, open amount, payment status, issue and due dates), oldest due first;
- `GET /{keyword}/api/v1/billing/payment-methods`: the account's saved payment methods (brand, last
  four digits, expiry, which is the default). A method's token and gateway are never read for the portal.

Both answer 404 while the setting or the billing module is off. Two changes run, like the subscription
changes, as the portal's service user (which also needs `payment_link.create` and
`saved_payment_method.delete`), the audit naming the portal user:

- `POST /{keyword}/api/v1/billing/invoices/{id}/pay`: a payment link for one of the account's open
  invoices; the customer pays on the hosted payment page it opens.
- `DELETE /{keyword}/api/v1/billing/payment-methods/{id}`: removes one of the account's saved methods.
