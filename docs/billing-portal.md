# Subscriptions on the portal

With the setting `billing.portal.subscriptions` on (it is off by default), a person signed in to a
portal can read their own account's subscriptions: `GET /{keyword}/api/v1/billing/subscriptions` answers
each subscription's name, status, currency, term, billing frequency, renewal mode and any cancellation
date, the lines in force today (product, quantity, unit price) and up to twelve charges still to come.
The account is the portal user's contact's account, never one the request names. While the setting or
the billing module is off, and for a portal user with no account, the route answers 404.

Changing a quantity or cancelling at the end of the term from the portal is not available yet: those
changes run through the subscription service, which acts as a staff user, and how a portal user may act
through it is still to be decided. Staff make them as before.
