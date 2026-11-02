# Subscriptions

Recurring billing (F3) in the billing engine: subscriptions with dated segments and charge models, usage
metering, daily charge planning, billing runs that hand charges to invoicing (F4), renewals, trials, the
portal, and recurring-revenue metrics.

## Routes

| Route | What it does |
|---|---|
| `POST /api/v1/billing/subscriptions`, `GET /api/v1/billing/subscriptions/{id}` | Create a subscription; read one with its segments (lists go through the record API). |
| `POST /api/v1/billing/subscriptions/{id}/amendments` and `…/amendments/{amendment_id}/reverse` | Change lines from a date (a new dated segment); reverse an amendment. |
| `POST /api/v1/billing/subscriptions/{id}/pause`, `/resume`, `/cancel` | Pause, resume and cancel. |
| `POST /api/v1/billing/usage` | Record metered usage for a usage-priced line. |
| `POST /api/v1/billing/runs/preview`, `POST /api/v1/billing/runs` | Preview what a billing run on a date would invoice (nothing written); run it. |
| `GET /api/v1/billing/metrics/recurring` | Recurring revenue figures. |

The portal routes (`/{keyword}/api/v1/billing/subscriptions…`) are in [billing-portal.md](billing-portal.md).

## How charges become invoices

Every day the charge job plans each active subscription's charges: one recurring charge per line and
billing period, priced from the segment in force when the period starts (a part period is prorated), a
setup charge once for a setup-fee line, and a usage charge per line and ended period from the metered
daily totals. Each charge has its own key, so running the job again plans nothing twice. A billing run
groups the planned charges by account, period end and currency and sends each group to invoicing as one
invoice request, also keyed, so a restarted run neither loses nor doubles a group.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `billing.renewal.lead_days` | 60 | Days before the end that a subscription renews (auto mode) or gets a renewal opportunity. |
| `billing.renewal.uplift_percent` | 0 | Percent added to each line's price on an automatic renewal. |
| `billing.trial.reminder_days` | 3 | Days before a trial ends that its owner is reminded. |
| `billing.trial.convert` | on | Whether a trial becomes an active subscription on its end date; off ends it. |
| `billing.portal.subscriptions` | off | Whether portal users see (and change) their account's subscriptions. |

## Open points

- **Usage volume.** How much metered usage a deployment stores, and for how long, has not been measured;
  daily totals are kept per line.
- **Hijri months.** Billing periods follow Gregorian months; billing by Hijri month is not enabled until
  the Hijri calendar check (AG2) is done.
