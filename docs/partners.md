# Partners

The partner pack (`packs/partner`) holds partner programmes and tiers, deal registrations,
applications, onboarding, certifications, market development funds and resources. The `partner`
module runs the engine code below; partners use the partner portal pages ([pages.md](pages.md)).

## Deal registration

A partner registers a deal as a `deal_registration` record, from the portal's **Register a deal**
page or any record write. It starts `submitted`.

**Conflict check.** Every minute the server checks each new registration against:

- the open opportunities on the same customer account, and
- other partners' registrations (submitted, in conflict or approved) for the same customer — the
  same account, or the same name with Arabic spelling folded (`أحمد` and `احمد` match) — and the
  same product when both name one.

With any, the registration becomes `conflict` and `conflict_summary` lists them; `checked_at`
records the check. The partner account's partner manager is told either way.
`GET /api/v1/partner/registrations/{id}/conflicts` finds them again at any time.

**Decision.** `POST /api/v1/partner/registrations/{id}/decision` with
`{"decision": "approve"}` (optionally `"opportunity_id"` to link an existing deal) or
`{"decision": "reject", "reason": "..."}`. A person with update access on the registration decides
from a signed-in browser session; API keys and S2S clients are refused, so an integration or agent
never decides. Approval:

- is refused (409) while another partner holds live protection for the same customer and product;
- sets `protection_ends_on` from the partner's tier (`protection_days`, else 90 days);
- links the opportunity named, or creates one on the customer account from the registration's
  name, amount and expected close, and names the partner in `opportunity.partner_account_ref`.

Partners reach their deals through the portal: give the partner portal role read access to
`opportunity` scoped to `partner_account_ref`. Do not grant portal write access to a registration's
`status`, `opportunity_ref`, `protection_ends_on`, `decision_reason`, `conflict_summary`,
`checked_at` or `decided_by`; the server sets them.

**Lapse.** Daily, an approved registration whose protection has ended becomes `lapsed`, and its
opportunity stops naming the partner unless the deal was won.

Every decision and lapse is written to the audit log as a business event.

## Market development funds

A partner asks for part of its fund (`mdf_fund`) as an `mdf_request`, and claims its spend against
an approved request as an `mdf_claim` with a proof file. Give the partner portal role access to
`mdf_fund`, `mdf_request` and `mdf_claim` scoped to the partner's own account, so no partner sees
another's amounts.

**Check.** Every minute the server refuses, with the reason, a submitted request asking for more
than is left of its fund — the fund's amount less the approved requests and the submitted ones made
before it, so pending requests are served first come, first served — and a claim whose request is
not approved or that has no proof file. The partner manager is told of each.

**Decision.** `POST /api/v1/partner/mdf/requests/{id}/decision` and
`POST /api/v1/partner/mdf/claims/{id}/decision`, with `{"decision": "approve"}` or
`{"decision": "reject", "reason": "..."}`, by a person with update access (API keys and S2S clients
are refused). A request is approved under the fund's lock only while it still fits. An approved
claim writes the event `partner.mdf_claim_approved` once, in the same transaction, for payment to
take up; nothing is posted to a ledger here.

## Certifications

Daily, a partner certification that expires within 30 days is warned once for that expiry date
(`warned_on`), telling the partner's partner manager. A certification renewed to a later date is
warned again 30 days before the new one.

## Leads

`POST /api/v1/partner/leads/{id}/offer`, with `{"partner_account_id": "...", "accept_hours": 48}`,
offers a lead to a partner; a person with update access on the lead offers it. The partner answers
on the portal (`POST /{keyword}/api/v1/partner/leads/{id}/accept` or `/reject`) before the limit;
only the partner the lead is offered to can answer. A rejection clears the partner from the lead.

Hourly, an offer past its limit, or an accepted lead untouched for `partner.lead_stale_days` days
(14 by default), becomes `returned` and no longer names the partner. The lead's owner never
changes, so it is simply theirs again. A lead is never deleted here.

## Tiers

On the first day of each fiscal quarter, each partner in a programme is measured over 12 months:
revenue from won opportunities naming it, certified people with an unexpired certification, and
approved registrations. A partner whose highest met tier differs from its own gets one
`tier_change_proposal`, unless one is already open. Nothing changes a tier until a person with
update access calls `POST /api/v1/partner/tier-proposals/{id}/confirm` or `/dismiss`, with
`If-Match`. Quarters start in January; the deployment has no fiscal-year setting yet.

## Recruiting

Anyone may apply through a portal: `POST /{keyword}/api/v1/partner/applications`, with the limits and
CAPTCHA of sign-up. The application is matched to an account by name or by email domain, ignoring
shared mail providers, and nothing else happens until a person decides.

`POST /api/v1/partner/applications/{id}/decision` needs update access. Approval, with a `portal_id`,
marks the matched account a partner or creates one, adds a contact and invites that person to the
portal, all or nothing. A rejection needs a reason.

`POST /api/v1/partner/applications/{id}/agreement` then sends the agreement document for e-signature,
once. Within the hour after it is signed the partner has three onboarding items: training (30 days),
first certification (60) and first registered deal (90). The last one finishes itself when the
partner's first registration is approved.

## Partner pay

A partner takes part in a commission plan like a seller: set `partner_account_ref` on the
`plan_participant` instead of `user_ref`. Publishing a plan refuses a participant with neither or
both. A plan pays a partner through a `partner_referral`, `partner_margin` or `rebate` component
measuring `split_amount`.

A won deal that names the partner (`opportunity.partner_account_ref`) credits that participation
once, and the credit has no owner, so sellers' record rules do not reach it. A person signed in to
the partner's portal reads the partner's statement with
`GET /{keyword}/api/v1/partner/statement?period_id=<id>`; a period with nothing for that partner
answers 404.
