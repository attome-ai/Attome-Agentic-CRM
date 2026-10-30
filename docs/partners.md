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
