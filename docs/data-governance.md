# Data governance

Who is accountable for which data, and how that accountability is worked: domains, governance roles,
policies and their exceptions, the steward inbox, governed change at publish, certification, and the
coverage report. Governance is off until the first domain is created.

## Domains

A data domain (Customer, Product, Finance, HR) can sit under a parent domain (`parent_ref`). Each entity
belongs to at most one domain (`entity_info.domain_ref`). Compliance administrators manage them:

- `GET`/`POST /api/v1/admin/governance/domains`, `GET`/`PATCH`/`DELETE .../domains/{id}`;
- `PUT`/`DELETE .../domains/{id}/entities/{entity_logicalname}` to assign or release an entity;
- `GET .../domains/{id}/report`, the domain's accountability report.

Domain and assignment changes are recorded in changesets, so they can be compared and promoted.

## Roles

`GET`/`PUT`/`DELETE /api/v1/admin/governance/domains/{id}/roles` assign people to a domain as **owner**
(accountable), **steward** or **deputy** (do the work), **custodian** (changes the model) or
**consumer**. These are role assignments, not new kinds of user. A domain's owner or steward edits its
roles and policies and certifies its entities without `system.admin`; anyone holding a role in the
domain reads its roles, policies and exceptions. Everyone else gets 403, or 404 for a policy they
cannot see. A user who still holds governance roles cannot be disabled: the request answers
`409 governance_roles_held` with the roles to reassign first.

## Policies and exceptions

A policy (`/api/v1/admin/governance/policies`) is a statement in Arabic and English, linked to what
enforces it: a write check, a label, attribute security, retention or residency, each naming its
target. A policy with no enforcement is reported as not enforced; there is no second enforcement
engine. Every edit raises the policy's `version`.

`POST .../policies/{id}/exceptions` asks for a time-limited exception with a reason. It goes to the
domain's owners and stewards as an approval request (the requester excluded) and shows as
`requested`, `approved`, `rejected` or `expired`.

Policies are deployment governance records and do not travel in changesets. Every role, policy,
exception and certification change writes a Configuration security event.

## The steward inbox

`GET /api/v1/governance/inbox` is one queue of the work waiting on a steward in their domains: open
duplicates, open quality issues and active legal holds, oldest first, each with a link to the screen
that owns it. Nothing is edited from the inbox. An entity's items are listed only when the steward may
read every record of it, so the inbox never names a record they cannot read.

A deputy sees a domain's items while its steward is out of office or the domain has no steward. Once a
day, items older than two days are escalated to the domain's owners, once each.

## Governed change at publish

With `PUT /api/v1/admin/governance/domains/{id}/governed-change` switched on, a changeset apply that
changes the domain's entities waits for approval by its owners or stewards, with the lineage impact of
every deleted, retyped or renamed field attached. Approved, it goes on as before. Applies that touch no
governed domain are unchanged.

## Certification

`POST /api/v1/admin/governance/certifications` certifies an entity as the trusted source for its
subject, storing a hash of its definition (its columns and active attributes). Once the definition
changes the certification reads back as `stale`; after each changeset apply, certified entities whose
definition changed are marked stale.

## Coverage, scorecards and evidence

For compliance administrators, read only, each list capped and marked `truncated` when cut:

- `GET /api/v1/admin/governance/coverage`: entities in no domain, domains with no owner, personal
  attributes in domains with no policy, policies with nothing enforcing them, and stewards with overdue
  inbox items.
- `GET /api/v1/admin/governance/domains/{id}/scorecard`: the domain's data quality, open and overdue
  inbox items, exceptions and policy coverage.
- `GET /api/v1/admin/governance/evidence`: roles, policies with their enforcements, exceptions and
  governed-change approvals as one JSON document for an audit.

## Agent tools

`governance.list_overdue` reads overdue exceptions, stale certifications and unowned entities.
`governance.propose_domains` and `governance.draft_policy` are consequential: an agent's call waits for a
person's approval and then runs as that person, through the same functions as the routes above.
