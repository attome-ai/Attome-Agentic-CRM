# The access model

Who can see and change a record, field by field. One filter decides record access
(`attome_security::rls`), one gate decides field visibility (`attome_security::field_gate`), and every
grant path checks conflict rules. This page is the model; the admin routes are in `openapi.json` under
`admin-security`.

## Privileges and levels

A person gets access through **roles** (held directly or through a **team**), **permission sets**, and
privileges granted to them directly. A per-entity privilege `{entity}.{action}` says *whether* they may do
something to an entity; a **level** per role and entity says *how far*:

| Level | Value | Records |
| --- | --- | --- |
| None | 0 | Only those shared with them |
| Team | 1 | Through shares to their teams |
| Business unit | 2 | Those in their units (and, by default, the units under them) |
| Global | 3 | All |

Levels are kept per operation in `role_mm_entity_access` (and `permission_set_entity_access`):

| Operation | Gated by the privilege | Level when not set |
| --- | --- | --- |
| read, update, delete | `{entity}.read` / `.update` / `.delete` | Global (no access row) |
| create | `{entity}.create` | the write level |
| assign | `{entity}.update` | the write level |
| share | `{entity}.share` | the write level |
| export | `{entity}.read` | none |
| bulk | `{entity}.bulk` | none |

Export and bulk are denied unless granted. A role in the D-589 **legacy** bulk mode (every role created
before it) keeps today's reach: export at its read level, bulk at its write level. A person's level is the
highest any of their roles, sets or direct grants gives (direct grants are Global).

**Child units.** Each business-unit level has a flag, `{operation}_bu_children`, on by default. Off, the
level reaches only the person's own units (memberships and home unit), not the units under them. Where
several roles give business-unit level, child units count when any of them includes them.

**Ownership.** A role can let owners see the records they own (`{operation}_owner_visible`), whatever
its level.

**My records and everything under me.** A role can also reach, per operation, the records owned by the
person and by everyone under them in the position hierarchy (`{operation}_owner_subtree` for read, write
and delete), whatever its level: a manager with no level of their own sees their team's records. The
subtree is resolved with the rest of the person's access and is separate from the position-hierarchy
switch that widens shares.

**Conditional grants.** A role's privilege may carry up to three conditions that narrow which records it
reaches (D-369): a field compared with a value, or (operator 7) a rule expression such as
`amount > 100 and status == "open"` over the entity's filterable, ungated fields. An expression runs in the
database as part of the filter; one the SQL translation cannot express (the clock, lookups, lists,
functions without a SQL meaning) is refused at save with 422 `untranslatable_condition`, and one that stops
translating later (a field removed) denies rather than opens.

## Suggested roles

Modules suggest roles (`GET /api/v1/admin/security/role-templates`, for the licensed modules): a sales
rep and a sales manager, and an auditor. Installing one (`POST .../role-templates/{key}/install`)
creates an ordinary role with the template's privileges and levels, which administrators then own;
upgrades never change it. A privilege or entity the deployment does not have is skipped and named.

## Permission sets

A permission set is an additive bundle of privileges and entity levels, assigned to a user or a team,
optionally until an end date (`ends_at`). A live assignment counts exactly like one more role; an ended one
gives nothing. A set never takes access away and never carries `system.admin` (refused with 422
`set_cannot_grant_admin`).

- Sets: `/api/v1/admin/security/permission-sets` (with `/entity-access` and `/privileges`). They travel in
  bundles and changesets and, on the production profile, change only through a promoted changeset.
- Assignments: `/api/v1/admin/security/permission-set-assignments/{set}`. They are environment data, like
  a user's roles, and do not travel.

## Sharing

- **Record shares** give one user or team `view` or `action` on one record; a `deny` share wins over
  everything but administration.
- **Default shares** give a user or team every record of an entity.
- **Sharing rules** (the `sharing_rule` metadata kind) share an entity's records owned by a unit, a team or
  a role's holders with another unit, team or role, to read or to read and change. A rule is a condition in
  the filter, not share rows, so it stops applying the moment it is unpublished; a deny still wins. A rule
  that would pick records by a condition is refused at save. Search and audit lists, which filter many
  entities at once, do not apply rules yet: they show less, never more.

## Controlled by parent

An entity's settings can make its records follow a parent record:
`"access": { "mode": "controlled_by_parent", "lookup": "<attribute id>" }` names one of the entity's
many-to-one lookups. A person then sees and changes a child record exactly when they may see or change its
parent record: their level is their level on the parent entity (through the parent's privilege), and the
filter checks the parent record's unit, owner, shares, sharing rules and deny. A deny share on the child
record still wins, and a child whose lookup is empty is visible only at Global level.

It is one hop: the parent's own roles decide, and a parent that is itself controlled by its parent is not
followed further. The lookup is checked when the settings are saved and again when the version is loaded;
one that no longer resolves is left out (the entity keeps its own access) and named in the log. Search and
audit lists, which filter many entities at once, apply the child's own levels: they show less, never more.

## Fields

A sensitive field needs a **field-security** grant: a profile, assigned to roles, that grants `can_read`
and `can_update` per field. A field is sensitive when it is marked `is_sensitive` (read as Secret) or its
sensitivity label is Personal, Financial, Health or Secret and a builder confirmed the label (setting it
through the admin field routes confirms it). Labels the A1-T1 migration mapped from `data_classification`
stay unconfirmed and gate nothing until confirmed, so no field disappears on upgrade. A grant may instead **mask** the field (`mask_format`:
`last4`, `email`, `phone` or `full`): the database computes the mask, so the value never reaches the
client in full; record reads and lists show the mask, export and other bulk surfaces hide the field, and a
masked field cannot be changed. A grant in full from any profile wins over a mask.

Bulk surfaces (export, query, reports, AI context) also need the field listed for the role, unless the
role is still in D-589 legacy mode.

**Who saw a Financial or Health value.** Every read that shows a confirmed Financial or Health value in
full (record reads, lists, `query/execute`, reports, AI context and document generation) is logged in
`field_view_log`: who, which entity, record and field, and when. A masked value is not logged. Each node
buffers up to 10,000 entries and writes them every ten seconds; a read that finds the buffer full writes
it before answering, and fails if it cannot, so no entry is dropped. A node that stops between writes
loses at most ten seconds of entries.

## Conflicting access

A **conflict rule** names two roles, privileges or permission sets one person must not hold together
(`/api/v1/admin/security/role-conflicts/rules`). Every grant that adds access checks the rules in its own
transaction: a direct role grant, joining a team, a team's new role, and a set assignment. A rule fires
when the grant would complete the pair:

- `refuse`: 409 `role_conflict`.
- `approval`: a direct role grant goes to a second administrator, with a reason required; the other paths
  refuse with `role_conflict_needs_approval`.

`GET /api/v1/admin/security/role-conflicts/current` lists who holds a pair today.

## Seeing and acting as someone

An administrator can start a session as another person (`POST /api/v1/admin/security/impersonation`
with the person, `view` or `act`, and a reason), after a fresh step-up (`impersonation`). The session lasts
30 minutes, is never refreshed, and is ended early with `DELETE .../impersonation/{id}`; an administrator
holds one at a time. Nobody is impersonated who is an administrator or a machine identity.

The administrator then sends the session id in the `x-attome-impersonation` header from their own signed-in
browser (never an API key or a machine), and each request runs with the person's access:

- **View as** changes nothing: every request but a read (and running a query or a search) is refused with
  `impersonation_read_only`.
- **Act as** needs the person's consent: the person allows one administrator, for 1 to 72 hours
  (`POST /api/v1/me/impersonation-consents`), and can withdraw it at any time, which also ends the session.
  Their credentials, second factors, keys, sessions and consents, approval decisions and administration are
  never done as them (`impersonation_refused`).

Every request in a session is logged before it runs (`impersonation_request`), and refused if it cannot be.
A request naming an unknown, ended or expired session is refused with 422 `impersonation_ended` (not 401, so
the browser does not take it for an expired sign-in), and the banner closes.
Every audit row it writes names both people: the person's access was used (`acting_user_id`), by whom
(initiator `impersonation`, the session, and `impersonator:<administrator id>`), all in the v2 hash. The
person sees every session about them at `GET /api/v1/me/impersonation-sessions`.

## Second factors by role

Each role can set what it asks of a person signing in: a second factor `required`, `optional` or
`off`, or `inherit`, which takes the deployment's `auth.mfa_policy`. The deployment value is the
default under the roles: it applies to a role set to `inherit` and to a person whose roles set
nothing. A role may set its own mode instead, stricter or not.

- **The strictest role wins.** A person with one `required` role and one `off` role needs a
  factor. The factors their roles allow are the ones every role allows.
- **Administrators always need one.** A `system.admin` holder needs a passkey or TOTP (or a
  recovery code) at every password sign-in, with no grace period, whatever the roles say. An
  administrator without a factor is asked to enrol at their next sign-in.
- **Grace period.** When a role requires a factor a person has not set up, the role's
  `mfa_grace_days` lets them sign in and put enrolment off a day at a time
  (`POST /api/v1/auth/mfa/postpone` with the pending sign-in token) until the grace period ends.
  After that, sign-in continues only through enrolment.
- **Provider sign-in.** A sign-in through a provider meets a required policy when the provider
  reports that it checked a second factor; otherwise it is refused with `mfa_required`.

A role's mode is stored with its sign-in policy (`role_auth_policy`). The route that sets it today,
`PUT /api/v1/admin/security/roles/{id}/auth-policy`, sets single sign-on only; setting the second
factor mode comes with the security policy screens.

## Explaining access

- `GET /api/v1/{entity}/{id}/access/explain?user=&action=` explains one record: every source the filter
  applies (administrator, privilege, role level, business unit, ownership, user and team shares, default
  share, sharing rule, deny), with the deciding one marked. Asking about someone else needs the Security
  administration area; asking about yourself needs read access to the record.
- `GET /api/v1/admin/security/users/{id}/effective-access?entity=&action=` lists every path to a
  person's level on an entity: roles direct and through teams, permission sets, conditional grants, the
  position for hierarchy roles, and direct grants.

## Screens

Security administration has a page for each part: role access levels (every operation's level),
permission sets, conflict rules, role templates, and user access (a direct role grant's end date and
reason). A new deployment shows only roles: these feature switches, all off by default, reveal the rest
(`/api/v1/admin/features`):

| Switch | Shows |
| --- | --- |
| `security.permission_sets` | The permission sets page |
| `security.role_conflicts` | The conflict rules page |
| `security.grant_end_dates` | End dates and reasons on role and set assignments |
| `security.child_units` | The include-child-units choice beside each business-unit level |

The switches hide screens only. The routes stay open to administrators whatever the switches say, and a
hidden child-unit choice is saved as included.

## Unused privileges

Each node counts privilege use per person and day (the four central privilege checks; a few engine
routes that read privileges directly are not counted). A daily job drafts a removal proposal for each
role privilege none of the role's holders used in 90 days
(`GET /api/v1/admin/security/privilege-removal-proposals`). A proposal is only a draft for a person to
review; a dismissed one is not proposed again for 90 days.
