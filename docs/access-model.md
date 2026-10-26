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

## Fields

A sensitive field (`is_sensitive`) needs a **field-security** grant: a profile, assigned to roles, that
grants `can_read` and `can_update` per field. A grant may instead **mask** the field (`mask_format`:
`last4`, `email`, `phone` or `full`): the database computes the mask, so the value never reaches the
client in full; record reads and lists show the mask, export and other bulk surfaces hide the field, and a
masked field cannot be changed. A grant in full from any profile wins over a mask.

Bulk surfaces (export, query, reports, AI context) also need the field listed for the role, unless the
role is still in D-589 legacy mode.

## Conflicting access

A **conflict rule** names two roles, privileges or permission sets one person must not hold together
(`/api/v1/admin/security/role-conflicts/rules`). Every grant that adds access checks the rules in its own
transaction: a direct role grant, joining a team, a team's new role, and a set assignment. A rule fires
when the grant would complete the pair:

- `refuse`: 409 `role_conflict`.
- `approval`: a direct role grant goes to a second administrator, with a reason required; the other paths
  refuse with `role_conflict_needs_approval`.

`GET /api/v1/admin/security/role-conflicts/current` lists who holds a pair today.

## Explaining access

- `GET /api/v1/{entity}/{id}/access/explain?user=&action=` explains one record: every source the filter
  applies (administrator, privilege, role level, business unit, ownership, user and team shares, default
  share, sharing rule, deny), with the deciding one marked. Asking about someone else needs the Security
  administration area; asking about yourself needs read access to the record.
- `GET /api/v1/admin/security/users/{id}/effective-access?entity=&action=` lists every path to a
  person's level on an entity: roles direct and through teams, permission sets, conditional grants, the
  position for hierarchy roles, and direct grants.
