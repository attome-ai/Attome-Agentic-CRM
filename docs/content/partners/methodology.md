# Implementation methodology

Every partner project goes through the same six phases. Each phase ends with a checkpoint the customer signs
off before the next one starts. The tools named are the ones Attome ships, so the evidence for each
checkpoint comes from the product, not from a separate document.

## 1. Discover

Understand the customer's processes, data and constraints before building anything.

- Map each process the customer wants in Attome to a pack where one fits (sales, service, marketing, the
  sector packs) and list what the pack does not cover.
- List the systems Attome must talk to, which of them are on the customer's own network, and the data that
  will move in.
- Agree the deployment: who hosts it, the region, the profile (Solo, Team, high availability), backups and
  recovery targets, and whether the deployment is sovereign (no outside services).

**Checkpoint:** the scope, the list of packs and gaps, the integration list and the deployment plan.

## 2. Design

Decide how each gap is met, preferring configuration over code.

- Entities, fields, forms, views and rules as metadata; flows for process automation; record types where one
  entity holds several kinds of record.
- Roles and teams from the customer's organisation chart, with the least access each role needs.
- A connector from the catalogue for each integration; an extension only where metadata and connectors cannot
  express it.
- Arabic and English labels for everything a user sees.

**Checkpoint:** the design, with the roles and access matrix, reviewed by the customer's administrator.

## 3. Build

Build in a development deployment, never in production.

- Every change is recorded in a changeset, so it can be reviewed, promoted and undone as one unit.
- Customer tests (the scenarios the customer cares about, written as tests) are added as features are built.
- The building agents may draft metadata and flows; a person reviews every draft before it is published.

**Checkpoint:** the changesets pass review and the customer tests pass in development.

## 4. Migrate

Move the customer's data in.

- Import through the import wizard or the API, never with SQL against the database.
- Run duplicate rules before and after the import.
- Rehearse on a copy first, and measure how long the real move will take.

**Checkpoint:** the rehearsal's record counts and spot checks match the source, and the customer accepts them.

## 5. Go live

- Promote the changesets to production through the environment screen.
- Prove backups by restoring one, and record the evidence.
- Train administrators and users with the role-based learning paths, in Arabic and English.
- Turn on monitoring and the built-in alerts.

**Checkpoint:** the go-live checklist complete, signed by the customer.

## 6. Support

- Answer the customer as the first line; escalate to Attome as the second line.
- Watch the first weeks closely: errors, slow screens, and requests users could not complete.
- Keep the deployment upgradeable: no change outside changesets, and the upgrade rehearsal run before each
  upgrade.

**Checkpoint:** the handover to steady-state support, with the open items listed.
