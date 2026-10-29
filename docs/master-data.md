# Master data and golden records

For builders, data stewards and integrators: how an entity becomes master data, how source
systems' versions of a record are combined into one trusted golden record, and how stewards and
other systems work with it. Decision: V2-D202.

## Making an entity master data

`PATCH /api/v1/admin/entities/{id}` with `master_data: {is_master: true, hub_style}` marks an
entity as master data. The hub style is `registry`, `consolidation` or `coexistence`. A master
entity must belong to a data domain, whose owners and stewards are the ones who act on it. Making
an entity master creates two side tables for it: `<entity>__contribution` (what each source system
sent) and `<entity>__provenance` (where each golden value came from). The setting travels in
changesets as `set_entity_master_data`.

## Contributions and the golden record

Each source system's version of a record is a contribution: the system, its external id, when it
arrived and the values it sent. A contribution that passes field validation is attached to its
golden record, found by its external-id link (or a new record is made). One that fails is held for
a steward and never overwrites a good value.

After a contribution arrives, a background rebuild recomputes the golden record attribute by
attribute and writes the changes through the ordinary update path, so validation, rules and audit
apply. The survivorship rule `source_system_rank` ranks the source systems per attribute (the ERP
for the billing address, the CRM for the mobile number), breaks ties by recency or completeness,
and can skip unvalidated contributions. Without a rank, the newest value wins. Every golden value
records the contribution, system, time and rule that chose it.

## Stewards

An administrator, or an owner or steward of the entity's data domain, may:

| Route | What it does |
|---|---|
| `POST /api/v1/master/{entity}/{id}/pins` | Pins an attribute (optionally setting its value first); rebuilds leave it alone. |
| `DELETE /api/v1/master/{entity}/{id}/pins/{attribute}` | Unpins it and queues a rebuild. |
| `POST /api/v1/master/{entity}/contributions/{cid}/release` | Validates a held contribution again (with a corrected `payload` if sent) and attaches it. |
| `POST .../contributions/{cid}/reject` | Detaches a held contribution with a reason. |
| `POST .../contributions/{cid}/detach` | Takes an attached contribution out of its golden record and rebuilds without it. |
| `POST /api/v1/master/{entity}/{id}/certify` | Sets `draft`, `certified` or `retired`. |
| `GET /api/v1/master/held` | The held contributions across the master entities the steward may act on. |

A steward of another domain, or anyone else, is refused. Pins and certifications are audited.

A master entity's form has a Golden record tab: each value with the source system, date and rule
that chose it, pin and unpin, and the contributions with Detach. `/xrm/admin/master-data` holds the
cross-reference search and the held queue.

## Reading

Anyone who can read the record may use these. Attributes the reader cannot read never appear.

- `GET /api/v1/master/{entity}/xref?system=&external_id=`: the golden record of a source system's id.
- `GET /api/v1/master/{entity}/{id}/xref`: every system id of a golden record.
- `GET /api/v1/master/{entity}/{id}/as-of?at=`: the values held at a moment, from the field
  history; a readable sensitive value changed since is listed as withheld.
- `GET /api/v1/master/{entity}/{id}/provenance`: where each readable value came from.

## Other systems

A rebuild that changes a golden record writes a `master.golden_changed` change event naming the
changed attributes. An event subscription can name its `external_system`; its webhook body then
carries `master`, with the golden record's certification and that system's own external id for the
record. Entities listed in the `master.certified_only` setting send changes only while the golden
record is certified. Sending outside the deployment is set per subscriber.

## Reference code mappings

`POST /api/v1/admin/data/code-maps` maps a source system's code in one of its code lists to the
value stored here, always as a new version; `GET` lists the mappings in effect, or every version
with `history=true`. A data-mapping field with `code_map: {source_system, code_list}` stores the
newest mapping in effect for each imported code; a code with no mapping rejects its record.

## Agents

`master.xref` answers cross-reference questions under the record's own read check.
`master.preview_ranking` counts, per attribute, the golden values a proposed trust ranking would
change ("changes 1,240 city values"), leaving pinned values out and writing nothing.
`master.propose_release` releases a held contribution only after a person approves it.

## Not built yet

These parts of the design are not in this release:

- The `registry` hub style is stored, but golden values are not read live from the sources (that
  needs virtual entities, L8).
- Building a golden record from a duplicate-detection cluster (E24).
- Steward approval before chosen attributes change (governed change requests).
- Preferring the Arabic legal name from a trusted government source.
- Limiting a source system's contributions to chosen roles.
