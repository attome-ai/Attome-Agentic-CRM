# Data lineage

Lineage is the graph of what uses what: which flows, queries, views, forms, metrics,
dashboards and agents read, write or derive which entities and attributes, and which
outside systems feed or read them. It answers "what breaks if I change this field" before
the change is published, shows where a value comes from and where it goes, and exports the
graph for a data catalogue. The screen is **Administration → Governance → Lineage**
(`/xrm/admin/lineage`).

## The graph

A node is a definition (`<kind>:<id>`, such as `workflow:…` or `metric:…`), data
(`entity:<entity>` or `entity:<entity>.<attribute>`) or an outside system (`system:<id>`).
An edge has a kind and a confidence:

| Kind | Meaning |
|---|---|
| `triggers` | the definition starts on changes of the data |
| `reads` | it reads the data |
| `derives` | it computes something from the data |
| `writes` | it writes the data |

| Confidence | Meaning |
|---|---|
| `parsed` | read from the definition's own text, down to the attribute |
| `entity_only` | the definition touches the entity, but which attributes is only known at run time (raw SQL, values supplied when a flow runs, a rule that does not parse) |
| `hand` | documented by a person (below) |

Edges are written when a definition is published, in the publish's own transaction, under a
new graph version; a republish replaces that definition's parsed edges and leaves hand edges
alone. Every replaced edge is kept in `lineage_edge_history` with the versions it was valid
in, so the graph can be read as of any version.

What is parsed: rule-language expressions (field references, lookup hops), stored queries
(selected, sorted, grouped and filtered fields), views and forms (their attributes), flows
(trigger entity, conditions, the fields create and update nodes write) and agents (their
triggers).

## Impact before a change

Deleting, retyping or renaming an attribute first asks the impact engine. It walks the graph
downstream up to 5 hops (at most 10), reporting each definition once at its shallowest depth:

- **breaking**: a definition that uses the attribute directly (parsed or hand) and is not a
  stored query or flow, which adjust themselves through their field hooks;
- **affected**: everything else reached, including entity-level and trigger edges, which
  never break;
- **hidden**: how many reached definitions the caller may not see, never their names.

A breaking item stops the field change: delete and type change answer 409 `field_in_use`
with the readers listed, dry runs included. The field-change dialog shows the same report
before anything is applied.

## Walking the graph

`GET /api/v1/lineage/{kind}/{ref}` walks downstream (what uses this) or upstream (what this
uses, or what writes this data), 1 to 10 hops (3 by default) and at most 2,000 nodes, optionally keeping only some
definition kinds or reading an earlier graph version. Any signed-in person may call it: an
administrator sees every node; anyone else sees the data of entities they may read, and
everything else is counted in `hidden` and not walked through. A definition that reads an
attribute classified above `general` is flagged `reads_personal` (red on the screen).

- `GET /api/v1/lineage/compare?from=&to=` lists the edges added and removed between two
  versions (administrators).
- `GET /api/v1/lineage/cleanup` lists edges to deleted entities or attributes, cycles between
  definitions and active attributes nothing uses (administrators).

## Hand-documented links

Systems Attome cannot parse (a warehouse that reads an export, an ERP that feeds an import)
are documented by hand: `POST /api/v1/lineage/manual-links` links an outside system (name,
kind, direction) or a definition to an entity or attribute with an edge kind and a required
note; `DELETE /api/v1/lineage/manual-links/{id}` removes one and keeps it in the history.
Administrators and the owners or stewards of the entity's data domain may do both, and each
change writes a configuration security event. A parsed edge for the same pair cannot be
overwritten by hand (409). Connector definitions do not yet write their edges automatically.

## Export

When the deployment setting `lineage.export_enabled` is on (off by default),
`GET /api/v1/lineage/export/openlineage?namespace=` gives administrators one OpenLineage
`RunEvent` per definition: its inputs are what it reads or derives from, its outputs what it
writes, with the attributes as each dataset's schema. Only names from the graph leave, never
record values. Nothing is pushed; the catalogue pulls, and each pull is a security event.

## Agent tools

`lineage.downstream`, `lineage.upstream` and `lineage.impact` run the same walk and impact
engine as the person the agent acts for. Agents are told to run `lineage.impact` before
proposing any schema change.

## Administration routes

| Route | Who | Does |
|---|---|---|
| `GET /api/v1/admin/lineage/impact?entity=&attribute=&change=&depth=` | administrators | The impact report of a change (`delete`, `retype`, `rename` or `other`). |
| `GET /api/v1/lineage/{kind}/{ref}` | signed in | Walk the graph. |
| `GET /api/v1/lineage/compare`, `GET /api/v1/lineage/cleanup` | administrators | Version diff and clean-up lists. |
| `POST /api/v1/lineage/manual-links`, `DELETE /api/v1/lineage/manual-links/{id}` | administrators, domain owners and stewards | Hand-documented links. |
| `GET /api/v1/lineage/export/openlineage` | administrators, when enabled | OpenLineage export. |
