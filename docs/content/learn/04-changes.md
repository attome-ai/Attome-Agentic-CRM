# Path 4: Changes as code

Two people editing the same record, and a configuration moving from your laptop to a server:
both are handled for you, if you use them the way they are meant.

## Exercise 4.1: optimistic updates

Every record carries a `row_version`. An update names the version it was made against in
`If-Match`; if someone changed the record since, the update is refused with `409` instead of
silently overwriting their change.

```sh
curl -s "$ATTOME/api/v1/course/<id>" -H "Authorization: ApiKey $KEY"     # note row_version, say 3
curl -s -X PATCH "$ATTOME/api/v1/course/<id>" -H "Authorization: ApiKey $KEY" \
  -H 'If-Match: "3"' -H "Content-Type: application/json" -d '{"seats": 25}'
curl -s -X PATCH "$ATTOME/api/v1/course/<id>" -H "Authorization: ApiKey $KEY" \
  -H 'If-Match: "3"' -H "Content-Type: application/json" -d '{"seats": 26}'  # 409: stale
```

**Answer check** (`check-4-1.json`): an update applies to the record it names.

```json
{
  "name": "learn 4.1: an update changes the seats",
  "definition": {
    "given": [ { "entity": "course", "ref": "c", "record": { "title": "Moving course", "seats": 10 } } ],
    "when": [ { "op": "update", "entity": "course", "ref": "c", "values": { "seats": 25 } } ],
    "expect": [ { "entity": "course", "ref": "c", "attribute": "seats", "equals": 25 } ]
  }
}
```

## Exercise 4.2: your work as a changeset

Everything you built in paths 1 to 3 (the entity, its fields, the rules, the roles) is
metadata. Open **Admin → Changesets**, open a new changeset, make one more change (add a
`starts_on` date field to `course`), and close it. Download it: it is one JSON file of
operations, checksummed.

## Exercise 4.3: move it to another install

On a second Solo install (or the same one after deleting the field), plan the changeset
(`POST /api/v1/admin/metadata/changesets/plan`): the plan lists what it would change and
writes nothing. Apply it (`.../apply`); then apply it again: the second apply changes
nothing, because the ledger records it once.

**Answer check** (`check-4-3.json`), on the second install:

```json
{
  "name": "learn 4.3: the moved field is there",
  "definition": {
    "when": [
      { "op": "create", "entity": "course", "ref": "c",
        "values": { "title": "Moved", "seats": 5, "starts_on": "2026-11-01" } }
    ],
    "expect": [ { "entity": "course", "ref": "c", "attribute": "starts_on", "equals": "2026-11-01" } ]
  }
}
```

You now have the loop every Attome builder uses: change in a changeset, check with customer
tests, plan, apply, and let blocking checks refuse a change that breaks what already worked.
