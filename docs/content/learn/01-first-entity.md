# Path 1: Your first entity

You will build a small **course** catalogue: an entity, its fields, and records written
through the API.

## Exercise 1.1: create the entity

In **Admin → Entities → New**, create an entity:

- logical name `course`, display name *Course*;
- a required text field `title` (up to 200 characters), the entity's primary name;
- a number field `seats`;
- a choice field `level` with the choices `beginner`, `intermediate` and `advanced`.

Everything you just did is metadata: it went through `/api/v1/admin/entities`, it is audited,
and the table was created for you. You never write SQL.

**Answer check** (`check-1-1.json`):

```json
{
  "name": "learn 1.1: a course keeps its fields",
  "definition": {
    "when": [
      { "op": "create", "entity": "course", "ref": "c",
        "values": { "title": "Arabic calligraphy", "seats": 12, "level": "beginner" } }
    ],
    "expect": [
      { "entity": "course", "ref": "c", "attribute": "title", "equals": "Arabic calligraphy" },
      { "entity": "course", "ref": "c", "attribute": "seats", "equals": 12 },
      { "entity": "course", "ref": "c", "attribute": "level", "equals": "beginner" }
    ]
  }
}
```

## Exercise 1.2: the title is required

Try to save a course without a title in the form: the form refuses it. The API refuses it
too, with a `422` naming the field.

**Answer check** (`check-1-2.json`):

```json
{
  "name": "learn 1.2: a course needs a title",
  "definition": {
    "when": [ { "op": "create", "entity": "course", "values": { "seats": 5 } } ],
    "expect": [ { "error": "validation" } ]
  }
}
```

## Exercise 1.3: records over the API

Create two courses with the generic record API, then list them:

```sh
curl -s -X POST "$ATTOME/api/v1/course" -H "Authorization: ApiKey $KEY" \
  -H "Content-Type: application/json" -d '{"title": "Hijri dates", "seats": 30, "level": "intermediate"}'
curl -s "$ATTOME/api/v1/course" -H "Authorization: ApiKey $KEY"
```

Note the `row_version` in each record: path 4 uses it.

**Answer check**: none needed; the list shows your two records. Run checks 1.1 and 1.2 again:
both still pass.
