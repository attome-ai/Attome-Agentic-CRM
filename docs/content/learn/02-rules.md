# Path 2: Rules that guard your data

Business rules run on every save, from the form, the API, an import or an agent alike. You
will add a default and a refusal to the `course` entity from path 1.

## Exercise 2.1: a default

In **Admin → Business rules → New**, on `course`, add a rule that sets `seats` to `20` when it
is empty. Save the rule and publish it.

**Answer check** (`check-2-1.json`):

```json
{
  "name": "learn 2.1: a course gets 20 seats by default",
  "definition": {
    "when": [ { "op": "create", "entity": "course", "ref": "c", "values": { "title": "Default seats" } } ],
    "expect": [ { "entity": "course", "ref": "c", "attribute": "seats", "equals": 20 } ]
  }
}
```

## Exercise 2.2: a refusal

Add a second rule that refuses a save when `seats` is below 1, with the message *A course
has at least one seat*. Publish it.

**Answer check** (`check-2-2.json`):

```json
{
  "name": "learn 2.2: no course with zero seats",
  "definition": {
    "when": [ { "op": "create", "entity": "course", "values": { "title": "Empty room", "seats": 0 } } ],
    "expect": [ { "error": "validation" } ]
  }
}
```

## Exercise 2.3: the rule holds on update too

Refusals are not only for new records.

**Answer check** (`check-2-3.json`):

```json
{
  "name": "learn 2.3: an update cannot remove every seat",
  "definition": {
    "given": [ { "entity": "course", "ref": "c", "record": { "title": "Full room", "seats": 10 } } ],
    "when": [ { "op": "update", "entity": "course", "ref": "c", "values": { "seats": 0 } } ],
    "expect": [ { "error": "validation" } ]
  }
}
```

Mark these three checks **blocking** (`"blocking": true` when you add them, or the switch in
**Admin → Customer tests**) and turn on the setting `customer_tests.require_pass_before_publish`:
from now on, a change that breaks them cannot be published.
