# Path 3: Who may do what

Access in Attome is roles and privileges: a privilege names an action on an entity
(`course.read`, `course.create`, ...), a role holds privileges, and people hold roles. You
will make a role that may look at courses but not change them.

## Exercise 3.1: a read-only role

In **Admin → Security → Roles → New**, create the role *Course Viewer* and give it
`course.read` only.

**Answer check** (`check-3-1.json`): the test runs its writes as the role.

```json
{
  "name": "learn 3.1: a course viewer cannot add a course",
  "definition": {
    "as_role": "Course Viewer",
    "when": [ { "op": "create", "entity": "course", "values": { "title": "Not allowed", "seats": 3 } } ],
    "expect": [ { "error": "forbidden" } ]
  }
}
```

## Exercise 3.2: an editor role

Create *Course Editor* with `course.read`, `course.create` and `course.update`, but not
`course.delete`.

**Answer check** (`check-3-2.json`): the editor may create a course but not delete one.

```json
{
  "name": "learn 3.2: a course editor creates but does not delete",
  "definition": {
    "as_role": "Course Editor",
    "given": [ { "entity": "course", "ref": "old", "record": { "title": "Old course", "seats": 8 } } ],
    "when": [
      { "op": "create", "entity": "course", "ref": "new", "values": { "title": "New course", "seats": 8 } },
      { "op": "delete", "entity": "course", "ref": "old" }
    ],
    "expect": [
      { "entity": "course", "ref": "new", "attribute": "title", "equals": "New course" },
      { "error": "forbidden" }
    ]
  }
}
```

## Exercise 3.3: give the role to a person

Invite a colleague (**Admin → Users → Invite**), give them *Course Viewer*, and sign in as
them in a private window: the course list shows, the *New* button does not. A role's
record-level scope (their own records, their team's, everyone's) is set on the role too; a
check about which rows a person sees needs a real user holding the role, so try it by hand.
