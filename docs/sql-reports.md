# SQL reports

A report author writes SQL over entities and test-runs it with `POST /api/v1/reports/sql/run`
(`{ "sql": "...", "explain": false, "max_rows": 1000 }`). It needs the `attome_report.author_sql`
privilege (platform changeset 0081), not administration: the SQL can only ever read what its
author can read.

```sql
SELECT a.name, count(o.id) AS open_deals
  FROM account a
  LEFT JOIN opportunity o ON o.account_ref = a.id AND o.stage NOT IN ('closed_won', 'closed_lost')
 GROUP BY a.name
```

The answer is `{ columns, rows, truncated, plan }`: the column names in order, up to 1000 rows as
objects, whether more matched, and `EXPLAIN (FORMAT JSON)` when `explain` is true. A statement
error (syntax, an unknown or unreadable table or column, a type error, the 10-second limit) is a
422 that carries PostgreSQL's message.

## How it is kept to the author's access

No parser decides what the SQL may touch; PostgreSQL's privileges do (V2-D1416). In one
transaction that is always rolled back:

1. For each entity named in the SQL that the author may read, a temporary view with the entity's
   name is made. It holds the rows a list shows the author (the same record filter as
   `query/execute`) and the columns a bulk read shows them: the system columns, the primary name,
   the fields their roles list, and a sensitive field only with its field-security grant.
2. The transaction turns read-only, the statement gets a 10-second limit, and the session
   switches to `attome_user_sql` (migration 0344), a role with no privilege on any schema or table,
   granted SELECT on this run's views only. `search_path` is `pg_temp`.
3. The SQL runs as one statement, wrapped as a subquery. A schema-qualified table, an entity the
   author may not read, a function that reads a table by name (`query_to_xml`), a second
   statement or a write fails on privileges or on the wrapping.
4. The run is rolled back, which drops the views, and any session advisory lock the SQL took is
   released.

Notes, activities, communications, follows and tags, and the audit tables, are gated by the record
they point at, which one view cannot express. Only an administrator's SQL reads them.

The catalog (`pg_catalog`) stays readable, as for any PostgreSQL role: an author can list table
and column names, never rows they cannot read.
