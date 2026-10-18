# Slow statements

How to see which statements are slow, where they come from and how PostgreSQL ran them. It is an
operator's choice per server: nothing here is on by default, and the platform works without it.
With it on, the index advisor (`GET /api/v1/admin/entities/{entity_id}/index-proposals`, and the
agents' `table.index_proposals`) has statements to read.

## Turn it on

Both extensions load at server start, so this is a change to the PostgreSQL server's own
configuration (`postgresql.conf`; on Windows it sits in the data directory, by default
`C:\Program Files\PostgreSQL\18\data`):

```ini
shared_preload_libraries = 'pg_stat_statements,auto_explain'

# Statements over one second go to the server log with their plan.
auto_explain.log_min_duration = '1s'
auto_explain.log_format = 'json'
log_min_duration_statement = '1s'
```

Restart PostgreSQL, then, once per database, as a superuser:

```sql
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
```

This is server administration, not a change to the platform's data or metadata; the platform's
migrations do not create the extension, because it needs the server change first.

## Read the source of a statement

Every statement the record engine, `query/execute` and the job queue send starts with a comment
naming its source (see [Data layer](data-layer.md#query-tags)):

```text
/* entity.merge */ UPDATE "account" SET ...
/* query.execute */ SELECT row_to_json(t.*) ...
/* jobs.queue */ SELECT apalis.push_job(...)
```

The comment is the engine and operation; the rest is the statement. PostgreSQL computes a
statement's id without the comment, so the same statement from two places shares one row in
`pg_stat_statements`, with the text of the first one seen.

## The slowest statements

```sql
SELECT calls,
       round(mean_exec_time::numeric, 1)  AS mean_ms,
       round(total_exec_time::numeric, 0) AS total_ms,
       rows,
       left(query, 160)                   AS query
  FROM pg_stat_statements
 ORDER BY total_exec_time DESC
 LIMIT 20;
```

Order by `mean_exec_time` to find the slowest single runs instead of the costliest overall.
`SELECT pg_stat_statements_reset();` starts the counts again (after an index is built, say).

## Their plans

`auto_explain` writes each statement over `auto_explain.log_min_duration` to the PostgreSQL server
log with its plan as JSON: under `log/` in the data directory by default (`log_directory`). Search
the log for `"Query Text"` to find a plan, and read its `"Plan"` tree: a `Seq Scan` on a large
entity table under a filter is what an index proposal answers.
