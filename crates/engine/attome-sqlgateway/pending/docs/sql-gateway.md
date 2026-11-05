# SQL gateway

The SQL gateway (Y3-T1, crate `attome-sqlgateway`) lets a BI tool or `psql` query Attome as if it
were PostgreSQL, and see exactly what its user sees in the app. It is **off by default** and must not be
exposed before the owner's security review.

## Turning it on

```json
"sql_gateway": { "enabled": true, "bind": "127.0.0.1:5433", "max_connections": 8 }
```

Boot refuses an enabled gateway whose `bind` is not a loopback `ip:port`, or whose `max_connections`
is outside 1 to 200. The gateway has no TLS of its own yet and the API key travels as the password, so
it is reached only through a TLS-terminating proxy on the same host (for example a stream proxy that
terminates TLS on the public port and forwards to `127.0.0.1:5433`).

## Signing in

- **User name**: an API key's public part. **Password**: its secret. The key is checked by the same
  code as the HTTP API's `X-API-Key`: an unknown key, a wrong secret, a revoked or expired key, a
  disabled user or an address outside the key's IP allow-list are refused.
- The key's user needs `attome_report.author_sql` (the privilege the SQL report runner needs), or to be
  an administrator. The database name is ignored.

```sh
psql "host=127.0.0.1 port=5433 user=atk_pub_... password=atk_sec_... sslmode=disable"
```

## Queries

Queries come by the simple-query protocol or the extended one (prepare, describe, execute), without
bound parameters. Each query runs through the secured SQL runner (`attome_report::secured_sql`, P2-T1), as for
`POST /api/v1/reports/sql/run`:

- one `SELECT` (a `WITH` query too); entities are named as tables (`SELECT name FROM account`);
- each entity is a view of the rows and the fields the user may read, built for that query; anything
  else (a platform table, another schema, a second statement, a write) fails on PostgreSQL's own
  privileges;
- a read-only transaction that is always rolled back, 10 seconds and 1,000 rows at most;
- the user's access is re-read for every query, so a revoked privilege or key applies at once.

Every value comes back as text (`t`/`f` for booleans, JSON text for arrays and objects). An error
from the statement (syntax, an unreadable table, the time limit) is returned with PostgreSQL's message;
any other failure is reported as `internal error` and logged.

## Audit

Every query writes one `BusinessEvent`, `sql_gateway.query` (source `Integration`), with the user,
whether it succeeded, the row count and the SQL's SHA-256 and length. The SQL text itself is never
stored, since its literals may be personal data.

## Not yet

- Bound parameters (`$1`): refused (SQLSTATE `0A000`); write the values into the query. A describe
  runs the statement for one row to learn its columns.
- The catalog queries (`pg_catalog`, `information_schema`) a BI tool sends to list tables.
- TLS on the gateway itself.
