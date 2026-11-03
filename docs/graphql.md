# GraphQL

`POST /api/v1/graphql` reads records with a GraphQL query; `GET /api/v1/graphql/schema` answers the
schema for the caller, in the GraphQL schema language. The schema is built from the metadata on each
request, so a new entity or field is there as soon as it is published, and it holds only what the
caller may read.

```graphql
query BigDeals($min: Float = 100000) {
  deals: opportunity_list(where: { amount: { gte: $min } }, sort: "-amount", first: 20) {
    items { id name amount account_ref { name } }
    next_cursor
  }
  account(id: "0190a0c2-...") { name __typename }
}
```

- Every entity the caller may read has two root fields: `<entity>(id: ID!)` and
  `<entity>_list(where, sort, first, after)`, which answers `{items, next_cursor}`.
- `where` is `{field: {op: value}}`, with the record list's operators (`eq`, `ne`, `gt`, `gte`, `lt`,
  `lte`, `in`, `contains`, `is_null`, …); several are combined with *and*. `sort` is `"field"` or
  `"-field"`. `first` is 1 to 100 (20 when absent). `after` is an earlier answer's `next_cursor`.
- A record's fields are its readable attributes and the system columns. A lookup with a selection
  answers the related record (read in one batch per lookup and level), without one its id.
- Reads run through the query engine with the caller's access: record-level security, field
  security and masks apply as on `GET /api/v1/{entity}`. A field the caller may not read is not in
  the schema.
- Limits, checked before anything runs: 10 root fields, 6 levels, and 10,000 records by estimate
  (a list reads `first` records, each record one more per nested lookup).
- Answers are `{"data": …}`, or `{"data": null, "errors": [{"message": …}]}` for a query that does
  not parse, breaks a limit or reads what the caller may not.
- Queries only: variables, aliases and `__typename` are supported; fragments, directives,
  mutations and subscriptions are refused. Write through the record API.
