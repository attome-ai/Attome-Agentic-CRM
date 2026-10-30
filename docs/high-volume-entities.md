# High-volume entities

An entity that collects many records over time (page views, sensor readings, call events, log
lines) can be created as high-volume. Its table is partitioned by month, so a read of a period
touches only that period's partitions and old months can be archived whole.

## Creating one

```http
POST /api/v1/admin/entities
{ "logicalname": "page_view", "name": "Page view", "storage_mode": "high_volume" }
```

`storage_mode` is `standard` (the default) or `high_volume`, and is chosen when the entity is
created; an existing entity's storage never changes in place. The table is partitioned by month on
the record's `created_at`, a moment in UTC, so no partition boundary moves with a time zone. Its
primary key is `(id, created_at)`, a BRIN index on `created_at` serves date ranges, and twelve
months of partitions are created ahead (the partition job keeps that lead). The storage mode
travels in changesets and bundles with the entity.

## Reading one

Every query on a high-volume entity names a window on `created_at`: a filter with `gte`, `gt`,
`lte`, `lt`, `eq` or `in` on it, or a stored query whose own `WHERE` bounds it. The entity's list
views (`Active …`, `Inactive …`) show the last 30 days when no window is given; any other query
without one is refused with 422 `date_window_required`. Records are read, written, updated and
deleted one at a time exactly as on any entity.

## What it does not take

- A unique business key: on a partitioned table a unique rule must include `created_at`, which a
  business key cannot, so declaring one is refused with 422 `unique_needs_partition_key`.
- A concurrent index build: PostgreSQL builds an index on a partitioned table without
  `CONCURRENTLY`, so marking a field sortable or filterable (or adding a lookup) builds its index
  while holding writes to the table. Add such fields while the entity is still small.
