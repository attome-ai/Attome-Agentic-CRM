# Mass operations

A mass operation applies one change to every record a filter selects:

- `update` sets the same values on each record;
- `delete` moves each record to the recycle bin;
- `reassign` gives each record a new owner (administrators only);
- `restore` brings back deleted records.

Each record goes through the normal single-record path, so record access, validation, business
rules and audit all apply exactly as they do for one record. A record the caller may not change is
skipped. A record someone else changed since it was read is counted as a conflict and left alone.

## Estimate first

`POST /api/v1/{entity}/mass/estimate` takes `{filter, kind, payload}` and returns the size check
(`attome_records::heavy_op`). It writes nothing.

The check counts the records the caller may change, stopping one past the inline threshold. The
threshold is the setting `limits.heavy_op.inline_max_rows`, 500 by default. The result says
`inline` or `background`, with the estimated rows and seconds.

`filter` is the query engine's condition (`query/run`'s `where`). `payload` holds:

| Kind | `payload` |
|---|---|
| `update` | the values to set |
| `reassign` | `user_email` or `team_name` |
| `delete`, `restore` | nothing |

## Start

`POST /api/v1/{entity}/mass` takes `{filter, kind, payload, reason, confirm_estimate_rows}`. It needs
the entity's `bulk` privilege and the change's own privilege: `delete` for a delete, `update` for
the other three kinds.

- **Up to the threshold**, the operation runs in the request. It answers `200` with the operation
  and each record's outcome (`done`, `conflict`, `skipped` or `failed`).
- **Past the threshold**, the caller must send `confirm_estimate_rows`, at least the number of rows
  counted. Without it the answer is `422`. With it, the operation is recorded as `queued` and the
  answer is `202`. The chunked background runner that works queued operations is roadmap AA10-T4.
  Until it lands, a queued operation stays queued.

A start sent with an `Idempotency-Key` takes the durable idempotency tier, so a retry does not
start a second operation.

## Follow and control

`GET /api/v1/mass/{id}` returns the status (`queued`, `running`, `paused`, `cancelled`, `failed`,
`done` or `undone`), the rows done, skipped and in conflict, and the seconds left while it works.

| Route | Moves |
|---|---|
| `POST /api/v1/mass/{id}/pause` | queued or running → paused |
| `POST /api/v1/mass/{id}/resume` | paused → queued |
| `POST /api/v1/mass/{id}/cancel` | queued, running or paused → cancelled |
| `POST /api/v1/mass/{id}/undo` | done or cancelled → undone |

Each control:

- needs the operation's `row_version` in `If-Match`;
- answers `422` without the header and `409` when the version is stale or the control does not
  apply in the current state;
- is audited.

Only the person who started an operation, or an administrator, can see or control it. Anyone else
gets `404`.

Undo writes the records back newest first, each only while it is still as the operation left it:

- updated values are set back;
- deleted records are restored;
- restored records are deleted again;
- owners are reassigned back.

The operation is marked `undone` before the replay starts, so two undos cannot both run. An
operation larger than the inline threshold cannot be undone in one request yet; that is roadmap
AA10-T5.

The entity name `mass` is reserved, because `/api/v1/mass/...` would otherwise collide with an
entity's own routes.
