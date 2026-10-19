# Scanning barcodes and QR codes

Scanning fills a field from a code read by the device's camera or a scanner,
finds the records a code belongs to, and can run an action bound to a code.
It is off until an administrator turns it on, and every lookup reads only
what the person scanning may read.

## Turning it on

Two feature flags, both off by default:

| Flag | What it turns on |
|---|---|
| `scan.enabled` | Scan buttons on scan-enabled fields, `GET /api/v1/scan/find`, the `scan.lookup` agent action |
| `scan.actions_enabled` | `POST /api/v1/scan/act`, which runs a scan action. Needs `scan.enabled`. |

Set them like any feature flag (their stored values are the settings
`feature.scan.enabled` and `feature.scan.actions_enabled`). While a flag is
off its routes answer 404, as if they did not exist.

## Making a field scannable: `options.scan`

A text, number or lookup field becomes scannable when its `options` carry a
`scan` object:

```json
{
  "scan": {
    "formats": ["ean_13", "code_128", "qr_code"],
    "gs1_batch_attribute": "batch_number",
    "gs1_expiry_attribute": "expiry_date",
    "on_unknown": "reject"
  }
}
```

| Key | Meaning |
|---|---|
| `enabled` | `true` by default; `false` keeps the setting but turns the field off. |
| `formats` | At least one of `ean_13`, `ean_8`, `upc_a`, `upc_e`, `code_128`, `code_39`, `qr_code`, `data_matrix`, `pdf417`. Anything else is refused. |
| `gs1_batch_attribute` | The field a GS1 code's batch (AI `10`) fills. |
| `gs1_expiry_attribute` | The field a GS1 code's expiry date (AI `17`) fills. |
| `on_unknown` | What a code matching no record does: `reject` (the default) or `offer_create`. |

Set it through the admin attribute API, like any other field option. A
sensitive field is never searched by a scan, even when it carries
`options.scan`: a match would confirm a value the person may not see.

### GS1 codes

A GS1-128, GS1 DataMatrix or GS1 QR code holds several values. The app
reads AI `01` (GTIN, 14 digits, check digit verified), `10` (batch), `17`
(expiry, `YYMMDD`; day `00` means the month's last day) and `21` (serial).
The GTIN is what is matched; the batch and expiry go to the fields named by
`gs1_batch_attribute` and `gs1_expiry_attribute`. Reading stops at an
identifier the app does not know.

## Finding records: `GET /api/v1/scan/find?value=…&entity=…`

Returns the records holding the scanned value in a scan-enabled field
(text compared exactly, numbers numerically), at most 50, searching at most
20 fields. Each record passes the caller's entity read privilege and
record-level security first; a record the caller may not read is never
returned. `entity` limits the search to one entity.

## Scan actions: `POST /api/v1/scan/act`

A `scan_action` record binds codes to something to do:

| Field | Meaning |
|---|---|
| `entity_logicalname` | The entity the code belongs to. |
| `match_attribute` | Optional: only matches in this field count. |
| `code_pattern` | Optional regular expression the whole code must match. |
| `action_kind` | `open`, `run_workflow` or `set_field` (`add_line` is reserved and refused). |
| `workflow_ref` | For `run_workflow`: the flow to start. |
| `set_field_attribute`, `set_field_value` | For `set_field`: the field and the value it gets. |
| `enabled` | Turns the action off without deleting it. |

The request is `{"value": "…", "scan_action_id": "…", "location": {"lat": …, "lng": …}}`.
The record is found exactly as `scan/find` finds it. No match is 404; more
than one is 409 with the matches listed, so the person picks one.

- `open` returns the record.
- `run_workflow` starts the flow, with the record as its subject, at the
  flow's `scan` trigger when it has one (a `trigger` node whose
  `trigger_type` is `scan`); it needs update access to the record.
- `set_field` sets the field through the ordinary record update, at the
  record's current version, with its rules and audit; it needs update access.

Each scan writes one audit event. The device's location is kept in it only
when the person has turned on the personal setting `scan.record_location`.
Send an `Idempotency-Key` so that a double scan runs once.

## Codes that open records: the deep-link rule

A printed code for a record carries the app's own link to it
(`/xrm/entity/{entity}/form?id={id}`), and nothing else: no token, no
signature, no data from the record. Opening it goes through the normal
sign-in and record read, so a code never lets anyone see a record they could
not already open. The agent action `code.generate` gives this link only for a
record the acting user may read, so it never confirms that a hidden record
exists.

## For agents

- `scan.lookup` (read-only): the `scan/find` lookup, as the agent's acting
  user. Hidden while `scan.enabled` is off.
- `code.generate` (read-only): the deep link for a record the acting user may
  read.
