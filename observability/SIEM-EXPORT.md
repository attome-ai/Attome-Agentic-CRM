# P-observability-bcdr Track B — SIEM export

Two independent feeds, both landing as newline-delimited JSON (ndjson) files
a customer's SIEM ingests by whatever mechanism it already uses for
file-based log sources. Neither feed depends on the other; adopt one or both.

| Feed | What | Source |
|---|---|---|
| Application logs | Every `server` container's stdout (already structured JSON — see main.rs's `tracing_subscriber::fmt().json()`) | Vector sidecar (D-066) — `docker-compose.observability.yml` + `observability/vector/vector.toml` |
| Audit ledger + S2S access log | `core_audit_header`, `core_audit_detail` (masked), `core_s2s_access_log` | `scripts/observability/export-audit-ledger.sh`, run on a schedule |

## 1. Application log pipeline

```
server container stdout (JSON, one object/line)
  -> Vector (docker_logs source, filtered by the `com.docker.compose.service=server` label)
  -> remap transform (re-parses the JSON message into top-level fields;
     preserves a non-JSON line verbatim under `.raw_message` instead of dropping it)
  -> sink (pick one; file is enabled by default)
       - file:    /var/log/attome/app.ndjson.log  (air-gap friendly, default)
       - socket:  newline-delimited JSON over TCP to a syslog-ng/rsyslog
                  relay or your SIEM's own TCP listener (reference block,
                  commented, in vector.toml)
       - OTLP:    an OTLP logs collector (reference block, commented — needs
                  a Vector build whose `opentelemetry` sink covers logs;
                  confirm against the pinned image tag before relying on it)
```

Bring it up: `docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d`

**Why label-based filtering, not container-name filtering.** Verified
empirically against Vector 0.46.1 (the image pinned in the compose
overlay): `docker_logs`'s `include_containers` matches a container's name or
ID *exactly*, not as a substring. Compose's default container naming is
`<project>-server-<n>` — the project name varies per checkout/deployment,
and `--scale server=N` adds a replica suffix — so a name-based filter would
silently match nothing in every real deployment. `include_labels` on
`com.docker.compose.service=server` is the label Compose stamps on every
container it creates for that service, regardless of project name, replica
count, or container name, and is what `vector.toml` actually uses.

**Docker-socket note.** The `docker_logs` source needs the host's Docker
socket mounted (read-only) to discover and tail containers — this is
effectively root-equivalent host access. If your environment disallows
that, `vector.toml` documents a file-tailing alternative (reads the
json-file log driver's on-disk files directly) that avoids the socket
entirely; switch to it and drop the socket mount from the compose overlay.

**Tested, not just written.** The pipeline (label-based discovery → JSON
reparse → file sink) was run end-to-end against the pinned Vector image: a
container labeled `com.docker.compose.service=server` emitting a
structured-JSON line and a plain-text line was correctly picked up, with
the JSON line's fields flattened to the top level and the plain-text line
preserved verbatim under `raw_message` rather than dropped. This is a
config/pipeline check, not an automated test in CI — re-run it by hand
(`docker run` a throwaway container with that label emitting known lines,
then read the sink's output) after upgrading the pinned Vector image.

## 2. Audit ledger + S2S access-log export

`scripts/observability/export-audit-ledger.sh` — a pull/batch COPY extract,
run on a schedule (cron/systemd timer), deliberately not a streaming feed:
air-gap friendly, same reasoning as Track C's backup design.

```
0 * * * *  PGHOST=... PGPORT=... PGDATABASE=... PGUSER=... PGPASSWORD=... \
           ATTOME_DB_SCHEMA=<your schema> EXPORT_DIR=/var/lib/attome/siem-export \
           /path/to/export-audit-ledger.sh >> /var/log/attome/export-ledger.log 2>&1
```

Each run exports three ndjson files (skipped/removed if empty) into
`EXPORT_DIR`, named `<table>_<UTC-timestamp>.ndjson`, and advances a
per-table high-water mark in `EXPORT_DIR/.export-state` so the next run
only picks up rows created since. Point your SIEM's file-based ingestion
(or a periodic `rsync`/object-store sync — Track C's bucket is a candidate
destination, though this is a separate feed from that backup, not the same
data) at `EXPORT_DIR`.

### Masking guarantee

Every `core_audit_detail` row with `is_sensitive = true` has its
`old_value`/`new_value`/`old_display_value`/`new_display_value`/
`old_lookup_name`/`new_lookup_name` replaced with the literal string
`***MASKED***` **in the SQL itself** — never filtered client-side, and
never by dropping the row. A masked row still proves *that* a sensitive
field changed (timestamp, who, which field, before/after nothing) — it
just never carries *what it changed to*. This mirrors guidelines §9's
existing "is_sensitive attributes are masked in audit output" rule; this
export is another audit-output surface, so it inherits the same guarantee.

`core_audit_header` rows are exported unmasked — the "who did what to which
record" identity fields (`user_id`, `user_email`, `entity_name`,
`record_id`, …) are exactly what an auditor's SIEM needs, and
`is_sensitive` is a field-level flag on `core_audit_detail`, not something
`core_audit_header` carries.

`core_s2s_access_log` is exported unmasked except `nonce`, which is
excluded entirely (not masked) — it is a replay-prevention value with no
SIEM/audit use, not a sensitive-data field in the audit-ledger sense.

**Proof, not just a claim.** `scripts/observability/test-export-masking.sh`
runs the same masking SQL shape against a live database, inside one
`BEGIN … ROLLBACK` — it inserts one sensitive and one non-sensitive
synthetic `core_audit_detail` row, runs the masking query in the same
transaction, asserts the sensitive row's values never appear in the output
and the non-sensitive row's values pass through unchanged, then rolls back.
Nothing it inserts is ever committed; run it against a real (dev/staging)
database with no risk of leaving test rows behind. Verified 2026-07-16
against the local dev Postgres — see D-066 for the run record.

### Column reference

| File | Columns |
|---|---|
| `core_audit_header_*.ndjson` | `id, created_at, organization_ref, category, entity_name, record_id, operation, version_before, version_after, user_id, user_name, user_display_name, user_email, user_job_ref, user_job_name, changed_on, source, ip_address, browser, device_type, correlation_id, batch_id, event_name, event_comment, event_index, prev_hash, event_hash, signing_key_id, signature, chain_batch_ref` |
| `core_audit_detail_*.ndjson` | `id, created_at, organization_ref, audit_ref, field_name, display_name, data_type, old_value, new_value, old_display_value, new_display_value, old_lookup_entity, old_lookup_name, new_lookup_entity, new_lookup_name, is_sensitive` (value/display/lookup-name fields masked when `is_sensitive`) |
| `core_s2s_access_log_*.ndjson` | `id, client_ref, client_name, method, path, status_code, response_time_ms, bytes_received, bytes_sent, correlation_id, ip_address, error_code, created_at` (`nonce` excluded) |

`category`/`operation`/`source`/`device_type`/`data_type` are the integer
codes documented as comments in migration `0003_core_audit.sql` — the
export does not resolve them to strings, matching the ledger's own storage
convention (resolve on the ingesting/reading side, same as the app's own
audit UI would).

## 3. What this does NOT cover

- Backups/PITR of the Postgres database itself (Track C) — a different
  concern from shipping a copy of the audit trail to a SIEM.
- Retention of the exported `.ndjson` files — point your SIEM's own
  retention policy or a `logrotate`/lifecycle rule at `EXPORT_DIR`; this
  script only ever appends new files, it never prunes old ones.
- Field-level security beyond `is_sensitive` audit masking (F013/F135,
  still not built per guidelines §7) — this export inherits whatever
  masking already exists today, no more, no less.
