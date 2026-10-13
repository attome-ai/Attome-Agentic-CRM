#!/bin/bash
# P-observability-bcdr Track B — scheduled COPY extract of the audit ledger
# (core_audit_header/core_audit_detail) and the S2S access log
# (core_s2s_access_log) for customer-side SIEM ingestion.
#
# Deliberately a pull/batch script (design section of
# attome-base/document_v2/docs/detailed-plans/P-observability-and-bcdr.md), not a
# streaming feed — air-gap friendly, same reasoning as Track C's backup
# design. Masking guarantee: any core_audit_detail row with
# is_sensitive = true has its old_value/new_value/old_display_value/
# new_display_value/old_lookup_name/new_lookup_name replaced with a fixed
# marker in the SQL itself (never filtered client-side, so a masked row
# still proves the field changed, just not to what value) — see
# test-export-masking.sh, which proves this against a live database inside
# a rolled-back transaction.
#
# Usage: PGPASSWORD=... ./export-audit-ledger.sh
# Config via environment (all standard libpq vars plus one extra):
#   PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD  — standard libpq vars
#   ATTOME_DB_SCHEMA   — search_path schema (default: public; attome-website's
#                        config.debug.json dev default is "attome_dev")
#   EXPORT_DIR         — where .ndjson files land (default: ./siem-export)
#   STATE_FILE         — high-water-mark file (default: $EXPORT_DIR/.export-state)
#
# Incremental: each table's watermark is the highest created_at/created_at
# already exported. The run captures its own start time once (RUN_TS) and
# exports the half-open range (watermark, RUN_TS] per table, so two tables
# never race against each other's clock and a row committed mid-run is
# picked up next run rather than risking a partial-transaction read.
#
# Implementation note: psql variable interpolation (:'var'/:"var") only
# expands when psql reads its script from stdin/a file — verified against
# the live PG18 client that `-c "... :'var' ..."` does NOT interpolate
# (silent syntax error), so this script feeds one heredoc script over
# stdin and uses \o file redirection per table instead of one `-c` per
# table with output capture.
#
# Each output file is chmod 600 immediately after creation — these are
# audit/security records, not general application logs.

set -euo pipefail

ATTOME_DB_SCHEMA="${ATTOME_DB_SCHEMA:-public}"
EXPORT_DIR="${EXPORT_DIR:-./siem-export}"
STATE_FILE="${STATE_FILE:-$EXPORT_DIR/.export-state}"
RUN_TS="$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)"
RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$EXPORT_DIR"
chmod 700 "$EXPORT_DIR"
touch "$STATE_FILE"
chmod 600 "$STATE_FILE"

watermark_for() {
  local table="$1"
  grep "^${table}=" "$STATE_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true
}

set_watermark() {
  local table="$1" ts="$2"
  local tmp
  tmp="$(mktemp "${STATE_FILE}.XXXXXX")"
  { grep -v "^${table}=" "$STATE_FILE" 2>/dev/null || true; echo "${table}=${ts}"; } > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$STATE_FILE"
}

WM_HEADER="$(watermark_for core_audit_header)"
WM_DETAIL="$(watermark_for core_audit_detail)"
WM_S2S="$(watermark_for core_s2s_access_log)"
WM_HEADER="${WM_HEADER:-1970-01-01T00:00:00Z}"
WM_DETAIL="${WM_DETAIL:-1970-01-01T00:00:00Z}"
WM_S2S="${WM_S2S:-1970-01-01T00:00:00Z}"

OUT_HEADER="$EXPORT_DIR/core_audit_header_${RUN_STAMP}.ndjson"
OUT_DETAIL="$EXPORT_DIR/core_audit_detail_${RUN_STAMP}.ndjson"
OUT_S2S="$EXPORT_DIR/core_s2s_access_log_${RUN_STAMP}.ndjson"

psql -X -q -v ON_ERROR_STOP=1 \
  -v "schema=${ATTOME_DB_SCHEMA}" \
  -v "run_ts=${RUN_TS}" \
  -v "wm_header=${WM_HEADER}" \
  -v "wm_detail=${WM_DETAIL}" \
  -v "wm_s2s=${WM_S2S}" <<SQL
SET search_path TO :"schema";

\o ${OUT_HEADER}
COPY (
  SELECT row_to_json(t) FROM (
    SELECT id, created_at, organization_ref, category, entity_name, record_id,
           operation, version_before, version_after, user_id, user_name,
           user_display_name, user_email, user_job_ref, user_job_name,
           changed_on, source, ip_address, browser, device_type,
           correlation_id, batch_id, event_name, event_comment, event_index,
           prev_hash, event_hash, signing_key_id, signature, chain_batch_ref
    FROM core_audit_header
    WHERE created_at > :'wm_header'::timestamptz AND created_at <= :'run_ts'::timestamptz
    ORDER BY created_at
  ) t
) TO STDOUT;
\o

\o ${OUT_DETAIL}
COPY (
  SELECT row_to_json(t) FROM (
    SELECT id, created_at, organization_ref, audit_ref, field_name, display_name,
           data_type,
           CASE WHEN is_sensitive THEN '***MASKED***' ELSE old_value END AS old_value,
           CASE WHEN is_sensitive THEN '***MASKED***' ELSE new_value END AS new_value,
           CASE WHEN is_sensitive THEN '***MASKED***' ELSE old_display_value END AS old_display_value,
           CASE WHEN is_sensitive THEN '***MASKED***' ELSE new_display_value END AS new_display_value,
           old_lookup_entity,
           CASE WHEN is_sensitive THEN '***MASKED***' ELSE old_lookup_name END AS old_lookup_name,
           new_lookup_entity,
           CASE WHEN is_sensitive THEN '***MASKED***' ELSE new_lookup_name END AS new_lookup_name,
           is_sensitive
    FROM core_audit_detail
    WHERE created_at > :'wm_detail'::timestamptz AND created_at <= :'run_ts'::timestamptz
    ORDER BY created_at
  ) t
) TO STDOUT;
\o

\o ${OUT_S2S}
COPY (
  SELECT row_to_json(t) FROM (
    -- nonce is deliberately excluded: a replay-prevention value with no
    -- SIEM/audit use, unlike the audit ledger's is_sensitive-gated fields.
    SELECT id, client_ref, client_name, method, path, status_code,
           response_time_ms, bytes_received, bytes_sent, correlation_id,
           ip_address, error_code, created_at
    FROM core_s2s_access_log
    WHERE created_at > :'wm_s2s'::timestamptz AND created_at <= :'run_ts'::timestamptz
    ORDER BY created_at
  ) t
) TO STDOUT;
\o
SQL

# COPY still writes a zero-byte file for a zero-row result — drop empty
# files rather than shipping them, but always advance the watermark since
# the queried range was genuinely checked, empty or not.
for pair in "core_audit_header:$OUT_HEADER:$RUN_TS" "core_audit_detail:$OUT_DETAIL:$RUN_TS" "core_s2s_access_log:$OUT_S2S:$RUN_TS"; do
  table="${pair%%:*}"
  rest="${pair#*:}"
  outfile="${rest%%:*}"
  ts="${rest#*:}"
  if [ -s "$outfile" ]; then
    chmod 600 "$outfile"
    echo "exported: $outfile ($(wc -l < "$outfile") rows)"
  else
    rm -f "$outfile"
    echo "exported: $table — no new rows"
  fi
  set_watermark "$table" "$ts"
done
