#!/usr/bin/env bash
# AA1-T9: the customer-run bench for Linux, the same four steps and flags as
# bench.ps1 (read that file's header for what each step does):
#
#   loadtest/scripts/bench.sh -BaseUrl https://crm.example.com -ApiKey '<public>:<secret>' \
#     -Profile solo -Published docs/evidence/latency-1.0.0.json
#
# Needs curl, k6 (or Docker) and Node.js. -Plan prints the steps and exits
# without any call.
set -euo pipefail

BASE_URL="http://127.0.0.1:7865"
API_KEY="${ATTOME_API_KEY:-}"
PROFILE="solo"
PUBLISHED=""
ROWS=10000
DURATION="60s"
CHANGESET=""
KEEP_RECORDS=0
PLAN=0

while [ $# -gt 0 ]; do
  case "$1" in
    -BaseUrl) BASE_URL="$2"; shift 2 ;;
    -ApiKey) API_KEY="$2"; shift 2 ;;
    -Profile) PROFILE="$2"; shift 2 ;;
    -Published) PUBLISHED="$2"; shift 2 ;;
    -Rows) ROWS="$2"; shift 2 ;;
    -Duration) DURATION="$2"; shift 2 ;;
    -Changeset) CHANGESET="$2"; shift 2 ;;
    -KeepRecords) KEEP_RECORDS=1; shift ;;
    -Plan) PLAN=1; shift ;;
    *) echo "bench.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done

SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
LOADTEST="$(dirname "$SCRIPTS")"
RESULTS="$LOADTEST/results"
ENTITY="bench_load"
QUERY_NAME="bench_load_list"
BASE_URL="${BASE_URL%/}"

# JSON helpers, through node (needed for the comparison anyway).
json() { node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));const v=($1);process.stdout.write(v===undefined||v===null?'':String(v))"; }

PROFILE_INFO="$(cd "$LOADTEST" && node -e "const p=require('./profiles.json')['$PROFILE'];if(!p||'$PROFILE'==='_comment'){process.exit(3)}const l=[...p.concurrency_levels].sort((a,b)=>a-b).slice(0,2);console.log(p.rated_rps+' '+l.join(' '))")" \
  || { echo "bench.sh: unknown profile $PROFILE" >&2; exit 2; }
read -r RATE LEVEL_A LEVEL_B <<<"$PROFILE_INFO"
LEVELS="$LEVEL_A ${LEVEL_B:-}"

if [ "$PLAN" = 1 ]; then
  echo "Bench plan for $BASE_URL, profile $PROFILE:"
  echo "  1. seed: entity $ENTITY (title, seq) and stored query $QUERY_NAME through the admin API, then $ROWS records through the bulk API"
  echo "  2. run: k6/production_mix.js for $DURATION at concurrency $LEVEL_A${LEVEL_B:+ and $LEVEL_B}, rate $RATE requests a second"
  echo "  3. compare: bench-compare.mjs, your p50/p95/p99 next to ${PUBLISHED:-no published report (pass -Published)}"
  echo "  4. clean up: delete every $ENTITY record through the bulk API$([ "$KEEP_RECORDS" = 1 ] && echo ' (skipped: -KeepRecords)')"
  exit 0
fi

[ -n "$API_KEY" ] || { echo "bench.sh: pass -ApiKey '<public>:<secret>' (or set ATTOME_API_KEY): an administrator's API key." >&2; exit 2; }
[ -z "$PUBLISHED" ] || [ -f "$PUBLISHED" ] || { echo "bench.sh: the published report $PUBLISHED does not exist." >&2; exit 2; }
mkdir -p "$RESULTS"

# One API call: prints the body; fails on a non-2xx answer (a 409 is allowed
# with ALLOW_CONFLICT=1 and prints nothing).
api() {
  local method="$1" path="$2" body="${3:-}" out status
  local args=(-s -o /dev/stdout -w '\n%{http_code}' -X "$method" "$BASE_URL$path"
    -H "Authorization: ApiKey $API_KEY" -H "Content-Type: application/json")
  [ -n "$CHANGESET" ] && args+=(-H "X-Attome-Changeset: $CHANGESET")
  [ -n "$body" ] && args+=(--data-binary "$body")
  out="$(curl "${args[@]}")"
  status="${out##*$'\n'}"
  out="${out%$'\n'*}"
  if [ "$status" -ge 200 ] && [ "$status" -lt 300 ]; then printf '%s' "$out"; return 0; fi
  if [ "${ALLOW_CONFLICT:-0}" = 1 ] && [ "$status" = 409 ]; then return 0; fi
  case "$status" in
    401) echo "$method $path -> 401: the API key was refused." >&2 ;;
    403) echo "$method $path -> 403: the API key's owner needs system.admin to create the bench entity." >&2 ;;
    *) echo "$method $path -> HTTP $status: $out" >&2 ;;
  esac
  return 1
}

wait_job() {
  local job="$1" status
  while true; do
    sleep 0.5
    status="$(api GET "/api/v1/$ENTITY/bulk/$job" | json 'd.status+" "+(d.failed??0)+" "+(d.succeeded??0)')"
    case "$status" in completed*|failed*) echo "$status"; return 0 ;; esac
  done
}

echo "=== 1. Seed $ENTITY ==="
ENTITY_ID="$(api GET /api/v1/admin/entities | json "(Array.isArray(d)?d:d.items||[]).find(e=>e.logicalname==='$ENTITY')?.id")"
if [ -z "$ENTITY_ID" ]; then
  ENTITY_ID="$(api POST /api/v1/admin/entities "{\"logicalname\":\"$ENTITY\",\"name\":\"Bench load\"}" | json 'd.id')"
  ALLOW_CONFLICT=1 api POST "/api/v1/admin/entities/$ENTITY_ID/fields" \
    '{"logicalname":"title","name":"Title","field_type":"text","is_sortable":true,"is_filterable":true}' >/dev/null
  ALLOW_CONFLICT=1 api POST "/api/v1/admin/entities/$ENTITY_ID/fields" \
    '{"logicalname":"seq","name":"Seq","field_type":"number","is_sortable":true,"is_filterable":true}' >/dev/null
  echo "  created $ENTITY"
else
  echo "  reusing $ENTITY"
fi
QUERY_ID="$(api GET /api/v1/admin/queries | json "(Array.isArray(d)?d:d.items||[]).find(q=>q.name==='$QUERY_NAME')?.id")"
if [ -z "$QUERY_ID" ]; then
  BODY="$(node -e "console.log(JSON.stringify({name:'$QUERY_NAME',sql_query:'SELECT id, seq, title FROM $ENTITY WHERE is_active = true',table_definition:JSON.stringify([{logicalName:'seq',displayName:'Seq',dataType:'integer',isSortable:true,isSearchable:false},{logicalName:'title',displayName:'Title',dataType:'text',isSortable:true,isSearchable:true}]),entity_logical_name:'$ENTITY_ID',required_privilege:'$ENTITY.read',is_report:false}))")"
  QUERY_ID="$(api POST /api/v1/admin/queries "$BODY" | json 'd.id')"
fi

SEQ=0
JOBS=()
while [ "$SEQ" -lt "$ROWS" ]; do
  N=$(( ROWS - SEQ < 500 ? ROWS - SEQ : 500 ))
  BODY="$(node -e "const s=$SEQ,n=$N;console.log(JSON.stringify({operation:'create',records:Array.from({length:n},(_,i)=>({data:{title:'bulk-row-'+(s+i+1),seq:s+i+1}}))}))")"
  JOBS+=("$(api POST "/api/v1/$ENTITY/bulk" "$BODY" | json 'd.id')")
  SEQ=$(( SEQ + N ))
done
for job in "${JOBS[@]}"; do
  result="$(wait_job "$job")"
  case "$result" in completed\ 0*) ;; *) echo "  warning: bulk job $job ended $result" >&2 ;; esac
done
echo "  $ROWS records seeded"

echo "=== 2. Run the production mix at concurrency $LEVEL_A${LEVEL_B:+ and $LEVEL_B} ==="
SUMMARIES=()
for level in $LEVELS; do
  FILE="bench-$PROFILE-c$level.json"
  OUT="$RESULTS/$FILE"
  rm -f "$OUT"
  ENV_ARGS=(-e "API_KEY=$API_KEY" -e "BULK_ENTITY=$ENTITY" -e "BULK_QUERY_ID=$QUERY_ID"
    -e "BULK_ROW_COUNT=$ROWS" -e "DURATION=$DURATION" -e "RATE=$RATE" -e "VUS=$level")
  if command -v k6 >/dev/null 2>&1; then
    k6 run -e "BASE_URLS=$BASE_URL" "${ENV_ARGS[@]}" "$LOADTEST/k6/production_mix.js" \
      --summary-trend-stats "avg,min,med,p(50),p(90),p(95),p(99),max" --summary-export "$OUT" || true
  else
    docker run --rm --network host -v "$LOADTEST:/work" -e "BASE_URLS=$BASE_URL" "${ENV_ARGS[@]}" grafana/k6 run \
      /work/k6/production_mix.js --summary-trend-stats "avg,min,med,p(50),p(90),p(95),p(99),max" \
      --summary-export "/work/results/$FILE" || true
  fi
  if [ -f "$OUT" ]; then SUMMARIES+=(--summary "$level=$OUT"); else echo "  warning: concurrency $level produced no summary" >&2; fi
done

echo "=== 3. Compare ==="
if [ "${#SUMMARIES[@]}" -gt 0 ]; then
  if [ -n "$PUBLISHED" ]; then
    node "$SCRIPTS/bench-compare.mjs" "${SUMMARIES[@]}" --published "$PUBLISHED"
  else
    node "$SCRIPTS/bench-compare.mjs" "${SUMMARIES[@]}"
  fi
fi

if [ "$KEEP_RECORDS" = 1 ]; then
  echo "=== 4. Clean up skipped (-KeepRecords) ==="
  exit 0
fi
echo "=== 4. Delete the $ENTITY records ==="
DELETED=0
while true; do
  IDS="$(api POST /api/v1/query/execute "{\"query_id\":\"$QUERY_ID\",\"page\":1,\"page_size\":200}" | json 'd.data.records.map(r=>r.id).join(",")')"
  [ -n "$IDS" ] || break
  BODY="$(node -e "console.log(JSON.stringify({operation:'delete',records:'$IDS'.split(',').map(id=>({id,data:{}}))}))")"
  JOB="$(api POST "/api/v1/$ENTITY/bulk" "$BODY" | json 'd.id')"
  result="$(wait_job "$JOB")"
  case "$result" in failed*|*\ 0) echo "Deleting $ENTITY records stopped: bulk job $JOB ended $result" >&2; exit 1 ;; esac
  DELETED=$(( DELETED + $(echo "$IDS" | tr ',' '\n' | wc -l) ))
done
echo "  deleted $DELETED records"
