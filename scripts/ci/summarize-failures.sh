#!/usr/bin/env bash
# Turns a failed `attome-release --check` log into GitHub annotations that a
# reader of the public checks API can act on without the raw log:
#   1. every panic with the message lines that follow it,
#   2. the failing test targets (cargo's "rerun pass" lines),
#   3. compile and lint errors with their locations,
#   4. rustfmt diffs,
#   5. every gate step that failed, with its reason (a failure outside the
#      tests, such as cargo-deny or the alert rules, shows nowhere else).
# GitHub keeps at most 10 error annotations per step and truncates long ones
# (about 4 KB each), so every line is cut to 240 characters and the summary is
# split into chunks of 14 lines, at most 9 annotations.
set -u
log="${1:-release-check.log}"
clean=$(mktemp)
sed -e 's/\x1b\[[0-9;]*m//g' "$log" > "$clean"

{
  echo "== failed gate steps"
  grep -E '^ +[a-z_]+: FAILED' "$clean" | sed -E 's/^ +//' | head -20
  echo "== panics"
  grep -E -A2 'panicked at' "$clean" \
    | grep -vE '^--$|^note: run with|^stack backtrace|^ +[0-9]+: |^ +at ' | head -400
  echo "== failing targets"
  grep -E 'rerun pass' "$clean" | sed -E 's/.*rerun pass `(.*)`/\1/' | sort -u
  # cargo-nextest (the CI test shards) names each failing test on its own line.
  grep -E '^ *(FAIL|TIMEOUT|SIGSEGV|SIGABRT|SIGKILL) +\[' "$clean" | sed -E 's/^ +//' | sort -u | head -150
  echo "== compile and lint errors"
  grep -E -A1 '^error(\[E[0-9]+\])?: ' "$clean" \
    | grep -vE '^--$|could not compile|aborting due to|test failed, to rerun|^ +Running |targets failed|exit successfully' \
    | head -200
  echo "== depth and recursion limits"
  grep -E -A10 'overflow the depth limit|recursion limit' "$clean"     | grep -E 'error|help|note|-->' | head -20
  echo "== format"
  grep -E '^Diff in' "$clean" | head -50
} | cut -c1-240 > failures.txt

total=$(wc -l < failures.txt)
chunk=14
part=1
start=1
while [ "$start" -le "$total" ] && [ "$part" -le 9 ]; do
  body=$(sed -n "${start},$((start + chunk - 1))p" failures.txt | sed -e 's/%/%25/g' | awk '{printf "%s%%0A", $0}')
  echo "::error title=release check failures ${part}::${body}"
  start=$((start + chunk))
  part=$((part + 1))
done
rm -f "$clean"
